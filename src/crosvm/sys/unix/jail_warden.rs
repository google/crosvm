// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Manages minijails creation after VM starts. Minijail is created during a device hotplug.

#![deny(missing_docs)]

use std::path::Path;
use std::sync::Arc;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use base::error;
use base::info;
use base::sys::Pid;
use base::syslog;
use base::unix::process::fork_process;
use base::unix::process::Child;
use base::AsRawDescriptor;
#[cfg(feature = "swap")]
use base::AsRawDescriptors;
use base::Tube;
use devices::virtio::VirtioDeviceType;
use devices::BusDevice;
use devices::ChildProcIntf;
use devices::PciDevice;
use devices::ProxyDevice;
use devices::ResourceCarrier;
use jail::create_base_minijail;
use jail::create_sandbox_minijail;
use jail::RunAsUser;
use jail::SandboxConfig;
use jail::MAX_OPEN_FILES_FOR_JAIL_WARDEN;
use serde::Deserialize;
use serde::Serialize;
#[cfg(feature = "swap")]
use swap::SwapDeviceHelper;
use sync::Mutex;
use vm_memory::GuestMemory;

use crate::crosvm::sys::unix::pci_hotplug_helpers::build_hotplug_net_device;
use crate::crosvm::sys::unix::pci_hotplug_helpers::NetLocalParameters;
use crate::crosvm::sys::unix::VirtioDeviceBuilder;
use crate::Config;

/// Control commands to jail warden process.
#[derive(Serialize, Deserialize)]
pub enum JailCommand {
    /// Quits jail warden process.
    Exit,
    /// Fork a process and create a device inside it.
    ForkDevice(ResourceCarrier),
}

/// Response to control commands.
#[derive(Serialize, Deserialize)]
pub enum JailResponse {
    /// Fork device failed with error.
    ForkDeviceError(String),
    /// Fork device succeeded with proxy device and keep_rds.
    ForkDeviceOk(ChildProcIntf),
}

/// JailWarden takes ResourceCarrier, jail it, and returns a proxy to the created device.
pub trait JailWarden {
    /// Make a PCI device, jail it, and return the proxy to the jailed device as a BusDevice.
    fn make_proxy_device(
        &self,
        resource_carrier: ResourceCarrier,
    ) -> Result<(Arc<Mutex<dyn BusDevice>>, Pid)>;
}

/// Implementation of JailWarden
pub struct JailWardenImpl {
    worker_process: Option<Child>,
    main_tube: Tube,
}

impl JailWardenImpl {
    /// Constructor of JailWardenImpl
    pub fn new(
        guest_memory: GuestMemory,
        config: &Config,
        #[cfg(feature = "swap")] swap_device_helper: Option<SwapDeviceHelper>,
    ) -> Result<Self> {
        let mut keep_rds = Vec::new();
        syslog::push_descriptors(&mut keep_rds);
        cros_tracing::push_descriptors!(&mut keep_rds);
        let (main_tube, worker_tube) = Tube::pair()?;
        keep_rds.push(worker_tube.as_raw_descriptor());
        #[cfg(feature = "swap")]
        if let Some(swap_device_helper) = &swap_device_helper {
            keep_rds.extend(swap_device_helper.as_raw_descriptors());
        }

        let jail = match &config.jail_config {
            Some(jail_config) => {
                base::info!("Using sandboxed jailwarden");
                let mut sandbox_config = SandboxConfig::new(jail_config, "jail_warden");
                // Sandbox need to run as current user to access hotplugged devices.
                sandbox_config.run_as = RunAsUser::CurrentUser;
                // Caps inside sandbox needed for configuring jails.
                sandbox_config.limit_caps = false;
                // jail warden need access to net namespace to open network tap.
                sandbox_config.namespace_net = false;
                create_sandbox_minijail(
                    Path::new("/"),
                    MAX_OPEN_FILES_FOR_JAIL_WARDEN,
                    &sandbox_config,
                )
            }
            None => {
                base::info!("Using base jailwarden");
                create_base_minijail(Path::new("/"), MAX_OPEN_FILES_FOR_JAIL_WARDEN)
            }
        }?;

        let worker_process =
            fork_process(jail, keep_rds, Some(String::from("jail warden")), || {
                if let Err(e) = jail_worker_process(
                    guest_memory,
                    worker_tube,
                    config,
                    #[cfg(feature = "swap")]
                    swap_device_helper,
                ) {
                    panic!("jail_worker_process exited with error: {:?}", e);
                }
            })?;
        Ok(Self {
            worker_process: Some(worker_process),
            main_tube,
        })
    }
}

impl JailWarden for JailWardenImpl {
    fn make_proxy_device(
        &self,
        resource_carrier: ResourceCarrier,
    ) -> Result<(Arc<Mutex<dyn BusDevice>>, Pid)> {
        self.main_tube
            .send(&JailCommand::ForkDevice(resource_carrier))?;
        match self.main_tube.recv::<JailResponse>()? {
            JailResponse::ForkDeviceOk(proxy_device_primitive) => {
                let proxy_device: ProxyDevice = proxy_device_primitive.try_into()?;
                let pid = proxy_device.pid();
                Ok((Arc::new(Mutex::new(proxy_device)), pid))
            }
            JailResponse::ForkDeviceError(e) => Err(anyhow!(e)),
        }
    }
}

impl Drop for JailWardenImpl {
    fn drop(&mut self) {
        if let Err(e) = self.main_tube.send(&JailCommand::Exit) {
            error!("Failed to send jail warden exit command: {:?}", &e);
        }
        if let Some(worker_process) = self.worker_process.take() {
            if let Err(e) = worker_process.wait() {
                error!(
                    "Failed to wait for jail warden worker process shutdown: {:?}",
                    &e
                );
            }
        }
    }
}

/// The worker thread of the warden process for creating jails and locking devices inside.
fn jail_worker_process(
    guest_memory: GuestMemory,
    worker_tube: Tube,
    config: &Config,
    #[cfg(feature = "swap")] mut swap_device_helper: Option<SwapDeviceHelper>,
) -> Result<()> {
    info!("JailWarden worker process started");

    'worker_loop: loop {
        match worker_tube.recv::<JailCommand>()? {
            JailCommand::Exit => {
                break 'worker_loop;
            }
            JailCommand::ForkDevice(hot_plug_device_builder) => {
                let (pci_device, jail) = match hot_plug_device_builder {
                    ResourceCarrier::VirtioNet(net_resource_carrier) => {
                        let net_param = &net_resource_carrier.net_param;
                        let jail = net_param
                            .create_jail(&config.jail_config, VirtioDeviceType::Regular)?
                            .ok_or(anyhow!("no jail created"))?;
                        let net_local_parameters =
                            NetLocalParameters::new(guest_memory.clone(), config.protection_type);
                        let pci_device =
                            build_hotplug_net_device(net_resource_carrier, net_local_parameters)?;
                        (pci_device, jail)
                    }
                };
                let mut keep_rds = vec![];
                syslog::push_descriptors(&mut keep_rds);
                cros_tracing::push_descriptors!(&mut keep_rds);
                keep_rds.extend(pci_device.keep_rds());
                let proxy_device_primitive = ChildProcIntf::new(
                    pci_device,
                    jail,
                    keep_rds,
                    #[cfg(feature = "swap")]
                    &mut swap_device_helper,
                )?;
                worker_tube
                    .send(&JailResponse::ForkDeviceOk(proxy_device_primitive))
                    .context("send ChildProcIntf failed.")?;
            }
        }
    }
    Ok(())
}

/// PermissiveJailWarden act as a JailWarden, but does not jail the device.
///
/// PermissiveJailWarden is used when disable_sandbox flag is selected from crosvm CLI.
pub struct PermissiveJailWarden {
    config: Config,
    guest_memory: GuestMemory,
}

impl PermissiveJailWarden {
    /// Constructor of PermissiveJailWarden
    pub fn new(
        guest_memory: GuestMemory,
        config: &Config,
        #[cfg(feature = "swap")] _swap_device_helper: Option<SwapDeviceHelper>,
    ) -> Result<Self> {
        let (main_tube, loopback_tube) = Tube::pair()?;
        main_tube.send(config)?;
        let config_clone = loopback_tube.recv::<Config>()?;
        Ok(Self {
            config: config_clone,
            guest_memory,
        })
    }
}

impl JailWarden for PermissiveJailWarden {
    fn make_proxy_device(
        &self,
        resource_carrier: ResourceCarrier,
    ) -> Result<(Arc<Mutex<dyn BusDevice>>, Pid)> {
        let pci_device = match resource_carrier {
            ResourceCarrier::VirtioNet(net_resource_carrier) => {
                let net_local_parameters =
                    NetLocalParameters::new(self.guest_memory.clone(), self.config.protection_type);
                build_hotplug_net_device(net_resource_carrier, net_local_parameters)?
            }
        };
        Ok((Arc::new(Mutex::new(pci_device)), 0))
    }
}
