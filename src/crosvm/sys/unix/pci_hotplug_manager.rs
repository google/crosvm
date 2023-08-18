// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! A high-level manager for hotplug PCI devices.

// TODO(b/243767476): Support aarch64.
use std::collections::HashMap;
use std::sync::mpsc;
use std::sync::Arc;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Error;
use arch::RunnableLinuxVm;
use devices::HotPlugBus;
use devices::HotPlugKey;
use devices::IrqEventSource;
use devices::IrqLevelEvent;
use devices::PciAddress;
use devices::PciInterruptPin;
use devices::PciRootCommand;
use devices::ResourceCarrier;
#[cfg(target_arch = "x86_64")]
use hypervisor::VcpuX86_64 as VcpuArch;
#[cfg(target_arch = "x86_64")]
use hypervisor::VmX86_64 as VmArch;
use resources::SystemAllocator;
#[cfg(feature = "swap")]
use swap::SwapDeviceHelper;
use sync::Mutex;
use vm_memory::GuestMemory;

use crate::crosvm::sys::unix::JailWarden;
use crate::crosvm::sys::unix::JailWardenImpl;
use crate::crosvm::sys::unix::PermissiveJailWarden;
use crate::Config;

pub type Result<T> = std::result::Result<T, Error>;

/// PciHotPlugManager manages hotplug ports, and handles PCI device hot plug and hot removal.
pub struct PciHotPlugManager {
    /// map of downstream bus number to corresponding PortStub
    ports: HashMap<u8, PortStub>,
    /// JailWarden for jailing hotplug devices
    jail_warden: Box<dyn JailWarden>,
    /// control channel to root bus
    rootbus_controller: Option<mpsc::Sender<PciRootCommand>>,
}

/// PortStub contains a hotplug port and set of hotplug devices on it.
struct PortStub {
    /// hotplug port
    port: Arc<Mutex<dyn HotPlugBus>>,
    /// Map of hotplugged devices, and system resources that can be released when device is removed.
    devices: HashMap<PciAddress, RecoverableResource>,
}

/// System resources that can be released when a hotplugged device is removed.
struct RecoverableResource {
    irq_num: u32,
    irq_evt: IrqLevelEvent,
}

impl PciHotPlugManager {
    /// Constructs PciHotPlugManager.
    ///
    /// Constructor uses forking, therefore has to be called early, before crosvm enters a
    /// multi-threaded context.
    pub fn new(
        guest_memory: GuestMemory,
        config: &Config,
        #[cfg(feature = "swap")] swap_device_helper: Option<SwapDeviceHelper>,
    ) -> Result<Self> {
        let jail_warden: Box<dyn JailWarden> = match config.jail_config {
            Some(_) => Box::new(
                JailWardenImpl::new(
                    guest_memory,
                    config,
                    #[cfg(feature = "swap")]
                    swap_device_helper,
                )
                .context("jail warden construction")?,
            ),
            None => Box::new(
                PermissiveJailWarden::new(
                    guest_memory,
                    config,
                    #[cfg(feature = "swap")]
                    swap_device_helper,
                )
                .context("jail warden construction")?,
            ),
        };
        Ok(Self {
            ports: HashMap::new(),
            jail_warden,
            rootbus_controller: None,
        })
    }

    /// Set root bus controller. Required before any hotplug commands.
    ///
    /// rootbus_controller cannot be intialized at PciHotPlugManager::new, which must be called in
    /// a single-threaded context. However, rootbus_controller is only available after VM boots,
    /// by which time crosvm is multi-threaded.
    pub fn set_rootbus_controller(
        &mut self,
        rootbus_controller: mpsc::Sender<PciRootCommand>,
    ) -> Result<()> {
        self.rootbus_controller = Some(rootbus_controller);
        Ok(())
    }

    /// Adds a hotplug capable port to manage.
    ///
    /// PciHotPlugManager assumes exclusive control for adding and removing devices to this port.
    pub fn add_port(&mut self, port: Arc<Mutex<dyn HotPlugBus>>) -> Result<()> {
        // Rejects hotplug bus with downstream devices.
        if !port.lock().is_empty() {
            bail!("invalid hotplug bus");
        }
        let downstream_bus = port
            .lock()
            .get_secondary_bus_number()
            .ok_or(anyhow!("cannot get downstream bus"))?;
        if self.ports.get(&downstream_bus).is_some() {
            Err(anyhow!("downstream bus already used for hotplug"))
        } else {
            self.ports.insert(
                downstream_bus,
                PortStub {
                    port,
                    devices: HashMap::new(),
                },
            );
            Ok(())
        }
    }

    /// hotplugs up to 8 PCI devices as "functions of a device" (in PCI Bus Device Function sense).
    ///
    /// returns the bus number of the bus on success.
    pub fn hotplug_device<V: VmArch, Vcpu: VcpuArch>(
        &mut self,
        resource_carriers: Vec<ResourceCarrier>,
        linux: &mut RunnableLinuxVm<V, Vcpu>,
        resources: &mut SystemAllocator,
    ) -> Result<u8> {
        if resource_carriers.len() > 8 || resource_carriers.is_empty() {
            bail!("PCI function has to be 1-8 inclusive");
        }
        let bus = self.find_empty_bus()?;
        for (func_num, mut resource_carrier) in resource_carriers.into_iter().enumerate() {
            let device_address = PciAddress::new(0, bus as u32, 0, func_num as u32)?;
            let hotplug_key = HotPlugKey::GuestDevice {
                guest_addr: device_address,
            };
            resource_carrier.allocate_address(device_address, resources)?;
            let irq_evt = IrqLevelEvent::new()?;
            let (pin, irq_num) = match bus % 4 {
                0 => (PciInterruptPin::IntA, 0),
                1 => (PciInterruptPin::IntB, 1),
                2 => (PciInterruptPin::IntC, 2),
                _ => (PciInterruptPin::IntD, 3),
            };
            resource_carrier.assign_irq(irq_evt.try_clone()?, pin, irq_num);
            let (proxy_device, pid) = self
                .jail_warden
                .make_proxy_device(resource_carrier)
                .context("make proxy device")?;
            let device_id = proxy_device.lock().device_id();
            let device_name = proxy_device.lock().debug_label();
            linux.irq_chip.as_irq_chip_mut().register_level_irq_event(
                irq_num,
                &irq_evt,
                IrqEventSource {
                    device_id,
                    queue_id: 0,
                    device_name: device_name.clone(),
                },
            )?;
            let pid: u32 = pid.try_into().context("fork fail")?;
            if pid > 0 {
                linux.pid_debug_label_map.insert(pid, device_name);
            }
            self.rootbus_controller
                .as_ref()
                .ok_or(anyhow!("root bus controller not initialized"))?
                .send(PciRootCommand::Add(device_address, proxy_device))?;
            let port_stub = self
                .ports
                .get_mut(&bus)
                .ok_or(anyhow!("invalid hotplug bus number"))?;
            port_stub
                .port
                .lock()
                .add_hotplug_device(hotplug_key, device_address);
            port_stub
                .devices
                .insert(device_address, RecoverableResource { irq_num, irq_evt });
        }
        // Send hotplug signal after all functions are added.
        self.send_hotplug_signal(bus)?;
        Ok(bus)
    }

    /// Removes all hotplugged devices on the hotplug bus.
    pub fn remove_hotplug_device<V: VmArch, Vcpu: VcpuArch>(
        &mut self,
        bus: u8,
        linux: &mut RunnableLinuxVm<V, Vcpu>,
        resources: &mut SystemAllocator,
    ) -> Result<()> {
        // Unlike hotplug, HotPlugBus removes all downstream devices when eject signal is sent.
        self.remove_device_from_port(bus)?;
        let port_stub = self
            .ports
            .get_mut(&bus)
            .ok_or(anyhow!("invalid hotplug bus number"))?;
        // Remove all devices on the hotplug bus.
        for (pci_address, recoverable_resource) in port_stub.devices.drain() {
            self.rootbus_controller
                .as_ref()
                .ok_or(anyhow!("root bus controller not initialized"))?
                .send(PciRootCommand::Remove(pci_address))?;
            // port_stub.port does not have remove_hotplug_device method, as devices are removed
            // when hot_unplug is called.
            resources.release_pci(pci_address.bus, pci_address.dev, pci_address.func);
            linux.irq_chip.unregister_level_irq_event(
                recoverable_resource.irq_num,
                &recoverable_resource.irq_evt,
            )?;
        }
        Ok(())
    }

    /// Find a bus number available for hotplug.
    fn find_empty_bus(&self) -> Result<u8> {
        for (bus_num, port_stub) in &self.ports {
            if port_stub.devices.is_empty() {
                return Ok(*bus_num);
            }
        }
        bail!("no ports available");
    }

    /// Sends hotplug signal on the port.
    fn send_hotplug_signal(&self, bus: u8) -> Result<()> {
        if let Some(port_stub) = self.ports.get(&bus) {
            let base_pci_address = PciAddress::new(0, bus as u32, 0, 0)?;
            port_stub.port.lock().hot_plug(base_pci_address);
            Ok(())
        } else {
            bail!("invalid hotplug bus number");
        }
    }

    /// Sends eject signal on the port, and removes downstream devices on the port.
    fn remove_device_from_port(&self, bus: u8) -> Result<()> {
        if let Some(port_stub) = self.ports.get(&bus) {
            if port_stub.devices.is_empty() {
                bail!("invalid hotplug bus number");
            }
            let base_pci_address = PciAddress::new(0, bus as u32, 0, 0)?;
            port_stub.port.lock().hot_unplug(base_pci_address);
            Ok(())
        } else {
            bail!("invalid hotplug bus number");
        }
    }
}
