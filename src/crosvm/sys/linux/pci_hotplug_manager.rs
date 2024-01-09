// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! A high-level manager for hotplug PCI devices.

// TODO(b/243767476): Support aarch64.
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::mpsc;
use std::sync::Arc;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Error;
use arch::RunnableLinuxVm;
use arch::VcpuArch;
use arch::VmArch;
use devices::HotPlugBus;
use devices::HotPlugKey;
use devices::IrqEventSource;
use devices::IrqLevelEvent;
use devices::PciAddress;
use devices::PciInterruptPin;
use devices::PciRootCommand;
use devices::ResourceCarrier;
use resources::SystemAllocator;
#[cfg(feature = "swap")]
use swap::SwapDeviceHelper;
use sync::Mutex;
use vm_memory::GuestMemory;

use crate::crosvm::sys::linux::JailWarden;
use crate::crosvm::sys::linux::JailWardenImpl;
use crate::crosvm::sys::linux::PermissiveJailWarden;
use crate::Config;

pub type Result<T> = std::result::Result<T, Error>;

/// PciHotPlugManager manages hotplug ports, and handles PCI device hot plug and hot removal.
pub struct PciHotPlugManager {
    /// map of empty ports available.
    ///
    /// empty ports are sorted such to ensure the ordering of the hotplugged devices. Specifically,
    /// if multiple devices are hotplugged before PCI enumeration, they will appear in the guest OS
    /// in the same order hotplug_device is called.
    available_ports: BTreeMap<PciAddress, PortStub>,
    /// map of occupied ports, indexed by downstream bus number
    occupied_ports: HashMap<u8, PortStub>,
    /// JailWarden for jailing hotplug devices
    jail_warden: Box<dyn JailWarden>,
    /// control channel to root bus
    rootbus_controller: Option<mpsc::Sender<PciRootCommand>>,
}

/// PortStub contains a hotplug port and set of hotplug devices on it.
struct PortStub {
    /// PCI address of the port (at upstream)
    pci_address: PciAddress,
    /// index of downstream bus
    downstream_bus: u8,
    /// hotplug port
    port: Arc<Mutex<dyn HotPlugBus>>,
    /// Map of hotplugged devices, and system resources that can be released when device is removed.
    devices: HashMap<PciAddress, RecoverableResource>,
}

impl PortStub {
    /// Sends hotplug signal on the port.
    fn send_hotplug_signal(&mut self) -> Result<()> {
        let base_pci_address = PciAddress::new(0, self.downstream_bus.into(), 0, 0)?;
        self.port.lock().hot_plug(base_pci_address);
        Ok(())
    }
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
            available_ports: BTreeMap::new(),
            occupied_ports: HashMap::new(),
            jail_warden,
            rootbus_controller: None,
        })
    }

    /// Set root bus controller. Required before any hotplug commands.
    ///
    /// rootbus_controller cannot be intialized at PciHotPlugManager::new, which must be called in
    /// a single-threaded context. However, rootbus_controller is only available after VM boots,
    /// by which time crosvm is multi-threaded.
    /// TODO(293801301): Remove unused after aarch64 support
    #[allow(unused)]
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
    /// TODO(293801301): Remove unused_variables after aarch64 support
    #[allow(unused)]
    pub fn add_port(&mut self, port: Arc<Mutex<dyn HotPlugBus>>) -> Result<()> {
        let port_lock = port.lock();
        // Rejects hotplug bus with downstream devices.
        if !port_lock.is_empty() {
            bail!("invalid hotplug bus");
        }
        let pci_address = port_lock
            .get_address()
            .context("Hotplug bus PCI address missing")?;
        // Reject hotplug buses not on rootbus, since otherwise the order of enumeration depends on
        // the topology of PCI.
        if pci_address.bus != 0 {
            bail!("hotplug port on non-root bus not supported");
        }
        let downstream_bus = port_lock
            .get_secondary_bus_number()
            .ok_or(anyhow!("cannot get downstream bus"))?;
        drop(port_lock);
        self.available_ports.insert(
            pci_address,
            PortStub {
                pci_address,
                downstream_bus,
                port,
                devices: HashMap::new(),
            },
        );
        Ok(())
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
            bail!("PCI function count has to be 1 to 8 inclusive");
        }
        let (_, mut port_stub) = self
            .available_ports
            .pop_first()
            .ok_or(anyhow!("no available ports"))?;
        let downstream_bus = port_stub.downstream_bus;
        if self.occupied_ports.contains_key(&downstream_bus) {
            bail!("Downstream bus {} already used", downstream_bus);
        }
        for (func_num, mut resource_carrier) in resource_carriers.into_iter().enumerate() {
            let device_address = PciAddress::new(0, downstream_bus as u32, 0, func_num as u32)?;
            let hotplug_key = HotPlugKey::GuestDevice {
                guest_addr: device_address,
            };
            resource_carrier.allocate_address(device_address, resources)?;
            let irq_evt = IrqLevelEvent::new()?;
            let (pin, irq_num) = match downstream_bus % 4 {
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
            port_stub
                .port
                .lock()
                .add_hotplug_device(hotplug_key, device_address);
            port_stub
                .devices
                .insert(device_address, RecoverableResource { irq_num, irq_evt });
        }
        // Send hotplug signal after all functions are added.
        port_stub.send_hotplug_signal()?;
        self.occupied_ports.insert(downstream_bus, port_stub);
        Ok(downstream_bus)
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
            .occupied_ports
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
        if let Some(port_stub) = self.occupied_ports.remove(&bus) {
            self.available_ports
                .insert(port_stub.pci_address, port_stub);
        } else {
            bail!("Failed to release bus {}", bus);
        }
        Ok(())
    }

    /// Sends eject signal on the port, and removes downstream devices on the port.
    fn remove_device_from_port(&self, bus: u8) -> Result<()> {
        if let Some(port_stub) = self.occupied_ports.get(&bus) {
            let base_pci_address = PciAddress::new(0, bus as u32, 0, 0)?;
            port_stub.port.lock().hot_unplug(base_pci_address);
            Ok(())
        } else {
            bail!("invalid bus number for device removal: {}", bus);
        }
    }
}
