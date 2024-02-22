// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! A high-level manager for hotplug PCI devices.

// TODO(b/243767476): Support aarch64.
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

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
use log::debug;
use log::error;
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

const PCI_SLOT_TIMEOUT: Duration = Duration::from_secs(1);

/// PciHotPlugManager manages hotplug ports, and handles PCI device hot plug and hot removal.
pub struct PciHotPlugManager {
    /// map of empty ports available.
    ///
    /// empty ports are sorted such to ensure the ordering of the hotplugged devices. Specifically,
    /// if multiple devices are hotplugged before PCI enumeration, they will appear in the guest OS
    /// in the same order hotplug_device is called.
    port_pool: PortPool,
    /// map of occupied ports, indexed by downstream bus number
    occupied_ports: HashMap<u8, PortStub>,
    /// JailWarden for jailing hotplug devices
    jail_warden: Box<dyn JailWarden>,
    /// control channel to root bus
    rootbus_controller: Option<mpsc::Sender<PciRootCommand>>,
}

/// HotPlugAvailability indicates when a port is available for hotplug.
#[derive(Debug)]
enum HotPlugAvailability {
    /// available now
    Now,
    /// available after notification is received.
    After(mpsc::Receiver<()>),
}

/// PortStub contains a hotplug port and set of hotplug devices on it.
struct PortStub {
    /// PCI address of the port (at upstream)
    pci_address: PciAddress,
    /// index of downstream bus
    downstream_bus: u8,
    /// hotplug port
    port: Arc<Mutex<dyn HotPlugBus>>,
    /// Map of hotplugged devices, and system resources that can be released when device is
    /// removed.
    devices: HashMap<PciAddress, RecoverableResource>,
}

impl PortStub {
    /// Sends hotplug signal on the port.
    fn send_hotplug_signal(&mut self) -> Result<()> {
        let base_pci_address = PciAddress::new(0, self.downstream_bus.into(), 0, 0)?;
        self.port.lock().hot_plug(base_pci_address)?;
        Ok(())
    }

    /// Sends hotplug signal after notification on the port.
    fn send_hotplug_signal_after_notification(
        &mut self,
        notf_recvr: mpsc::Receiver<()>,
    ) -> Result<()> {
        let base_pci_address = PciAddress::new(0, self.downstream_bus.into(), 0, 0)?;
        let weak_port = Arc::downgrade(&self.port);
        thread::spawn(move || {
            if let Err(e) = notf_recvr.recv_timeout(PCI_SLOT_TIMEOUT) {
                error!(
                    "failed to receive hot unplug command complete notification: {:#}",
                    &e
                );
            }
            match weak_port.upgrade() {
                Some(port) => {
                    if let Err(e) = port.lock().hot_plug(base_pci_address) {
                        error!("hot plug failed: {:#}", &e);
                    }
                }
                None => {
                    error!("hotplug signal cancelled since port is out of scope");
                }
            }
        });
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
            port_pool: PortPool::new(),
            occupied_ports: HashMap::new(),
            jail_warden,
            rootbus_controller: None,
        })
    }

    /// Starts PciHotPlugManager. Required before any other commands.
    ///
    /// PciHotPlugManager::new must be called in a single-threaded context as it forks.
    /// However, rootbus_controller is only available after VM boots when crosvm is multi-threaded.
    ///
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
            .context("cannot get downstream bus")?;
        drop(port_lock);
        self.port_pool.insert(PortStub {
            pci_address,
            downstream_bus,
            port,
            devices: HashMap::new(),
        });
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
        let (mut port_stub, port_availability) = self.port_pool.pop_first()?;
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
                .context("rootbus_controller not set: set_rootbus_controller not called?")?
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
        match port_availability {
            HotPlugAvailability::Now => port_stub.send_hotplug_signal()?,
            HotPlugAvailability::After(cc_recvr) => {
                debug!(
                    "Hotplug signal delayed since port {} is busy",
                    &port_stub.pci_address,
                );
                port_stub.send_hotplug_signal_after_notification(cc_recvr)?;
            }
        }
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
        let cc_recvr = self.remove_device_from_port(bus)?;
        let port_stub = self
            .occupied_ports
            .get_mut(&bus)
            .context("invalid hotplug bus number")?;
        // Remove all devices on the hotplug bus.
        for (pci_address, recoverable_resource) in port_stub.devices.drain() {
            self.rootbus_controller
                .as_ref()
                .context("rootbus_controller not set: set_rootbus_controller not called?")?
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
            self.port_pool
                .insert_after_notification(port_stub, cc_recvr)?;
        } else {
            bail!("Failed to release bus {}", bus);
        }
        Ok(())
    }

    /// Sends eject signal on the port, and removes downstream devices on the port.
    fn remove_device_from_port(&self, bus: u8) -> Result<mpsc::Receiver<()>> {
        let port_stub = self
            .occupied_ports
            .get(&bus)
            .ok_or(anyhow!("invalid bus number for device removal: {}", bus))?;
        let base_pci_address = PciAddress::new(0, bus as u32, 0, 0)?;
        port_stub
            .port
            .lock()
            .hot_unplug(base_pci_address)?
            .context("no notifier for hot unplug completion.")
    }
}

/// PortPool is a pool available PCI ports where ports can be added asynchronously.
struct PortPool {
    /// map of empty ports that are available
    ports_available: BTreeMap<PciAddress, PortStub>,
    /// map of ports that will soon be available
    ports_pending: BTreeMap<PciAddress, (mpsc::Receiver<()>, PortStub)>,
}

impl PortPool {
    /// constructor
    fn new() -> Self {
        Self {
            ports_available: BTreeMap::new(),
            ports_pending: BTreeMap::new(),
        }
    }

    /// Insert a port_stub that is available immediately.
    fn insert(&mut self, port_stub: PortStub) -> Result<()> {
        self.update_port_availability();
        let pci_addr = port_stub.pci_address;
        self.ports_available.insert(pci_addr, port_stub);
        Ok(())
    }

    /// Insert a port_stub that will be available after notification received. Returns immediately.
    fn insert_after_notification(
        &mut self,
        port_stub: PortStub,
        cc_recvr: mpsc::Receiver<()>,
    ) -> Result<()> {
        self.update_port_availability();
        self.ports_pending
            .insert(port_stub.pci_address, (cc_recvr, port_stub));
        Ok(())
    }

    /// Pop the first available port in the order of PCI enumeration. If no port is available now,
    /// pop the first in the order of PCI enumeration.
    fn pop_first(&mut self) -> Result<(PortStub, HotPlugAvailability)> {
        self.update_port_availability();
        if let Some((_, port_stub)) = self.ports_available.pop_first() {
            return Ok((port_stub, HotPlugAvailability::Now));
        }
        match self.ports_pending.pop_first() {
            Some((_, (cc_recvr, port_stub))) => {
                Ok((port_stub, HotPlugAvailability::After(cc_recvr)))
            }
            None => Err(anyhow!("No PCI ports available.")),
        }
    }

    /// Move pending ports to available ports if notification is received.
    fn update_port_availability(&mut self) {
        let mut new_ports_pending = BTreeMap::new();
        while let Some((pci_addr, (cc_recvr, port_stub))) = self.ports_pending.pop_first() {
            if cc_recvr.try_recv().is_ok() {
                let pci_addr = port_stub.pci_address;
                self.ports_available.insert(pci_addr, port_stub);
            } else {
                new_ports_pending.insert(pci_addr, (cc_recvr, port_stub));
            }
        }
        self.ports_pending = new_ports_pending;
    }
}

#[cfg(test)]
mod tests {
    use devices::PcieRootPort;

    use super::*;

    fn new_mock_port_stub(pci_address: PciAddress) -> PortStub {
        let hotplug_port = PcieRootPort::new(0, true);
        PortStub {
            pci_address,
            downstream_bus: 0,
            port: Arc::new(Mutex::new(hotplug_port)),
            devices: HashMap::new(),
        }
    }

    #[test]
    fn port_pool_pop_before_completion() {
        let mut port_pool = PortPool::new();
        let mock_port = new_mock_port_stub(PciAddress::new(0, 1, 0, 0).unwrap());
        let (_cc_sender, cc_recvr) = mpsc::channel();
        port_pool
            .insert_after_notification(mock_port, cc_recvr)
            .unwrap();
        let (_port_stub, port_availability) = port_pool.pop_first().unwrap();
        assert!(matches!(port_availability, HotPlugAvailability::After(_)));
    }

    #[test]
    fn port_pool_pop_after_completion() {
        let mut port_pool = PortPool::new();
        let mock_port = new_mock_port_stub(PciAddress::new(0, 1, 0, 0).unwrap());
        let (cc_sender, cc_recvr) = mpsc::channel();
        port_pool
            .insert_after_notification(mock_port, cc_recvr)
            .unwrap();
        cc_sender.send(()).unwrap();
        let (_port_stub, port_availability) = port_pool.pop_first().unwrap();
        assert!(matches!(port_availability, HotPlugAvailability::Now));
    }

    #[test]
    fn port_pool_pop_in_order() {
        let mut port_pool = PortPool::new();
        for bus_num in [2, 3, 4, 1, 0] {
            let mock_port = new_mock_port_stub(PciAddress::new(0, bus_num, 0, 0).unwrap());
            port_pool.insert(mock_port).unwrap();
        }
        for bus_num in 0..=4 {
            assert_eq!(port_pool.pop_first().unwrap().0.pci_address.bus, bus_num);
        }
    }
}
