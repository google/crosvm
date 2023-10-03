// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg_attr(windows, allow(unused))]

//! Emulates virtual and hardware devices.

pub mod ac_adapter;
pub mod acpi;
pub mod bat;
mod bus;
#[cfg(feature = "stats")]
mod bus_stats;
pub mod cmos;
#[cfg(target_arch = "x86_64")]
mod debugcon;
mod fw_cfg;
mod i8042;
mod irq_event;
pub mod irqchip;
mod pci;
mod pflash;
pub mod pl030;
pub mod pmc_virt;
mod serial;
pub mod serial_device;
mod suspendable;
mod sys;
mod virtcpufreq;
pub mod virtio;
#[cfg(feature = "vtpm")]
mod vtpm_proxy;

cfg_if::cfg_if! {
    if #[cfg(target_arch = "x86_64")] {
        mod pit;
        pub use self::pit::{Pit, PitError};
        pub mod tsc;
    }
}

use std::collections::HashMap;
use std::collections::VecDeque;
use std::fs::File;
use std::sync::Arc;

use anyhow::anyhow;
use anyhow::Context;
use base::error;
use base::info;
use base::Tube;
use base::TubeError;
use cros_async::AsyncTube;
use cros_async::Executor;
use vm_control::DeviceControlCommand;
use vm_control::DevicesState;
use vm_control::VmResponse;
use vm_memory::GuestMemory;

pub use self::acpi::ACPIPMFixedEvent;
pub use self::acpi::ACPIPMResource;
pub use self::bat::BatteryError;
pub use self::bat::GoldfishBattery;
pub use self::bus::Bus;
pub use self::bus::BusAccessInfo;
pub use self::bus::BusDevice;
pub use self::bus::BusDeviceObj;
pub use self::bus::BusDeviceSync;
pub use self::bus::BusRange;
pub use self::bus::BusResumeDevice;
pub use self::bus::BusType;
pub use self::bus::Error as BusError;
pub use self::bus::HotPlugBus;
pub use self::bus::HotPlugKey;
#[cfg(feature = "stats")]
pub use self::bus_stats::BusStatistics;
#[cfg(target_arch = "x86_64")]
pub use self::debugcon::Debugcon;
pub use self::fw_cfg::Error as FwCfgError;
pub use self::fw_cfg::FwCfgDevice;
pub use self::fw_cfg::FwCfgItemType;
pub use self::fw_cfg::FwCfgParameters;
pub use self::fw_cfg::FW_CFG_BASE_PORT;
pub use self::fw_cfg::FW_CFG_MAX_FILE_SLOTS;
pub use self::fw_cfg::FW_CFG_WIDTH;
pub use self::i8042::I8042Device;
pub use self::irq_event::IrqEdgeEvent;
pub use self::irq_event::IrqLevelEvent;
pub use self::irqchip::*;
pub use self::pci::BarRange;
pub use self::pci::CrosvmDeviceId;
pub use self::pci::GpeScope;
#[cfg(feature = "pci-hotplug")]
pub use self::pci::HotPluggable;
#[cfg(feature = "pci-hotplug")]
pub use self::pci::IntxParameter;
#[cfg(feature = "pci-hotplug")]
pub use self::pci::NetResourceCarrier;
pub use self::pci::PciAddress;
pub use self::pci::PciAddressError;
pub use self::pci::PciBarConfiguration;
pub use self::pci::PciBarIndex;
pub use self::pci::PciBus;
pub use self::pci::PciClassCode;
pub use self::pci::PciConfigIo;
pub use self::pci::PciConfigMmio;
pub use self::pci::PciDevice;
pub use self::pci::PciDeviceError;
pub use self::pci::PciInterruptPin;
pub use self::pci::PciRoot;
pub use self::pci::PciRootCommand;
pub use self::pci::PciVirtualConfigMmio;
pub use self::pci::PreferredIrq;
#[cfg(feature = "pci-hotplug")]
pub use self::pci::ResourceCarrier;
pub use self::pci::StubPciDevice;
pub use self::pci::StubPciParameters;
pub use self::pflash::Pflash;
pub use self::pflash::PflashParameters;
pub use self::pl030::Pl030;
pub use self::serial::Serial;
pub use self::serial_device::Error as SerialError;
pub use self::serial_device::SerialDevice;
pub use self::serial_device::SerialHardware;
pub use self::serial_device::SerialParameters;
pub use self::serial_device::SerialType;
pub use self::suspendable::DeviceState;
pub use self::suspendable::Suspendable;
pub use self::virtcpufreq::VirtCpufreq;
pub use self::virtio::VirtioMmioDevice;
pub use self::virtio::VirtioPciDevice;
#[cfg(feature = "vtpm")]
pub use self::vtpm_proxy::VtpmProxy;

cfg_if::cfg_if! {
    if #[cfg(any(target_os = "android", target_os = "linux"))] {
        mod platform;
        mod proxy;
        pub mod vmwdt;
        pub mod vfio;
        #[cfg(feature = "usb")]
        #[macro_use]
        mod register_space;
        #[cfg(feature = "usb")]
        pub mod usb;
        #[cfg(feature = "usb")]
        mod utils;

        pub use self::pci::{
            CoIommuDev, CoIommuParameters, CoIommuUnpinPolicy, PciBridge, PcieDownstreamPort,
            PcieHostPort, PcieRootPort, PcieUpstreamPort, PvPanicCode, PvPanicPciDevice,
            VfioPciDevice,
        };
        pub use self::platform::VfioPlatformDevice;
        pub use self::ac_adapter::AcAdapter;
        pub use self::pmc_virt::VirtualPmc;
        pub use self::proxy::ChildProcIntf;
        pub use self::proxy::Error as ProxyError;
        pub use self::proxy::ProxyDevice;
        #[cfg(feature = "usb")]
        pub use self::usb::backend::device_provider::DeviceProvider;
        #[cfg(feature = "usb")]
        pub use self::usb::xhci::xhci_controller::XhciController;
        pub use self::vfio::VfioContainer;
        pub use self::vfio::VfioDevice;
        pub use self::vfio::VfioDeviceType;
        pub use self::virtio::vfio_wrapper;

    } else if #[cfg(windows)] {
    } else {
        compile_error!("Unsupported platform");
    }
}

/// Request CoIOMMU to unpin a specific range.
use serde::Deserialize;
/// Request CoIOMMU to unpin a specific range.
use serde::Serialize;
#[derive(Serialize, Deserialize, Debug)]
pub struct UnpinRequest {
    /// The ranges presents (start gfn, count).
    ranges: Vec<(u64, u64)>,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum UnpinResponse {
    Success,
    Failed,
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
pub enum IommuDevType {
    #[serde(rename = "off")]
    #[default]
    NoIommu,
    #[serde(rename = "viommu")]
    VirtioIommu,
    #[serde(rename = "coiommu")]
    CoIommu,
}

// Thread that handles commands sent to devices - such as snapshot, sleep, suspend
// Created when the VM is first created, and re-created on resumption of the VM.
pub fn create_devices_worker_thread(
    guest_memory: GuestMemory,
    io_bus: Arc<Bus>,
    mmio_bus: Arc<Bus>,
    device_ctrl_resp: Tube,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("device_control".to_string())
        .spawn(move || {
            let ex = Executor::new().expect("Failed to create an executor");

            let async_control = AsyncTube::new(&ex, device_ctrl_resp).unwrap();
            match ex.run_until(async move {
                handle_command_tube(async_control, guest_memory, io_bus, mmio_bus).await
            }) {
                Ok(_) => {}
                Err(e) => {
                    error!("Device control thread exited with error: {}", e);
                }
            };
        })
}

fn sleep_devices(bus: &Bus) -> anyhow::Result<()> {
    match bus.sleep_devices() {
        Ok(_) => {
            info!("Devices slept successfully");
            Ok(())
        }
        Err(e) => Err(anyhow!(
            "Failed to sleep all devices: {}. Waking up sleeping devices.",
            e
        )),
    }
}

fn wake_devices(bus: &Bus) {
    match bus.wake_devices() {
        Ok(_) => {
            info!("Devices awoken successfully");
        }
        Err(e) => {
            // Some devices may have slept. Eternally.
            // Recovery - impossible.
            // Shut down VM.
            panic!(
                "Failed to wake devices: {}. VM panicked to avoid unexpected behavior",
                e
            )
        }
    }
}

/// `SleepGuard` sends the devices on all of the provided buses to sleep when it is created and
/// wakes them all up when it is dropped.
///
/// This allows snapshot and restore operations to be executed while the `BusDevice`s attached to
/// the buses are stopped so that the VM state will not change during the snapshot process.
struct SleepGuard<'a> {
    buses: &'a [&'a Bus],
}

impl<'a> SleepGuard<'a> {
    pub fn new(buses: &'a [&'a Bus]) -> anyhow::Result<Self> {
        for bus in buses {
            if let Err(e) = sleep_devices(bus) {
                // Failing to sleep could mean a single device failing to sleep.
                // Wake up devices to resume functionality of the VM.
                for bus in buses {
                    wake_devices(bus);
                }

                return Err(e);
            }
        }

        Ok(SleepGuard { buses })
    }
}

impl<'a> Drop for SleepGuard<'a> {
    fn drop(&mut self) {
        for bus in self.buses {
            wake_devices(bus);
        }
    }
}

fn snapshot_devices(
    bus: &Bus,
    add_snapshot: impl FnMut(u32, serde_json::Value),
) -> anyhow::Result<()> {
    match bus.snapshot_devices(add_snapshot) {
        Ok(_) => {
            info!("Devices snapshot successfully");
            Ok(())
        }
        Err(e) => {
            // If snapshot fails, wake devices and return error
            error!("failed to snapshot devices: {}", e);
            Err(e)
        }
    }
}

fn restore_devices(
    bus: &Bus,
    devices_map: &mut HashMap<u32, VecDeque<serde_json::Value>>,
) -> anyhow::Result<()> {
    match bus.restore_devices(devices_map) {
        Ok(_) => {
            info!("Devices restore successfully");
            Ok(())
        }
        Err(e) => {
            // If restore fails, wake devices and return error
            error!("failed to restore devices: {:#}", e);
            Err(e)
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SnapshotRoot {
    guest_memory_metadata: serde_json::Value,
    devices: Vec<HashMap<u32, serde_json::Value>>,
}

async fn snapshot_handler(
    path: &std::path::Path,
    guest_memory: &GuestMemory,
    buses: &[&Bus],
) -> anyhow::Result<()> {
    let mut snapshot_root = SnapshotRoot {
        guest_memory_metadata: serde_json::Value::Null,
        devices: Vec::new(),
    };

    // TODO(b/268093674): Better output file format.
    // TODO(b/268094487): If the snapshot fail, this leaves an incomplete memory snapshot at the
    // requested path.

    let mut json_file =
        File::create(path).with_context(|| format!("failed to open {}", path.display()))?;

    let mem_path = path.with_extension("mem");
    let mut mem_file = File::create(&mem_path)
        .with_context(|| format!("failed to open {}", mem_path.display()))?;

    snapshot_root.guest_memory_metadata = guest_memory
        .snapshot(&mut mem_file)
        .context("failed to snapshot memory")?;

    for bus in buses {
        snapshot_devices(bus, |id, snapshot| {
            snapshot_root.devices.push([(id, snapshot)].into())
        })
        .context("failed to snapshot devices")?;
    }

    serde_json::to_writer(&mut json_file, &snapshot_root)?;

    Ok(())
}

async fn restore_handler(
    path: &std::path::Path,
    guest_memory: &GuestMemory,
    buses: &[&Bus],
) -> anyhow::Result<()> {
    let file = File::open(path).with_context(|| format!("failed to open {}", path.display()))?;

    let mem_path = path.with_extension("mem");
    let mut mem_file =
        File::open(&mem_path).with_context(|| format!("failed to open {}", mem_path.display()))?;

    let snapshot_root: SnapshotRoot = serde_json::from_reader(file)?;

    let mut devices_map: HashMap<u32, VecDeque<serde_json::Value>> = HashMap::new();
    for (id, device) in snapshot_root.devices.into_iter().flatten() {
        devices_map.entry(id).or_default().push_back(device)
    }

    {
        guest_memory.restore(snapshot_root.guest_memory_metadata, &mut mem_file)?;

        for bus in buses {
            restore_devices(bus, &mut devices_map)?;
        }
    }

    for (key, _) in devices_map.iter().filter(|(_, v)| !v.is_empty()) {
        info!(
            "Unused restore data for device_id {}, device might be missing.",
            key
        );
    }

    Ok(())
}

async fn handle_command_tube(
    command_tube: AsyncTube,
    guest_memory: GuestMemory,
    io_bus: Arc<Bus>,
    mmio_bus: Arc<Bus>,
) -> anyhow::Result<()> {
    let buses = &[&*io_bus, &*mmio_bus];
    let mut _sleep_guard = None;
    loop {
        match command_tube.next().await {
            Ok(command) => {
                match command {
                    DeviceControlCommand::SleepDevices => match SleepGuard::new(buses) {
                        Ok(guard) => {
                            _sleep_guard = Some(guard);
                            command_tube
                                .send(VmResponse::Ok)
                                .await
                                .context("failed to reply to sleep command")?;
                        }
                        Err(e) => {
                            error!("failed to sleep: {:#}", e);
                            command_tube
                                .send(VmResponse::ErrString(e.to_string()))
                                .await
                                .context("failed to send response.")?;
                        }
                    },
                    DeviceControlCommand::WakeDevices => {
                        _sleep_guard = None;
                        command_tube
                            .send(VmResponse::Ok)
                            .await
                            .context("failed to reply to wake devices request")?;
                    }
                    DeviceControlCommand::SnapshotDevices {
                        snapshot_path: path,
                    } => {
                        assert!(
                            _sleep_guard.is_some(),
                            "devices must be sleeping to snapshot"
                        );
                        if let Err(e) = snapshot_handler(path.as_path(), &guest_memory, buses).await
                        {
                            error!("failed to snapshot: {:#}", e);
                            command_tube
                                .send(VmResponse::ErrString(e.to_string()))
                                .await
                                .context("Failed to send response")?;
                            continue;
                        }
                        command_tube
                            .send(VmResponse::Ok)
                            .await
                            .context("Failed to send response")?;
                    }
                    DeviceControlCommand::RestoreDevices { restore_path: path } => {
                        assert!(
                            _sleep_guard.is_some(),
                            "devices must be sleeping to restore"
                        );
                        if let Err(e) =
                            restore_handler(path.as_path(), &guest_memory, &[&*io_bus, &*mmio_bus])
                                .await
                        {
                            error!("failed to restore: {:#}", e);
                            command_tube
                                .send(VmResponse::ErrString(e.to_string()))
                                .await
                                .context("Failed to send response")?;
                            continue;
                        }
                        command_tube
                            .send(VmResponse::Ok)
                            .await
                            .context("Failed to send response")?;
                    }
                    DeviceControlCommand::GetDevicesState => {
                        let state = if _sleep_guard.is_some() {
                            DevicesState::Sleep
                        } else {
                            DevicesState::Wake
                        };
                        command_tube
                            .send(VmResponse::DevicesState(state))
                            .await
                            .context("failed to send response")?;
                    }
                    DeviceControlCommand::Exit => {
                        return Ok(());
                    }
                };
            }
            Err(e) => {
                if matches!(e, TubeError::Disconnected) {
                    // Tube disconnected - shut down thread.
                    return Ok(());
                }
                return Err(anyhow!("Failed to receive: {}", e));
            }
        }
    }
}
