// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::read;
#[cfg(feature = "direct")]
use std::fs::read_to_string;
use std::fs::write;
use std::fs::File;
use std::fs::OpenOptions;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use base::error;
#[cfg(feature = "direct")]
use base::warn;
use base::Tube;
use data_model::DataInit;
use sync::Mutex;
use vm_control::HotPlugDeviceInfo;
use vm_control::HotPlugDeviceType;
use vm_control::VmRequest;
use vm_control::VmResponse;

use crate::pci::pci_configuration::PciBridgeSubclass;
use crate::pci::pci_configuration::CAPABILITY_LIST_HEAD_OFFSET;
#[cfg(feature = "direct")]
use crate::pci::pci_configuration::CLASS_REG;
#[cfg(feature = "direct")]
use crate::pci::pci_configuration::CLASS_REG_REVISION_ID_OFFSET;
use crate::pci::pci_configuration::HEADER_TYPE_REG;
use crate::pci::pci_configuration::PCI_CAP_NEXT_POINTER;
use crate::pci::pcie::pci_bridge::PciBridgeBusRange;
use crate::pci::pcie::pci_bridge::BR_BUS_NUMBER_REG;
use crate::pci::pcie::pci_bridge::BR_MEM_BASE_MASK;
use crate::pci::pcie::pci_bridge::BR_MEM_BASE_SHIFT;
use crate::pci::pcie::pci_bridge::BR_MEM_LIMIT_MASK;
use crate::pci::pcie::pci_bridge::BR_MEM_MINIMUM;
use crate::pci::pcie::pci_bridge::BR_MEM_REG;
use crate::pci::pcie::pci_bridge::BR_PREF_MEM_64BIT;
use crate::pci::pcie::pci_bridge::BR_PREF_MEM_BASE_HIGH_REG;
use crate::pci::pcie::pci_bridge::BR_PREF_MEM_LIMIT_HIGH_REG;
use crate::pci::pcie::pci_bridge::BR_PREF_MEM_LOW_REG;
use crate::pci::pcie::pci_bridge::BR_WINDOW_ALIGNMENT;
use crate::pci::pcie::PcieDevicePortType;
use crate::pci::PciCapabilityID;
use crate::pci::PciClassCode;

// Host Pci device's sysfs config file
struct PciHostConfig {
    config_file: File,
}

impl PciHostConfig {
    // Create a new host pci device's sysfs config file
    fn new(host_sysfs_path: &Path) -> Result<Self> {
        let mut config_path = PathBuf::new();
        config_path.push(host_sysfs_path);
        config_path.push("config");
        let f = OpenOptions::new()
            .write(true)
            .read(true)
            .open(config_path.as_path())
            .with_context(|| format!("failed to open: {}", config_path.display()))?;
        Ok(PciHostConfig { config_file: f })
    }

    // Read host pci device's config register
    fn read_config<T: DataInit>(&self, offset: u64) -> T {
        let length = std::mem::size_of::<T>();
        let mut buf = vec![0u8; length];
        if offset % length as u64 != 0 {
            error!(
                "read_config, offset {} isn't aligned to length {}",
                offset, length
            );
        } else if let Err(e) = self.config_file.read_exact_at(&mut buf, offset) {
            error!("failed to read host sysfs config: {}", e);
        }

        T::from_slice(&buf)
            .copied()
            .expect("failed to convert host sysfs config data from slice")
    }

    // write host pci device's config register
    #[allow(dead_code)]
    fn write_config(&self, offset: u64, data: &[u8]) {
        if offset % data.len() as u64 != 0 {
            error!(
                "write_config, offset {} isn't aligned to length {}",
                offset,
                data.len()
            );
            return;
        }
        if let Err(e) = self.config_file.write_all_at(data, offset) {
            error!("failed to write host sysfs config: {}", e);
        }
    }
}

// Find all the added pcie devices
fn visit_children(dir: &Path, children: &mut Vec<HotPlugDeviceInfo>) -> Result<()> {
    // Each pci device has a sysfs directory
    if !dir.is_dir() {
        bail!("{} isn't directory", dir.display());
    }
    // Loop device sysfs subdirectory
    let entries = dir
        .read_dir()
        .with_context(|| format!("failed to read dir {}", dir.display()))?;
    let mut devices = Vec::new();
    for entry in entries {
        let sub_dir = match entry {
            Ok(sub) => sub,
            _ => continue,
        };

        if !sub_dir.path().is_dir() {
            continue;
        }

        let name = sub_dir
            .file_name()
            .into_string()
            .map_err(|_| anyhow!("failed to get dir name"))?;
        // Child pci device has name format 0000:xx:xx.x, length is 12
        if name.len() != 12 || !name.starts_with("0000:") {
            continue;
        }
        let child_path = dir.join(name);
        devices.push(child_path);
    }
    devices.reverse();
    let mut iter = devices.iter().peekable();
    while let Some(device) = iter.next() {
        let class_path = device.join("class");
        let class_id = read(class_path.as_path())
            .with_context(|| format!("failed to read {}", class_path.display()))?;
        let hp_interrupt = iter.peek().is_none();
        if !class_id.starts_with("0x0604".as_bytes()) {
            // If the device isn't pci bridge, this is a pcie endpoint device
            children.push(HotPlugDeviceInfo {
                device_type: HotPlugDeviceType::EndPoint,
                path: device.to_path_buf(),
                hp_interrupt,
            });
            // No need to look further
            return Ok(());
        } else {
            // Find the pci express cap to get the port type of the pcie bridge
            let host_config = PciHostConfig::new(device)?;
            let mut cap_pointer: u8 = host_config.read_config(CAPABILITY_LIST_HEAD_OFFSET as u64);
            while cap_pointer != 0x0 {
                let cap_id: u8 = host_config.read_config(cap_pointer as u64);
                if cap_id == PciCapabilityID::PciExpress as u8 {
                    break;
                }
                cap_pointer = host_config.read_config(cap_pointer as u64 + 0x1);
            }
            if cap_pointer == 0x0 {
                bail!(
                    "Failed to get pcie express capability for {}",
                    device.display()
                );
            }
            let express_cap_reg: u16 = host_config.read_config(cap_pointer as u64 + 0x2);
            match (express_cap_reg & 0xf0) >> 4 {
                x if x == PcieDevicePortType::UpstreamPort as u16 => {
                    children.push(HotPlugDeviceInfo {
                        device_type: HotPlugDeviceType::UpstreamPort,
                        path: device.to_path_buf(),
                        hp_interrupt,
                    })
                }
                x if x == PcieDevicePortType::DownstreamPort as u16 => {
                    children.push(HotPlugDeviceInfo {
                        device_type: HotPlugDeviceType::DownstreamPort,
                        path: device.to_path_buf(),
                        hp_interrupt,
                    })
                }
                _ => (),
            }
        }
    }
    for device in devices.iter() {
        visit_children(device.as_path(), children)?;
    }
    Ok(())
}

struct HotplugWorker {
    host_name: String,
}

impl HotplugWorker {
    fn run(&self, vm_socket: Arc<Mutex<Tube>>, child_exist: Arc<Mutex<bool>>) -> Result<()> {
        let mut host_sysfs = PathBuf::new();
        host_sysfs.push("/sys/bus/pci/devices/");
        host_sysfs.push(self.host_name.clone());
        let rescan_path = host_sysfs.join("rescan");
        // Let pcie root port rescan to find the added or removed children devices
        write(rescan_path.as_path(), "1")
            .with_context(|| format!("failed to write {}", rescan_path.display()))?;

        // If child device existed, but code run here again, this means host has a
        // hotplug out event, after the above rescan, host should find the removed
        // child device, and host vfio-pci kernel driver should notify crosvm vfio-pci
        // devie such hotplug out event, so nothing is needed to do here, just return
        // it now.
        let mut child_exist = child_exist.lock();
        if *child_exist {
            return Ok(());
        }

        // Probe the new added pcie endpoint devices
        let mut children: Vec<HotPlugDeviceInfo> = Vec::new();
        visit_children(host_sysfs.as_path(), &mut children)?;

        // Without reverse children, physical larger BDF device is at the top, it will be
        // added into guest first with smaller virtual function number, so physical smaller
        // BDF device has larger virtual function number, phyiscal larger BDF device has
        // smaller virtual function number. During hotplug out process, host pcie root port
        // driver remove physical smaller BDF pcie endpoint device first, so host vfio-pci
        // driver send plug out event first for smaller BDF device and wait for this device
        // removed from crosvm, when crosvm receives this plug out event, crosvm will remove
        // all the children devices, crosvm remove smaller virtual function number device
        // first, this isn't the target device which host vfio-pci driver is waiting for.
        // Host vfio-pci driver holds a lock when it is waiting, when crosvm remove another
        // device throgh vfio-pci which try to get the same lock, so deadlock happens in
        // host kernel.
        //
        // In order to fix the deadlock, children is reversed, so physical smaller BDF
        // device has smaller virtual function number, and it will have the same order
        // between host kernel and crosvm during hotplug out process.
        children.reverse();
        while let Some(child) = children.pop() {
            if let HotPlugDeviceType::EndPoint = child.device_type {
                // In order to bind device to vfio-pci driver, get device VID and DID
                let vendor_path = child.path.join("vendor");
                let vendor_id = read(vendor_path.as_path())
                    .with_context(|| format!("failed to read {}", vendor_path.display()))?;
                // Remove the first two elements 0x
                let prefix: &str = "0x";
                let vendor = match vendor_id.strip_prefix(prefix.as_bytes()) {
                    Some(v) => v.to_vec(),
                    None => vendor_id,
                };
                let device_path = child.path.join("device");
                let device_id = read(device_path.as_path())
                    .with_context(|| format!("failed to read {}", device_path.display()))?;
                // Remove the first two elements 0x
                let device = match device_id.strip_prefix(prefix.as_bytes()) {
                    Some(d) => d.to_vec(),
                    None => device_id,
                };
                let new_id = vec![
                    String::from_utf8_lossy(&vendor),
                    String::from_utf8_lossy(&device),
                ]
                .join(" ");
                if Path::new("/sys/bus/pci/drivers/vfio-pci-pm/new_id").exists() {
                    let _ = write("/sys/bus/pci/drivers/vfio-pci-pm/new_id", &new_id);
                }
                // This is normal - either the kernel doesn't support vfio-pci-pm driver,
                // or the device failed to attach to vfio-pci-pm driver (most likely due to
                // lack of power management capability).
                if !child.path.join("driver/unbind").exists() {
                    write("/sys/bus/pci/drivers/vfio-pci/new_id", &new_id).with_context(|| {
                        format!("failed to write {} into vfio-pci/new_id", new_id)
                    })?;
                }
            }
            // Request to hotplug the new added pcie device into guest
            let request = VmRequest::HotPlugCommand {
                device: child.clone(),
                add: true,
            };
            let vm_socket = vm_socket.lock();
            vm_socket
                .send(&request)
                .with_context(|| format!("failed to send hotplug request for {:?}", child))?;
            let response = vm_socket
                .recv::<VmResponse>()
                .with_context(|| format!("failed to receive hotplug response for {:?}", child))?;
            match response {
                VmResponse::Ok => {}
                _ => bail!("unexpected hotplug response: {response}"),
            };
            if !*child_exist {
                *child_exist = true;
            }
        }

        Ok(())
    }
}

const PCI_CONFIG_DEVICE_ID: u64 = 0x02;
const PCI_BASE_CLASS_CODE: u64 = 0x0B;
const PCI_SUB_CLASS_CODE: u64 = 0x0A;

/// Pcie root port device has a corresponding host pcie root port.
pub struct PcieHostPort {
    host_config: PciHostConfig,
    host_name: String,
    hotplug_in_process: Arc<Mutex<bool>>,
    hotplug_child_exist: Arc<Mutex<bool>>,
    vm_socket: Arc<Mutex<Tube>>,
    #[cfg(feature = "direct")]
    sysfs_path: Option<PathBuf>,
    #[cfg(feature = "direct")]
    header_type_reg: Option<u32>,
}

impl PcieHostPort {
    /// Create PcieHostPort, host_syfsfs_patch specify host pcie port
    /// sysfs path.
    pub fn new(host_sysfs_path: &Path, socket: Tube) -> Result<Self> {
        let host_config = PciHostConfig::new(host_sysfs_path)?;
        let host_name = host_sysfs_path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let base_class: u8 = host_config.read_config(PCI_BASE_CLASS_CODE);
        if base_class != PciClassCode::BridgeDevice.get_register_value() {
            return Err(anyhow!("host {} isn't bridge", host_name));
        }
        let sub_class: u8 = host_config.read_config(PCI_SUB_CLASS_CODE);
        if sub_class != PciBridgeSubclass::PciToPciBridge as u8 {
            return Err(anyhow!("host {} isn't pci to pci bridge", host_name));
        }

        let mut pcie_cap_reg: u8 = 0;

        let mut cap_next: u8 = host_config.read_config(CAPABILITY_LIST_HEAD_OFFSET as u64);
        let mut counter: u16 = 0;
        while cap_next != 0 && counter < 256 {
            let cap_id: u8 = host_config.read_config(cap_next.into());
            if cap_id == PciCapabilityID::PciExpress as u8 {
                pcie_cap_reg = cap_next;
                break;
            }
            let offset = cap_next as u64 + PCI_CAP_NEXT_POINTER as u64;
            cap_next = host_config.read_config(offset);
            counter += 1;
        }

        if pcie_cap_reg == 0 {
            return Err(anyhow!("host {} isn't pcie device", host_name));
        }

        #[cfg(feature = "direct")]
        let (sysfs_path, header_type_reg) =
            match PcieHostPort::coordinated_pm(host_sysfs_path, true) {
                Ok(_) => {
                    // Cache the dword at offset 0x0c (cacheline size, latency timer,
                    // header type, BIST).
                    // When using the "direct" feature, this dword can be accessed for
                    // device power state. Directly accessing a device's physical PCI
                    // config space in D3cold state causes a hang. We treat the cacheline
                    // size, latency timer and header type field as immutable in the
                    // guest.
                    let reg: u32 = host_config.read_config((HEADER_TYPE_REG as u64) * 4);
                    (Some(host_sysfs_path.to_path_buf()), Some(reg))
                }
                Err(e) => {
                    warn!("coordinated_pm not supported: {}", e);
                    (None, None)
                }
            };

        Ok(PcieHostPort {
            host_config,
            host_name,
            hotplug_in_process: Arc::new(Mutex::new(false)),
            hotplug_child_exist: Arc::new(Mutex::new(false)),
            vm_socket: Arc::new(Mutex::new(socket)),
            #[cfg(feature = "direct")]
            sysfs_path,
            #[cfg(feature = "direct")]
            header_type_reg,
        })
    }

    pub fn get_bus_range(&self) -> PciBridgeBusRange {
        let bus_num: u32 = self.host_config.read_config((BR_BUS_NUMBER_REG * 4) as u64);
        let primary = (bus_num & 0xFF) as u8;
        let secondary = ((bus_num >> 8) & 0xFF) as u8;
        let subordinate = ((bus_num >> 16) & 0xFF) as u8;

        PciBridgeBusRange {
            primary,
            secondary,
            subordinate,
        }
    }

    pub fn read_device_id(&self) -> u16 {
        self.host_config.read_config::<u16>(PCI_CONFIG_DEVICE_ID)
    }

    pub fn host_name(&self) -> String {
        self.host_name.clone()
    }

    pub fn read_config(&self, reg_idx: usize, data: &mut u32) {
        if reg_idx == HEADER_TYPE_REG {
            #[cfg(feature = "direct")]
            if let Some(header_type_reg) = self.header_type_reg {
                let mut v = header_type_reg.to_le_bytes();
                // HACK
                // Reads from the "BIST" register are interpreted as device
                // PCI power state
                v[3] = self.power_state().unwrap_or_else(|e| {
                    error!("Failed to get device power state: {}", e);
                    5 // unknown state
                });
                *data = u32::from_le_bytes(v);
                return;
            }
            *data = self.host_config.read_config((HEADER_TYPE_REG as u64) * 4)
        }
    }

    #[allow(unused_variables)]
    pub fn write_config(&mut self, reg_idx: usize, offset: u64, data: &[u8]) {
        #[cfg(feature = "direct")]
        if self.sysfs_path.is_some()
            && reg_idx == CLASS_REG
            && offset == CLASS_REG_REVISION_ID_OFFSET as u64
            && data.len() == 1
        {
            // HACK
            // Byte writes to the "Revision ID" register are interpreted as PM
            // op calls
            if let Err(e) = self.op_call(data[0]) {
                error!("Failed to perform op call: {}", e);
            }
        }
    }

    pub fn get_bridge_window_size(&self) -> (u64, u64) {
        let br_memory: u32 = self.host_config.read_config(BR_MEM_REG as u64 * 4);
        let mem_base = (br_memory & BR_MEM_BASE_MASK) << BR_MEM_BASE_SHIFT;
        let mem_limit = br_memory & BR_MEM_LIMIT_MASK;
        let mem_size = if mem_limit > mem_base {
            (mem_limit - mem_base) as u64 + BR_WINDOW_ALIGNMENT
        } else {
            BR_MEM_MINIMUM
        };
        let br_pref_mem_low: u32 = self.host_config.read_config(BR_PREF_MEM_LOW_REG as u64 * 4);
        let pref_mem_base_low = (br_pref_mem_low & BR_MEM_BASE_MASK) << BR_MEM_BASE_SHIFT;
        let pref_mem_limit_low = br_pref_mem_low & BR_MEM_LIMIT_MASK;
        let mut pref_mem_base: u64 = pref_mem_base_low as u64;
        let mut pref_mem_limit: u64 = pref_mem_limit_low as u64;
        if br_pref_mem_low & BR_PREF_MEM_64BIT == BR_PREF_MEM_64BIT {
            // 64bit prefetch memory
            let pref_mem_base_high: u32 = self
                .host_config
                .read_config(BR_PREF_MEM_BASE_HIGH_REG as u64 * 4);
            let pref_mem_limit_high: u32 = self
                .host_config
                .read_config(BR_PREF_MEM_LIMIT_HIGH_REG as u64 * 4);
            pref_mem_base = ((pref_mem_base_high as u64) << 32) | (pref_mem_base_low as u64);
            pref_mem_limit = ((pref_mem_limit_high as u64) << 32) | (pref_mem_limit_low as u64);
        }
        let pref_mem_size = if pref_mem_limit > pref_mem_base {
            pref_mem_limit - pref_mem_base + BR_WINDOW_ALIGNMENT
        } else {
            BR_MEM_MINIMUM
        };

        (mem_size, pref_mem_size)
    }

    pub fn hotplug_probe(&mut self) {
        if *self.hotplug_in_process.lock() {
            return;
        }

        let hotplug_process = self.hotplug_in_process.clone();
        let child_exist = self.hotplug_child_exist.clone();
        let socket = self.vm_socket.clone();
        let name = self.host_name.clone();
        let _ = thread::Builder::new()
            .name("pcie_hotplug".to_string())
            .spawn(move || {
                let mut hotplug = hotplug_process.lock();
                *hotplug = true;
                let hotplug_worker = HotplugWorker { host_name: name };
                let _ = hotplug_worker.run(socket, child_exist);
                *hotplug = false;
            });
    }

    pub fn hot_unplug(&mut self) {
        *self.hotplug_child_exist.lock() = false;
    }

    #[cfg(feature = "direct")]
    fn coordinated_pm(host_sysfs_path: &Path, enter: bool) -> Result<()> {
        let path = Path::new(host_sysfs_path).join("power/coordinated");
        write(&path, if enter { "enter\n" } else { "exit\n" })
            .with_context(|| format!("Failed to write to {}", path.to_string_lossy()))
    }

    #[cfg(feature = "direct")]
    fn power_state(&self) -> Result<u8> {
        let path = Path::new(&self.sysfs_path.as_ref().unwrap()).join("power_state");
        let state = read_to_string(&path)
            .with_context(|| format!("Failed to read from {}", path.to_string_lossy()))?;
        match state.as_str() {
            "D0\n" => Ok(0),
            "D1\n" => Ok(1),
            "D2\n" => Ok(2),
            "D3hot\n" => Ok(3),
            "D3cold\n" => Ok(4),
            "unknown\n" => Ok(5),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid state",
            ))?,
        }
    }

    #[cfg(feature = "direct")]
    fn op_call(&self, id: u8) -> Result<()> {
        let path = Path::new(self.sysfs_path.as_ref().unwrap()).join("power/op_call");
        write(&path, &[id])
            .with_context(|| format!("Failed to write to {}", path.to_string_lossy()))
    }
}

#[cfg(feature = "direct")]
impl Drop for PcieHostPort {
    fn drop(&mut self) {
        if self.sysfs_path.is_some() {
            let _ = PcieHostPort::coordinated_pm(self.sysfs_path.as_ref().unwrap(), false);
        }
    }
}
