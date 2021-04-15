// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use data_model::vec_with_array_field;
use std::collections::HashMap;
use std::ffi::CString;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io;
use std::mem;
use std::os::unix::prelude::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::u32;
use sync::Mutex;

use base::{
    ioctl, ioctl_with_mut_ref, ioctl_with_ptr, ioctl_with_ref, ioctl_with_val, warn,
    AsRawDescriptor, Error, Event, FromRawDescriptor, RawDescriptor, SafeDescriptor,
};
use hypervisor::{DeviceKind, Vm};
use vm_memory::GuestMemory;

use vfio_sys::*;

#[derive(Debug)]
pub enum VfioError {
    OpenContainer(io::Error),
    OpenGroup(io::Error),
    GetGroupStatus(Error),
    GroupViable,
    VfioApiVersion,
    VfioType1V2,
    GroupSetContainer(Error),
    ContainerSetIOMMU(Error),
    GroupGetDeviceFD(Error),
    CreateVfioKvmDevice(Error),
    KvmSetDeviceAttr(Error),
    VfioDeviceGetInfo(Error),
    VfioDeviceGetRegionInfo(Error),
    InvalidPath,
    IommuDmaMap(Error),
    IommuDmaUnmap(Error),
    VfioIrqEnable(Error),
    VfioIrqDisable(Error),
    VfioIrqUnmask(Error),
    VfioIrqMask(Error),
}

impl fmt::Display for VfioError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VfioError::OpenContainer(e) => write!(f, "failed to open /dev/vfio/vfio container: {}", e),
            VfioError::OpenGroup(e) => write!(f, "failed to open /dev/vfio/$group_num group: {}", e),
            VfioError::GetGroupStatus(e) => write!(f, "failed to get Group Status: {}", e),
            VfioError::GroupViable => write!(f, "group is inviable"),
            VfioError::VfioApiVersion => write!(f, "vfio API version doesn't match with VFIO_API_VERSION defined in vfio_sys/srv/vfio.rs"),
            VfioError::VfioType1V2 => write!(f, "container dones't support VfioType1V2 IOMMU driver type"),
            VfioError::GroupSetContainer(e) => write!(f, "failed to add vfio group into vfio container: {}", e),
            VfioError::ContainerSetIOMMU(e) => write!(f, "failed to set container's IOMMU driver type as VfioType1V2: {}", e),
            VfioError::GroupGetDeviceFD(e) => write!(f, "failed to get vfio device fd: {}", e),
            VfioError::CreateVfioKvmDevice(e) => write!(f, "failed to create KVM vfio device: {}", e),
            VfioError::KvmSetDeviceAttr(e) => write!(f, "failed to set KVM vfio device's attribute: {}", e),
            VfioError::VfioDeviceGetInfo(e) => write!(f, "failed to get vfio device's info or info doesn't match: {}", e),
            VfioError::VfioDeviceGetRegionInfo(e) => write!(f, "failed to get vfio device's region info: {}", e),
            VfioError::InvalidPath => write!(f,"invalid file path"),
            VfioError::IommuDmaMap(e) => write!(f, "failed to add guest memory map into iommu table: {}", e),
            VfioError::IommuDmaUnmap(e) => write!(f, "failed to remove guest memory map from iommu table: {}", e),
            VfioError::VfioIrqEnable(e) => write!(f, "failed to enable vfio deviece's irq: {}", e),
            VfioError::VfioIrqDisable(e) => write!(f, "failed to disable vfio deviece's irq: {}", e),
            VfioError::VfioIrqUnmask(e) => write!(f, "failed to unmask vfio deviece's irq: {}", e),
            VfioError::VfioIrqMask(e) => write!(f, "failed to mask vfio deviece's irq: {}", e),
        }
    }
}

fn get_error() -> Error {
    Error::last()
}

/// VfioContainer contain multi VfioGroup, and delegate an IOMMU domain table
pub struct VfioContainer {
    container: File,
    kvm_vfio_dev: Option<SafeDescriptor>,
    groups: HashMap<u32, Arc<VfioGroup>>,
}

const VFIO_API_VERSION: u8 = 0;
impl VfioContainer {
    /// Open VfioContainer
    pub fn new() -> Result<Self, VfioError> {
        let container = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/vfio/vfio")
            .map_err(VfioError::OpenContainer)?;

        // Safe as file is vfio container descriptor and ioctl is defined by kernel.
        let version = unsafe { ioctl(&container, VFIO_GET_API_VERSION()) };
        if version as u8 != VFIO_API_VERSION {
            return Err(VfioError::VfioApiVersion);
        }

        Ok(VfioContainer {
            container,
            kvm_vfio_dev: None,
            groups: HashMap::new(),
        })
    }

    fn check_extension(&self, val: u32) -> bool {
        if val != VFIO_TYPE1_IOMMU && val != VFIO_TYPE1v2_IOMMU {
            panic!("IOMMU type error");
        }

        // Safe as file is vfio container and make sure val is valid.
        let ret = unsafe { ioctl_with_val(self, VFIO_CHECK_EXTENSION(), val.into()) };
        ret == 1
    }

    fn set_iommu(&self, val: u32) -> i32 {
        if val != VFIO_TYPE1_IOMMU && val != VFIO_TYPE1v2_IOMMU {
            panic!("IOMMU type error");
        }

        // Safe as file is vfio container and make sure val is valid.
        unsafe { ioctl_with_val(self, VFIO_SET_IOMMU(), val.into()) }
    }

    unsafe fn vfio_dma_map(&self, iova: u64, size: u64, user_addr: u64) -> Result<(), VfioError> {
        let dma_map = vfio_iommu_type1_dma_map {
            argsz: mem::size_of::<vfio_iommu_type1_dma_map>() as u32,
            flags: VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE,
            vaddr: user_addr,
            iova,
            size,
        };

        let ret = ioctl_with_ref(self, VFIO_IOMMU_MAP_DMA(), &dma_map);
        if ret != 0 {
            return Err(VfioError::IommuDmaMap(get_error()));
        }

        Ok(())
    }

    fn vfio_dma_unmap(&self, iova: u64, size: u64) -> Result<(), VfioError> {
        let mut dma_unmap = vfio_iommu_type1_dma_unmap {
            argsz: mem::size_of::<vfio_iommu_type1_dma_unmap>() as u32,
            flags: 0,
            iova,
            size,
        };

        // Safe as file is vfio container, dma_unmap is constructed by us, and
        // we check the return value
        let ret = unsafe { ioctl_with_mut_ref(self, VFIO_IOMMU_UNMAP_DMA(), &mut dma_unmap) };
        if ret != 0 || dma_unmap.size != size {
            return Err(VfioError::IommuDmaUnmap(get_error()));
        }

        Ok(())
    }

    fn init(&mut self, vm: &impl Vm, guest_mem: &GuestMemory) -> Result<(), VfioError> {
        if !self.check_extension(VFIO_TYPE1v2_IOMMU) {
            return Err(VfioError::VfioType1V2);
        }

        if self.set_iommu(VFIO_TYPE1v2_IOMMU) < 0 {
            return Err(VfioError::ContainerSetIOMMU(get_error()));
        }

        // Add all guest memory regions into vfio container's iommu table,
        // then vfio kernel driver could access guest memory from gfn
        guest_mem.with_regions(|_index, guest_addr, size, host_addr, _mmap, _fd_offset| {
            // Safe because the guest regions are guaranteed not to overlap
            unsafe { self.vfio_dma_map(guest_addr.0, size as u64, host_addr as u64) }
        })?;

        let vfio_descriptor = vm
            .create_device(DeviceKind::Vfio)
            .map_err(VfioError::CreateVfioKvmDevice)?;
        self.kvm_vfio_dev = Some(vfio_descriptor);

        Ok(())
    }

    fn get_group(
        &mut self,
        id: u32,
        vm: &impl Vm,
        guest_mem: &GuestMemory,
    ) -> Result<Arc<VfioGroup>, VfioError> {
        match self.groups.get(&id) {
            Some(group) => Ok(group.clone()),
            None => {
                let group = Arc::new(VfioGroup::new(self, id)?);

                if self.groups.is_empty() {
                    // Before the first group is added into container, do once cotainer
                    // initialize for a vm
                    self.init(vm, guest_mem)?;
                }

                let kvm_vfio_file = self
                    .kvm_vfio_dev
                    .as_ref()
                    .expect("kvm vfio device should exist");
                group.kvm_device_add_group(kvm_vfio_file)?;

                self.groups.insert(id, group.clone());

                Ok(group)
            }
        }
    }
}

impl AsRawDescriptor for VfioContainer {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.container.as_raw_descriptor()
    }
}

struct VfioGroup {
    group: File,
}

impl VfioGroup {
    fn new(container: &VfioContainer, id: u32) -> Result<Self, VfioError> {
        let mut group_path = String::from("/dev/vfio/");
        let s_id = &id;
        group_path.push_str(s_id.to_string().as_str());

        let group_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(Path::new(&group_path))
            .map_err(VfioError::OpenGroup)?;

        let mut group_status = vfio_group_status {
            argsz: mem::size_of::<vfio_group_status>() as u32,
            flags: 0,
        };
        // Safe as we are the owner of group_file and group_status which are valid value.
        let mut ret =
            unsafe { ioctl_with_mut_ref(&group_file, VFIO_GROUP_GET_STATUS(), &mut group_status) };
        if ret < 0 {
            return Err(VfioError::GetGroupStatus(get_error()));
        }

        if group_status.flags != VFIO_GROUP_FLAGS_VIABLE {
            return Err(VfioError::GroupViable);
        }

        // Safe as we are the owner of group_file and container_raw_descriptor which are valid value,
        // and we verify the ret value
        let container_raw_descriptor = container.as_raw_descriptor();
        ret = unsafe {
            ioctl_with_ref(
                &group_file,
                VFIO_GROUP_SET_CONTAINER(),
                &container_raw_descriptor,
            )
        };
        if ret < 0 {
            return Err(VfioError::GroupSetContainer(get_error()));
        }

        Ok(VfioGroup { group: group_file })
    }

    fn kvm_device_add_group(&self, kvm_vfio_file: &SafeDescriptor) -> Result<(), VfioError> {
        let group_descriptor = self.as_raw_descriptor();
        let group_descriptor_ptr = &group_descriptor as *const i32;
        let vfio_dev_attr = kvm_sys::kvm_device_attr {
            flags: 0,
            group: kvm_sys::KVM_DEV_VFIO_GROUP,
            attr: kvm_sys::KVM_DEV_VFIO_GROUP_ADD as u64,
            addr: group_descriptor_ptr as u64,
        };

        // Safe as we are the owner of vfio_dev_fd and vfio_dev_attr which are valid value,
        // and we verify the return value.
        if 0 != unsafe {
            ioctl_with_ref(
                kvm_vfio_file,
                kvm_sys::KVM_SET_DEVICE_ATTR(),
                &vfio_dev_attr,
            )
        } {
            return Err(VfioError::KvmSetDeviceAttr(get_error()));
        }

        Ok(())
    }

    fn get_device(&self, name: &str) -> Result<File, VfioError> {
        let path: CString = CString::new(name.as_bytes()).expect("CString::new() failed");
        let path_ptr = path.as_ptr();

        // Safe as we are the owner of self and path_ptr which are valid value.
        let ret = unsafe { ioctl_with_ptr(self, VFIO_GROUP_GET_DEVICE_FD(), path_ptr) };
        if ret < 0 {
            return Err(VfioError::GroupGetDeviceFD(get_error()));
        }

        // Safe as ret is valid FD
        Ok(unsafe { File::from_raw_descriptor(ret) })
    }
}

impl AsRawDescriptor for VfioGroup {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.group.as_raw_descriptor()
    }
}

/// Vfio Irq type used to enable/disable/mask/unmask vfio irq
pub enum VfioIrqType {
    Intx,
    Msi,
    Msix,
}

struct VfioRegion {
    // flags for this region: read/write/mmap
    flags: u32,
    size: u64,
    // region offset used to read/write with vfio device descriptor
    offset: u64,
    // vectors for mmap offset and size
    mmaps: Vec<vfio_region_sparse_mmap_area>,
    // type and subtype for cap type
    cap_info: Option<(u32, u32)>,
}

/// Vfio device for exposing regions which could be read/write to kernel vfio device.
pub struct VfioDevice {
    dev: File,
    name: String,
    container: Arc<Mutex<VfioContainer>>,
    group_descriptor: RawDescriptor,
    // vec for vfio device's regions
    regions: Vec<VfioRegion>,
}

impl VfioDevice {
    /// Create a new vfio device, then guest read/write on this device could be
    /// transfered into kernel vfio.
    /// sysfspath specify the vfio device path in sys file system.
    pub fn new(
        sysfspath: &Path,
        vm: &impl Vm,
        guest_mem: &GuestMemory,
        container: Arc<Mutex<VfioContainer>>,
    ) -> Result<Self, VfioError> {
        let mut uuid_path = PathBuf::new();
        uuid_path.push(sysfspath);
        uuid_path.push("iommu_group");
        let group_path = uuid_path.read_link().map_err(|_| VfioError::InvalidPath)?;
        let group_osstr = group_path.file_name().ok_or(VfioError::InvalidPath)?;
        let group_str = group_osstr.to_str().ok_or(VfioError::InvalidPath)?;
        let group_id = group_str
            .parse::<u32>()
            .map_err(|_| VfioError::InvalidPath)?;

        let group = container.lock().get_group(group_id, vm, guest_mem)?;
        let name_osstr = sysfspath.file_name().ok_or(VfioError::InvalidPath)?;
        let name_str = name_osstr.to_str().ok_or(VfioError::InvalidPath)?;
        let name = String::from(name_str);
        let dev = group.get_device(&name)?;
        let regions = Self::get_regions(&dev)?;

        Ok(VfioDevice {
            dev,
            name,
            container,
            group_descriptor: group.as_raw_descriptor(),
            regions,
        })
    }

    /// Returns PCI device name, formatted as BUS:DEVICE.FUNCTION string.
    pub fn device_name(&self) -> &String {
        &self.name
    }

    /// Enable vfio device's irq and associate Irqfd Event with device.
    /// When MSIx is enabled, multi vectors will be supported, so descriptors is vector and the vector
    /// length is the num of MSIx vectors
    pub fn irq_enable(&self, descriptors: Vec<&Event>, index: u32) -> Result<(), VfioError> {
        let count = descriptors.len();
        let u32_size = mem::size_of::<u32>();
        let mut irq_set = vec_with_array_field::<vfio_irq_set, u32>(count);
        irq_set[0].argsz = (mem::size_of::<vfio_irq_set>() + count * u32_size) as u32;
        irq_set[0].flags = VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER;
        irq_set[0].index = index;
        irq_set[0].start = 0;
        irq_set[0].count = count as u32;

        // irq_set.data could be none, bool or descriptor according to flags, so irq_set.data
        // is u8 default, here irq_set.data is descriptor as u32, so 4 default u8 are combined
        // together as u32. It is safe as enough space is reserved through
        // vec_with_array_field(u32)<count>.
        let mut data = unsafe { irq_set[0].data.as_mut_slice(count * u32_size) };
        for descriptor in descriptors.iter().take(count) {
            let (left, right) = data.split_at_mut(u32_size);
            left.copy_from_slice(&descriptor.as_raw_descriptor().to_ne_bytes()[..]);
            data = right;
        }

        // Safe as we are the owner of self and irq_set which are valid value
        let ret = unsafe { ioctl_with_ref(&self.dev, VFIO_DEVICE_SET_IRQS(), &irq_set[0]) };
        if ret < 0 {
            Err(VfioError::VfioIrqEnable(get_error()))
        } else {
            Ok(())
        }
    }

    /// When intx is enabled, irqfd is used to trigger a level interrupt into guest, resample irqfd
    /// is used to get guest EOI notification.
    /// When host hw generates interrupt, vfio irq handler in host kernel receive and handle it,
    /// this handler disable hw irq first, then trigger irqfd to inject interrupt into guest. When
    /// resample irqfd is triggered by guest EOI, vfio kernel could enable hw irq, so hw could
    /// generate another interrupts.
    /// This function enable resample irqfd and let vfio kernel could get EOI notification.
    ///
    /// descriptor: should be resample IrqFd.
    pub fn resample_virq_enable(&self, descriptor: &Event, index: u32) -> Result<(), VfioError> {
        let mut irq_set = vec_with_array_field::<vfio_irq_set, u32>(1);
        irq_set[0].argsz = (mem::size_of::<vfio_irq_set>() + mem::size_of::<u32>()) as u32;
        irq_set[0].flags = VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_UNMASK;
        irq_set[0].index = index;
        irq_set[0].start = 0;
        irq_set[0].count = 1;

        {
            // irq_set.data could be none, bool or descriptor according to flags, so irq_set.data is
            // u8 default, here irq_set.data is descriptor as u32, so 4 default u8 are combined
            // together as u32. It is safe as enough space is reserved through
            // vec_with_array_field(u32)<1>.
            let descriptors = unsafe { irq_set[0].data.as_mut_slice(4) };
            descriptors.copy_from_slice(&descriptor.as_raw_descriptor().to_le_bytes()[..]);
        }

        // Safe as we are the owner of self and irq_set which are valid value
        let ret = unsafe { ioctl_with_ref(&self.dev, VFIO_DEVICE_SET_IRQS(), &irq_set[0]) };
        if ret < 0 {
            Err(VfioError::VfioIrqEnable(get_error()))
        } else {
            Ok(())
        }
    }

    /// disable vfio device's irq and disconnect Irqfd Event with device
    pub fn irq_disable(&self, index: u32) -> Result<(), VfioError> {
        let mut irq_set = vec_with_array_field::<vfio_irq_set, u32>(0);
        irq_set[0].argsz = mem::size_of::<vfio_irq_set>() as u32;
        irq_set[0].flags = VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_ACTION_TRIGGER;
        irq_set[0].index = index;
        irq_set[0].start = 0;
        irq_set[0].count = 0;

        // Safe as we are the owner of self and irq_set which are valid value
        let ret = unsafe { ioctl_with_ref(&self.dev, VFIO_DEVICE_SET_IRQS(), &irq_set[0]) };
        if ret < 0 {
            Err(VfioError::VfioIrqDisable(get_error()))
        } else {
            Ok(())
        }
    }

    /// Unmask vfio device irq
    pub fn irq_unmask(&self, index: u32) -> Result<(), VfioError> {
        let mut irq_set = vec_with_array_field::<vfio_irq_set, u32>(0);
        irq_set[0].argsz = mem::size_of::<vfio_irq_set>() as u32;
        irq_set[0].flags = VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_ACTION_UNMASK;
        irq_set[0].index = index;
        irq_set[0].start = 0;
        irq_set[0].count = 1;

        // Safe as we are the owner of self and irq_set which are valid value
        let ret = unsafe { ioctl_with_ref(&self.dev, VFIO_DEVICE_SET_IRQS(), &irq_set[0]) };
        if ret < 0 {
            Err(VfioError::VfioIrqUnmask(get_error()))
        } else {
            Ok(())
        }
    }

    /// Mask vfio device irq
    pub fn irq_mask(&self, index: u32) -> Result<(), VfioError> {
        let mut irq_set = vec_with_array_field::<vfio_irq_set, u32>(0);
        irq_set[0].argsz = mem::size_of::<vfio_irq_set>() as u32;
        irq_set[0].flags = VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_ACTION_MASK;
        irq_set[0].index = index;
        irq_set[0].start = 0;
        irq_set[0].count = 1;

        // Safe as we are the owner of self and irq_set which are valid value
        let ret = unsafe { ioctl_with_ref(&self.dev, VFIO_DEVICE_SET_IRQS(), &irq_set[0]) };
        if ret < 0 {
            Err(VfioError::VfioIrqMask(get_error()))
        } else {
            Ok(())
        }
    }

    #[allow(clippy::cast_ptr_alignment)]
    fn get_regions(dev: &File) -> Result<Vec<VfioRegion>, VfioError> {
        let mut regions: Vec<VfioRegion> = Vec::new();
        let mut dev_info = vfio_device_info {
            argsz: mem::size_of::<vfio_device_info>() as u32,
            flags: 0,
            num_regions: 0,
            num_irqs: 0,
        };
        // Safe as we are the owner of dev and dev_info which are valid value,
        // and we verify the return value.
        let mut ret = unsafe { ioctl_with_mut_ref(dev, VFIO_DEVICE_GET_INFO(), &mut dev_info) };
        if ret < 0
            || (dev_info.flags & VFIO_DEVICE_FLAGS_PCI) == 0
            || dev_info.num_regions < VFIO_PCI_CONFIG_REGION_INDEX + 1
            || dev_info.num_irqs < VFIO_PCI_MSIX_IRQ_INDEX + 1
        {
            return Err(VfioError::VfioDeviceGetInfo(get_error()));
        }

        for i in VFIO_PCI_BAR0_REGION_INDEX..dev_info.num_regions {
            let argsz = mem::size_of::<vfio_region_info>() as u32;
            let mut reg_info = vfio_region_info {
                argsz,
                flags: 0,
                index: i,
                cap_offset: 0,
                size: 0,
                offset: 0,
            };
            // Safe as we are the owner of dev and reg_info which are valid value,
            // and we verify the return value.
            ret = unsafe { ioctl_with_mut_ref(dev, VFIO_DEVICE_GET_REGION_INFO(), &mut reg_info) };
            if ret < 0 {
                continue;
            }

            let mut mmaps: Vec<vfio_region_sparse_mmap_area> = Vec::new();
            let mut cap_info: Option<(u32, u32)> = None;
            if reg_info.argsz > argsz {
                let cap_len: usize = (reg_info.argsz - argsz) as usize;
                let mut region_with_cap =
                    vec_with_array_field::<vfio_region_info_with_cap, u8>(cap_len);
                region_with_cap[0].region_info.argsz = reg_info.argsz;
                region_with_cap[0].region_info.flags = 0;
                region_with_cap[0].region_info.index = i;
                region_with_cap[0].region_info.cap_offset = 0;
                region_with_cap[0].region_info.size = 0;
                region_with_cap[0].region_info.offset = 0;
                // Safe as we are the owner of dev and region_info which are valid value,
                // and we verify the return value.
                ret = unsafe {
                    ioctl_with_mut_ref(
                        dev,
                        VFIO_DEVICE_GET_REGION_INFO(),
                        &mut (region_with_cap[0].region_info),
                    )
                };
                if ret < 0 {
                    return Err(VfioError::VfioDeviceGetRegionInfo(get_error()));
                }

                if region_with_cap[0].region_info.flags & VFIO_REGION_INFO_FLAG_CAPS == 0 {
                    continue;
                }

                let cap_header_sz = mem::size_of::<vfio_info_cap_header>() as u32;
                let mmap_cap_sz = mem::size_of::<vfio_region_info_cap_sparse_mmap>() as u32;
                let mmap_area_sz = mem::size_of::<vfio_region_sparse_mmap_area>() as u32;
                let type_cap_sz = mem::size_of::<vfio_region_info_cap_type>() as u32;
                let region_info_sz = reg_info.argsz;

                // region_with_cap[0].cap_info may contain many structures, like
                // vfio_region_info_cap_sparse_mmap struct or vfio_region_info_cap_type struct.
                // Both of them begin with vfio_info_cap_header, so we will get individual cap from
                // vfio_into_cap_header.
                // Go through all the cap structs.
                let info_ptr = region_with_cap.as_ptr() as *mut u8;
                let mut offset = region_with_cap[0].region_info.cap_offset;
                while offset != 0 {
                    if offset + cap_header_sz >= region_info_sz {
                        break;
                    }
                    // Safe, as cap_header struct is in this function allocated region_with_cap
                    // vec.
                    let cap_ptr = unsafe { info_ptr.offset(offset as isize) };
                    let cap_header =
                        unsafe { &*(cap_ptr as *mut u8 as *const vfio_info_cap_header) };
                    if cap_header.id as u32 == VFIO_REGION_INFO_CAP_SPARSE_MMAP {
                        if offset + mmap_cap_sz >= region_info_sz {
                            break;
                        }
                        // cap_ptr is vfio_region_info_cap_sparse_mmap here
                        // Safe, this vfio_region_info_cap_sparse_mmap is in this function allocated
                        // region_with_cap vec.
                        let sparse_mmap = unsafe {
                            &*(cap_ptr as *mut u8 as *const vfio_region_info_cap_sparse_mmap)
                        };

                        let area_num = sparse_mmap.nr_areas;
                        if offset + mmap_cap_sz + area_num * mmap_area_sz > region_info_sz {
                            break;
                        }
                        // Safe, these vfio_region_sparse_mmap_area are in this function allocated
                        // region_with_cap vec.
                        let areas =
                            unsafe { sparse_mmap.areas.as_slice(sparse_mmap.nr_areas as usize) };
                        for area in areas.iter() {
                            mmaps.push(*area);
                        }
                    } else if cap_header.id as u32 == VFIO_REGION_INFO_CAP_TYPE {
                        if offset + type_cap_sz > region_info_sz {
                            break;
                        }
                        // cap_ptr is vfio_region_info_cap_type here
                        // Safe, this vfio_region_info_cap_type is in this function allocated
                        // region_with_cap vec
                        let cap_type_info =
                            unsafe { &*(cap_ptr as *mut u8 as *const vfio_region_info_cap_type) };

                        cap_info = Some((cap_type_info.type_, cap_type_info.subtype));
                    }

                    offset = cap_header.next;
                }
            } else if reg_info.flags & VFIO_REGION_INFO_FLAG_MMAP != 0 {
                mmaps.push(vfio_region_sparse_mmap_area {
                    offset: 0,
                    size: reg_info.size,
                });
            }

            let region = VfioRegion {
                flags: reg_info.flags,
                size: reg_info.size,
                offset: reg_info.offset,
                mmaps,
                cap_info,
            };
            regions.push(region);
        }

        Ok(regions)
    }

    /// get a region's flag
    /// the return's value may conatin:
    ///     VFIO_REGION_INFO_FLAG_READ:  region supports read
    ///     VFIO_REGION_INFO_FLAG_WRITE: region supports write
    ///     VFIO_REGION_INFO_FLAG_MMAP:  region supports mmap
    ///     VFIO_REGION_INFO_FLAG_CAPS:  region's info supports caps
    pub fn get_region_flags(&self, index: u32) -> u32 {
        match self.regions.get(index as usize) {
            Some(v) => v.flags,
            None => {
                warn!("get_region_flags() with invalid index: {}", index);
                0
            }
        }
    }

    /// get a region's offset
    /// return: Region offset from the start of vfio device descriptor
    pub fn get_region_offset(&self, index: u32) -> u64 {
        match self.regions.get(index as usize) {
            Some(v) => v.offset,
            None => {
                warn!("get_region_offset with invalid index: {}", index);
                0
            }
        }
    }

    /// get a region's mmap info vector
    pub fn get_region_mmap(&self, index: u32) -> Vec<vfio_region_sparse_mmap_area> {
        match self.regions.get(index as usize) {
            Some(v) => v.mmaps.clone(),
            None => {
                warn!("get_region_mmap with invalid index: {}", index);
                Vec::new()
            }
        }
    }

    /// find the specified cap type in device regions
    /// Input:
    ///      type_:  cap type
    ///      sub_type: cap sub_type
    /// Output:
    ///     None: device doesn't have the specified cap type
    ///     Some((bar_index, region_size)): device has the specified cap type, return region's
    ///                                     index and size
    pub fn get_cap_type_info(&self, type_: u32, sub_type: u32) -> Option<(u32, u64)> {
        for (index, region) in self.regions.iter().enumerate() {
            if let Some(cap_info) = &region.cap_info {
                if cap_info.0 == type_ && cap_info.1 == sub_type {
                    return Some((index as u32, region.size));
                }
            }
        }

        None
    }

    /// Read region's data from VFIO device into buf
    /// index: region num
    /// buf: data destination and buf length is read size
    /// addr: offset in the region
    pub fn region_read(&self, index: u32, buf: &mut [u8], addr: u64) {
        let stub: &VfioRegion;
        match self.regions.get(index as usize) {
            Some(v) => stub = v,
            None => {
                warn!("region read with invalid index: {}", index);
                return;
            }
        }

        let size = buf.len() as u64;
        if size > stub.size || addr + size > stub.size {
            warn!(
                "region read with invalid parameter, index: {}, add: {:x}, size: {:x}",
                index, addr, size
            );
            return;
        }

        if let Err(e) = self.dev.read_exact_at(buf, stub.offset + addr) {
            warn!(
                "Failed to read region in index: {}, addr: {:x}, error: {}",
                index, addr, e
            );
        }
    }

    /// write the data from buf into a vfio device region
    /// index: region num
    /// buf: data src and buf length is write size
    /// addr: offset in the region
    pub fn region_write(&self, index: u32, buf: &[u8], addr: u64) {
        let stub: &VfioRegion;
        match self.regions.get(index as usize) {
            Some(v) => stub = v,
            None => {
                warn!("region write with invalid index: {}", index);
                return;
            }
        }

        let size = buf.len() as u64;
        if size > stub.size
            || addr + size > stub.size
            || (stub.flags & VFIO_REGION_INFO_FLAG_WRITE) == 0
        {
            warn!(
                "region write with invalid parameter,indxe: {}, add: {:x}, size: {:x}",
                index, addr, size
            );
            return;
        }

        if let Err(e) = self.dev.write_all_at(buf, stub.offset + addr) {
            warn!(
                "Failed to write region in index: {}, addr: {:x}, error: {}",
                index, addr, e
            );
        }
    }

    /// get vfio device's descriptors which are passed into minijail process
    pub fn keep_rds(&self) -> Vec<RawDescriptor> {
        let mut rds = Vec::new();
        rds.push(self.dev.as_raw_descriptor());
        rds.push(self.group_descriptor);
        rds.push(self.container.lock().as_raw_descriptor());
        rds
    }

    /// Add (iova, user_addr) map into vfio container iommu table
    pub unsafe fn vfio_dma_map(
        &self,
        iova: u64,
        size: u64,
        user_addr: u64,
    ) -> Result<(), VfioError> {
        self.container.lock().vfio_dma_map(iova, size, user_addr)
    }

    /// Remove (iova, user_addr) map from vfio container iommu table
    pub fn vfio_dma_unmap(&self, iova: u64, size: u64) -> Result<(), VfioError> {
        self.container.lock().vfio_dma_unmap(iova, size)
    }

    /// Gets the vfio device backing `File`.
    pub fn device_file(&self) -> &File {
        &self.dev
    }
}
