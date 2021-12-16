// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::CString;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::mem;
use std::os::raw::c_ulong;
use std::os::unix::prelude::FileExt;
use std::path::Path;
use std::path::PathBuf;
use std::slice;
use std::sync::Arc;
use std::u32;

use base::error;
use base::ioctl;
use base::ioctl_with_mut_ptr;
use base::ioctl_with_mut_ref;
use base::ioctl_with_ptr;
use base::ioctl_with_ref;
use base::ioctl_with_val;
use base::warn;
use base::AsRawDescriptor;
use base::Error;
use base::Event;
use base::FromRawDescriptor;
use base::RawDescriptor;
use base::SafeDescriptor;
use data_model::vec_with_array_field;
use data_model::DataInit;
use hypervisor::DeviceKind;
use hypervisor::Vm;
use once_cell::sync::OnceCell;
use remain::sorted;
use resources::address_allocator::AddressAllocator;
use resources::AddressRange;
use resources::Alloc;
use resources::Error as ResourcesError;
use sync::Mutex;
use thiserror::Error;
use vfio_sys::*;

use crate::IommuDevType;

#[sorted]
#[derive(Error, Debug)]
pub enum VfioError {
    #[error("failed to borrow global vfio container")]
    BorrowVfioContainer,
    #[error("failed to duplicate VfioContainer")]
    ContainerDupError,
    #[error("failed to set container's IOMMU driver type as VfioType1V2: {0}")]
    ContainerSetIOMMU(Error),
    #[error("failed to create KVM vfio device: {0}")]
    CreateVfioKvmDevice(Error),
    #[error("failed to get Group Status: {0}")]
    GetGroupStatus(Error),
    #[error("failed to get vfio device fd: {0}")]
    GroupGetDeviceFD(Error),
    #[error("failed to add vfio group into vfio container: {0}")]
    GroupSetContainer(Error),
    #[error("group is inviable")]
    GroupViable,
    #[error("invalid region index: {0}")]
    InvalidIndex(u32),
    #[error("invalid file path")]
    InvalidPath,
    #[error("failed to add guest memory map into iommu table: {0}")]
    IommuDmaMap(Error),
    #[error("failed to remove guest memory map from iommu table: {0}")]
    IommuDmaUnmap(Error),
    #[error("failed to get IOMMU cap info from host")]
    IommuGetCapInfo,
    #[error("failed to get IOMMU info from host: {0}")]
    IommuGetInfo(Error),
    #[error("failed to set KVM vfio device's attribute: {0}")]
    KvmSetDeviceAttr(Error),
    #[error("AddressAllocator is unavailable")]
    NoRescAlloc,
    #[error("failed to open /dev/vfio/vfio container: {0}")]
    OpenContainer(io::Error),
    #[error("failed to open {1} group: {0}")]
    OpenGroup(io::Error, String),
    #[error("resources error: {0}")]
    Resources(ResourcesError),
    #[error(
        "vfio API version doesn't match with VFIO_API_VERSION defined in vfio_sys/src/vfio.rs"
    )]
    VfioApiVersion,
    #[error("failed to get vfio device's info or info doesn't match: {0}")]
    VfioDeviceGetInfo(Error),
    #[error("failed to get vfio device's region info: {0}")]
    VfioDeviceGetRegionInfo(Error),
    #[error("failed to disable vfio deviece's irq: {0}")]
    VfioIrqDisable(Error),
    #[error("failed to enable vfio deviece's irq: {0}")]
    VfioIrqEnable(Error),
    #[error("failed to mask vfio deviece's irq: {0}")]
    VfioIrqMask(Error),
    #[error("failed to unmask vfio deviece's irq: {0}")]
    VfioIrqUnmask(Error),
    #[error("failed to enter vfio deviece's low power state: {0}")]
    VfioPmLowPowerEnter(Error),
    #[error("failed to exit vfio deviece's low power state: {0}")]
    VfioPmLowPowerExit(Error),
    #[error("container dones't support VfioType1V2 IOMMU driver type")]
    VfioType1V2,
}

type Result<T> = std::result::Result<T, VfioError>;

fn get_error() -> Error {
    Error::last()
}

static KVM_VFIO_FILE: OnceCell<SafeDescriptor> = OnceCell::new();

enum KvmVfioGroupOps {
    Add,
    Delete,
}

#[repr(u32)]
enum IommuType {
    Type1V2 = VFIO_TYPE1v2_IOMMU,
    // ChromeOS specific vfio_iommu_type1 implementation that is optimized for
    // small, dynamic mappings. For clients which create large, relatively
    // static mappings, Type1V2 is still preferred.
    //
    // See crrev.com/c/3593528 for the implementation.
    Type1ChromeOS = 100001,
}

// Hint as to whether IOMMU mappings will tend to be large and static or
// small and dynamic.
#[derive(PartialEq)]
enum IommuMappingHint {
    Static,
    Dynamic,
}

/// VfioContainer contain multi VfioGroup, and delegate an IOMMU domain table
pub struct VfioContainer {
    container: File,
    groups: HashMap<u32, Arc<Mutex<VfioGroup>>>,
}

fn extract_vfio_struct<T>(bytes: &[u8], offset: usize) -> T
where
    T: DataInit,
{
    T::from_reader(&bytes[offset..(offset + mem::size_of::<T>())]).expect("malformed kernel data")
}

const VFIO_API_VERSION: u8 = 0;
impl VfioContainer {
    pub fn new() -> Result<Self> {
        let container = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/vfio/vfio")
            .map_err(VfioError::OpenContainer)?;

        Self::new_from_container(container)
    }

    // Construct a VfioContainer from an exist container file.
    pub fn new_from_container(container: File) -> Result<Self> {
        // Safe as file is vfio container descriptor and ioctl is defined by kernel.
        let version = unsafe { ioctl(&container, VFIO_GET_API_VERSION()) };
        if version as u8 != VFIO_API_VERSION {
            return Err(VfioError::VfioApiVersion);
        }

        Ok(VfioContainer {
            container,
            groups: HashMap::new(),
        })
    }

    fn is_group_set(&self, group_id: u32) -> bool {
        self.groups.get(&group_id).is_some()
    }

    fn check_extension(&self, val: IommuType) -> bool {
        // Safe as file is vfio container and make sure val is valid.
        let ret = unsafe { ioctl_with_val(self, VFIO_CHECK_EXTENSION(), val as c_ulong) };
        ret == 1
    }

    fn set_iommu(&self, val: IommuType) -> i32 {
        // Safe as file is vfio container and make sure val is valid.
        unsafe { ioctl_with_val(self, VFIO_SET_IOMMU(), val as c_ulong) }
    }

    pub unsafe fn vfio_dma_map(
        &self,
        iova: u64,
        size: u64,
        user_addr: u64,
        write_en: bool,
    ) -> Result<()> {
        let mut dma_map = vfio_iommu_type1_dma_map {
            argsz: mem::size_of::<vfio_iommu_type1_dma_map>() as u32,
            flags: VFIO_DMA_MAP_FLAG_READ,
            vaddr: user_addr,
            iova,
            size,
        };

        if write_en {
            dma_map.flags |= VFIO_DMA_MAP_FLAG_WRITE;
        }

        let ret = ioctl_with_ref(self, VFIO_IOMMU_MAP_DMA(), &dma_map);
        if ret != 0 {
            return Err(VfioError::IommuDmaMap(get_error()));
        }

        Ok(())
    }

    pub fn vfio_dma_unmap(&self, iova: u64, size: u64) -> Result<()> {
        let mut dma_unmap = vfio_iommu_type1_dma_unmap {
            argsz: mem::size_of::<vfio_iommu_type1_dma_unmap>() as u32,
            flags: 0,
            iova,
            size,
            ..Default::default()
        };

        // Safe as file is vfio container, dma_unmap is constructed by us, and
        // we check the return value
        let ret = unsafe { ioctl_with_mut_ref(self, VFIO_IOMMU_UNMAP_DMA(), &mut dma_unmap) };
        if ret != 0 || dma_unmap.size != size {
            return Err(VfioError::IommuDmaUnmap(get_error()));
        }

        Ok(())
    }

    pub fn vfio_get_iommu_page_size_mask(&self) -> Result<u64> {
        let mut iommu_info = vfio_iommu_type1_info {
            argsz: mem::size_of::<vfio_iommu_type1_info>() as u32,
            flags: 0,
            iova_pgsizes: 0,
            ..Default::default()
        };

        // Safe as file is vfio container, iommu_info has valid values,
        // and we check the return value
        let ret = unsafe { ioctl_with_mut_ref(self, VFIO_IOMMU_GET_INFO(), &mut iommu_info) };
        if ret != 0 || (iommu_info.flags & VFIO_IOMMU_INFO_PGSIZES) == 0 {
            return Err(VfioError::IommuGetInfo(get_error()));
        }

        Ok(iommu_info.iova_pgsizes)
    }

    pub fn vfio_iommu_iova_get_iova_ranges(&self) -> Result<Vec<AddressRange>> {
        // Query the buffer size needed fetch the capabilities.
        let mut iommu_info_argsz = vfio_iommu_type1_info {
            argsz: mem::size_of::<vfio_iommu_type1_info>() as u32,
            flags: 0,
            iova_pgsizes: 0,
            ..Default::default()
        };

        // Safe as file is vfio container, iommu_info_argsz has valid values,
        // and we check the return value
        let ret = unsafe { ioctl_with_mut_ref(self, VFIO_IOMMU_GET_INFO(), &mut iommu_info_argsz) };
        if ret != 0 {
            return Err(VfioError::IommuGetInfo(get_error()));
        }

        if (iommu_info_argsz.flags & VFIO_IOMMU_INFO_CAPS) == 0 {
            return Err(VfioError::IommuGetCapInfo);
        }

        let mut iommu_info = vec_with_array_field::<vfio_iommu_type1_info, u8>(
            iommu_info_argsz.argsz as usize - mem::size_of::<vfio_iommu_type1_info>(),
        );
        iommu_info[0].argsz = iommu_info_argsz.argsz;
        // Safe as file is vfio container, iommu_info has valid values,
        // and we check the return value
        let ret =
            unsafe { ioctl_with_mut_ptr(self, VFIO_IOMMU_GET_INFO(), iommu_info.as_mut_ptr()) };
        if ret != 0 {
            return Err(VfioError::IommuGetInfo(get_error()));
        }

        // Safe because we initialized iommu_info with enough space, u8 has less strict
        // alignment, and since it will no longer be mutated.
        let info_bytes = unsafe {
            std::slice::from_raw_parts(
                iommu_info.as_ptr() as *const u8,
                iommu_info_argsz.argsz as usize,
            )
        };

        if (iommu_info[0].flags & VFIO_IOMMU_INFO_CAPS) == 0 {
            return Err(VfioError::IommuGetCapInfo);
        }

        let mut offset = iommu_info[0].cap_offset as usize;
        while offset != 0 {
            let header = extract_vfio_struct::<vfio_info_cap_header>(info_bytes, offset);

            if header.id == VFIO_IOMMU_TYPE1_INFO_CAP_IOVA_RANGE as u16 && header.version == 1 {
                let iova_header = extract_vfio_struct::<vfio_iommu_type1_info_cap_iova_range_header>(
                    info_bytes, offset,
                );
                let range_offset = offset + mem::size_of::<vfio_iommu_type1_info_cap_iova_range>();
                let mut ret = Vec::new();
                for i in 0..iova_header.nr_iovas {
                    ret.push(extract_vfio_struct::<vfio_iova_range>(
                        info_bytes,
                        range_offset + i as usize * mem::size_of::<vfio_iova_range>(),
                    ));
                }
                return Ok(ret
                    .iter()
                    .map(|range| AddressRange {
                        start: range.start,
                        end: range.end,
                    })
                    .collect());
            }
            offset = header.next as usize;
        }

        Err(VfioError::IommuGetCapInfo)
    }

    fn init_vfio_iommu(&mut self, hint: IommuMappingHint) -> Result<()> {
        // If we expect granular, dynamic mappings (i.e. viommu/coiommu), try the
        // ChromeOS Type1ChromeOS first, then fall back to upstream versions.
        if hint == IommuMappingHint::Dynamic {
            if self.set_iommu(IommuType::Type1ChromeOS) == 0 {
                return Ok(());
            }
        }

        if !self.check_extension(IommuType::Type1V2) {
            return Err(VfioError::VfioType1V2);
        }

        if self.set_iommu(IommuType::Type1V2) < 0 {
            return Err(VfioError::ContainerSetIOMMU(get_error()));
        }

        Ok(())
    }

    fn get_group_with_vm(
        &mut self,
        id: u32,
        vm: &impl Vm,
        iommu_enabled: bool,
    ) -> Result<Arc<Mutex<VfioGroup>>> {
        match self.groups.get(&id) {
            Some(group) => Ok(group.clone()),
            None => {
                let group = Arc::new(Mutex::new(VfioGroup::new(self, id)?));
                if self.groups.is_empty() {
                    // Before the first group is added into container, do once per container
                    // initialization. Both coiommu and virtio-iommu rely on small, dynamic
                    // mappings. However, if an iommu is not enabled, then we map the entirety
                    // of guest memory as a small number of large, static mappings.
                    let mapping_hint = if iommu_enabled {
                        IommuMappingHint::Dynamic
                    } else {
                        IommuMappingHint::Static
                    };
                    self.init_vfio_iommu(mapping_hint)?;

                    if !iommu_enabled {
                        vm.get_memory().with_regions(
                            |_index, guest_addr, size, host_addr, _mmap, _fd_offset| {
                                // Safe because the guest regions are guaranteed not to overlap
                                unsafe {
                                    self.vfio_dma_map(
                                        guest_addr.0,
                                        size as u64,
                                        host_addr as u64,
                                        true,
                                    )
                                }
                            },
                        )?;
                    }
                }

                let kvm_vfio_file = KVM_VFIO_FILE
                    .get_or_try_init(|| vm.create_device(DeviceKind::Vfio))
                    .map_err(VfioError::CreateVfioKvmDevice)?;
                group
                    .lock()
                    .kvm_device_set_group(kvm_vfio_file, KvmVfioGroupOps::Add)?;

                self.groups.insert(id, group.clone());

                Ok(group)
            }
        }
    }

    fn get_group(&mut self, id: u32) -> Result<Arc<Mutex<VfioGroup>>> {
        match self.groups.get(&id) {
            Some(group) => Ok(group.clone()),
            None => {
                let group = Arc::new(Mutex::new(VfioGroup::new(self, id)?));

                if self.groups.is_empty() {
                    // Before the first group is added into container, do once per
                    // container initialization.
                    self.init_vfio_iommu(IommuMappingHint::Static)?;
                }

                self.groups.insert(id, group.clone());
                Ok(group)
            }
        }
    }

    fn remove_group(&mut self, id: u32, reduce: bool) {
        let mut remove = false;

        if let Some(group) = self.groups.get(&id) {
            if reduce {
                group.lock().reduce_device_num();
            }
            if group.lock().device_num() == 0 {
                let kvm_vfio_file = KVM_VFIO_FILE.get().expect("kvm vfio file isn't created");
                if group
                    .lock()
                    .kvm_device_set_group(kvm_vfio_file, KvmVfioGroupOps::Delete)
                    .is_err()
                {
                    warn!("failing in remove vfio group from kvm device");
                }
                remove = true;
            }
        }

        if remove {
            self.groups.remove(&id);
        }
    }

    pub fn clone_as_raw_descriptor(&self) -> Result<RawDescriptor> {
        let raw_descriptor = unsafe { libc::dup(self.container.as_raw_descriptor()) };
        if raw_descriptor < 0 {
            Err(VfioError::ContainerDupError)
        } else {
            Ok(raw_descriptor)
        }
    }

    // Gets group ids for all groups in the container.
    pub fn group_ids(&self) -> Vec<&u32> {
        self.groups.keys().collect()
    }
}

impl AsRawDescriptor for VfioContainer {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.container.as_raw_descriptor()
    }
}

struct VfioGroup {
    group: File,
    device_num: u32,
}

impl VfioGroup {
    fn new(container: &VfioContainer, id: u32) -> Result<Self> {
        let group_path = format!("/dev/vfio/{}", id);
        let group_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(Path::new(&group_path))
            .map_err(|e| VfioError::OpenGroup(e, group_path))?;

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

        Ok(VfioGroup {
            group: group_file,
            device_num: 0,
        })
    }

    fn get_group_id<P: AsRef<Path>>(sysfspath: P) -> Result<u32> {
        let mut uuid_path = PathBuf::new();
        uuid_path.push(sysfspath);
        uuid_path.push("iommu_group");
        let group_path = uuid_path.read_link().map_err(|_| VfioError::InvalidPath)?;
        let group_osstr = group_path.file_name().ok_or(VfioError::InvalidPath)?;
        let group_str = group_osstr.to_str().ok_or(VfioError::InvalidPath)?;
        let group_id = group_str
            .parse::<u32>()
            .map_err(|_| VfioError::InvalidPath)?;

        Ok(group_id)
    }

    fn kvm_device_set_group(
        &self,
        kvm_vfio_file: &SafeDescriptor,
        ops: KvmVfioGroupOps,
    ) -> Result<()> {
        let group_descriptor = self.as_raw_descriptor();
        let group_descriptor_ptr = &group_descriptor as *const i32;
        let vfio_dev_attr = match ops {
            KvmVfioGroupOps::Add => kvm_sys::kvm_device_attr {
                flags: 0,
                group: kvm_sys::KVM_DEV_VFIO_GROUP,
                attr: kvm_sys::KVM_DEV_VFIO_GROUP_ADD as u64,
                addr: group_descriptor_ptr as u64,
            },
            KvmVfioGroupOps::Delete => kvm_sys::kvm_device_attr {
                flags: 0,
                group: kvm_sys::KVM_DEV_VFIO_GROUP,
                attr: kvm_sys::KVM_DEV_VFIO_GROUP_DEL as u64,
                addr: group_descriptor_ptr as u64,
            },
        };

        // Safe as we are the owner of vfio_dev_descriptor and vfio_dev_attr which are valid value,
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

    fn get_device(&self, name: &str) -> Result<File> {
        let path: CString = CString::new(name.as_bytes()).expect("CString::new() failed");
        let path_ptr = path.as_ptr();

        // Safe as we are the owner of self and path_ptr which are valid value.
        let ret = unsafe { ioctl_with_ptr(self, VFIO_GROUP_GET_DEVICE_FD(), path_ptr) };
        if ret < 0 {
            return Err(VfioError::GroupGetDeviceFD(get_error()));
        }

        // Safe as ret is valid descriptor
        Ok(unsafe { File::from_raw_descriptor(ret) })
    }

    fn add_device_num(&mut self) {
        self.device_num += 1;
    }

    fn reduce_device_num(&mut self) {
        self.device_num -= 1;
    }

    fn device_num(&self) -> u32 {
        self.device_num
    }
}

impl AsRawDescriptor for VfioGroup {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.group.as_raw_descriptor()
    }
}

/// A helper trait for managing VFIO setup
pub trait VfioCommonTrait: Send + Sync {
    /// The single place to create a VFIO container for a PCI endpoint.
    ///
    /// The policy to determine whether an individual or a shared VFIO container
    /// will be created for this device is governed by the physical PCI topology,
    /// and the argument iommu_enabled.
    ///
    ///  # Arguments
    ///
    ///  * `sysfspath` - the path to the PCI device, e.g. /sys/bus/pci/devices/0000:02:00.0
    ///  * `iommu_enabled` - whether virtio IOMMU is enabled on this device
    fn vfio_get_container<P: AsRef<Path>>(
        iommu_dev: IommuDevType,
        sysfspath: Option<P>,
    ) -> Result<Arc<Mutex<VfioContainer>>>;
}

thread_local! {

    // One VFIO container is shared by all VFIO devices that don't
    // attach to the virtio IOMMU device
    static NO_IOMMU_CONTAINER: RefCell<Option<Arc<Mutex<VfioContainer>>>> = RefCell::new(None);

    // For IOMMU enabled devices, all VFIO groups that share the same IOVA space
    // are managed by one VFIO container
    static IOMMU_CONTAINERS: RefCell<Option<Vec<Arc<Mutex<VfioContainer>>>>> = RefCell::new(Some(Default::default()));

    // One VFIO container is shared by all VFIO devices that
    // attach to the CoIOMMU device
    static COIOMMU_CONTAINER: RefCell<Option<Arc<Mutex<VfioContainer>>>> = RefCell::new(None);
}

pub struct VfioCommonSetup;

impl VfioCommonTrait for VfioCommonSetup {
    fn vfio_get_container<P: AsRef<Path>>(
        iommu_dev: IommuDevType,
        sysfspath: Option<P>,
    ) -> Result<Arc<Mutex<VfioContainer>>> {
        match iommu_dev {
            IommuDevType::NoIommu => {
                // One VFIO container is used for all IOMMU disabled groups
                NO_IOMMU_CONTAINER.with(|v| {
                    if v.borrow().is_some() {
                        if let Some(ref container) = *v.borrow() {
                            Ok(container.clone())
                        } else {
                            Err(VfioError::BorrowVfioContainer)
                        }
                    } else {
                        let container = Arc::new(Mutex::new(VfioContainer::new()?));
                        *v.borrow_mut() = Some(container.clone());
                        Ok(container)
                    }
                })
            }
            IommuDevType::VirtioIommu => {
                let path = sysfspath.ok_or(VfioError::InvalidPath)?;
                let group_id = VfioGroup::get_group_id(path)?;

                // One VFIO container is used for all devices belong to one VFIO group
                // NOTE: vfio_wrapper relies on each container containing exactly one group.
                IOMMU_CONTAINERS.with(|v| {
                    if let Some(ref mut containers) = *v.borrow_mut() {
                        let container = containers
                            .iter()
                            .find(|container| container.lock().is_group_set(group_id));

                        match container {
                            None => {
                                let container = Arc::new(Mutex::new(VfioContainer::new()?));
                                containers.push(container.clone());
                                Ok(container)
                            }
                            Some(container) => Ok(container.clone()),
                        }
                    } else {
                        Err(VfioError::BorrowVfioContainer)
                    }
                })
            }
            IommuDevType::CoIommu => {
                // One VFIO container is used for devices attached to CoIommu
                COIOMMU_CONTAINER.with(|v| {
                    if v.borrow().is_some() {
                        if let Some(ref container) = *v.borrow() {
                            Ok(container.clone())
                        } else {
                            Err(VfioError::BorrowVfioContainer)
                        }
                    } else {
                        let container = Arc::new(Mutex::new(VfioContainer::new()?));
                        *v.borrow_mut() = Some(container.clone());
                        Ok(container)
                    }
                })
            }
        }
    }
}

/// Vfio Irq type used to enable/disable/mask/unmask vfio irq
pub enum VfioIrqType {
    Intx,
    Msi,
    Msix,
}

/// Vfio Irq information used to assign and enable/disable/mask/unmask vfio irq
pub struct VfioIrq {
    pub flags: u32,
    pub index: u32,
}

/// Address on VFIO memory region.
#[derive(Debug, Default, Clone)]
pub struct VfioRegionAddr {
    /// region number.
    pub index: u32,
    /// offset in the region.
    pub addr: u64,
}

#[derive(Debug)]
pub struct VfioRegion {
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
    group_id: u32,
    // vec for vfio device's regions
    regions: Vec<VfioRegion>,

    iova_alloc: Arc<Mutex<AddressAllocator>>,
}

impl VfioDevice {
    /// Create a new vfio device, then guest read/write on this device could be
    /// transfered into kernel vfio.
    /// sysfspath specify the vfio device path in sys file system.
    pub fn new_passthrough<P: AsRef<Path>>(
        sysfspath: &P,
        vm: &impl Vm,
        container: Arc<Mutex<VfioContainer>>,
        iommu_enabled: bool,
    ) -> Result<Self> {
        let group_id = VfioGroup::get_group_id(&sysfspath)?;

        let group = container
            .lock()
            .get_group_with_vm(group_id, vm, iommu_enabled)?;
        let name_osstr = sysfspath
            .as_ref()
            .file_name()
            .ok_or(VfioError::InvalidPath)?;
        let name_str = name_osstr.to_str().ok_or(VfioError::InvalidPath)?;
        let name = String::from(name_str);
        let dev = group.lock().get_device(&name)?;
        let regions = Self::get_regions(&dev)?;
        group.lock().add_device_num();
        let group_descriptor = group.lock().as_raw_descriptor();

        let iova_ranges = container.lock().vfio_iommu_iova_get_iova_ranges()?;
        let iova_alloc = AddressAllocator::new_from_list(iova_ranges, None, None)
            .map_err(VfioError::Resources)?;

        Ok(VfioDevice {
            dev,
            name,
            container,
            group_descriptor,
            group_id,
            regions,
            iova_alloc: Arc::new(Mutex::new(iova_alloc)),
        })
    }

    pub fn new<P: AsRef<Path>>(
        sysfspath: &P,
        container: Arc<Mutex<VfioContainer>>,
    ) -> Result<Self> {
        let group_id = VfioGroup::get_group_id(&sysfspath)?;
        let group = container.lock().get_group(group_id)?;
        let name_osstr = sysfspath
            .as_ref()
            .file_name()
            .ok_or(VfioError::InvalidPath)?;
        let name_str = name_osstr.to_str().ok_or(VfioError::InvalidPath)?;
        let name = String::from(name_str);

        let dev = match group.lock().get_device(&name) {
            Ok(dev) => dev,
            Err(e) => {
                container.lock().remove_group(group_id, false);
                return Err(e);
            }
        };
        let regions = match Self::get_regions(&dev) {
            Ok(regions) => regions,
            Err(e) => {
                container.lock().remove_group(group_id, false);
                return Err(e);
            }
        };
        group.lock().add_device_num();
        let group_descriptor = group.lock().as_raw_descriptor();

        let iova_ranges = container.lock().vfio_iommu_iova_get_iova_ranges()?;
        let iova_alloc = AddressAllocator::new_from_list(iova_ranges, None, None)
            .map_err(VfioError::Resources)?;

        Ok(VfioDevice {
            dev,
            name,
            container,
            group_descriptor,
            group_id,
            regions,
            iova_alloc: Arc::new(Mutex::new(iova_alloc)),
        })
    }

    /// Returns the file for this device.
    pub fn dev_file(&self) -> &File {
        &self.dev
    }

    /// Returns PCI device name, formatted as BUS:DEVICE.FUNCTION string.
    pub fn device_name(&self) -> &String {
        &self.name
    }

    /// enter the device's low power state
    pub fn pm_low_power_enter(&self) -> Result<()> {
        let mut device_feature = vec_with_array_field::<vfio_device_feature, u8>(0);
        device_feature[0].argsz = mem::size_of::<vfio_device_feature>() as u32;
        device_feature[0].flags = VFIO_DEVICE_FEATURE_SET | VFIO_DEVICE_FEATURE_LOW_POWER_ENTRY;
        // Safe as we are the owner of self and power_management which are valid value
        let ret = unsafe { ioctl_with_ref(&self.dev, VFIO_DEVICE_FEATURE(), &device_feature[0]) };
        if ret < 0 {
            Err(VfioError::VfioPmLowPowerEnter(get_error()))
        } else {
            Ok(())
        }
    }

    /// exit the device's low power state
    pub fn pm_low_power_exit(&self) -> Result<()> {
        let mut device_feature = vec_with_array_field::<vfio_device_feature, u8>(0);
        device_feature[0].argsz = mem::size_of::<vfio_device_feature>() as u32;
        device_feature[0].flags = VFIO_DEVICE_FEATURE_SET | VFIO_DEVICE_FEATURE_LOW_POWER_EXIT;
        // Safe as we are the owner of self and power_management which are valid value
        let ret = unsafe { ioctl_with_ref(&self.dev, VFIO_DEVICE_FEATURE(), &device_feature[0]) };
        if ret < 0 {
            Err(VfioError::VfioPmLowPowerExit(get_error()))
        } else {
            Ok(())
        }
    }

    /// Enable vfio device's irq and associate Irqfd Event with device.
    /// When MSIx is enabled, multi vectors will be supported, and vectors starting from subindex to subindex +
    /// descriptors length will be assigned with irqfd in the descriptors array.
    /// when index = VFIO_PCI_REQ_IRQ_INDEX, kernel vfio will trigger this event when physical device
    /// is removed.
    /// If descriptor is None, -1 is assigned to the irq. A value of -1 is used to either de-assign
    /// interrupts if already assigned or skip un-assigned interrupts.
    pub fn irq_enable(
        &self,
        descriptors: &[Option<&Event>],
        index: u32,
        subindex: u32,
    ) -> Result<()> {
        let count = descriptors.len();
        let u32_size = mem::size_of::<u32>();
        let mut irq_set = vec_with_array_field::<vfio_irq_set, u32>(count);
        irq_set[0].argsz = (mem::size_of::<vfio_irq_set>() + count * u32_size) as u32;
        irq_set[0].flags = VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER;
        irq_set[0].index = index;
        irq_set[0].start = subindex;
        irq_set[0].count = count as u32;

        // irq_set.data could be none, bool or descriptor according to flags, so irq_set.data
        // is u8 default, here irq_set.data is descriptor as u32, so 4 default u8 are combined
        // together as u32. It is safe as enough space is reserved through
        // vec_with_array_field(u32)<count>.
        let mut data = unsafe { irq_set[0].data.as_mut_slice(count * u32_size) };
        for descriptor in descriptors.iter().take(count) {
            let (left, right) = data.split_at_mut(u32_size);
            match descriptor {
                Some(fd) => left.copy_from_slice(&fd.as_raw_descriptor().to_ne_bytes()[..]),
                None => left.copy_from_slice(&(-1i32).to_ne_bytes()[..]),
            }
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
    pub fn resample_virq_enable(&self, descriptor: &Event, index: u32) -> Result<()> {
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
    pub fn irq_disable(&self, index: u32) -> Result<()> {
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
    pub fn irq_unmask(&self, index: u32) -> Result<()> {
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
    pub fn irq_mask(&self, index: u32) -> Result<()> {
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

    fn validate_dev_info(dev_info: &mut vfio_device_info) -> Result<()> {
        if (dev_info.flags & VFIO_DEVICE_FLAGS_PCI) != 0 {
            if dev_info.num_regions < VFIO_PCI_CONFIG_REGION_INDEX + 1
                || dev_info.num_irqs < VFIO_PCI_MSIX_IRQ_INDEX + 1
            {
                return Err(VfioError::VfioDeviceGetInfo(get_error()));
            }
            return Ok(());
        } else if (dev_info.flags & VFIO_DEVICE_FLAGS_PLATFORM) != 0 {
            return Ok(());
        }

        Err(VfioError::VfioDeviceGetInfo(get_error()))
    }

    /// Get and validate VFIO device information.
    pub fn check_device_info(&self) -> Result<vfio_device_info> {
        let mut dev_info = vfio_device_info {
            argsz: mem::size_of::<vfio_device_info>() as u32,
            flags: 0,
            num_regions: 0,
            num_irqs: 0,
            ..Default::default()
        };

        // Safe as we are the owner of device_file and dev_info which are valid value,
        // and we verify the return value.
        let ret = unsafe {
            ioctl_with_mut_ref(self.device_file(), VFIO_DEVICE_GET_INFO(), &mut dev_info)
        };
        if ret < 0 {
            return Err(VfioError::VfioDeviceGetInfo(get_error()));
        }

        Self::validate_dev_info(&mut dev_info)?;
        Ok(dev_info)
    }

    /// Query interrupt information
    /// return: Vector of interrupts information, each of which contains flags and index
    pub fn get_irqs(&self) -> Result<Vec<VfioIrq>> {
        let dev_info = self.check_device_info()?;
        let mut irqs: Vec<VfioIrq> = Vec::new();

        for i in 0..dev_info.num_irqs {
            let argsz = mem::size_of::<vfio_irq_info>() as u32;
            let mut irq_info = vfio_irq_info {
                argsz,
                flags: 0,
                index: i,
                count: 0,
            };
            // Safe as we are the owner of dev and dev_info which are valid value,
            // and we verify the return value.
            let ret = unsafe {
                ioctl_with_mut_ref(
                    self.device_file(),
                    VFIO_DEVICE_GET_IRQ_INFO(),
                    &mut irq_info,
                )
            };
            if ret < 0 || irq_info.count != 1 {
                return Err(VfioError::VfioDeviceGetInfo(get_error()));
            }

            let irq = VfioIrq {
                flags: irq_info.flags,
                index: irq_info.index,
            };
            irqs.push(irq);
        }
        Ok(irqs)
    }

    #[allow(clippy::cast_ptr_alignment)]
    fn get_regions(dev: &File) -> Result<Vec<VfioRegion>> {
        let mut regions: Vec<VfioRegion> = Vec::new();
        let mut dev_info = vfio_device_info {
            argsz: mem::size_of::<vfio_device_info>() as u32,
            flags: 0,
            num_regions: 0,
            num_irqs: 0,
            ..Default::default()
        };
        // Safe as we are the owner of dev and dev_info which are valid value,
        // and we verify the return value.
        let mut ret = unsafe { ioctl_with_mut_ref(dev, VFIO_DEVICE_GET_INFO(), &mut dev_info) };
        if ret < 0 {
            return Err(VfioError::VfioDeviceGetInfo(get_error()));
        }

        Self::validate_dev_info(&mut dev_info)?;
        for i in 0..dev_info.num_regions {
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
                    if offset + cap_header_sz > region_info_sz {
                        break;
                    }
                    // Safe, as cap_header struct is in this function allocated region_with_cap
                    // vec.
                    let cap_ptr = unsafe { info_ptr.offset(offset as isize) };
                    let cap_header =
                        unsafe { &*(cap_ptr as *mut u8 as *const vfio_info_cap_header) };
                    if cap_header.id as u32 == VFIO_REGION_INFO_CAP_SPARSE_MMAP {
                        if offset + mmap_cap_sz > region_info_sz {
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
                    } else if cap_header.id as u32 == VFIO_REGION_INFO_CAP_MSIX_MAPPABLE {
                        mmaps.push(vfio_region_sparse_mmap_area {
                            offset: 0,
                            size: region_with_cap[0].region_info.size,
                        });
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

    /// get a region's size
    /// return: Region size from the start of vfio device descriptor
    pub fn get_region_size(&self, index: u32) -> u64 {
        match self.regions.get(index as usize) {
            Some(v) => v.size,
            None => {
                warn!("get_region_size with invalid index: {}", index);
                0
            }
        }
    }

    /// get a number of regions
    /// return: Number of regions of vfio device descriptor
    pub fn get_region_count(&self) -> u32 {
        self.regions.len() as u32
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

    /// Returns file offset corresponding to the given `VfioRegionAddr`.
    /// The offset can be used when reading/writing the VFIO device's FD directly.
    pub fn get_offset_for_addr(&self, addr: &VfioRegionAddr) -> Result<u64> {
        let region = self
            .regions
            .get(addr.index as usize)
            .ok_or(VfioError::InvalidIndex(addr.index))?;
        Ok(region.offset + addr.addr)
    }

    /// Read region's data from VFIO device into buf
    /// index: region num
    /// buf: data destination and buf length is read size
    /// addr: offset in the region
    pub fn region_read(&self, index: u32, buf: &mut [u8], addr: u64) {
        let stub: &VfioRegion = self
            .regions
            .get(index as usize)
            .unwrap_or_else(|| panic!("tried to read VFIO with an invalid index: {}", index));

        let size = buf.len() as u64;
        if size > stub.size || addr + size > stub.size {
            panic!(
                "tried to read VFIO region with invalid arguments: index={}, addr=0x{:x}, size=0x{:x}",
                index, addr, size
            );
        }

        self.dev
            .read_exact_at(buf, stub.offset + addr)
            .unwrap_or_else(|e| {
                panic!(
                    "failed to read region: index={}, addr=0x{:x}, error={}",
                    index, addr, e
                )
            });
    }

    /// Reads a value from the specified `VfioRegionAddr.addr` + `offset`.
    pub fn region_read_from_addr<T: DataInit>(&self, addr: &VfioRegionAddr, offset: u64) -> T {
        let mut val = mem::MaybeUninit::zeroed();
        // Safe because we have zero-initialized `size_of::<T>()` bytes.
        let buf =
            unsafe { slice::from_raw_parts_mut(val.as_mut_ptr() as *mut u8, mem::size_of::<T>()) };
        self.region_read(addr.index, buf, addr.addr + offset);
        // Safe because any bit pattern is valid for a type that implements
        // DataInit.
        unsafe { val.assume_init() }
    }

    /// write the data from buf into a vfio device region
    /// index: region num
    /// buf: data src and buf length is write size
    /// addr: offset in the region
    pub fn region_write(&self, index: u32, buf: &[u8], addr: u64) {
        let stub: &VfioRegion = self
            .regions
            .get(index as usize)
            .unwrap_or_else(|| panic!("tried to write VFIO with an invalid index: {}", index));

        let size = buf.len() as u64;
        if size > stub.size
            || addr + size > stub.size
            || (stub.flags & VFIO_REGION_INFO_FLAG_WRITE) == 0
        {
            panic!(
                "tried to write VFIO region with invalid arguments: index={}, addr=0x{:x}, size=0x{:x}",
                index, addr, size
            );
        }

        self.dev
            .write_all_at(buf, stub.offset + addr)
            .unwrap_or_else(|e| {
                panic!(
                    "failed to write region: index={}, addr=0x{:x}, error={}",
                    index, addr, e
                )
            });
    }

    /// Writes data into the specified `VfioRegionAddr.addr` + `offset`.
    pub fn region_write_to_addr<T: DataInit>(&self, val: &T, addr: &VfioRegionAddr, offset: u64) {
        self.region_write(addr.index, val.as_slice(), addr.addr + offset);
    }

    /// get vfio device's descriptors which are passed into minijail process
    pub fn keep_rds(&self) -> Vec<RawDescriptor> {
        vec![
            self.dev.as_raw_descriptor(),
            self.group_descriptor,
            self.container.lock().as_raw_descriptor(),
        ]
    }

    /// Add (iova, user_addr) map into vfio container iommu table
    pub unsafe fn vfio_dma_map(
        &self,
        iova: u64,
        size: u64,
        user_addr: u64,
        write_en: bool,
    ) -> Result<()> {
        self.container
            .lock()
            .vfio_dma_map(iova, size, user_addr, write_en)
    }

    /// Remove (iova, user_addr) map from vfio container iommu table
    pub fn vfio_dma_unmap(&self, iova: u64, size: u64) -> Result<()> {
        self.container.lock().vfio_dma_unmap(iova, size)
    }

    pub fn vfio_get_iommu_page_size_mask(&self) -> Result<u64> {
        self.container.lock().vfio_get_iommu_page_size_mask()
    }

    pub fn alloc_iova(&self, size: u64, align_size: u64, alloc: Alloc) -> Result<u64> {
        self.iova_alloc
            .lock()
            .allocate_with_align(size, alloc, "alloc_iova".to_owned(), align_size)
            .map_err(VfioError::Resources)
    }

    pub fn get_iova(&self, alloc: &Alloc) -> Option<AddressRange> {
        self.iova_alloc.lock().get(alloc).map(|res| res.0)
    }

    pub fn release_iova(&self, alloc: Alloc) -> Result<AddressRange> {
        self.iova_alloc
            .lock()
            .release(alloc)
            .map_err(VfioError::Resources)
    }

    pub fn get_max_addr(&self) -> u64 {
        self.iova_alloc.lock().get_max_addr()
    }

    /// Gets the vfio device backing `File`.
    pub fn device_file(&self) -> &File {
        &self.dev
    }

    /// close vfio device
    pub fn close(&self) {
        self.container.lock().remove_group(self.group_id, true);
    }
}

pub struct VfioPciConfig {
    device: Arc<VfioDevice>,
}

impl VfioPciConfig {
    pub fn new(device: Arc<VfioDevice>) -> Self {
        VfioPciConfig { device }
    }

    pub fn read_config<T: DataInit>(&self, offset: u32) -> T {
        let mut buf = vec![0u8; std::mem::size_of::<T>()];
        self.device
            .region_read(VFIO_PCI_CONFIG_REGION_INDEX, &mut buf, offset.into());
        T::from_slice(&buf)
            .copied()
            .expect("failed to convert config data from slice")
    }

    pub fn write_config<T: DataInit>(&self, config: T, offset: u32) {
        self.device.region_write(
            VFIO_PCI_CONFIG_REGION_INDEX,
            config.as_slice(),
            offset.into(),
        );
    }

    /// Set the VFIO device this config refers to as the bus master.
    pub fn set_bus_master(&self) {
        /// Constant definitions from `linux/pci_regs.h`.
        const PCI_COMMAND: u32 = 0x4;
        /// Enable bus mastering
        const PCI_COMMAND_MASTER: u16 = 0x4;

        let mut cmd: u16 = self.read_config(PCI_COMMAND);

        if cmd & PCI_COMMAND_MASTER != 0 {
            return;
        }

        cmd |= PCI_COMMAND_MASTER;

        self.write_config(cmd, PCI_COMMAND);
    }
}

impl AsRawDescriptor for VfioDevice {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.dev.as_raw_descriptor()
    }
}
