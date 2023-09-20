// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Resource management and resolution for the virtio-video device.

use std::convert::TryInto;
use std::fmt;

use base::FromRawDescriptor;
use base::IntoRawDescriptor;
use base::MemoryMappingArena;
use base::MemoryMappingBuilder;
use base::MemoryMappingBuilderUnix;
use base::MmapError;
use base::SafeDescriptor;
use thiserror::Error as ThisError;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
use vm_memory::GuestMemoryError;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

use crate::virtio::resource_bridge;
use crate::virtio::resource_bridge::ResourceBridgeError;
use crate::virtio::resource_bridge::ResourceInfo;
use crate::virtio::resource_bridge::ResourceRequest;
use crate::virtio::video::format::Format;
use crate::virtio::video::format::FramePlane;
use crate::virtio::video::params::Params;
use crate::virtio::video::protocol::virtio_video_mem_entry;
use crate::virtio::video::protocol::virtio_video_object_entry;

/// Defines how resources for a given queue are represented.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ResourceType {
    /// Resources are backed by guest memory pages.
    GuestPages,
    /// Resources are backed by virtio objects.
    #[default]
    VirtioObject,
}

#[repr(C)]
#[derive(Clone, Copy, AsBytes, FromZeroes, FromBytes)]
/// A guest resource entry which type is not decided yet.
pub union UnresolvedResourceEntry {
    pub object: virtio_video_object_entry,
    pub guest_mem: virtio_video_mem_entry,
}

impl fmt::Debug for UnresolvedResourceEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Safe because `self.object` and `self.guest_mem` are the same size and both made of
        // integers, making it safe to display them no matter their value.
        write!(
            f,
            "unresolved {:?} or {:?}",
            unsafe { self.object },
            unsafe { self.guest_mem }
        )
    }
}

/// Trait for types that can serve as video buffer backing memory.
pub trait BufferHandle: Sized {
    /// Try to clone this handle. This must only create a new reference to the same backing memory
    /// and not duplicate the buffer itself.
    fn try_clone(&self) -> Result<Self, base::Error>;

    /// Returns a linear mapping of [`offset`..`offset`+`size`] of the memory backing this buffer.
    fn get_mapping(&self, offset: usize, size: usize) -> Result<MemoryMappingArena, MmapError>;
}

/// Linear memory area of a `GuestMemHandle`
#[derive(Clone)]
pub struct GuestMemArea {
    /// Offset within the guest region to the start of the area.
    pub offset: u64,
    /// Length of the area within the memory region.
    pub length: usize,
}

pub struct GuestMemHandle {
    /// Descriptor to the guest memory region containing the buffer.
    pub desc: SafeDescriptor,
    /// Memory areas (i.e. sg list) that make the memory buffer.
    pub mem_areas: Vec<GuestMemArea>,
}

impl BufferHandle for GuestMemHandle {
    fn try_clone(&self) -> Result<Self, base::Error> {
        Ok(Self {
            desc: self.desc.try_clone()?,
            mem_areas: self.mem_areas.clone(),
        })
    }

    fn get_mapping(&self, offset: usize, size: usize) -> Result<MemoryMappingArena, MmapError> {
        let mut arena = MemoryMappingArena::new(size)?;
        let mut mapped_size = 0;
        let mut area_iter = self.mem_areas.iter();
        let mut area_offset = offset;
        while mapped_size < size {
            let area = match area_iter.next() {
                Some(area) => area,
                None => {
                    return Err(MmapError::InvalidRange(
                        offset,
                        size,
                        self.mem_areas.iter().map(|a| a.length).sum(),
                    ));
                }
            };
            if area_offset > area.length {
                area_offset -= area.length;
            } else {
                let mapping_length = std::cmp::min(area.length - area_offset, size - mapped_size);
                arena.add_fd_offset(mapped_size, mapping_length, &self.desc, area.offset)?;
                mapped_size += mapping_length;
                area_offset = 0;
            }
        }
        Ok(arena)
    }
}

pub struct VirtioObjectHandle {
    /// Descriptor for the object.
    pub desc: SafeDescriptor,
    /// Modifier to apply to frame resources.
    pub modifier: u64,
}

impl BufferHandle for VirtioObjectHandle {
    fn try_clone(&self) -> Result<Self, base::Error> {
        Ok(Self {
            desc: self.desc.try_clone()?,
            modifier: self.modifier,
        })
    }

    fn get_mapping(&self, offset: usize, size: usize) -> Result<MemoryMappingArena, MmapError> {
        MemoryMappingBuilder::new(size)
            .from_descriptor(&self.desc)
            .offset(offset as u64)
            .build()
            .map(MemoryMappingArena::from)
    }
}

pub enum GuestResourceHandle {
    GuestPages(GuestMemHandle),
    VirtioObject(VirtioObjectHandle),
}

impl BufferHandle for GuestResourceHandle {
    fn try_clone(&self) -> Result<Self, base::Error> {
        Ok(match self {
            Self::GuestPages(handle) => Self::GuestPages(handle.try_clone()?),
            Self::VirtioObject(handle) => Self::VirtioObject(handle.try_clone()?),
        })
    }

    fn get_mapping(&self, offset: usize, size: usize) -> Result<MemoryMappingArena, MmapError> {
        match self {
            GuestResourceHandle::GuestPages(handle) => handle.get_mapping(offset, size),
            GuestResourceHandle::VirtioObject(handle) => handle.get_mapping(offset, size),
        }
    }
}

pub struct GuestResource {
    /// Handle to the backing memory.
    pub handle: GuestResourceHandle,
    /// Layout of color planes, if the resource will receive frames.
    pub planes: Vec<FramePlane>,
    pub width: u32,
    pub height: u32,
    pub format: Format,
    /// Whether the buffer can be accessed by the guest CPU. This means the host must ensure that
    /// all operations on the buffer are completed before passing it to the guest.
    pub guest_cpu_mappable: bool,
}

#[derive(Debug, ThisError)]
pub enum GuestMemResourceCreationError {
    #[error("Provided slice of entries is empty")]
    NoEntriesProvided,
    #[error("cannot get shm region: {0}")]
    CantGetShmRegion(GuestMemoryError),
    #[error("cannot get shm offset: {0}")]
    CantGetShmOffset(GuestMemoryError),
    #[error("error while cloning shm region descriptor: {0}")]
    DescriptorCloneError(base::Error),
}

#[derive(Debug, ThisError)]
pub enum ObjectResourceCreationError {
    #[error("uuid {0:08} is larger than 32 bits")]
    UuidNot32Bits(u128),
    #[error("resource returned by bridge is not a buffer")]
    NotABuffer,
    #[error("resource bridge failure: {0}")]
    ResourceBridgeFailure(ResourceBridgeError),
}

impl GuestResource {
    /// Try to convert an unresolved virtio guest memory entry into a resolved guest memory
    /// resource.
    ///
    /// Convert `mem_entry` into the guest memory resource it represents and resolve it through
    /// `mem`.
    /// Width, height and format is set from `params`.
    ///
    /// Panics if `params.format` is `None`.
    pub fn from_virtio_guest_mem_entry(
        mem_entries: &[virtio_video_mem_entry],
        mem: &GuestMemory,
        params: &Params,
    ) -> Result<GuestResource, GuestMemResourceCreationError> {
        let region_desc = match mem_entries.first() {
            None => return Err(GuestMemResourceCreationError::NoEntriesProvided),
            Some(entry) => {
                let addr: u64 = entry.addr.into();

                let guest_region = mem
                    .shm_region(GuestAddress(addr))
                    .map_err(GuestMemResourceCreationError::CantGetShmRegion)?;
                let desc = base::clone_descriptor(guest_region)
                    .map_err(GuestMemResourceCreationError::DescriptorCloneError)?;
                // Safe because we are the sole owner of the duplicated descriptor.
                unsafe { SafeDescriptor::from_raw_descriptor(desc) }
            }
        };

        let mem_areas = mem_entries
            .iter()
            .map(|entry| {
                let addr: u64 = entry.addr.into();
                let length: u32 = entry.length.into();
                let region_offset = mem
                    .offset_from_base(GuestAddress(addr))
                    .map_err(GuestMemResourceCreationError::CantGetShmOffset)
                    .unwrap();

                GuestMemArea {
                    offset: region_offset,
                    length: length as usize,
                }
            })
            .collect();

        let handle = GuestResourceHandle::GuestPages(GuestMemHandle {
            desc: region_desc,
            mem_areas,
        });

        // The plane information can be computed from the currently set format.
        let mut buffer_offset = 0;
        let planes = params
            .plane_formats
            .iter()
            .map(|p| {
                let plane_offset = buffer_offset;
                buffer_offset += p.plane_size;

                FramePlane {
                    offset: plane_offset as usize,
                    stride: p.stride as usize,
                    size: p.plane_size as usize,
                }
            })
            .collect();

        Ok(GuestResource {
            handle,
            planes,
            width: params.frame_width,
            height: params.frame_height,
            format: params.format.unwrap(),
            guest_cpu_mappable: true,
        })
    }

    /// Try to convert an unresolved virtio object entry into a resolved object resource.
    ///
    /// Convert `object` into the object resource it represents and resolve it through `res_bridge`.
    /// Returns an error if the object's UUID is invalid or cannot be resolved to a buffer object
    /// by `res_bridge`.
    pub fn from_virtio_object_entry(
        object: virtio_video_object_entry,
        res_bridge: &base::Tube,
        params: &Params,
    ) -> Result<GuestResource, ObjectResourceCreationError> {
        // We trust that the caller has chosen the correct object type.
        let uuid = u128::from_be_bytes(object.uuid);

        // TODO(stevensd): `Virtio3DBackend::resource_assign_uuid` is currently implemented to use
        // 32-bits resource_handles as UUIDs. Once it starts using real UUIDs, we need to update
        // this conversion.
        let handle = TryInto::<u32>::try_into(uuid)
            .map_err(|_| ObjectResourceCreationError::UuidNot32Bits(uuid))?;

        let buffer_info = match resource_bridge::get_resource_info(
            res_bridge,
            ResourceRequest::GetBuffer { id: handle },
        ) {
            Ok(ResourceInfo::Buffer(buffer_info)) => buffer_info,
            Ok(_) => return Err(ObjectResourceCreationError::NotABuffer),
            Err(e) => return Err(ObjectResourceCreationError::ResourceBridgeFailure(e)),
        };

        let handle = GuestResourceHandle::VirtioObject(VirtioObjectHandle {
            // Safe because `buffer_info.file` is a valid file descriptor and we are stealing
            // it.
            desc: unsafe {
                SafeDescriptor::from_raw_descriptor(buffer_info.handle.into_raw_descriptor())
            },
            modifier: buffer_info.modifier,
        });

        // TODO(ishitatsuyuki): Right now, there are two sources of metadata: through the
        //                      virtio_video_params fields, or through the buffer metadata provided
        //                      by the VirtioObject backend.
        //                      Unfortunately neither is sufficient. The virtio_video_params struct
        //                      lacks the plane offset, while some virtio-gpu backend doesn't
        //                      have information about the plane size, or in some cases even the
        //                      overall frame width and height.
        //                      We will mix-and-match metadata from the more reliable data source
        //                      below; ideally this should be fixed to use single source of truth.
        let planes = params
            .plane_formats
            .iter()
            .zip(&buffer_info.planes)
            .map(|(param, buffer)| FramePlane {
                // When the virtio object backend was implemented, the buffer and stride was sourced
                // from the object backend's metadata (`buffer`). To lean on the safe side, we'll
                // keep using data from `buffer`, even in case of stride it's also provided by
                // `param`.
                offset: buffer.offset as usize,
                stride: buffer.stride as usize,
                size: param.plane_size as usize,
            })
            .collect();

        Ok(GuestResource {
            handle,
            planes,
            width: params.frame_width,
            height: params.frame_height,
            format: params.format.unwrap(),
            guest_cpu_mappable: buffer_info.guest_cpu_mappable,
        })
    }

    #[cfg(feature = "video-encoder")]
    pub fn try_clone(&self) -> Result<Self, base::Error> {
        Ok(Self {
            handle: self.handle.try_clone()?,
            planes: self.planes.clone(),
            width: self.width,
            height: self.height,
            format: self.format,
            guest_cpu_mappable: self.guest_cpu_mappable,
        })
    }
}

#[cfg(test)]
mod tests {
    use base::MappedRegion;
    use base::SafeDescriptor;
    use base::SharedMemory;

    use super::*;

    /// Creates a sparse guest memory handle using as many pages as there are entries in
    /// `page_order`. The page with index `0` will be the first page, `1` will be the second page,
    /// etc.
    ///
    /// The memory handle is filled with increasing u32s starting from page 0, then page 1, and so
    /// on. Finally the handle is mapped into a linear space and we check that the written integers
    /// appear in the expected order.
    fn check_guest_mem_handle(page_order: &[usize]) {
        const PAGE_SIZE: usize = 0x1000;
        const U32_SIZE: usize = std::mem::size_of::<u32>();
        const ENTRIES_PER_PAGE: usize = PAGE_SIZE / std::mem::size_of::<u32>();

        // Fill a vector of the same size as the handle with u32s of increasing value, following
        // the page layout given as argument.
        let mut data = vec![0u8; PAGE_SIZE * page_order.len()];
        for (page_index, page) in page_order.iter().enumerate() {
            let page_slice = &mut data[(page * PAGE_SIZE)..((page + 1) * PAGE_SIZE)];
            for (index, chunk) in page_slice.chunks_exact_mut(4).enumerate() {
                let sized_chunk: &mut [u8; 4] = chunk.try_into().unwrap();
                *sized_chunk = (((page_index * ENTRIES_PER_PAGE) + index) as u32).to_ne_bytes();
            }
        }

        // Copy the initialized vector's content into an anonymous shared memory.
        let mem = SharedMemory::new("data-dest", data.len() as u64).unwrap();
        let mapping = MemoryMappingBuilder::new(mem.size() as usize)
            .from_shared_memory(&mem)
            .build()
            .unwrap();
        assert_eq!(mapping.write_slice(&data, 0).unwrap(), data.len());

        // Create the `GuestMemHandle` we will try to map and retrieve the data from.
        let mem_handle = GuestResourceHandle::GuestPages(GuestMemHandle {
            desc: unsafe {
                SafeDescriptor::from_raw_descriptor(base::clone_descriptor(&mem).unwrap())
            },
            mem_areas: page_order
                .iter()
                .map(|&page| GuestMemArea {
                    offset: page as u64 * PAGE_SIZE as u64,
                    length: PAGE_SIZE,
                })
                .collect(),
        });

        // Map the handle into a linear memory area, retrieve its data into a new vector, and check
        // that its u32s appear to increase linearly.
        let mapping = mem_handle.get_mapping(0, mem.size() as usize).unwrap();
        let mut data = vec![0u8; PAGE_SIZE * page_order.len()];
        unsafe { std::ptr::copy_nonoverlapping(mapping.as_ptr(), data.as_mut_ptr(), data.len()) };
        for (index, chunk) in data.chunks_exact(U32_SIZE).enumerate() {
            let sized_chunk: &[u8; 4] = chunk.try_into().unwrap();
            assert_eq!(u32::from_ne_bytes(*sized_chunk), index as u32);
        }
    }

    // Fill a guest memory handle with a single memory page.
    // Then check that the data can be properly mapped and appears in the expected order.
    #[test]
    fn test_single_guest_mem_handle() {
        check_guest_mem_handle(&[0])
    }

    // Fill a guest memory handle with 4 memory pages that are contiguous.
    // Then check that the pages appear in the expected order in the mapping.
    #[test]
    fn test_linear_guest_mem_handle() {
        check_guest_mem_handle(&[0, 1, 2, 3])
    }

    // Fill a guest memory handle with 8 pages mapped in non-linear order.
    // Then check that the pages appear in the expected order in the mapping.
    #[test]
    fn test_sparse_guest_mem_handle() {
        check_guest_mem_handle(&[1, 7, 6, 3, 5, 0, 4, 2])
    }
}
