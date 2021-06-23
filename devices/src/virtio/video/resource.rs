// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Resource management and resolution for the virtio-video device.

use std::convert::TryInto;
use std::fmt;

use base::{self, FromRawDescriptor, IntoRawDescriptor, SafeDescriptor};
use vm_memory::{GuestAddress, GuestMemory, GuestMemoryError};

use thiserror::Error as ThisError;

use crate::virtio::resource_bridge::{self, ResourceBridgeError, ResourceInfo, ResourceRequest};
use crate::virtio::video::format::{FramePlane, PlaneFormat};
use crate::virtio::video::protocol::{virtio_video_mem_entry, virtio_video_object_entry};

/// Defines how resources for a given queue are represented.
#[derive(Clone, Copy, Debug)]
pub enum ResourceType {
    /// Resources are backed by guest memory pages.
    GuestPages,
    /// Resources are backed by virtio objects.
    VirtioObject,
}

impl Default for ResourceType {
    fn default() -> Self {
        ResourceType::VirtioObject
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
/// A guest resource entry which type is not decided yet.
pub union UnresolvedResourceEntry {
    pub object: virtio_video_object_entry,
    pub guest_mem: virtio_video_mem_entry,
}
unsafe impl data_model::DataInit for UnresolvedResourceEntry {}

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
}

pub struct GuestResource {
    /// Handle to the backing memory.
    pub handle: GuestResourceHandle,
    /// Layout of color planes, if the resource will receive frames.
    pub planes: Vec<FramePlane>,
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
    /// `mem`. `planes_format` describes the format of the individual planes for the buffer.
    pub fn from_virtio_guest_mem_entry(
        mem_entries: &[virtio_video_mem_entry],
        mem: &GuestMemory,
        planes_format: &[PlaneFormat],
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
            .into_iter()
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

        // The plane information can be computed from the currently set format.
        let mut buffer_offset = 0;
        let planes = planes_format
            .iter()
            .map(|p| {
                let plane_offset = buffer_offset;
                buffer_offset += p.plane_size;

                FramePlane {
                    offset: plane_offset as usize,
                    stride: p.stride as usize,
                }
            })
            .collect();

        Ok(GuestResource {
            handle: GuestResourceHandle::GuestPages(GuestMemHandle {
                desc: region_desc,
                mem_areas,
            }),
            planes,
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

        Ok(GuestResource {
            handle: GuestResourceHandle::VirtioObject(VirtioObjectHandle {
                // Safe because `buffer_info.file` is a valid file descriptor and we are stealing
                // it.
                desc: unsafe {
                    SafeDescriptor::from_raw_descriptor(buffer_info.file.into_raw_descriptor())
                },
                modifier: buffer_info.modifier,
            }),
            planes: buffer_info
                .planes
                .iter()
                .take_while(|p| p.offset != 0 || p.stride != 0)
                .map(|p| FramePlane {
                    offset: p.offset as usize,
                    stride: p.stride as usize,
                })
                .collect(),
        })
    }

    #[cfg(feature = "video-encoder")]
    pub fn try_clone(&self) -> Result<Self, base::Error> {
        Ok(Self {
            handle: self.handle.try_clone()?,
            planes: self.planes.clone(),
        })
    }
}
