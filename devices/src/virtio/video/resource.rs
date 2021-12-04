// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Resource management and resolution for the virtio-video device.

use std::convert::TryInto;
use std::fmt;

use base::{FromRawDescriptor, IntoRawDescriptor, SafeDescriptor};
use thiserror::Error as ThisError;

use crate::virtio::resource_bridge::{self, ResourceBridgeError, ResourceInfo, ResourceRequest};
use crate::virtio::video::format::FramePlane;
use crate::virtio::video::protocol::virtio_video_object_entry;

/// Defines how resources for a given queue are represented.
#[derive(Clone, Copy, Debug)]
pub enum ResourceType {
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
/// A guest resource which type is not decided yet.
pub union UnresolvedGuestResource {
    pub object: virtio_video_object_entry,
}
unsafe impl data_model::DataInit for UnresolvedGuestResource {}

impl fmt::Debug for UnresolvedGuestResource {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Safe because `self.object` is a [u8] and thus is valid no matter its raw data.
        write!(f, "unresolved {:?}", unsafe { self.object })
    }
}

pub struct VirtioObjectHandle {
    /// Descriptor for the object.
    pub desc: SafeDescriptor,
    /// Modifier to apply to frame resources.
    pub modifier: u64,
}

impl VirtioObjectHandle {
    pub fn try_clone(&self) -> Result<Self, base::Error> {
        Ok(Self {
            desc: self.desc.try_clone()?,
            modifier: self.modifier,
        })
    }
}

pub enum GuestResourceHandle {
    VirtioObject(VirtioObjectHandle),
}

impl GuestResourceHandle {
    pub fn try_clone(&self) -> Result<Self, base::Error> {
        Ok(match self {
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
pub enum ObjectResourceCreationError {
    #[error("uuid {0:08} is larger than 32 bits")]
    UuidNot32Bits(u128),
    #[error("resource returned by bridge is not a buffer")]
    NotABuffer,
    #[error("resource bridge failure: {0}")]
    ResourceBridgeFailure(ResourceBridgeError),
}

impl GuestResource {
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
