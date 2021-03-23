// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! The cross-domain component type, specialized for allocating and sharing resources across domain
//! boundaries.

use std::collections::BTreeMap as Map;
use std::mem::size_of;
use std::os::unix::net::UnixStream;
use std::sync::Arc;

use crate::cross_domain::cross_domain_protocol::*;
use crate::rutabaga_core::{RutabagaComponent, RutabagaContext, RutabagaResource};
use crate::rutabaga_utils::*;
use crate::{
    DrmFormat, ImageAllocationInfo, ImageMemoryRequirements, RutabagaGralloc, RutabagaGrallocFlags,
};

use data_model::{DataInit, VolatileMemory, VolatileSlice};

use sync::Mutex;

struct CrossDomainResource {
    pub handle: Option<Arc<RutabagaHandle>>,
    pub backing_iovecs: Option<Vec<RutabagaIovec>>,
}

/// The CrossDomain component contains a list of channels that the guest may connect to and the
/// ability to allocate memory.
pub struct CrossDomain {
    channels: Option<Vec<RutabagaChannel>>,
    gralloc: Arc<Mutex<RutabagaGralloc>>,
}

struct CrossDomainContext {
    channels: Option<Vec<RutabagaChannel>>,
    gralloc: Arc<Mutex<RutabagaGralloc>>,
    connection: Option<UnixStream>,
    ring_id: u32,
    requirements_blobs: Map<u64, ImageMemoryRequirements>,
    context_resources: Map<u32, CrossDomainResource>,
    last_fence_data: Option<RutabagaFenceData>,
    blob_id: u64,
}

impl CrossDomain {
    /// Initializes the cross-domain component by taking the the rutabaga channels (if any) and
    /// initializing rutabaga gralloc.
    pub fn init(
        channels: Option<Vec<RutabagaChannel>>,
    ) -> RutabagaResult<Box<dyn RutabagaComponent>> {
        let gralloc = RutabagaGralloc::new()?;
        Ok(Box::new(CrossDomain {
            channels,
            gralloc: Arc::new(Mutex::new(gralloc)),
        }))
    }
}

impl CrossDomainContext {
    fn initialize(&mut self, cmd_init: &CrossDomainInit) -> RutabagaResult<()> {
        if !self.context_resources.contains_key(&cmd_init.ring_id) {
            return Err(RutabagaError::InvalidResourceId);
        }

        self.ring_id = cmd_init.ring_id;
        // Zero means no requested channel.
        if cmd_init.channel_type != 0 {
            let channels = self.channels.take().ok_or(RutabagaError::SpecViolation)?;
            let base_channel = &channels
                .iter()
                .find(|channel| channel.channel_type == cmd_init.channel_type)
                .ok_or(RutabagaError::SpecViolation)?
                .base_channel;

            self.connection = Some(UnixStream::connect(base_channel)?);
        }

        Ok(())
    }

    fn get_image_requirements(
        &mut self,
        cmd_get_reqs: &CrossDomainGetImageRequirements,
    ) -> RutabagaResult<()> {
        let info = ImageAllocationInfo {
            width: cmd_get_reqs.width,
            height: cmd_get_reqs.height,
            drm_format: DrmFormat::from(cmd_get_reqs.drm_format),
            flags: RutabagaGrallocFlags::new(cmd_get_reqs.flags),
        };

        self.blob_id += 1;
        let reqs = self.gralloc.lock().get_image_memory_requirements(info)?;

        let mut response = CrossDomainImageRequirements {
            strides: reqs.strides,
            offsets: reqs.offsets,
            modifier: reqs.modifier,
            size: reqs.size,
            blob_id: self.blob_id,
            map_info: reqs.map_info,
            pad: 0,
            memory_idx: -1,
            physical_device_idx: -1,
        };

        if let Some(ref vk_info) = reqs.vulkan_info {
            response.memory_idx = vk_info.memory_idx as i32;
            response.physical_device_idx = vk_info.physical_device_idx as i32;
        }

        let resource = self
            .context_resources
            .get_mut(&self.ring_id)
            .ok_or(RutabagaError::InvalidResourceId)?;

        let iovecs = resource
            .backing_iovecs
            .take()
            .ok_or(RutabagaError::InvalidIovec)?;

        // Safe because we've verified the iovecs are attached and owned only by this context.
        let slice =
            unsafe { VolatileSlice::from_raw_parts(iovecs[0].base as *mut u8, iovecs[0].len) };

        // The copy_from(..) method guarantees out of bounds buffer accesses will not occur.
        slice.copy_from(&[response]);
        resource.backing_iovecs = Some(iovecs);
        self.requirements_blobs.insert(self.blob_id, reqs);
        Ok(())
    }
}

impl RutabagaContext for CrossDomainContext {
    fn context_create_blob(
        &mut self,
        resource_id: u32,
        resource_create_blob: ResourceCreateBlob,
        handle: Option<RutabagaHandle>,
    ) -> RutabagaResult<RutabagaResource> {
        let reqs = self
            .requirements_blobs
            .get(&resource_create_blob.blob_id)
            .ok_or(RutabagaError::SpecViolation)?;

        if reqs.size != resource_create_blob.size {
            return Err(RutabagaError::SpecViolation);
        }

        // Strictly speaking, it's against the virtio-gpu spec to allocate memory in the context
        // create blob function, which says "the actual allocation is done via
        // VIRTIO_GPU_CMD_SUBMIT_3D."  However, atomic resource creation is easiest for the
        // cross-domain use case, so whatever.
        let hnd = match handle {
            Some(handle) => handle,
            None => self.gralloc.lock().allocate_memory(*reqs)?,
        };

        let info_3d = Resource3DInfo {
            width: reqs.info.width,
            height: reqs.info.height,
            drm_fourcc: reqs.info.drm_format.into(),
            strides: reqs.strides,
            offsets: reqs.offsets,
            modifier: reqs.modifier,
        };

        Ok(RutabagaResource {
            resource_id,
            handle: Some(Arc::new(hnd)),
            blob: true,
            blob_mem: resource_create_blob.blob_mem,
            blob_flags: resource_create_blob.blob_flags,
            map_info: Some(reqs.map_info),
            info_2d: None,
            info_3d: Some(info_3d),
            vulkan_info: reqs.vulkan_info,
            backing_iovecs: None,
        })
    }

    fn submit_cmd(&mut self, commands: &mut [u8]) -> RutabagaResult<()> {
        let size = commands.len();
        let slice = VolatileSlice::new(commands);
        let mut offset: usize = 0;

        while offset < size {
            let hdr: CrossDomainHeader = slice.get_ref(offset)?.load();

            match hdr.cmd {
                CROSS_DOMAIN_CMD_INIT => {
                    let cmd_init: CrossDomainInit = slice.get_ref(offset)?.load();

                    self.initialize(&cmd_init)?;
                }
                CROSS_DOMAIN_CMD_GET_IMAGE_REQUIREMENTS => {
                    let cmd_get_reqs: CrossDomainGetImageRequirements =
                        slice.get_ref(offset)?.load();

                    self.get_image_requirements(&cmd_get_reqs)?;
                }
                _ => return Err(RutabagaError::Unsupported),
            }

            offset += hdr.cmd_size as usize;
        }

        Ok(())
    }

    fn attach(&mut self, resource: &mut RutabagaResource) {
        match resource.blob_mem {
            RUTABAGA_BLOB_MEM_GUEST => {
                self.context_resources.insert(
                    resource.resource_id,
                    CrossDomainResource {
                        handle: None,
                        backing_iovecs: resource.backing_iovecs.take(),
                    },
                );
            }
            _ => match resource.handle {
                Some(ref handle) => {
                    self.context_resources.insert(
                        resource.resource_id,
                        CrossDomainResource {
                            handle: Some(handle.clone()),
                            backing_iovecs: None,
                        },
                    );
                }
                _ => (),
            },
        }
    }

    fn detach(&mut self, resource: &RutabagaResource) {
        self.context_resources.remove(&resource.resource_id);
    }

    fn context_create_fence(&mut self, fence_data: RutabagaFenceData) -> RutabagaResult<()> {
        self.last_fence_data = Some(fence_data);
        Ok(())
    }

    fn context_poll(&mut self) -> Option<Vec<RutabagaFenceData>> {
        let fence_data = self.last_fence_data.take();
        match fence_data {
            Some(fence_data) => Some(vec![fence_data]),
            None => None,
        }
    }
}

impl RutabagaComponent for CrossDomain {
    fn get_capset_info(&self, _capset_id: u32) -> (u32, u32) {
        return (0u32, size_of::<CrossDomainCapabilities>() as u32);
    }

    fn get_capset(&self, _capset_id: u32, _version: u32) -> Vec<u8> {
        let mut caps: CrossDomainCapabilities = Default::default();
        match self.channels {
            Some(ref channels) => {
                for channel in channels {
                    caps.supported_channels = 1 << channel.channel_type;
                }
            }
            None => (),
        };

        if self.gralloc.lock().supports_dmabuf() {
            caps.supports_dmabuf = 1;
        }

        if self.gralloc.lock().supports_external_gpu_memory() {
            caps.supports_external_gpu_memory = 1;
        }

        // Version 1 supports all commands up to and including CROSS_DOMAIN_CMD_RECEIVE.
        caps.version = 1;
        caps.as_slice().to_vec()
    }

    fn create_context(
        &self,
        _ctx_id: u32,
        _context_init: u32,
    ) -> RutabagaResult<Box<dyn RutabagaContext>> {
        Ok(Box::new(CrossDomainContext {
            channels: self.channels.clone(),
            gralloc: self.gralloc.clone(),
            connection: None,
            ring_id: 0,
            requirements_blobs: Default::default(),
            context_resources: Default::default(),
            last_fence_data: None,
            blob_id: 0,
        }))
    }
}
