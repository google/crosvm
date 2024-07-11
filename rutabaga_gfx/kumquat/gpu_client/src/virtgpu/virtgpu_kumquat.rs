// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp::min;
use std::collections::BTreeMap as Map;
use std::convert::TryInto;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::slice::from_raw_parts_mut;

use nix::unistd::read;
use rutabaga_gfx::kumquat_gpu_protocol::*;
use rutabaga_gfx::RutabagaDescriptor;
use rutabaga_gfx::RutabagaError;
use rutabaga_gfx::RutabagaFromRawDescriptor;
use rutabaga_gfx::RutabagaGralloc;
use rutabaga_gfx::RutabagaGrallocBackendFlags;
use rutabaga_gfx::RutabagaHandle;
use rutabaga_gfx::RutabagaIntoRawDescriptor;
use rutabaga_gfx::RutabagaMappedRegion;
use rutabaga_gfx::RutabagaMapping;
use rutabaga_gfx::RutabagaMemoryMapping;
use rutabaga_gfx::RutabagaRawDescriptor;
use rutabaga_gfx::RutabagaReader;
use rutabaga_gfx::RutabagaResult;
use rutabaga_gfx::RutabagaSharedMemory;
use rutabaga_gfx::RutabagaStream;
use rutabaga_gfx::RutabagaWriter;
use rutabaga_gfx::VulkanInfo;
use rutabaga_gfx::RUTABAGA_FLAG_FENCE;
use rutabaga_gfx::RUTABAGA_FLAG_FENCE_HOST_SHAREABLE;
use rutabaga_gfx::RUTABAGA_FLAG_INFO_RING_IDX;
use rutabaga_gfx::RUTABAGA_MAP_ACCESS_RW;
use rutabaga_gfx::RUTABAGA_MAP_CACHE_CACHED;
use rutabaga_gfx::RUTABAGA_MEM_HANDLE_TYPE_OPAQUE_FD;

use crate::virtgpu::defines::*;

const VK_ICD_FILENAMES: &str = "VK_ICD_FILENAMES";

pub struct VirtGpuResource {
    resource_id: u32,
    size: usize,
    handle: RutabagaHandle,
    attached_fences: Vec<RutabagaHandle>,
    vulkan_info: VulkanInfo,
    system_mapping: Option<RutabagaMemoryMapping>,
    gpu_mapping: Option<Box<dyn RutabagaMappedRegion>>,
}

impl VirtGpuResource {
    pub fn new(
        resource_id: u32,
        size: usize,
        handle: RutabagaHandle,
        vulkan_info: VulkanInfo,
    ) -> VirtGpuResource {
        VirtGpuResource {
            resource_id,
            size,
            handle,
            attached_fences: Vec::new(),
            vulkan_info,
            system_mapping: None,
            gpu_mapping: None,
        }
    }
}

pub struct VirtGpuKumquat {
    context_id: u32,
    id_allocator: u32,
    capset_mask: u64,
    stream: RutabagaStream,
    capsets: Map<u32, Vec<u8>>,
    resources: Map<u32, VirtGpuResource>,
    gralloc_opt: Option<RutabagaGralloc>,
}

impl VirtGpuKumquat {
    pub fn new() -> RutabagaResult<VirtGpuKumquat> {
        let connection = UnixStream::connect("/tmp/rutabaga-0")?;
        let mut stream = RutabagaStream::new(connection);

        let get_num_capsets = kumquat_gpu_protocol_ctrl_hdr {
            type_: KUMQUAT_GPU_PROTOCOL_GET_NUM_CAPSETS,
            ..Default::default()
        };

        stream.write(KumquatGpuProtocolWrite::Cmd(get_num_capsets))?;
        let mut protocols = stream.read()?;
        let num_capsets = match protocols.remove(0) {
            KumquatGpuProtocol::RespNumCapsets(num) => num,
            _ => return Err(RutabagaError::Unsupported),
        };

        let mut capset_mask = 0;
        let mut capsets: Map<u32, Vec<u8>> = Default::default();
        for capset_index in 0..num_capsets {
            let get_capset_info = kumquat_gpu_protocol_ctrl_hdr {
                type_: KUMQUAT_GPU_PROTOCOL_GET_CAPSET_INFO,
                payload: capset_index,
            };

            stream.write(KumquatGpuProtocolWrite::Cmd(get_capset_info))?;
            protocols = stream.read()?;
            let resp_capset_info = match protocols.remove(0) {
                KumquatGpuProtocol::RespCapsetInfo(info) => info,
                _ => return Err(RutabagaError::Unsupported),
            };

            let get_capset = kumquat_gpu_protocol_get_capset {
                hdr: kumquat_gpu_protocol_ctrl_hdr {
                    type_: KUMQUAT_GPU_PROTOCOL_GET_CAPSET,
                    ..Default::default()
                },
                capset_id: resp_capset_info.capset_id,
                capset_version: resp_capset_info.version,
            };

            stream.write(KumquatGpuProtocolWrite::Cmd(get_capset))?;
            protocols = stream.read()?;
            let capset = match protocols.remove(0) {
                KumquatGpuProtocol::RespCapset(capset) => capset,
                _ => return Err(RutabagaError::Unsupported),
            };

            capset_mask = 1u64 << resp_capset_info.capset_id | capset_mask;
            capsets.insert(resp_capset_info.capset_id, capset);
        }

        Ok(VirtGpuKumquat {
            context_id: 0,
            id_allocator: 0,
            capset_mask,
            stream,
            capsets,
            resources: Default::default(),
            gralloc_opt: None,
        })
    }

    pub fn allocate_id(&mut self) -> u32 {
        self.id_allocator = self.id_allocator + 1;
        self.id_allocator
    }

    pub fn get_param(&self, getparam: &mut VirtGpuParam) -> RutabagaResult<()> {
        getparam.value = match getparam.param {
            VIRTGPU_KUMQUAT_PARAM_3D_FEATURES => (self.capset_mask != 0) as u64,
            VIRTGPU_KUMQUAT_PARAM_CAPSET_QUERY_FIX..=VIRTGPU_KUMQUAT_PARAM_CONTEXT_INIT => 1,
            VIRTGPU_KUMQUAT_PARAM_SUPPORTED_CAPSET_IDS => self.capset_mask,
            VIRTGPU_KUMQUAT_PARAM_EXPLICIT_DEBUG_NAME => 0,
            VIRTGPU_KUMQUAT_PARAM_FENCE_PASSING => 1,
            _ => return Err(RutabagaError::Unsupported),
        };

        Ok(())
    }

    pub fn get_caps(&self, capset_id: u32, slice: &mut [u8]) -> RutabagaResult<()> {
        let caps = self
            .capsets
            .get(&capset_id)
            .ok_or(RutabagaError::InvalidCapset)?;
        let length = min(slice.len(), caps.len());
        slice.copy_from_slice(&caps[0..length]);
        Ok(())
    }

    pub fn context_create(&mut self, capset_id: u64, name: &str) -> RutabagaResult<u32> {
        let mut debug_name = [0u8; 64];
        debug_name
            .iter_mut()
            .zip(name.bytes())
            .for_each(|(dst, src)| *dst = src);

        let context_create = kumquat_gpu_protocol_ctx_create {
            hdr: kumquat_gpu_protocol_ctrl_hdr {
                type_: KUMQUAT_GPU_PROTOCOL_CTX_CREATE,
                ..Default::default()
            },
            nlen: 0,
            context_init: capset_id.try_into()?,
            debug_name,
        };

        self.stream
            .write(KumquatGpuProtocolWrite::Cmd(context_create))?;
        let mut protocols = self.stream.read()?;
        self.context_id = match protocols.remove(0) {
            KumquatGpuProtocol::RespContextCreate(ctx_id) => ctx_id,
            _ => return Err(RutabagaError::Unsupported),
        };

        Ok(self.context_id)
    }

    pub fn resource_create_3d(
        &mut self,
        create_3d: &mut VirtGpuResourceCreate3D,
    ) -> RutabagaResult<()> {
        let resource_create_3d = kumquat_gpu_protocol_resource_create_3d {
            hdr: kumquat_gpu_protocol_ctrl_hdr {
                type_: KUMQUAT_GPU_PROTOCOL_RESOURCE_CREATE_3D,
                ..Default::default()
            },
            target: create_3d.target,
            format: create_3d.format,
            bind: create_3d.bind,
            width: create_3d.width,
            height: create_3d.height,
            depth: create_3d.depth,
            array_size: create_3d.array_size,
            last_level: create_3d.last_level,
            nr_samples: create_3d.nr_samples,
            flags: create_3d.flags,
            size: create_3d.size,
            stride: create_3d.stride,
        };

        self.stream
            .write(KumquatGpuProtocolWrite::Cmd(resource_create_3d))?;
        let mut protocols = self.stream.read()?;
        let resource = match protocols.remove(0) {
            KumquatGpuProtocol::RespResourceCreate(resp, handle) => {
                let size: usize = create_3d.size.try_into()?;
                VirtGpuResource::new(resp.resource_id, size, handle, resp.vulkan_info)
            }
            _ => return Err(RutabagaError::Unsupported),
        };

        create_3d.res_handle = resource.resource_id;
        create_3d.bo_handle = self.allocate_id();
        self.resources.insert(create_3d.bo_handle, resource);

        Ok(())
    }

    pub fn resource_create_blob(
        &mut self,
        create_blob: &mut VirtGpuResourceCreateBlob,
        blob_cmd: &[u8],
    ) -> RutabagaResult<()> {
        if blob_cmd.len() != 0 {
            let submit_command = kumquat_gpu_protocol_cmd_submit {
                hdr: kumquat_gpu_protocol_ctrl_hdr {
                    type_: KUMQUAT_GPU_PROTOCOL_SUBMIT_3D,
                    ..Default::default()
                },
                ctx_id: self.context_id,
                pad: 0,
                size: blob_cmd.len().try_into()?,
                num_in_fences: 0,
                flags: 0,
                ring_idx: 0,
                padding: Default::default(),
            };

            let mut data: Vec<u8> = vec![0; blob_cmd.len()];
            data.copy_from_slice(blob_cmd);

            self.stream
                .write(KumquatGpuProtocolWrite::CmdWithData(submit_command, data))?;
        }

        let resource_create_blob = kumquat_gpu_protocol_resource_create_blob {
            hdr: kumquat_gpu_protocol_ctrl_hdr {
                type_: KUMQUAT_GPU_PROTOCOL_RESOURCE_CREATE_BLOB,
                ..Default::default()
            },
            ctx_id: self.context_id,
            blob_mem: create_blob.blob_mem,
            blob_flags: create_blob.blob_flags,
            padding: 0,
            blob_id: create_blob.blob_id,
            size: create_blob.size,
        };

        self.stream
            .write(KumquatGpuProtocolWrite::Cmd(resource_create_blob))?;
        let mut protocols = self.stream.read()?;
        let resource = match protocols.remove(0) {
            KumquatGpuProtocol::RespResourceCreate(resp, handle) => {
                let size: usize = create_blob.size.try_into()?;
                VirtGpuResource::new(resp.resource_id, size, handle, resp.vulkan_info)
            }
            _ => {
                return Err(RutabagaError::Unsupported);
            }
        };

        create_blob.res_handle = resource.resource_id;
        create_blob.bo_handle = self.allocate_id();
        self.resources.insert(create_blob.bo_handle, resource);
        Ok(())
    }

    pub fn resource_unref(&mut self, bo_handle: u32) -> RutabagaResult<()> {
        let resource = self
            .resources
            .remove(&bo_handle)
            .ok_or(RutabagaError::InvalidResourceId)?;

        let detach_resource = kumquat_gpu_protocol_ctx_resource {
            hdr: kumquat_gpu_protocol_ctrl_hdr {
                type_: KUMQUAT_GPU_PROTOCOL_CTX_DETACH_RESOURCE,
                ..Default::default()
            },
            ctx_id: self.context_id,
            resource_id: resource.resource_id,
        };

        self.stream
            .write(KumquatGpuProtocolWrite::Cmd(detach_resource))?;

        Ok(())
    }

    pub fn map(&mut self, bo_handle: u32) -> RutabagaResult<RutabagaMapping> {
        let resource = self
            .resources
            .get_mut(&bo_handle)
            .ok_or(RutabagaError::InvalidResourceId)?;

        if let Some(ref system_mapping) = resource.system_mapping {
            let rutabaga_mapping = system_mapping.as_rutabaga_mapping();
            Ok(rutabaga_mapping)
        } else if let Some(ref gpu_mapping) = resource.gpu_mapping {
            let rutabaga_mapping = gpu_mapping.as_rutabaga_mapping();
            Ok(rutabaga_mapping)
        } else {
            let clone = resource.handle.try_clone()?;

            if clone.handle_type == RUTABAGA_MEM_HANDLE_TYPE_OPAQUE_FD {
                if self.gralloc_opt.is_none() {
                    // The idea is to make sure the gfxstream ICD isn't loaded when gralloc starts
                    // up. The Nvidia ICD should be loaded.
                    let vk_driver = std::env::var(VK_ICD_FILENAMES).unwrap();
                    std::env::remove_var(VK_ICD_FILENAMES);
                    self.gralloc_opt =
                        Some(RutabagaGralloc::new(RutabagaGrallocBackendFlags::new())?);
                    std::env::set_var(VK_ICD_FILENAMES, vk_driver);
                }

                if let Some(ref mut gralloc) = self.gralloc_opt {
                    let region = gralloc.import_and_map(
                        clone,
                        resource.vulkan_info,
                        resource.size as u64,
                    )?;

                    let rutabaga_mapping = region.as_rutabaga_mapping();
                    resource.gpu_mapping = Some(region);
                    Ok(rutabaga_mapping)
                } else {
                    return Err(RutabagaError::SpecViolation("no gralloc"));
                }
            } else {
                let mapping = RutabagaMemoryMapping::from_safe_descriptor(
                    clone.os_handle,
                    resource.size,
                    RUTABAGA_MAP_CACHE_CACHED | RUTABAGA_MAP_ACCESS_RW,
                )?;

                let rutabaga_mapping = mapping.as_rutabaga_mapping();
                resource.system_mapping = Some(mapping);
                Ok(rutabaga_mapping)
            }
        }
    }

    pub fn unmap(&mut self, bo_handle: u32) -> RutabagaResult<()> {
        let resource = self
            .resources
            .get_mut(&bo_handle)
            .ok_or(RutabagaError::InvalidResourceId)?;

        resource.system_mapping = None;
        resource.gpu_mapping = None;
        Ok(())
    }

    pub fn transfer_to_host(&mut self, transfer: &VirtGpuTransfer) -> RutabagaResult<()> {
        let resource = self
            .resources
            .get_mut(&transfer.bo_handle)
            .ok_or(RutabagaError::InvalidResourceId)?;

        let transfer_to_host = kumquat_gpu_protocol_transfer_host_3d {
            hdr: kumquat_gpu_protocol_ctrl_hdr {
                type_: KUMQUAT_GPU_PROTOCOL_TRANSFER_TO_HOST_3D,
                ..Default::default()
            },
            box_: kumquat_gpu_protocol_box {
                x: transfer._box.x,
                y: transfer._box.y,
                z: transfer._box.z,
                w: transfer._box.w,
                h: transfer._box.h,
                d: transfer._box.d,
            },
            offset: transfer.offset,
            level: transfer.level,
            stride: transfer.stride,
            layer_stride: transfer.layer_stride,
            ctx_id: self.context_id,
            resource_id: resource.resource_id,
            padding: 0,
        };

        self.stream
            .write(KumquatGpuProtocolWrite::Cmd(transfer_to_host))?;
        Ok(())
    }

    pub fn transfer_from_host(&mut self, transfer: &VirtGpuTransfer) -> RutabagaResult<()> {
        let resource = self
            .resources
            .get_mut(&transfer.bo_handle)
            .ok_or(RutabagaError::InvalidResourceId)?;

        let transfer_from_host = kumquat_gpu_protocol_transfer_host_3d {
            hdr: kumquat_gpu_protocol_ctrl_hdr {
                type_: KUMQUAT_GPU_PROTOCOL_TRANSFER_FROM_HOST_3D,
                ..Default::default()
            },
            box_: kumquat_gpu_protocol_box {
                x: transfer._box.x,
                y: transfer._box.y,
                z: transfer._box.z,
                w: transfer._box.w,
                h: transfer._box.h,
                d: transfer._box.d,
            },
            offset: transfer.offset,
            level: transfer.level,
            stride: transfer.stride,
            layer_stride: transfer.layer_stride,
            ctx_id: self.context_id,
            resource_id: resource.resource_id,
            padding: 0,
        };

        self.stream
            .write(KumquatGpuProtocolWrite::Cmd(transfer_from_host))?;
        Ok(())
    }

    pub fn submit_command(
        &mut self,
        flags: u32,
        bo_handles: &[u32],
        cmd: &[u8],
        ring_idx: u32,
        in_fences: &[u64],
        raw_descriptor: &mut RutabagaRawDescriptor,
    ) -> RutabagaResult<()> {
        let mut fence_opt: Option<RutabagaHandle> = None;
        let mut data: Vec<u8> = vec![0; cmd.len()];
        let mut host_flags = 0;

        if flags & VIRTGPU_KUMQUAT_EXECBUF_RING_IDX != 0 {
            host_flags = RUTABAGA_FLAG_INFO_RING_IDX;
        }

        let need_fence =
            bo_handles.len() != 0 || (flags & VIRTGPU_KUMQUAT_EXECBUF_FENCE_FD_OUT) != 0;

        let actual_fence = (flags & VIRTGPU_KUMQUAT_EXECBUF_SHAREABLE_OUT) != 0
            && (flags & VIRTGPU_KUMQUAT_EXECBUF_FENCE_FD_OUT) != 0;

        // Should copy from in-fences when gfxstream supports it.
        data.copy_from_slice(cmd);

        if actual_fence {
            host_flags |= RUTABAGA_FLAG_FENCE_HOST_SHAREABLE;
            host_flags |= RUTABAGA_FLAG_FENCE;
        } else if need_fence {
            host_flags |= RUTABAGA_FLAG_FENCE;
        }

        let submit_command = kumquat_gpu_protocol_cmd_submit {
            hdr: kumquat_gpu_protocol_ctrl_hdr {
                type_: KUMQUAT_GPU_PROTOCOL_SUBMIT_3D,
                ..Default::default()
            },
            ctx_id: self.context_id,
            pad: 0,
            size: cmd.len().try_into()?,
            num_in_fences: in_fences.len().try_into()?,
            flags: host_flags,
            ring_idx: ring_idx.try_into()?,
            padding: Default::default(),
        };

        if need_fence {
            self.stream
                .write(KumquatGpuProtocolWrite::CmdWithData(submit_command, data))?;

            let mut protocols = self.stream.read()?;
            let fence = match protocols.remove(0) {
                KumquatGpuProtocol::RespCmdSubmit3d(_fence_id, handle) => handle,
                _ => {
                    return Err(RutabagaError::Unsupported);
                }
            };

            for handle in bo_handles {
                // We could support implicit sync with real fences, but the need does not exist.
                if actual_fence {
                    return Err(RutabagaError::Unsupported);
                }

                let resource = self
                    .resources
                    .get_mut(handle)
                    .ok_or(RutabagaError::InvalidResourceId)?;

                resource.attached_fences.push(fence.try_clone()?);
            }

            fence_opt = Some(fence);
        } else {
            self.stream
                .write(KumquatGpuProtocolWrite::CmdWithData(submit_command, data))?;
        }

        if flags & VIRTGPU_KUMQUAT_EXECBUF_FENCE_FD_OUT != 0 {
            *raw_descriptor = fence_opt
                .ok_or(RutabagaError::SpecViolation("no fence found"))?
                .os_handle
                .into_raw_descriptor();
        }

        Ok(())
    }

    pub fn wait(&mut self, bo_handle: u32) -> RutabagaResult<()> {
        let resource = self
            .resources
            .get_mut(&bo_handle)
            .ok_or(RutabagaError::InvalidResourceId)?;

        let new_fences: Vec<RutabagaHandle> = std::mem::take(&mut resource.attached_fences);
        for fence in new_fences {
            let file = unsafe { File::from_raw_descriptor(fence.os_handle.into_raw_descriptor()) };
            read(file.as_raw_fd(), &mut 1u64.to_ne_bytes())?;
        }

        Ok(())
    }

    pub fn resource_export(
        &mut self,
        bo_handle: u32,
        flags: u32,
    ) -> RutabagaResult<RutabagaHandle> {
        let resource = self
            .resources
            .get_mut(&bo_handle)
            .ok_or(RutabagaError::InvalidResourceId)?;

        if flags & VIRTGPU_KUMQUAT_EMULATED_EXPORT != 0 {
            let descriptor: RutabagaDescriptor =
                RutabagaSharedMemory::new("virtgpu_export", VIRTGPU_KUMQUAT_PAGE_SIZE as u64)?
                    .into();

            let clone = descriptor.try_clone()?;

            // Creating the mapping closes the cloned descriptor.
            let mapping = RutabagaMemoryMapping::from_safe_descriptor(
                clone,
                VIRTGPU_KUMQUAT_PAGE_SIZE,
                RUTABAGA_MAP_CACHE_CACHED | RUTABAGA_MAP_ACCESS_RW,
            )?;
            let rutabaga_mapping = mapping.as_rutabaga_mapping();

            let mut slice: &mut [u8] = unsafe {
                from_raw_parts_mut(rutabaga_mapping.ptr as *mut u8, VIRTGPU_KUMQUAT_PAGE_SIZE)
            };
            let mut writer = RutabagaWriter::new(&mut slice);
            writer.write_obj(resource.resource_id)?;

            // Opaque to users of this API, shared memory internally
            Ok(RutabagaHandle {
                os_handle: descriptor,
                handle_type: RUTABAGA_MEM_HANDLE_TYPE_OPAQUE_FD,
            })
        } else {
            let clone = resource.handle.try_clone()?;
            Ok(clone)
        }
    }

    pub fn resource_import(
        &mut self,
        handle: RutabagaHandle,
        bo_handle: &mut u32,
        resource_handle: &mut u32,
        size: &mut u64,
    ) -> RutabagaResult<()> {
        let clone = handle.try_clone()?;
        let mapping = RutabagaMemoryMapping::from_safe_descriptor(
            clone.os_handle,
            VIRTGPU_KUMQUAT_PAGE_SIZE,
            RUTABAGA_MAP_CACHE_CACHED | RUTABAGA_MAP_ACCESS_RW,
        )?;

        let rutabaga_mapping = mapping.as_rutabaga_mapping();

        let mut slice: &mut [u8] = unsafe {
            from_raw_parts_mut(rutabaga_mapping.ptr as *mut u8, VIRTGPU_KUMQUAT_PAGE_SIZE)
        };

        let mut reader = RutabagaReader::new(&mut slice);
        *resource_handle = reader.read_obj()?;

        let attach_resource = kumquat_gpu_protocol_ctx_resource {
            hdr: kumquat_gpu_protocol_ctrl_hdr {
                type_: KUMQUAT_GPU_PROTOCOL_CTX_ATTACH_RESOURCE,
                ..Default::default()
            },
            ctx_id: self.context_id,
            resource_id: *resource_handle,
        };

        self.stream
            .write(KumquatGpuProtocolWrite::Cmd(attach_resource))?;
        let resource = VirtGpuResource::new(
            *resource_handle,
            VIRTGPU_KUMQUAT_PAGE_SIZE,
            handle,
            Default::default(),
        );

        *bo_handle = self.allocate_id();
        // Should ask the server about the size long-term.
        *size = VIRTGPU_KUMQUAT_PAGE_SIZE as u64;
        self.resources.insert(*bo_handle, resource);

        Ok(())
    }

    pub fn snapshot(&mut self) -> RutabagaResult<()> {
        let snapshot_save = kumquat_gpu_protocol_ctrl_hdr {
            type_: KUMQUAT_GPU_PROTOCOL_SNAPSHOT_SAVE,
            ..Default::default()
        };

        self.stream
            .write(KumquatGpuProtocolWrite::Cmd(snapshot_save))?;
        Ok(())
    }

    pub fn restore(&mut self) -> RutabagaResult<()> {
        let snapshot_restore = kumquat_gpu_protocol_ctrl_hdr {
            type_: KUMQUAT_GPU_PROTOCOL_SNAPSHOT_RESTORE,
            ..Default::default()
        };

        self.stream
            .write(KumquatGpuProtocolWrite::Cmd(snapshot_restore))?;
        Ok(())
    }
}

impl Drop for VirtGpuKumquat {
    fn drop(&mut self) {
        if self.context_id != 0 {
            for (_, resource) in self.resources.iter() {
                let detach_resource = kumquat_gpu_protocol_ctx_resource {
                    hdr: kumquat_gpu_protocol_ctrl_hdr {
                        type_: KUMQUAT_GPU_PROTOCOL_CTX_DETACH_RESOURCE,
                        ..Default::default()
                    },
                    ctx_id: self.context_id,
                    resource_id: resource.resource_id,
                };

                let _ = self
                    .stream
                    .write(KumquatGpuProtocolWrite::Cmd(detach_resource));
            }

            self.resources.clear();
            let context_destroy = kumquat_gpu_protocol_ctrl_hdr {
                type_: KUMQUAT_GPU_PROTOCOL_CTX_DESTROY,
                ..Default::default()
            };

            let _ = self
                .stream
                .write(KumquatGpuProtocolWrite::Cmd(context_destroy));
        }
    }
}
