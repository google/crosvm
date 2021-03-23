// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! virgl_renderer: Handles 3D virtio-gpu hypercalls using virglrenderer.
//! External code found at https://gitlab.freedesktop.org/virgl/virglrenderer/.

#![cfg(feature = "virgl_renderer")]

use std::cell::RefCell;
use std::ffi::CString;
use std::mem::{size_of, transmute};
use std::os::raw::{c_char, c_void};
use std::ptr::null_mut;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use base::{
    warn, Error as SysError, ExternalMapping, ExternalMappingError, ExternalMappingResult,
    FromRawDescriptor, SafeDescriptor,
};

use crate::generated::virgl_renderer_bindings::*;
use crate::renderer_utils::*;
use crate::rutabaga_core::{RutabagaComponent, RutabagaContext, RutabagaResource};
use crate::rutabaga_utils::*;

use data_model::VolatileSlice;

use libc::close;

type Query = virgl_renderer_export_query;

/// The virtio-gpu backend state tracker which supports accelerated rendering.
pub struct VirglRenderer {
    fence_state: Rc<RefCell<FenceState>>,
}

struct VirglRendererContext {
    ctx_id: u32,
}

impl RutabagaContext for VirglRendererContext {
    fn submit_cmd(&mut self, commands: &mut [u8]) -> RutabagaResult<()> {
        if commands.len() % size_of::<u32>() != 0 {
            return Err(RutabagaError::InvalidCommandSize(commands.len()));
        }
        let dword_count = (commands.len() / size_of::<u32>()) as i32;
        // Safe because the context and buffer are valid and virglrenderer will have been
        // initialized if there are Context instances.
        let ret = unsafe {
            virgl_renderer_submit_cmd(
                commands.as_mut_ptr() as *mut c_void,
                self.ctx_id as i32,
                dword_count,
            )
        };
        ret_to_res(ret)
    }

    fn attach(&mut self, resource: &mut RutabagaResource) {
        // The context id and resource id must be valid because the respective instances ensure
        // their lifetime.
        unsafe {
            virgl_renderer_ctx_attach_resource(self.ctx_id as i32, resource.resource_id as i32);
        }
    }

    fn detach(&mut self, resource: &RutabagaResource) {
        // The context id and resource id must be valid because the respective instances ensure
        // their lifetime.
        unsafe {
            virgl_renderer_ctx_detach_resource(self.ctx_id as i32, resource.resource_id as i32);
        }
    }
}

impl Drop for VirglRendererContext {
    fn drop(&mut self) {
        // The context is safe to destroy because nothing else can be referencing it.
        unsafe {
            virgl_renderer_context_destroy(self.ctx_id);
        }
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
extern "C" fn debug_callback(fmt: *const ::std::os::raw::c_char, ap: *mut __va_list_tag) {
    let len: u32 = 256;
    let mut c_str = CString::new(vec![' ' as u8; len as usize]).unwrap();
    unsafe {
        let mut varargs = __va_list_tag {
            gp_offset: (*ap).gp_offset,
            fp_offset: (*ap).fp_offset,
            overflow_arg_area: (*ap).overflow_arg_area,
            reg_save_area: (*ap).reg_save_area,
        };

        let raw = c_str.into_raw();
        vsnprintf(raw, len.into(), fmt, &mut varargs);
        c_str = CString::from_raw(raw);
    }
    base::debug!("{}", c_str.to_string_lossy());
}

const VIRGL_RENDERER_CALLBACKS: &virgl_renderer_callbacks = &virgl_renderer_callbacks {
    version: 1,
    write_fence: Some(write_fence),
    create_gl_context: None,
    destroy_gl_context: None,
    make_current: None,
    get_drm_fd: None,
};

/// Retrieves metadata suitable for export about this resource. If "export_fd" is true,
/// performs an export of this resource so that it may be imported by other processes.
fn export_query(resource_id: u32) -> RutabagaResult<Query> {
    let mut query: Query = Default::default();
    query.hdr.stype = VIRGL_RENDERER_STRUCTURE_TYPE_EXPORT_QUERY;
    query.hdr.stype_version = 0;
    query.hdr.size = size_of::<Query>() as u32;
    query.in_resource_id = resource_id;
    query.in_export_fds = 0;

    // Safe because the image parameters are stack variables of the correct type.
    let ret =
        unsafe { virgl_renderer_execute(&mut query as *mut _ as *mut c_void, query.hdr.size) };

    ret_to_res(ret)?;
    Ok(query)
}

#[allow(unused_variables)]
fn map_func(resource_id: u32) -> ExternalMappingResult<(u64, usize)> {
    #[cfg(feature = "virgl_renderer_next")]
    {
        let mut map: *mut c_void = null_mut();
        let map_ptr: *mut *mut c_void = &mut map;
        let mut size: u64 = 0;
        // Safe because virglrenderer wraps and validates use of GL/VK.
        let ret = unsafe { virgl_renderer_resource_map(resource_id, map_ptr, &mut size) };
        if ret != 0 {
            return Err(ExternalMappingError::LibraryError(ret));
        }

        Ok((map as u64, size as usize))
    }
    #[cfg(not(feature = "virgl_renderer_next"))]
    Err(ExternalMappingError::Unsupported)
}

#[allow(unused_variables)]
fn unmap_func(resource_id: u32) {
    #[cfg(feature = "virgl_renderer_next")]
    {
        unsafe {
            // Usually, process_gpu_command forces ctx0 when processing a virtio-gpu command.
            // During VM shutdown, the KVM thread releases mappings without virtio-gpu being
            // involved, so force ctx0 here. It's a no-op when the ctx is already 0, so there's
            // little performance loss during normal VM operation.
            virgl_renderer_force_ctx_0();
            virgl_renderer_resource_unmap(resource_id);
        }
    }
}

impl VirglRenderer {
    pub fn init(
        virglrenderer_flags: VirglRendererFlags,
    ) -> RutabagaResult<Box<dyn RutabagaComponent>> {
        if cfg!(debug_assertions) {
            let ret = unsafe { libc::dup2(libc::STDOUT_FILENO, libc::STDERR_FILENO) };
            if ret == -1 {
                warn!("unable to dup2 stdout to stderr: {}", SysError::last());
            }
        }

        // virglrenderer is a global state backed library that uses thread bound OpenGL contexts.
        // Initialize it only once and use the non-send/non-sync Renderer struct to keep things tied
        // to whichever thread called this function first.
        static INIT_ONCE: AtomicBool = AtomicBool::new(false);
        if INIT_ONCE
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Acquire)
            .is_err()
        {
            return Err(RutabagaError::AlreadyInUse);
        }

        // Cookie is intentionally never freed because virglrenderer never gets uninitialized.
        // Otherwise, Resource and Context would become invalid because their lifetime is not tied
        // to the Renderer instance. Doing so greatly simplifies the ownership for users of this
        // library.

        let fence_state = Rc::new(RefCell::new(FenceState { latest_fence: 0 }));

        let cookie: *mut VirglCookie = Box::into_raw(Box::new(VirglCookie {
            fence_state: Rc::clone(&fence_state),
        }));

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        unsafe {
            virgl_set_debug_callback(Some(debug_callback))
        };

        // Safe because a valid cookie and set of callbacks is used and the result is checked for
        // error.
        let ret = unsafe {
            virgl_renderer_init(
                cookie as *mut c_void,
                virglrenderer_flags.into(),
                transmute(VIRGL_RENDERER_CALLBACKS),
            )
        };

        ret_to_res(ret)?;
        Ok(Box::new(VirglRenderer { fence_state }))
    }

    #[allow(unused_variables)]
    fn map_info(&self, resource_id: u32) -> RutabagaResult<u32> {
        #[cfg(feature = "virgl_renderer_next")]
        {
            let mut map_info = 0;
            let ret =
                unsafe { virgl_renderer_resource_get_map_info(resource_id as u32, &mut map_info) };
            ret_to_res(ret)?;

            Ok(map_info)
        }
        #[cfg(not(feature = "virgl_renderer_next"))]
        Err(RutabagaError::Unsupported)
    }

    fn query(&self, resource_id: u32) -> RutabagaResult<Resource3DInfo> {
        let query = export_query(resource_id)?;
        if query.out_num_fds == 0 {
            return Err(RutabagaError::Unsupported);
        }

        // virglrenderer unfortunately doesn't return the width or height, so map to zero.
        Ok(Resource3DInfo {
            width: 0,
            height: 0,
            drm_fourcc: query.out_fourcc,
            strides: query.out_strides,
            offsets: query.out_offsets,
            modifier: query.out_modifier,
        })
    }

    #[allow(unused_variables)]
    fn export_blob(&self, resource_id: u32) -> RutabagaResult<Arc<RutabagaHandle>> {
        #[cfg(feature = "virgl_renderer_next")]
        {
            let mut fd_type = 0;
            let mut fd = 0;
            let ret = unsafe {
                virgl_renderer_resource_export_blob(resource_id as u32, &mut fd_type, &mut fd)
            };
            ret_to_res(ret)?;

            /* Only support dma-bufs until someone wants opaque fds too. */
            if fd_type != VIRGL_RENDERER_BLOB_FD_TYPE_DMABUF {
                // Safe because the FD was just returned by a successful virglrenderer
                // call so it must be valid and owned by us.
                unsafe { close(fd) };
                return Err(RutabagaError::Unsupported);
            }

            let dmabuf = unsafe { SafeDescriptor::from_raw_descriptor(fd) };
            Ok(Arc::new(RutabagaHandle {
                os_handle: dmabuf,
                handle_type: RUTABAGA_MEM_HANDLE_TYPE_DMABUF,
            }))
        }
        #[cfg(not(feature = "virgl_renderer_next"))]
        Err(RutabagaError::Unsupported)
    }
}

impl RutabagaComponent for VirglRenderer {
    fn get_capset_info(&self, capset_id: u32) -> (u32, u32) {
        let mut version = 0;
        let mut size = 0;
        // Safe because virglrenderer is initialized by now and properly size stack variables are
        // used for the pointers.
        unsafe {
            virgl_renderer_get_cap_set(capset_id, &mut version, &mut size);
        }
        (version, size)
    }

    fn get_capset(&self, capset_id: u32, version: u32) -> Vec<u8> {
        let (_, max_size) = self.get_capset_info(capset_id);
        let mut buf = vec![0u8; max_size as usize];
        // Safe because virglrenderer is initialized by now and the given buffer is sized properly
        // for the given cap id/version.
        unsafe {
            virgl_renderer_fill_caps(capset_id, version, buf.as_mut_ptr() as *mut c_void);
        }
        buf
    }

    fn force_ctx_0(&self) {
        unsafe { virgl_renderer_force_ctx_0() };
    }

    fn create_fence(&mut self, fence_data: RutabagaFenceData) -> RutabagaResult<()> {
        let ret =
            unsafe { virgl_renderer_create_fence(fence_data.fence_id as i32, fence_data.ctx_id) };
        ret_to_res(ret)
    }

    fn poll(&self) -> u32 {
        unsafe { virgl_renderer_poll() };
        self.fence_state.borrow().latest_fence
    }

    fn create_3d(
        &self,
        resource_id: u32,
        resource_create_3d: ResourceCreate3D,
    ) -> RutabagaResult<RutabagaResource> {
        let mut args = virgl_renderer_resource_create_args {
            handle: resource_id,
            target: resource_create_3d.target,
            format: resource_create_3d.format,
            bind: resource_create_3d.bind,
            width: resource_create_3d.width,
            height: resource_create_3d.height,
            depth: resource_create_3d.depth,
            array_size: resource_create_3d.array_size,
            last_level: resource_create_3d.last_level,
            nr_samples: resource_create_3d.nr_samples,
            flags: resource_create_3d.flags,
        };

        // Safe because virglrenderer is initialized by now, and the return value is checked before
        // returning a new resource. The backing buffers are not supplied with this call.
        let ret = unsafe { virgl_renderer_resource_create(&mut args, null_mut(), 0) };
        ret_to_res(ret)?;

        Ok(RutabagaResource {
            resource_id,
            handle: self.export_blob(resource_id).ok(),
            blob: false,
            blob_mem: 0,
            blob_flags: 0,
            map_info: None,
            info_2d: None,
            info_3d: self.query(resource_id).ok(),
            vulkan_info: None,
            backing_iovecs: None,
        })
    }

    fn attach_backing(
        &self,
        resource_id: u32,
        vecs: &mut Vec<RutabagaIovec>,
    ) -> RutabagaResult<()> {
        // Safe because the backing is into guest memory that we store a reference count for.
        let ret = unsafe {
            virgl_renderer_resource_attach_iov(
                resource_id as i32,
                vecs.as_mut_ptr() as *mut iovec,
                vecs.len() as i32,
            )
        };
        ret_to_res(ret)
    }

    fn detach_backing(&self, resource_id: u32) {
        // Safe as we don't need the old backing iovecs returned and the reference to the guest
        // memory can be dropped as it will no longer be needed for this resource.
        unsafe {
            virgl_renderer_resource_detach_iov(resource_id as i32, null_mut(), null_mut());
        }
    }

    fn unref_resource(&self, resource_id: u32) {
        // The resource is safe to unreference destroy because no user of these bindings can still
        // be holding a reference.
        unsafe {
            virgl_renderer_resource_unref(resource_id);
        }
    }

    fn transfer_write(
        &self,
        ctx_id: u32,
        resource: &mut RutabagaResource,
        transfer: Transfer3D,
    ) -> RutabagaResult<()> {
        if transfer.is_empty() {
            return Ok(());
        }

        let mut transfer_box = VirglBox {
            x: transfer.x,
            y: transfer.y,
            z: transfer.z,
            w: transfer.w,
            h: transfer.h,
            d: transfer.d,
        };

        // Safe because only stack variables of the appropriate type are used.
        let ret = unsafe {
            virgl_renderer_transfer_write_iov(
                resource.resource_id,
                ctx_id,
                transfer.level as i32,
                transfer.stride,
                transfer.layer_stride,
                &mut transfer_box as *mut VirglBox as *mut virgl_box,
                transfer.offset,
                null_mut(),
                0,
            )
        };
        ret_to_res(ret)
    }

    fn transfer_read(
        &self,
        ctx_id: u32,
        resource: &mut RutabagaResource,
        transfer: Transfer3D,
        buf: Option<VolatileSlice>,
    ) -> RutabagaResult<()> {
        if transfer.is_empty() {
            return Ok(());
        }

        let mut transfer_box = VirglBox {
            x: transfer.x,
            y: transfer.y,
            z: transfer.z,
            w: transfer.w,
            h: transfer.h,
            d: transfer.d,
        };

        let mut iov = RutabagaIovec {
            base: null_mut(),
            len: 0,
        };

        let (iovecs, num_iovecs) = match buf {
            Some(buf) => {
                iov.base = buf.as_ptr() as *mut c_void;
                iov.len = buf.size() as usize;
                (&mut iov as *mut RutabagaIovec as *mut iovec, 1)
            }
            None => (null_mut(), 0),
        };

        // Safe because only stack variables of the appropriate type are used.
        let ret = unsafe {
            virgl_renderer_transfer_read_iov(
                resource.resource_id,
                ctx_id,
                transfer.level,
                transfer.stride,
                transfer.layer_stride,
                &mut transfer_box as *mut VirglBox as *mut virgl_box,
                transfer.offset,
                iovecs,
                num_iovecs,
            )
        };
        ret_to_res(ret)
    }

    #[allow(unused_variables)]
    fn create_blob(
        &mut self,
        ctx_id: u32,
        resource_id: u32,
        resource_create_blob: ResourceCreateBlob,
        mut iovec_opt: Option<Vec<RutabagaIovec>>,
    ) -> RutabagaResult<RutabagaResource> {
        #[cfg(feature = "virgl_renderer_next")]
        {
            let mut iovec_ptr = null_mut();
            let mut num_iovecs = 0;
            if let Some(ref mut iovecs) = iovec_opt {
                iovec_ptr = iovecs.as_mut_ptr();
                num_iovecs = iovecs.len();
            }

            let resource_create_args = virgl_renderer_resource_create_blob_args {
                res_handle: resource_id,
                ctx_id,
                blob_mem: resource_create_blob.blob_mem,
                blob_flags: resource_create_blob.blob_flags,
                blob_id: resource_create_blob.blob_id,
                size: resource_create_blob.size,
                iovecs: iovec_ptr as *const iovec,
                num_iovs: num_iovecs as u32,
            };

            let ret = unsafe { virgl_renderer_resource_create_blob(&resource_create_args) };
            ret_to_res(ret)?;

            Ok(RutabagaResource {
                resource_id,
                handle: self.export_blob(resource_id).ok(),
                blob: true,
                blob_mem: resource_create_blob.blob_mem,
                blob_flags: resource_create_blob.blob_flags,
                map_info: self.map_info(resource_id).ok(),
                info_2d: None,
                info_3d: self.query(resource_id).ok(),
                vulkan_info: None,
                backing_iovecs: iovec_opt,
            })
        }
        #[cfg(not(feature = "virgl_renderer_next"))]
        Err(RutabagaError::Unsupported)
    }

    fn map(&self, resource_id: u32) -> RutabagaResult<ExternalMapping> {
        let map_result = unsafe { ExternalMapping::new(resource_id, map_func, unmap_func) };
        match map_result {
            Ok(mapping) => Ok(mapping),
            Err(e) => Err(RutabagaError::MappingFailed(e)),
        }
    }

    #[allow(unused_variables)]
    fn export_fence(&self, fence_id: u32) -> RutabagaResult<RutabagaHandle> {
        #[cfg(feature = "virgl_renderer_next")]
        {
            // Safe because the parameters are stack variables of the correct type.
            let mut fd: i32 = 0;
            let ret = unsafe { virgl_renderer_export_fence(fence_id, &mut fd) };
            ret_to_res(ret)?;

            // Safe because the FD was just returned by a successful virglrenderer call so it must
            // be valid and owned by us.
            let fence = unsafe { SafeDescriptor::from_raw_descriptor(fd) };
            Ok(RutabagaHandle {
                os_handle: fence,
                handle_type: RUTABAGA_FENCE_HANDLE_TYPE_SYNC_FD,
            })
        }
        #[cfg(not(feature = "virgl_renderer_next"))]
        Err(RutabagaError::Unsupported)
    }

    #[allow(unused_variables)]
    fn create_context(
        &self,
        ctx_id: u32,
        context_init: u32,
    ) -> RutabagaResult<Box<dyn RutabagaContext>> {
        const CONTEXT_NAME: &[u8] = b"gpu_renderer";
        // Safe because virglrenderer is initialized by now and the context name is statically
        // allocated. The return value is checked before returning a new context.
        let ret = unsafe {
            #[cfg(feature = "virgl_renderer_next")]
            match context_init {
                0 => virgl_renderer_context_create(
                    ctx_id,
                    CONTEXT_NAME.len() as u32,
                    CONTEXT_NAME.as_ptr() as *const c_char,
                ),
                _ => virgl_renderer_context_create_with_flags(
                    ctx_id,
                    context_init,
                    CONTEXT_NAME.len() as u32,
                    CONTEXT_NAME.as_ptr() as *const c_char,
                ),
            }
            #[cfg(not(feature = "virgl_renderer_next"))]
            virgl_renderer_context_create(
                ctx_id,
                CONTEXT_NAME.len() as u32,
                CONTEXT_NAME.as_ptr() as *const c_char,
            )
        };
        ret_to_res(ret)?;
        Ok(Box::new(VirglRendererContext { ctx_id }))
    }
}
