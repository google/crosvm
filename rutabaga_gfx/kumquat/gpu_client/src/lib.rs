// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

extern crate rutabaga_gfx;

mod virtgpu;

use std::boxed::Box;
use std::os::raw::c_void;
use std::panic::catch_unwind;
use std::panic::AssertUnwindSafe;
use std::ptr::null_mut;
use std::slice::from_raw_parts;
use std::slice::from_raw_parts_mut;
use std::sync::Mutex;

use libc::EINVAL;
use libc::ESRCH;
use log::error;
use rutabaga_gfx::RutabagaDescriptor;
use rutabaga_gfx::RutabagaFromRawDescriptor;
use rutabaga_gfx::RutabagaHandle;
use rutabaga_gfx::RutabagaIntoRawDescriptor;
use rutabaga_gfx::RutabagaRawDescriptor;
use rutabaga_gfx::RutabagaResult;
use virtgpu::defines::*;
use virtgpu::VirtGpuKumquat;

const NO_ERROR: i32 = 0;

fn return_result<T>(result: RutabagaResult<T>) -> i32 {
    if let Err(e) = result {
        error!("An error occurred: {}", e);
        -EINVAL
    } else {
        NO_ERROR
    }
}

macro_rules! return_on_error {
    ($result:expr) => {
        match $result {
            Ok(t) => t,
            Err(e) => {
                error!("An error occurred: {}", e);
                return -EINVAL;
            }
        }
    };
}

#[allow(non_camel_case_types)]
type virtgpu_kumquat = Mutex<VirtGpuKumquat>;

// The following structs (in define.rs) must be ABI-compatible with FFI header
// (virtgpu_kumquat_ffi.h).

#[allow(non_camel_case_types)]
type drm_kumquat_getparam = VirtGpuParam;

#[allow(non_camel_case_types)]
type drm_kumquat_resource_unref = VirtGpuResourceUnref;

#[allow(non_camel_case_types)]
type drm_kumquat_get_caps = VirtGpuGetCaps;

#[allow(non_camel_case_types)]
type drm_kumquat_context_init = VirtGpuContextInit;

#[allow(non_camel_case_types)]
type drm_kumquat_resource_create_3d = VirtGpuResourceCreate3D;

#[allow(non_camel_case_types)]
type drm_kumquat_resource_create_blob = VirtGpuResourceCreateBlob;

#[allow(non_camel_case_types)]
type drm_kumquat_transfer_to_host = VirtGpuTransfer;

#[allow(non_camel_case_types)]
type drm_kumquat_transfer_from_host = VirtGpuTransfer;

#[allow(non_camel_case_types)]
type drm_kumquat_execbuffer = VirtGpuExecBuffer;

#[allow(non_camel_case_types)]
type drm_kumquat_wait = VirtGpuWait;

#[allow(non_camel_case_types)]
type drm_kumquat_resource_map = VirtGpuResourceMap;

#[allow(non_camel_case_types)]
type drm_kumquat_resource_export = VirtGpuResourceExport;

#[allow(non_camel_case_types)]
type drm_kumquat_resource_import = VirtGpuResourceImport;

#[no_mangle]
pub unsafe extern "C" fn virtgpu_kumquat_init(ptr: &mut *mut virtgpu_kumquat) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let result = VirtGpuKumquat::new();
        let rtbg = return_on_error!(result);
        *ptr = Box::into_raw(Box::new(Mutex::new(rtbg))) as _;
        NO_ERROR
    }))
    .unwrap_or(-ESRCH)
}

#[no_mangle]
pub extern "C" fn virtgpu_kumquat_finish(ptr: &mut *mut virtgpu_kumquat) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let _ = unsafe { Box::from_raw(*ptr) };
        *ptr = null_mut();
        NO_ERROR
    }))
    .unwrap_or(-ESRCH)
}

#[no_mangle]
pub unsafe extern "C" fn virtgpu_kumquat_get_param(
    ptr: &mut virtgpu_kumquat,
    cmd: &mut drm_kumquat_getparam,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let result = ptr.lock().unwrap().get_param(cmd);
        return_result(result)
    }))
    .unwrap_or(-ESRCH)
}

#[no_mangle]
pub unsafe extern "C" fn virtgpu_kumquat_get_caps(
    ptr: &mut virtgpu_kumquat,
    cmd: &drm_kumquat_get_caps,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let caps_slice = from_raw_parts_mut(cmd.addr as *mut u8, cmd.size as usize);
        let result = ptr.lock().unwrap().get_caps(cmd.cap_set_id, caps_slice);
        return_result(result)
    }))
    .unwrap_or(-ESRCH)
}

#[no_mangle]
pub unsafe extern "C" fn virtgpu_kumquat_context_init(
    ptr: &mut virtgpu_kumquat,
    cmd: &drm_kumquat_context_init,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let context_params: &[VirtGpuParam] = from_raw_parts(
            cmd.ctx_set_params as *const VirtGpuParam,
            cmd.num_params as usize,
        );

        let mut capset_id: u64 = 0;

        for param in context_params {
            match param.param {
                VIRTGPU_KUMQUAT_CONTEXT_PARAM_CAPSET_ID => {
                    capset_id = param.value;
                }
                _ => (),
            }
        }

        let result = ptr.lock().unwrap().context_create(capset_id, "");
        return_result(result)
    }))
    .unwrap_or(-ESRCH)
}

#[no_mangle]
pub unsafe extern "C" fn virtgpu_kumquat_resource_create_3d(
    ptr: &mut virtgpu_kumquat,
    cmd: &mut drm_kumquat_resource_create_3d,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let result = ptr.lock().unwrap().resource_create_3d(cmd);
        return_result(result)
    }))
    .unwrap_or(-ESRCH)
}

#[no_mangle]
pub unsafe extern "C" fn virtgpu_kumquat_resource_create_blob(
    ptr: &mut virtgpu_kumquat,
    cmd: &mut drm_kumquat_resource_create_blob,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let blob_cmd = from_raw_parts(cmd.cmd as *const u8, cmd.cmd_size as usize);
        let result = ptr.lock().unwrap().resource_create_blob(cmd, blob_cmd);
        return_result(result)
    }))
    .unwrap_or(-ESRCH)
}

#[no_mangle]
pub unsafe extern "C" fn virtgpu_kumquat_resource_unref(
    ptr: &mut virtgpu_kumquat,
    cmd: &mut drm_kumquat_resource_unref,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let result = ptr.lock().unwrap().resource_unref(cmd.bo_handle);
        return_result(result)
    }))
    .unwrap_or(-ESRCH)
}

#[no_mangle]
pub unsafe extern "C" fn virtgpu_kumquat_resource_map(
    ptr: &mut virtgpu_kumquat,
    cmd: &mut drm_kumquat_resource_map,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let result = ptr.lock().unwrap().map(cmd.bo_handle);
        let internal_map = return_on_error!(result);
        (*cmd).ptr = internal_map.ptr as *mut c_void;
        (*cmd).size = internal_map.size;
        NO_ERROR
    }))
    .unwrap_or(-ESRCH)
}

#[no_mangle]
pub unsafe extern "C" fn virtgpu_kumquat_resource_unmap(
    ptr: &mut virtgpu_kumquat,
    bo_handle: u32,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let result = ptr.lock().unwrap().unmap(bo_handle);
        return_result(result)
    }))
    .unwrap_or(-ESRCH)
}

#[no_mangle]
pub unsafe extern "C" fn virtgpu_kumquat_transfer_to_host(
    ptr: &mut virtgpu_kumquat,
    cmd: &mut drm_kumquat_transfer_to_host,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let result = ptr.lock().unwrap().transfer_to_host(cmd);
        return_result(result)
    }))
    .unwrap_or(-ESRCH)
}

#[no_mangle]
pub unsafe extern "C" fn virtgpu_kumquat_transfer_from_host(
    ptr: &mut virtgpu_kumquat,
    cmd: &mut drm_kumquat_transfer_from_host,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let result = ptr.lock().unwrap().transfer_from_host(cmd);
        return_result(result)
    }))
    .unwrap_or(-ESRCH)
}

#[no_mangle]
pub unsafe extern "C" fn virtgpu_kumquat_execbuffer(
    ptr: &mut virtgpu_kumquat,
    cmd: &mut drm_kumquat_execbuffer,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let bo_handles = from_raw_parts(cmd.bo_handles as *const u32, cmd.num_bo_handles as usize);
        let cmd_buf = from_raw_parts(cmd.command as *const u8, cmd.size as usize);

        // TODO
        let in_fences: &[u64] = &[0; 0];

        let result = ptr.lock().unwrap().submit_command(
            cmd.flags,
            bo_handles,
            cmd_buf,
            cmd.ring_idx,
            in_fences,
            &mut cmd.fence_fd as &mut RutabagaRawDescriptor,
        );
        return_result(result)
    }))
    .unwrap_or(-ESRCH)
}

#[no_mangle]
pub unsafe extern "C" fn virtgpu_kumquat_wait(
    ptr: &mut virtgpu_kumquat,
    cmd: &mut drm_kumquat_wait,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let result = ptr.lock().unwrap().wait(cmd.bo_handle);
        return_result(result)
    }))
    .unwrap_or(-ESRCH)
}

#[no_mangle]
pub extern "C" fn virtgpu_kumquat_resource_export(
    ptr: &mut virtgpu_kumquat,
    cmd: &mut drm_kumquat_resource_export,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let result = ptr
            .lock()
            .unwrap()
            .resource_export(cmd.bo_handle, cmd.flags);
        let hnd = return_on_error!(result);

        (*cmd).handle_type = hnd.handle_type;
        (*cmd).os_handle = hnd.os_handle.into_raw_descriptor() as i64;
        NO_ERROR
    }))
    .unwrap_or(-ESRCH)
}

#[no_mangle]
pub unsafe extern "C" fn virtgpu_kumquat_resource_import(
    ptr: &mut virtgpu_kumquat,
    cmd: &mut drm_kumquat_resource_import,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let handle = RutabagaHandle {
            os_handle: RutabagaDescriptor::from_raw_descriptor(
                (*cmd).os_handle.try_into().unwrap(),
            ),
            handle_type: (*cmd).handle_type,
        };

        let result = ptr.lock().unwrap().resource_import(
            handle,
            &mut cmd.bo_handle,
            &mut cmd.res_handle,
            &mut cmd.size,
        );

        return_result(result)
    }))
    .unwrap_or(-ESRCH)
}

#[no_mangle]
pub unsafe extern "C" fn virtgpu_kumquat_snapshot_save(ptr: &mut virtgpu_kumquat) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let result = ptr.lock().unwrap().snapshot();
        return_result(result)
    }))
    .unwrap_or(-ESRCH)
}

#[no_mangle]
pub unsafe extern "C" fn virtgpu_kumquat_snapshot_restore(ptr: &mut virtgpu_kumquat) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let result = ptr.lock().unwrap().restore();
        return_result(result)
    }))
    .unwrap_or(-ESRCH)
}
