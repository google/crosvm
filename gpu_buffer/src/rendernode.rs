// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::CString;
use std::fs::{File, OpenOptions};
#[cfg(target_pointer_width = "64")]
use std::os::raw::c_ulong;
use std::os::raw::{c_char, c_int, c_uint};
use std::path::Path;
use std::ptr::null_mut;

use sys_util::{ioctl_iowr_nr, ioctl_with_mut_ref};

// Consistent with __kernel_size_t in include/uapi/asm-generic/posix_types.h.
#[cfg(not(target_pointer_width = "64"))]
#[allow(non_camel_case_types)]
type __kernel_size_t = c_uint;
#[cfg(target_pointer_width = "64")]
#[allow(non_camel_case_types)]
type __kernel_size_t = c_ulong;

const DRM_IOCTL_BASE: c_uint = 0x64;

#[repr(C)]
#[derive(Copy, Clone)]
struct drm_version {
    version_major: c_int,
    version_minor: c_int,
    version_patchlevel: c_int,
    name_len: __kernel_size_t,
    name: *mut c_char,
    date_len: __kernel_size_t,
    date: *mut c_char,
    desc_len: __kernel_size_t,
    desc: *mut c_char,
}

ioctl_iowr_nr!(DRM_IOCTL_VERSION, DRM_IOCTL_BASE, 0x0, drm_version);

fn get_drm_device_name(fd: &File) -> Result<String, ()> {
    let mut version = drm_version {
        version_major: 0,
        version_minor: 0,
        version_patchlevel: 0,
        name_len: 0,
        name: null_mut(),
        date_len: 0,
        date: null_mut(),
        desc_len: 0,
        desc: null_mut(),
    };

    // Get the length of the device name.
    if unsafe { ioctl_with_mut_ref(fd, DRM_IOCTL_VERSION(), &mut version) } < 0 {
        return Err(());
    }

    // Enough bytes to hold the device name and terminating null character.
    let mut name_bytes: Vec<u8> = vec![0; (version.name_len + 1) as usize];
    let mut version = drm_version {
        version_major: 0,
        version_minor: 0,
        version_patchlevel: 0,
        name_len: name_bytes.len() as __kernel_size_t,
        name: name_bytes.as_mut_ptr() as *mut c_char,
        date_len: 0,
        date: null_mut(),
        desc_len: 0,
        desc: null_mut(),
    };

    // Safe as no more than name_len + 1 bytes will be written to name.
    if unsafe { ioctl_with_mut_ref(fd, DRM_IOCTL_VERSION(), &mut version) } < 0 {
        return Err(());
    }

    Ok(CString::new(&name_bytes[..(version.name_len as usize)])
        .map_err(|_| ())?
        .into_string()
        .map_err(|_| ())?)
}

/// Returns a `fd` for an opened rendernode device, while filtering out specified
/// undesired drivers.
pub fn open_device(undesired: &[&str]) -> Result<File, ()> {
    const DRM_DIR_NAME: &str = "/dev/dri";
    const DRM_MAX_MINOR: u32 = 15;
    const RENDER_NODE_START: u32 = 128;

    for n in RENDER_NODE_START..=RENDER_NODE_START + DRM_MAX_MINOR {
        let path = Path::new(DRM_DIR_NAME).join(format!("renderD{}", n));

        if let Ok(fd) = OpenOptions::new().read(true).write(true).open(path) {
            if let Ok(name) = get_drm_device_name(&fd) {
                if !undesired.iter().any(|item| *item == name) {
                    return Ok(fd);
                }
            }
        }
    }

    Err(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // no access to /dev/dri
    fn open_rendernode_device() {
        let undesired: &[&str] = &["bad_driver", "another_bad_driver"];
        open_device(undesired).expect("failed to open rendernode");
    }
}
