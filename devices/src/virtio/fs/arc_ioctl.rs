// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Data structures and logic for virtio-fs IOCTLs specific to ARCVM.

use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

const FS_IOCTL_PATH_MAX_LEN: usize = 128;

#[derive(Debug, Clone)]
pub(crate) struct PermissionData {
    pub guest_uid: libc::uid_t,
    pub guest_gid: libc::gid_t,
    pub host_uid: libc::uid_t,
    pub host_gid: libc::gid_t,
    pub umask: libc::mode_t,
    pub perm_path: String,
}

impl PermissionData {
    pub(crate) fn need_set_permission(&self, path: &str) -> bool {
        path.starts_with(&self.perm_path)
    }
}

#[repr(C)]
#[derive(Clone, Copy, AsBytes, FromZeroes, FromBytes)]
pub(crate) struct FsPermissionDataBuffer {
    pub guest_uid: u32,
    pub guest_gid: u32,
    pub host_uid: u32,
    pub host_gid: u32,
    pub umask: u32,
    pub pad: u32,
    pub perm_path: [u8; FS_IOCTL_PATH_MAX_LEN],
}
