// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::CString;
use std::ffi::OsStr;
use std::fmt;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::RawFd;

/// Mount options to pass to mount(2) for a FUSE filesystem. See the [official document](
/// https://www.kernel.org/doc/html/latest/filesystems/fuse.html#mount-options) for the
/// descriptions.
pub enum MountOption<'a> {
    FD(RawFd),
    RootMode(u32),
    UserId(libc::uid_t),
    GroupId(libc::gid_t),
    DefaultPermissions,
    AllowOther,
    MaxRead(u32),
    BlockSize(u32),
    // General mount options that are not specific to FUSE. Note that the value is not checked
    // or interpreted by this library, but by kernel.
    Extra(&'a str),
}

// Implement Display for ToString to convert to actual mount options.
impl<'a> fmt::Display for MountOption<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self {
            MountOption::FD(fd) => write!(f, "fd={}", fd),
            MountOption::RootMode(mode) => write!(f, "rootmode={:o}", mode),
            MountOption::UserId(uid) => write!(f, "user_id={}", uid),
            MountOption::GroupId(gid) => write!(f, "group_id={}", gid),
            MountOption::DefaultPermissions => write!(f, "default_permissions"),
            MountOption::AllowOther => write!(f, "allow_other"),
            MountOption::MaxRead(size) => write!(f, "max_read={}", size),
            MountOption::BlockSize(size) => write!(f, "blksize={}", size),
            MountOption::Extra(text) => write!(f, "{}", text),
        }
    }
}

fn join_mount_options(options: &[MountOption]) -> String {
    if !options.is_empty() {
        let mut concat = options[0].to_string();
        for opt in &options[1..] {
            concat.push(',');
            concat.push_str(&opt.to_string());
        }
        concat
    } else {
        String::new()
    }
}

/// Initiates a FUSE mount at `mountpoint` directory with `flags` and `options` via mount(2). The
/// caller should provide a file descriptor (backed by /dev/fuse) with `MountOption::FD`. After
/// this function completes, the FUSE filesystem can start to handle the requests, e.g. via
/// `fuse::worker::start_message_loop()`.
///
/// This operation requires CAP_SYS_ADMIN privilege, but the privilege can be dropped afterward.
pub fn mount<P: AsRef<OsStr>>(
    mountpoint: P,
    name: &str,
    flags: libc::c_ulong,
    options: &[MountOption],
) -> Result<(), io::Error> {
    let mount_name = CString::new(name.as_bytes())?;
    let fs_type = CString::new(String::from("fuse.") + name)?;
    let mountpoint = CString::new(mountpoint.as_ref().as_bytes())?;
    let mount_options = CString::new(join_mount_options(options))?;

    // SAFETY:
    // Safe because pointer arguments all points to null-terminiated CStrings.
    let retval = unsafe {
        libc::mount(
            mount_name.as_ptr(),
            mountpoint.as_ptr(),
            fs_type.as_ptr(),
            flags,
            mount_options.as_ptr() as *const std::ffi::c_void,
        )
    };
    if retval < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_options_concatenate_in_order() {
        assert_eq!("".to_string(), join_mount_options(&[]));

        assert_eq!(
            "fd=42".to_string(),
            join_mount_options(&[MountOption::FD(42),])
        );

        assert_eq!(
            "fd=42,rootmode=40111,allow_other,user_id=12,group_id=34,max_read=4096".to_string(),
            join_mount_options(&[
                MountOption::FD(42),
                MountOption::RootMode(
                    libc::S_IFDIR | libc::S_IXUSR | libc::S_IXGRP | libc::S_IXOTH
                ),
                MountOption::AllowOther,
                MountOption::UserId(12),
                MountOption::GroupId(34),
                MountOption::MaxRead(4096),
            ])
        );

        assert_eq!(
            "fd=42,default_permissions,user_id=12,group_id=34,max_read=4096".to_string(),
            join_mount_options(&[
                MountOption::FD(42),
                MountOption::DefaultPermissions,
                MountOption::UserId(12),
                MountOption::GroupId(34),
                MountOption::MaxRead(4096),
            ])
        );

        assert_eq!(
            "option1=a,option2=b".to_string(),
            join_mount_options(&[MountOption::Extra("option1=a,option2=b"),])
        );
    }
}
