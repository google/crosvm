// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(not(any(target_os = "windows", target_arch = "arm")))]

use kvm_sys::*;
use libc::c_char;
use libc::ioctl;
use libc::open64;
use libc::O_RDWR;

const KVM_PATH: &str = "/dev/kvm\0";

#[test]
fn get_version() {
    // SAFETY: KVM_PATH is expected to be valid and return value is checked.
    let sys_fd = unsafe { open64(KVM_PATH.as_ptr() as *const c_char, O_RDWR) };
    assert!(sys_fd >= 0);

    // SAFETY: sys_fd is expected to be valid and return value is checked.
    let ret = unsafe { ioctl(sys_fd, KVM_GET_API_VERSION, 0) };
    assert_eq!(ret as u32, KVM_API_VERSION);
}

#[test]
fn create_vm_fd() {
    // SAFETY: KVM_PATH is expected to be valid and return value is checked.
    let sys_fd = unsafe { open64(KVM_PATH.as_ptr() as *const c_char, O_RDWR) };
    assert!(sys_fd >= 0);

    // SAFETY: sys_fd is expected to be valid and return value is checked.
    let vm_fd = unsafe { ioctl(sys_fd, KVM_CREATE_VM, 0) };
    assert!(vm_fd >= 0);
}

#[test]
fn check_vm_extension() {
    // SAFETY: KVM_PATH is expected to be valid and return value is checked.
    let sys_fd = unsafe { open64(KVM_PATH.as_ptr() as *const c_char, O_RDWR) };
    assert!(sys_fd >= 0);

    // SAFETY: sys_fd is expected to be valid and return value is checked.
    let has_user_memory = unsafe { ioctl(sys_fd, KVM_CHECK_EXTENSION, KVM_CAP_USER_MEMORY) };
    assert_eq!(has_user_memory, 1);
}
