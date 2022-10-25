// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::os::raw::c_char;
use std::os::raw::c_int;

use base::errno_result;
use base::Error;
use base::FromRawDescriptor;
use base::MappedRegion;
use base::Result;
use base::SafeDescriptor;
use libc::open64;
use libc::EBUSY;
use libc::O_CLOEXEC;
use libc::O_RDWR;

use super::haxm_sys::hax_tunnel;
use super::HaxmVcpu;
use super::HAX_EXIT_PAUSED;
use crate::VcpuRunHandle;

pub(super) fn open_haxm_device(_use_ghaxm: bool) -> Result<SafeDescriptor> {
    // Open calls are safe because we give a constant nul-terminated string and verify the
    // result.
    let ret = unsafe { open64("/dev/HAX\0".as_ptr() as *const c_char, O_RDWR | O_CLOEXEC) };
    if ret < 0 {
        return errno_result();
    }
    // Safe because we verify that ret is valid and we own the fd.
    Ok(unsafe { SafeDescriptor::from_raw_descriptor(ret) })
}

pub(super) fn open_haxm_vm_device(_use_ghaxm: bool, vm_id: u32) -> Result<SafeDescriptor> {
    // Haxm creates additional device paths when VMs are created
    let path = format!("/dev/hax_vm/vm{:02}\0", vm_id);

    let ret = unsafe { open64(path.as_ptr() as *const c_char, O_RDWR | O_CLOEXEC) };
    if ret < 0 {
        return errno_result();
    }

    // Safe because we verify that ret is valid and we own the fd.
    Ok(unsafe { SafeDescriptor::from_raw_descriptor(ret) })
}

pub(super) fn open_haxm_vcpu_device(
    _use_ghaxm: bool,
    vm_id: u32,
    vcpu_id: u32,
) -> Result<SafeDescriptor> {
    // Haxm creates additional device paths when VMs are created
    let path = format!("/dev/hax_vm{:02}/vcpu{:02}\0", vm_id, vcpu_id);

    let ret = unsafe { open64(path.as_ptr() as *const c_char, O_RDWR | O_CLOEXEC) };
    if ret < 0 {
        return errno_result();
    }

    // Safe because we verify that ret is valid and we own the fd.
    unsafe { SafeDescriptor::from_raw_descriptor(ret) };
}

pub(super) struct VcpuThread {
    tunnel: *mut hax_tunnel,
    signal_num: Option<c_int>,
}

thread_local!(static VCPU_THREAD: RefCell<Option<VcpuThread>> = RefCell::new(None));

pub(super) fn take_run_handle(vcpu: &HaxmVcpu, signal_num: Option<c_int>) -> Result<VcpuRunHandle> {
    fn vcpu_run_handle_drop() {
        VCPU_THREAD.with(|v| {
            // This assumes that a failure in `BlockedSignal::new` means the signal is already
            // blocked and there it should not be unblocked on exit.
            let _blocked_signal = &(*v.borrow())
                .as_ref()
                .and_then(|state| state.signal_num)
                .map(BlockedSignal::new);

            *v.borrow_mut() = None;
        });
    }

    let vcpu_run_handle = VcpuRunHandle::new(vcpu_run_handle_drop);

    // AcqRel ordering is sufficient to ensure only one thread gets to set its fingerprint to
    // this Vcpu and subsequent `run` calls will see the fingerprint.
    if vcpu
        .vcpu_run_handle_fingerprint
        .compare_exchange(
            0,
            vcpu_run_handle.fingerprint().as_u64(),
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        )
        .is_err()
    {
        // Prevent `vcpu_run_handle_drop` from being called.
        std::mem::forget(vcpu_run_handle);
        return Err(Error::new(EBUSY));
    }

    // Block signal while we add -- if a signal fires (very unlikely,
    // as this means something is trying to pause the vcpu before it has
    // even started) it'll try to grab the read lock while this write
    // lock is grabbed and cause a deadlock.
    // Assuming that a failure to block means it's already blocked.
    let _blocked_signal = signal_num.map(BlockedSignal::new);

    VCPU_THREAD.with(|v| {
        if v.borrow().is_none() {
            *v.borrow_mut() = Some(VcpuThread {
                tunnel: vcpu.tunnel,
                signal_num,
            });
            Ok(())
        } else {
            Err(Error::new(EBUSY))
        }
    })?;

    Ok(vcpu_run_handle)
}

pub(super) fn set_local_immediate_exit(exit: bool) {
    VCPU_THREAD.with(|v| {
        if let Some(state) = &(*v.borrow()) {
            // Safe because VCPU_THREAD is only populated by to_runnable, which makes
            // sure that the cell contains a vaild pointer to a tunnel.
            unsafe {
                // Crosvm's HAXM implementation does not use the _exit_reason, so if we
                // happen to change the exit reason in our signal handler while crosvm is
                // in the middle of handling an exit it shouldn't be a problem
                (*state.tunnel)._exit_reason = if exit { HAX_EXIT_PAUSED } else { 0 };
            };
        }
    });
}
