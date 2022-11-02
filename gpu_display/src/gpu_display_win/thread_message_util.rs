// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::mem;
use std::ptr::null_mut;

use anyhow::Result;
use win_util::syscall_bail;
use winapi::shared::minwindef::DWORD;
use winapi::shared::minwindef::LPARAM;
use winapi::shared::minwindef::UINT;
use winapi::shared::minwindef::WPARAM;
use winapi::um::winuser::*;

/// Using `PostThreadMessageW()` requires that the thread-specific message queue must have been
/// created on the targeted thread. We can call `PeekMessageW()` from the targeted thread first to
/// ensure it:
/// https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-postthreadmessagea#remarks
/// It does no harm calling this function multiple times, since it won't remove any message from the
/// queue.
pub(crate) fn force_create_message_queue() {
    // Safe because if `message` is initialized, we will extract and drop the value.
    let mut message = mem::MaybeUninit::uninit();
    // Safe because we know the lifetime of `message`, and `PeekMessageW()` has no failure mode.
    if unsafe {
        PeekMessageW(
            message.as_mut_ptr(),
            null_mut(),
            WM_USER,
            WM_USER,
            PM_NOREMOVE,
        ) != 0
    } {
        // Safe because `PeekMessageW()` has populated `message`.
        unsafe {
            message.assume_init_drop();
        }
    }
}

/// Calls `PostThreadMessageW()` internally.
/// # Safety
/// The caller must make sure the thread is still running and has created the message queue.
pub(crate) unsafe fn post_message(
    thread_id: DWORD,
    msg: UINT,
    w_param: WPARAM,
    l_param: LPARAM,
) -> Result<()> {
    if PostThreadMessageW(thread_id, msg, w_param, l_param) == 0 {
        syscall_bail!("Failed to call PostThreadMessageW()");
    }
    Ok(())
}

/// Calls `PostThreadMessageW()` internally. This is a common pattern, where we send a pointer to
/// the given object as the lParam. The receiver is responsible for destructing the object.
/// # Safety
/// The caller must make sure the thread is still running and has created the message queue.
pub(crate) unsafe fn post_message_carrying_object<T>(
    thread_id: DWORD,
    msg: UINT,
    object: T,
) -> Result<()> {
    let mut boxed_object = Box::new(object);
    post_message(
        thread_id,
        msg,
        /* w_param */ 0,
        &mut *boxed_object as *mut T as LPARAM,
    )
    // If successful, the receiver will be responsible for destructing the object.
    .map(|_| std::mem::forget(boxed_object))
}
