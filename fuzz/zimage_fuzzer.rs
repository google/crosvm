// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![no_main]

use sys_util::{GuestAddress, GuestMemory};

use std::io::Cursor;
use std::panic;
use std::process;
use std::slice;

#[export_name = "LLVMFuzzerTestOneInput"]
pub fn test_one_input(data: *const u8, size: usize) -> i32 {
    // We cannot unwind past ffi boundaries.
    panic::catch_unwind(|| {
        // Safe because the libfuzzer runtime will guarantee that `data` is at least
        // `size` bytes long and that it will be valid for the lifetime of this
        // function.
        let bytes = unsafe { slice::from_raw_parts(data, size) };
        let mut kimage = Cursor::new(bytes);
        let mem = GuestMemory::new(&[(GuestAddress(0), bytes.len() as u64 + 0x1000)]).unwrap();
        let _ = kernel_loader::load_kernel(&mem, GuestAddress(0), &mut kimage);
    })
    .err()
    .map(|_| process::abort());

    0
}
