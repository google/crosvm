// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![no_main]

use cros_fuzz::fuzz_target;
use sys_util::{GuestAddress, GuestMemory, SharedMemory};

use std::fs::File;
use std::io::Write;

const MEM_SIZE: u64 = 256 * 1024 * 1024;

fn make_elf_bin(elf_bytes: &[u8]) -> File {
    let mut shm = SharedMemory::anon().expect("failed to create shared memory");
    shm.set_size(elf_bytes.len() as u64)
        .expect("failed to set shared memory size");
    shm.write_all(elf_bytes)
        .expect("failed to write elf to shared memoy");
    shm.into()
}

fuzz_target!(|bytes| {
    let mut kimage = make_elf_bin(bytes);
    let mem = GuestMemory::new(&[(GuestAddress(0), MEM_SIZE)]).unwrap();
    let _ = kernel_loader::load_kernel(&mem, GuestAddress(0), &mut kimage);
});
