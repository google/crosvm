// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(not(test))]
#![no_main]

use std::fs::File;
use std::io::Write;

use cros_fuzz::fuzz_target;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;

const MEM_SIZE: u64 = 256 * 1024 * 1024;

fn make_elf_bin(elf_bytes: &[u8]) -> File {
    let mut elf_bin = tempfile::tempfile().expect("failed to create tempfile");
    elf_bin
        .write_all(elf_bytes)
        .expect("failed to write elf to tempfile");
    elf_bin
}

fuzz_target!(|bytes| {
    let mut kimage = make_elf_bin(bytes);
    let mem = GuestMemory::new(&[(GuestAddress(0), MEM_SIZE)]).unwrap();
    let _ = kernel_loader::load_elf32(&mem, GuestAddress(0), &mut kimage, 0);
    let _ = kernel_loader::load_elf64(&mem, GuestAddress(0), &mut kimage, 0);
});
