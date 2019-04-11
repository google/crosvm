// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![no_main]

use qcow::QcowFile;
use sys_util::SharedMemory;

use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::mem::size_of;
use std::panic;
use std::process;
use std::slice;

// Take the first 64 bits of data as an address and the next 64 bits as data to
// store there. The rest of the data is used as a qcow image.
#[export_name = "LLVMFuzzerTestOneInput"]
pub fn test_one_input(data: *const u8, size: usize) -> i32 {
    // We cannot unwind past ffi boundaries.
    panic::catch_unwind(|| {
        // Safe because the libfuzzer runtime will guarantee that `data` is at least
        // `size` bytes long and that it will be valid for the lifetime of this
        // function.
        let bytes = unsafe { slice::from_raw_parts(data, size) };
        if bytes.len() < 16 {
            // Need an address and data, each are 8 bytes.
            return;
        }
        let mut disk_image = Cursor::new(bytes);
        let addr = read_u64(&mut disk_image);
        let value = read_u64(&mut disk_image);
        let shm = SharedMemory::new(None).unwrap();
        let mut disk_file: File = shm.into();
        disk_file.write_all(&bytes[16..]).unwrap();
        disk_file.seek(SeekFrom::Start(0)).unwrap();
        if let Ok(mut qcow) = QcowFile::from(disk_file) {
            if qcow.seek(SeekFrom::Start(addr)).is_ok() {
                let _ = qcow.write_all(&value.to_le_bytes());
            }
        }
    })
    .err()
    .map(|_| process::abort());

    0
}

fn read_u64<T: Read>(readable: &mut T) -> u64 {
    let mut buf = [0u8; size_of::<u64>()];
    readable.read_exact(&mut buf[..]).unwrap();
    u64::from_le_bytes(buf)
}
