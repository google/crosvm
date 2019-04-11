// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![no_main]

use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::mem::size_of;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::panic;
use std::process;
use std::slice;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

use devices::virtio::{Block, Queue, VirtioDevice};
use sys_util::{EventFd, GuestAddress, GuestMemory, SharedMemory};

const MEM_SIZE: u64 = 256 * 1024 * 1024;
const DESC_SIZE: u64 = 16; // Bytes in one virtio descriptor.
const QUEUE_SIZE: u16 = 16; // Max entries in the queue.
const CMD_SIZE: usize = 16; // Bytes in the command.

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
        let size_u64 = size_of::<u64>();
        let mem = GuestMemory::new(&[(GuestAddress(0), MEM_SIZE)]).unwrap();

        // The fuzz data is interpreted as:
        // starting index 8 bytes
        // command location 8 bytes
        // command 16 bytes
        // descriptors circular buffer 16 bytes * 3
        if bytes.len() < 4 * size_u64 {
            // Need an index to start.
            return;
        }

        let mut data_image = Cursor::new(bytes);

        let first_index = read_u64(&mut data_image);
        if first_index > MEM_SIZE / DESC_SIZE {
            return;
        }
        let first_offset = first_index * DESC_SIZE;
        if first_offset as usize + size_u64 > bytes.len() {
            return;
        }

        let command_addr = read_u64(&mut data_image);
        if command_addr > MEM_SIZE - CMD_SIZE as u64 {
            return;
        }
        if mem
            .write_all_at_addr(
                &bytes[2 * size_u64..(2 * size_u64) + CMD_SIZE],
                GuestAddress(command_addr as u64),
            )
            .is_err()
        {
            return;
        }

        data_image.seek(SeekFrom::Start(first_offset)).unwrap();
        let desc_table = read_u64(&mut data_image);

        if mem
            .write_all_at_addr(&bytes[32..], GuestAddress(desc_table as u64))
            .is_err()
        {
            return;
        }

        let mut q = Queue::new(QUEUE_SIZE);
        q.ready = true;
        q.size = QUEUE_SIZE / 2;
        q.max_size = QUEUE_SIZE;

        let queue_evts: Vec<EventFd> = vec![EventFd::new().unwrap()];
        let queue_fd = queue_evts[0].as_raw_fd();
        let queue_evt = unsafe { EventFd::from_raw_fd(libc::dup(queue_fd)) };

        let shm = SharedMemory::new(None).unwrap();
        let disk_file: File = shm.into();
        let mut block = Block::new(disk_file, false, None).unwrap();

        block.activate(
            mem,
            EventFd::new().unwrap(),
            EventFd::new().unwrap(),
            Arc::new(AtomicUsize::new(0)),
            vec![q],
            queue_evts,
        );

        queue_evt.write(77).unwrap(); // Rings the doorbell, any byte will do.
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
