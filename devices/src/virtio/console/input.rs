// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Virtio console device input handling.

use std::collections::VecDeque;
use std::io::Write;

use crate::virtio::Interrupt;
use crate::virtio::Queue;

/// Checks for input from `buffer` and transfers it to the receive queue, if any.
///
/// # Arguments
///
/// * `interrupt` - Interrupt used to signal that the queue has been used
/// * `buffer` - Ring buffer providing data to put into the guest
/// * `receive_queue` - The receive virtio Queue
pub fn process_receive_queue(
    interrupt: &Interrupt,
    buffer: &mut VecDeque<u8>,
    receive_queue: &mut Queue,
) {
    while let Some(mut desc) = receive_queue.peek() {
        if buffer.is_empty() {
            break;
        }

        let writer = &mut desc.writer;
        while writer.available_bytes() > 0 && !buffer.is_empty() {
            let (buffer_front, buffer_back) = buffer.as_slices();
            let buffer_chunk = if !buffer_front.is_empty() {
                buffer_front
            } else {
                buffer_back
            };
            let written = writer.write(buffer_chunk).unwrap();
            drop(buffer.drain(..written));
        }

        let bytes_written = writer.bytes_written() as u32;

        if bytes_written > 0 {
            let desc = desc.pop();
            receive_queue.add_used(desc, bytes_written);
            receive_queue.trigger_interrupt(interrupt);
        }
    }
}
