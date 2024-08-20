// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Virtio console device output handling.

use std::io;
use std::io::Read;

use base::error;

use crate::virtio::Queue;
use crate::virtio::Reader;

/// Writes the available data from the reader into the given output queue.
///
/// # Arguments
///
/// * `reader` - The Reader with the data we want to write.
/// * `output` - The output sink we are going to write the data to.
fn process_transmit_request(reader: &mut Reader, output: &mut dyn io::Write) -> io::Result<()> {
    let len = reader.available_bytes();
    let mut data = vec![0u8; len];
    reader.read_exact(&mut data)?;
    output.write_all(&data)?;
    output.flush()?;
    Ok(())
}

/// Processes the data taken from the given transmit queue into the output sink.
///
/// # Arguments
///
/// * `interrupt` - Interrupt used to signal (if required) that the queue has been used
/// * `transmit_queue` - The transmit virtio Queue
/// * `output` - The output sink we are going to write the data into
pub fn process_transmit_queue(transmit_queue: &mut Queue, output: &mut dyn io::Write) {
    let mut needs_interrupt = false;
    while let Some(mut avail_desc) = transmit_queue.pop() {
        if let Err(e) = process_transmit_request(&mut avail_desc.reader, output) {
            error!("console: process_transmit_request failed: {}", e);
        }

        transmit_queue.add_used(avail_desc, 0);
        needs_interrupt = true;
    }

    if needs_interrupt {
        transmit_queue.trigger_interrupt();
    }
}
