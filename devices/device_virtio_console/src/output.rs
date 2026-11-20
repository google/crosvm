// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Virtio console device output handling.

use std::io;

use base::error;
use devices::virtio::Queue;
use devices::virtio::Reader;

/// Writes the available data from the reader into the given output queue.
///
/// # Arguments
///
/// * `reader` - The Reader with the data we want to write.
/// * `output` - The output sink we are going to write the data to.
fn process_transmit_request(reader: &mut Reader, output: &mut dyn io::Write) -> io::Result<()> {
    // The guest sets the chain's size, up to 4 GiB, so stream it.
    io::copy(reader, output)?;
    output.flush()
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

        transmit_queue.add_used(avail_desc);
        needs_interrupt = true;
    }

    if needs_interrupt {
        transmit_queue.trigger_interrupt();
    }
}

#[cfg(test)]
mod tests {
    use devices::virtio::create_descriptor_chain;
    use devices::virtio::DescriptorType;
    use vm_memory::GuestAddress;
    use vm_memory::GuestMemory;

    use super::*;

    #[derive(Default)]
    struct RecordingSink {
        data: Vec<u8>,
        largest_write: usize,
    }

    impl io::Write for RecordingSink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.largest_write = self.largest_write.max(buf.len());
            self.data.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn transmit_request_is_streamed() {
        const LEN: usize = 0x10_0000;
        let mem = GuestMemory::new(&[(GuestAddress(0), 2 * LEN as u64)]).unwrap();
        let payload: Vec<u8> = (0..LEN).map(|i| i as u8).collect();
        mem.write_all_at_addr(&payload, GuestAddress(LEN as u64))
            .unwrap();
        let mut chain = create_descriptor_chain(
            &mem,
            GuestAddress(0),
            GuestAddress(LEN as u64),
            vec![(DescriptorType::Readable, LEN as u32)],
            0,
        )
        .unwrap();

        let mut sink = RecordingSink::default();
        process_transmit_request(&mut chain.reader, &mut sink).unwrap();

        assert_eq!(sink.data, payload);
        // The chain's data is not gathered into one buffer.
        assert!(sink.largest_write < LEN);
    }
}
