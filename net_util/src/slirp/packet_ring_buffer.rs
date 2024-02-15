// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::VecDeque;
use std::fmt;
use std::fmt::Display;
use std::time::Duration;

use pcap_file::pcap::PacketHeader;

const PACKET_HEADER_SIZE_IN_BYTES: usize = std::mem::size_of::<PacketHeader>();

/// A wrapper around a ringer buffer that stores packet information.
/// This was made so on crosvm, we can write the packet information to a file
/// for debugging purposes.

pub struct PacketRingBuffer {
    ring_buffer: VecDeque<PacketInfo>,
    max_size_in_bytes: usize,
    current_size_in_bytes: usize,
    last_popped_packet_timestamp: Option<Duration>,
}

pub struct PacketInfo {
    pub buf: Vec<u8>,
    pub timestamp: Duration,
}

#[derive(Eq, PartialEq, Debug)]
pub enum Error {
    PacketTooBigError {
        rb_max_size_in_bytes: usize,
        packet_size_in_bytes: usize,
    },
}
pub type Result<T> = std::result::Result<T, Error>;

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            PacketTooBigError {
                rb_max_size_in_bytes,
                packet_size_in_bytes,
            } => write!(
                f,
                "Packet of size {} bytes can't fit into Ring buffer of size {}",
                rb_max_size_in_bytes, packet_size_in_bytes
            ),
        }
    }
}

impl PacketRingBuffer {
    pub fn new(max_size_in_bytes: usize) -> PacketRingBuffer {
        PacketRingBuffer {
            ring_buffer: VecDeque::new(),
            max_size_in_bytes,
            current_size_in_bytes: 0,
            last_popped_packet_timestamp: None,
        }
    }

    pub fn add_packet(&mut self, buf: &[u8], packet_timestamp: Duration) -> Result<()> {
        self.prune_from_ring_buffer_if_oversized(buf)?;

        self.ring_buffer.push_front(PacketInfo {
            buf: buf.to_vec(),
            timestamp: packet_timestamp,
        });
        self.current_size_in_bytes += buf.len() + PACKET_HEADER_SIZE_IN_BYTES;

        Ok(())
    }

    // While the size of the rb with the new packet is less than the max size of the rb.
    fn prune_from_ring_buffer_if_oversized(&mut self, buf: &[u8]) -> Result<()> {
        let new_packet_size_in_bytes = buf.len() + PACKET_HEADER_SIZE_IN_BYTES;

        while self.current_size_in_bytes + new_packet_size_in_bytes > self.max_size_in_bytes {
            match self.ring_buffer.pop_back() {
                Some(val) => {
                    self.current_size_in_bytes -= val.buf.len() + PACKET_HEADER_SIZE_IN_BYTES;
                    self.last_popped_packet_timestamp = self
                        .last_popped_packet_timestamp
                        .map(|t| std::cmp::max(t, val.timestamp))
                        .or(Some(val.timestamp))
                }
                None => {
                    return Err(Error::PacketTooBigError {
                        rb_max_size_in_bytes: self.max_size_in_bytes,
                        packet_size_in_bytes: new_packet_size_in_bytes,
                    })
                }
            }
        }
        Ok(())
    }

    /// Aggregates two ring buffers of packets by removing packets prior to the max oldest
    /// removed packet and sorting them by time.
    pub fn pop_ring_buffers_and_aggregate<'a>(
        packet_rb1: &'a mut PacketRingBuffer,
        packet_rb2: &'a mut PacketRingBuffer,
    ) -> Vec<&'a PacketInfo> {
        let mut result: Vec<&PacketInfo> = Vec::new();
        result.extend(packet_rb1.ring_buffer.iter().collect::<Vec<&PacketInfo>>());
        result.extend(packet_rb2.ring_buffer.iter().collect::<Vec<&PacketInfo>>());

        // The oldest time we want to keep in the aggregated result.
        let start_time = std::cmp::max(
            packet_rb1.last_popped_packet_timestamp,
            packet_rb2.last_popped_packet_timestamp,
        );

        let mut result = if let Some(start_time) = start_time {
            result
                .into_iter()
                .filter(|packet| packet.timestamp > start_time)
                .collect()
        } else {
            result
        };

        result.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add() {
        let mut packet_rb = PacketRingBuffer::new(
            /* max_size_in_bytes= */ 4 + PACKET_HEADER_SIZE_IN_BYTES,
        );
        let buf: &[u8] = &[1, 2, 3, 4];
        let start_time = Duration::from_nanos(45);

        assert_eq!(packet_rb.ring_buffer.len(), 0);

        packet_rb
            .add_packet(buf, start_time)
            .expect("Failed to add packet.");

        let packet = packet_rb.ring_buffer.pop_back().unwrap();
        assert_eq!(packet.buf, &[1, 2, 3, 4]);
        assert_eq!(packet.timestamp.as_nanos(), 45);
        assert_eq!(packet_rb.last_popped_packet_timestamp, None);
        // Each packet has 16 bytes in it's PacketHeader
        assert_eq!(
            packet_rb.current_size_in_bytes,
            4 + PACKET_HEADER_SIZE_IN_BYTES
        );
    }

    #[test]
    fn test_add_no_space() {
        // Max size is 3 bytes of buffer data + PACKET_HEADER_SIZE_IN_BYTES
        let mut packet_rb = PacketRingBuffer::new(
            /* max_size_in_bytes= */ 3 + PACKET_HEADER_SIZE_IN_BYTES,
        );
        let buf: &[u8] = &[1, 2, 3, 4];
        let start_time = Duration::from_nanos(45);

        let res = packet_rb.add_packet(buf, start_time);

        // Should error because rb size is 19 bytes, but packet will take 20 bytes (4 bytes in
        // buffer + 16 bytes from Packet header)
        assert!(res.is_err());

        assert_eq!(
            res.unwrap_err(),
            Error::PacketTooBigError {
                rb_max_size_in_bytes: packet_rb.max_size_in_bytes,
                packet_size_in_bytes: 4 + PACKET_HEADER_SIZE_IN_BYTES
            }
        );
    }

    #[test]
    fn test_add_exceeds_size_pop_one() {
        let mut packet_rb = PacketRingBuffer::new(
            /* max_size_in_bytes= */ 3 + 3 * PACKET_HEADER_SIZE_IN_BYTES,
        );

        packet_rb
            .add_packet(&[1], Duration::from_nanos(1))
            .expect("Failed to add packet.");
        packet_rb
            .add_packet(&[2], Duration::from_nanos(2))
            .expect("Failed to add packet.");
        packet_rb
            .add_packet(&[3], Duration::from_nanos(3))
            .expect("Failed to add packet.");
        packet_rb
            .add_packet(&[4], Duration::from_nanos(4))
            .expect("Failed to add packet.");

        assert_eq!(packet_rb.ring_buffer.len(), 3);

        let packet1 = packet_rb.ring_buffer.pop_back().unwrap();
        let packet2 = packet_rb.ring_buffer.pop_back().unwrap();
        let packet3 = packet_rb.ring_buffer.pop_back().unwrap();

        assert_eq!(packet1.buf, &[2]);
        assert_eq!(packet1.timestamp.as_nanos(), 2);
        assert_eq!(packet2.buf, &[3]);
        assert_eq!(packet2.timestamp.as_nanos(), 3);
        assert_eq!(packet3.buf, &[4]);
        assert_eq!(packet3.timestamp.as_nanos(), 4);
        assert_eq!(
            packet_rb.last_popped_packet_timestamp.unwrap().as_nanos(),
            1
        );
        assert_eq!(packet_rb.current_size_in_bytes, 3 + 3 * 16);
    }

    #[test]
    fn test_add_exceeds_size_pop_multiple() {
        let mut packet_rb = PacketRingBuffer::new(
            /* max_size_in_bytes= */ 2 + PACKET_HEADER_SIZE_IN_BYTES,
        );

        packet_rb
            .add_packet(&[1], Duration::from_nanos(1))
            .expect("Failed to add packet.");
        packet_rb
            .add_packet(&[2], Duration::from_nanos(2))
            .expect("Failed to add packet.");
        packet_rb
            .add_packet(&[3, 4], Duration::from_nanos(3))
            .expect("Failed to add packet.");
        packet_rb
            .add_packet(&[5, 6], Duration::from_nanos(4))
            .expect("Failed to add packet.");

        // The first 3 packets should've been popped
        assert_eq!(packet_rb.ring_buffer.len(), 1);

        let packet1 = packet_rb.ring_buffer.pop_back().unwrap();

        assert_eq!(packet1.buf, &[5, 6]);
        assert_eq!(packet1.timestamp.as_nanos(), 4);
        assert_eq!(
            packet_rb.last_popped_packet_timestamp.unwrap().as_nanos(),
            3
        );
        assert_eq!(
            packet_rb.current_size_in_bytes,
            2 + PACKET_HEADER_SIZE_IN_BYTES
        );
    }

    #[test]
    fn test_aggregate_one_empty() {
        let mut tx_packet_rb = PacketRingBuffer::new(
            /* max_size_in_bytes= */ 3 + 3 * PACKET_HEADER_SIZE_IN_BYTES,
        );

        let mut rx_packet_rb = PacketRingBuffer::new(
            /* max_size_in_bytes= */ 3 + 3 * PACKET_HEADER_SIZE_IN_BYTES,
        );
        rx_packet_rb
            .add_packet(&[4], Duration::from_nanos(6))
            .expect("Failed to add packet.");
        rx_packet_rb
            .add_packet(&[5], Duration::from_nanos(10))
            .expect("Failed to add packet.");

        let res =
            PacketRingBuffer::pop_ring_buffers_and_aggregate(&mut tx_packet_rb, &mut rx_packet_rb);
        let packet_data_list: Vec<&[u8]> = res.iter().map(|packet| packet.buf.as_ref()).collect();

        assert_eq!(packet_data_list, [&[4], &[5]]);
    }

    #[test]
    fn test_aggregate_both_empty() {
        let mut tx_packet_rb = PacketRingBuffer::new(
            /* max_size_in_bytes= */ 3 + 3 * PACKET_HEADER_SIZE_IN_BYTES,
        );

        let mut rx_packet_rb = PacketRingBuffer::new(
            /* max_size_in_bytes= */ 3 + 3 * PACKET_HEADER_SIZE_IN_BYTES,
        );

        let res =
            PacketRingBuffer::pop_ring_buffers_and_aggregate(&mut tx_packet_rb, &mut rx_packet_rb);
        let packet_data_list: Vec<&[u8]> = res.iter().map(|packet| packet.buf.as_ref()).collect();

        assert!(packet_data_list.is_empty());
    }

    #[test]
    fn test_aggregate_none_popped() {
        let mut tx_packet_rb = PacketRingBuffer::new(
            /* max_size_in_bytes= */ 3 + 3 * PACKET_HEADER_SIZE_IN_BYTES,
        );
        tx_packet_rb
            .add_packet(&[1], Duration::from_nanos(2))
            .expect("Failed to add packet.");
        tx_packet_rb
            .add_packet(&[2], Duration::from_nanos(8))
            .expect("Failed to add packet.");
        tx_packet_rb
            .add_packet(&[3], Duration::from_nanos(9))
            .expect("Failed to add packet.");

        let mut rx_packet_rb = PacketRingBuffer::new(
            /* max_size_in_bytes= */ 3 + 3 * PACKET_HEADER_SIZE_IN_BYTES,
        );
        rx_packet_rb
            .add_packet(&[4], Duration::from_nanos(6))
            .expect("Failed to add packet.");
        rx_packet_rb
            .add_packet(&[5], Duration::from_nanos(10))
            .expect("Failed to add packet.");

        let res =
            PacketRingBuffer::pop_ring_buffers_and_aggregate(&mut tx_packet_rb, &mut rx_packet_rb);

        let packet_data_list: Vec<&[u8]> = res.iter().map(|packet| packet.buf.as_ref()).collect();
        assert_eq!(packet_data_list, [&[1], &[4], &[2], &[3], &[5]]);
    }

    #[test]
    fn test_aggregate_with_one_ring_buffer_popped() {
        let mut tx_packet_rb = PacketRingBuffer::new(
            /* max_size_in_bytes= */ 3 + 3 * PACKET_HEADER_SIZE_IN_BYTES,
        );
        tx_packet_rb
            .add_packet(&[1], Duration::from_nanos(2))
            .expect("Failed to add packet.");
        tx_packet_rb
            .add_packet(&[2], Duration::from_nanos(8))
            .expect("Failed to add packet.");
        tx_packet_rb
            .add_packet(&[3, 4], Duration::from_nanos(9))
            .expect("Failed to add packet.");
        tx_packet_rb
            .add_packet(&[5], Duration::from_nanos(14))
            .expect("Failed to add packet.");

        let mut rx_packet_rb = PacketRingBuffer::new(
            /* max_size_in_bytes= */ 2 + 2 * PACKET_HEADER_SIZE_IN_BYTES,
        );
        rx_packet_rb
            .add_packet(&[6], Duration::from_nanos(6))
            .expect("Failed to add packet.");
        rx_packet_rb
            .add_packet(&[7], Duration::from_nanos(10))
            .expect("Failed to add packet.");

        let res =
            PacketRingBuffer::pop_ring_buffers_and_aggregate(&mut tx_packet_rb, &mut rx_packet_rb);

        let packet_data_list: Vec<&[u8]> = res.iter().map(|packet| packet.buf.as_ref()).collect();
        assert_eq!(packet_data_list.len(), 3);
        assert_eq!(packet_data_list[0], &[3, 4]);
        assert_eq!(packet_data_list[1], &[7]);
        assert_eq!(packet_data_list[2], &[5]);
    }

    #[test]
    fn test_aggregate_with_both_ring_buffers_popped() {
        let mut tx_packet_rb = PacketRingBuffer::new(
            /* max_size_in_bytes= */ 3 + 3 * PACKET_HEADER_SIZE_IN_BYTES,
        );
        tx_packet_rb
            .add_packet(&[1], Duration::from_nanos(2))
            .expect("Failed to add packet.");
        tx_packet_rb
            .add_packet(&[2], Duration::from_nanos(8))
            .expect("Failed to add packet.");
        tx_packet_rb
            .add_packet(&[3, 4], Duration::from_nanos(9))
            .expect("Failed to add packet.");
        tx_packet_rb
            .add_packet(&[5], Duration::from_nanos(15))
            .expect("Failed to add packet.");

        let mut rx_packet_rb = PacketRingBuffer::new(
            /* max_size_in_bytes= */ 5 + 2 * PACKET_HEADER_SIZE_IN_BYTES,
        );
        rx_packet_rb
            .add_packet(&[6], Duration::from_nanos(6))
            .expect("Failed to add packet.");
        rx_packet_rb
            .add_packet(&[7, 8], Duration::from_nanos(10))
            .expect("Failed to add packet.");
        rx_packet_rb
            .add_packet(&[9], Duration::from_nanos(12))
            .expect("Failed to add packet.");
        rx_packet_rb
            .add_packet(&[10, 11, 12], Duration::from_nanos(13))
            .expect("Failed to add packet.");
        rx_packet_rb
            .add_packet(&[13, 14], Duration::from_nanos(16))
            .expect("Failed to add packet.");

        let res =
            PacketRingBuffer::pop_ring_buffers_and_aggregate(&mut tx_packet_rb, &mut rx_packet_rb);

        let packet_data_list: Vec<&[u8]> = res.iter().map(|packet| packet.buf.as_ref()).collect();
        assert_eq!(packet_data_list.len(), 3);
        assert_eq!(packet_data_list[0], &[10, 11, 12]);
        assert_eq!(packet_data_list[1], &[5]);
        assert_eq!(packet_data_list[2], &[13, 14]);
    }
}
