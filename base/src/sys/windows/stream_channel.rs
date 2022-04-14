// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::RawDescriptor;
use crate::descriptor::AsRawDescriptor;
use std::io;
#[path = "win/stream_channel.rs"]
mod stream_channel;
pub use stream_channel::*;

#[derive(Copy, Clone)]
pub enum FramingMode {
    Message,
    Byte,
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum BlockingMode {
    Blocking,
    Nonblocking,
}

impl io::Read for StreamChannel {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner_read(buf)
    }
}

impl io::Read for &StreamChannel {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner_read(buf)
    }
}

impl AsRawDescriptor for StreamChannel {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        (&self).as_raw_descriptor()
    }
}

#[cfg(test)]
mod test {
    use super::{
        super::{EventContext, EventTrigger, PollToken, ReadNotifier},
        *,
    };
    use std::io::{Read, Write};

    #[derive(PollToken, Debug, Eq, PartialEq, Copy, Clone)]
    enum Token {
        ReceivedData,
    }

    #[test]
    fn test_non_blocking_pair() {
        let (mut sender, mut receiver) =
            StreamChannel::pair(BlockingMode::Nonblocking, FramingMode::Byte).unwrap();

        sender.write_all(&[75, 77, 54, 82, 76, 65]).unwrap();

        // Wait for the data to arrive.
        let event_ctx: EventContext<Token> = EventContext::build_with(&[EventTrigger::from(
            receiver.get_read_notifier(),
            Token::ReceivedData,
        )])
        .unwrap();
        let events = event_ctx.wait().unwrap();
        let tokens: Vec<Token> = events
            .iter()
            .filter(|e| e.is_readable)
            .map(|e| e.token)
            .collect();
        assert_eq!(tokens, vec! {Token::ReceivedData});

        // Smaller than what we sent so we get multiple chunks
        let mut recv_buffer: [u8; 4] = [0; 4];

        let mut size = receiver.read(&mut recv_buffer).unwrap();
        assert_eq!(size, 4);
        assert_eq!(recv_buffer, [75, 77, 54, 82]);

        size = receiver.read(&mut recv_buffer).unwrap();
        assert_eq!(size, 2);
        assert_eq!(recv_buffer[0..2], [76, 65]);

        // Now that we've polled for & received all data, polling again should show no events.
        assert_eq!(
            event_ctx
                .wait_timeout(std::time::Duration::new(0, 0))
                .unwrap()
                .len(),
            0
        );
    }

    #[test]
    fn test_non_blocking_pair_error_no_data() {
        let (mut sender, mut receiver) =
            StreamChannel::pair(BlockingMode::Nonblocking, FramingMode::Byte).unwrap();
        receiver
            .set_nonblocking(true)
            .expect("Failed to set receiver to nonblocking mode.");

        sender.write_all(&[75, 77]).unwrap();

        // Wait for the data to arrive.
        let event_ctx: EventContext<Token> = EventContext::build_with(&[EventTrigger::from(
            receiver.get_read_notifier(),
            Token::ReceivedData,
        )])
        .unwrap();
        let events = event_ctx.wait().unwrap();
        let tokens: Vec<Token> = events
            .iter()
            .filter(|e| e.is_readable)
            .map(|e| e.token)
            .collect();
        assert_eq!(tokens, vec! {Token::ReceivedData});

        // We only read 2 bytes, even though we requested 4 bytes.
        let mut recv_buffer: [u8; 4] = [0; 4];
        let size = receiver.read(&mut recv_buffer).unwrap();
        assert_eq!(size, 2);
        assert_eq!(recv_buffer, [75, 77, 00, 00]);

        // Further reads should encounter an error since there is no available data and this is a
        // non blocking pipe.
        assert!(receiver.read(&mut recv_buffer).is_err());
    }
}
