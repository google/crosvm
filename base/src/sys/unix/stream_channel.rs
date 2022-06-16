// Copyright 2022 The ChromiumOS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::super::{net::UnixSeqpacket, Result};
use super::RawDescriptor;
use crate::{descriptor::AsRawDescriptor, ReadNotifier};
use libc::{
    c_void, {self},
};
use std::{
    io::{
        Read, {self},
    },
    os::unix::net::UnixStream,
};

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

enum SocketType {
    Message(UnixSeqpacket),
    Byte(UnixStream),
}

/// An abstraction over named pipes and unix socketpairs. This abstraction can be used in a blocking
/// and non blocking mode.
pub struct StreamChannel {
    stream: SocketType,
}

impl StreamChannel {
    pub fn set_nonblocking(&mut self, nonblocking: bool) -> io::Result<()> {
        match &mut self.stream {
            SocketType::Byte(sock) => sock.set_nonblocking(nonblocking),
            SocketType::Message(sock) => sock.set_nonblocking(nonblocking),
        }
    }

    pub(super) fn inner_read(&self, buf: &mut [u8]) -> io::Result<usize> {
        match &self.stream {
            SocketType::Byte(sock) => (&mut &*sock).read(buf),

            // On Windows, reading from SOCK_SEQPACKET with a buffer that is too small is an error,
            // but on Linux will silently truncate unless MSG_TRUNC is passed. Here, we emulate
            // Windows behavior on POSIX.
            //
            // Note that Rust translates ERROR_MORE_DATA into io::ErrorKind::Other
            // (see sys::decode_error_kind) on Windows, so we preserve this behavior on POSIX even
            // though one could argue ErrorKind::UnexpectedEof is a closer match to the true error.
            SocketType::Message(sock) => {
                // Safe because buf is valid, we pass buf's size to recv to bound the return
                // length, and we check the return code.
                let retval = unsafe {
                    // TODO(nkgold|b/152067913): Move this into the UnixSeqpacket struct as a
                    // recv_with_flags method once that struct's tests are working.
                    libc::recv(
                        sock.as_raw_descriptor(),
                        buf.as_mut_ptr() as *mut c_void,
                        buf.len(),
                        libc::MSG_TRUNC,
                    )
                };
                let receive_len = if retval < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(retval)
                }? as usize;

                if receive_len > buf.len() {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!(
                            "packet size {:?} encountered, but buffer was only of size {:?}",
                            receive_len,
                            buf.len()
                        ),
                    ))
                } else {
                    Ok(receive_len)
                }
            }
        }
    }

    /// Creates a cross platform stream pair.
    pub fn pair(
        blocking_mode: BlockingMode,
        framing_mode: FramingMode,
    ) -> Result<(StreamChannel, StreamChannel)> {
        let (pipe_a, pipe_b) = match framing_mode {
            FramingMode::Byte => {
                let (pipe_a, pipe_b) = UnixStream::pair()?;
                (SocketType::Byte(pipe_a), SocketType::Byte(pipe_b))
            }
            FramingMode::Message => {
                let (pipe_a, pipe_b) = UnixSeqpacket::pair()?;
                (SocketType::Message(pipe_a), SocketType::Message(pipe_b))
            }
        };
        let mut stream_a = StreamChannel { stream: pipe_a };
        let mut stream_b = StreamChannel { stream: pipe_b };
        let is_non_blocking = blocking_mode == BlockingMode::Nonblocking;
        stream_a.set_nonblocking(is_non_blocking)?;
        stream_b.set_nonblocking(is_non_blocking)?;
        Ok((stream_a, stream_b))
    }
}

impl io::Write for StreamChannel {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match &mut self.stream {
            SocketType::Byte(sock) => sock.write(buf),
            SocketType::Message(sock) => sock.send(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match &mut self.stream {
            SocketType::Byte(sock) => sock.flush(),
            SocketType::Message(_) => Ok(()),
        }
    }
}

impl AsRawDescriptor for &StreamChannel {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        match &self.stream {
            SocketType::Byte(sock) => sock.as_raw_descriptor(),
            SocketType::Message(sock) => sock.as_raw_descriptor(),
        }
    }
}

impl ReadNotifier for StreamChannel {
    /// Returns a RawDescriptor that can be polled for reads using PollContext.
    fn get_read_notifier(&self) -> &dyn AsRawDescriptor {
        self
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{EventContext, EventToken, ReadNotifier};
    use std::io::{Read, Write};

    #[derive(EventToken, Debug, Eq, PartialEq, Copy, Clone)]
    enum Token {
        ReceivedData,
    }

    #[test]
    fn test_non_blocking_pair() {
        let (mut sender, mut receiver) =
            StreamChannel::pair(BlockingMode::Nonblocking, FramingMode::Byte).unwrap();

        sender.write_all(&[75, 77, 54, 82, 76, 65]).unwrap();

        // Wait for the data to arrive.
        let event_ctx: EventContext<Token> =
            EventContext::build_with(&[(receiver.get_read_notifier(), Token::ReceivedData)])
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
        let event_ctx: EventContext<Token> =
            EventContext::build_with(&[(receiver.get_read_notifier(), Token::ReceivedData)])
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
