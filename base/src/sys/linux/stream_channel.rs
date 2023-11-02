// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;
use std::io::Read;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use libc::c_void;
use serde::Deserialize;
use serde::Serialize;

use super::super::net::UnixSeqpacket;
use super::super::Result;
use super::RawDescriptor;
use crate::descriptor::AsRawDescriptor;
use crate::ReadNotifier;

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

#[derive(Debug, Deserialize, Serialize)]
enum SocketType {
    Message(UnixSeqpacket),
    #[serde(with = "crate::with_as_descriptor")]
    Byte(UnixStream),
}

/// An abstraction over named pipes and unix socketpairs. This abstraction can be used in a blocking
/// and non blocking mode.
#[derive(Debug, Deserialize, Serialize)]
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

    pub fn get_framing_mode(&self) -> FramingMode {
        match &self.stream {
            SocketType::Message(_) => FramingMode::Message,
            SocketType::Byte(_) => FramingMode::Byte,
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

    pub fn from_unix_seqpacket(sock: UnixSeqpacket) -> StreamChannel {
        StreamChannel {
            stream: SocketType::Message(sock),
        }
    }

    pub fn peek_size(&self) -> io::Result<usize> {
        match &self.stream {
            SocketType::Byte(_) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Cannot check the size of streamed data",
            )),
            SocketType::Message(sock) => Ok(sock.next_packet_size()?),
        }
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match &self.stream {
            SocketType::Byte(sock) => sock.set_read_timeout(timeout),
            SocketType::Message(sock) => sock.set_read_timeout(timeout),
        }
    }

    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match &self.stream {
            SocketType::Byte(sock) => sock.set_write_timeout(timeout),
            SocketType::Message(sock) => sock.set_write_timeout(timeout),
        }
    }

    // WARNING: Generally, multiple StreamChannel ends are not wanted. StreamChannel behavior with
    // > 1 reader per end is not defined.
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(StreamChannel {
            stream: match &self.stream {
                SocketType::Byte(sock) => SocketType::Byte(sock.try_clone()?),
                SocketType::Message(sock) => SocketType::Message(sock.try_clone()?),
            },
        })
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

impl io::Write for &StreamChannel {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match &self.stream {
            SocketType::Byte(sock) => (&mut &*sock).write(buf),
            SocketType::Message(sock) => sock.send(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match &self.stream {
            SocketType::Byte(sock) => (&mut &*sock).flush(),
            SocketType::Message(_) => Ok(()),
        }
    }
}

impl AsRawFd for StreamChannel {
    fn as_raw_fd(&self) -> RawFd {
        match &self.stream {
            SocketType::Byte(sock) => sock.as_raw_descriptor(),
            SocketType::Message(sock) => sock.as_raw_descriptor(),
        }
    }
}

impl AsRawFd for &StreamChannel {
    fn as_raw_fd(&self) -> RawFd {
        self.as_raw_descriptor()
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
    use std::io::Read;
    use std::io::Write;

    use super::*;
    use crate::EventContext;
    use crate::EventToken;
    use crate::ReadNotifier;

    #[derive(EventToken, Debug, Eq, PartialEq, Copy, Clone)]
    enum Token {
        ReceivedData,
    }

    #[test]
    fn test_non_blocking_pair_byte() {
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
    fn test_non_blocking_pair_message() {
        let (mut sender, mut receiver) =
            StreamChannel::pair(BlockingMode::Nonblocking, FramingMode::Message).unwrap();

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

        // Unlike Byte format, Message mode panics if the buffer is smaller than the packet size;
        // make the buffer the right size.
        let mut recv_buffer: [u8; 6] = [0; 6];

        let size = receiver.read(&mut recv_buffer).unwrap();
        assert_eq!(size, 6);
        assert_eq!(recv_buffer, [75, 77, 54, 82, 76, 65]);

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

    #[test]
    fn test_from_unix_seqpacket() {
        let (sock_sender, sock_receiver) = UnixSeqpacket::pair().unwrap();
        let mut sender = StreamChannel::from_unix_seqpacket(sock_sender);
        let mut receiver = StreamChannel::from_unix_seqpacket(sock_receiver);

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

        let mut recv_buffer: [u8; 6] = [0; 6];

        let size = receiver.read(&mut recv_buffer).unwrap();
        assert_eq!(size, 6);
        assert_eq!(recv_buffer, [75, 77, 54, 82, 76, 65]);

        // Now that we've polled for & received all data, polling again should show no events.
        assert_eq!(
            event_ctx
                .wait_timeout(std::time::Duration::new(0, 0))
                .unwrap()
                .len(),
            0
        );
    }
}
