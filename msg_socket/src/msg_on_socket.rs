// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fmt::{self, Display};
use std::fs::File;
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};
use std::result;

use data_model::*;
use sys_util::{Error as SysError, EventFd};

#[derive(Debug, PartialEq)]
/// An error during transaction or serialization/deserialization.
pub enum MsgError {
    /// Error while sending a request or response.
    Send(SysError),
    /// Error while receiving a request or response.
    Recv(SysError),
    /// The type of a received request or response is unknown.
    InvalidType,
    /// There was not the expected amount of data when receiving a message. The inner
    /// value is how much data is expected and how much data was actually received.
    BadRecvSize { expected: usize, actual: usize },
    /// There was no associated file descriptor received for a request that expected it.
    ExpectFd,
    /// There was some associated file descriptor received but not used when deserialize.
    NotExpectFd,
    /// Trying to serialize/deserialize, but fd buffer size is too small. This typically happens
    /// when max_fd_count() returns a value that is too small.
    WrongFdBufferSize,
    /// Trying to serialize/deserialize, but msg buffer size is too small. This typically happens
    /// when msg_size() returns a value that is too small.
    WrongMsgBufferSize,
}

pub type MsgResult<T> = result::Result<T, MsgError>;

impl Display for MsgError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::MsgError::*;

        match self {
            Send(e) => write!(f, "failed to send request or response: {}", e),
            Recv(e) => write!(f, "failed to receive request or response: {}", e),
            InvalidType => write!(f, "invalid type"),
            BadRecvSize { expected, actual } => write!(
                f,
                "wrong amount of data received; expected {} bytes; got {} bytes",
                expected, actual
            ),
            ExpectFd => write!(f, "missing associated file descriptor for request"),
            NotExpectFd => write!(f, "unexpected file descriptor is unused"),
            WrongFdBufferSize => write!(f, "fd buffer size too small"),
            WrongMsgBufferSize => write!(f, "msg buffer size too small"),
        }
    }
}

/// A msg that could be serialized to and deserialize from array in little endian.
///
/// For structs, we always have fixed size of bytes and fixed count of fds.
/// For enums, the size needed might be different for each variant.
///
/// e.g.
/// ```
/// use std::os::unix::io::RawFd;
/// enum Message {
///     VariantA(u8),
///     VariantB(u32, RawFd),
///     VariantC,
/// }
/// ```
///
/// For variant A, we need 1 byte to store its inner value.
/// For variant B, we need 4 bytes and 1 RawFd to store its inner value.
/// For variant C, we need 0 bytes to store its inner value.
/// When we serialize Message to (buffer, fd_buffer), we always use fixed number of bytes in
/// the buffer. Unused buffer bytes will be padded with zero.
/// However, for fd_buffer, we could not do the same thing. Otherwise, we are essentially sending
/// fd 0 through the socket.
/// Thus, read/write functions always the return correct count of fds in this variant. There will be
/// no padding in fd_buffer.
pub trait MsgOnSocket: Sized {
    /// Size of message in bytes.
    fn msg_size() -> usize;
    /// Max possible fd count in this type.
    fn max_fd_count() -> usize {
        0
    }
    /// Returns (self, fd read count).
    /// This function is safe only when:
    ///     0. fds contains valid fds, received from socket, serialized by Self::write_to_buffer.
    ///     1. For enum, fds contains correct fd layout of the particular variant.
    ///     2. write_to_buffer is implemented correctly(put valid fds into the buffer, has no padding,
    ///        return correct count).
    unsafe fn read_from_buffer(buffer: &[u8], fds: &[RawFd]) -> MsgResult<(Self, usize)>;
    /// Serialize self to buffers.
    fn write_to_buffer(&self, buffer: &mut [u8], fds: &mut [RawFd]) -> MsgResult<usize>;
}

impl MsgOnSocket for SysError {
    fn msg_size() -> usize {
        u32::msg_size()
    }
    unsafe fn read_from_buffer(buffer: &[u8], fds: &[RawFd]) -> MsgResult<(Self, usize)> {
        let (v, size) = u32::read_from_buffer(buffer, fds)?;
        Ok((SysError::new(v as i32), size))
    }
    fn write_to_buffer(&self, buffer: &mut [u8], fds: &mut [RawFd]) -> MsgResult<usize> {
        let v = self.errno() as u32;
        v.write_to_buffer(buffer, fds)
    }
}

impl MsgOnSocket for RawFd {
    fn msg_size() -> usize {
        0
    }
    fn max_fd_count() -> usize {
        1
    }
    unsafe fn read_from_buffer(_buffer: &[u8], fds: &[RawFd]) -> MsgResult<(Self, usize)> {
        if fds.is_empty() {
            return Err(MsgError::ExpectFd);
        }
        Ok((fds[0], 1))
    }
    fn write_to_buffer(&self, _buffer: &mut [u8], fds: &mut [RawFd]) -> MsgResult<usize> {
        if fds.is_empty() {
            return Err(MsgError::WrongFdBufferSize);
        }
        fds[0] = *self;
        Ok(1)
    }
}

impl<T: MsgOnSocket> MsgOnSocket for Option<T> {
    fn msg_size() -> usize {
        T::msg_size() + 1
    }

    fn max_fd_count() -> usize {
        T::max_fd_count()
    }

    unsafe fn read_from_buffer(buffer: &[u8], fds: &[RawFd]) -> MsgResult<(Self, usize)> {
        match buffer[0] {
            0 => Ok((None, 0)),
            1 => {
                let (inner, len) = T::read_from_buffer(&buffer[1..], fds)?;
                Ok((Some(inner), len))
            }
            _ => Err(MsgError::InvalidType),
        }
    }

    fn write_to_buffer(&self, buffer: &mut [u8], fds: &mut [RawFd]) -> MsgResult<usize> {
        match self {
            None => {
                buffer[0] = 0;
                Ok(0)
            }
            Some(inner) => {
                buffer[0] = 1;
                inner.write_to_buffer(&mut buffer[1..], fds)
            }
        }
    }
}

impl MsgOnSocket for () {
    fn msg_size() -> usize {
        0
    }

    fn max_fd_count() -> usize {
        0
    }

    unsafe fn read_from_buffer(_buffer: &[u8], _fds: &[RawFd]) -> MsgResult<(Self, usize)> {
        Ok(((), 0))
    }

    fn write_to_buffer(&self, _buffer: &mut [u8], _fds: &mut [RawFd]) -> MsgResult<usize> {
        Ok(0)
    }
}

macro_rules! rawfd_impl {
    ($type:ident) => {
        impl MsgOnSocket for $type {
            fn msg_size() -> usize {
                0
            }
            fn max_fd_count() -> usize {
                1
            }
            unsafe fn read_from_buffer(_buffer: &[u8], fds: &[RawFd]) -> MsgResult<(Self, usize)> {
                if fds.len() < 1 {
                    return Err(MsgError::ExpectFd);
                }
                Ok(($type::from_raw_fd(fds[0].clone()), 1))
            }
            fn write_to_buffer(&self, _buffer: &mut [u8], fds: &mut [RawFd]) -> MsgResult<usize> {
                if fds.len() < 1 {
                    return Err(MsgError::WrongFdBufferSize);
                }
                fds[0] = self.as_raw_fd();
                Ok(1)
            }
        }
    };
}

rawfd_impl!(EventFd);
rawfd_impl!(File);
rawfd_impl!(UnixStream);
rawfd_impl!(TcpStream);
rawfd_impl!(TcpListener);
rawfd_impl!(UdpSocket);
rawfd_impl!(UnixListener);
rawfd_impl!(UnixDatagram);

// Converts a slice into an array of fixed size inferred from by the return value. Panics if the
// slice is too small, but will tolerate slices that are too large.
fn slice_to_array<T, O>(s: &[T]) -> O
where
    T: Copy,
    O: Default + AsMut<[T]>,
{
    let mut o = O::default();
    let o_slice = o.as_mut();
    let len = o_slice.len();
    o_slice.copy_from_slice(&s[..len]);
    o
}

// usize could be different sizes on different targets. We always use u64.
impl MsgOnSocket for usize {
    fn msg_size() -> usize {
        std::mem::size_of::<u64>()
    }
    unsafe fn read_from_buffer(buffer: &[u8], _fds: &[RawFd]) -> MsgResult<(Self, usize)> {
        if buffer.len() < std::mem::size_of::<u64>() {
            return Err(MsgError::WrongMsgBufferSize);
        }
        let t = u64::from_le_bytes(slice_to_array(buffer));
        Ok((t as usize, 0))
    }

    fn write_to_buffer(&self, buffer: &mut [u8], _fds: &mut [RawFd]) -> MsgResult<usize> {
        if buffer.len() < std::mem::size_of::<u64>() {
            return Err(MsgError::WrongMsgBufferSize);
        }
        let t: Le64 = (*self as u64).into();
        buffer[0..Self::msg_size()].copy_from_slice(t.as_slice());
        Ok(0)
    }
}

// Encode bool as a u8 of value 0 or 1
impl MsgOnSocket for bool {
    fn msg_size() -> usize {
        std::mem::size_of::<u8>()
    }
    unsafe fn read_from_buffer(buffer: &[u8], _fds: &[RawFd]) -> MsgResult<(Self, usize)> {
        if buffer.len() < std::mem::size_of::<u8>() {
            return Err(MsgError::WrongMsgBufferSize);
        }
        let t: u8 = buffer[0];
        match t {
            0 => Ok((false, 0)),
            1 => Ok((true, 0)),
            _ => Err(MsgError::InvalidType),
        }
    }
    fn write_to_buffer(&self, buffer: &mut [u8], _fds: &mut [RawFd]) -> MsgResult<usize> {
        if buffer.len() < std::mem::size_of::<u8>() {
            return Err(MsgError::WrongMsgBufferSize);
        }
        buffer[0] = *self as u8;
        Ok(0)
    }
}

macro_rules! le_impl {
    ($type:ident, $native_type:ident) => {
        impl MsgOnSocket for $type {
            fn msg_size() -> usize {
                std::mem::size_of::<$native_type>()
            }
            unsafe fn read_from_buffer(buffer: &[u8], _fds: &[RawFd]) -> MsgResult<(Self, usize)> {
                if buffer.len() < std::mem::size_of::<$native_type>() {
                    return Err(MsgError::WrongMsgBufferSize);
                }
                let t = $native_type::from_le_bytes(slice_to_array(buffer));
                Ok((t.into(), 0))
            }

            fn write_to_buffer(&self, buffer: &mut [u8], _fds: &mut [RawFd]) -> MsgResult<usize> {
                if buffer.len() < std::mem::size_of::<$native_type>() {
                    return Err(MsgError::WrongMsgBufferSize);
                }
                let t: $native_type = self.clone().into();
                buffer[0..Self::msg_size()].copy_from_slice(&t.to_le_bytes());
                Ok(0)
            }
        }
    };
}

le_impl!(u8, u8);
le_impl!(u16, u16);
le_impl!(u32, u32);
le_impl!(u64, u64);

le_impl!(Le16, u16);
le_impl!(Le32, u32);
le_impl!(Le64, u64);

macro_rules! array_impls {
    ($N:expr, $t: ident $($ts:ident)*)
    => {
        impl<T: MsgOnSocket + Clone> MsgOnSocket for [T; $N] {
            fn msg_size() -> usize {
                T::msg_size() * $N
            }
            fn max_fd_count() -> usize {
                T::max_fd_count() * $N
            }
            unsafe fn read_from_buffer(buffer: &[u8], fds: &[RawFd]) -> MsgResult<(Self, usize)> {
                if buffer.len() < Self::msg_size() {
                    return Err(MsgError::WrongMsgBufferSize);
                }
                let mut offset = 0usize;
                let mut fd_offset = 0usize;
                let ($t, fd_size) =
                    T::read_from_buffer(&buffer[offset..], &fds[fd_offset..])?;
                offset += T::msg_size();
                fd_offset += fd_size;
                $(
                    let ($ts, fd_size) =
                        T::read_from_buffer(&buffer[offset..], &fds[fd_offset..])?;
                    offset += T::msg_size();
                    fd_offset += fd_size;
                    )*
                assert_eq!(offset, Self::msg_size());
                Ok(([$t, $($ts),*], fd_offset))
            }

            fn write_to_buffer(
                &self,
                buffer: &mut [u8],
                fds: &mut [RawFd],
                ) -> MsgResult<usize> {
                if buffer.len() < Self::msg_size() {
                    return Err(MsgError::WrongMsgBufferSize);
                }
                let mut offset = 0usize;
                let mut fd_offset = 0usize;
                for idx in 0..$N {
                    let fd_size = self[idx].clone().write_to_buffer(&mut buffer[offset..],
                                                            &mut fds[fd_offset..])?;
                    offset += T::msg_size();
                    fd_offset += fd_size;
                }

                Ok(fd_offset)
            }
        }
        array_impls!(($N - 1), $($ts)*);
    };
    {$N:expr, } => {};
}

array_impls! {
    32, tmp1 tmp2 tmp3 tmp4 tmp5 tmp6 tmp7 tmp8 tmp9 tmp10 tmp11 tmp12 tmp13 tmp14 tmp15 tmp16
        tmp17 tmp18 tmp19 tmp20 tmp21 tmp22 tmp23 tmp24 tmp25 tmp26 tmp27 tmp28 tmp29 tmp30 tmp31
        tmp32
}

// TODO(jkwang) Define MsgOnSocket for tuple?
