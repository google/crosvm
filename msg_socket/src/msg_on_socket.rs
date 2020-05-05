// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fmt::{self, Display};
use std::fs::File;
use std::mem::{size_of, transmute_copy, MaybeUninit};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};
use std::ptr::drop_in_place;
use std::result;
use std::sync::Arc;

use data_model::*;
use sync::Mutex;
use sys_util::{Error as SysError, EventFd};

#[derive(Debug, PartialEq)]
/// An error during transaction or serialization/deserialization.
pub enum MsgError {
    /// Error adding a waker for async read.
    AddingWaker(cros_async::Error),
    /// Error while sending a request or response.
    Send(SysError),
    /// Error while receiving a request or response.
    Recv(SysError),
    /// The type of a received request or response is unknown.
    InvalidType,
    /// There was not the expected amount of data when receiving a message. The inner
    /// value is how much data is expected and how much data was actually received.
    BadRecvSize { expected: usize, actual: usize },
    /// There was no data received when the socket `recv`-ed.
    RecvZero,
    /// There was no associated file descriptor received for a request that expected it.
    ExpectFd,
    /// There was some associated file descriptor received but not used when deserialize.
    NotExpectFd,
    /// Failed to set flags on the file descriptor.
    SettingFdFlags(SysError),
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
            AddingWaker(e) => write!(f, "failed to add a waker: {}", e),
            Send(e) => write!(f, "failed to send request or response: {}", e),
            Recv(e) => write!(f, "failed to receive request or response: {}", e),
            InvalidType => write!(f, "invalid type"),
            BadRecvSize { expected, actual } => write!(
                f,
                "wrong amount of data received; expected {} bytes; got {} bytes",
                expected, actual
            ),
            RecvZero => write!(f, "received zero data"),
            ExpectFd => write!(f, "missing associated file descriptor for request"),
            NotExpectFd => write!(f, "unexpected file descriptor is unused"),
            SettingFdFlags(e) => write!(f, "failed setting flags on the message FD: {}", e),
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
    // `true` if this structure can potentially serialize fds.
    fn uses_fd() -> bool {
        false
    }

    // Returns `Some(size)` if this structure always has a fixed size.
    fn fixed_size() -> Option<usize> {
        None
    }

    /// Size of message in bytes.
    fn msg_size(&self) -> usize {
        Self::fixed_size().unwrap()
    }

    /// Number of FDs in this message. This must be overridden if `uses_fd()` returns true.
    fn fd_count(&self) -> usize {
        assert!(!Self::uses_fd());
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
    fn fixed_size() -> Option<usize> {
        Some(size_of::<u32>())
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
    fn fixed_size() -> Option<usize> {
        Some(0)
    }

    fn fd_count(&self) -> usize {
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
    fn uses_fd() -> bool {
        T::uses_fd()
    }

    fn msg_size(&self) -> usize {
        match self {
            Some(v) => v.msg_size() + 1,
            None => 0,
        }
    }

    fn fd_count(&self) -> usize {
        match self {
            Some(v) => v.fd_count(),
            None => 0,
        }
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

impl<T: MsgOnSocket> MsgOnSocket for Mutex<T> {
    fn uses_fd() -> bool {
        T::uses_fd()
    }

    fn msg_size(&self) -> usize {
        self.lock().msg_size()
    }

    fn fd_count(&self) -> usize {
        self.lock().fd_count()
    }

    unsafe fn read_from_buffer(buffer: &[u8], fds: &[RawFd]) -> MsgResult<(Self, usize)> {
        T::read_from_buffer(buffer, fds).map(|(v, count)| (Mutex::new(v), count))
    }

    fn write_to_buffer(&self, buffer: &mut [u8], fds: &mut [RawFd]) -> MsgResult<usize> {
        self.lock().write_to_buffer(buffer, fds)
    }
}

impl<T: MsgOnSocket> MsgOnSocket for Arc<T> {
    fn uses_fd() -> bool {
        T::uses_fd()
    }

    fn msg_size(&self) -> usize {
        (**self).msg_size()
    }

    fn fd_count(&self) -> usize {
        (**self).fd_count()
    }

    unsafe fn read_from_buffer(buffer: &[u8], fds: &[RawFd]) -> MsgResult<(Self, usize)> {
        T::read_from_buffer(buffer, fds).map(|(v, count)| (Arc::new(v), count))
    }

    fn write_to_buffer(&self, buffer: &mut [u8], fds: &mut [RawFd]) -> MsgResult<usize> {
        (**self).write_to_buffer(buffer, fds)
    }
}

impl MsgOnSocket for () {
    fn fixed_size() -> Option<usize> {
        Some(0)
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
            fn uses_fd() -> bool {
                true
            }
            fn msg_size(&self) -> usize {
                0
            }
            fn fd_count(&self) -> usize {
                1
            }
            unsafe fn read_from_buffer(_buffer: &[u8], fds: &[RawFd]) -> MsgResult<(Self, usize)> {
                if fds.len() < 1 {
                    return Err(MsgError::ExpectFd);
                }
                Ok(($type::from_raw_fd(fds[0]), 1))
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
    fn msg_size(&self) -> usize {
        size_of::<u64>()
    }
    unsafe fn read_from_buffer(buffer: &[u8], _fds: &[RawFd]) -> MsgResult<(Self, usize)> {
        if buffer.len() < size_of::<u64>() {
            return Err(MsgError::WrongMsgBufferSize);
        }
        let t = u64::from_le_bytes(slice_to_array(buffer));
        Ok((t as usize, 0))
    }

    fn write_to_buffer(&self, buffer: &mut [u8], _fds: &mut [RawFd]) -> MsgResult<usize> {
        if buffer.len() < size_of::<u64>() {
            return Err(MsgError::WrongMsgBufferSize);
        }
        let t: Le64 = (*self as u64).into();
        buffer[0..self.msg_size()].copy_from_slice(t.as_slice());
        Ok(0)
    }
}

// Encode bool as a u8 of value 0 or 1
impl MsgOnSocket for bool {
    fn msg_size(&self) -> usize {
        size_of::<u8>()
    }
    unsafe fn read_from_buffer(buffer: &[u8], _fds: &[RawFd]) -> MsgResult<(Self, usize)> {
        if buffer.len() < size_of::<u8>() {
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
        if buffer.len() < size_of::<u8>() {
            return Err(MsgError::WrongMsgBufferSize);
        }
        buffer[0] = *self as u8;
        Ok(0)
    }
}

macro_rules! le_impl {
    ($type:ident, $native_type:ident) => {
        impl MsgOnSocket for $type {
            fn fixed_size() -> Option<usize> {
                Some(size_of::<$native_type>())
            }

            unsafe fn read_from_buffer(buffer: &[u8], _fds: &[RawFd]) -> MsgResult<(Self, usize)> {
                if buffer.len() < size_of::<$native_type>() {
                    return Err(MsgError::WrongMsgBufferSize);
                }
                let t = $native_type::from_le_bytes(slice_to_array(buffer));
                Ok((t.into(), 0))
            }

            fn write_to_buffer(&self, buffer: &mut [u8], _fds: &mut [RawFd]) -> MsgResult<usize> {
                if buffer.len() < size_of::<$native_type>() {
                    return Err(MsgError::WrongMsgBufferSize);
                }
                let t: $native_type = self.clone().into();
                buffer[0..self.msg_size()].copy_from_slice(&t.to_le_bytes());
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
            fn uses_fd() -> bool {
                T::uses_fd()
            }

            fn fixed_size() -> Option<usize> {
                Some(T::fixed_size()? * $N)
            }

            fn msg_size(&self) -> usize {
                match T::fixed_size() {
                    Some(s) => s * $N,
                    None => self.iter().map(|i| i.msg_size()).sum::<usize>() + size_of::<u64>() * $N
                }
            }

            fn fd_count(&self) -> usize {
                if T::uses_fd() {
                    self.iter().map(|i| i.fd_count()).sum()
                } else {
                    0
                }
            }

            unsafe fn read_from_buffer(buffer: &[u8], fds: &[RawFd]) -> MsgResult<(Self, usize)> {
                // Taken from the canonical example of initializing an array, the `assume_init` can
                // be assumed safe because the array elements (`MaybeUninit<T>` in this case)
                // themselves don't require initializing.
                let mut msgs: [MaybeUninit<T>; $N] =  MaybeUninit::uninit().assume_init();

                let mut offset = 0usize;
                let mut fd_offset = 0usize;

                // In case of an error, we need to keep track of how many elements got initialized.
                // In order to perform the necessary drops, the below loop is executed in a closure
                // to capture errors without returning.
                let mut last_index = 0;
                let res = (|| {
                    for msg in &mut msgs[..] {
                        let element_size = match T::fixed_size() {
                            Some(s) => s,
                            None => {
                                let (element_size, _) = u64::read_from_buffer(&buffer[offset..], &[])?;
                                offset += element_size.msg_size();
                                element_size as usize
                            }
                        };
                        let (m, fd_size) =
                            T::read_from_buffer(&buffer[offset..], &fds[fd_offset..])?;
                        *msg = MaybeUninit::new(m);
                        offset += element_size;
                        fd_offset += fd_size;
                        last_index += 1;
                    }
                    Ok(())
                })();

                // Because `MaybeUninit` will not automatically call drops, we have to drop the
                // partially initialized array manually in the case of an error.
                if let Err(e) = res {
                    for msg in &mut msgs[..last_index] {
                        // The call to `as_mut_ptr()` turns the `MaybeUninit` element of the array
                        // into a pointer, which can be used with `drop_in_place` to call the
                        // destructor without moving the element, which is impossible. This is safe
                        // because `last_index` prevents this loop from traversing into the
                        // uninitialized parts of the array.
                        drop_in_place(msg.as_mut_ptr());
                    }
                    return Err(e)
                }

                // Also taken from the canonical example, we initialized every member of the array
                // in the first loop of this function, so it is safe to `transmute_copy` the array
                // of `MaybeUninit` data to plain data. Although `transmute`, which checks the
                // types' sizes, would have been preferred in this code, the compiler complains with
                // "cannot transmute between types of different sizes, or dependently-sized types."
                // Because this function operates on generic data, the type is "dependently-sized"
                // and so the compiler will not check that the size of the input and output match.
                // See this issue for details: https://github.com/rust-lang/rust/issues/61956
                Ok((transmute_copy::<_, [T; $N]>(&msgs), fd_offset))
            }

            fn write_to_buffer(
                &self,
                buffer: &mut [u8],
                fds: &mut [RawFd],
                ) -> MsgResult<usize> {
                let mut offset = 0usize;
                let mut fd_offset = 0usize;
                for idx in 0..$N {
                    let element_size = match T::fixed_size() {
                        Some(s) => s,
                        None => {
                            let element_size = self[idx].msg_size() as u64;
                            element_size.write_to_buffer(&mut buffer[offset..], &mut [])?;
                            offset += element_size.msg_size();
                            element_size as usize
                        }
                    };
                    let fd_size = self[idx].write_to_buffer(&mut buffer[offset..],
                                                            &mut fds[fd_offset..])?;
                    offset += element_size;
                    fd_offset += fd_size;
                }

                Ok(fd_offset)
            }
        }
        #[cfg(test)]
        mod $t {
            use super::MsgOnSocket;

            #[test]
            fn read_write_option_array() {
                type ArrayType = [Option<u32>; $N];
                let array = [Some($N); $N];
                let mut buffer = vec![0; array.msg_size()];
                array.write_to_buffer(&mut buffer, &mut []).unwrap();
                let read_array = unsafe { ArrayType::read_from_buffer(&buffer, &[]) }.unwrap().0;

                assert_eq!(array, read_array);
            }

            #[test]
            fn read_write_fixed() {
                type ArrayType = [u32; $N];
                let mut buffer = vec![0; <ArrayType>::fixed_size().unwrap()];
                let array = [$N as u32; $N];
                array.write_to_buffer(&mut buffer, &mut []).unwrap();
                let read_array = unsafe { ArrayType::read_from_buffer(&buffer, &[]) }.unwrap().0;

                assert_eq!(array, read_array);
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
