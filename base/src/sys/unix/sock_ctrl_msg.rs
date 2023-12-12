// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Used to send and receive messages with file descriptors on sockets that accept control messages
//! (e.g. Unix domain sockets).

use std::fs::File;
use std::io;
use std::io::IoSlice;
use std::io::IoSliceMut;
use std::mem::size_of;
use std::mem::size_of_val;
use std::mem::MaybeUninit;
use std::os::unix::io::RawFd;
use std::ptr::copy_nonoverlapping;
use std::ptr::null_mut;
use std::ptr::write_unaligned;
use std::slice;

use libc::c_long;
use libc::c_void;
use libc::cmsghdr;
use libc::iovec;
use libc::msghdr;
use libc::recvmsg;
use libc::SCM_RIGHTS;
use libc::SOL_SOCKET;
use serde::Deserialize;
use serde::Serialize;

use crate::sys::sendmsg;
use crate::AsRawDescriptor;
use crate::FromRawDescriptor;
use crate::IoBufMut;
use crate::RawDescriptor;
use crate::SafeDescriptor;
use crate::VolatileSlice;

// Each of the following functions performs the same function as their C counterparts. They are
// reimplemented as const fns here because they are used to size statically allocated arrays.

#[allow(non_snake_case)]
const fn CMSG_ALIGN(len: usize) -> usize {
    (len + size_of::<c_long>() - 1) & !(size_of::<c_long>() - 1)
}

#[allow(non_snake_case)]
const fn CMSG_SPACE(len: usize) -> usize {
    size_of::<cmsghdr>() + CMSG_ALIGN(len)
}

#[allow(non_snake_case)]
const fn CMSG_LEN(len: usize) -> usize {
    size_of::<cmsghdr>() + len
}

// This function (macro in the C version) is not used in any compile time constant slots, so is just
// an ordinary function. The returned pointer is hard coded to be RawFd because that's all that this
// module supports.
#[allow(non_snake_case)]
#[inline(always)]
fn CMSG_DATA(cmsg_buffer: *mut cmsghdr) -> *mut RawFd {
    // Essentially returns a pointer to just past the header.
    cmsg_buffer.wrapping_offset(1) as *mut RawFd
}

// This function is like CMSG_NEXT, but safer because it reads only from references, although it
// does some pointer arithmetic on cmsg_ptr.
#[allow(clippy::cast_ptr_alignment, clippy::unnecessary_cast)]
fn get_next_cmsg(msghdr: &msghdr, cmsg: &cmsghdr, cmsg_ptr: *mut cmsghdr) -> *mut cmsghdr {
    // The extra cast of cmsg_len to usize is required to build against musl libc, which uses
    // u32 for cmsg_len.
    let next_cmsg =
        (cmsg_ptr as *mut u8).wrapping_add(CMSG_ALIGN(cmsg.cmsg_len as usize)) as *mut cmsghdr;
    if next_cmsg
        .wrapping_offset(1)
        .wrapping_sub(msghdr.msg_control as usize) as usize
        > msghdr.msg_controllen as usize
    {
        null_mut()
    } else {
        next_cmsg
    }
}

const CMSG_BUFFER_INLINE_CAPACITY: usize = CMSG_SPACE(size_of::<RawFd>() * 32);

enum CmsgBuffer {
    Inline([u64; (CMSG_BUFFER_INLINE_CAPACITY + 7) / 8]),
    Heap(Box<[cmsghdr]>),
}

impl CmsgBuffer {
    fn with_capacity(capacity: usize) -> CmsgBuffer {
        let cap_in_cmsghdr_units =
            (capacity.checked_add(size_of::<cmsghdr>()).unwrap() - 1) / size_of::<cmsghdr>();
        if capacity <= CMSG_BUFFER_INLINE_CAPACITY {
            CmsgBuffer::Inline([0u64; (CMSG_BUFFER_INLINE_CAPACITY + 7) / 8])
        } else {
            CmsgBuffer::Heap(
                vec![
                    // SAFETY:
                    // Safe because cmsghdr only contains primitive types for
                    // which zero initialization is valid.
                    unsafe { MaybeUninit::<cmsghdr>::zeroed().assume_init() };
                    cap_in_cmsghdr_units
                ]
                .into_boxed_slice(),
            )
        }
    }

    fn as_mut_ptr(&mut self) -> *mut cmsghdr {
        match self {
            CmsgBuffer::Inline(a) => a.as_mut_ptr() as *mut cmsghdr,
            CmsgBuffer::Heap(a) => a.as_mut_ptr(),
        }
    }
}

// Musl requires a try_into when assigning to msg_iovlen and msg_controllen
// that is unnecessary when compiling for glibc.
#[allow(clippy::useless_conversion)]
fn raw_sendmsg(fd: RawFd, iovec: &[iovec], out_fds: &[RawFd]) -> io::Result<usize> {
    let cmsg_capacity = CMSG_SPACE(size_of_val(out_fds));
    let mut cmsg_buffer = CmsgBuffer::with_capacity(cmsg_capacity);

    // SAFETY:
    // msghdr on musl has private __pad1 and __pad2 fields that cannot be initialized.
    // Safe because msghdr only contains primitive types for which zero
    // initialization is valid.
    let mut msg: msghdr = unsafe { MaybeUninit::zeroed().assume_init() };
    msg.msg_iov = iovec.as_ptr() as *mut iovec;
    msg.msg_iovlen = iovec.len().try_into().unwrap();

    if !out_fds.is_empty() {
        // SAFETY:
        // msghdr on musl has an extra __pad1 field, initialize the whole struct to zero.
        // Safe because cmsghdr only contains primitive types for which zero
        // initialization is valid.
        let mut cmsg: cmsghdr = unsafe { MaybeUninit::zeroed().assume_init() };
        cmsg.cmsg_len = CMSG_LEN(size_of_val(out_fds)).try_into().unwrap();
        cmsg.cmsg_level = SOL_SOCKET;
        cmsg.cmsg_type = SCM_RIGHTS;
        // SAFETY: See call specific comments within unsafe block.
        unsafe {
            // SAFETY:
            // Safe because cmsg_buffer was allocated to be large enough to contain cmsghdr.
            write_unaligned(cmsg_buffer.as_mut_ptr(), cmsg);
            // SAFETY:
            // Safe because the cmsg_buffer was allocated to be large enough to hold out_fds.len()
            // file descriptors.
            copy_nonoverlapping(
                out_fds.as_ptr(),
                CMSG_DATA(cmsg_buffer.as_mut_ptr()),
                out_fds.len(),
            );
        }

        msg.msg_control = cmsg_buffer.as_mut_ptr() as *mut c_void;
        msg.msg_controllen = cmsg_capacity.try_into().unwrap();
    }

    // SAFETY:
    // Safe because the msghdr was properly constructed from valid (or null) pointers of the
    // indicated length and we check the return value.
    let write_count = unsafe { sendmsg(fd, &msg, 0) };

    if write_count == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(write_count as usize)
    }
}

// Musl requires a try_into when assigning to msg_iovlen, msg_controllen and
// cmsg_len that is unnecessary when compiling for glibc.
#[allow(clippy::useless_conversion, clippy::unnecessary_cast)]
fn raw_recvmsg(
    fd: RawFd,
    iovs: &mut [iovec],
    max_fds: usize,
) -> io::Result<(usize, Vec<SafeDescriptor>)> {
    let cmsg_capacity = CMSG_SPACE(max_fds * size_of::<RawFd>());
    let mut cmsg_buffer = CmsgBuffer::with_capacity(cmsg_capacity);

    // SAFETY:
    // msghdr on musl has private __pad1 and __pad2 fields that cannot be initialized.
    // Safe because msghdr only contains primitive types for which zero
    // initialization is valid.
    let mut msg: msghdr = unsafe { MaybeUninit::zeroed().assume_init() };
    msg.msg_iov = iovs.as_mut_ptr() as *mut iovec;
    msg.msg_iovlen = iovs.len().try_into().unwrap();

    if max_fds > 0 {
        msg.msg_control = cmsg_buffer.as_mut_ptr() as *mut c_void;
        msg.msg_controllen = cmsg_capacity.try_into().unwrap();
    }

    // SAFETY:
    // Safe because the msghdr was properly constructed from valid (or null) pointers of the
    // indicated length and we check the return value.
    let total_read = unsafe { recvmsg(fd, &mut msg, 0) };

    if total_read == -1 {
        return Err(io::Error::last_os_error());
    }

    if total_read == 0 && (msg.msg_controllen as usize) < size_of::<cmsghdr>() {
        return Ok((0, Vec::new()));
    }

    let mut cmsg_ptr = msg.msg_control as *mut cmsghdr;
    let mut in_fds: Vec<SafeDescriptor> = Vec::with_capacity(max_fds);
    while !cmsg_ptr.is_null() {
        // SAFETY:
        // Safe because we checked that cmsg_ptr was non-null, and the loop is constructed such that
        // that only happens when there is at least sizeof(cmsghdr) space after the pointer to read.
        let cmsg = unsafe { (cmsg_ptr as *mut cmsghdr).read_unaligned() };

        if cmsg.cmsg_level == SOL_SOCKET && cmsg.cmsg_type == SCM_RIGHTS {
            let fd_count = (cmsg.cmsg_len as usize - CMSG_LEN(0)) / size_of::<RawFd>();
            let fd_ptr: *const RawFd = CMSG_DATA(cmsg_ptr);
            for i in 0..fd_count {
                // SAFETY: `fd_ptr[i]` is within the `CMsgBuffer` allocation.
                let fd: RawFd = unsafe { fd_ptr.add(i).read_unaligned() };
                // SAFETY: We own the raw descriptor returned from `recvmsg()`.
                let sd = unsafe { SafeDescriptor::from_raw_descriptor(fd) };
                in_fds.push(sd);
            }
        }

        cmsg_ptr = get_next_cmsg(&msg, &cmsg, cmsg_ptr);
    }

    Ok((total_read as usize, in_fds))
}

/// The maximum number of FDs that can be sent in a single send.
pub const SCM_SOCKET_MAX_FD_COUNT: usize = 253;

/// Trait for file descriptors can send and receive socket control messages via `sendmsg` and
/// `recvmsg`.
///
/// On Linux, this uses MSG_NOSIGNAL to avoid triggering signals. On MacOS, this sets the
/// SO_NOSIGPIPE option on the file descriptor to avoid triggering signals.
#[derive(Serialize, Deserialize)]
pub struct ScmSocket<T: AsRawDescriptor> {
    pub(in crate::sys) socket: T,
}

impl<T: AsRawDescriptor> ScmSocket<T> {
    /// Sends the given data and file descriptors over the socket.
    ///
    /// On success, returns the number of bytes sent.
    ///
    /// The error is constructed via `std::io::Error::last_os_error()`.
    ///
    /// # Arguments
    ///
    /// * `buf` - A buffer of data to send on the `socket`.
    /// * `fds` - A list of file descriptors to be sent.
    pub fn send_with_fds(&self, buf: &[u8], fds: &[RawFd]) -> io::Result<usize> {
        self.send_vectored_with_fds(&[IoSlice::new(buf)], fds)
    }

    /// Sends the given data and file descriptors over the socket.
    ///
    /// On success, returns the number of bytes sent.
    ///
    /// The error is constructed via `std::io::Error::last_os_error()`.
    ///
    /// # Arguments
    ///
    /// * `bufs` - A slice of buffers of data to send on the `socket`.
    /// * `fds` - A list of file descriptors to be sent.
    pub fn send_vectored_with_fds(
        &self,
        bufs: &[impl AsIobuf],
        fds: &[RawFd],
    ) -> io::Result<usize> {
        raw_sendmsg(
            self.socket.as_raw_descriptor(),
            AsIobuf::as_iobuf_slice(bufs),
            fds,
        )
    }

    /// Receives data and file descriptors from the socket.
    ///
    /// On success, returns the number of bytes and file descriptors received as a tuple
    /// `(bytes count, descriptors)`.
    ///
    /// The error is constructed via `std::io::Error::last_os_error()`.
    ///
    /// # Arguments
    ///
    /// * `buf` - A buffer to store received data.
    /// * `max_descriptors` - Maximum number of file descriptors to receive.
    pub fn recv_with_fds(
        &self,
        buf: &mut [u8],
        max_descriptors: usize,
    ) -> io::Result<(usize, Vec<SafeDescriptor>)> {
        self.recv_vectored_with_fds(&mut [IoSliceMut::new(buf)], max_descriptors)
    }

    /// Receives data and file descriptors from the socket.
    ///
    /// On success, returns the number of bytes and file descriptors received as a tuple
    /// `(bytes count, files count)`.
    ///
    /// The error is constructed via `std::io::Error::last_os_error()`.
    ///
    /// # Arguments
    ///
    /// * `bufs` - A slice of buffers to store received data.
    /// * `max_descriptors` - Maximum number of file descriptors to receive.
    pub fn recv_vectored_with_fds(
        &self,
        bufs: &mut [IoSliceMut],
        max_descriptors: usize,
    ) -> io::Result<(usize, Vec<SafeDescriptor>)> {
        raw_recvmsg(
            self.socket.as_raw_descriptor(),
            IoSliceMut::as_iobuf_mut_slice(bufs),
            max_descriptors,
        )
    }

    /// Receives data and potentially a file descriptor from the socket.
    ///
    /// On success, returns the number of bytes and an optional file descriptor.
    ///
    /// The error is constructed via `std::io::Error::last_os_error()`.
    ///
    /// # Arguments
    ///
    /// * `buf` - A buffer to receive data from the socket.vm
    pub fn recv_with_file(&self, buf: &mut [u8]) -> io::Result<(usize, Option<File>)> {
        let (read_count, mut descriptors) = self.recv_with_fds(buf, 1)?;
        let file = if descriptors.len() == 1 {
            Some(File::from(descriptors.swap_remove(0)))
        } else {
            None
        };
        Ok((read_count, file))
    }

    /// Returns a reference to the wrapped instance.
    pub fn inner(&self) -> &T {
        &self.socket
    }

    /// Returns a mutable reference to the wrapped instance.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.socket
    }

    /// Returns the inner object, destroying the ScmSocket.
    pub fn into_inner(self) -> T {
        self.socket
    }
}

impl<T: AsRawDescriptor> AsRawDescriptor for ScmSocket<T> {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.socket.as_raw_descriptor()
    }
}

/// Trait for types that can be converted into an `iovec` that can be referenced by a syscall for
/// the lifetime of this object.
///
/// # Safety
/// This trait is unsafe because interfaces that use this trait depend on the base pointer and size
/// being accurate.
pub unsafe trait AsIobuf: Sized {
    /// Returns a `iovec` that describes a contiguous region of memory.
    fn as_iobuf(&self) -> iovec;

    /// Returns a slice of `iovec`s that each describe a contiguous region of memory.
    #[allow(clippy::wrong_self_convention)]
    fn as_iobuf_slice(bufs: &[Self]) -> &[iovec];

    /// Returns a mutable slice of `iovecs` that each describe a contiguous region of memory.
    fn as_iobuf_mut_slice(bufs: &mut [Self]) -> &mut [iovec];
}

// SAFETY:
// Safe because there are no other mutable references to the memory described by `IoSlice` and it is
// guaranteed to be ABI-compatible with `iovec`.
unsafe impl<'a> AsIobuf for IoSlice<'a> {
    fn as_iobuf(&self) -> iovec {
        iovec {
            iov_base: self.as_ptr() as *mut c_void,
            iov_len: self.len(),
        }
    }

    fn as_iobuf_slice(bufs: &[Self]) -> &[iovec] {
        // SAFETY:
        // Safe because `IoSlice` is guaranteed to be ABI-compatible with `iovec`.
        unsafe { slice::from_raw_parts(bufs.as_ptr() as *const iovec, bufs.len()) }
    }

    fn as_iobuf_mut_slice(bufs: &mut [Self]) -> &mut [iovec] {
        // SAFETY:
        // Safe because `IoSlice` is guaranteed to be ABI-compatible with `iovec`.
        unsafe { slice::from_raw_parts_mut(bufs.as_mut_ptr() as *mut iovec, bufs.len()) }
    }
}

// SAFETY:
// Safe because there are no other references to the memory described by `IoSliceMut` and it is
// guaranteed to be ABI-compatible with `iovec`.
unsafe impl<'a> AsIobuf for IoSliceMut<'a> {
    fn as_iobuf(&self) -> iovec {
        iovec {
            iov_base: self.as_ptr() as *mut c_void,
            iov_len: self.len(),
        }
    }

    fn as_iobuf_slice(bufs: &[Self]) -> &[iovec] {
        // SAFETY:
        // Safe because `IoSliceMut` is guaranteed to be ABI-compatible with `iovec`.
        unsafe { slice::from_raw_parts(bufs.as_ptr() as *const iovec, bufs.len()) }
    }

    fn as_iobuf_mut_slice(bufs: &mut [Self]) -> &mut [iovec] {
        // SAFETY:
        // Safe because `IoSliceMut` is guaranteed to be ABI-compatible with `iovec`.
        unsafe { slice::from_raw_parts_mut(bufs.as_mut_ptr() as *mut iovec, bufs.len()) }
    }
}

// SAFETY:
// Safe because volatile slices are only ever accessed with other volatile interfaces and the
// pointer and size are guaranteed to be accurate.
unsafe impl<'a> AsIobuf for VolatileSlice<'a> {
    fn as_iobuf(&self) -> iovec {
        *self.as_iobuf().as_ref()
    }

    fn as_iobuf_slice(bufs: &[Self]) -> &[iovec] {
        IoBufMut::as_iobufs(VolatileSlice::as_iobufs(bufs))
    }

    fn as_iobuf_mut_slice(bufs: &mut [Self]) -> &mut [iovec] {
        IoBufMut::as_iobufs_mut(VolatileSlice::as_iobufs_mut(bufs))
    }
}

#[cfg(test)]
#[cfg(any(target_os = "android", target_os = "linux"))] // TODO: eliminate Linux-specific EventExt usage
mod tests {
    use std::io::Write;
    use std::mem::size_of;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixDatagram;
    use std::slice::from_raw_parts;

    use super::*;
    use crate::AsRawDescriptor;
    use crate::Event;
    use crate::EventExt;

    // Doing this as a macro makes it easier to see the line if it fails
    macro_rules! CMSG_SPACE_TEST {
        ($len:literal) => {
            assert_eq!(
                CMSG_SPACE(size_of::<[RawFd; $len]>()) as libc::c_uint,
                // SAFETY: trivially safe
                unsafe { libc::CMSG_SPACE(size_of::<[RawFd; $len]>() as libc::c_uint) }
            );
        };
    }

    #[test]
    #[allow(clippy::erasing_op, clippy::identity_op)]
    fn buffer_len() {
        CMSG_SPACE_TEST!(0);
        CMSG_SPACE_TEST!(1);
        CMSG_SPACE_TEST!(2);
        CMSG_SPACE_TEST!(3);
        CMSG_SPACE_TEST!(4);
    }

    #[test]
    fn send_recv_no_fd() {
        let (u1, u2) = UnixDatagram::pair().expect("failed to create socket pair");
        let (s1, s2) = (
            ScmSocket::try_from(u1).unwrap(),
            ScmSocket::try_from(u2).unwrap(),
        );

        let send_buf = [1u8, 1, 2, 21, 34, 55];
        let write_count = s1
            .send_with_fds(&send_buf, &[])
            .expect("failed to send data");

        assert_eq!(write_count, 6);

        let mut buf = [0; 6];
        let (read_count, files) = s2.recv_with_fds(&mut buf, 1).expect("failed to recv data");

        assert_eq!(read_count, 6);
        assert_eq!(files.len(), 0);
        assert_eq!(buf, [1, 1, 2, 21, 34, 55]);

        let write_count = s1
            .send_with_fds(&send_buf, &[])
            .expect("failed to send data");

        assert_eq!(write_count, 6);
        let (read_count, files) = s2.recv_with_fds(&mut buf, 1).expect("failed to recv data");

        assert_eq!(read_count, 6);
        assert_eq!(files.len(), 0);
        assert_eq!(buf, [1, 1, 2, 21, 34, 55]);
    }

    #[test]
    fn send_recv_only_fd() {
        let (u1, u2) = UnixDatagram::pair().expect("failed to create socket pair");
        let (s1, s2) = (
            ScmSocket::try_from(u1).unwrap(),
            ScmSocket::try_from(u2).unwrap(),
        );

        let evt = Event::new().expect("failed to create event");
        let write_count = s1
            .send_with_fds(&[], &[evt.as_raw_descriptor()])
            .expect("failed to send fd");

        assert_eq!(write_count, 0);

        let mut buf = [];
        let (read_count, file_opt) = s2.recv_with_file(&mut buf).expect("failed to recv fd");

        let mut file = file_opt.unwrap();

        assert_eq!(read_count, 0);
        assert!(file.as_raw_fd() >= 0);
        assert_ne!(file.as_raw_fd(), s1.as_raw_descriptor());
        assert_ne!(file.as_raw_fd(), s2.as_raw_descriptor());
        assert_ne!(file.as_raw_fd(), evt.as_raw_descriptor());

        // SAFETY: trivially safe
        file.write_all(unsafe { from_raw_parts(&1203u64 as *const u64 as *const u8, 8) })
            .expect("failed to write to sent fd");

        assert_eq!(evt.read_count().expect("failed to read from event"), 1203);
    }

    #[test]
    fn send_recv_with_fd() {
        let (u1, u2) = UnixDatagram::pair().expect("failed to create socket pair");
        let (s1, s2) = (
            ScmSocket::try_from(u1).unwrap(),
            ScmSocket::try_from(u2).unwrap(),
        );

        let evt = Event::new().expect("failed to create event");
        let write_count = s1
            .send_with_fds(&[237], &[evt.as_raw_descriptor()])
            .expect("failed to send fd");

        assert_eq!(write_count, 1);

        let mut buf = [0u8];
        let (read_count, mut files) = s2.recv_with_fds(&mut buf, 2).expect("failed to recv fd");

        assert_eq!(read_count, 1);
        assert_eq!(buf[0], 237);
        assert_eq!(files.len(), 1);
        assert!(files[0].as_raw_descriptor() >= 0);
        assert_ne!(files[0].as_raw_descriptor(), s1.as_raw_descriptor());
        assert_ne!(files[0].as_raw_descriptor(), s2.as_raw_descriptor());
        assert_ne!(files[0].as_raw_descriptor(), evt.as_raw_descriptor());

        let mut file = File::from(files.swap_remove(0));

        // SAFETY: trivially safe
        file.write_all(unsafe { from_raw_parts(&1203u64 as *const u64 as *const u8, 8) })
            .expect("failed to write to sent fd");

        assert_eq!(evt.read_count().expect("failed to read from event"), 1203);
    }
}
