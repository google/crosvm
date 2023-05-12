// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Used to send and receive messages with file descriptors on sockets that accept control messages
//! (e.g. Unix domain sockets).

use std::fs::File;
use std::io::IoSlice;
use std::io::IoSliceMut;
use std::mem::size_of;
use std::mem::MaybeUninit;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::FromRawFd;
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixDatagram;
use std::os::unix::net::UnixStream;
use std::ptr::copy_nonoverlapping;
use std::ptr::null_mut;
use std::ptr::write_unaligned;
use std::slice;

use data_model::IoBufMut;
use data_model::VolatileSlice;
use libc::c_long;
use libc::c_void;
use libc::cmsghdr;
use libc::iovec;
use libc::msghdr;
use libc::recvmsg;
use libc::sendmsg;
use libc::MSG_NOSIGNAL;
use libc::SCM_RIGHTS;
use libc::SOL_SOCKET;

use super::net::UnixSeqpacket;
use super::Error;
use super::Result;
use super::StreamChannel;
use crate::AsRawDescriptor;

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
fn raw_sendmsg<D: AsIobuf>(fd: RawFd, out_data: &[D], out_fds: &[RawFd]) -> Result<usize> {
    let cmsg_capacity = CMSG_SPACE(size_of::<RawFd>() * out_fds.len());
    let mut cmsg_buffer = CmsgBuffer::with_capacity(cmsg_capacity);

    let iovec = AsIobuf::as_iobuf_slice(out_data);

    // msghdr on musl has private __pad1 and __pad2 fields that cannot be initialized.
    // Safe because msghdr only contains primitive types for which zero
    // initialization is valid.
    let mut msg: msghdr = unsafe { MaybeUninit::zeroed().assume_init() };
    msg.msg_iov = iovec.as_ptr() as *mut iovec;
    msg.msg_iovlen = iovec.len().try_into().unwrap();

    if !out_fds.is_empty() {
        // msghdr on musl has an extra __pad1 field, initialize the whole struct to zero.
        // Safe because cmsghdr only contains primitive types for which zero
        // initialization is valid.
        let mut cmsg: cmsghdr = unsafe { MaybeUninit::zeroed().assume_init() };
        cmsg.cmsg_len = CMSG_LEN(size_of::<RawFd>() * out_fds.len())
            .try_into()
            .unwrap();
        cmsg.cmsg_level = SOL_SOCKET;
        cmsg.cmsg_type = SCM_RIGHTS;
        unsafe {
            // Safe because cmsg_buffer was allocated to be large enough to contain cmsghdr.
            write_unaligned(cmsg_buffer.as_mut_ptr() as *mut cmsghdr, cmsg);
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

    // Safe because the msghdr was properly constructed from valid (or null) pointers of the
    // indicated length and we check the return value.
    let write_count = unsafe { sendmsg(fd, &msg, MSG_NOSIGNAL) };

    if write_count == -1 {
        Err(Error::last())
    } else {
        Ok(write_count as usize)
    }
}

// Musl requires a try_into when assigning to msg_iovlen, msg_controllen and
// cmsg_len that is unnecessary when compiling for glibc.
#[allow(clippy::useless_conversion, clippy::unnecessary_cast)]
fn raw_recvmsg(fd: RawFd, iovs: &mut [IoSliceMut], in_fds: &mut [RawFd]) -> Result<(usize, usize)> {
    let cmsg_capacity = CMSG_SPACE(size_of::<RawFd>() * in_fds.len());
    let mut cmsg_buffer = CmsgBuffer::with_capacity(cmsg_capacity);

    // msghdr on musl has private __pad1 and __pad2 fields that cannot be initialized.
    // Safe because msghdr only contains primitive types for which zero
    // initialization is valid.
    let mut msg: msghdr = unsafe { MaybeUninit::zeroed().assume_init() };
    msg.msg_iov = iovs.as_mut_ptr() as *mut iovec;
    msg.msg_iovlen = iovs.len().try_into().unwrap();

    if !in_fds.is_empty() {
        msg.msg_control = cmsg_buffer.as_mut_ptr() as *mut c_void;
        msg.msg_controllen = cmsg_capacity.try_into().unwrap();
    }

    // Safe because the msghdr was properly constructed from valid (or null) pointers of the
    // indicated length and we check the return value.
    let total_read = unsafe { recvmsg(fd, &mut msg, 0) };

    if total_read == -1 {
        return Err(Error::last());
    }

    if total_read == 0 && (msg.msg_controllen as usize) < size_of::<cmsghdr>() {
        return Ok((0, 0));
    }

    let mut cmsg_ptr = msg.msg_control as *mut cmsghdr;
    let mut in_fds_count = 0;
    while !cmsg_ptr.is_null() {
        // Safe because we checked that cmsg_ptr was non-null, and the loop is constructed such that
        // that only happens when there is at least sizeof(cmsghdr) space after the pointer to read.
        let cmsg = unsafe { (cmsg_ptr as *mut cmsghdr).read_unaligned() };

        if cmsg.cmsg_level == SOL_SOCKET && cmsg.cmsg_type == SCM_RIGHTS {
            let fd_count = (cmsg.cmsg_len as usize - CMSG_LEN(0)) / size_of::<RawFd>();
            unsafe {
                copy_nonoverlapping(
                    CMSG_DATA(cmsg_ptr),
                    in_fds[in_fds_count..(in_fds_count + fd_count)].as_mut_ptr(),
                    fd_count,
                );
            }
            in_fds_count += fd_count;
        }

        cmsg_ptr = get_next_cmsg(&msg, &cmsg, cmsg_ptr);
    }

    Ok((total_read as usize, in_fds_count))
}

/// The maximum number of FDs that can be sent in a single send.
pub const SCM_SOCKET_MAX_FD_COUNT: usize = 253;

/// Trait for file descriptors can send and receive socket control messages via `sendmsg` and
/// `recvmsg`.
pub trait ScmSocket {
    /// Gets the file descriptor of this socket.
    fn socket_fd(&self) -> RawFd;

    /// Sends the given data and file descriptor over the socket.
    ///
    /// On success, returns the number of bytes sent.
    ///
    /// # Arguments
    ///
    /// * `buf` - A buffer of data to send on the `socket`.
    /// * `fd` - A file descriptors to be sent.
    fn send_with_fd<D: AsIobuf>(&self, buf: &[D], fd: RawFd) -> Result<usize> {
        self.send_with_fds(buf, &[fd])
    }

    /// Sends the given data and file descriptors over the socket.
    ///
    /// On success, returns the number of bytes sent.
    ///
    /// # Arguments
    ///
    /// * `buf` - A buffer of data to send on the `socket`.
    /// * `fds` - A list of file descriptors to be sent.
    fn send_with_fds<D: AsIobuf>(&self, buf: &[D], fd: &[RawFd]) -> Result<usize> {
        raw_sendmsg(self.socket_fd(), buf, fd)
    }

    /// Sends the given data and file descriptor over the socket.
    ///
    /// On success, returns the number of bytes sent.
    ///
    /// # Arguments
    ///
    /// * `bufs` - A slice of slices of data to send on the `socket`.
    /// * `fd` - A file descriptors to be sent.
    fn send_bufs_with_fd(&self, bufs: &[IoSlice], fd: RawFd) -> Result<usize> {
        self.send_bufs_with_fds(bufs, &[fd])
    }

    /// Sends the given data and file descriptors over the socket.
    ///
    /// On success, returns the number of bytes sent.
    ///
    /// # Arguments
    ///
    /// * `bufs` - A slice of slices of data to send on the `socket`.
    /// * `fds` - A list of file descriptors to be sent.
    fn send_bufs_with_fds(&self, bufs: &[IoSlice], fd: &[RawFd]) -> Result<usize> {
        raw_sendmsg(self.socket_fd(), bufs, fd)
    }

    /// Receives data and potentially a file descriptor from the socket.
    ///
    /// On success, returns the number of bytes and an optional file descriptor.
    ///
    /// # Arguments
    ///
    /// * `buf` - A buffer to receive data from the socket.vm
    fn recv_with_fd(&self, buf: IoSliceMut) -> Result<(usize, Option<File>)> {
        let mut fd = [0];
        let (read_count, fd_count) = self.recv_with_fds(buf, &mut fd)?;
        let file = if fd_count == 0 {
            None
        } else {
            // Safe because the first fd from recv_with_fds is owned by us and valid because this
            // branch was taken.
            Some(unsafe { File::from_raw_fd(fd[0]) })
        };
        Ok((read_count, file))
    }

    /// Receives data and file descriptors from the socket.
    ///
    /// On success, returns the number of bytes and file descriptors received as a tuple
    /// `(bytes count, files count)`.
    ///
    /// # Arguments
    ///
    /// * `buf` - A buffer to receive data from the socket.
    /// * `fds` - A slice of `RawFd`s to put the received file descriptors into. On success, the
    ///           number of valid file descriptors is indicated by the second element of the
    ///           returned tuple. The caller owns these file descriptors, but they will not be
    ///           closed on drop like a `File`-like type would be. It is recommended that each valid
    ///           file descriptor gets wrapped in a drop type that closes it after this returns.
    fn recv_with_fds(&self, buf: IoSliceMut, fds: &mut [RawFd]) -> Result<(usize, usize)> {
        raw_recvmsg(self.socket_fd(), &mut [buf], fds)
    }

    /// Receives data and file descriptors from the socket.
    ///
    /// On success, returns the number of bytes and file descriptors received as a tuple
    /// `(bytes count, files count)`.
    ///
    /// # Arguments
    ///
    /// * `iovecs` - A slice of buffers to store received data.
    /// * `offset` - An offset for `bufs`. The first `offset` bytes in `bufs` won't be touched.
    ///              Returns an error if `offset` is larger than or equal to the total size of
    ///              `bufs`.
    /// * `fds` - A slice of `RawFd`s to put the received file descriptors into. On success, the
    ///           number of valid file descriptors is indicated by the second element of the
    ///           returned tuple. The caller owns these file descriptors, but they will not be
    ///           closed on drop like a `File`-like type would be. It is recommended that each valid
    ///           file descriptor gets wrapped in a drop type that closes it after this returns.
    fn recv_iovecs_with_fds(
        &self,
        iovecs: &mut [IoSliceMut],
        fds: &mut [RawFd],
    ) -> Result<(usize, usize)> {
        raw_recvmsg(self.socket_fd(), iovecs, fds)
    }
}

impl ScmSocket for UnixDatagram {
    fn socket_fd(&self) -> RawFd {
        self.as_raw_fd()
    }
}

impl ScmSocket for UnixStream {
    fn socket_fd(&self) -> RawFd {
        self.as_raw_fd()
    }
}

impl ScmSocket for UnixSeqpacket {
    fn socket_fd(&self) -> RawFd {
        self.as_raw_descriptor()
    }
}

impl ScmSocket for StreamChannel {
    fn socket_fd(&self) -> RawFd {
        self.as_raw_fd()
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
}

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
        // Safe because `IoSlice` is guaranteed to be ABI-compatible with `iovec`.
        unsafe { slice::from_raw_parts(bufs.as_ptr() as *const iovec, bufs.len()) }
    }
}

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
        // Safe because `IoSliceMut` is guaranteed to be ABI-compatible with `iovec`.
        unsafe { slice::from_raw_parts(bufs.as_ptr() as *const iovec, bufs.len()) }
    }
}

// Safe because volatile slices are only ever accessed with other volatile interfaces and the
// pointer and size are guaranteed to be accurate.
unsafe impl<'a> AsIobuf for VolatileSlice<'a> {
    fn as_iobuf(&self) -> iovec {
        *self.as_iobuf().as_ref()
    }

    fn as_iobuf_slice(bufs: &[Self]) -> &[iovec] {
        IoBufMut::as_iobufs(VolatileSlice::as_iobufs(bufs))
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::mem::size_of;
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
        let (s1, s2) = UnixDatagram::pair().expect("failed to create socket pair");

        let send_buf = [1u8, 1, 2, 21, 34, 55];
        let ioslice = IoSlice::new(&send_buf);
        let write_count = s1
            .send_with_fds(&[ioslice], &[])
            .expect("failed to send data");

        assert_eq!(write_count, 6);

        let mut buf = [0; 6];
        let mut files = [0; 1];
        let (read_count, file_count) = s2
            .recv_with_fds(IoSliceMut::new(&mut buf), &mut files)
            .expect("failed to recv data");

        assert_eq!(read_count, 6);
        assert_eq!(file_count, 0);
        assert_eq!(buf, [1, 1, 2, 21, 34, 55]);

        let write_count = s1
            .send_bufs_with_fds(&[IoSlice::new(&send_buf[..])], &[])
            .expect("failed to send data");

        assert_eq!(write_count, 6);
        let (read_count, file_count) = s2
            .recv_with_fds(IoSliceMut::new(&mut buf), &mut files)
            .expect("failed to recv data");

        assert_eq!(read_count, 6);
        assert_eq!(file_count, 0);
        assert_eq!(buf, [1, 1, 2, 21, 34, 55]);
    }

    #[test]
    fn send_recv_only_fd() {
        let (s1, s2) = UnixDatagram::pair().expect("failed to create socket pair");

        let evt = Event::new().expect("failed to create event");
        let ioslice = IoSlice::new([].as_ref());
        let write_count = s1
            .send_with_fd(&[ioslice], evt.as_raw_descriptor())
            .expect("failed to send fd");

        assert_eq!(write_count, 0);

        let mut buf = [];
        let (read_count, file_opt) = s2
            .recv_with_fd(IoSliceMut::new(&mut buf))
            .expect("failed to recv fd");

        let mut file = file_opt.unwrap();

        assert_eq!(read_count, 0);
        assert!(file.as_raw_fd() >= 0);
        assert_ne!(file.as_raw_fd(), s1.as_raw_fd());
        assert_ne!(file.as_raw_fd(), s2.as_raw_fd());
        assert_ne!(file.as_raw_fd(), evt.as_raw_descriptor());

        file.write_all(unsafe { from_raw_parts(&1203u64 as *const u64 as *const u8, 8) })
            .expect("failed to write to sent fd");

        assert_eq!(evt.read_count().expect("failed to read from event"), 1203);
    }

    #[test]
    fn send_recv_with_fd() {
        let (s1, s2) = UnixDatagram::pair().expect("failed to create socket pair");

        let evt = Event::new().expect("failed to create event");
        let ioslice = IoSlice::new([237].as_ref());
        let write_count = s1
            .send_with_fds(&[ioslice], &[evt.as_raw_descriptor()])
            .expect("failed to send fd");

        assert_eq!(write_count, 1);

        let mut files = [0; 2];
        let mut buf = [0u8];
        let (read_count, file_count) = s2
            .recv_with_fds(IoSliceMut::new(&mut buf), &mut files)
            .expect("failed to recv fd");

        assert_eq!(read_count, 1);
        assert_eq!(buf[0], 237);
        assert_eq!(file_count, 1);
        assert!(files[0] >= 0);
        assert_ne!(files[0], s1.as_raw_fd());
        assert_ne!(files[0], s2.as_raw_fd());
        assert_ne!(files[0], evt.as_raw_descriptor());

        let mut file = unsafe { File::from_raw_fd(files[0]) };

        file.write_all(unsafe { from_raw_parts(&1203u64 as *const u64 as *const u8, 8) })
            .expect("failed to write to sent fd");

        assert_eq!(evt.read_count().expect("failed to read from event"), 1203);
    }
}
