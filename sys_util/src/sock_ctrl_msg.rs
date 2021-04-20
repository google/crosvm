// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Used to send and receive messages with file descriptors on sockets that accept control messages
//! (e.g. Unix domain sockets).

use std::fs::File;
use std::io::{IoSlice, IoSliceMut};
use std::mem::size_of;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::ptr::{copy_nonoverlapping, null_mut, write_unaligned};
use std::slice;

use libc::{
    c_long, c_void, cmsghdr, iovec, msghdr, recvmsg, sendmsg, MSG_NOSIGNAL, SCM_RIGHTS, SOL_SOCKET,
};

use data_model::VolatileSlice;

use crate::net::UnixSeqpacket;
use crate::{Error, Result};

// Each of the following macros performs the same function as their C counterparts. They are each
// macros because they are used to size statically allocated arrays.

macro_rules! CMSG_ALIGN {
    ($len:expr) => {
        (($len) + size_of::<c_long>() - 1) & !(size_of::<c_long>() - 1)
    };
}

macro_rules! CMSG_SPACE {
    ($len:expr) => {
        size_of::<cmsghdr>() + CMSG_ALIGN!($len)
    };
}

macro_rules! CMSG_LEN {
    ($len:expr) => {
        size_of::<cmsghdr>() + ($len)
    };
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
#[allow(clippy::cast_ptr_alignment)]
fn get_next_cmsg(msghdr: &msghdr, cmsg: &cmsghdr, cmsg_ptr: *mut cmsghdr) -> *mut cmsghdr {
    let next_cmsg = (cmsg_ptr as *mut u8).wrapping_add(CMSG_ALIGN!(cmsg.cmsg_len)) as *mut cmsghdr;
    if next_cmsg
        .wrapping_offset(1)
        .wrapping_sub(msghdr.msg_control as usize) as usize
        > msghdr.msg_controllen
    {
        null_mut()
    } else {
        next_cmsg
    }
}

const CMSG_BUFFER_INLINE_CAPACITY: usize = CMSG_SPACE!(size_of::<RawFd>() * 32);

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
                    cmsghdr {
                        cmsg_len: 0,
                        cmsg_level: 0,
                        cmsg_type: 0,
                    };
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

fn raw_sendmsg<D: AsIobuf>(fd: RawFd, out_data: &[D], out_fds: &[RawFd]) -> Result<usize> {
    let cmsg_capacity = CMSG_SPACE!(size_of::<RawFd>() * out_fds.len());
    let mut cmsg_buffer = CmsgBuffer::with_capacity(cmsg_capacity);

    let iovec = AsIobuf::as_iobuf_slice(out_data);

    let mut msg = msghdr {
        msg_name: null_mut(),
        msg_namelen: 0,
        msg_iov: iovec.as_ptr() as *mut iovec,
        msg_iovlen: iovec.len(),
        msg_control: null_mut(),
        msg_controllen: 0,
        msg_flags: 0,
    };

    if !out_fds.is_empty() {
        let cmsg = cmsghdr {
            cmsg_len: CMSG_LEN!(size_of::<RawFd>() * out_fds.len()),
            cmsg_level: SOL_SOCKET,
            cmsg_type: SCM_RIGHTS,
        };
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
        msg.msg_controllen = cmsg_capacity;
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

fn raw_recvmsg(fd: RawFd, in_data: &mut [u8], in_fds: &mut [RawFd]) -> Result<(usize, usize)> {
    let iovec = iovec {
        iov_base: in_data.as_mut_ptr() as *mut c_void,
        iov_len: in_data.len(),
    };
    raw_recvmsg_iovecs(fd, &mut [iovec], in_fds)
}

fn raw_recvmsg_iovecs(
    fd: RawFd,
    iovecs: &mut [iovec],
    in_fds: &mut [RawFd],
) -> Result<(usize, usize)> {
    let cmsg_capacity = CMSG_SPACE!(size_of::<RawFd>() * in_fds.len());
    let mut cmsg_buffer = CmsgBuffer::with_capacity(cmsg_capacity);

    let mut msg = msghdr {
        msg_name: null_mut(),
        msg_namelen: 0,
        msg_iov: iovecs.as_mut_ptr() as *mut iovec,
        msg_iovlen: iovecs.len(),
        msg_control: null_mut(),
        msg_controllen: 0,
        msg_flags: 0,
    };

    if !in_fds.is_empty() {
        msg.msg_control = cmsg_buffer.as_mut_ptr() as *mut c_void;
        msg.msg_controllen = cmsg_capacity;
    }

    // Safe because the msghdr was properly constructed from valid (or null) pointers of the
    // indicated length and we check the return value.
    let total_read = unsafe { recvmsg(fd, &mut msg, 0) };

    if total_read == -1 {
        return Err(Error::last());
    }

    if total_read == 0 && msg.msg_controllen < size_of::<cmsghdr>() {
        return Ok((0, 0));
    }

    let mut cmsg_ptr = msg.msg_control as *mut cmsghdr;
    let mut in_fds_count = 0;
    while !cmsg_ptr.is_null() {
        // Safe because we checked that cmsg_ptr was non-null, and the loop is constructed such that
        // that only happens when there is at least sizeof(cmsghdr) space after the pointer to read.
        let cmsg = unsafe { (cmsg_ptr as *mut cmsghdr).read_unaligned() };

        if cmsg.cmsg_level == SOL_SOCKET && cmsg.cmsg_type == SCM_RIGHTS {
            let fd_count = (cmsg.cmsg_len - CMSG_LEN!(0)) / size_of::<RawFd>();
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
    fn send_bufs_with_fd(&self, bufs: &[&[u8]], fd: RawFd) -> Result<usize> {
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
    fn send_bufs_with_fds(&self, bufs: &[&[u8]], fd: &[RawFd]) -> Result<usize> {
        let slices: Vec<IoSlice> = bufs.iter().map(|&b| IoSlice::new(b)).collect();
        raw_sendmsg(self.socket_fd(), &slices, fd)
    }

    /// Receives data and potentially a file descriptor from the socket.
    ///
    /// On success, returns the number of bytes and an optional file descriptor.
    ///
    /// # Arguments
    ///
    /// * `buf` - A buffer to receive data from the socket.vm
    fn recv_with_fd(&self, buf: &mut [u8]) -> Result<(usize, Option<File>)> {
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
    fn recv_with_fds(&self, buf: &mut [u8], fds: &mut [RawFd]) -> Result<(usize, usize)> {
        raw_recvmsg(self.socket_fd(), buf, fds)
    }

    /// Receives data and file descriptors from the socket.
    ///
    /// On success, returns the number of bytes and file descriptors received as a tuple
    /// `(bytes count, files count)`.
    ///
    /// # Arguments
    ///
    /// * `ioves` - A slice of iovecs to store received data.
    /// * `fds` - A slice of `RawFd`s to put the received file descriptors into. On success, the
    ///           number of valid file descriptors is indicated by the second element of the
    ///           returned tuple. The caller owns these file descriptors, but they will not be
    ///           closed on drop like a `File`-like type would be. It is recommended that each valid
    ///           file descriptor gets wrapped in a drop type that closes it after this returns.
    fn recv_iovecs_with_fds(
        &self,
        iovecs: &mut [iovec],
        fds: &mut [RawFd],
    ) -> Result<(usize, usize)> {
        raw_recvmsg_iovecs(self.socket_fd(), iovecs, fds)
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
        self.as_raw_fd()
    }
}

/// Trait for types that can be converted into an `iovec` that can be referenced by a syscall for
/// the lifetime of this object.
///
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
        *self.as_iobuf()
    }

    fn as_iobuf_slice(bufs: &[Self]) -> &[iovec] {
        VolatileSlice::as_iobufs(bufs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Write;
    use std::mem::size_of;
    use std::os::raw::c_long;
    use std::os::unix::net::UnixDatagram;
    use std::slice::from_raw_parts;

    use libc::cmsghdr;

    use crate::EventFd;

    #[test]
    #[allow(clippy::erasing_op, clippy::identity_op)]
    fn buffer_len() {
        assert_eq!(CMSG_SPACE!(0 * size_of::<RawFd>()), size_of::<cmsghdr>());
        assert_eq!(
            CMSG_SPACE!(1 * size_of::<RawFd>()),
            size_of::<cmsghdr>() + size_of::<c_long>()
        );
        if size_of::<RawFd>() == 4 {
            assert_eq!(
                CMSG_SPACE!(2 * size_of::<RawFd>()),
                size_of::<cmsghdr>() + size_of::<c_long>()
            );
            assert_eq!(
                CMSG_SPACE!(3 * size_of::<RawFd>()),
                size_of::<cmsghdr>() + size_of::<c_long>() * 2
            );
            assert_eq!(
                CMSG_SPACE!(4 * size_of::<RawFd>()),
                size_of::<cmsghdr>() + size_of::<c_long>() * 2
            );
        } else if size_of::<RawFd>() == 8 {
            assert_eq!(
                CMSG_SPACE!(2 * size_of::<RawFd>()),
                size_of::<cmsghdr>() + size_of::<c_long>() * 2
            );
            assert_eq!(
                CMSG_SPACE!(3 * size_of::<RawFd>()),
                size_of::<cmsghdr>() + size_of::<c_long>() * 3
            );
            assert_eq!(
                CMSG_SPACE!(4 * size_of::<RawFd>()),
                size_of::<cmsghdr>() + size_of::<c_long>() * 4
            );
        }
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
            .recv_with_fds(&mut buf[..], &mut files)
            .expect("failed to recv data");

        assert_eq!(read_count, 6);
        assert_eq!(file_count, 0);
        assert_eq!(buf, [1, 1, 2, 21, 34, 55]);

        let write_count = s1
            .send_bufs_with_fds(&[&send_buf[..]], &[])
            .expect("failed to send data");

        assert_eq!(write_count, 6);
        let (read_count, file_count) = s2
            .recv_with_fds(&mut buf[..], &mut files)
            .expect("failed to recv data");

        assert_eq!(read_count, 6);
        assert_eq!(file_count, 0);
        assert_eq!(buf, [1, 1, 2, 21, 34, 55]);
    }

    #[test]
    fn send_recv_only_fd() {
        let (s1, s2) = UnixDatagram::pair().expect("failed to create socket pair");

        let evt = EventFd::new().expect("failed to create eventfd");
        let ioslice = IoSlice::new([].as_ref());
        let write_count = s1
            .send_with_fd(&[ioslice], evt.as_raw_fd())
            .expect("failed to send fd");

        assert_eq!(write_count, 0);

        let (read_count, file_opt) = s2.recv_with_fd(&mut []).expect("failed to recv fd");

        let mut file = file_opt.unwrap();

        assert_eq!(read_count, 0);
        assert!(file.as_raw_fd() >= 0);
        assert_ne!(file.as_raw_fd(), s1.as_raw_fd());
        assert_ne!(file.as_raw_fd(), s2.as_raw_fd());
        assert_ne!(file.as_raw_fd(), evt.as_raw_fd());

        file.write_all(unsafe { from_raw_parts(&1203u64 as *const u64 as *const u8, 8) })
            .expect("failed to write to sent fd");

        assert_eq!(evt.read().expect("failed to read from eventfd"), 1203);
    }

    #[test]
    fn send_recv_with_fd() {
        let (s1, s2) = UnixDatagram::pair().expect("failed to create socket pair");

        let evt = EventFd::new().expect("failed to create eventfd");
        let ioslice = IoSlice::new([237].as_ref());
        let write_count = s1
            .send_with_fds(&[ioslice], &[evt.as_raw_fd()])
            .expect("failed to send fd");

        assert_eq!(write_count, 1);

        let mut files = [0; 2];
        let mut buf = [0u8];
        let (read_count, file_count) = s2
            .recv_with_fds(&mut buf, &mut files)
            .expect("failed to recv fd");

        assert_eq!(read_count, 1);
        assert_eq!(buf[0], 237);
        assert_eq!(file_count, 1);
        assert!(files[0] >= 0);
        assert_ne!(files[0], s1.as_raw_fd());
        assert_ne!(files[0], s2.as_raw_fd());
        assert_ne!(files[0], evt.as_raw_fd());

        let mut file = unsafe { File::from_raw_fd(files[0]) };

        file.write_all(unsafe { from_raw_parts(&1203u64 as *const u64 as *const u8, 8) })
            .expect("failed to write to sent fd");

        assert_eq!(evt.read().expect("failed to read from eventfd"), 1203);
    }
}
