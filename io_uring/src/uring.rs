// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file makes several casts from u8 pointers into more-aligned pointer types.
// We assume that the kernel will give us suitably aligned memory.
#![allow(clippy::cast_ptr_alignment)]

use std::collections::BTreeMap;
use std::fs::File;
use std::io;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::FromRawFd;
use std::os::unix::io::RawFd;
use std::pin::Pin;
use std::ptr::null;
use std::sync::atomic::AtomicPtr;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;

use base::AsRawDescriptor;
use base::EventType;
use base::MappedRegion;
use base::MemoryMapping;
use base::MemoryMappingBuilder;
use base::Protection;
use base::RawDescriptor;
use data_model::IoBufMut;
use libc::c_void;
use remain::sorted;
use sync::Mutex;
use thiserror::Error as ThisError;

use crate::bindings::*;
use crate::syscalls::*;

/// Holds per-operation, user specified data. The usage is up to the caller. The most common use is
/// for callers to identify each request.
pub type UserData = u64;

#[sorted]
#[derive(Debug, ThisError)]
pub enum Error {
    /// Failed to map the completion ring.
    #[error("Failed to mmap completion ring {0}")]
    MappingCompleteRing(base::MmapError),
    /// Failed to map submit entries.
    #[error("Failed to mmap submit entries {0}")]
    MappingSubmitEntries(base::MmapError),
    /// Failed to map the submit ring.
    #[error("Failed to mmap submit ring {0}")]
    MappingSubmitRing(base::MmapError),
    /// Too many ops are already queued.
    #[error("No space for more ring entries, try increasing the size passed to `new`")]
    NoSpace,
    /// The call to `io_uring_enter` failed with the given errno.
    #[error("Failed to enter io uring: {0}")]
    RingEnter(libc::c_int),
    /// The call to `io_uring_register` failed with the given errno.
    #[error("Failed to register operations for io uring: {0}")]
    RingRegister(libc::c_int),
    /// The call to `io_uring_setup` failed with the given errno.
    #[error("Failed to setup io uring {0}")]
    Setup(libc::c_int),
}
pub type Result<T> = std::result::Result<T, Error>;

impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        use Error::*;
        match e {
            RingEnter(errno) => io::Error::from_raw_os_error(errno),
            Setup(errno) => io::Error::from_raw_os_error(errno),
            e => io::Error::new(io::ErrorKind::Other, e),
        }
    }
}

pub struct SubmitQueue {
    submit_ring: SubmitQueueState,
    submit_queue_entries: SubmitQueueEntries,
    io_vecs: Pin<Box<[IoBufMut<'static>]>>,
    submitting: usize, // The number of ops in the process of being submitted.
    pub added: usize,  // The number of ops added since the last call to `io_uring_enter`.
    num_sqes: usize,   // The total number of sqes allocated in shared memory.
}

// Helper functions to set io_uring_sqe bindgen union members in a less verbose manner.
impl io_uring_sqe {
    pub fn set_addr(&mut self, val: u64) {
        self.__bindgen_anon_2.addr = val;
    }
    pub fn set_off(&mut self, val: u64) {
        self.__bindgen_anon_1.off = val;
    }

    pub fn set_buf_index(&mut self, val: u16) {
        self.__bindgen_anon_4.buf_index = val;
    }

    pub fn set_rw_flags(&mut self, val: libc::c_int) {
        self.__bindgen_anon_3.rw_flags = val;
    }

    pub fn set_poll_events(&mut self, val: u32) {
        let val = if cfg!(target_endian = "big") {
            // Swap words on big-endian platforms to match the original ABI where poll_events was 16
            // bits wide.
            val.rotate_left(16)
        } else {
            val
        };
        self.__bindgen_anon_3.poll32_events = val;
    }
}

// Convert a file offset to the raw io_uring offset format.
// Some => explicit offset
// None => use current file position
fn file_offset_to_raw_offset(offset: Option<u64>) -> u64 {
    // File offsets are interpretted as off64_t inside io_uring, with -1 representing the current
    // file position.
    const USE_CURRENT_FILE_POS: libc::off64_t = -1;
    offset.unwrap_or(USE_CURRENT_FILE_POS as u64)
}

impl SubmitQueue {
    // Call `f` with the next available sqe or return an error if none are available.
    // After `f` returns, the sqe is appended to the kernel's queue.
    fn prep_next_sqe<F>(&mut self, mut f: F) -> Result<()>
    where
        F: FnMut(&mut io_uring_sqe, &mut libc::iovec),
    {
        if self.added == self.num_sqes {
            return Err(Error::NoSpace);
        }

        // Find the next free submission entry in the submit ring and fill it with an iovec.
        // The below raw pointer derefs are safe because the memory the pointers use lives as long
        // as the mmap in self.
        let tail = self.submit_ring.pointers.tail(Ordering::Relaxed);
        let next_tail = tail.wrapping_add(1);
        if next_tail == self.submit_ring.pointers.head(Ordering::Acquire) {
            return Err(Error::NoSpace);
        }
        // `tail` is the next sqe to use.
        let index = (tail & self.submit_ring.ring_mask) as usize;
        let sqe = self.submit_queue_entries.get_mut(index).unwrap();

        f(sqe, self.io_vecs[index].as_mut());

        // Tells the kernel to use the new index when processing the entry at that index.
        self.submit_ring.set_array_entry(index, index as u32);
        // Ensure the above writes to sqe are seen before the tail is updated.
        // set_tail uses Release ordering when storing to the ring.
        self.submit_ring.pointers.set_tail(next_tail);

        self.added += 1;

        Ok(())
    }

    // Returns the number of entries that have been added to this SubmitQueue since the last time
    // `prepare_submit` was called.
    fn prepare_submit(&mut self) -> usize {
        let out = self.added - self.submitting;
        self.submitting = self.added;

        out
    }

    // Indicates that we failed to submit `count` entries to the kernel and that they should be
    // retried.
    fn fail_submit(&mut self, count: usize) {
        debug_assert!(count <= self.submitting);
        self.submitting -= count;
    }

    // Indicates that `count` entries have been submitted to the kernel and so the space may be
    // reused for new entries.
    fn complete_submit(&mut self, count: usize) {
        debug_assert!(count <= self.submitting);
        self.submitting -= count;
        self.added -= count;
    }

    unsafe fn add_rw_op(
        &mut self,
        ptr: *const u8,
        len: usize,
        fd: RawFd,
        offset: Option<u64>,
        user_data: UserData,
        op: u8,
    ) -> Result<()> {
        self.prep_next_sqe(|sqe, iovec| {
            iovec.iov_base = ptr as *const libc::c_void as *mut _;
            iovec.iov_len = len;
            sqe.opcode = op;
            sqe.set_addr(iovec as *const _ as *const libc::c_void as u64);
            sqe.len = 1;
            sqe.set_off(file_offset_to_raw_offset(offset));
            sqe.set_buf_index(0);
            sqe.ioprio = 0;
            sqe.user_data = user_data;
            sqe.flags = 0;
            sqe.fd = fd;
        })?;

        Ok(())
    }
}

/// Enum to represent all io_uring operations
#[repr(u32)]
pub enum URingOperation {
    Nop = io_uring_op_IORING_OP_NOP,
    Readv = io_uring_op_IORING_OP_READV,
    Writev = io_uring_op_IORING_OP_WRITEV,
    Fsync = io_uring_op_IORING_OP_FSYNC,
    ReadFixed = io_uring_op_IORING_OP_READ_FIXED,
    WriteFixed = io_uring_op_IORING_OP_WRITE_FIXED,
    PollAdd = io_uring_op_IORING_OP_POLL_ADD,
    PollRemove = io_uring_op_IORING_OP_POLL_REMOVE,
    SyncFileRange = io_uring_op_IORING_OP_SYNC_FILE_RANGE,
    Sendmsg = io_uring_op_IORING_OP_SENDMSG,
    Recvmsg = io_uring_op_IORING_OP_RECVMSG,
    Timeout = io_uring_op_IORING_OP_TIMEOUT,
    TimeoutRemove = io_uring_op_IORING_OP_TIMEOUT_REMOVE,
    Accept = io_uring_op_IORING_OP_ACCEPT,
    AsyncCancel = io_uring_op_IORING_OP_ASYNC_CANCEL,
    LinkTimeout = io_uring_op_IORING_OP_LINK_TIMEOUT,
    Connect = io_uring_op_IORING_OP_CONNECT,
    Fallocate = io_uring_op_IORING_OP_FALLOCATE,
    Openat = io_uring_op_IORING_OP_OPENAT,
    Close = io_uring_op_IORING_OP_CLOSE,
    FilesUpdate = io_uring_op_IORING_OP_FILES_UPDATE,
    Statx = io_uring_op_IORING_OP_STATX,
    Read = io_uring_op_IORING_OP_READ,
    Write = io_uring_op_IORING_OP_WRITE,
    Fadvise = io_uring_op_IORING_OP_FADVISE,
    Madvise = io_uring_op_IORING_OP_MADVISE,
    Send = io_uring_op_IORING_OP_SEND,
    Recv = io_uring_op_IORING_OP_RECV,
    Openat2 = io_uring_op_IORING_OP_OPENAT2,
    EpollCtl = io_uring_op_IORING_OP_EPOLL_CTL,
    Splice = io_uring_op_IORING_OP_SPLICE,
    ProvideBuffers = io_uring_op_IORING_OP_PROVIDE_BUFFERS,
    RemoveBuffers = io_uring_op_IORING_OP_REMOVE_BUFFERS,
    Tee = io_uring_op_IORING_OP_TEE,
    Shutdown = io_uring_op_IORING_OP_SHUTDOWN,
    Renameat = io_uring_op_IORING_OP_RENAMEAT,
    Unlinkat = io_uring_op_IORING_OP_UNLINKAT,
    Mkdirat = io_uring_op_IORING_OP_MKDIRAT,
    Symlinkat = io_uring_op_IORING_OP_SYMLINKAT,
    Linkat = io_uring_op_IORING_OP_LINKAT,
}

/// Represents an allowlist of the restrictions to be registered to a uring.
#[derive(Default)]
pub struct URingAllowlist(Vec<io_uring_restriction>);

impl URingAllowlist {
    /// Create a new `UringAllowList` which allows no operation.
    pub fn new() -> Self {
        URingAllowlist::default()
    }

    /// Allow `operation` to be submitted to the submit queue of the io_uring.
    pub fn allow_submit_operation(&mut self, operation: URingOperation) -> &mut Self {
        self.0.push(io_uring_restriction {
            opcode: IORING_RESTRICTION_SQE_OP as u16,
            __bindgen_anon_1: io_uring_restriction__bindgen_ty_1 {
                sqe_op: operation as u8,
            },
            ..Default::default()
        });
        self
    }
}

/// Unsafe wrapper for the kernel's io_uring interface. Allows for queueing multiple I/O operations
/// to the kernel and asynchronously handling the completion of these operations.
/// Use the various `add_*` functions to configure operations, then call `wait` to start
/// the operations and get any completed results. Each op is given a u64 user_data argument that is
/// used to identify the result when returned in the iterator provided by `wait`.
///
/// # Example polling an FD for readable status.
///
/// ```no_run
/// # use std::fs::File;
/// # use std::os::unix::io::AsRawFd;
/// # use std::path::Path;
/// # use base::EventType;
/// # use io_uring::URingContext;
/// let f = File::open(Path::new("/dev/zero")).unwrap();
/// let uring = URingContext::new(16, None).unwrap();
/// uring
///   .add_poll_fd(f.as_raw_fd(), EventType::Read, 454)
/// .unwrap();
/// let (user_data, res) = uring.wait().unwrap().next().unwrap();
/// assert_eq!(user_data, 454 as io_uring::UserData);
/// assert_eq!(res.unwrap(), 1 as u32);
///
/// ```
pub struct URingContext {
    ring_file: File, // Holds the io_uring context FD returned from io_uring_setup.
    pub submit_ring: Mutex<SubmitQueue>,
    pub complete_ring: CompleteQueueState,
}

impl URingContext {
    /// Creates a `URingContext` where the underlying uring has a space for `num_entries`
    /// simultaneous operations. If `allowlist` is given, all operations other
    /// than those explicitly permitted by `allowlist` are prohibited.
    pub fn new(num_entries: usize, allowlist: Option<&URingAllowlist>) -> Result<URingContext> {
        let mut ring_params = io_uring_params::default();
        if allowlist.is_some() {
            // To register restrictions, a uring must start in a disabled state.
            ring_params.flags |= IORING_SETUP_R_DISABLED;
        }

        // The below unsafe block isolates the creation of the URingContext. Each step on it's own
        // is unsafe. Using the uring FD for the mapping and the offsets returned by the kernel for
        // base addresses maintains safety guarantees assuming the kernel API guarantees are
        // trusted.
        unsafe {
            // Safe because the kernel is trusted to only modify params and `File` is created with
            // an FD that it takes complete ownership of.
            let fd = io_uring_setup(num_entries, &ring_params).map_err(Error::Setup)?;
            let ring_file = File::from_raw_fd(fd);

            // Register the restrictions if it's given
            if let Some(restrictions) = allowlist {
                // safe because IORING_REGISTER_RESTRICTIONS does not modify the memory and `restrictions`
                // contains a valid pointer and length.
                io_uring_register(
                    fd,
                    IORING_REGISTER_RESTRICTIONS,
                    restrictions.0.as_ptr() as *const c_void,
                    restrictions.0.len() as u32,
                )
                .map_err(Error::RingRegister)?;

                // enables the URingContext since it was started in a disabled state.
                // safe because IORING_REGISTER_RESTRICTIONS does not modify the memory
                io_uring_register(fd, IORING_REGISTER_ENABLE_RINGS, null::<c_void>(), 0)
                    .map_err(Error::RingRegister)?;
            }

            // Mmap the submit and completion queues.
            // Safe because we trust the kernel to set valid sizes in `io_uring_setup` and any error
            // is checked.
            let submit_ring = SubmitQueueState::new(
                MemoryMappingBuilder::new(
                    ring_params.sq_off.array as usize
                        + ring_params.sq_entries as usize * std::mem::size_of::<u32>(),
                )
                .from_file(&ring_file)
                .offset(u64::from(IORING_OFF_SQ_RING))
                .protection(Protection::read_write())
                .populate()
                .build()
                .map_err(Error::MappingSubmitRing)?,
                &ring_params,
            );

            let num_sqe = ring_params.sq_entries as usize;
            let submit_queue_entries = SubmitQueueEntries {
                mmap: MemoryMappingBuilder::new(
                    ring_params.sq_entries as usize * std::mem::size_of::<io_uring_sqe>(),
                )
                .from_file(&ring_file)
                .offset(u64::from(IORING_OFF_SQES))
                .protection(Protection::read_write())
                .populate()
                .build()
                .map_err(Error::MappingSubmitEntries)?,
                len: num_sqe,
            };

            let complete_ring = CompleteQueueState::new(
                MemoryMappingBuilder::new(
                    ring_params.cq_off.cqes as usize
                        + ring_params.cq_entries as usize * std::mem::size_of::<io_uring_cqe>(),
                )
                .from_file(&ring_file)
                .offset(u64::from(IORING_OFF_CQ_RING))
                .protection(Protection::read_write())
                .populate()
                .build()
                .map_err(Error::MappingCompleteRing)?,
                &ring_params,
            );

            Ok(URingContext {
                ring_file,
                submit_ring: Mutex::new(SubmitQueue {
                    submit_ring,
                    submit_queue_entries,
                    io_vecs: Pin::from(vec![IoBufMut::new(&mut []); num_sqe].into_boxed_slice()),
                    submitting: 0,
                    added: 0,
                    num_sqes: ring_params.sq_entries as usize,
                }),
                complete_ring,
            })
        }
    }

    /// Asynchronously writes to `fd` from the address given in `ptr`.
    /// # Safety
    /// `add_write` will write up to `len` bytes of data from the address given by `ptr`. This is
    /// only safe if the caller guarantees that the memory lives until the transaction is complete
    /// and that completion has been returned from the `wait` function. In addition there must not
    /// be other references to the data pointed to by `ptr` until the operation completes.  Ensure
    /// that the fd remains open until the op completes as well.
    pub unsafe fn add_write(
        &self,
        ptr: *const u8,
        len: usize,
        fd: RawFd,
        offset: Option<u64>,
        user_data: UserData,
    ) -> Result<()> {
        self.submit_ring.lock().add_rw_op(
            ptr,
            len,
            fd,
            offset,
            user_data,
            io_uring_op_IORING_OP_WRITEV as u8,
        )
    }

    /// Asynchronously reads from `fd` to the address given in `ptr`.
    /// # Safety
    /// `add_read` will write up to `len` bytes of data to the address given by `ptr`. This is only
    /// safe if the caller guarantees there are no other references to that memory and that the
    /// memory lives until the transaction is complete and that completion has been returned from
    /// the `wait` function.  In addition there must not be any mutable references to the data
    /// pointed to by `ptr` until the operation completes.  Ensure that the fd remains open until
    /// the op completes as well.
    pub unsafe fn add_read(
        &self,
        ptr: *mut u8,
        len: usize,
        fd: RawFd,
        offset: Option<u64>,
        user_data: UserData,
    ) -> Result<()> {
        self.submit_ring.lock().add_rw_op(
            ptr,
            len,
            fd,
            offset,
            user_data,
            io_uring_op_IORING_OP_READV as u8,
        )
    }

    /// # Safety
    /// See 'writev' but accepts an iterator instead of a vector if there isn't already a vector in
    /// existence.
    pub unsafe fn add_writev_iter<I>(
        &self,
        iovecs: I,
        fd: RawFd,
        offset: Option<u64>,
        user_data: UserData,
    ) -> Result<()>
    where
        I: Iterator<Item = libc::iovec>,
    {
        self.add_writev(
            Pin::from(
                // Safe because the caller is required to guarantee that the memory pointed to by
                // `iovecs` lives until the transaction is complete and the completion has been
                // returned from `wait()`.
                iovecs
                    .map(|iov| IoBufMut::from_raw_parts(iov.iov_base as *mut u8, iov.iov_len))
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
            ),
            fd,
            offset,
            user_data,
        )
    }

    /// Asynchronously writes to `fd` from the addresses given in `iovecs`.
    /// # Safety
    /// `add_writev` will write to the address given by `iovecs`. This is only safe if the caller
    /// guarantees there are no other references to that memory and that the memory lives until the
    /// transaction is complete and that completion has been returned from the `wait` function.  In
    /// addition there must not be any mutable references to the data pointed to by `iovecs` until
    /// the operation completes.  Ensure that the fd remains open until the op completes as well.
    /// The iovecs reference must be kept alive until the op returns.
    pub unsafe fn add_writev(
        &self,
        iovecs: Pin<Box<[IoBufMut<'static>]>>,
        fd: RawFd,
        offset: Option<u64>,
        user_data: UserData,
    ) -> Result<()> {
        self.submit_ring.lock().prep_next_sqe(|sqe, _iovec| {
            sqe.opcode = io_uring_op_IORING_OP_WRITEV as u8;
            sqe.set_addr(iovecs.as_ptr() as *const _ as *const libc::c_void as u64);
            sqe.len = iovecs.len() as u32;
            sqe.set_off(file_offset_to_raw_offset(offset));
            sqe.set_buf_index(0);
            sqe.ioprio = 0;
            sqe.user_data = user_data;
            sqe.flags = 0;
            sqe.fd = fd;
        })?;
        self.complete_ring.add_op_data(user_data, iovecs);
        Ok(())
    }

    /// # Safety
    /// See 'readv' but accepts an iterator instead of a vector if there isn't already a vector in
    /// existence.
    pub unsafe fn add_readv_iter<I>(
        &self,
        iovecs: I,
        fd: RawFd,
        offset: Option<u64>,
        user_data: UserData,
    ) -> Result<()>
    where
        I: Iterator<Item = libc::iovec>,
    {
        self.add_readv(
            Pin::from(
                // Safe because the caller is required to guarantee that the memory pointed to by
                // `iovecs` lives until the transaction is complete and the completion has been
                // returned from `wait()`.
                iovecs
                    .map(|iov| IoBufMut::from_raw_parts(iov.iov_base as *mut u8, iov.iov_len))
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
            ),
            fd,
            offset,
            user_data,
        )
    }

    /// Asynchronously reads from `fd` to the addresses given in `iovecs`.
    /// # Safety
    /// `add_readv` will write to the address given by `iovecs`. This is only safe if the caller
    /// guarantees there are no other references to that memory and that the memory lives until the
    /// transaction is complete and that completion has been returned from the `wait` function.  In
    /// addition there must not be any references to the data pointed to by `iovecs` until the
    /// operation completes.  Ensure that the fd remains open until the op completes as well.
    /// The iovecs reference must be kept alive until the op returns.
    pub unsafe fn add_readv(
        &self,
        iovecs: Pin<Box<[IoBufMut<'static>]>>,
        fd: RawFd,
        offset: Option<u64>,
        user_data: UserData,
    ) -> Result<()> {
        self.submit_ring.lock().prep_next_sqe(|sqe, _iovec| {
            sqe.opcode = io_uring_op_IORING_OP_READV as u8;
            sqe.set_addr(iovecs.as_ptr() as *const _ as *const libc::c_void as u64);
            sqe.len = iovecs.len() as u32;
            sqe.set_off(file_offset_to_raw_offset(offset));
            sqe.set_buf_index(0);
            sqe.ioprio = 0;
            sqe.user_data = user_data;
            sqe.flags = 0;
            sqe.fd = fd;
        })?;
        self.complete_ring.add_op_data(user_data, iovecs);
        Ok(())
    }

    /// Add a no-op operation that doesn't perform any IO. Useful for testing the performance of the
    /// io_uring itself and for waking up a thread that's blocked inside a wait() call.
    pub fn add_nop(&self, user_data: UserData) -> Result<()> {
        self.submit_ring.lock().prep_next_sqe(|sqe, _iovec| {
            sqe.opcode = io_uring_op_IORING_OP_NOP as u8;
            sqe.fd = -1;
            sqe.user_data = user_data;

            sqe.set_addr(0);
            sqe.len = 0;
            sqe.set_off(0);
            sqe.set_buf_index(0);
            sqe.set_rw_flags(0);
            sqe.ioprio = 0;
            sqe.flags = 0;
        })
    }

    /// Syncs all completed operations, the ordering with in-flight async ops is not
    /// defined.
    pub fn add_fsync(&self, fd: RawFd, user_data: UserData) -> Result<()> {
        self.submit_ring.lock().prep_next_sqe(|sqe, _iovec| {
            sqe.opcode = io_uring_op_IORING_OP_FSYNC as u8;
            sqe.fd = fd;
            sqe.user_data = user_data;

            sqe.set_addr(0);
            sqe.len = 0;
            sqe.set_off(0);
            sqe.set_buf_index(0);
            sqe.set_rw_flags(0);
            sqe.ioprio = 0;
            sqe.flags = 0;
        })
    }

    /// See the usage of `fallocate`, this asynchronously performs the same operations.
    pub fn add_fallocate(
        &self,
        fd: RawFd,
        offset: u64,
        len: u64,
        mode: u32,
        user_data: UserData,
    ) -> Result<()> {
        // Note that len for fallocate in passed in the addr field of the sqe and the mode uses the
        // len field.
        self.submit_ring.lock().prep_next_sqe(|sqe, _iovec| {
            sqe.opcode = io_uring_op_IORING_OP_FALLOCATE as u8;

            sqe.fd = fd;
            sqe.set_addr(len);
            sqe.len = mode;
            sqe.set_off(offset);
            sqe.user_data = user_data;

            sqe.set_buf_index(0);
            sqe.set_rw_flags(0);
            sqe.ioprio = 0;
            sqe.flags = 0;
        })
    }

    /// Adds an FD to be polled based on the given flags.
    /// The user must keep the FD open until the operation completion is returned from
    /// `wait`.
    /// Note that io_uring is always a one shot poll. After the fd is returned, it must be re-added
    /// to get future events.
    pub fn add_poll_fd(&self, fd: RawFd, events: EventType, user_data: UserData) -> Result<()> {
        self.submit_ring.lock().prep_next_sqe(|sqe, _iovec| {
            sqe.opcode = io_uring_op_IORING_OP_POLL_ADD as u8;
            sqe.fd = fd;
            sqe.user_data = user_data;
            sqe.set_poll_events(events.into());

            sqe.set_addr(0);
            sqe.len = 0;
            sqe.set_off(0);
            sqe.set_buf_index(0);
            sqe.ioprio = 0;
            sqe.flags = 0;
        })
    }

    /// Removes an FD that was previously added with `add_poll_fd`.
    pub fn remove_poll_fd(&self, fd: RawFd, events: EventType, user_data: UserData) -> Result<()> {
        self.submit_ring.lock().prep_next_sqe(|sqe, _iovec| {
            sqe.opcode = io_uring_op_IORING_OP_POLL_REMOVE as u8;
            sqe.fd = fd;
            sqe.user_data = user_data;
            sqe.set_poll_events(events.into());

            sqe.set_addr(0);
            sqe.len = 0;
            sqe.set_off(0);
            sqe.set_buf_index(0);
            sqe.ioprio = 0;
            sqe.flags = 0;
        })
    }

    /// Attempt to cancel an already issued request. addr must contain the user_data field of the
    /// request that should be cancelled. The cancellation request will complete with one of the
    /// following results codes. If found, the res field of the cqe will contain 0. If not found,
    /// res will contain -ENOENT. If found and attempted cancelled, the res field will contain
    /// -EALREADY. In this case, the request may or may not terminate. In general, requests that
    /// are interruptible (like socket IO) will get cancelled, while disk IO requests cannot be
    /// cancelled if already started.
    pub fn async_cancel(&self, addr: UserData, user_data: UserData) -> Result<()> {
        self.submit_ring.lock().prep_next_sqe(|sqe, _iovec| {
            sqe.opcode = io_uring_op_IORING_OP_ASYNC_CANCEL as u8;
            sqe.user_data = user_data;
            sqe.set_addr(addr);

            sqe.len = 0;
            sqe.fd = 0;
            sqe.set_off(0);
            sqe.set_buf_index(0);
            sqe.ioprio = 0;
            sqe.flags = 0;
        })
    }

    // Calls io_uring_enter, submitting any new sqes that have been added to the submit queue and
    // waiting for `wait_nr` operations to complete.
    fn enter(&self, wait_nr: u64) -> Result<()> {
        let added = self.submit_ring.lock().prepare_submit();
        if added == 0 && wait_nr == 0 {
            return Ok(());
        }

        let flags = if wait_nr > 0 {
            IORING_ENTER_GETEVENTS
        } else {
            0
        };
        let res = unsafe {
            // Safe because the only memory modified is in the completion queue.
            io_uring_enter(self.ring_file.as_raw_fd(), added as u64, wait_nr, flags)
        };

        match res {
            Ok(_) => {
                self.submit_ring.lock().complete_submit(added);
            }
            Err(e) => {
                // An EBUSY return means that some completed events must be processed before
                // submitting more, so wait for some to finish without pushing the new sqes in
                // that case.
                // An EINTR means we successfully submitted the events but were interrupted while
                // waiting, so just wait again.
                // Any other error should be propagated up.

                if e != libc::EINTR {
                    self.submit_ring.lock().fail_submit(added);
                }

                if wait_nr == 0 || (e != libc::EBUSY && e != libc::EINTR) {
                    return Err(Error::RingEnter(e));
                }

                loop {
                    // Safe because the only memory modified is in the completion queue.
                    let res =
                        unsafe { io_uring_enter(self.ring_file.as_raw_fd(), 0, wait_nr, flags) };
                    if res != Err(libc::EINTR) {
                        return res.map_err(Error::RingEnter);
                    }
                }
            }
        }

        Ok(())
    }

    /// Sends operations added with the `add_*` functions to the kernel.
    pub fn submit(&self) -> Result<()> {
        self.enter(0)
    }

    /// Sends operations added with the `add_*` functions to the kernel and return an iterator to any
    /// completed operations. `wait` blocks until at least one completion is ready.  If called
    /// without any new events added, this simply waits for any existing events to complete and
    /// returns as soon an one or more is ready.
    pub fn wait(&self) -> Result<impl Iterator<Item = (UserData, std::io::Result<u32>)> + '_> {
        // We only want to wait for events if there aren't already events in the completion queue.
        let wait_nr = if self.complete_ring.num_ready() > 0 {
            0
        } else {
            1
        };

        // The CompletionQueue will iterate all completed ops.
        match self.enter(wait_nr) {
            Ok(()) => Ok(&self.complete_ring),
            // If we cannot submit any more entries then we need to pull stuff out of the completion
            // ring, so just return the completion ring. This can only happen when `wait_nr` is 0 so
            // we know there are already entries in the completion queue.
            Err(Error::RingEnter(libc::EBUSY)) => Ok(&self.complete_ring),
            Err(e) => Err(e),
        }
    }
}

impl AsRawFd for URingContext {
    fn as_raw_fd(&self) -> RawFd {
        self.ring_file.as_raw_fd()
    }
}

impl AsRawDescriptor for URingContext {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.ring_file.as_raw_descriptor()
    }
}

struct SubmitQueueEntries {
    mmap: MemoryMapping,
    len: usize,
}

impl SubmitQueueEntries {
    fn get_mut(&mut self, index: usize) -> Option<&mut io_uring_sqe> {
        if index >= self.len {
            return None;
        }
        let mut_ref = unsafe {
            // Safe because the mut borrow of self resticts to one mutable reference at a time and
            // we trust that the kernel has returned enough memory in io_uring_setup and mmap.
            &mut *(self.mmap.as_ptr() as *mut io_uring_sqe).add(index)
        };
        // Clear any state.
        *mut_ref = io_uring_sqe::default();
        Some(mut_ref)
    }
}

struct SubmitQueueState {
    _mmap: MemoryMapping,
    pointers: QueuePointers,
    ring_mask: u32,
    array: AtomicPtr<u32>,
}

impl SubmitQueueState {
    // # Safety
    // Safe iff `mmap` is created by mapping from a uring FD at the SQ_RING offset and params is
    // the params struct passed to io_uring_setup.
    unsafe fn new(mmap: MemoryMapping, params: &io_uring_params) -> SubmitQueueState {
        let ptr = mmap.as_ptr();
        // Transmutes are safe because a u32 is atomic on all supported architectures and the
        // pointer will live until after self is dropped because the mmap is owned.
        let head = ptr.add(params.sq_off.head as usize) as *const AtomicU32;
        let tail = ptr.add(params.sq_off.tail as usize) as *const AtomicU32;
        // This offset is guaranteed to be within the mmap so unwrap the result.
        let ring_mask = mmap.read_obj(params.sq_off.ring_mask as usize).unwrap();
        let array = AtomicPtr::new(ptr.add(params.sq_off.array as usize) as *mut u32);
        SubmitQueueState {
            _mmap: mmap,
            pointers: QueuePointers { head, tail },
            ring_mask,
            array,
        }
    }

    // Sets the kernel's array entry at the given `index` to `value`.
    fn set_array_entry(&self, index: usize, value: u32) {
        // Safe because self being constructed from the correct mmap guaratees that the memory is
        // valid to written.
        unsafe {
            std::ptr::write_volatile(self.array.load(Ordering::Relaxed).add(index), value);
        }
    }
}

#[derive(Default)]
struct CompleteQueueData {
    //For ops that pass in arrays of iovecs, they need to be valid for the duration of the
    //operation because the kernel might read them at any time.
    pending_op_addrs: BTreeMap<UserData, Pin<Box<[IoBufMut<'static>]>>>,
}

pub struct CompleteQueueState {
    mmap: MemoryMapping,
    pointers: QueuePointers,
    ring_mask: u32,
    cqes_offset: u32,
    data: Mutex<CompleteQueueData>,
}

impl CompleteQueueState {
    /// # Safety
    /// Safe iff `mmap` is created by mapping from a uring FD at the CQ_RING offset and params is
    /// the params struct passed to io_uring_setup.
    unsafe fn new(mmap: MemoryMapping, params: &io_uring_params) -> CompleteQueueState {
        let ptr = mmap.as_ptr();
        let head = ptr.add(params.cq_off.head as usize) as *const AtomicU32;
        let tail = ptr.add(params.cq_off.tail as usize) as *const AtomicU32;
        let ring_mask = mmap.read_obj(params.cq_off.ring_mask as usize).unwrap();
        CompleteQueueState {
            mmap,
            pointers: QueuePointers { head, tail },
            ring_mask,
            cqes_offset: params.cq_off.cqes,
            data: Default::default(),
        }
    }

    fn add_op_data(&self, user_data: UserData, addrs: Pin<Box<[IoBufMut<'static>]>>) {
        self.data.lock().pending_op_addrs.insert(user_data, addrs);
    }

    fn get_cqe(&self, head: u32) -> &io_uring_cqe {
        unsafe {
            // Safe because we trust that the kernel has returned enough memory in io_uring_setup
            // and mmap and index is checked within range by the ring_mask.
            let cqes = (self.mmap.as_ptr() as *const u8).add(self.cqes_offset as usize)
                as *const io_uring_cqe;

            let index = head & self.ring_mask;

            &*cqes.add(index as usize)
        }
    }

    pub fn num_ready(&self) -> u32 {
        let tail = self.pointers.tail(Ordering::Acquire);
        let head = self.pointers.head(Ordering::Relaxed);

        tail.saturating_sub(head)
    }

    fn pop_front(&self) -> Option<(UserData, std::io::Result<u32>)> {
        // Take the lock on self.data first so that 2 threads don't try to pop the same completed op
        // from the queue.
        let mut data = self.data.lock();

        // Safe because the pointers to the atomics are valid and the cqe must be in range
        // because the kernel provided mask is applied to the index.
        let head = self.pointers.head(Ordering::Relaxed);

        // Synchronize the read of tail after the read of head.
        if head == self.pointers.tail(Ordering::Acquire) {
            return None;
        }

        let cqe = self.get_cqe(head);
        let user_data = cqe.user_data;
        let res = cqe.res;

        // free the addrs saved for this op.
        let _ = data.pending_op_addrs.remove(&user_data);

        // Store the new head and ensure the reads above complete before the kernel sees the
        // update to head, `set_head` uses `Release` ordering
        let new_head = head.wrapping_add(1);
        self.pointers.set_head(new_head);

        let io_res = match res {
            r if r < 0 => Err(std::io::Error::from_raw_os_error(-r)),
            r => Ok(r as u32),
        };
        Some((user_data, io_res))
    }
}

// Return the completed ops with their result.
impl<'c> Iterator for &'c CompleteQueueState {
    type Item = (UserData, std::io::Result<u32>);

    fn next(&mut self) -> Option<Self::Item> {
        self.pop_front()
    }
}

struct QueuePointers {
    head: *const AtomicU32,
    tail: *const AtomicU32,
}

// Rust pointers don't implement Send or Sync but in this case both fields are atomics and so it's
// safe to send the pointers between threads or access them concurrently from multiple threads.
unsafe impl Send for QueuePointers {}
unsafe impl Sync for QueuePointers {}

impl QueuePointers {
    // Loads the tail pointer atomically with the given ordering.
    fn tail(&self, ordering: Ordering) -> u32 {
        // Safe because self being constructed from the correct mmap guaratees that the memory is
        // valid to read.
        unsafe { (*self.tail).load(ordering) }
    }

    // Stores the new value of the tail in the submit queue. This allows the kernel to start
    // processing entries that have been added up until the given tail pointer.
    // Always stores with release ordering as that is the only valid way to use the pointer.
    fn set_tail(&self, next_tail: u32) {
        // Safe because self being constructed from the correct mmap guaratees that the memory is
        // valid to read and it's used as an atomic to cover mutability concerns.
        unsafe { (*self.tail).store(next_tail, Ordering::Release) }
    }

    // Loads the head pointer atomically with the given ordering.
    fn head(&self, ordering: Ordering) -> u32 {
        // Safe because self being constructed from the correct mmap guaratees that the memory is
        // valid to read.
        unsafe { (*self.head).load(ordering) }
    }

    // Stores the new value of the head in the submit queue. This allows the kernel to start
    // processing entries that have been added up until the given head pointer.
    // Always stores with release ordering as that is the only valid way to use the pointer.
    fn set_head(&self, next_head: u32) {
        // Safe because self being constructed from the correct mmap guaratees that the memory is
        // valid to read and it's used as an atomic to cover mutability concerns.
        unsafe { (*self.head).store(next_head, Ordering::Release) }
    }
}
