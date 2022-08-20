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
use std::sync::atomic::AtomicPtr;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use base::AsRawDescriptor;
use base::EventType;
use base::MappedRegion;
use base::MemoryMapping;
use base::MemoryMappingBuilder;
use base::Protection;
use base::RawDescriptor;
use data_model::IoBufMut;
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

/// Basic statistics about the operations that have been submitted to the uring.
#[derive(Default)]
pub struct URingStats {
    total_enter_calls: AtomicU64, // Number of times the uring has been entered.
    total_ops: AtomicU64,         // Total ops submitted to io_uring.
    total_complete: AtomicU64,    // Total ops completed by io_uring.
}

struct SubmitQueue {
    submit_ring: SubmitQueueState,
    submit_queue_entries: SubmitQueueEntries,
    io_vecs: Pin<Box<[IoBufMut<'static>]>>,
    submitting: usize, // The number of ops in the process of being submitted.
    added: usize,      // The number of ops added since the last call to `io_uring_enter`.
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

/// Unsafe wrapper for the kernel's io_uring interface. Allows for queueing multiple I/O operations
/// to the kernel and asynchronously handling the completion of these operations.
/// Use the various `add_*` functions to configure operations, then call `wait` to start
/// the operations and get any completed results. Each op is given a u64 user_data argument that is
/// used to identify the result when returned in the iterator provided by `wait`.
///
/// # Example polling an FD for readable status.
///
/// ```
/// # use std::fs::File;
/// # use std::os::unix::io::AsRawFd;
/// # use std::path::Path;
/// # use base::EventType;
/// # use io_uring::URingContext;
/// let f = File::open(Path::new("/dev/zero")).unwrap();
/// let uring = URingContext::new(16).unwrap();
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
    submit_ring: Mutex<SubmitQueue>,
    complete_ring: CompleteQueueState,
    in_flight: AtomicUsize, // The number of pending operations.
    stats: URingStats,
}

impl URingContext {
    /// Creates a `URingContext` where the underlying uring has a space for `num_entries`
    /// simultaneous operations.
    pub fn new(num_entries: usize) -> Result<URingContext> {
        let ring_params = io_uring_params::default();
        // The below unsafe block isolates the creation of the URingContext. Each step on it's own
        // is unsafe. Using the uring FD for the mapping and the offsets returned by the kernel for
        // base addresses maintains safety guarantees assuming the kernel API guarantees are
        // trusted.
        unsafe {
            // Safe because the kernel is trusted to only modify params and `File` is created with
            // an FD that it takes complete ownership of.
            let fd = io_uring_setup(num_entries, &ring_params).map_err(Error::Setup)?;
            let ring_file = File::from_raw_fd(fd);

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
                in_flight: AtomicUsize::new(0),
                stats: Default::default(),
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
        self.submit_ring
            .lock()
            .add_rw_op(ptr, len, fd, offset, user_data, IORING_OP_WRITEV as u8)
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
        self.submit_ring
            .lock()
            .add_rw_op(ptr, len, fd, offset, user_data, IORING_OP_READV as u8)
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
            sqe.opcode = IORING_OP_WRITEV as u8;
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
            sqe.opcode = IORING_OP_READV as u8;
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
            sqe.opcode = IORING_OP_NOP as u8;
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
            sqe.opcode = IORING_OP_FSYNC as u8;
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
            sqe.opcode = IORING_OP_FALLOCATE as u8;

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
            sqe.opcode = IORING_OP_POLL_ADD as u8;
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
            sqe.opcode = IORING_OP_POLL_REMOVE as u8;
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
            sqe.opcode = IORING_OP_ASYNC_CANCEL as u8;
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
        let completed = self.complete_ring.num_completed();
        self.stats
            .total_complete
            .fetch_add(completed as u64, Ordering::Relaxed);
        self.in_flight.fetch_sub(completed, Ordering::Relaxed);

        let added = self.submit_ring.lock().prepare_submit();
        if added == 0 && wait_nr == 0 {
            return Ok(());
        }

        self.stats.total_enter_calls.fetch_add(1, Ordering::Relaxed);
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
                self.stats
                    .total_ops
                    .fetch_add(added as u64, Ordering::Relaxed);

                // Release store synchronizes with acquire load above.
                self.in_flight.fetch_add(added, Ordering::Release);
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
            std::ptr::write_volatile(self.array.load(Ordering::Relaxed).add(index), value as u32);
        }
    }
}

#[derive(Default)]
struct CompleteQueueData {
    completed: usize,
    //For ops that pass in arrays of iovecs, they need to be valid for the duration of the
    //operation because the kernel might read them at any time.
    pending_op_addrs: BTreeMap<UserData, Pin<Box<[IoBufMut<'static>]>>>,
}

struct CompleteQueueState {
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

    fn num_ready(&self) -> u32 {
        let tail = self.pointers.tail(Ordering::Acquire);
        let head = self.pointers.head(Ordering::Relaxed);

        tail.saturating_sub(head)
    }

    fn num_completed(&self) -> usize {
        let mut data = self.data.lock();
        ::std::mem::replace(&mut data.completed, 0)
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

        data.completed += 1;

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

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs::OpenOptions;
    use std::io::IoSlice;
    use std::io::IoSliceMut;
    use std::io::Read;
    use std::io::Seek;
    use std::io::SeekFrom;
    use std::io::Write;
    use std::mem;
    use std::path::Path;
    use std::path::PathBuf;
    use std::sync::mpsc::channel;
    use std::sync::Arc;
    use std::sync::Barrier;
    use std::thread;
    use std::time::Duration;

    use base::pipe;
    use base::WaitContext;
    use sync::Condvar;
    use sync::Mutex;
    use tempfile::tempfile;
    use tempfile::TempDir;

    use super::*;

    fn append_file_name(path: &Path, name: &str) -> PathBuf {
        let mut joined = path.to_path_buf();
        joined.push(name);
        joined
    }

    fn check_one_read(
        uring: &URingContext,
        buf: &mut [u8],
        fd: RawFd,
        offset: u64,
        user_data: UserData,
    ) {
        let (user_data_ret, res) = unsafe {
            // Safe because the `wait` call waits until the kernel is done with `buf`.
            uring
                .add_read(buf.as_mut_ptr(), buf.len(), fd, Some(offset), user_data)
                .unwrap();
            uring.wait().unwrap().next().unwrap()
        };
        assert_eq!(user_data_ret, user_data);
        assert_eq!(res.unwrap(), buf.len() as u32);
    }

    fn check_one_readv(
        uring: &URingContext,
        buf: &mut [u8],
        fd: RawFd,
        offset: u64,
        user_data: UserData,
    ) {
        let io_vecs = unsafe {
            //safe to transmut from IoSlice to iovec.
            vec![IoSliceMut::new(buf)]
                .into_iter()
                .map(|slice| std::mem::transmute::<IoSliceMut, libc::iovec>(slice))
        };
        let (user_data_ret, res) = unsafe {
            // Safe because the `wait` call waits until the kernel is done with `buf`.
            uring
                .add_readv_iter(io_vecs, fd, Some(offset), user_data)
                .unwrap();
            uring.wait().unwrap().next().unwrap()
        };
        assert_eq!(user_data_ret, user_data);
        assert_eq!(res.unwrap(), buf.len() as u32);
    }

    fn create_test_file(size: u64) -> std::fs::File {
        let f = tempfile().unwrap();
        f.set_len(size).unwrap();
        f
    }

    #[test]
    // Queue as many reads as possible and then collect the completions.
    fn read_parallel() {
        const QUEUE_SIZE: usize = 10;
        const BUF_SIZE: usize = 0x1000;

        let uring = URingContext::new(QUEUE_SIZE).unwrap();
        let mut buf = [0u8; BUF_SIZE * QUEUE_SIZE];
        let f = create_test_file((BUF_SIZE * QUEUE_SIZE) as u64);

        // check that the whole file can be read and that the queues wrapping is handled by reading
        // double the quue depth of buffers.
        for i in 0..QUEUE_SIZE * 64 {
            let index = i as u64;
            unsafe {
                let offset = (i % QUEUE_SIZE) * BUF_SIZE;
                match uring.add_read(
                    buf[offset..].as_mut_ptr(),
                    BUF_SIZE,
                    f.as_raw_fd(),
                    Some(offset as u64),
                    index,
                ) {
                    Ok(_) => (),
                    Err(Error::NoSpace) => {
                        let _ = uring.wait().unwrap().next().unwrap();
                    }
                    Err(_) => panic!("unexpected error from uring wait"),
                }
            }
        }
    }

    #[test]
    fn read_readv() {
        let queue_size = 128;

        let uring = URingContext::new(queue_size).unwrap();
        let mut buf = [0u8; 0x1000];
        let f = create_test_file(0x1000 * 2);

        // check that the whole file can be read and that the queues wrapping is handled by reading
        // double the quue depth of buffers.
        for i in 0..queue_size * 2 {
            let index = i as u64;
            check_one_read(&uring, &mut buf, f.as_raw_fd(), (index % 2) * 0x1000, index);
            check_one_readv(&uring, &mut buf, f.as_raw_fd(), (index % 2) * 0x1000, index);
        }
    }

    #[test]
    fn readv_vec() {
        let queue_size = 128;
        const BUF_SIZE: usize = 0x2000;

        let uring = URingContext::new(queue_size).unwrap();
        let mut buf = [0u8; BUF_SIZE];
        let mut buf2 = [0u8; BUF_SIZE];
        let mut buf3 = [0u8; BUF_SIZE];
        let io_vecs = unsafe {
            //safe to transmut from IoSlice to iovec.
            vec![
                IoSliceMut::new(&mut buf),
                IoSliceMut::new(&mut buf2),
                IoSliceMut::new(&mut buf3),
            ]
            .into_iter()
            .map(|slice| std::mem::transmute::<IoSliceMut, libc::iovec>(slice))
            .collect::<Vec<libc::iovec>>()
        };
        let total_len = io_vecs.iter().fold(0, |a, iovec| a + iovec.iov_len);
        let f = create_test_file(total_len as u64 * 2);
        let (user_data_ret, res) = unsafe {
            // Safe because the `wait` call waits until the kernel is done with `buf`.
            uring
                .add_readv_iter(io_vecs.into_iter(), f.as_raw_fd(), Some(0), 55)
                .unwrap();
            uring.wait().unwrap().next().unwrap()
        };
        assert_eq!(user_data_ret, 55);
        assert_eq!(res.unwrap(), total_len as u32);
    }

    #[test]
    fn write_one_block() {
        let uring = URingContext::new(16).unwrap();
        let mut buf = [0u8; 4096];
        let mut f = create_test_file(0);
        f.write_all(&buf).unwrap();
        f.write_all(&buf).unwrap();

        unsafe {
            // Safe because the `wait` call waits until the kernel is done mutating `buf`.
            uring
                .add_write(buf.as_mut_ptr(), buf.len(), f.as_raw_fd(), Some(0), 55)
                .unwrap();
            let (user_data, res) = uring.wait().unwrap().next().unwrap();
            assert_eq!(user_data, 55_u64);
            assert_eq!(res.unwrap(), buf.len() as u32);
        }
    }

    #[test]
    fn write_one_submit_poll() {
        let uring = URingContext::new(16).unwrap();
        let mut buf = [0u8; 4096];
        let mut f = create_test_file(0);
        f.write_all(&buf).unwrap();
        f.write_all(&buf).unwrap();

        let ctx: WaitContext<u64> = WaitContext::build_with(&[(&uring, 1)]).unwrap();
        {
            // Test that the uring context isn't readable before any events are complete.
            let events = ctx.wait_timeout(Duration::from_millis(1)).unwrap();
            assert!(events.iter().next().is_none());
        }

        unsafe {
            // Safe because the `wait` call waits until the kernel is done mutating `buf`.
            uring
                .add_write(buf.as_mut_ptr(), buf.len(), f.as_raw_fd(), Some(0), 55)
                .unwrap();
            uring.submit().unwrap();
            // Poll for completion with epoll.
            let events = ctx.wait().unwrap();
            let event = events.iter().next().unwrap();
            assert!(event.is_readable);
            assert_eq!(event.token, 1);
            let (user_data, res) = uring.wait().unwrap().next().unwrap();
            assert_eq!(user_data, 55_u64);
            assert_eq!(res.unwrap(), buf.len() as u32);
        }
    }

    #[test]
    fn writev_vec() {
        let queue_size = 128;
        const BUF_SIZE: usize = 0x2000;
        const OFFSET: u64 = 0x2000;

        let uring = URingContext::new(queue_size).unwrap();
        let buf = [0xaau8; BUF_SIZE];
        let buf2 = [0xffu8; BUF_SIZE];
        let buf3 = [0x55u8; BUF_SIZE];
        let io_vecs = unsafe {
            //safe to transmut from IoSlice to iovec.
            vec![IoSlice::new(&buf), IoSlice::new(&buf2), IoSlice::new(&buf3)]
                .into_iter()
                .map(|slice| std::mem::transmute::<IoSlice, libc::iovec>(slice))
                .collect::<Vec<libc::iovec>>()
        };
        let total_len = io_vecs.iter().fold(0, |a, iovec| a + iovec.iov_len);
        let mut f = create_test_file(total_len as u64 * 2);
        let (user_data_ret, res) = unsafe {
            // Safe because the `wait` call waits until the kernel is done with `buf`.
            uring
                .add_writev_iter(io_vecs.into_iter(), f.as_raw_fd(), Some(OFFSET), 55)
                .unwrap();
            uring.wait().unwrap().next().unwrap()
        };
        assert_eq!(user_data_ret, 55);
        assert_eq!(res.unwrap(), total_len as u32);

        let mut read_back = [0u8; BUF_SIZE];
        f.seek(SeekFrom::Start(OFFSET)).unwrap();
        f.read_exact(&mut read_back).unwrap();
        assert!(!read_back.iter().any(|&b| b != 0xaa));
        f.read_exact(&mut read_back).unwrap();
        assert!(!read_back.iter().any(|&b| b != 0xff));
        f.read_exact(&mut read_back).unwrap();
        assert!(!read_back.iter().any(|&b| b != 0x55));
    }

    #[test]
    fn fallocate_fsync() {
        let tempdir = TempDir::new().unwrap();
        let file_path = append_file_name(tempdir.path(), "test");

        {
            let buf = [0u8; 4096];
            let mut f = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(&file_path)
                .unwrap();
            f.write_all(&buf).unwrap();
        }

        let init_size = std::fs::metadata(&file_path).unwrap().len() as usize;
        let set_size = init_size + 1024 * 1024 * 50;
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&file_path)
            .unwrap();

        let uring = URingContext::new(16).unwrap();
        uring
            .add_fallocate(f.as_raw_fd(), 0, set_size as u64, 0, 66)
            .unwrap();
        let (user_data, res) = uring.wait().unwrap().next().unwrap();
        assert_eq!(user_data, 66_u64);
        match res {
            Err(e) => {
                if e.kind() == std::io::ErrorKind::InvalidInput {
                    // skip on kernels that don't support fallocate.
                    return;
                }
                panic!("Unexpected fallocate error: {}", e);
            }
            Ok(val) => assert_eq!(val, 0_u32),
        }

        // Add a few writes and then fsync
        let buf = [0u8; 4096];
        let mut pending = std::collections::BTreeSet::new();
        unsafe {
            uring
                .add_write(buf.as_ptr(), buf.len(), f.as_raw_fd(), Some(0), 67)
                .unwrap();
            pending.insert(67u64);
            uring
                .add_write(buf.as_ptr(), buf.len(), f.as_raw_fd(), Some(4096), 68)
                .unwrap();
            pending.insert(68);
            uring
                .add_write(buf.as_ptr(), buf.len(), f.as_raw_fd(), Some(8192), 69)
                .unwrap();
            pending.insert(69);
        }
        uring.add_fsync(f.as_raw_fd(), 70).unwrap();
        pending.insert(70);

        let mut wait_calls = 0;

        while !pending.is_empty() && wait_calls < 5 {
            let events = uring.wait().unwrap();
            for (user_data, res) in events {
                assert!(res.is_ok());
                assert!(pending.contains(&user_data));
                pending.remove(&user_data);
            }
            wait_calls += 1;
        }
        assert!(pending.is_empty());

        uring
            .add_fallocate(
                f.as_raw_fd(),
                init_size as u64,
                (set_size - init_size) as u64,
                (libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE) as u32,
                68,
            )
            .unwrap();
        let (user_data, res) = uring.wait().unwrap().next().unwrap();
        assert_eq!(user_data, 68_u64);
        assert_eq!(res.unwrap(), 0_u32);

        drop(f); // Close to ensure directory entires for metadata are updated.

        let new_size = std::fs::metadata(&file_path).unwrap().len() as usize;
        assert_eq!(new_size, set_size);
    }

    #[test]
    fn dev_zero_readable() {
        let f = File::open(Path::new("/dev/zero")).unwrap();
        let uring = URingContext::new(16).unwrap();
        uring
            .add_poll_fd(f.as_raw_fd(), EventType::Read, 454)
            .unwrap();
        let (user_data, res) = uring.wait().unwrap().next().unwrap();
        assert_eq!(user_data, 454_u64);
        assert_eq!(res.unwrap(), 1_u32);
    }

    #[test]
    fn queue_many_ebusy_retry() {
        let num_entries = 16;
        let f = File::open(Path::new("/dev/zero")).unwrap();
        let uring = URingContext::new(num_entries).unwrap();
        // Fill the sumbit ring.
        for sqe_batch in 0..3 {
            for i in 0..num_entries {
                uring
                    .add_poll_fd(
                        f.as_raw_fd(),
                        EventType::Read,
                        (sqe_batch * num_entries + i) as u64,
                    )
                    .unwrap();
            }
            uring.submit().unwrap();
        }
        // Adding more than the number of cqes will cause the uring to return ebusy, make sure that
        // is handled cleanly and wait still returns the completed entries.
        uring
            .add_poll_fd(f.as_raw_fd(), EventType::Read, (num_entries * 3) as u64)
            .unwrap();
        // The first wait call should return the cques that are already filled.
        {
            let mut results = uring.wait().unwrap();
            for _i in 0..num_entries * 2 {
                assert_eq!(results.next().unwrap().1.unwrap(), 1_u32);
            }
            assert!(results.next().is_none());
        }
        // The second will finish submitting any more sqes and return the rest.
        let mut results = uring.wait().unwrap();
        for _i in 0..num_entries + 1 {
            assert_eq!(results.next().unwrap().1.unwrap(), 1_u32);
        }
        assert!(results.next().is_none());
    }

    #[test]
    fn wake_with_nop() {
        const PIPE_READ: UserData = 0;
        const NOP: UserData = 1;
        const BUF_DATA: [u8; 16] = [0xf4; 16];

        let uring = URingContext::new(4).map(Arc::new).unwrap();
        let (pipe_out, mut pipe_in) = pipe(true).unwrap();
        let (tx, rx) = channel();

        let uring2 = uring.clone();
        let wait_thread = thread::spawn(move || {
            let mut buf = [0u8; BUF_DATA.len()];
            unsafe {
                uring2
                    .add_read(
                        buf.as_mut_ptr(),
                        buf.len(),
                        pipe_out.as_raw_fd(),
                        Some(0),
                        0,
                    )
                    .unwrap();
            }

            // This is still a bit racy as the other thread may end up adding the NOP before we make
            // the syscall but I'm not aware of a mechanism that will notify the other thread
            // exactly when we make the syscall.
            tx.send(()).unwrap();
            let mut events = uring2.wait().unwrap();
            let (user_data, result) = events.next().unwrap();
            assert_eq!(user_data, NOP);
            assert_eq!(result.unwrap(), 0);

            tx.send(()).unwrap();
            let mut events = uring2.wait().unwrap();
            let (user_data, result) = events.next().unwrap();
            assert_eq!(user_data, PIPE_READ);
            assert_eq!(result.unwrap(), buf.len() as u32);
            assert_eq!(&buf, &BUF_DATA);
        });

        // Wait until the other thread is about to make the syscall.
        rx.recv_timeout(Duration::from_secs(10)).unwrap();

        // Now add a NOP operation. This should wake up the other thread even though it cannot yet
        // read from the pipe.
        uring.add_nop(NOP).unwrap();
        uring.submit().unwrap();

        // Wait for the other thread to process the NOP result.
        rx.recv_timeout(Duration::from_secs(10)).unwrap();

        // Now write to the pipe to finish the uring read.
        pipe_in.write_all(&BUF_DATA).unwrap();

        wait_thread.join().unwrap();
    }

    #[test]
    fn complete_from_any_thread() {
        let num_entries = 16;
        let uring = URingContext::new(num_entries).map(Arc::new).unwrap();

        // Fill the sumbit ring.
        for sqe_batch in 0..3 {
            for i in 0..num_entries {
                uring.add_nop((sqe_batch * num_entries + i) as u64).unwrap();
            }
            uring.submit().unwrap();
        }

        // Spawn a bunch of threads that pull cqes out of the uring and make sure none of them see a
        // duplicate.
        const NUM_THREADS: usize = 7;
        let completed = Arc::new(Mutex::new(BTreeSet::new()));
        let cv = Arc::new(Condvar::new());
        let barrier = Arc::new(Barrier::new(NUM_THREADS));

        let mut threads = Vec::with_capacity(NUM_THREADS);
        for _ in 0..NUM_THREADS {
            let uring = uring.clone();
            let completed = completed.clone();
            let barrier = barrier.clone();
            let cv = cv.clone();
            threads.push(thread::spawn(move || {
                barrier.wait();

                'wait: while completed.lock().len() < num_entries * 3 {
                    for (user_data, result) in uring.wait().unwrap() {
                        assert_eq!(result.unwrap(), 0);

                        let mut completed = completed.lock();
                        assert!(completed.insert(user_data));
                        if completed.len() >= num_entries * 3 {
                            break 'wait;
                        }
                    }
                }

                cv.notify_one();
            }));
        }

        // Wait until all the operations have completed.
        let mut c = completed.lock();
        while c.len() < num_entries * 3 {
            c = cv.wait(c);
        }
        mem::drop(c);

        // Let the OS clean up the still-waiting threads after the test run.
    }

    #[test]
    fn submit_from_any_thread() {
        const NUM_THREADS: usize = 7;
        const ITERATIONS: usize = 113;
        const NUM_ENTRIES: usize = 16;

        fn wait_for_completion_thread(in_flight: &Mutex<isize>, cv: &Condvar) {
            let mut in_flight = in_flight.lock();
            while *in_flight > NUM_ENTRIES as isize {
                in_flight = cv.wait(in_flight);
            }
        }

        let uring = URingContext::new(NUM_ENTRIES).map(Arc::new).unwrap();
        let in_flight = Arc::new(Mutex::new(0));
        let cv = Arc::new(Condvar::new());

        let mut threads = Vec::with_capacity(NUM_THREADS);
        for idx in 0..NUM_THREADS {
            let uring = uring.clone();
            let in_flight = in_flight.clone();
            let cv = cv.clone();
            threads.push(thread::spawn(move || {
                for iter in 0..ITERATIONS {
                    loop {
                        match uring.add_nop(((idx * NUM_THREADS) + iter) as UserData) {
                            Ok(()) => *in_flight.lock() += 1,
                            Err(Error::NoSpace) => {
                                wait_for_completion_thread(&in_flight, &cv);
                                continue;
                            }
                            Err(e) => panic!("Failed to add nop: {}", e),
                        }

                        // We don't need to wait for the completion queue if the submit fails with
                        // EBUSY because we already added the operation to the submit queue. It will
                        // get added eventually.
                        match uring.submit() {
                            Ok(()) => break,
                            Err(Error::RingEnter(libc::EBUSY)) => break,
                            Err(e) => panic!("Failed to submit ops: {}", e),
                        }
                    }
                }
            }));
        }

        let mut completed = 0;
        while completed < NUM_THREADS * ITERATIONS {
            for (_, res) in uring.wait().unwrap() {
                assert_eq!(res.unwrap(), 0);
                completed += 1;

                let mut in_flight = in_flight.lock();
                *in_flight -= 1;
                let notify_submitters = *in_flight <= NUM_ENTRIES as isize;
                mem::drop(in_flight);

                if notify_submitters {
                    cv.notify_all();
                }

                if completed >= NUM_THREADS * ITERATIONS {
                    break;
                }
            }
        }

        for t in threads {
            t.join().unwrap();
        }

        // Make sure we didn't submit more entries than expected.
        assert_eq!(*in_flight.lock(), 0);
        assert_eq!(uring.submit_ring.lock().added, 0);
        assert_eq!(uring.complete_ring.num_ready(), 0);
        assert_eq!(
            uring.stats.total_ops.load(Ordering::Relaxed),
            (NUM_THREADS * ITERATIONS) as u64
        );
    }

    // TODO(b/183722981): Fix and re-enable test
    #[test]
    #[ignore]
    fn multi_thread_submit_and_complete() {
        const NUM_SUBMITTERS: usize = 7;
        const NUM_COMPLETERS: usize = 3;
        const ITERATIONS: usize = 113;
        const NUM_ENTRIES: usize = 16;

        fn wait_for_completion_thread(in_flight: &Mutex<isize>, cv: &Condvar) {
            let mut in_flight = in_flight.lock();
            while *in_flight > NUM_ENTRIES as isize {
                in_flight = cv.wait(in_flight);
            }
        }

        let uring = URingContext::new(NUM_ENTRIES).map(Arc::new).unwrap();
        let in_flight = Arc::new(Mutex::new(0));
        let cv = Arc::new(Condvar::new());

        let mut threads = Vec::with_capacity(NUM_SUBMITTERS + NUM_COMPLETERS);
        for idx in 0..NUM_SUBMITTERS {
            let uring = uring.clone();
            let in_flight = in_flight.clone();
            let cv = cv.clone();
            threads.push(thread::spawn(move || {
                for iter in 0..ITERATIONS {
                    loop {
                        match uring.add_nop(((idx * NUM_SUBMITTERS) + iter) as UserData) {
                            Ok(()) => *in_flight.lock() += 1,
                            Err(Error::NoSpace) => {
                                wait_for_completion_thread(&in_flight, &cv);
                                continue;
                            }
                            Err(e) => panic!("Failed to add nop: {}", e),
                        }

                        // We don't need to wait for the completion queue if the submit fails with
                        // EBUSY because we already added the operation to the submit queue. It will
                        // get added eventually.
                        match uring.submit() {
                            Ok(()) => break,
                            Err(Error::RingEnter(libc::EBUSY)) => break,
                            Err(e) => panic!("Failed to submit ops: {}", e),
                        }
                    }
                }
            }));
        }

        let completed = Arc::new(AtomicUsize::new(0));
        for _ in 0..NUM_COMPLETERS {
            let uring = uring.clone();
            let in_flight = in_flight.clone();
            let cv = cv.clone();
            let completed = completed.clone();
            threads.push(thread::spawn(move || {
                while completed.load(Ordering::Relaxed) < NUM_SUBMITTERS * ITERATIONS {
                    for (_, res) in uring.wait().unwrap() {
                        assert_eq!(res.unwrap(), 0);
                        completed.fetch_add(1, Ordering::Relaxed);

                        let mut in_flight = in_flight.lock();
                        *in_flight -= 1;
                        let notify_submitters = *in_flight <= NUM_ENTRIES as isize;
                        mem::drop(in_flight);

                        if notify_submitters {
                            cv.notify_all();
                        }

                        if completed.load(Ordering::Relaxed) >= NUM_SUBMITTERS * ITERATIONS {
                            break;
                        }
                    }
                }
            }));
        }

        for t in threads.drain(..NUM_SUBMITTERS) {
            t.join().unwrap();
        }

        // Now that all submitters are finished, add NOPs to wake up any completers blocked on the
        // syscall.
        for i in 0..NUM_COMPLETERS {
            uring
                .add_nop((NUM_SUBMITTERS * ITERATIONS + i) as UserData)
                .unwrap();
        }
        uring.submit().unwrap();

        for t in threads {
            t.join().unwrap();
        }

        // Make sure we didn't submit more entries than expected. Only the last few NOPs added to
        // wake up the completer threads may still be in the completion ring.
        assert!(uring.complete_ring.num_ready() <= NUM_COMPLETERS as u32);
        assert_eq!(
            in_flight.lock().unsigned_abs() as u32 + uring.complete_ring.num_ready(),
            NUM_COMPLETERS as u32
        );
        assert_eq!(uring.submit_ring.lock().added, 0);
        assert_eq!(
            uring.stats.total_ops.load(Ordering::Relaxed),
            (NUM_SUBMITTERS * ITERATIONS + NUM_COMPLETERS) as u64
        );
    }
}
