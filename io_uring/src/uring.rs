// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file makes several casts from u8 pointers into more-aligned pointer types.
// We assume that the kernel will give us suitably aligned memory.
#![allow(clippy::cast_ptr_alignment)]

use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::ptr::null_mut;
use std::sync::atomic::{AtomicU32, Ordering};

use sys_util::{MappedRegion, MemoryMapping, WatchingEvents};

use crate::bindings::*;
use crate::syscalls::*;

/// Holds per-operation, user specified data. The usage is up to the caller. The most common use is
/// for callers to identify each request.
pub type UserData = u64;

#[derive(Debug)]
pub enum Error {
    /// The call to `io_uring_enter` failed with the given errno.
    RingEnter(libc::c_int),
    /// The call to `io_uring_setup` failed with the given errno.
    Setup(libc::c_int),
    /// Failed to map the completion ring.
    MappingCompleteRing(sys_util::MmapError),
    /// Failed to map the submit ring.
    MappingSubmitRing(sys_util::MmapError),
    /// Failed to map submit entries.
    MappingSubmitEntries(sys_util::MmapError),
    /// Too many ops are already queued.
    NoSpace,
}
pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            RingEnter(e) => write!(f, "Failed to enter io uring {}", e),
            Setup(e) => write!(f, "Failed to setup io uring {}", e),
            MappingCompleteRing(e) => write!(f, "Failed to mmap completion ring {}", e),
            MappingSubmitRing(e) => write!(f, "Failed to mmap submit ring {}", e),
            MappingSubmitEntries(e) => write!(f, "Failed to mmap submit entries {}", e),
            NoSpace => write!(
                f,
                "No space for more ring entries, try increasing the size passed to `new`",
            ),
        }
    }
}

/// Basic statistics about the operations that have been submitted to the uring.
#[derive(Default)]
pub struct URingStats {
    total_enter_calls: u64, // Number of times the uring has been entered.
    total_ops: u64,         // Total ops submitted to io_uring.
    total_complete: u64,    // Total ops completed by io_uring.
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
/// # use sys_util::WatchingEvents;
/// # use io_uring::URingContext;
/// let f = File::open(Path::new("/dev/zero")).unwrap();
/// let mut uring = URingContext::new(16).unwrap();
/// uring
///   .add_poll_fd(f.as_raw_fd(), &WatchingEvents::empty().set_read(), 454)
/// .unwrap();
/// let (user_data, res) = uring.wait().unwrap().next().unwrap();
/// assert_eq!(user_data, 454 as io_uring::UserData);
/// assert_eq!(res.unwrap(), 1 as u32);
///
/// ```
pub struct URingContext {
    ring_file: File, // Holds the io_uring context FD returned from io_uring_setup.
    submit_ring: SubmitQueueState,
    submit_queue_entries: SubmitQueueEntries,
    complete_ring: CompleteQueueState,
    io_vecs: Vec<libc::iovec>,
    in_flight: usize, // The number of pending operations.
    added: usize,     // The number of ops added since the last call to `io_uring_enter`.
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
                MemoryMapping::from_fd_offset_populate(
                    &ring_file,
                    ring_params.sq_off.array as usize
                        + ring_params.sq_entries as usize * std::mem::size_of::<u32>(),
                    u64::from(IORING_OFF_SQ_RING),
                )
                .map_err(Error::MappingSubmitRing)?,
                &ring_params,
            );

            let num_sqe = ring_params.sq_entries as usize;
            let submit_queue_entries = SubmitQueueEntries {
                mmap: MemoryMapping::from_fd_offset_populate(
                    &ring_file,
                    ring_params.sq_entries as usize * std::mem::size_of::<io_uring_sqe>(),
                    u64::from(IORING_OFF_SQES),
                )
                .map_err(Error::MappingSubmitEntries)?,
                len: num_sqe,
            };

            let complete_ring = CompleteQueueState::new(
                MemoryMapping::from_fd_offset_populate(
                    &ring_file,
                    ring_params.cq_off.cqes as usize
                        + ring_params.cq_entries as usize * std::mem::size_of::<io_uring_cqe>(),
                    u64::from(IORING_OFF_CQ_RING),
                )
                .map_err(Error::MappingCompleteRing)?,
                &ring_params,
            );

            Ok(URingContext {
                ring_file,
                submit_ring,
                submit_queue_entries,
                complete_ring,
                io_vecs: vec![
                    libc::iovec {
                        iov_base: null_mut(),
                        iov_len: 0
                    };
                    num_sqe
                ],
                added: 0,
                in_flight: 0,
                stats: Default::default(),
            })
        }
    }

    // Call `f` with the next available sqe or return an error if none are available.
    // After `f` returns, the sqe is appended to the kernel's queue.
    fn prep_next_sqe<F>(&mut self, mut f: F) -> Result<()>
    where
        F: FnMut(&mut io_uring_sqe, &mut libc::iovec),
    {
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

        f(sqe, &mut self.io_vecs[index]);

        // Tells the kernel to use the new index when processing the entry at that index.
        self.submit_ring.set_array_entry(index, index as u32);
        // Ensure the above writes to sqe are seen before the tail is updated.
        // set_tail uses Release ordering when storing to the ring.
        self.submit_ring.pointers.set_tail(next_tail);

        self.added += 1;

        Ok(())
    }

    unsafe fn add_rw_op(
        &mut self,
        ptr: *const u8,
        len: usize,
        fd: RawFd,
        offset: u64,
        user_data: UserData,
        op: u8,
    ) -> Result<()> {
        self.prep_next_sqe(|sqe, iovec| {
            iovec.iov_base = ptr as *const libc::c_void as *mut _;
            iovec.iov_len = len;
            sqe.opcode = op;
            sqe.addr = iovec as *const _ as *const libc::c_void as u64;
            sqe.len = 1;
            sqe.__bindgen_anon_1.off = offset;
            sqe.__bindgen_anon_3.__bindgen_anon_1.buf_index = 0;
            sqe.ioprio = 0;
            sqe.user_data = user_data;
            sqe.flags = 0;
            sqe.fd = fd;
        })?;

        Ok(())
    }

    /// Asynchronously writes to `fd` from the address given in `ptr`.
    /// # Safety
    /// `add_write` will write up to `len` bytes of data from the address given by `ptr`. This is
    /// only safe if the caller guarantees that the memory lives until the transaction is complete
    /// and that completion has been returned from the `wait` function. In addition there must not
    /// be other references to the data pointed to by `ptr` until the operation completes.  Ensure
    /// that the fd remains open until the op completes as well.
    pub unsafe fn add_write(
        &mut self,
        ptr: *const u8,
        len: usize,
        fd: RawFd,
        offset: u64,
        user_data: UserData,
    ) -> Result<()> {
        self.add_rw_op(ptr, len, fd, offset, user_data, IORING_OP_WRITEV as u8)
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
        &mut self,
        ptr: *mut u8,
        len: usize,
        fd: RawFd,
        offset: u64,
        user_data: UserData,
    ) -> Result<()> {
        self.add_rw_op(ptr, len, fd, offset, user_data, IORING_OP_READV as u8)
    }

    /// See 'writev' but accepts an iterator instead of a vector if there isn't already a vector in
    /// existence.
    pub unsafe fn add_writev_iter<I>(
        &mut self,
        iovecs: I,
        fd: RawFd,
        offset: u64,
        user_data: UserData,
    ) -> Result<()>
    where
        I: Iterator<Item = libc::iovec>,
    {
        self.add_writev(iovecs.collect(), fd, offset, user_data)
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
        &mut self,
        iovecs: Vec<libc::iovec>,
        fd: RawFd,
        offset: u64,
        user_data: UserData,
    ) -> Result<()> {
        self.prep_next_sqe(|sqe, _iovec| {
            sqe.opcode = IORING_OP_WRITEV as u8;
            sqe.addr = iovecs.as_ptr() as *const _ as *const libc::c_void as u64;
            sqe.len = iovecs.len() as u32;
            sqe.__bindgen_anon_1.off = offset;
            sqe.__bindgen_anon_3.__bindgen_anon_1.buf_index = 0;
            sqe.ioprio = 0;
            sqe.user_data = user_data;
            sqe.flags = 0;
            sqe.fd = fd;
        })?;
        self.complete_ring.add_op_data(user_data, iovecs);
        Ok(())
    }

    /// See 'readv' but accepts an iterator instead of a vector if there isn't already a vector in
    /// existence.
    pub unsafe fn add_readv_iter<I>(
        &mut self,
        iovecs: I,
        fd: RawFd,
        offset: u64,
        user_data: UserData,
    ) -> Result<()>
    where
        I: Iterator<Item = libc::iovec>,
    {
        self.add_readv(iovecs.collect(), fd, offset, user_data)
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
        &mut self,
        iovecs: Vec<libc::iovec>,
        fd: RawFd,
        offset: u64,
        user_data: UserData,
    ) -> Result<()> {
        self.prep_next_sqe(|sqe, _iovec| {
            sqe.opcode = IORING_OP_READV as u8;
            sqe.addr = iovecs.as_ptr() as *const _ as *const libc::c_void as u64;
            sqe.len = iovecs.len() as u32;
            sqe.__bindgen_anon_1.off = offset;
            sqe.__bindgen_anon_3.__bindgen_anon_1.buf_index = 0;
            sqe.ioprio = 0;
            sqe.user_data = user_data;
            sqe.flags = 0;
            sqe.fd = fd;
        })?;
        self.complete_ring.add_op_data(user_data, iovecs);
        Ok(())
    }

    /// Syncs all completed operations, the ordering with in-flight async ops is not
    /// defined.
    pub fn add_fsync(&mut self, fd: RawFd, user_data: UserData) -> Result<()> {
        self.prep_next_sqe(|sqe, _iovec| {
            sqe.opcode = IORING_OP_FSYNC as u8;
            sqe.fd = fd;
            sqe.user_data = user_data;

            sqe.addr = 0;
            sqe.len = 0;
            sqe.__bindgen_anon_1.off = 0;
            sqe.__bindgen_anon_3.__bindgen_anon_1.buf_index = 0;
            sqe.__bindgen_anon_2.rw_flags = 0;
            sqe.ioprio = 0;
            sqe.flags = 0;
        })
    }

    /// See the usage of `fallocate`, this asynchronously performs the same operations.
    pub fn add_fallocate(
        &mut self,
        fd: RawFd,
        offset: u64,
        len: u64,
        mode: u32,
        user_data: UserData,
    ) -> Result<()> {
        // Note that len for fallocate in passed in the addr field of the sqe and the mode uses the
        // len field.
        self.prep_next_sqe(|sqe, _iovec| {
            sqe.opcode = IORING_OP_FALLOCATE as u8;

            sqe.fd = fd;
            sqe.addr = len;
            sqe.len = mode;
            sqe.__bindgen_anon_1.off = offset;
            sqe.user_data = user_data;

            sqe.__bindgen_anon_3.__bindgen_anon_1.buf_index = 0;
            sqe.__bindgen_anon_2.rw_flags = 0;
            sqe.ioprio = 0;
            sqe.flags = 0;
        })
    }

    /// Adds an FD to be polled based on the given flags.
    /// The user must keep the FD open until the operation completion is returned from
    /// `wait`.
    /// Note that io_uring is always a one shot poll. After the fd is returned, it must be re-added
    /// to get future events.
    pub fn add_poll_fd(
        &mut self,
        fd: RawFd,
        events: &WatchingEvents,
        user_data: UserData,
    ) -> Result<()> {
        self.prep_next_sqe(|sqe, _iovec| {
            sqe.opcode = IORING_OP_POLL_ADD as u8;
            sqe.fd = fd;
            sqe.user_data = user_data;
            sqe.__bindgen_anon_2.poll_events = events.get_raw() as u16;

            sqe.addr = 0;
            sqe.len = 0;
            sqe.__bindgen_anon_1.off = 0;
            sqe.__bindgen_anon_3.__bindgen_anon_1.buf_index = 0;
            sqe.ioprio = 0;
            sqe.flags = 0;
        })
    }

    /// Removes an FD that was previously added with `add_poll_fd`.
    pub fn remove_poll_fd(
        &mut self,
        fd: RawFd,
        events: &WatchingEvents,
        user_data: UserData,
    ) -> Result<()> {
        self.prep_next_sqe(|sqe, _iovec| {
            sqe.opcode = IORING_OP_POLL_REMOVE as u8;
            sqe.fd = fd;
            sqe.user_data = user_data;
            sqe.__bindgen_anon_2.poll_events = events.get_raw() as u16;

            sqe.addr = 0;
            sqe.len = 0;
            sqe.__bindgen_anon_1.off = 0;
            sqe.__bindgen_anon_3.__bindgen_anon_1.buf_index = 0;
            sqe.ioprio = 0;
            sqe.flags = 0;
        })
    }

    /// Sends operations added with the `add_*` functions to the kernel.
    pub fn submit(&mut self) -> Result<()> {
        self.in_flight += self.added;
        self.stats.total_ops = self.stats.total_ops.wrapping_add(self.added as u64);
        if self.added > 0 {
            self.stats.total_enter_calls = self.stats.total_enter_calls.wrapping_add(1);
            unsafe {
                // Safe because the only memory modified is in the completion queue.
                io_uring_enter(self.ring_file.as_raw_fd(), self.added as u64, 0, 0)
                    .map_err(Error::RingEnter)?;
            }
        }
        self.added = 0;

        Ok(())
    }

    /// Sends operations added with the `add_*` functions to the kernel and return an iterator to any
    /// completed operations. `wait` blocks until at least one completion is ready.  If called
    /// without any new events added, this simply waits for any existing events to complete and
    /// returns as soon an one or more is ready.
    pub fn wait<'a>(
        &'a mut self,
    ) -> Result<impl Iterator<Item = (UserData, std::io::Result<u32>)> + 'a> {
        let completed = self.complete_ring.num_completed();
        self.stats.total_complete = self.stats.total_complete.wrapping_add(completed as u64);
        self.in_flight -= completed;
        self.in_flight += self.added;
        self.stats.total_ops = self.stats.total_ops.wrapping_add(self.added as u64);
        if self.in_flight > 0 {
            unsafe {
                self.stats.total_enter_calls = self.stats.total_enter_calls.wrapping_add(1);
                // Safe because the only memory modified is in the completion queue.
                io_uring_enter(
                    self.ring_file.as_raw_fd(),
                    self.added as u64,
                    1,
                    IORING_ENTER_GETEVENTS,
                )
                .map_err(Error::RingEnter)?;
            }
        }
        self.added = 0;

        // The CompletionQueue will iterate all completed ops.
        Ok(&mut self.complete_ring)
    }
}

impl AsRawFd for URingContext {
    fn as_raw_fd(&self) -> RawFd {
        self.ring_file.as_raw_fd()
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
    array: *mut u32,
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
        let array = ptr.add(params.sq_off.array as usize) as *mut u32;
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
            std::ptr::write_volatile(self.array.add(index), value as u32);
        }
    }
}

struct CompleteQueueState {
    mmap: MemoryMapping,
    pointers: QueuePointers,
    ring_mask: u32,
    cqes_offset: u32,
    completed: usize,
    //For ops that pass in arrays of iovecs, they need to be valid for the duration of the
    //operation because the kernel might read them at any time.
    pending_op_addrs: BTreeMap<UserData, Vec<libc::iovec>>,
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
            completed: 0,
            pending_op_addrs: BTreeMap::new(),
        }
    }

    fn add_op_data(&mut self, user_data: UserData, addrs: Vec<libc::iovec>) {
        self.pending_op_addrs.insert(user_data, addrs);
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

    fn num_completed(&mut self) -> usize {
        std::mem::replace(&mut self.completed, 0)
    }
}

// Return the completed ops with their result.
impl Iterator for CompleteQueueState {
    type Item = (UserData, std::io::Result<u32>);

    fn next(&mut self) -> Option<Self::Item> {
        // Safe because the pointers to the atomics are valid and the cqe must be in range
        // because the kernel provided mask is applied to the index.
        let head = self.pointers.head(Ordering::Relaxed);

        // Synchronize the read of tail after the read of head.
        if head == self.pointers.tail(Ordering::Acquire) {
            return None;
        }

        self.completed += 1;

        let cqe = self.get_cqe(head);
        let user_data = cqe.user_data;
        let res = cqe.res;

        // free the addrs saved for this op.
        let _ = self.pending_op_addrs.remove(&user_data);

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

struct QueuePointers {
    head: *const AtomicU32,
    tail: *const AtomicU32,
}

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
    use std::fs::OpenOptions;
    use std::io::{IoSlice, IoSliceMut};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use sys_util::PollContext;
    use tempfile::TempDir;

    use super::*;

    fn append_file_name(path: &Path, name: &str) -> PathBuf {
        let mut joined = path.to_path_buf();
        joined.push(name);
        joined
    }

    fn check_one_read(
        uring: &mut URingContext,
        buf: &mut [u8],
        fd: RawFd,
        offset: u64,
        user_data: UserData,
    ) {
        let (user_data_ret, res) = unsafe {
            // Safe because the `wait` call waits until the kernel is done with `buf`.
            uring
                .add_read(buf.as_mut_ptr(), buf.len(), fd, offset, user_data)
                .unwrap();
            uring.wait().unwrap().next().unwrap()
        };
        assert_eq!(user_data_ret, user_data);
        assert_eq!(res.unwrap(), buf.len() as u32);
    }

    fn check_one_readv(
        uring: &mut URingContext,
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
                .collect::<Vec<libc::iovec>>()
        };
        let (user_data_ret, res) = unsafe {
            // Safe because the `wait` call waits until the kernel is done with `buf`.
            uring
                .add_readv_iter(io_vecs.into_iter(), fd, offset, user_data)
                .unwrap();
            uring.wait().unwrap().next().unwrap()
        };
        assert_eq!(user_data_ret, user_data);
        assert_eq!(res.unwrap(), buf.len() as u32);
    }

    fn create_test_file(temp_dir: &TempDir, size: u64) -> std::fs::File {
        let file_path = append_file_name(temp_dir.path(), "test");
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&file_path)
            .unwrap();
        f.set_len(size).unwrap();
        f
    }

    #[test]
    // Queue as many reads as possible and then collect the completions.
    fn read_parallel() {
        let temp_dir = TempDir::new().unwrap();
        const QUEUE_SIZE: usize = 10;
        const BUF_SIZE: usize = 0x1000;

        let mut uring = URingContext::new(QUEUE_SIZE).unwrap();
        let mut buf = [0u8; BUF_SIZE * QUEUE_SIZE];
        let f = create_test_file(&temp_dir, (BUF_SIZE * QUEUE_SIZE) as u64);

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
                    offset as u64,
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
        let temp_dir = TempDir::new().unwrap();
        let queue_size = 128;

        let mut uring = URingContext::new(queue_size).unwrap();
        let mut buf = [0u8; 0x1000];
        let f = create_test_file(&temp_dir, 0x1000 * 2);

        // check that the whole file can be read and that the queues wrapping is handled by reading
        // double the quue depth of buffers.
        for i in 0..queue_size * 2 {
            let index = i as u64;
            check_one_read(
                &mut uring,
                &mut buf,
                f.as_raw_fd(),
                (index % 2) * 0x1000,
                index,
            );
            check_one_readv(
                &mut uring,
                &mut buf,
                f.as_raw_fd(),
                (index % 2) * 0x1000,
                index,
            );
        }
    }

    #[test]
    fn readv_vec() {
        let temp_dir = TempDir::new().unwrap();
        let queue_size = 128;
        const BUF_SIZE: usize = 0x2000;

        let mut uring = URingContext::new(queue_size).unwrap();
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
        let f = create_test_file(&temp_dir, total_len as u64 * 2);
        let (user_data_ret, res) = unsafe {
            // Safe because the `wait` call waits until the kernel is done with `buf`.
            uring
                .add_readv_iter(io_vecs.into_iter(), f.as_raw_fd(), 0, 55)
                .unwrap();
            uring.wait().unwrap().next().unwrap()
        };
        assert_eq!(user_data_ret, 55);
        assert_eq!(res.unwrap(), total_len as u32);
    }

    #[test]
    fn write_one_block() {
        let tempdir = TempDir::new().unwrap();
        let file_path = append_file_name(tempdir.path(), "test");

        let mut uring = URingContext::new(16).unwrap();
        let mut buf = [0u8; 4096];
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&file_path)
            .unwrap();
        f.write(&buf).unwrap();
        f.write(&buf).unwrap();

        unsafe {
            // Safe because the `wait` call waits until the kernel is done mutating `buf`.
            uring
                .add_write(buf.as_mut_ptr(), buf.len(), f.as_raw_fd(), 0, 55)
                .unwrap();
            let (user_data, res) = uring.wait().unwrap().next().unwrap();
            assert_eq!(user_data, 55 as UserData);
            assert_eq!(res.unwrap(), buf.len() as u32);
        }
    }

    #[test]
    fn write_one_submit_poll() {
        let tempdir = TempDir::new().unwrap();
        let file_path = append_file_name(tempdir.path(), "test");

        let mut uring = URingContext::new(16).unwrap();
        let mut buf = [0u8; 4096];
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&file_path)
            .unwrap();
        f.write(&buf).unwrap();
        f.write(&buf).unwrap();

        let ctx: PollContext<u64> = PollContext::build_with(&[(&uring, 1)]).unwrap();
        {
            // Test that the uring context isn't readable before any events are complete.
            let events = ctx.wait_timeout(Duration::from_millis(1)).unwrap();
            assert!(events.iter_readable().next().is_none());
        }

        unsafe {
            // Safe because the `wait` call waits until the kernel is done mutating `buf`.
            uring
                .add_write(buf.as_mut_ptr(), buf.len(), f.as_raw_fd(), 0, 55)
                .unwrap();
            uring.submit().unwrap();
            // Poll for completion with epoll.
            let events = ctx.wait().unwrap();
            let event = events.iter_readable().next().unwrap();
            assert_eq!(event.token(), 1);
            let (user_data, res) = uring.wait().unwrap().next().unwrap();
            assert_eq!(user_data, 55 as UserData);
            assert_eq!(res.unwrap(), buf.len() as u32);
        }
    }

    #[test]
    fn writev_vec() {
        let temp_dir = TempDir::new().unwrap();
        let queue_size = 128;
        const BUF_SIZE: usize = 0x2000;
        const OFFSET: u64 = 0x2000;

        let mut uring = URingContext::new(queue_size).unwrap();
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
        let mut f = create_test_file(&temp_dir, total_len as u64 * 2);
        let (user_data_ret, res) = unsafe {
            // Safe because the `wait` call waits until the kernel is done with `buf`.
            uring
                .add_writev_iter(io_vecs.into_iter(), f.as_raw_fd(), OFFSET, 55)
                .unwrap();
            uring.wait().unwrap().next().unwrap()
        };
        assert_eq!(user_data_ret, 55);
        assert_eq!(res.unwrap(), total_len as u32);

        let mut read_back = [0u8; BUF_SIZE];
        f.seek(SeekFrom::Start(OFFSET)).unwrap();
        f.read(&mut read_back).unwrap();
        assert!(!read_back.iter().any(|&b| b != 0xaa));
        f.read(&mut read_back).unwrap();
        assert!(!read_back.iter().any(|&b| b != 0xff));
        f.read(&mut read_back).unwrap();
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
            f.write(&buf).unwrap();
        }

        let init_size = std::fs::metadata(&file_path).unwrap().len() as usize;
        let set_size = init_size + 1024 * 1024 * 50;
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&file_path)
            .unwrap();

        let mut uring = URingContext::new(16).unwrap();
        uring
            .add_fallocate(f.as_raw_fd(), 0, set_size as u64, 0, 66)
            .unwrap();
        let (user_data, res) = uring.wait().unwrap().next().unwrap();
        assert_eq!(user_data, 66 as UserData);
        match res {
            Err(e) => {
                if e.kind() == std::io::ErrorKind::InvalidInput {
                    // skip on kernels that don't support fallocate.
                    return;
                }
                panic!("Unexpected fallocate error: {}", e);
            }
            Ok(val) => assert_eq!(val, 0 as u32),
        }

        // Add a few writes and then fsync
        let buf = [0u8; 4096];
        let mut pending = std::collections::BTreeSet::new();
        unsafe {
            uring
                .add_write(buf.as_ptr(), buf.len(), f.as_raw_fd(), 0, 67)
                .unwrap();
            pending.insert(67u64);
            uring
                .add_write(buf.as_ptr(), buf.len(), f.as_raw_fd(), 4096, 68)
                .unwrap();
            pending.insert(68);
            uring
                .add_write(buf.as_ptr(), buf.len(), f.as_raw_fd(), 8192, 69)
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
        assert_eq!(user_data, 68 as UserData);
        assert_eq!(res.unwrap(), 0 as u32);

        drop(f); // Close to ensure directory entires for metadata are updated.

        let new_size = std::fs::metadata(&file_path).unwrap().len() as usize;
        assert_eq!(new_size, set_size);
    }

    #[test]
    fn dev_zero_readable() {
        let f = File::open(Path::new("/dev/zero")).unwrap();
        let mut uring = URingContext::new(16).unwrap();
        uring
            .add_poll_fd(f.as_raw_fd(), &WatchingEvents::empty().set_read(), 454)
            .unwrap();
        let (user_data, res) = uring.wait().unwrap().next().unwrap();
        assert_eq!(user_data, 454 as UserData);
        assert_eq!(res.unwrap(), 1 as u32);
    }
}
