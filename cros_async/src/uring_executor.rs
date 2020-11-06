// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! `URingExecutor`
//!
//! The executor runs all given futures to completion. Futures register wakers associated with
//! io_uring operations. A waker is called when the set of uring ops the waker is waiting on
//! completes.
//!
//! `URingExecutor` is meant to be used with the `futures-rs` crate that provides combinators and
//! utility functions to combine futures. In general, the interface provided by `URingExecutor`
//! shouldn't be used directly. Instead, use them by interacting with implementors of `IoSource`,
//! and the high-level future functions.
//!
//!
//! ## Read/Write buffer management.
//!
//! There are two key issues managing asynchronous IO buffers in rust.
//! 1) The kernel has a mutable reference to the memory until the completion is returned. Rust must
//! not have any references to it during that time.
//! 2) The memory must remain valid as long as the kernel has a reference to it.
//!
//! ### The kernel's mutable borrow of the buffer
//!
//! Because the buffers used for read and write must be passed to the kernel for an unknown
//! duration, the functions must maintain ownership of the memory.  The core of this problem is that
//! the lifetime of the future isn't tied to the scope in which the kernel can modify the buffer the
//! future has a reference to.  The buffer can be modified at any point from submission until the
//! operation completes. The operation can't be synchronously canceled when the future is dropped,
//! and Drop can't be used for safety guarantees. To ensure this never happens, only memory that
//! implements `BackingMemory` is accepted.  For implementors of `BackingMemory` the mut borrow
//! isn't an issue because those are already Ok with external modifications to the memory (Like a
//! `VolatileSlice`).
//!
//! ### Buffer lifetime
//!
//! What if the kernel's reference to the buffer outlives the buffer itself?  This could happen if a
//! read operation was submitted, then the memory is dropped.  To solve this, the executor takes an
//! Rc to the backing memory. Vecs being read to are also wrapped in an Rc before being passed to
//! the executor.  The executor holds the Rc and ensures all operations are complete before dropping
//! it, that guarantees the memory is valid for the duration.
//!
//! The buffers _have_ to be on the heap. Because we don't have a way to cancel a future if it is
//! dropped(can't rely on drop running), there is no way to ensure the kernel's buffer remains valid
//! until the operation completes unless the executor holds an Rc to the memory on the heap.
//!
//! ## Using `Vec` for reads/writes.
//!
//! There is a convenience wrapper `VecIoWrapper` provided for fully owned vectors. This type
//! ensures that only the kernel is allowed to access the `Vec` and wraps the the `Vec` in an Rc to
//! ensure it lives long enough.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::convert::TryInto;
use std::fmt::{self, Display};
use std::fs::File;
use std::future::Future;
use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::pin::Pin;
use std::rc::Rc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::task::Waker;
use std::task::{Context, Poll};

use futures::pin_mut;
use slab::Slab;

use io_uring::URingContext;
use sys_util::WatchingEvents;

use crate::executor::{ExecutableFuture, Executor, FutureList};
use crate::uring_mem::{BackingMemory, MemRegion};
use crate::waker::WakerToken;

#[derive(Debug)]
pub enum Error {
    /// Attempts to create two Executors on the same thread fail.
    AttemptedDuplicateExecutor,
    /// Failed to copy the FD for the polling context.
    DuplicatingFd(sys_util::Error),
    /// Failed accessing the thread local storage for wakers.
    InvalidContext,
    /// Invalid offset or length given for an iovec in backing memory.
    InvalidOffset,
    /// Invalid FD source specified.
    InvalidSource,
    /// Error doing the IO.
    Io(io::Error),
    /// Creating a context to wait on FDs failed.
    CreatingContext(io_uring::Error),
    /// Failed to remove the waker remove the polling context.
    RemovingWaker(io_uring::Error),
    /// Failed to submit the operation to the polling context.
    SubmittingOp(io_uring::Error),
    /// URingContext failure.
    URingContextError(io_uring::Error),
    /// Failed to submit or wait for io_uring events.
    URingEnter(io_uring::Error),
}
pub type Result<T> = std::result::Result<T, Error>;

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            AttemptedDuplicateExecutor => write!(f, "Cannot have two executors on one thread."),
            DuplicatingFd(e) => write!(f, "Failed to copy the FD for the polling context: {}", e),
            InvalidContext => write!(
                f,
                "Invalid context, was the Fd executor created successfully?"
            ),
            InvalidOffset => write!(f, "Invalid offset/len for getting an iovec."),
            InvalidSource => write!(f, "Invalid source, FD not registered for use."),
            Io(e) => write!(f, "Error during IO: {}", e),
            CreatingContext(e) => write!(f, "Error creating the fd waiting context: {}.", e),
            RemovingWaker(e) => write!(f, "Error removing from the URing context: {}.", e),
            SubmittingOp(e) => write!(f, "Error adding to the URing context: {}.", e),
            URingContextError(e) => write!(f, "URingContext failure: {}", e),
            URingEnter(e) => write!(f, "URing::enter: {}", e),
        }
    }
}

impl std::error::Error for Error {}

// Checks if the uring executor is available.
// Caches the result so that the check is only run once.
// Useful for falling back to the FD executor on pre-uring kernels.
pub(crate) fn use_uring() -> bool {
    const UNKNOWN: u32 = 0;
    const URING: u32 = 1;
    const FD: u32 = 2;
    static USE_URING: AtomicU32 = AtomicU32::new(UNKNOWN);
    match USE_URING.load(Ordering::Relaxed) {
        UNKNOWN => {
            // Create a dummy uring context to check that the kernel understands the syscalls.
            if URingContext::new(8).is_ok() {
                USE_URING.store(URING, Ordering::Relaxed);
                true
            } else {
                USE_URING.store(FD, Ordering::Relaxed);
                false
            }
        }
        URING => true,
        FD => false,
        _ => unreachable!("invalid use uring state"),
    }
}

/// Register a file and memory pair for buffered asynchronous operation.
pub fn register_source<F: AsRawFd>(fd: &F) -> Result<RegisteredSource> {
    RingWakerState::register_source(fd)
}

pub(crate) fn add_future(future: Pin<Box<dyn Future<Output = ()>>>) {
    NEW_FUTURES.with(|new_futures| {
        let mut new_futures = new_futures.borrow_mut();
        new_futures.push_back(ExecutableFuture::new(future));
    });
}

// Tracks active wakers and manages waking pending operations after completion.
thread_local!(static STATE: RefCell<Option<RingWakerState>> = RefCell::new(None));
// Tracks new futures that have been added while running the executor.
thread_local!(static NEW_FUTURES: RefCell<VecDeque<ExecutableFuture<()>>>
              = RefCell::new(VecDeque::new()));

// Tracks `RingWakerState` instances and prevents `RegisteredSource`s created by an older executor
// from affecting a newer one.
static GENERATION: AtomicU64 = AtomicU64::new(0);

pub struct RegisteredSource {
    generation: u64,
    tag: usize,

    // Since a `RegisteredSource` is associated with a thread-local executor, it cannot be Send or
    // Sync. However, negative trait impls are not supported yet so use an Rc, which is neither Send
    // nor Sync, to poison the struct. TODO: Consider using negative trait impls once
    // https://github.com/rust-lang/rust/issues/68318 is fixed.
    _block_send_sync: Rc<()>,
}

impl RegisteredSource {
    pub fn start_read_to_mem(
        &self,
        file_offset: u64,
        mem: Rc<dyn BackingMemory>,
        addrs: &[MemRegion],
    ) -> Result<PendingOperation> {
        let token = STATE.with(|state| {
            let mut state = state.borrow_mut();
            if let Some(state) = state.as_mut() {
                state.submit_read_to_vectored(self, mem, file_offset, addrs)
            } else {
                Err(Error::InvalidContext)
            }
        })?;

        Ok(PendingOperation {
            waker_token: Some(token),
        })
    }

    pub fn start_write_from_mem(
        &self,
        file_offset: u64,
        mem: Rc<dyn BackingMemory>,
        addrs: &[MemRegion],
    ) -> Result<PendingOperation> {
        let token = STATE.with(|state| {
            let mut state = state.borrow_mut();
            if let Some(state) = state.as_mut() {
                state.submit_write_from_vectored(self, mem, file_offset, addrs)
            } else {
                Err(Error::InvalidContext)
            }
        })?;

        Ok(PendingOperation {
            waker_token: Some(token),
        })
    }

    pub fn start_fallocate(&self, offset: u64, len: u64, mode: u32) -> Result<PendingOperation> {
        let token = STATE.with(|state| {
            let mut state = state.borrow_mut();
            if let Some(state) = state.as_mut() {
                state.submit_fallocate(self, offset, len, mode)
            } else {
                Err(Error::InvalidContext)
            }
        })?;

        Ok(PendingOperation {
            waker_token: Some(token),
        })
    }

    pub fn start_fsync(&self) -> Result<PendingOperation> {
        let token = STATE.with(|state| {
            let mut state = state.borrow_mut();
            if let Some(state) = state.as_mut() {
                state.submit_fsync(self)
            } else {
                Err(Error::InvalidContext)
            }
        })?;

        Ok(PendingOperation {
            waker_token: Some(token),
        })
    }

    pub fn poll_fd_readable(&self) -> Result<PendingOperation> {
        let events = WatchingEvents::empty().set_read();
        let token = STATE.with(|state| {
            let mut state = state.borrow_mut();
            if let Some(state) = state.as_mut() {
                state.submit_poll(self, &events)
            } else {
                Err(Error::InvalidContext)
            }
        })?;

        Ok(PendingOperation {
            waker_token: Some(token),
        })
    }

    pub fn poll_complete(&self, cx: &mut Context, op: &mut PendingOperation) -> Poll<Result<u32>> {
        pin_mut!(op);
        op.poll(cx)
    }
}

impl Drop for RegisteredSource {
    fn drop(&mut self) {
        let _ = RingWakerState::deregister_source(self);
    }
}

// An operation that has been submitted to the uring and is potentially being waited on.
struct OpData {
    _file: Rc<File>,
    _mem: Option<Rc<dyn BackingMemory>>,
    waker: Option<Waker>,
    canceled: bool,
}

// The current status of an operation that's been submitted to the uring.
enum OpStatus {
    Pending(OpData),
    Completed(Option<::std::io::Result<u32>>),
}

// Tracks active wakers and associates wakers with the futures that registered them.
struct RingWakerState {
    ctx: URingContext,
    ops: Slab<OpStatus>,
    registered_sources: Slab<Rc<File>>,
    generation: u64,
}

impl RingWakerState {
    fn new() -> Result<Self> {
        Ok(RingWakerState {
            ctx: URingContext::new(256).map_err(Error::CreatingContext)?,
            ops: Slab::with_capacity(256),
            registered_sources: Slab::with_capacity(256),
            generation: GENERATION.fetch_add(1, Ordering::Relaxed),
        })
    }

    fn register_source(fd: &dyn AsRawFd) -> Result<RegisteredSource> {
        Self::with(|state| {
            let duped_fd = unsafe {
                // Safe because duplicating an FD doesn't affect memory safety, and the dup'd FD
                // will only be added to the poll loop.
                File::from_raw_fd(dup_fd(fd.as_raw_fd())?)
            };
            let tag = state.registered_sources.insert(Rc::new(duped_fd));
            Ok(RegisteredSource {
                generation: state.generation,
                tag,
                _block_send_sync: Rc::new(()),
            })
        })?
    }

    fn deregister_source(source: &RegisteredSource) {
        // There isn't any need to pull pending ops out, the all have Rc's to the file and mem they
        // need.let them complete. deregister with pending ops is not a common path no need to
        // optimize that case yet.
        let _ = Self::with(|state| {
            if source.generation == state.generation {
                state.registered_sources.remove(source.tag);
            }
        });
    }

    fn submit_poll(
        &mut self,
        source: &RegisteredSource,
        events: &sys_util::WatchingEvents,
    ) -> Result<WakerToken> {
        let src = self
            .registered_sources
            .get(source.tag)
            .ok_or(Error::InvalidSource)?;
        let entry = self.ops.vacant_entry();
        let next_op_token = entry.key();
        self.ctx
            .add_poll_fd(src.as_raw_fd(), events, usize_to_u64(next_op_token))
            .map_err(Error::SubmittingOp)?;

        entry.insert(OpStatus::Pending(OpData {
            _file: Rc::clone(&src),
            _mem: None,
            waker: None,
            canceled: false,
        }));
        Ok(WakerToken(next_op_token))
    }

    fn submit_fallocate(
        &mut self,
        source: &RegisteredSource,
        offset: u64,
        len: u64,
        mode: u32,
    ) -> Result<WakerToken> {
        let src = self
            .registered_sources
            .get(source.tag)
            .ok_or(Error::InvalidSource)?;
        let entry = self.ops.vacant_entry();
        let next_op_token = entry.key();
        self.ctx
            .add_fallocate(
                src.as_raw_fd(),
                offset,
                len,
                mode,
                usize_to_u64(next_op_token),
            )
            .map_err(Error::SubmittingOp)?;

        entry.insert(OpStatus::Pending(OpData {
            _file: Rc::clone(&src),
            _mem: None,
            waker: None,
            canceled: false,
        }));
        Ok(WakerToken(next_op_token))
    }

    fn submit_fsync(&mut self, source: &RegisteredSource) -> Result<WakerToken> {
        let src = self
            .registered_sources
            .get(source.tag)
            .ok_or(Error::InvalidSource)?;
        let entry = self.ops.vacant_entry();
        let next_op_token = entry.key();
        self.ctx
            .add_fsync(src.as_raw_fd(), usize_to_u64(next_op_token))
            .map_err(Error::SubmittingOp)?;

        entry.insert(OpStatus::Pending(OpData {
            _file: Rc::clone(&src),
            _mem: None,
            waker: None,
            canceled: false,
        }));
        Ok(WakerToken(next_op_token))
    }

    fn submit_read_to_vectored(
        &mut self,
        source: &RegisteredSource,
        mem: Rc<dyn BackingMemory>,
        offset: u64,
        addrs: &[MemRegion],
    ) -> Result<WakerToken> {
        if addrs
            .iter()
            .any(|&mem_range| mem.get_iovec(mem_range).is_err())
        {
            return Err(Error::InvalidOffset);
        }

        let src = self
            .registered_sources
            .get(source.tag)
            .ok_or(Error::InvalidSource)?;

        // We can't insert the OpData into the slab yet because `iovecs` borrows `mem` below.
        let entry = self.ops.vacant_entry();
        let next_op_token = entry.key();

        // The addresses have already been validated, so unwrapping them will succeed.
        // validate their addresses before submitting.
        let iovecs = addrs
            .iter()
            .map(|&mem_range| mem.get_iovec(mem_range).unwrap().iovec());

        unsafe {
            // Safe because all the addresses are within the Memory that an Rc is kept for the
            // duration to ensure the memory is valid while the kernel accesses it.
            // Tested by `dont_drop_backing_mem_read` unit test.
            self.ctx
                .add_readv_iter(iovecs, src.as_raw_fd(), offset, usize_to_u64(next_op_token))
                .map_err(Error::SubmittingOp)?;
        }

        entry.insert(OpStatus::Pending(OpData {
            _file: Rc::clone(&src),
            _mem: Some(mem),
            waker: None,
            canceled: false,
        }));

        Ok(WakerToken(next_op_token))
    }

    fn submit_write_from_vectored(
        &mut self,
        source: &RegisteredSource,
        mem: Rc<dyn BackingMemory>,
        offset: u64,
        addrs: &[MemRegion],
    ) -> Result<WakerToken> {
        if addrs
            .iter()
            .any(|&mem_range| mem.get_iovec(mem_range).is_err())
        {
            return Err(Error::InvalidOffset);
        }

        let src = self
            .registered_sources
            .get(source.tag)
            .ok_or(Error::InvalidSource)?;

        // We can't insert the OpData into the slab yet because `iovecs` borrows `mem` below.
        let entry = self.ops.vacant_entry();
        let next_op_token = entry.key();

        // The addresses have already been validated, so unwrapping them will succeed.
        // validate their addresses before submitting.
        let iovecs = addrs
            .iter()
            .map(|&mem_range| mem.get_iovec(mem_range).unwrap().iovec());

        unsafe {
            // Safe because all the addresses are within the Memory that an Rc is kept for the
            // duration to ensure the memory is valid while the kernel accesses it.
            // Tested by `dont_drop_backing_mem_write` unit test.
            self.ctx
                .add_writev_iter(iovecs, src.as_raw_fd(), offset, usize_to_u64(next_op_token))
                .map_err(Error::SubmittingOp)?;
        }

        entry.insert(OpStatus::Pending(OpData {
            _file: Rc::clone(&src),
            _mem: Some(mem),
            waker: None,
            canceled: false,
        }));

        Ok(WakerToken(next_op_token))
    }

    // Remove the waker for the given token if it hasn't fired yet.
    fn cancel_waker(token: WakerToken) -> Result<()> {
        Self::with(|state| {
            if let Some(op) = state.ops.get_mut(token.0) {
                match op {
                    OpStatus::Pending(data) => {
                        if data.canceled {
                            panic!("uring operation canceled more than once");
                        }

                        // Clear the waker as it is no longer needed.
                        data.waker = None;
                        data.canceled = true;

                        // Keep the rest of the op data as the uring might still be accessing either
                        // the source of the backing memory so it needs to live until the kernel
                        // completes the operation.  TODO: cancel the operation in the uring.
                    }
                    OpStatus::Completed(_) => {
                        state.ops.remove(token.0);
                    }
                }
            }
            Ok(())
        })?
    }

    // Waits until one of the FDs is readable and wakes the associated waker.
    fn wait_wake_event() -> Result<()> {
        Self::with(|state| {
            let events = state.ctx.wait().map_err(Error::URingEnter)?;
            for (raw_token, result) in events {
                // While the `expect()` might fail on arbitrary `u64`s, the `raw_token` was
                // something that we originally gave to the kernel and that was created from a
                // `usize` so we should always be able to convert it back into a `usize`.
                let token = raw_token
                    .try_into()
                    .expect("`u64` doesn't fit inside a `usize`");

                if let Some(op) = state.ops.get_mut(token) {
                    match op {
                        OpStatus::Pending(data) => {
                            if data.canceled {
                                // No one is waiting for this operation and the uring is done with
                                // it so it's safe to remove.
                                state.ops.remove(token);
                            } else {
                                let waker = data.waker.take();
                                *op = OpStatus::Completed(Some(result));

                                if let Some(waker) = waker {
                                    waker.wake();
                                }
                            }
                        }
                        OpStatus::Completed(_) => {
                            panic!("uring operation completed more than once")
                        }
                    }
                }
            }
            Ok(())
        })?
    }

    fn get_result(token: &WakerToken, waker: Waker) -> Result<Option<io::Result<u32>>> {
        Self::with(|state| {
            if let Some(op) = state.ops.get_mut(token.0) {
                match op {
                    OpStatus::Pending(data) => {
                        if data.canceled {
                            panic!("`get_result` called on canceled operation");
                        }
                        data.waker = Some(waker);
                        None
                    }
                    OpStatus::Completed(res) => {
                        let out = res.take();
                        state.ops.remove(token.0);
                        out
                    }
                }
            } else {
                None
            }
        })
    }

    fn with<R, F: FnOnce(&mut RingWakerState) -> R>(f: F) -> Result<R> {
        STATE.with(|state| {
            if state.borrow().is_none() {
                state.replace(Some(RingWakerState::new()?));
            }
            state
                .borrow_mut()
                .as_mut()
                .map(f)
                .ok_or(Error::InvalidContext)
        })
    }
}

/// Runs futures to completion on a single thread. Futures are allowed to block on file descriptors
/// only. Futures can only block on FDs becoming readable or writable. `URingExecutor` is meant to
/// be used where a poll or select loop would be used otherwise.
pub(crate) struct URingExecutor<T: FutureList> {
    futures: T,
}

impl<T: FutureList> Executor for URingExecutor<T> {
    type Output = Result<T::Output>;

    fn run(&mut self) -> Self::Output {
        self.append_futures();

        loop {
            if let Some(output) = self.futures.poll_results() {
                return Ok(output);
            }

            self.append_futures();

            // If no futures are ready, sleep until a waker is signaled.
            if !self.futures.any_ready() {
                RingWakerState::wait_wake_event()?;
            }
        }
    }
}

impl<T: FutureList> URingExecutor<T> {
    /// Create a new executor.
    pub fn new(futures: T) -> Result<URingExecutor<T>> {
        RingWakerState::with(|_| ())?;
        Ok(URingExecutor { futures })
    }

    // Add any new futures and wakers to the lists.
    fn append_futures(&mut self) {
        NEW_FUTURES.with(|new_futures| {
            let mut new_futures = new_futures.borrow_mut();
            self.futures.futures_mut().append(&mut new_futures);
        })
    }
}

impl<T: FutureList> Drop for URingExecutor<T> {
    fn drop(&mut self) {
        STATE.with(|state| {
            state.replace(None);
        });
        // Drop any pending futures that were added.
        NEW_FUTURES.with(|new_futures| {
            let mut new_futures = new_futures.borrow_mut();
            new_futures.clear();
        });
    }
}

// Used to dup the FDs passed to the executor so there is a guarantee they aren't closed while
// waiting in TLS to be added to the main polling context.
unsafe fn dup_fd(fd: RawFd) -> Result<RawFd> {
    let ret = libc::dup(fd);
    if ret < 0 {
        Err(Error::DuplicatingFd(sys_util::Error::last()))
    } else {
        Ok(ret)
    }
}

// Converts a `usize` into a `u64` and panics if the conversion fails.
#[inline]
fn usize_to_u64(val: usize) -> u64 {
    val.try_into().expect("`usize` doesn't fit inside a `u64`")
}

#[derive(Debug)]
pub struct PendingOperation {
    waker_token: Option<WakerToken>,
}

impl Future for PendingOperation {
    type Output = Result<u32>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        if let Some(waker_token) = &self.waker_token {
            if let Some(result) = RingWakerState::get_result(waker_token, cx.waker().clone())? {
                self.waker_token = None;
                return Poll::Ready(result.map_err(Error::Io));
            }
        }
        Poll::Pending
    }
}

impl Drop for PendingOperation {
    fn drop(&mut self) {
        if let Some(waker_token) = self.waker_token.take() {
            let _ = RingWakerState::cancel_waker(waker_token);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::mem;

    use super::*;
    use crate::uring_mem::{BackingMemory, MemRegion, VecIoWrapper};

    #[test]
    fn dont_drop_backing_mem_read() {
        // Create a backing memory wrapped in an Rc and check that the drop isn't called while the
        // op is pending.
        let bm = Rc::new(VecIoWrapper::from(vec![0u8; 4096])) as Rc<dyn BackingMemory>;

        // Use pipes to create a future that will block forever.
        let (rx, mut tx) = sys_util::pipe(true).unwrap();

        // Set up the TLS for the uring_executor by creating one.
        let _ex = URingExecutor::new(crate::executor::UnitFutures::new()).unwrap();

        // Register the receive side of the pipe with the executor.
        let registered_source = register_source(&rx).expect("register source failed");

        // Submit the op to the kernel. Next, test that the source keeps its Rc open for the duration
        // of the op.
        let pending_op = registered_source
            .start_read_to_mem(0, Rc::clone(&bm), &[MemRegion { offset: 0, len: 8 }])
            .expect("failed to start read to mem");

        // Here the Rc count must be two, one for `bm` and one to signify that the kernel has a
        // reference while the op is active.
        assert_eq!(Rc::strong_count(&bm), 2);

        // Dropping the operation shouldn't reduce the Rc count, as the kernel could still be using
        // it.
        drop(pending_op);
        assert_eq!(Rc::strong_count(&bm), 2);

        // Finishing the operation should put the Rc count back to 1.
        // write to the pipe to wake the read pipe and then wait for the uring result in the
        // executor.
        tx.write(&[0u8; 8]).expect("write failed");
        RingWakerState::wait_wake_event().expect("Failed to wait for read pipe ready");
        assert_eq!(Rc::strong_count(&bm), 1);
    }

    #[test]
    fn dont_drop_backing_mem_write() {
        // Create a backing memory wrapped in an Rc and check that the drop isn't called while the
        // op is pending.
        let bm = Rc::new(VecIoWrapper::from(vec![0u8; 4096])) as Rc<dyn BackingMemory>;

        // Use pipes to create a future that will block forever.
        let (mut rx, tx) = sys_util::new_pipe_full().expect("Pipe failed");

        // Set up the TLS for the uring_executor by creating one.
        let _ex = URingExecutor::new(crate::executor::UnitFutures::new()).unwrap();

        // Register the receive side of the pipe with the executor.
        let registered_source = register_source(&tx).expect("register source failed");

        // Submit the op to the kernel. Next, test that the source keeps its Rc open for the duration
        // of the op.
        let pending_op = registered_source
            .start_write_from_mem(0, Rc::clone(&bm), &[MemRegion { offset: 0, len: 8 }])
            .expect("failed to start write to mem");

        // Here the Rc count must be two, one for `bm` and one to signify that the kernel has a
        // reference while the op is active.
        assert_eq!(Rc::strong_count(&bm), 2);

        // Dropping the operation shouldn't reduce the Rc count, as the kernel could still be using
        // it.
        drop(pending_op);
        assert_eq!(Rc::strong_count(&bm), 2);

        // Finishing the operation should put the Rc count back to 1.
        // write to the pipe to wake the read pipe and then wait for the uring result in the
        // executor.
        let mut buf = vec![0u8; sys_util::round_up_to_page_size(1)];
        rx.read(&mut buf).expect("read to empty failed");
        RingWakerState::wait_wake_event().expect("Failed to wait for read pipe ready");
        assert_eq!(Rc::strong_count(&bm), 1);
    }

    #[test]
    fn registered_source_outlives_executor() {
        let bm = Rc::new(VecIoWrapper::from(vec![0u8; 4096])) as Rc<dyn BackingMemory>;
        let (rx, tx) = sys_util::pipe(true).unwrap();

        // Register a source before creating the executor.
        let rx_source = register_source(&rx).expect("register source failed");

        let ex = URingExecutor::new(crate::executor::UnitFutures::new()).unwrap();
        let _pending_op = rx_source
            .start_read_to_mem(0, Rc::clone(&bm), &[MemRegion { offset: 0, len: 8 }])
            .expect("failed to start read to mem");

        // Now drop the executor without finishing the operation.
        mem::drop(ex);

        // Register another source.
        let tx_source = register_source(&tx).expect("register source failed");

        assert!(RingWakerState::with(|state| state
            .registered_sources
            .get(tx_source.tag)
            .is_some())
        .expect("failed to check registered source"));

        // Since they were created by separate executors, they should both have the same tag.
        assert_eq!(tx_source.tag, rx_source.tag);

        // Dropping `rx_source` shouldn't affect `tx_source`.
        mem::drop(rx_source);

        assert!(RingWakerState::with(|state| state
            .registered_sources
            .get(tx_source.tag)
            .is_some())
        .expect("failed to check registered source"));
    }

    #[test]
    fn canceled_before_completion() {
        async fn cancel_io(op: PendingOperation) {
            mem::drop(op);
        }

        async fn check_result(op: PendingOperation, expected: u32) {
            let actual = op.await.expect("operation failed to complete");
            assert_eq!(expected, actual);
        }

        let bm = Rc::new(VecIoWrapper::from(vec![0u8; 16])) as Rc<dyn BackingMemory>;

        let (rx, tx) = sys_util::pipe(true).expect("Pipe failed");

        let mut ex = URingExecutor::new(crate::executor::UnitFutures::new()).unwrap();

        let rx_source = register_source(&rx).expect("register source failed");
        let tx_source = register_source(&tx).expect("register source failed");

        let read_op = rx_source
            .start_read_to_mem(0, Rc::clone(&bm), &[MemRegion { offset: 0, len: 8 }])
            .expect("failed to start read to mem");

        let read_token = read_op
            .waker_token
            .as_ref()
            .map(|t| t.0)
            .expect("No `WakerToken` in `PendingOperation`");
        assert!(
            RingWakerState::with(|state| state.ops.get(read_token).is_some())
                .expect("Failed to check `RingWakerState` for pending operation")
        );

        add_future(Box::pin(cancel_io(read_op)));

        // Write to the pipe so that the kernel operation will complete.
        let buf = Rc::new(VecIoWrapper::from(vec![0xc2u8; 16])) as Rc<dyn BackingMemory>;
        let write_op = tx_source
            .start_write_from_mem(0, Rc::clone(&buf), &[MemRegion { offset: 0, len: 8 }])
            .expect("failed to start write from mem");
        add_future(Box::pin(check_result(write_op, 8)));

        ex.run().expect("Failed to run executor");

        assert!(
            RingWakerState::with(|state| state.ops.get(read_token).is_none())
                .expect("Failed to check `RingWakerState` for canceled operation")
        );
    }
}
