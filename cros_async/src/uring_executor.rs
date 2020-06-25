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
use std::collections::{BTreeMap, VecDeque};
use std::fmt::{self, Display};
use std::fs::File;
use std::future::Future;
use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::pin::Pin;
use std::rc::Rc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::task::Waker;
use std::task::{Context, Poll};

use futures::pin_mut;

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

#[derive(Clone, Debug, PartialEq, PartialOrd, Eq, Ord)]
struct RegisteredSourceTag(u64);
pub struct RegisteredSource(RegisteredSourceTag);
impl RegisteredSource {
    pub fn start_read_to_mem(
        &self,
        file_offset: u64,
        mem: Rc<dyn BackingMemory>,
        iovecs: &[MemRegion],
    ) -> Result<PendingOperation> {
        let op = IoOperation::ReadToVectored {
            mem,
            file_offset,
            addrs: iovecs,
        };
        op.submit(&self.0)
    }

    pub fn start_write_from_mem(
        &self,
        file_offset: u64,
        mem: Rc<dyn BackingMemory>,
        iovecs: &[MemRegion],
    ) -> Result<PendingOperation> {
        let op = IoOperation::WriteFromVectored {
            mem,
            file_offset,
            addrs: iovecs,
        };
        op.submit(&self.0)
    }

    pub fn start_fallocate(&self, offset: u64, len: u64, mode: u32) -> Result<PendingOperation> {
        let op = IoOperation::Fallocate { offset, len, mode };
        op.submit(&self.0)
    }

    pub fn start_fsync(&self) -> Result<PendingOperation> {
        let op = IoOperation::Fsync;
        op.submit(&self.0)
    }

    pub fn poll_fd_readable(&self) -> Result<PendingOperation> {
        let op = IoOperation::PollFd {
            events: WatchingEvents::empty().set_read(),
        };
        op.submit(&self.0)
    }

    pub fn poll_complete(&self, cx: &mut Context, op: &mut PendingOperation) -> Poll<Result<u32>> {
        pin_mut!(op);
        op.poll(cx)
    }
}

impl Drop for RegisteredSource {
    fn drop(&mut self) {
        let _ = RingWakerState::deregister_source(&self.0);
    }
}

// An operation that has been submitted to the uring and is potentially being waited on.
struct OpData {
    _file: Rc<File>,
    waker: Option<Waker>,
}

// Tracks active wakers and associates wakers with the futures that registered them.
struct RingWakerState {
    ctx: URingContext,
    pending_ops: BTreeMap<WakerToken, OpData>,
    next_op_token: u64, // Next token for adding to the context.
    completed_ops: BTreeMap<WakerToken, std::io::Result<u32>>,
    registered_sources: BTreeMap<RegisteredSourceTag, Rc<File>>,
    next_source_token: u64, // Next token for registering sources.
}

impl RingWakerState {
    fn new() -> Result<Self> {
        Ok(RingWakerState {
            ctx: URingContext::new(256).map_err(Error::CreatingContext)?,
            pending_ops: BTreeMap::new(),
            next_op_token: 0,
            completed_ops: BTreeMap::new(),
            registered_sources: BTreeMap::new(),
            next_source_token: 0,
        })
    }

    fn register_source(fd: &dyn AsRawFd) -> Result<RegisteredSource> {
        Self::with(|state| {
            let duped_fd = unsafe {
                // Safe because duplicating an FD doesn't affect memory safety, and the dup'd FD
                // will only be added to the poll loop.
                File::from_raw_fd(dup_fd(fd.as_raw_fd())?)
            };
            let tag = RegisteredSourceTag(state.next_source_token);
            state
                .registered_sources
                .insert(tag.clone(), Rc::new(duped_fd));
            state.next_source_token += 1;
            Ok(RegisteredSource(tag))
        })?
    }

    fn deregister_source(tag: &RegisteredSourceTag) {
        // There isn't any need to pull pending ops out, the all have Rc's to the file and mem they
        // need.let them complete. deregister with pending ops is not a common path no need to
        // optimize that case yet.
        let _ = Self::with(|state| {
            state.registered_sources.remove(tag);
        });
    }

    fn submit_poll(
        &mut self,
        source_tag: &RegisteredSourceTag,
        events: &sys_util::WatchingEvents,
    ) -> Result<WakerToken> {
        let source = self
            .registered_sources
            .get(source_tag)
            .ok_or(Error::InvalidSource)?;
        self.ctx
            .add_poll_fd(source.as_raw_fd(), events, self.next_op_token)
            .map_err(Error::SubmittingOp)?;
        let next_op_token = WakerToken(self.next_op_token);
        self.pending_ops.insert(
            next_op_token.clone(),
            OpData {
                _file: Rc::clone(&source),
                waker: None,
            },
        );
        self.next_op_token += 1;
        Ok(next_op_token)
    }

    fn submit_fallocate(
        &mut self,
        source_tag: &RegisteredSourceTag,
        offset: u64,
        len: u64,
        mode: u32,
    ) -> Result<WakerToken> {
        let source = self
            .registered_sources
            .get(source_tag)
            .ok_or(Error::InvalidSource)?;
        self.ctx
            .add_fallocate(source.as_raw_fd(), offset, len, mode, self.next_op_token)
            .map_err(Error::SubmittingOp)?;
        let next_op_token = WakerToken(self.next_op_token);
        self.pending_ops.insert(
            next_op_token.clone(),
            OpData {
                _file: Rc::clone(&source),
                waker: None,
            },
        );
        self.next_op_token += 1;
        Ok(next_op_token)
    }

    fn submit_fsync(&mut self, source_tag: &RegisteredSourceTag) -> Result<WakerToken> {
        let source = self
            .registered_sources
            .get(source_tag)
            .ok_or(Error::InvalidSource)?;
        self.ctx
            .add_fsync(source.as_raw_fd(), self.next_op_token)
            .map_err(Error::SubmittingOp)?;
        let next_op_token = WakerToken(self.next_op_token);
        self.pending_ops.insert(
            next_op_token.clone(),
            OpData {
                _file: Rc::clone(&source),
                waker: None,
            },
        );
        self.next_op_token += 1;
        Ok(next_op_token)
    }

    fn submit_read_to_vectored(
        &mut self,
        source_tag: &RegisteredSourceTag,
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

        let source = self
            .registered_sources
            .get(source_tag)
            .ok_or(Error::InvalidSource)?;

        // The addresses have already been validated, so unwrapping them will succeed.
        // validate their addresses before submitting.
        let iovecs = addrs
            .iter()
            .map(|&mem_range| mem.get_iovec(mem_range).unwrap().iovec());
        unsafe {
            // Safe because all the addresses are within the Memory that an Rc is kept for the
            // duration to ensure the memory is valid while the kernel accesses it.
            self.ctx
                .add_readv_iter(iovecs, source.as_raw_fd(), offset, self.next_op_token)
                .map_err(Error::SubmittingOp)?;
        }
        let next_op_token = WakerToken(self.next_op_token);
        self.pending_ops.insert(
            next_op_token.clone(),
            OpData {
                _file: Rc::clone(&source),
                waker: None,
            },
        );
        self.next_op_token += 1;
        Ok(next_op_token)
    }

    fn submit_write_from_vectored(
        &mut self,
        source_tag: &RegisteredSourceTag,
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

        let source = self
            .registered_sources
            .get(source_tag)
            .ok_or(Error::InvalidSource)?;

        // The addresses have already been validated, so unwrapping them will succeed.
        // validate their addresses before submitting.
        let iovecs = addrs
            .iter()
            .map(|&mem_range| mem.get_iovec(mem_range).unwrap().iovec());
        unsafe {
            // Safe because all the addresses are within the Memory that an Rc is kept for the
            // duration to ensure the memory is valid while the kernel accesses it.
            self.ctx
                .add_writev_iter(iovecs, source.as_raw_fd(), offset, self.next_op_token)
                .map_err(Error::SubmittingOp)?;
        }
        let next_op_token = WakerToken(self.next_op_token);
        self.pending_ops.insert(
            next_op_token.clone(),
            OpData {
                _file: Rc::clone(&source),
                waker: None,
            },
        );
        self.next_op_token += 1;
        Ok(next_op_token)
    }

    // Remove the waker for the given token if it hasn't fired yet.
    fn cancel_waker(token: &WakerToken) -> Result<()> {
        Self::with(|state| {
            let _ = state.pending_ops.remove(token);
            // TODO - handle canceling ops in the uring
            // For now the op will complete but the response will be dropped.
            let _ = state.completed_ops.remove(token);
            Ok(())
        })?
    }

    // Waits until one of the FDs is readable and wakes the associated waker.
    fn wait_wake_event() -> Result<()> {
        Self::with(|state| {
            let events = state.ctx.wait().map_err(Error::URingEnter)?;
            for (raw_token, result) in events {
                let token = WakerToken(raw_token);
                // if the op is still in pending_ops then it hasn't been cancelled and someone is
                // interested in the result, so save it. Otherwise, drop it.
                if let Some(op) = state.pending_ops.remove(&token) {
                    if let Some(waker) = op.waker {
                        waker.wake_by_ref();
                    }
                    state.completed_ops.insert(token, result);
                }
            }
            Ok(())
        })?
    }

    fn get_result(token: &WakerToken, waker: Waker) -> Result<Option<io::Result<u32>>> {
        Self::with(|state| {
            if let Some(result) = state.completed_ops.remove(token) {
                Some(result)
            } else {
                if let Some(op) = state.pending_ops.get_mut(token) {
                    op.waker = Some(waker);
                }
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

enum IoOperation<'a> {
    ReadToVectored {
        mem: Rc<dyn BackingMemory>,
        file_offset: u64,
        addrs: &'a [MemRegion],
    },
    WriteFromVectored {
        mem: Rc<dyn BackingMemory>,
        file_offset: u64,
        addrs: &'a [MemRegion],
    },
    PollFd {
        events: WatchingEvents,
    },
    Fallocate {
        offset: u64,
        len: u64,
        mode: u32,
    },
    Fsync,
}

impl<'a> IoOperation<'a> {
    fn submit(self, tag: &RegisteredSourceTag) -> Result<PendingOperation> {
        let waker_token = match self {
            IoOperation::ReadToVectored {
                mem,
                file_offset,
                addrs,
            } => STATE.with(|state| {
                let mut state = state.borrow_mut();
                if let Some(state) = state.as_mut() {
                    state.submit_read_to_vectored(tag, mem, file_offset, addrs)
                } else {
                    Err(Error::InvalidContext)
                }
            })?,
            IoOperation::WriteFromVectored {
                mem,
                file_offset,
                addrs,
            } => STATE.with(|state| {
                let mut state = state.borrow_mut();
                if let Some(state) = state.as_mut() {
                    state.submit_write_from_vectored(tag, mem, file_offset, addrs)
                } else {
                    Err(Error::InvalidContext)
                }
            })?,
            IoOperation::PollFd { events } => STATE.with(|state| {
                let mut state = state.borrow_mut();
                if let Some(state) = state.as_mut() {
                    state.submit_poll(tag, &events)
                } else {
                    Err(Error::InvalidContext)
                }
            })?,
            IoOperation::Fallocate { offset, len, mode } => STATE.with(|state| {
                let mut state = state.borrow_mut();
                if let Some(state) = state.as_mut() {
                    state.submit_fallocate(tag, offset, len, mode)
                } else {
                    Err(Error::InvalidContext)
                }
            })?,
            IoOperation::Fsync => STATE.with(|state| {
                let mut state = state.borrow_mut();
                if let Some(state) = state.as_mut() {
                    state.submit_fsync(tag)
                } else {
                    Err(Error::InvalidContext)
                }
            })?,
        };

        Ok(PendingOperation {
            waker_token: Some(waker_token),
        })
    }
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
            let _ = RingWakerState::cancel_waker(&waker_token);
        }
    }
}
