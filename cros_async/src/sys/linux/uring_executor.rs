// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// TODO: Move this doc to one of the public APIs, it isn't io_uring specific.

//! `UringReactor`
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
//! Arc to the backing memory. Vecs being read to are also wrapped in an Arc before being passed to
//! the executor.  The executor holds the Arc and ensures all operations are complete before dropping
//! it, that guarantees the memory is valid for the duration.
//!
//! The buffers _have_ to be on the heap. Because we don't have a way to cancel a future if it is
//! dropped(can't rely on drop running), there is no way to ensure the kernel's buffer remains valid
//! until the operation completes unless the executor holds an Arc to the memory on the heap.
//!
//! ## Using `Vec` for reads/writes.
//!
//! There is a convenience wrapper `VecIoWrapper` provided for fully owned vectors. This type
//! ensures that only the kernel is allowed to access the `Vec` and wraps the the `Vec` in an Arc to
//! ensure it lives long enough.

use std::convert::TryInto;
use std::ffi::CStr;
use std::fs::File;
use std::future::Future;
use std::io;
use std::mem;
use std::mem::MaybeUninit;
use std::os::unix::io::FromRawFd;
use std::os::unix::io::RawFd;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Weak;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;
use std::thread;
use std::thread::ThreadId;

use base::trace;
use base::warn;
use base::AsRawDescriptor;
use base::EventType;
use base::IoBufMut;
use base::RawDescriptor;
use io_uring::URingAllowlist;
use io_uring::URingContext;
use io_uring::URingOperation;
use once_cell::sync::Lazy;
use remain::sorted;
use slab::Slab;
use sync::Mutex;
use thiserror::Error as ThisError;

use crate::common_executor::RawExecutor;
use crate::common_executor::Reactor;
use crate::mem::BackingMemory;
use crate::waker::WakerToken;
use crate::waker::WeakWake;
use crate::AsyncResult;
use crate::IoSource;
use crate::MemRegion;

#[sorted]
#[derive(Debug, ThisError)]
pub enum Error {
    /// Creating a context to wait on FDs failed.
    #[error("Error creating the fd waiting context: {0}")]
    CreatingContext(io_uring::Error),
    /// Failed to discard a block
    #[error("Failed to discard a block: {0}")]
    Discard(base::Error),
    /// Failed to copy the FD for the polling context.
    #[error("Failed to copy the FD for the polling context: {0}")]
    DuplicatingFd(base::Error),
    /// Enabling a context faild.
    #[error("Error enabling the URing context: {0}")]
    EnablingContext(io_uring::Error),
    /// The Executor is gone.
    #[error("The executor is gone")]
    ExecutorGone,
    /// Invalid offset or length given for an iovec in backing memory.
    #[error("Invalid offset/len for getting an iovec")]
    InvalidOffset,
    /// Invalid FD source specified.
    #[error("Invalid source, FD not registered for use")]
    InvalidSource,
    /// Error doing the IO.
    #[error("Error during IO: {0}")]
    Io(io::Error),
    /// Registering operation restrictions to a uring failed.
    #[error("Error registering restrictions to the URing context: {0}")]
    RegisteringURingRestriction(io_uring::Error),
    /// Failed to remove the waker remove the polling context.
    #[error("Error removing from the URing context: {0}")]
    RemovingWaker(io_uring::Error),
    /// Failed to submit the operation to the polling context.
    #[error("Error adding to the URing context: {0}")]
    SubmittingOp(io_uring::Error),
    /// URingContext failure.
    #[error("URingContext failure: {0}")]
    URingContextError(io_uring::Error),
    /// Failed to submit or wait for io_uring events.
    #[error("URing::enter: {0}")]
    URingEnter(io_uring::Error),
}
pub type Result<T> = std::result::Result<T, Error>;

impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        use Error::*;
        match e {
            Discard(e) => e.into(),
            DuplicatingFd(e) => e.into(),
            ExecutorGone => io::Error::new(io::ErrorKind::Other, ExecutorGone),
            InvalidOffset => io::Error::new(io::ErrorKind::InvalidInput, InvalidOffset),
            InvalidSource => io::Error::new(io::ErrorKind::InvalidData, InvalidSource),
            Io(e) => e,
            CreatingContext(e) => e.into(),
            RemovingWaker(e) => e.into(),
            SubmittingOp(e) => e.into(),
            URingContextError(e) => e.into(),
            URingEnter(e) => e.into(),
            EnablingContext(e) => e.into(),
            RegisteringURingRestriction(e) => e.into(),
        }
    }
}

static IS_URING_STABLE: Lazy<bool> = Lazy::new(|| {
    let mut utsname = MaybeUninit::zeroed();

    // SAFETY:
    // Safe because this will only modify `utsname` and we check the return value.
    let res = unsafe { libc::uname(utsname.as_mut_ptr()) };
    if res < 0 {
        return false;
    }

    // SAFETY:
    // Safe because the kernel has initialized `utsname`.
    let utsname = unsafe { utsname.assume_init() };

    // SAFETY:
    // Safe because the pointer is valid and the kernel guarantees that this is a valid C string.
    let release = unsafe { CStr::from_ptr(utsname.release.as_ptr()) };

    let mut components = match release.to_str().map(|r| r.split('.').map(str::parse)) {
        Ok(c) => c,
        Err(_) => return false,
    };

    // Kernels older than 5.10 either didn't support io_uring or had bugs in the implementation.
    match (components.next(), components.next()) {
        (Some(Ok(major)), Some(Ok(minor))) if (major, minor) >= (5, 10) => {
            // The kernel version is new enough so check if we can actually make a uring context.
            URingContext::new(8, None).is_ok()
        }
        _ => false,
    }
});

// Checks if the uring executor is stable.
// Caches the result so that the check is only run once.
// Useful for falling back to the FD executor on pre-uring kernels.
pub fn is_uring_stable() -> bool {
    *IS_URING_STABLE
}

// Checks the uring availability by checking if the uring creation succeeds.
// If uring creation succeeds, it returns `Ok(())`. It returns an `URingContextError` otherwise.
// It fails if the kernel does not support io_uring, but note that the cause is not limited to it.
pub(crate) fn check_uring_availability() -> Result<()> {
    URingContext::new(8, None)
        .map(drop)
        .map_err(Error::URingContextError)
}

pub struct RegisteredSource {
    tag: usize,
    ex: Weak<RawExecutor<UringReactor>>,
}

impl RegisteredSource {
    pub fn start_read_to_mem(
        &self,
        file_offset: Option<u64>,
        mem: Arc<dyn BackingMemory + Send + Sync>,
        addrs: impl IntoIterator<Item = MemRegion>,
    ) -> Result<PendingOperation> {
        let ex = self.ex.upgrade().ok_or(Error::ExecutorGone)?;
        let token = ex
            .reactor
            .submit_read_to_vectored(self, mem, file_offset, addrs)?;

        Ok(PendingOperation {
            waker_token: Some(token),
            ex: self.ex.clone(),
            submitted: false,
        })
    }

    pub fn start_write_from_mem(
        &self,
        file_offset: Option<u64>,
        mem: Arc<dyn BackingMemory + Send + Sync>,
        addrs: impl IntoIterator<Item = MemRegion>,
    ) -> Result<PendingOperation> {
        let ex = self.ex.upgrade().ok_or(Error::ExecutorGone)?;
        let token = ex
            .reactor
            .submit_write_from_vectored(self, mem, file_offset, addrs)?;

        Ok(PendingOperation {
            waker_token: Some(token),
            ex: self.ex.clone(),
            submitted: false,
        })
    }

    pub fn start_fallocate(&self, offset: u64, len: u64, mode: u32) -> Result<PendingOperation> {
        let ex = self.ex.upgrade().ok_or(Error::ExecutorGone)?;
        let token = ex.reactor.submit_fallocate(self, offset, len, mode)?;

        Ok(PendingOperation {
            waker_token: Some(token),
            ex: self.ex.clone(),
            submitted: false,
        })
    }

    pub fn start_fsync(&self) -> Result<PendingOperation> {
        let ex = self.ex.upgrade().ok_or(Error::ExecutorGone)?;
        let token = ex.reactor.submit_fsync(self)?;

        Ok(PendingOperation {
            waker_token: Some(token),
            ex: self.ex.clone(),
            submitted: false,
        })
    }

    pub fn poll_fd_readable(&self) -> Result<PendingOperation> {
        let events = EventType::Read;

        let ex = self.ex.upgrade().ok_or(Error::ExecutorGone)?;
        let token = ex.reactor.submit_poll(self, events)?;

        Ok(PendingOperation {
            waker_token: Some(token),
            ex: self.ex.clone(),
            submitted: false,
        })
    }
}

impl Drop for RegisteredSource {
    fn drop(&mut self) {
        if let Some(ex) = self.ex.upgrade() {
            ex.reactor.deregister_source(self);
        }
    }
}

// Number of entries in the ring.
const NUM_ENTRIES: usize = 256;

// An operation that has been submitted to the uring and is potentially being waited on.
struct OpData {
    _file: Arc<File>,
    _mem: Option<Arc<dyn BackingMemory + Send + Sync>>,
    waker: Option<Waker>,
    canceled: bool,
}

// The current status of an operation that's been submitted to the uring.
enum OpStatus {
    Nop,
    Pending(OpData),
    Completed(Option<::std::io::Result<u32>>),
}

struct Ring {
    ops: Slab<OpStatus>,
    registered_sources: Slab<Arc<File>>,
}

/// `Reactor` that manages async IO work using io_uring.
pub struct UringReactor {
    // The URingContext needs to be first so that it is dropped first, closing the uring fd, and
    // releasing the resources borrowed by the kernel before we free them.
    ctx: URingContext,
    ring: Mutex<Ring>,
    thread_id: Mutex<Option<ThreadId>>,
}

impl UringReactor {
    fn new() -> Result<UringReactor> {
        // Allow operations only that the UringReactor really submits to enhance the security.
        let mut restrictions = URingAllowlist::new();
        let ops = [
            URingOperation::Writev,
            URingOperation::Readv,
            URingOperation::Nop,
            URingOperation::Fsync,
            URingOperation::Fallocate,
            URingOperation::PollAdd,
            URingOperation::PollRemove,
            URingOperation::AsyncCancel,
        ];
        for op in ops {
            restrictions.allow_submit_operation(op);
        }

        let ctx =
            URingContext::new(NUM_ENTRIES, Some(&restrictions)).map_err(Error::CreatingContext)?;

        Ok(UringReactor {
            ctx,
            ring: Mutex::new(Ring {
                ops: Slab::with_capacity(NUM_ENTRIES),
                registered_sources: Slab::with_capacity(NUM_ENTRIES),
            }),
            thread_id: Mutex::new(None),
        })
    }

    fn runs_tasks_on_current_thread(&self) -> bool {
        let executor_thread = self.thread_id.lock();
        executor_thread
            .map(|id| id == thread::current().id())
            .unwrap_or(false)
    }

    fn get_result(&self, token: &WakerToken, cx: &mut Context) -> Option<io::Result<u32>> {
        let mut ring = self.ring.lock();

        let op = ring
            .ops
            .get_mut(token.0)
            .expect("`get_result` called on unknown operation");
        match op {
            OpStatus::Nop => panic!("`get_result` called on nop"),
            OpStatus::Pending(data) => {
                if data.canceled {
                    panic!("`get_result` called on canceled operation");
                }
                data.waker = Some(cx.waker().clone());
                None
            }
            OpStatus::Completed(res) => {
                let out = res.take();
                ring.ops.remove(token.0);
                Some(out.expect("Missing result in completed operation"))
            }
        }
    }

    // Remove the waker for the given token if it hasn't fired yet.
    fn cancel_operation(&self, token: WakerToken) {
        let mut ring = self.ring.lock();
        let submit_cancel = if let Some(op) = ring.ops.get_mut(token.0) {
            match op {
                OpStatus::Nop => panic!("`cancel_operation` called on nop"),
                OpStatus::Pending(data) => {
                    if data.canceled {
                        panic!("uring operation canceled more than once");
                    }

                    if let Some(waker) = data.waker.take() {
                        waker.wake();
                    }
                    // Clear the waker as it is no longer needed.
                    data.waker = None;
                    data.canceled = true;

                    // Keep the rest of the op data as the uring might still be accessing either
                    // the source of the backing memory so it needs to live until the kernel
                    // completes the operation.
                    true
                }
                OpStatus::Completed(_) => {
                    ring.ops.remove(token.0);
                    false
                }
            }
        } else {
            false
        };
        std::mem::drop(ring);
        if submit_cancel {
            let _best_effort = self.submit_cancel_async(token.0);
        }
    }

    pub(crate) fn register_source<F: AsRawDescriptor>(
        &self,
        raw: &Arc<RawExecutor<UringReactor>>,
        fd: &F,
    ) -> Result<RegisteredSource> {
        // SAFETY:
        // Safe because duplicating an FD doesn't affect memory safety, and the dup'd FD
        // will only be added to the poll loop.
        let duped_fd = unsafe { File::from_raw_fd(dup_fd(fd.as_raw_descriptor())?) };

        Ok(RegisteredSource {
            tag: self
                .ring
                .lock()
                .registered_sources
                .insert(Arc::new(duped_fd)),
            ex: Arc::downgrade(raw),
        })
    }

    fn deregister_source(&self, source: &RegisteredSource) {
        // There isn't any need to pull pending ops out, the all have Arc's to the file and mem they
        // need.let them complete. deregister with pending ops is not a common path no need to
        // optimize that case yet.
        self.ring.lock().registered_sources.remove(source.tag);
    }

    fn submit_poll(
        &self,
        source: &RegisteredSource,
        events: base::EventType,
    ) -> Result<WakerToken> {
        let mut ring = self.ring.lock();
        let src = ring
            .registered_sources
            .get(source.tag)
            .map(Arc::clone)
            .ok_or(Error::InvalidSource)?;
        let entry = ring.ops.vacant_entry();
        let next_op_token = entry.key();
        self.ctx
            .add_poll_fd(src.as_raw_descriptor(), events, usize_to_u64(next_op_token))
            .map_err(Error::SubmittingOp)?;
        entry.insert(OpStatus::Pending(OpData {
            _file: src,
            _mem: None,
            waker: None,
            canceled: false,
        }));

        Ok(WakerToken(next_op_token))
    }

    fn submit_fallocate(
        &self,
        source: &RegisteredSource,
        offset: u64,
        len: u64,
        mode: u32,
    ) -> Result<WakerToken> {
        let mut ring = self.ring.lock();
        let src = ring
            .registered_sources
            .get(source.tag)
            .map(Arc::clone)
            .ok_or(Error::InvalidSource)?;
        let entry = ring.ops.vacant_entry();
        let next_op_token = entry.key();
        self.ctx
            .add_fallocate(
                src.as_raw_descriptor(),
                offset,
                len,
                mode,
                usize_to_u64(next_op_token),
            )
            .map_err(Error::SubmittingOp)?;

        entry.insert(OpStatus::Pending(OpData {
            _file: src,
            _mem: None,
            waker: None,
            canceled: false,
        }));

        Ok(WakerToken(next_op_token))
    }

    fn submit_cancel_async(&self, token: usize) -> Result<WakerToken> {
        let mut ring = self.ring.lock();
        let entry = ring.ops.vacant_entry();
        let next_op_token = entry.key();
        self.ctx
            .async_cancel(usize_to_u64(token), usize_to_u64(next_op_token))
            .map_err(Error::SubmittingOp)?;

        entry.insert(OpStatus::Nop);

        Ok(WakerToken(next_op_token))
    }

    fn submit_fsync(&self, source: &RegisteredSource) -> Result<WakerToken> {
        let mut ring = self.ring.lock();
        let src = ring
            .registered_sources
            .get(source.tag)
            .map(Arc::clone)
            .ok_or(Error::InvalidSource)?;
        let entry = ring.ops.vacant_entry();
        let next_op_token = entry.key();
        self.ctx
            .add_fsync(src.as_raw_descriptor(), usize_to_u64(next_op_token))
            .map_err(Error::SubmittingOp)?;
        entry.insert(OpStatus::Pending(OpData {
            _file: src,
            _mem: None,
            waker: None,
            canceled: false,
        }));

        Ok(WakerToken(next_op_token))
    }

    fn submit_read_to_vectored(
        &self,
        source: &RegisteredSource,
        mem: Arc<dyn BackingMemory + Send + Sync>,
        offset: Option<u64>,
        addrs: impl IntoIterator<Item = MemRegion>,
    ) -> Result<WakerToken> {
        let iovecs = addrs
            .into_iter()
            .map(|mem_range| {
                let vslice = mem
                    .get_volatile_slice(mem_range)
                    .map_err(|_| Error::InvalidOffset)?;
                // SAFETY:
                // Safe because we guarantee that the memory pointed to by `iovecs` lives until the
                // transaction is complete and the completion has been returned from `wait()`.
                Ok(unsafe { IoBufMut::from_raw_parts(vslice.as_mut_ptr(), vslice.size()) })
            })
            .collect::<Result<Vec<_>>>()?;
        let iovecs = Pin::from(iovecs.into_boxed_slice());

        let mut ring = self.ring.lock();
        let src = ring
            .registered_sources
            .get(source.tag)
            .map(Arc::clone)
            .ok_or(Error::InvalidSource)?;

        let entry = ring.ops.vacant_entry();
        let next_op_token = entry.key();

        // SAFETY:
        // Safe because all the addresses are within the Memory that an Arc is kept for the
        // duration to ensure the memory is valid while the kernel accesses it.
        // Tested by `dont_drop_backing_mem_read` unit test.
        unsafe {
            self.ctx
                .add_readv(
                    iovecs,
                    src.as_raw_descriptor(),
                    offset,
                    usize_to_u64(next_op_token),
                )
                .map_err(Error::SubmittingOp)?;
        }

        entry.insert(OpStatus::Pending(OpData {
            _file: src,
            _mem: Some(mem),
            waker: None,
            canceled: false,
        }));

        Ok(WakerToken(next_op_token))
    }

    fn submit_write_from_vectored(
        &self,
        source: &RegisteredSource,
        mem: Arc<dyn BackingMemory + Send + Sync>,
        offset: Option<u64>,
        addrs: impl IntoIterator<Item = MemRegion>,
    ) -> Result<WakerToken> {
        let iovecs = addrs
            .into_iter()
            .map(|mem_range| {
                let vslice = mem
                    .get_volatile_slice(mem_range)
                    .map_err(|_| Error::InvalidOffset)?;
                // SAFETY:
                // Safe because we guarantee that the memory pointed to by `iovecs` lives until the
                // transaction is complete and the completion has been returned from `wait()`.
                Ok(unsafe { IoBufMut::from_raw_parts(vslice.as_mut_ptr(), vslice.size()) })
            })
            .collect::<Result<Vec<_>>>()?;
        let iovecs = Pin::from(iovecs.into_boxed_slice());

        let mut ring = self.ring.lock();
        let src = ring
            .registered_sources
            .get(source.tag)
            .map(Arc::clone)
            .ok_or(Error::InvalidSource)?;

        let entry = ring.ops.vacant_entry();
        let next_op_token = entry.key();

        // SAFETY:
        // Safe because all the addresses are within the Memory that an Arc is kept for the
        // duration to ensure the memory is valid while the kernel accesses it.
        // Tested by `dont_drop_backing_mem_write` unit test.
        unsafe {
            self.ctx
                .add_writev(
                    iovecs,
                    src.as_raw_descriptor(),
                    offset,
                    usize_to_u64(next_op_token),
                )
                .map_err(Error::SubmittingOp)?;
        }

        entry.insert(OpStatus::Pending(OpData {
            _file: src,
            _mem: Some(mem),
            waker: None,
            canceled: false,
        }));

        Ok(WakerToken(next_op_token))
    }
}

impl Reactor for UringReactor {
    fn new() -> std::io::Result<Self> {
        Ok(UringReactor::new()?)
    }

    fn wake(&self) {
        let mut ring = self.ring.lock();
        let entry = ring.ops.vacant_entry();
        let next_op_token = entry.key();
        if let Err(e) = self.ctx.add_nop(usize_to_u64(next_op_token)) {
            warn!("Failed to add NOP for waking up executor: {}", e);
        }
        entry.insert(OpStatus::Nop);
        mem::drop(ring);

        match self.ctx.submit() {
            Ok(()) => {}
            // If the kernel's submit ring is full then we know we won't block when calling
            // io_uring_enter, which is all we really care about.
            Err(io_uring::Error::RingEnter(libc::EBUSY)) => {}
            Err(e) => warn!("Failed to submit NOP for waking up executor: {}", e),
        }
    }

    fn on_executor_drop<'a>(&'a self) -> Pin<Box<dyn Future<Output = ()> + 'a>> {
        // At this point, there are no strong references to the executor (see `on_executor_drop`
        // docs). That means all the `RegisteredSource::ex` will fail to upgrade and so no more IO
        // work can be submitted.

        // Submit cancellations for all operations
        #[allow(clippy::needless_collect)]
        let ops: Vec<_> = self
            .ring
            .lock()
            .ops
            .iter_mut()
            .filter_map(|op| match op.1 {
                OpStatus::Pending(data) if !data.canceled => Some(op.0),
                _ => None,
            })
            .collect();
        for token in ops {
            self.cancel_operation(WakerToken(token));
        }

        // Since the UringReactor is wrapped in an Arc it may end up being dropped from a different
        // thread than the one that called `run` or `run_until`. Since we know there are no other
        // references, just clear the thread id so that we don't panic.
        *self.thread_id.lock() = None;

        // Make sure all pending uring operations are completed as kernel may try to write to
        // memory that we may drop.
        //
        // This future doesn't use the waker, it assumes the future will always be polled after
        // processing other woken futures.
        // TODO: Find a more robust solution.
        Box::pin(futures::future::poll_fn(|_cx| {
            if self.ring.lock().ops.is_empty() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }))
    }

    fn on_thread_start(&self) {
        let current_thread = thread::current().id();
        let mut thread_id = self.thread_id.lock();
        assert_eq!(
            *thread_id.get_or_insert(current_thread),
            current_thread,
            "`UringReactor::wait_for_work` cannot be called from more than one thread"
        );
    }

    fn wait_for_work(&self, set_processing: impl Fn()) -> std::io::Result<()> {
        trace!(
            "Waiting on events, {} pending ops",
            self.ring.lock().ops.len()
        );
        let events = self.ctx.wait().map_err(Error::URingEnter)?;

        // Set the state back to PROCESSING to prevent any tasks woken up by the loop below from
        // writing to the eventfd.
        set_processing();

        let mut ring = self.ring.lock();
        for (raw_token, result) in events {
            // While the `expect()` might fail on arbitrary `u64`s, the `raw_token` was
            // something that we originally gave to the kernel and that was created from a
            // `usize` so we should always be able to convert it back into a `usize`.
            let token = raw_token
                .try_into()
                .expect("`u64` doesn't fit inside a `usize`");

            let op = ring
                .ops
                .get_mut(token)
                .expect("Received completion token for unexpected operation");
            match mem::replace(op, OpStatus::Completed(Some(result))) {
                // No one is waiting on a Nop.
                OpStatus::Nop => mem::drop(ring.ops.remove(token)),
                OpStatus::Pending(data) => {
                    if data.canceled {
                        // No one is waiting for this operation and the uring is done with
                        // it so it's safe to remove.
                        ring.ops.remove(token);
                    }
                    if let Some(waker) = data.waker {
                        waker.wake();
                    }
                }
                OpStatus::Completed(_) => panic!("uring operation completed more than once"),
            }
        }

        Ok(())
    }

    fn new_source<F: AsRawDescriptor>(
        &self,
        ex: &Arc<RawExecutor<Self>>,
        f: F,
    ) -> AsyncResult<IoSource<F>> {
        Ok(IoSource::Uring(super::UringSource::new(f, ex)?))
    }
}

impl AsRawDescriptor for UringReactor {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.ctx.as_raw_descriptor()
    }
}

impl WeakWake for UringReactor {
    fn wake_by_ref(weak_self: &Weak<Self>) {
        if let Some(arc_self) = weak_self.upgrade() {
            Reactor::wake(&*arc_self);
        }
    }
}

impl Drop for UringReactor {
    fn drop(&mut self) {
        // The ring should have been drained when the executor's Drop ran.
        assert!(self.ring.lock().ops.is_empty());
    }
}

// SAFETY:
// Used to dup the FDs passed to the executor so there is a guarantee they aren't closed while
// waiting in TLS to be added to the main polling context.
unsafe fn dup_fd(fd: RawFd) -> Result<RawFd> {
    let ret = libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0);
    if ret < 0 {
        Err(Error::DuplicatingFd(base::Error::last()))
    } else {
        Ok(ret)
    }
}

// Converts a `usize` into a `u64` and panics if the conversion fails.
#[inline]
fn usize_to_u64(val: usize) -> u64 {
    val.try_into().expect("`usize` doesn't fit inside a `u64`")
}

pub struct PendingOperation {
    waker_token: Option<WakerToken>,
    ex: Weak<RawExecutor<UringReactor>>,
    submitted: bool,
}

impl Future for PendingOperation {
    type Output = Result<u32>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let token = self
            .waker_token
            .as_ref()
            .expect("PendingOperation polled after returning Poll::Ready");
        if let Some(ex) = self.ex.upgrade() {
            if let Some(result) = ex.reactor.get_result(token, cx) {
                self.waker_token = None;
                Poll::Ready(result.map_err(Error::Io))
            } else {
                // If we haven't submitted the operation yet, and the executor runs on a different
                // thread then submit it now. Otherwise the executor will submit it automatically
                // the next time it calls UringContext::wait.
                if !self.submitted && !ex.reactor.runs_tasks_on_current_thread() {
                    match ex.reactor.ctx.submit() {
                        Ok(()) => self.submitted = true,
                        // If the kernel ring is full then wait until some ops are removed from the
                        // completion queue. This op should get submitted the next time the executor
                        // calls UringContext::wait.
                        Err(io_uring::Error::RingEnter(libc::EBUSY)) => {}
                        Err(e) => return Poll::Ready(Err(Error::URingEnter(e))),
                    }
                }
                Poll::Pending
            }
        } else {
            Poll::Ready(Err(Error::ExecutorGone))
        }
    }
}

impl Drop for PendingOperation {
    fn drop(&mut self) {
        if let Some(waker_token) = self.waker_token.take() {
            if let Some(ex) = self.ex.upgrade() {
                ex.reactor.cancel_operation(waker_token);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::io::Read;
    use std::io::Write;
    use std::mem;
    use std::pin::Pin;
    use std::rc::Rc;
    use std::task::Context;
    use std::task::Poll;

    use futures::executor::block_on;

    use super::*;
    use crate::mem::BackingMemory;
    use crate::mem::MemRegion;
    use crate::mem::VecIoWrapper;
    use crate::BlockingPool;

    // A future that returns ready when the uring queue is empty.
    struct UringQueueEmpty<'a> {
        ex: &'a Arc<RawExecutor<UringReactor>>,
    }

    impl<'a> Future for UringQueueEmpty<'a> {
        type Output = ();

        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
            if self.ex.reactor.ring.lock().ops.is_empty() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }
    }

    #[test]
    fn dont_drop_backing_mem_read() {
        if !is_uring_stable() {
            return;
        }

        // Create a backing memory wrapped in an Arc and check that the drop isn't called while the
        // op is pending.
        let bm =
            Arc::new(VecIoWrapper::from(vec![0u8; 4096])) as Arc<dyn BackingMemory + Send + Sync>;

        // Use pipes to create a future that will block forever.
        let (rx, mut tx) = base::pipe(true).unwrap();

        // Set up the TLS for the uring_executor by creating one.
        let ex = RawExecutor::<UringReactor>::new().unwrap();

        // Register the receive side of the pipe with the executor.
        let registered_source = ex
            .reactor
            .register_source(&ex, &rx)
            .expect("register source failed");

        // Submit the op to the kernel. Next, test that the source keeps its Arc open for the duration
        // of the op.
        let pending_op = registered_source
            .start_read_to_mem(None, Arc::clone(&bm), [MemRegion { offset: 0, len: 8 }])
            .expect("failed to start read to mem");

        // Here the Arc count must be two, one for `bm` and one to signify that the kernel has a
        // reference while the op is active.
        assert_eq!(Arc::strong_count(&bm), 2);

        // Dropping the operation shouldn't reduce the Arc count, as the kernel could still be using
        // it.
        drop(pending_op);
        assert_eq!(Arc::strong_count(&bm), 2);

        // Finishing the operation should put the Arc count back to 1.
        // write to the pipe to wake the read pipe and then wait for the uring result in the
        // executor.
        tx.write_all(&[0u8; 8]).expect("write failed");
        ex.run_until(UringQueueEmpty { ex: &ex })
            .expect("Failed to wait for read pipe ready");
        assert_eq!(Arc::strong_count(&bm), 1);
    }

    #[test]
    fn dont_drop_backing_mem_write() {
        if !is_uring_stable() {
            return;
        }

        // Create a backing memory wrapped in an Arc and check that the drop isn't called while the
        // op is pending.
        let bm =
            Arc::new(VecIoWrapper::from(vec![0u8; 4096])) as Arc<dyn BackingMemory + Send + Sync>;

        // Use pipes to create a future that will block forever.
        let (mut rx, tx) = base::new_pipe_full().expect("Pipe failed");

        // Set up the TLS for the uring_executor by creating one.
        let ex = RawExecutor::<UringReactor>::new().unwrap();

        // Register the receive side of the pipe with the executor.
        let registered_source = ex
            .reactor
            .register_source(&ex, &tx)
            .expect("register source failed");

        // Submit the op to the kernel. Next, test that the source keeps its Arc open for the duration
        // of the op.
        let pending_op = registered_source
            .start_write_from_mem(None, Arc::clone(&bm), [MemRegion { offset: 0, len: 8 }])
            .expect("failed to start write to mem");

        // Here the Arc count must be two, one for `bm` and one to signify that the kernel has a
        // reference while the op is active.
        assert_eq!(Arc::strong_count(&bm), 2);

        // Dropping the operation shouldn't reduce the Arc count, as the kernel could still be using
        // it.
        drop(pending_op);
        assert_eq!(Arc::strong_count(&bm), 2);

        // Finishing the operation should put the Arc count back to 1.
        // write to the pipe to wake the read pipe and then wait for the uring result in the
        // executor.
        let mut buf = vec![0u8; base::round_up_to_page_size(1)];
        rx.read_exact(&mut buf).expect("read to empty failed");
        ex.run_until(UringQueueEmpty { ex: &ex })
            .expect("Failed to wait for write pipe ready");
        assert_eq!(Arc::strong_count(&bm), 1);
    }

    #[test]
    fn canceled_before_completion() {
        if !is_uring_stable() {
            return;
        }

        async fn cancel_io(op: PendingOperation) {
            mem::drop(op);
        }

        async fn check_result(op: PendingOperation, expected: u32) {
            let actual = op.await.expect("operation failed to complete");
            assert_eq!(expected, actual);
        }

        let bm =
            Arc::new(VecIoWrapper::from(vec![0u8; 16])) as Arc<dyn BackingMemory + Send + Sync>;

        let (rx, tx) = base::pipe(true).expect("Pipe failed");

        let ex = RawExecutor::<UringReactor>::new().unwrap();

        let rx_source = ex
            .reactor
            .register_source(&ex, &rx)
            .expect("register source failed");
        let tx_source = ex
            .reactor
            .register_source(&ex, &tx)
            .expect("register source failed");

        let read_task = rx_source
            .start_read_to_mem(None, Arc::clone(&bm), [MemRegion { offset: 0, len: 8 }])
            .expect("failed to start read to mem");

        ex.spawn_local(cancel_io(read_task)).detach();

        // Write to the pipe so that the kernel operation will complete.
        let buf =
            Arc::new(VecIoWrapper::from(vec![0xc2u8; 16])) as Arc<dyn BackingMemory + Send + Sync>;
        let write_task = tx_source
            .start_write_from_mem(None, Arc::clone(&buf), [MemRegion { offset: 0, len: 8 }])
            .expect("failed to start write from mem");

        ex.run_until(check_result(write_task, 8))
            .expect("Failed to run executor");
    }

    // We will drain all ops on drop and its not guaranteed that operation won't finish
    #[ignore]
    #[test]
    fn drop_before_completion() {
        if !is_uring_stable() {
            return;
        }

        const VALUE: u64 = 0xef6c_a8df_b842_eb9c;

        async fn check_op(op: PendingOperation) {
            let err = op.await.expect_err("Op completed successfully");
            match err {
                Error::ExecutorGone => {}
                e => panic!("Unexpected error from op: {}", e),
            }
        }

        let (mut rx, mut tx) = base::pipe(true).expect("Pipe failed");

        let ex = RawExecutor::<UringReactor>::new().unwrap();

        let tx_source = ex
            .reactor
            .register_source(&ex, &tx)
            .expect("Failed to register source");
        let bm = Arc::new(VecIoWrapper::from(VALUE.to_ne_bytes().to_vec()));
        let op = tx_source
            .start_write_from_mem(
                None,
                bm,
                [MemRegion {
                    offset: 0,
                    len: mem::size_of::<u64>(),
                }],
            )
            .expect("Failed to start write from mem");

        ex.spawn_local(check_op(op)).detach();

        // Now drop the executor. It shouldn't run the write operation.
        mem::drop(ex);

        // Make sure the executor did not complete the uring operation.
        let new_val = [0x2e; 8];
        tx.write_all(&new_val).unwrap();

        let mut buf = 0u64.to_ne_bytes();
        rx.read_exact(&mut buf[..])
            .expect("Failed to read from pipe");

        assert_eq!(buf, new_val);
    }

    // Dropping a task that owns a BlockingPool shouldn't leak the pool.
    #[test]
    fn drop_detached_blocking_pool() {
        if !is_uring_stable() {
            return;
        }

        struct Cleanup(BlockingPool);

        impl Drop for Cleanup {
            fn drop(&mut self) {
                // Make sure we shutdown cleanly (BlockingPool::drop just prints a warning).
                self.0
                    .shutdown(Some(
                        std::time::Instant::now() + std::time::Duration::from_secs(1),
                    ))
                    .unwrap();
            }
        }

        let rc = Rc::new(std::cell::Cell::new(0));
        {
            let ex = RawExecutor::<UringReactor>::new().unwrap();
            let rc_clone = rc.clone();
            ex.spawn_local(async move {
                rc_clone.set(1);
                let pool = Cleanup(BlockingPool::new(1, std::time::Duration::new(60, 0)));
                let (send, recv) = std::sync::mpsc::sync_channel::<()>(0);
                // Spawn a blocking task.
                let blocking_task = pool.0.spawn(move || {
                    // Rendezvous.
                    assert_eq!(recv.recv(), Ok(()));
                    // Wait for drop.
                    assert_eq!(recv.recv(), Err(std::sync::mpsc::RecvError));
                });
                // Make sure it has actually started (using a "rendezvous channel" send).
                //
                // Without this step, we'll have a race where we can shutdown the blocking pool
                // before the worker thread pops off the task.
                send.send(()).unwrap();
                // Wait for it to finish
                blocking_task.await;
                rc_clone.set(2);
            })
            .detach();
            ex.run_until(async {}).unwrap();
            // `ex` is dropped here. If everything is working as expected, it should drop all of
            // its tasks, including `send` and `pool` (in that order, which is important). `pool`'s
            // `Drop` impl will try to join all the worker threads, which should work because send
            // half of the channel closed.
        }
        assert_eq!(rc.get(), 1);
        Rc::try_unwrap(rc).expect("Rc had too many refs");
    }

    #[test]
    fn drop_on_different_thread() {
        if !is_uring_stable() {
            return;
        }

        let ex = RawExecutor::<UringReactor>::new().unwrap();

        let ex2 = ex.clone();
        let t = thread::spawn(move || ex2.run_until(async {}));

        t.join().unwrap().unwrap();

        // Leave an uncompleted operation in the queue so that the drop impl will try to drive it to
        // completion.
        let (_rx, tx) = base::pipe(true).expect("Pipe failed");
        let tx = ex
            .reactor
            .register_source(&ex, &tx)
            .expect("Failed to register source");
        let bm = Arc::new(VecIoWrapper::from(0xf2e96u64.to_ne_bytes().to_vec()));
        let op = tx
            .start_write_from_mem(
                None,
                bm,
                [MemRegion {
                    offset: 0,
                    len: mem::size_of::<u64>(),
                }],
            )
            .expect("Failed to start write from mem");

        mem::drop(ex);

        match block_on(op).expect_err("Pending operation completed after executor was dropped") {
            Error::ExecutorGone => {}
            e => panic!("Unexpected error after dropping executor: {}", e),
        }
    }
}
