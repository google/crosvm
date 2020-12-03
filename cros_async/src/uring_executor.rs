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
use std::fs::File;
use std::future::Future;
use std::io;
use std::mem;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::pin::Pin;
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::sync::{Arc, Weak};
use std::task::Waker;
use std::task::{Context, Poll};
use std::thread::{self, ThreadId};

use async_task::Task;
use futures::task::{noop_waker, waker_ref, ArcWake};
use io_uring::URingContext;
use pin_utils::pin_mut;
use slab::Slab;
use sync::Mutex;
use sys_util::{warn, EventFd, WatchingEvents};
use thiserror::Error as ThisError;

use crate::queue::RunnableQueue;
use crate::uring_mem::{BackingMemory, MemRegion, VecIoWrapper};
use crate::waker::WakerToken;

#[derive(Debug, ThisError)]
pub enum Error {
    /// Failed to clone the EventFd for waking the executor.
    #[error("Failed to clone the EventFd for waking the executor: {0}")]
    CloneEventFd(sys_util::Error),
    /// Failed to create the EventFd for waking the executor.
    #[error("Failed to create the EventFd for waking the executor: {0}")]
    CreateEventFd(sys_util::Error),
    /// Failed to copy the FD for the polling context.
    #[error("Failed to copy the FD for the polling context: {0}")]
    DuplicatingFd(sys_util::Error),
    /// The Executor is gone.
    #[error("The URingExecutor is gone")]
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
    /// Creating a context to wait on FDs failed.
    #[error("Error creating the fd waiting context: {0}")]
    CreatingContext(io_uring::Error),
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

pub struct RegisteredSource {
    tag: usize,
    ex: Weak<RawExecutor>,
}

impl RegisteredSource {
    pub fn start_read_to_mem(
        &self,
        file_offset: u64,
        mem: Arc<dyn BackingMemory + Send + Sync>,
        addrs: &[MemRegion],
    ) -> Result<PendingOperation> {
        let ex = self.ex.upgrade().ok_or(Error::ExecutorGone)?;
        let token = ex.submit_read_to_vectored(self, mem, file_offset, addrs)?;

        Ok(PendingOperation {
            waker_token: Some(token),
            ex: self.ex.clone(),
        })
    }

    pub fn start_write_from_mem(
        &self,
        file_offset: u64,
        mem: Arc<dyn BackingMemory + Send + Sync>,
        addrs: &[MemRegion],
    ) -> Result<PendingOperation> {
        let ex = self.ex.upgrade().ok_or(Error::ExecutorGone)?;
        let token = ex.submit_write_from_vectored(self, mem, file_offset, addrs)?;

        Ok(PendingOperation {
            waker_token: Some(token),
            ex: self.ex.clone(),
        })
    }

    pub fn start_fallocate(&self, offset: u64, len: u64, mode: u32) -> Result<PendingOperation> {
        let ex = self.ex.upgrade().ok_or(Error::ExecutorGone)?;
        let token = ex.submit_fallocate(self, offset, len, mode)?;

        Ok(PendingOperation {
            waker_token: Some(token),
            ex: self.ex.clone(),
        })
    }

    pub fn start_fsync(&self) -> Result<PendingOperation> {
        let ex = self.ex.upgrade().ok_or(Error::ExecutorGone)?;
        let token = ex.submit_fsync(self)?;

        Ok(PendingOperation {
            waker_token: Some(token),
            ex: self.ex.clone(),
        })
    }

    pub fn poll_fd_readable(&self) -> Result<PendingOperation> {
        let events = WatchingEvents::empty().set_read();

        let ex = self.ex.upgrade().ok_or(Error::ExecutorGone)?;
        let token = ex.submit_poll(self, &events)?;

        Ok(PendingOperation {
            waker_token: Some(token),
            ex: self.ex.clone(),
        })
    }
}

impl Drop for RegisteredSource {
    fn drop(&mut self) {
        if let Some(ex) = self.ex.upgrade() {
            let _ = ex.deregister_source(self);
        }
    }
}

// This function exists to guarantee that non-uring futures will not starve until a uring future is
// ready to be polled again. The mechanism is very similar to the self-pipe trick used by C programs
// to reliably mix select / poll with signal handling. This is how it works:
//
// * RawExecutor::new creates an eventfd, dupes it, and spawns this async function with the duped fd.
// * The first time notify_task is polled it will add a read on the eventfd to the uring.
// * Meanwhile the RawExecutor keeps the original fd for the eventfd.
// * Whenever RawExecutor::wake is called it will write to the eventfd if it determines that the
//   executor thread is currently blocked inside an io_uring_enter call. This can happen when a
//   non-uring future becomes ready to poll.
// * The write to the eventfd allows the read that we queued earlier to complete, which then causes
//   the io_uring_enter call to return with at least one completed operation.
// * The executor then polls the non-uring future that became ready, any uring futures that
//   completed, and the notify_task function, which then queues up another read on the eventfd and
//   the process can repeat.
//
// # Dropping the executor.
//
// When the URingExecutor is dropped it needs to block until all uring operations have completed
// since the kernel is borrowing the memory associated with those operations. To ensure that the
// notify_task doesn't cause the drop impl to block indefinitely, RawExecutor::drop writes to the
// eventfd one more time. The next time notify_task is polled it will get an ExecutorGone error,
// which it uses as a sign to break the loop and return.
async fn notify_task(notify: EventFd, raw: Weak<RawExecutor>) {
    // Safe because notify has a valid fd and we are just transferring it into a File.
    let f = unsafe { File::from_raw_fd(notify.into_raw_fd()) };
    let source = if let Some(ex) = raw.upgrade() {
        let tag = ex.register_source(Arc::new(f));

        // This is probably not necessary but drop order in rust is weird and we definitely don't
        // want to hold an active reference to the executor in the loop below.
        mem::drop(ex);

        RegisteredSource {
            tag,
            ex: raw.clone(),
        }
    } else {
        // The executor is already gone so just exit.
        return;
    };

    let buf = Arc::new(VecIoWrapper::from(0u64.to_ne_bytes().to_vec()));
    while let Some(ex) = raw.upgrade() {
        let token = ex
            .submit_read_to_vectored(
                &source,
                buf.clone(),
                0,
                &[MemRegion {
                    offset: 0,
                    len: buf.len(),
                }],
            )
            .expect("Failed to start notify_task read");

        // We don't want to hold an active reference to the executor in the .await below.
        mem::drop(ex);

        let op = PendingOperation {
            waker_token: Some(token),
            ex: raw.clone(),
        };

        match op.await {
            Ok(ret) => {
                if ret != mem::size_of::<u64>() as u32 {
                    panic!("Unexpected return value from notify EventFd");
                }
            }
            Err(Error::ExecutorGone) => break,
            Err(e) => panic!("Failed to read notify_task EventFd: {}", e),
        }
    }
}

// Indicates that the executor is either within or about to make an io_uring_enter syscall. When a
// waker sees this value, it will write to the notify EventFd, which will cause the io_uring_enter
// call to return.
const WAITING: i32 = 0xb80d_21b5u32 as i32;

// Indicates that the executor is processing any futures that are ready to run.
const PROCESSING: i32 = 0xdb31_83a3u32 as i32;

// Indicates that one or more futures may be ready to make progress.
const WOKEN: i32 = 0x0fc7_8f7eu32 as i32;

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
    Pending(OpData),
    Completed(Option<::std::io::Result<u32>>),
}

struct Ring {
    ops: Slab<OpStatus>,
    registered_sources: Slab<Arc<File>>,
}

struct RawExecutor {
    queue: RunnableQueue,
    ctx: Mutex<URingContext>,
    ring: Mutex<Ring>,
    thread_id: Mutex<Option<ThreadId>>,
    state: AtomicI32,
    notify: EventFd,
}

impl RawExecutor {
    fn new(notify: EventFd) -> Result<RawExecutor> {
        let ctx = URingContext::new(NUM_ENTRIES).map_err(Error::CreatingContext)?;
        Ok(RawExecutor {
            queue: RunnableQueue::new(),
            ctx: Mutex::new(ctx),
            ring: Mutex::new(Ring {
                ops: Slab::with_capacity(NUM_ENTRIES),
                registered_sources: Slab::with_capacity(NUM_ENTRIES),
            }),
            thread_id: Mutex::new(None),
            state: AtomicI32::new(PROCESSING),
            notify,
        })
    }

    fn wake(&self) {
        let oldstate = self.state.swap(WOKEN, Ordering::Release);
        if oldstate == WAITING {
            if let Err(e) = self.notify.write(1) {
                warn!("Failed to notify executor that a future is ready: {}", e);
            }
        }
    }

    fn spawn<F>(self: &Arc<Self>, f: F) -> Task<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let raw = Arc::downgrade(self);
        let schedule = move |runnable| {
            if let Some(r) = raw.upgrade() {
                r.queue.schedule(runnable);
            }
        };
        let (runnable, task) = async_task::spawn(f, schedule);
        self.queue.schedule(runnable);
        task
    }

    fn spawn_local<F>(self: &Arc<Self>, f: F) -> Task<F::Output>
    where
        F: Future + 'static,
        F::Output: 'static,
    {
        let raw = Arc::downgrade(self);
        let schedule = move |runnable| {
            if let Some(r) = raw.upgrade() {
                r.queue.schedule(runnable);
            }
        };
        let (runnable, task) = async_task::spawn_local(f, schedule);
        self.queue.schedule(runnable);
        task
    }

    fn run<F: Future>(&self, cx: &mut Context, done: F) -> Result<F::Output> {
        let current_thread = thread::current().id();
        let mut thread_id = self.thread_id.lock();
        assert_eq!(
            *thread_id.get_or_insert(current_thread),
            current_thread,
            "`URingExecutor::run` cannot be called from more than one thread"
        );
        mem::drop(thread_id);

        pin_mut!(done);
        loop {
            self.state.store(PROCESSING, Ordering::Release);
            self.queue.set_waker(cx.waker().clone());
            for runnable in self.queue.iter() {
                runnable.run();
            }

            if let Poll::Ready(val) = done.as_mut().poll(cx) {
                return Ok(val);
            }

            let oldstate = self
                .state
                .compare_and_swap(PROCESSING, WAITING, Ordering::Acquire);
            if oldstate != PROCESSING {
                debug_assert_eq!(oldstate, WOKEN);
                // One or more futures have become runnable.
                continue;
            }

            // We need to make sure we always acquire the ring lock before the ctx lock. TODO: drop
            // the ctx lock once UringContext is Sync.
            let mut ring = self.ring.lock();
            let mut ctx = self.ctx.lock();
            let events = ctx.wait().map_err(Error::URingEnter)?;

            // Set the state back to PROCESSING to prevent any tasks woken up by the loop below from
            // writing to the eventfd.
            self.state.store(PROCESSING, Ordering::Release);
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
                    OpStatus::Completed(_) => {
                        panic!("uring operation completed more than once")
                    }
                }
            }
        }
    }

    fn get_result(&self, token: &WakerToken, cx: &mut Context) -> Option<io::Result<u32>> {
        let mut ring = self.ring.lock();

        let op = ring
            .ops
            .get_mut(token.0)
            .expect("`get_result` called on unknown operation");
        match op {
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
        if let Some(op) = ring.ops.get_mut(token.0) {
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
                    ring.ops.remove(token.0);
                }
            }
        }
    }

    fn register_source(&self, f: Arc<File>) -> usize {
        self.ring.lock().registered_sources.insert(f)
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
        events: &sys_util::WatchingEvents,
    ) -> Result<WakerToken> {
        // We need to make sure we always acquire the ring lock before the ctx lock. TODO: drop
        // the ctx lock once UringContext is Sync.
        let mut ring = self.ring.lock();
        let mut ctx = self.ctx.lock();

        let src = ring
            .registered_sources
            .get(source.tag)
            .map(Arc::clone)
            .ok_or(Error::InvalidSource)?;
        let entry = ring.ops.vacant_entry();
        let next_op_token = entry.key();
        ctx.add_poll_fd(src.as_raw_fd(), events, usize_to_u64(next_op_token))
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
        // We need to make sure we always acquire the ring lock before the ctx lock. TODO: drop
        // the ctx lock once UringContext is Sync.
        let mut ring = self.ring.lock();
        let mut ctx = self.ctx.lock();

        let src = ring
            .registered_sources
            .get(source.tag)
            .map(Arc::clone)
            .ok_or(Error::InvalidSource)?;
        let entry = ring.ops.vacant_entry();
        let next_op_token = entry.key();
        ctx.add_fallocate(
            src.as_raw_fd(),
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

    fn submit_fsync(&self, source: &RegisteredSource) -> Result<WakerToken> {
        // We need to make sure we always acquire the ring lock before the ctx lock. TODO: drop
        // the ctx lock once UringContext is Sync.
        let mut ring = self.ring.lock();
        let mut ctx = self.ctx.lock();

        let src = ring
            .registered_sources
            .get(source.tag)
            .map(Arc::clone)
            .ok_or(Error::InvalidSource)?;
        let entry = ring.ops.vacant_entry();
        let next_op_token = entry.key();
        ctx.add_fsync(src.as_raw_fd(), usize_to_u64(next_op_token))
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
        offset: u64,
        addrs: &[MemRegion],
    ) -> Result<WakerToken> {
        if addrs
            .iter()
            .any(|&mem_range| mem.get_iovec(mem_range).is_err())
        {
            return Err(Error::InvalidOffset);
        }

        // We need to make sure we always acquire the ring lock before the ctx lock. TODO: drop
        // the ctx lock once UringContext is Sync.
        let mut ring = self.ring.lock();
        let mut ctx = self.ctx.lock();

        let src = ring
            .registered_sources
            .get(source.tag)
            .map(Arc::clone)
            .ok_or(Error::InvalidSource)?;

        // We can't insert the OpData into the slab yet because `iovecs` borrows `mem` below.
        let entry = ring.ops.vacant_entry();
        let next_op_token = entry.key();

        // The addresses have already been validated, so unwrapping them will succeed.
        // validate their addresses before submitting.
        let iovecs = addrs
            .iter()
            .map(|&mem_range| mem.get_iovec(mem_range).unwrap().iovec());

        unsafe {
            // Safe because all the addresses are within the Memory that an Arc is kept for the
            // duration to ensure the memory is valid while the kernel accesses it.
            // Tested by `dont_drop_backing_mem_read` unit test.
            ctx.add_readv_iter(iovecs, src.as_raw_fd(), offset, usize_to_u64(next_op_token))
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
        offset: u64,
        addrs: &[MemRegion],
    ) -> Result<WakerToken> {
        if addrs
            .iter()
            .any(|&mem_range| mem.get_iovec(mem_range).is_err())
        {
            return Err(Error::InvalidOffset);
        }

        // We need to make sure we always acquire the ring lock before the ctx lock. TODO: drop
        // the ctx lock once UringContext is Sync.
        let mut ring = self.ring.lock();
        let mut ctx = self.ctx.lock();

        let src = ring
            .registered_sources
            .get(source.tag)
            .map(Arc::clone)
            .ok_or(Error::InvalidSource)?;

        // We can't insert the OpData into the slab yet because `iovecs` borrows `mem` below.
        let entry = ring.ops.vacant_entry();
        let next_op_token = entry.key();

        // The addresses have already been validated, so unwrapping them will succeed.
        // validate their addresses before submitting.
        let iovecs = addrs
            .iter()
            .map(|&mem_range| mem.get_iovec(mem_range).unwrap().iovec());

        unsafe {
            // Safe because all the addresses are within the Memory that an Arc is kept for the
            // duration to ensure the memory is valid while the kernel accesses it.
            // Tested by `dont_drop_backing_mem_write` unit test.
            ctx.add_writev_iter(iovecs, src.as_raw_fd(), offset, usize_to_u64(next_op_token))
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

impl ArcWake for RawExecutor {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        RawExecutor::wake(arc_self);
    }
}

impl Drop for RawExecutor {
    // We need to block until there are no more uring operations as the kernel may still be
    // using the memory associated with them.
    fn drop(&mut self) {
        // Wake up the notify_task. We set the state to WAITING here so that wake() will write to
        // the eventfd.
        self.state.store(WAITING, Ordering::Release);
        self.wake();

        let ring = self.ring.get_mut();
        let mut to_remove = Vec::with_capacity(ring.ops.len());
        for (tag, op) in ring.ops.iter_mut() {
            match op {
                OpStatus::Pending(data) => {
                    // If the operation wasn't already canceled then wake up the future waiting on
                    // it. When polled that future will get an ExecutorGone error anyway so there's
                    // no point in waiting until the operation completes to wake it up.
                    if !data.canceled {
                        if let Some(waker) = data.waker.take() {
                            waker.wake();
                        }
                    }

                    // Now mark this operation canceled so that it will be removed once it
                    // completes.
                    data.canceled = true;
                }

                OpStatus::Completed(_) => {
                    // The future waiting on this operation hasn't collected the result yet but if
                    // it tries to get the result now it will just get an ExecutorGone error. Remove
                    // this operation ourselves.
                    to_remove.push(tag);
                }
            }
        }

        for tag in to_remove {
            ring.ops.remove(tag);
        }

        struct ShouldExit<'a> {
            ring: &'a Mutex<Ring>,
        }

        impl<'a> Future for ShouldExit<'a> {
            type Output = ();

            fn poll(self: Pin<&mut Self>, _: &mut Context) -> Poll<()> {
                if self.ring.lock().ops.is_empty() {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            }
        }

        // Now run the uring until all pending operations have completed.
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let res = self.run(&mut cx, ShouldExit { ring: &self.ring });

        if let Err(e) = res {
            warn!("Failed to drive uring to completion: {}", e);
        }
    }
}

/// An executor that uses io_uring for its asynchronous I/O operations. See the documentation of
/// `Executor` for more details about the methods.
#[derive(Clone)]
pub struct URingExecutor {
    raw: Arc<RawExecutor>,
}

impl URingExecutor {
    pub fn new() -> Result<URingExecutor> {
        let notify = EventFd::new().map_err(Error::CreateEventFd)?;
        let raw = notify
            .try_clone()
            .map_err(Error::CloneEventFd)
            .and_then(RawExecutor::new)
            .map(Arc::new)?;

        raw.spawn(notify_task(notify, Arc::downgrade(&raw)))
            .detach();

        Ok(URingExecutor { raw })
    }

    pub fn spawn<F>(&self, f: F) -> Task<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.raw.spawn(f)
    }

    pub fn spawn_local<F>(&self, f: F) -> Task<F::Output>
    where
        F: Future + 'static,
        F::Output: 'static,
    {
        self.raw.spawn_local(f)
    }

    pub fn run(&self) -> Result<()> {
        let waker = waker_ref(&self.raw);
        let mut cx = Context::from_waker(&waker);

        self.raw.run(&mut cx, crate::empty::<()>())
    }

    pub fn run_until<F: Future>(&self, f: F) -> Result<F::Output> {
        let waker = waker_ref(&self.raw);
        let mut ctx = Context::from_waker(&waker);
        self.raw.run(&mut ctx, f)
    }

    /// Register a file and memory pair for buffered asynchronous operation.
    pub(crate) fn register_source<F: AsRawFd>(&self, fd: &F) -> Result<RegisteredSource> {
        let duped_fd = unsafe {
            // Safe because duplicating an FD doesn't affect memory safety, and the dup'd FD
            // will only be added to the poll loop.
            File::from_raw_fd(dup_fd(fd.as_raw_fd())?)
        };

        Ok(RegisteredSource {
            tag: self.raw.register_source(Arc::new(duped_fd)),
            ex: Arc::downgrade(&self.raw),
        })
    }
}

// Used to dup the FDs passed to the executor so there is a guarantee they aren't closed while
// waiting in TLS to be added to the main polling context.
unsafe fn dup_fd(fd: RawFd) -> Result<RawFd> {
    let ret = libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0);
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

pub struct PendingOperation {
    waker_token: Option<WakerToken>,
    ex: Weak<RawExecutor>,
}

impl Future for PendingOperation {
    type Output = Result<u32>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let token = self
            .waker_token
            .as_ref()
            .expect("PendingOperation polled after returning Poll::Ready");
        if let Some(ex) = self.ex.upgrade() {
            if let Some(result) = ex.get_result(token, cx) {
                self.waker_token = None;
                Poll::Ready(result.map_err(Error::Io))
            } else {
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
                ex.cancel_operation(waker_token);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::io::{Read, Write};
    use std::mem;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use super::*;
    use crate::uring_mem::{BackingMemory, MemRegion, VecIoWrapper};

    async fn pending() {
        Pending { is_ready: false }.await
    }

    struct Pending {
        is_ready: bool,
    }

    impl Future for Pending {
        type Output = ();
        fn poll(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
            if self.is_ready {
                Poll::Ready(())
            } else {
                self.is_ready = true;
                Poll::Pending
            }
        }
    }

    #[test]
    fn dont_drop_backing_mem_read() {
        // Create a backing memory wrapped in an Arc and check that the drop isn't called while the
        // op is pending.
        let bm =
            Arc::new(VecIoWrapper::from(vec![0u8; 4096])) as Arc<dyn BackingMemory + Send + Sync>;

        // Use pipes to create a future that will block forever.
        let (rx, mut tx) = sys_util::pipe(true).unwrap();

        // Set up the TLS for the uring_executor by creating one.
        let ex = URingExecutor::new().unwrap();

        // Register the receive side of the pipe with the executor.
        let registered_source = ex.register_source(&rx).expect("register source failed");

        // Submit the op to the kernel. Next, test that the source keeps its Arc open for the duration
        // of the op.
        let pending_op = registered_source
            .start_read_to_mem(0, Arc::clone(&bm), &[MemRegion { offset: 0, len: 8 }])
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
        tx.write(&[0u8; 8]).expect("write failed");
        ex.run_until(pending())
            .expect("Failed to wait for read pipe ready");
        assert_eq!(Arc::strong_count(&bm), 1);
    }

    #[test]
    fn dont_drop_backing_mem_write() {
        // Create a backing memory wrapped in an Arc and check that the drop isn't called while the
        // op is pending.
        let bm =
            Arc::new(VecIoWrapper::from(vec![0u8; 4096])) as Arc<dyn BackingMemory + Send + Sync>;

        // Use pipes to create a future that will block forever.
        let (mut rx, tx) = sys_util::new_pipe_full().expect("Pipe failed");

        // Set up the TLS for the uring_executor by creating one.
        let ex = URingExecutor::new().unwrap();

        // Register the receive side of the pipe with the executor.
        let registered_source = ex.register_source(&tx).expect("register source failed");

        // Submit the op to the kernel. Next, test that the source keeps its Arc open for the duration
        // of the op.
        let pending_op = registered_source
            .start_write_from_mem(0, Arc::clone(&bm), &[MemRegion { offset: 0, len: 8 }])
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
        let mut buf = vec![0u8; sys_util::round_up_to_page_size(1)];
        rx.read(&mut buf).expect("read to empty failed");
        ex.run_until(pending())
            .expect("Failed to wait for read pipe ready");
        assert_eq!(Arc::strong_count(&bm), 1);
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

        let bm =
            Arc::new(VecIoWrapper::from(vec![0u8; 16])) as Arc<dyn BackingMemory + Send + Sync>;

        let (rx, tx) = sys_util::pipe(true).expect("Pipe failed");

        let ex = URingExecutor::new().unwrap();

        let rx_source = ex.register_source(&rx).expect("register source failed");
        let tx_source = ex.register_source(&tx).expect("register source failed");

        let read_task = rx_source
            .start_read_to_mem(0, Arc::clone(&bm), &[MemRegion { offset: 0, len: 8 }])
            .expect("failed to start read to mem");

        ex.spawn_local(cancel_io(read_task)).detach();

        // Write to the pipe so that the kernel operation will complete.
        let buf =
            Arc::new(VecIoWrapper::from(vec![0xc2u8; 16])) as Arc<dyn BackingMemory + Send + Sync>;
        let write_task = tx_source
            .start_write_from_mem(0, Arc::clone(&buf), &[MemRegion { offset: 0, len: 8 }])
            .expect("failed to start write from mem");

        ex.run_until(check_result(write_task, 8))
            .expect("Failed to run executor");
    }

    #[test]
    fn drop_before_completion() {
        const VALUE: u64 = 0xef6c_a8df_b842_eb9c;

        async fn check_op(op: PendingOperation) {
            let err = op.await.expect_err("Op completed successfully");
            match err {
                Error::ExecutorGone => {}
                e => panic!("Unexpected error from op: {}", e),
            }
        }

        let (mut rx, tx) = sys_util::pipe(true).expect("Pipe failed");

        let ex = URingExecutor::new().unwrap();

        let tx = ex.register_source(&tx).expect("Failed to register source");
        let bm = Arc::new(VecIoWrapper::from(VALUE.to_ne_bytes().to_vec()));
        let op = tx
            .start_write_from_mem(
                0,
                bm,
                &[MemRegion {
                    offset: 0,
                    len: mem::size_of::<u64>(),
                }],
            )
            .expect("Failed to start write from mem");

        ex.spawn_local(check_op(op)).detach();

        // Now drop the executor. It should still run until the write to the pipe is complete.
        mem::drop(ex);
        mem::drop(tx);

        let mut buf = 0u64.to_ne_bytes();
        rx.read(&mut buf[..]).expect("Failed to read from pipe");

        assert_eq!(u64::from_ne_bytes(buf), VALUE);
    }
}
