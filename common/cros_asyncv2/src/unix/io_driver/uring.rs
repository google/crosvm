// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::alloc::Layout;
use std::any::Any;
use std::cell::RefCell;
use std::cmp::min;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::ffi::CStr;
use std::future::Future;
use std::io;
use std::mem::replace;
use std::mem::size_of;
use std::mem::MaybeUninit;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::RawFd;
use std::pin::Pin;
use std::ptr;
use std::rc::Rc;
use std::sync::Arc;
use std::task;
use std::task::Poll;
use std::time::Duration;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::ensure;
use anyhow::Context;
use base::error;
use base::warn;
use base::AsRawDescriptor;
use base::FromRawDescriptor;
use base::LayoutAllocation;
use base::SafeDescriptor;
use data_model::IoBufMut;
use io_uring::cqueue;
use io_uring::cqueue::buffer_select;
use io_uring::opcode;
use io_uring::squeue;
use io_uring::types::Fd;
use io_uring::types::FsyncFlags;
use io_uring::types::SubmitArgs;
use io_uring::types::Timespec;
use io_uring::Builder;
use io_uring::IoUring;
use io_uring::Probe;
use once_cell::sync::Lazy;
use once_cell::sync::OnceCell;
use slab::Slab;
use thiserror::Error as ThisError;

use super::cmsg::*;
use crate::AsIoBufs;
use crate::OwnedIoBuf;

// For now all buffers live in the same buffer group.
const BUFFER_GROUP: u16 = 0;
// The top 8 bits of the buffer id encode the index of the LayoutAllocation and the bottom 8 bits
// encode the index of the buffer within that allocation.
const ALLOC_IDX_SHIFT: usize = 8;
const BUFFERS_PER_ALLOC: u16 = 32;
const BUFFER_IDX_MASK: u16 = (1 << ALLOC_IDX_SHIFT) - 1;

// Number of entries in the ring.
const NUM_ENTRIES: u32 = 256;

// The user_data for the waker. Since our user_data is based on the index in a Slab we'll run out of
// memory well before a real operation gets usize::MAX as the index.
const WAKER_DATA: usize = usize::MAX;

// The global IoUring instance. Each thread-local IoUring shares its kernel backend with this
// instance.
static GLOBAL_URING: OnceCell<IoUring> = OnceCell::new();
static URING_STATUS: Lazy<UringStatus> = Lazy::new(|| {
    let mut utsname = MaybeUninit::zeroed();

    // Safe because this will only modify `utsname` and we check the return value.
    let res = unsafe { libc::uname(utsname.as_mut_ptr()) };
    if res < 0 {
        return UringStatus::Disabled;
    }

    // Safe because the kernel has initialized `utsname`.
    let utsname = unsafe { utsname.assume_init() };

    // Safe because the pointer is valid and the kernel guarantees that this is a valid C string.
    let release = unsafe { CStr::from_ptr(utsname.release.as_ptr()) };

    let mut components = match release.to_str().map(|r| r.split('.').map(str::parse)) {
        Ok(c) => c,
        Err(_) => return UringStatus::Disabled,
    };

    // Kernels older than 5.10 either didn't support io_uring or had bugs in the implementation.
    match (components.next(), components.next()) {
        (Some(Ok(major)), Some(Ok(minor))) if (major, minor) >= (5, 10) => {
            // The kernel version is new enough so check if we can actually make a uring context.
            if probe_uring().is_ok() {
                UringStatus::Enabled(major, minor)
            } else {
                UringStatus::Disabled
            }
        }
        _ => UringStatus::Disabled,
    }
});
static EXT_ARG_SUPPORTED: Lazy<bool> = Lazy::new(
    || matches!(&*URING_STATUS, UringStatus::Enabled(major, minor) if (*major, *minor) >= (5, 11)),
);

#[derive(Debug)]
enum UringStatus {
    Enabled(usize, usize),
    Disabled,
}

thread_local! (static THREAD_STATE: OnceCell<Rc<RefCell<State>>> = OnceCell::new());
fn new_state() -> anyhow::Result<Rc<RefCell<State>>> {
    State::new().map(RefCell::new).map(Rc::new)
}

fn with_state<F, R>(f: F) -> anyhow::Result<R>
where
    F: FnOnce(&mut State) -> anyhow::Result<R>,
{
    THREAD_STATE.with(|thread_state| {
        let state = thread_state.get_or_try_init(new_state)?;
        f(&mut state.borrow_mut())
    })
}

fn clone_state() -> anyhow::Result<Rc<RefCell<State>>> {
    THREAD_STATE.with(|thread_state| thread_state.get_or_try_init(new_state).map(Rc::clone))
}

#[derive(Debug, ThisError)]
enum ErrorContext {
    #[error("`io_uring_enter` failed")]
    EnterFailed,
    #[error("failed to return buffer to kernel")]
    ReturnBuffer,
    #[error("`SubmissionQueue` full")]
    SubmissionQueueFull,
}

fn probe_uring() -> anyhow::Result<()> {
    const REQUIRED_OPS: &[u8] = &[
        opcode::Accept::CODE,
        opcode::AsyncCancel::CODE,
        opcode::Connect::CODE,
        opcode::Fallocate::CODE,
        opcode::Fsync::CODE,
        opcode::PollAdd::CODE,
        opcode::ProvideBuffers::CODE,
        opcode::Read::CODE,
        opcode::Readv::CODE,
        opcode::RecvMsg::CODE,
        opcode::SendMsg::CODE,
        opcode::Write::CODE,
        opcode::Writev::CODE,
    ];
    let uring = IoUring::new(8)?;
    let mut probe = Probe::new();
    uring.submitter().register_probe(&mut probe)?;
    if REQUIRED_OPS
        .iter()
        .all(|&opcode| probe.is_supported(opcode))
    {
        Ok(())
    } else {
        bail!("Not all required uring operations supported")
    }
}

pub fn use_uring() -> bool {
    match &*URING_STATUS {
        UringStatus::Enabled(_, _) => true,
        UringStatus::Disabled => false,
    }
}

struct State {
    uring: IoUring,
    waker: Waker,
    ops: Slab<OpStatus>,
    buffers: [LayoutAllocation; 5],
}

impl State {
    fn new() -> anyhow::Result<State> {
        let global_uring = GLOBAL_URING.get_or_try_init(|| IoUring::new(NUM_ENTRIES))?;

        // The `setup_attach_wq` call here ensures that each thread shares the same backend in the
        // kernel but has its own separate completion and submission queues, avoiding the need to do
        // expensive synchronization when touching those queues in userspace.
        let uring = Builder::default()
            .setup_attach_wq(global_uring.as_raw_fd())
            .build(NUM_ENTRIES)?;
        let waker = Waker::new()?;
        let ops = Slab::new();
        let buffers = [
            new_buffer_allocation(64),
            new_buffer_allocation(128),
            new_buffer_allocation(256),
            new_buffer_allocation(512),
            new_buffer_allocation(1024),
        ];
        let mut state = State {
            uring,
            waker,
            ops,
            buffers,
        };

        for (idx, alloc) in state.buffers.iter().enumerate() {
            let layout = alloc.layout();
            debug_assert_eq!(layout.size(), layout.align() * BUFFERS_PER_ALLOC as usize);

            // We can't use `State::provide_buffers` directly here because `state` is already
            // borrowed by the for loop.
            let entry = opcode::ProvideBuffers::new(
                alloc.as_ptr(),
                layout.align() as i32,
                BUFFERS_PER_ALLOC,
                BUFFER_GROUP,
                pack_buffer_id(idx, 0),
            )
            .build()
            .user_data(idx as u64);

            // Safety: The allocation is valid for `layout.align() * BUFFERS_PER_ALLOC` bytes of
            // memory and is valid for the lifetime of the `IoUring` because it lives in the same
            // struct.
            unsafe { state.uring.submission().push(&entry) }
                .context("failed to submit `ProvideBuffers` operation")?;
        }

        // Wait for all the `ProvideBuffers` operations to finish.
        let count = state
            .uring
            .submit_and_wait(state.buffers.len())
            .context(ErrorContext::EnterFailed)?;
        debug_assert_eq!(count, state.buffers.len());

        for entry in state.uring.completion() {
            if entry.result() < 0 {
                return Err(io::Error::from_raw_os_error(-entry.result()))
                    .context("failed to provide buffers to io_uring");
            }
        }

        // Now start the waker that other threads can use to break us out of an `io_uring_enter`
        // syscall.
        state.submit_waker()?;

        Ok(state)
    }

    fn getevents(&mut self) -> anyhow::Result<()> {
        let (submitter, squeue, _) = self.uring.split();
        let to_submit = squeue.len();
        let min_complete = 0;

        // This flag should really be provided by the `io_uring` crate directly.
        const IORING_ENTER_GETEVENTS: u32 = 1 << 0;

        // We need to manually call `Submitter::enter` here because `submit_and_wait` will only add
        // the `IORING_ENTER_GETEVENTS` flag when `want > 0`.
        // Safety: the kernel will only ready `to_submit` entries from the submission queue,
        // which have all been initialized.
        unsafe {
            submitter.enter::<libc::sigset_t>(
                to_submit as u32,
                min_complete,
                IORING_ENTER_GETEVENTS,
                None,
            )
        }
        .map(drop)
        .context(ErrorContext::EnterFailed)
    }

    fn submit_timer(&mut self, ts: Box<Timespec>) -> anyhow::Result<()> {
        let slot = self.ops.vacant_entry();
        let entry = opcode::Timeout::new(&*ts)
            .build()
            .user_data(slot.key() as u64);

        slot.insert(OpStatus::System(ts));

        // Safety: the entry is valid and we can guarantee that the Timespec will live for the
        // lifetime of the operation.
        unsafe { self.submit_entry(&entry) }
    }

    fn wait(&mut self, timeout: Option<Duration>) -> anyhow::Result<()> {
        if let Some(timeout) = timeout {
            if timeout > Duration::from_secs(0) {
                let ts = Timespec::new()
                    .sec(timeout.as_secs())
                    .nsec(timeout.subsec_nanos());
                if *EXT_ARG_SUPPORTED {
                    let args = SubmitArgs::new().timespec(&ts);
                    self.uring
                        .submitter()
                        .submit_with_args(1, &args)
                        .map(drop)
                        .context(ErrorContext::EnterFailed)
                } else {
                    // Since `IORING_ENTER_EXT_ARG` is not supported we need to add a `Timeout`
                    // operation and then do a regular wait.
                    self.submit_timer(Box::new(ts))?;
                    self.uring
                        .submit_and_wait(1)
                        .map(drop)
                        .context(ErrorContext::EnterFailed)
                }
            } else {
                // A zero timeout means we should submit new operations and fetch any completed
                // operations without blocking.
                self.getevents()
            }
        } else {
            self.uring
                .submit_and_wait(1)
                .map(drop)
                .context(ErrorContext::EnterFailed)
        }
    }

    // Dispatches all completed IO operations. Returns true if one of the completed operations was the
    // thread waker.
    fn dispatch(&mut self) -> anyhow::Result<()> {
        let mut waker_entry = None;
        let mut needs_cleanup = Vec::new();
        for entry in self.uring.completion() {
            let idx = entry.user_data() as usize;
            if idx == WAKER_DATA {
                waker_entry = Some(entry);
                continue;
            }
            let status = replace(&mut self.ops[idx], OpStatus::Ready(entry));
            match status {
                OpStatus::New(_) => {
                    panic!("Received completion for operation that has not been started")
                }
                OpStatus::Waiting(w) => w.wake(),
                OpStatus::Ready(_) => panic!("Received completion for finished operation"),
                OpStatus::Canceled(cleanup, _) => {
                    let entry = if let OpStatus::Ready(entry) = self.ops.remove(idx) {
                        entry
                    } else {
                        panic!();
                    };
                    if let Some(c) = cleanup {
                        needs_cleanup.push((c, entry));
                    }
                }
                OpStatus::System(_) => drop(self.ops.remove(idx)),
                OpStatus::Processing | OpStatus::Finished => {
                    panic!("Unexpected state for `OpStatus`")
                }
            }
        }

        if !needs_cleanup.is_empty() || waker_entry.is_some() {
            // When there is a completion queue overflow, we can end up in an infinite loop:
            // submit_entry() -> cq_overflow() -> dispatch() -> provide_buffers() / submit_waker()
            // -> submit_entry(). Now that we've drained the completion queue, submit any pending
            // operations in the submission queue to break the loop.
            if self.uring.submission().cq_overflow() {
                self.uring.submit()?;
            }
        }

        if let Some(entry) = waker_entry {
            // We were woken up so return the buffer to the kernel and resubmit the waker.
            let SelectedBuffer { ptr, len, cap, bid } = self
                .get_selected_buffer(entry)
                .context("failed to read from waker")?;
            debug_assert_eq!(len, size_of::<u64>());

            // Safety: this was a buffer that we previously provided so we know that it is valid and
            // lives at least as long as the `IoUring`.
            unsafe { self.provide_buffers(ptr, cap as i32, 1, BUFFER_GROUP, bid) }
                .context(ErrorContext::ReturnBuffer)?;

            self.submit_waker()?;
        }

        for (cleanup, entry) in needs_cleanup {
            cleanup(self, entry);
        }

        Ok(())
    }

    // Safety: This function has the same safety requirements as `SubmissionQueue::push`, namely that
    // the parameters of `entry` are valid and will be valid for the entire duration of the operation.
    unsafe fn submit_entry(&mut self, entry: &squeue::Entry) -> anyhow::Result<()> {
        if self.uring.submission().push(entry).is_err() {
            if self.uring.submission().cq_overflow() {
                self.dispatch()
                    .context("failed to dispatch completed ops during cqueue overflow")?;
            }
            self.uring.submit().context(ErrorContext::EnterFailed)?;
            self.uring
                .submission()
                .push(entry)
                .map_err(|_| io::Error::from_raw_os_error(libc::EBUSY))
                .context(ErrorContext::SubmissionQueueFull)
        } else {
            Ok(())
        }
    }

    fn submit_waker(&mut self) -> anyhow::Result<()> {
        let entry = opcode::Read::new(
            Fd(self.waker.0.as_raw_descriptor()),
            ptr::null_mut(),
            size_of::<u64>() as u32,
        )
        .buf_group(BUFFER_GROUP)
        .build()
        .user_data(WAKER_DATA as u64)
        .flags(squeue::Flags::BUFFER_SELECT);

        // Safety: the entry is valid and doesn't reference any memory.
        unsafe { self.submit_entry(&entry) }
    }

    // Safety: `buffer` must be a valid pointer to `len * nbufs` bytes of memory and must live at
    // least as long as `self`.
    unsafe fn provide_buffers(
        &mut self,
        buffer: *mut u8,
        len: i32,
        nbufs: u16,
        bgid: u16,
        bid: u16,
    ) -> anyhow::Result<()> {
        let slot = self.ops.vacant_entry();
        let idx = slot.key();
        let entry = opcode::ProvideBuffers::new(buffer, len, nbufs, bgid, bid)
            .build()
            .user_data(idx as u64);

        slot.insert(OpStatus::System(Box::new(())));

        // Safety: `buffer` is a valid pointer to `len * nbufs` bytes of memory and will be valid
        // for the lifetime of the `IoUring` because it lives at least as long as `self`.
        self.submit_entry(&entry)
    }

    // Returns the buffer selected by the kernel for `entry`. Panics if no buffer was selected by
    // the kernel.
    fn get_selected_buffer(&self, entry: cqueue::Entry) -> anyhow::Result<SelectedBuffer> {
        let len = entry_to_result(entry.clone())?;

        let bid = buffer_select(entry.flags()).expect("No buffer selected");
        let (alloc_idx, buffer_idx) = unpack_buffer_id(bid);
        let alloc = &self.buffers[alloc_idx];
        let layout = alloc.layout();
        let cap = layout.align();

        debug_assert!(len <= cap);
        debug_assert!(buffer_idx * layout.align() <= layout.size() - len);

        // Safety: the allocation is valid for at least `buffer_idx * layout.align()` bytes of
        // memory.
        let ptr = unsafe { alloc.as_ptr::<u8>().add(buffer_idx * layout.align()) };
        Ok(SelectedBuffer { ptr, len, cap, bid })
    }

    // Copies data from the kernel-selected buffer into the user-provided buffer and returns the
    // selected buffer to the kernel. Panics if no buffer was selected by the kernel.
    fn copy_from_selected_buffer(
        &mut self,
        entry: cqueue::Entry,
        buf: &mut [u8],
    ) -> anyhow::Result<usize> {
        let SelectedBuffer { ptr, len, cap, bid } = self.get_selected_buffer(entry)?;
        let count = min(len, buf.len());

        // Safety: both pointers point to at least `count` bytes of allocated memory.
        unsafe { ptr::copy_nonoverlapping(ptr, buf.as_mut_ptr(), count) };

        // Now that we've copied the data out we need to return the buffer to the kernel.
        // Safety: this is a buffer that was previously registered with the kernel and the caller
        // that registered it was required to guarantee that it lives as long as the `IoUring`.
        // We're reusing that guarantee here.
        unsafe { self.provide_buffers(ptr, cap as i32, 1, BUFFER_GROUP, bid) }
            .context(ErrorContext::ReturnBuffer)?;

        Ok(count)
    }

    fn cancel_op(&mut self, idx: usize) -> anyhow::Result<()> {
        // We're still waiting for the underlying IO to complete so try to cancel it if we can.
        let slot = self.ops.vacant_entry();
        let cancel = opcode::AsyncCancel::new(idx as u64)
            .build()
            .user_data(slot.key() as u64);

        slot.insert(OpStatus::System(Box::new(())));

        // Safety: The entry is valid and doesn't reference any memory.
        unsafe { self.submit_entry(&cancel) }.context("failed to submit async cancellation")
    }

    // TODO: Do we actually need any of this? Once the IoUring is dropped, the fd should be closed
    // so it doesn't seem necessary for us to actually drain it. It would be weird if the kernel
    // kept around references to memory once the uring fd is gone.
    // fn shutdown(&mut self, deadline: Instant) -> anyhow::Result<()> {
    //     // Every async operation owns a reference to the `State` and either removes itself from
    //     // `self.ops` or changes its status to `Canceled` when it is dropped so `self.ops` shouldn't
    //     // contain anything other than canceled and system operations.
    //     let pending = self
    //         .ops
    //         .iter_mut()
    //         .filter_map(|(idx, op)| match replace(op, OpStatus::Processing) {
    //             OpStatus::System(data) => {
    //                 *op = OpStatus::Canceled(data);
    //                 Some(idx)
    //             }
    //             OpStatus::Canceled(data) => {
    //                 *op = OpStatus::Canceled(data);
    //                 None
    //             }
    //             _ => panic!(
    //                 "Thread state dropped while there are still non-canceled operations pending"
    //             ),
    //         })
    //         .collect::<Vec<_>>();

    //     for idx in pending {
    //         self.cancel_op(idx)?;
    //     }

    //     // Wait for all the canceled operations to finish.
    //     if !self.ops.is_empty() {
    //         self.wait(
    //             self.ops.len(),
    //             Some(deadline.saturating_duration_since(Instant::now())),
    //         )?;
    //     }
    //     self.dispatch()?;

    //     let ext_arg_supported = *EXT_ARG_SUPPORTED;
    //     // When `IORING_ENTER_EXT_ARG` is not supported, there may still be a timer op left in
    //     // `self.ops`.
    //     if (ext_arg_supported && !self.ops.is_empty()) || (!ext_arg_supported && self.ops.len() > 1)
    //     {
    //         return Err(anyhow!(io::Error::from_raw_os_error(libc::ETIMEDOUT))).context(format!(
    //             "Still waiting for {} operations to finish",
    //             self.ops.len()
    //         ));
    //     }

    //     // The `Waker` is the last pending operation.
    //     self.waker.wake().context("failed to wake Waker")?;
    //     self.wait(1, Some(deadline.saturating_duration_since(Instant::now())))?;

    //     Ok(())
    // }
}

// TODO: Do we actually need this?  See State::shutdown above.
// impl Drop for State {
//     fn drop(&mut self) {
//         // How long we should wait to drain the `IoUring` before giving up.
//         const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
//         if let Err(e) = self.shutdown(Instant::now() + SHUTDOWN_TIMEOUT) {
//             process::abort();
//         }
//     }
// }

struct SelectedBuffer {
    ptr: *mut u8,
    len: usize,
    cap: usize,
    bid: u16,
}

fn new_buffer_allocation(size: usize) -> LayoutAllocation {
    let layout = Layout::from_size_align(size * usize::from(BUFFERS_PER_ALLOC), size)
        .expect("Invalid layout");
    LayoutAllocation::uninitialized(layout)
}

fn pack_buffer_id(alloc_idx: usize, buffer_idx: usize) -> u16 {
    debug_assert!(alloc_idx << ALLOC_IDX_SHIFT <= u16::MAX as usize);
    debug_assert_eq!(buffer_idx & usize::from(BUFFER_IDX_MASK), buffer_idx);
    ((alloc_idx << ALLOC_IDX_SHIFT) | buffer_idx) as u16
}

// Returns the index of the `LayoutAllocation` and the index of the buffer within that allocation.
fn unpack_buffer_id(bid: u16) -> (usize, usize) {
    let alloc_idx = (bid >> ALLOC_IDX_SHIFT).into();
    let buffer_idx = (bid & BUFFER_IDX_MASK).into();
    (alloc_idx, buffer_idx)
}

pub struct Waker(base::Event);
impl Waker {
    fn new() -> anyhow::Result<Waker> {
        base::Event::new()
            .map(Waker)
            .map_err(|e| anyhow!(io::Error::from(e)))
    }

    fn try_clone(&self) -> anyhow::Result<Waker> {
        self.0
            .try_clone()
            .map(Waker)
            .map_err(|e| anyhow!(io::Error::from(e)))
    }

    pub fn wake(&self) -> anyhow::Result<()> {
        self.0.signal().map_err(|e| anyhow!(io::Error::from(e)))
    }
}

pub fn new_waker() -> anyhow::Result<Waker> {
    with_state(|state| state.waker.try_clone())
}

// Wait for more events.
pub fn wait(timeout: Option<Duration>) -> anyhow::Result<()> {
    with_state(|state| state.wait(timeout))
}

// Wake up any tasks that are ready.
pub fn dispatch() -> anyhow::Result<()> {
    with_state(|state| state.dispatch())
}

enum OpStatus {
    New(squeue::Entry),
    Waiting(task::Waker),
    Ready(cqueue::Entry),
    Canceled(Option<fn(&mut State, cqueue::Entry)>, Box<dyn Any>),
    System(Box<dyn Any>),
    Processing,
    Finished,
}

struct Op<'a, B: Unpin + 'static> {
    state: Rc<RefCell<State>>,
    desc: &'a Arc<SafeDescriptor>,
    cleanup: Option<fn(&mut State, cqueue::Entry)>,
    buf: Option<B>,
    idx: usize,
}

impl<'a, B: Unpin + 'static> Future for Op<'a, B> {
    type Output = (anyhow::Result<cqueue::Entry>, Option<B>);

    fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        let mut state = self.state.borrow_mut();
        let status = replace(&mut state.ops[self.idx], OpStatus::Processing);

        match status {
            // We don't want to submit the operation to the kernel until this future is polled
            // because polling requires pinning and pinning guarantees that our drop impl will be
            // called, which is necessary to ensure that resources shared with the kernel will live
            // for the lifetime of the operation.
            OpStatus::New(entry) => {
                // Safety: The parameters in `Entry` are owned by `Op` and will be transferred to
                // the thread state if this `Op` is dropped, guaranteeing that they are valid for
                // the lifetime of the operation. Also see above for the drop guarantee.
                let res = unsafe { state.submit_entry(&entry) };

                if let Err(e) = res {
                    drop(state);
                    return Poll::Ready((Err(e), self.buf.take()));
                }

                state.ops[self.idx] = OpStatus::Waiting(cx.waker().clone());
            }
            OpStatus::Waiting(w) if !w.will_wake(cx.waker()) => {
                state.ops[self.idx] = OpStatus::Waiting(cx.waker().clone())
            }
            // If `cx.waker()` and the currently stored waker are the same then no need to do
            // anything.
            OpStatus::Waiting(w) => state.ops[self.idx] = OpStatus::Waiting(w),
            OpStatus::Ready(entry) => {
                state.ops[self.idx] = OpStatus::Finished;
                drop(state);

                let buf = self.buf.take();
                return Poll::Ready((Ok(entry), buf));
            }
            OpStatus::Canceled(_, _) => panic!("`Op` polled after drop"),
            OpStatus::System(_) | OpStatus::Processing => panic!("Unexpected state for `OpStatus`"),
            OpStatus::Finished => panic!("`Op` polled after returning `Poll::Ready`"),
        }

        Poll::Pending
    }
}

impl<'a, B: Unpin + 'static> Drop for Op<'a, B> {
    fn drop(&mut self) {
        let mut state = self.state.borrow_mut();
        let status = replace(&mut state.ops[self.idx], OpStatus::Processing);

        if let OpStatus::Waiting(_) = status {
            // If we're still waiting for the IO to finish then we cannot free the resources until
            // the operation is complete.
            if let Err(e) = state.cancel_op(self.idx) {
                warn!("Failed to cancel dropped operation: {:#}", e);
            }

            // Now take ownership of any resources associated with the canceled operation.
            state.ops[self.idx] = OpStatus::Canceled(
                self.cleanup.take(),
                Box::new((self.desc.clone(), self.buf.take())),
            )
        } else {
            // We have not shared any resources with the kernel so we can clean up the `OpStatus` now.
            state.ops.remove(self.idx);
        }
    }
}

fn start_op<B: Unpin + 'static>(
    state: Rc<RefCell<State>>,
    entry: squeue::Entry,
    desc: &Arc<SafeDescriptor>,
    cleanup: Option<fn(&mut State, cqueue::Entry)>,
    buf: Option<B>,
) -> Op<B> {
    let idx = {
        let mut state = state.borrow_mut();
        let slot = state.ops.vacant_entry();
        let idx = slot.key();
        slot.insert(OpStatus::New(entry.user_data(idx as u64)));
        idx
    };
    Op {
        state,
        desc,
        cleanup,
        buf,
        idx,
    }
}

fn entry_to_result(entry: cqueue::Entry) -> anyhow::Result<usize> {
    let res = entry.result();
    if res < 0 {
        Err(anyhow!(io::Error::from_raw_os_error(-res)))
    } else {
        Ok(res as usize)
    }
}

fn return_selected_buffer(state: &mut State, entry: cqueue::Entry) {
    let inner = || {
        let SelectedBuffer {
            ptr,
            len: _,
            cap,
            bid,
        } = state.get_selected_buffer(entry)?;

        // Safety: we are returning a buffer that was previously provided to the kernel so we know
        // it must live as long as the `IoUring`.
        unsafe { state.provide_buffers(ptr, cap as i32, 1, BUFFER_GROUP, bid) }
    };

    if let Err(e) = inner() {
        warn!(
            "Failed to return selected buffer to kernel; buffer will be leaked: {:#}",
            e
        );
    }
}

pub async fn read(
    desc: &Arc<SafeDescriptor>,
    buf: &mut [u8],
    offset: Option<u64>,
) -> anyhow::Result<usize> {
    let len = buf
        .len()
        .try_into()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mut read =
        opcode::Read::new(Fd(desc.as_raw_fd()), ptr::null_mut(), len).buf_group(BUFFER_GROUP);
    if let Some(offset) = offset {
        // TODO(b/256213235): Use offset64 instead of casting to off_t
        read = read.offset(offset as libc::off_t);
    }
    let entry = read.build().flags(squeue::Flags::BUFFER_SELECT);
    let state = clone_state()?;
    let (res, _) = start_op(state, entry, desc, Some(return_selected_buffer), None::<()>).await;
    with_state(|state| state.copy_from_selected_buffer(res?, buf))
}

pub async fn read_iobuf<B: AsIoBufs + Unpin + 'static>(
    desc: &Arc<SafeDescriptor>,
    mut buf: B,
    offset: Option<u64>,
) -> (anyhow::Result<usize>, B) {
    let iobufs = IoBufMut::as_iobufs(buf.as_iobufs());
    let mut readv = opcode::Readv::new(Fd(desc.as_raw_fd()), iobufs.as_ptr(), iobufs.len() as u32);
    if let Some(off) = offset {
        // TODO(b/256213235): Use offset64 instead of casting to off_t
        readv = readv.offset(off as libc::off_t);
    }

    let state = match clone_state() {
        Ok(s) => s,
        Err(e) => return (Err(e), buf),
    };
    let (res, buf) = start_op(state, readv.build(), desc, None, Some(buf)).await;
    (res.and_then(entry_to_result), buf.unwrap())
}

pub async fn write(
    desc: &Arc<SafeDescriptor>,
    buf: &[u8],
    offset: Option<u64>,
) -> anyhow::Result<usize> {
    // TODO: Maybe we should do something smarter here with a shared buffer pool like we do for
    // `read`.
    let (res, _) = write_iobuf(desc, OwnedIoBuf::new(buf.to_vec()), offset).await;
    res
}

pub async fn write_iobuf<B: AsIoBufs + Unpin + 'static>(
    desc: &Arc<SafeDescriptor>,
    mut buf: B,
    offset: Option<u64>,
) -> (anyhow::Result<usize>, B) {
    let iobufs = IoBufMut::as_iobufs(buf.as_iobufs());
    let mut writev =
        opcode::Writev::new(Fd(desc.as_raw_fd()), iobufs.as_ptr(), iobufs.len() as u32);
    if let Some(off) = offset {
        // TODO(b/256213235): Use offset64 instead of casting to off_t
        writev = writev.offset(off as libc::off_t);
    }

    let state = match clone_state() {
        Ok(s) => s,
        Err(e) => return (Err(e), buf),
    };
    let (res, buf) = start_op(state, writev.build(), desc, None, Some(buf)).await;
    (res.and_then(entry_to_result), buf.unwrap())
}

pub async fn fallocate(
    desc: &Arc<SafeDescriptor>,
    file_offset: u64,
    len: u64,
    mode: u32,
) -> anyhow::Result<()> {
    // TODO(b/256213235): Use offset64 instead of casting to off_t
    let entry = opcode::Fallocate::new(Fd(desc.as_raw_fd()), len as libc::off_t)
        .offset(file_offset as libc::off_t)
        .mode(mode as libc::c_int)
        .build();
    let state = clone_state()?;
    let (res, _) = start_op(state, entry, desc, None, None::<()>).await;
    res.and_then(entry_to_result).map(drop)
}

pub async fn ftruncate(desc: &Arc<SafeDescriptor>, len: u64) -> anyhow::Result<()> {
    let ret = unsafe { libc::ftruncate64(desc.as_raw_descriptor(), len as libc::off64_t) };

    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error().into())
    }
}

pub async fn stat(desc: &Arc<SafeDescriptor>) -> anyhow::Result<libc::stat64> {
    // TODO: use opcode::Statx
    let mut st = MaybeUninit::zeroed();

    // Safe because this will only modify `st` and we check the return value.
    let ret = unsafe { libc::fstat64(desc.as_raw_descriptor(), st.as_mut_ptr()) };

    if ret == 0 {
        // Safe because the kernel guarantees that `st` is now initialized.
        Ok(unsafe { st.assume_init() })
    } else {
        Err(io::Error::last_os_error().into())
    }
}

pub async fn fsync(desc: &Arc<SafeDescriptor>, datasync: bool) -> anyhow::Result<()> {
    let mut entry = opcode::Fsync::new(Fd(desc.as_raw_fd()));
    if datasync {
        entry = entry.flags(FsyncFlags::DATASYNC);
    }
    let state = clone_state()?;
    let (res, _) = start_op(state, entry.build(), desc, None, None::<()>).await;
    res.and_then(entry_to_result).map(drop)
}

pub async fn connect(
    desc: &Arc<SafeDescriptor>,
    addr: libc::sockaddr_un,
    len: libc::socklen_t,
) -> anyhow::Result<()> {
    ensure!(
        len <= size_of::<libc::sockaddr_un>() as libc::socklen_t,
        io::Error::from_raw_os_error(libc::EINVAL)
    );
    // TODO: Figure out a way to get rid of this box.
    let addr = Box::new(addr);

    let entry = opcode::Connect::new(
        Fd(desc.as_raw_fd()),
        &*addr as *const libc::sockaddr_un as *const _,
        len,
    )
    .build();
    let state = clone_state()?;
    let (res, _) = start_op(state, entry, desc, None, Some(addr)).await;

    res.and_then(entry_to_result).map(drop)
}

pub async fn next_packet_size(desc: &Arc<SafeDescriptor>) -> anyhow::Result<usize> {
    // For some reason, this always returns 0 under uring so use epoll-style for now. TODO: Figure
    // out how we can go back to using uring.
    #[cfg(not(debug_assertions))]
    let buf = ptr::null_mut();
    // Work around for qemu's syscall translation which will reject null pointers in recvfrom.
    // This only matters for running the unit tests for a non-native architecture. See the
    // upstream thread for the qemu fix:
    // https://lists.nongnu.org/archive/html/qemu-devel/2021-03/msg09027.html
    #[cfg(debug_assertions)]
    let buf = ptr::NonNull::dangling().as_ptr();

    loop {
        // Safe because this will not modify any memory and we check the return value.
        let ret = unsafe {
            libc::recvfrom(
                desc.as_raw_descriptor(),
                buf,
                0,
                libc::MSG_TRUNC | libc::MSG_PEEK | libc::MSG_DONTWAIT,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };

        if ret >= 0 {
            return Ok(ret as usize);
        }

        match base::Error::last() {
            e if e.errno() == libc::EWOULDBLOCK || e.errno() == libc::EAGAIN => {
                wait_readable(desc).await?;
            }
            e => bail!(io::Error::from(e)),
        }
    }
}

pub async fn sendmsg(
    desc: &Arc<SafeDescriptor>,
    buf: &[u8],
    fds: &[RawFd],
) -> anyhow::Result<usize> {
    // TODO: Consider using a shared buffer pool.
    let (res, _) = send_iobuf_with_fds(desc, OwnedIoBuf::new(buf.to_vec()), fds).await;
    res
}

pub async fn recvmsg(
    desc: &Arc<SafeDescriptor>,
    buf: &mut [u8],
    fds: &mut [RawFd],
) -> anyhow::Result<(usize, usize)> {
    // TODO: The io_uring crate doesn't support using BUFFER_SELECT for recvmsg even though it's
    // supported by the kernel.
    let (res, src) = recv_iobuf_with_fds(desc, OwnedIoBuf::new(vec![0u8; buf.len()]), fds).await;
    let (buflen, fd_count) = res?;
    let count = min(buflen, buf.len());
    buf[..count].copy_from_slice(&src[..count]);
    Ok((count, fd_count))
}

pub async fn send_iobuf_with_fds<B: AsIoBufs + Unpin + 'static>(
    desc: &Arc<SafeDescriptor>,
    mut buf: B,
    fds: &[RawFd],
) -> (anyhow::Result<usize>, B) {
    let iovs = IoBufMut::as_iobufs(buf.as_iobufs());
    let mut msg = libc::msghdr {
        msg_name: ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: iovs.as_ptr() as *mut libc::iovec,
        msg_iovlen: iovs.len(),
        msg_flags: libc::MSG_NOSIGNAL,
        msg_control: ptr::null_mut(),
        msg_controllen: 0,
    };

    // `IORING_OP_SENDMSG` internally uses the `__sys_sendmsg_sock` kernel function, which disallows
    // control messages. In that case we fall back to epoll-style async operations.
    if !fds.is_empty() {
        let inner = async {
            let cmsg_buffer = add_fds_to_message(&mut msg, fds)?;

            loop {
                // Safe because this doesn't modify any memory and we check the return value.
                let ret = unsafe {
                    libc::sendmsg(
                        desc.as_raw_descriptor(),
                        &msg,
                        libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
                    )
                };

                if ret >= 0 {
                    return Ok(ret as usize);
                }

                match base::Error::last() {
                    e if e.errno() == libc::EWOULDBLOCK || e.errno() == libc::EAGAIN => {
                        wait_writable(desc).await?;
                    }
                    e => return Err(anyhow!(io::Error::from(e))),
                }
            }
        };
        (inner.await, buf)
    } else {
        let msg = Box::new(msg);
        let entry = opcode::SendMsg::new(Fd(desc.as_raw_descriptor()), &*msg).build();
        let state = match clone_state() {
            Ok(s) => s,
            Err(e) => return (Err(e), buf),
        };
        let (res, data) = start_op(state, entry, desc, None, Some((buf, msg))).await;
        (res.and_then(entry_to_result), data.unwrap().0)
    }
}

pub async fn recv_iobuf_with_fds<B: AsIoBufs + Unpin + 'static>(
    desc: &Arc<SafeDescriptor>,
    mut buf: B,
    fds: &mut [RawFd],
) -> (anyhow::Result<(usize, usize)>, B) {
    let iovs = IoBufMut::as_iobufs(buf.as_iobufs());
    // `IORING_OP_RECVMSG` internally uses the `__sys_recvmsg_sock` kernel function, which disallows
    // control messages. In that case we fall back to epoll-style async operations.
    if !fds.is_empty() {
        let inner = async {
            let fd_cap = fds
                .len()
                .checked_mul(size_of::<RawFd>())
                .and_then(|l| u32::try_from(l).ok())
                .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
            let (cmsg_buffer, cmsg_cap) = allocate_cmsg_buffer(fd_cap)?;
            let mut msg = libc::msghdr {
                msg_name: ptr::null_mut(),
                msg_namelen: 0,
                msg_iov: iovs.as_ptr() as *mut libc::iovec,
                msg_iovlen: iovs.len(),
                msg_flags: 0,
                msg_control: cmsg_buffer.as_ptr(),
                msg_controllen: cmsg_cap,
            };

            let buflen = loop {
                // Safe because this will only modify `buf` and `cmsg_buffer` and we check the return value.
                let ret = unsafe {
                    libc::recvmsg(
                        desc.as_raw_descriptor(),
                        &mut msg,
                        libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
                    )
                };

                if ret >= 0 {
                    break ret as usize;
                }

                match base::Error::last() {
                    e if e.errno() == libc::EWOULDBLOCK || e.errno() == libc::EAGAIN => {
                        wait_readable(desc).await?;
                    }
                    e => return Err(anyhow!(io::Error::from(e))),
                }
            };

            let fd_count = take_fds_from_message(&msg, fds)?;
            Ok((buflen, fd_count))
        };
        (inner.await, buf)
    } else {
        let mut msg = Box::new(libc::msghdr {
            msg_name: ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: iovs.as_ptr() as *mut libc::iovec,
            msg_iovlen: iovs.len(),
            msg_flags: libc::MSG_NOSIGNAL,
            msg_control: ptr::null_mut(),
            msg_controllen: 0,
        });

        let entry = opcode::RecvMsg::new(Fd(desc.as_raw_descriptor()), &mut *msg).build();
        let state = match clone_state() {
            Ok(s) => s,
            Err(e) => return (Err(e), buf),
        };
        let (res, data) = start_op(state, entry, desc, None, Some((buf, msg))).await;
        let (buf, msg) = data.unwrap();

        let inner = || {
            let buflen = res.and_then(entry_to_result)?;
            let fd_count = take_fds_from_message(&msg, fds)?;
            Ok((buflen, fd_count))
        };
        (inner(), buf)
    }
}

pub async fn accept(desc: &Arc<SafeDescriptor>) -> anyhow::Result<SafeDescriptor> {
    let entry = opcode::Accept::new(Fd(desc.as_raw_fd()), ptr::null_mut(), ptr::null_mut())
        .flags(libc::SOCK_CLOEXEC)
        .build();
    let state = clone_state()?;
    let (res, _) = start_op(state, entry, desc, None, None::<()>).await;

    // Safe because we own this fd.
    res.and_then(entry_to_result)
        .map(|fd| unsafe { SafeDescriptor::from_raw_descriptor(fd as _) })
}

pub async fn wait_readable(desc: &Arc<SafeDescriptor>) -> anyhow::Result<()> {
    let entry = opcode::PollAdd::new(Fd(desc.as_raw_fd()), libc::POLLIN as u32).build();
    let state = clone_state()?;
    let (res, _) = start_op(state, entry, desc, None, None::<()>).await;
    res.and_then(entry_to_result).map(drop)
}

pub async fn wait_writable(desc: &Arc<SafeDescriptor>) -> anyhow::Result<()> {
    let entry = opcode::PollAdd::new(Fd(desc.as_raw_fd()), libc::POLLOUT as u32).build();
    let state = clone_state()?;
    let (res, _) = start_op(state, entry, desc, None, None::<()>).await;
    res.and_then(entry_to_result).map(drop)
}

pub fn prepare(_fd: &dyn AsRawDescriptor) -> anyhow::Result<()> {
    Ok(())
}
