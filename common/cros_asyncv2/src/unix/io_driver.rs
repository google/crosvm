// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::{
    os::unix::io::RawFd,
    sync::{
        atomic::{AtomicI32, Ordering},
        Arc,
    },
    time::Duration,
};

use futures::task::{waker_ref, ArcWake, WakerRef};
use once_cell::sync::OnceCell;
use sys_util::{error, AsRawDescriptor, SafeDescriptor};

use crate::{executor, AsIoBufs};

mod cmsg;
mod mio;

#[cfg(feature = "uring")]
#[allow(unused_variables)]
mod uring;

#[cfg(feature = "uring")]
use uring::use_uring;

// Indicates that the IO driver is either within or about to make a blocking syscall. When a waker
// sees this value, it will wake the associated waker, which will cause the blocking syscall to
// return.
const WAITING: i32 = 0x1d5b_c019u32 as i32;

// Indicates that the executor is processing any futures that are ready to run.
const PROCESSING: i32 = 0xd474_77bcu32 as i32;

// Indicates that one or more futures may be ready to make progress.
const WOKEN: i32 = 0x3e4d_3276u32 as i32;

enum PlatformWaker {
    Mio(::mio::Waker),
    #[cfg(feature = "uring")]
    Uring(uring::Waker),
}

impl PlatformWaker {
    fn new() -> anyhow::Result<Self> {
        #[cfg(feature = "uring")]
        if use_uring() {
            return uring::new_waker().map(PlatformWaker::Uring);
        }

        mio::new_waker().map(PlatformWaker::Mio)
    }

    fn wake(&self) -> anyhow::Result<()> {
        use PlatformWaker::*;
        match self {
            Mio(waker) => waker.wake().map_err(From::from),
            #[cfg(feature = "uring")]
            Uring(waker) => waker.wake(),
        }
    }
}

struct State {
    waker: PlatformWaker,
    state: AtomicI32,
}

impl State {
    fn new() -> anyhow::Result<Arc<State>> {
        Ok(Arc::new(State {
            waker: PlatformWaker::new()?,
            state: AtomicI32::new(PROCESSING),
        }))
    }
}

impl ArcWake for State {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        let oldstate = arc_self.state.swap(WOKEN, Ordering::AcqRel);
        if oldstate == WAITING {
            if let Err(e) = arc_self.waker.wake() {
                error!("Failed to wake executor thread: {:#}", e);
            }
        }
    }
}

impl executor::PlatformState for Arc<State> {
    fn start_processing(&self) -> bool {
        self.state.swap(PROCESSING, Ordering::AcqRel) == WOKEN
    }

    fn waker_ref(&self) -> WakerRef {
        waker_ref(self)
    }

    fn wait(&self, timeout: Option<Duration>) -> anyhow::Result<()> {
        let oldstate =
            self.state
                .compare_exchange(PROCESSING, WAITING, Ordering::AcqRel, Ordering::Acquire);
        if let Err(oldstate) = oldstate {
            debug_assert_eq!(oldstate, WOKEN);
            return Ok(());
        }

        // Wait for more events.
        wait(timeout)?;

        // Set the state to `WOKEN` to prevent unnecessary writes to the inner `PlatformWaker`.
        match self.state.swap(WOKEN, Ordering::AcqRel) {
            WOKEN => {}   // One or more futures have become runnable.
            WAITING => {} // Timed out or IO completed.
            n => panic!("Unexpected waker state: {}", n),
        }

        // Wake up any tasks that are ready.
        dispatch()
    }
}

thread_local! (static THREAD_STATE: OnceCell<Arc<State>> = OnceCell::new() );

fn wait(timeout: Option<Duration>) -> anyhow::Result<()> {
    #[cfg(feature = "uring")]
    if use_uring() {
        return uring::wait(timeout);
    }

    mio::wait(timeout)
}

fn dispatch() -> anyhow::Result<()> {
    #[cfg(feature = "uring")]
    if use_uring() {
        return uring::dispatch();
    }

    mio::dispatch()
}

pub(crate) fn platform_state() -> anyhow::Result<impl executor::PlatformState> {
    THREAD_STATE.with(|state| state.get_or_try_init(State::new).map(Arc::clone))
}

pub fn prepare(fd: &dyn AsRawDescriptor) -> anyhow::Result<()> {
    #[cfg(feature = "uring")]
    if use_uring() {
        return uring::prepare(fd);
    }

    mio::prepare(fd)
}

pub async fn read(
    desc: &Arc<SafeDescriptor>,
    buf: &mut [u8],
    offset: Option<u64>,
) -> anyhow::Result<usize> {
    #[cfg(feature = "uring")]
    if use_uring() {
        return uring::read(desc, buf, offset).await;
    }

    mio::read(desc, buf, offset).await
}

pub async fn read_iobuf<B: AsIoBufs + Unpin + 'static>(
    desc: &Arc<SafeDescriptor>,
    buf: B,
    offset: Option<u64>,
) -> (anyhow::Result<usize>, B) {
    #[cfg(feature = "uring")]
    if use_uring() {
        return uring::read_iobuf(desc, buf, offset).await;
    }

    mio::read_iobuf(desc, buf, offset).await
}

pub async fn write(
    desc: &Arc<SafeDescriptor>,
    buf: &[u8],
    offset: Option<u64>,
) -> anyhow::Result<usize> {
    #[cfg(feature = "uring")]
    if use_uring() {
        return uring::write(desc, buf, offset).await;
    }

    mio::write(desc, buf, offset).await
}

pub async fn write_iobuf<B: AsIoBufs + Unpin + 'static>(
    desc: &Arc<SafeDescriptor>,
    buf: B,
    offset: Option<u64>,
) -> (anyhow::Result<usize>, B) {
    #[cfg(feature = "uring")]
    if use_uring() {
        return uring::write_iobuf(desc, buf, offset).await;
    }

    mio::write_iobuf(desc, buf, offset).await
}

pub async fn fallocate(
    desc: &Arc<SafeDescriptor>,
    file_offset: u64,
    len: u64,
    mode: u32,
) -> anyhow::Result<()> {
    #[cfg(feature = "uring")]
    if use_uring() {
        return uring::fallocate(desc, file_offset, len, mode).await;
    }

    mio::fallocate(desc, file_offset, len, mode).await
}

pub async fn ftruncate(desc: &Arc<SafeDescriptor>, len: u64) -> anyhow::Result<()> {
    #[cfg(feature = "uring")]
    if use_uring() {
        return uring::ftruncate(desc, len).await;
    }

    mio::ftruncate(desc, len).await
}

pub async fn stat(desc: &Arc<SafeDescriptor>) -> anyhow::Result<libc::stat64> {
    #[cfg(feature = "uring")]
    if use_uring() {
        return uring::stat(desc).await;
    }

    mio::stat(desc).await
}

pub async fn fsync(desc: &Arc<SafeDescriptor>, datasync: bool) -> anyhow::Result<()> {
    #[cfg(feature = "uring")]
    if use_uring() {
        return uring::fsync(desc, datasync).await;
    }

    mio::fsync(desc, datasync).await
}

pub async fn connect(
    desc: &Arc<SafeDescriptor>,
    addr: libc::sockaddr_un,
    len: libc::socklen_t,
) -> anyhow::Result<()> {
    #[cfg(feature = "uring")]
    if use_uring() {
        return uring::connect(desc, addr, len).await;
    }

    mio::connect(desc, addr, len).await
}

pub async fn next_packet_size(desc: &Arc<SafeDescriptor>) -> anyhow::Result<usize> {
    #[cfg(feature = "uring")]
    if use_uring() {
        return uring::next_packet_size(desc).await;
    }

    mio::next_packet_size(desc).await
}

pub async fn sendmsg(
    desc: &Arc<SafeDescriptor>,
    buf: &[u8],
    fds: &[RawFd],
) -> anyhow::Result<usize> {
    #[cfg(feature = "uring")]
    if use_uring() {
        return uring::sendmsg(desc, buf, fds).await;
    }

    mio::sendmsg(desc, buf, fds).await
}

pub async fn recvmsg(
    desc: &Arc<SafeDescriptor>,
    buf: &mut [u8],
    fds: &mut [RawFd],
) -> anyhow::Result<(usize, usize)> {
    #[cfg(feature = "uring")]
    if use_uring() {
        return uring::recvmsg(desc, buf, fds).await;
    }

    mio::recvmsg(desc, buf, fds).await
}

pub async fn send_iobuf_with_fds<B: AsIoBufs + Unpin + 'static>(
    desc: &Arc<SafeDescriptor>,
    buf: B,
    fds: &[RawFd],
) -> (anyhow::Result<usize>, B) {
    #[cfg(feature = "uring")]
    if use_uring() {
        return uring::send_iobuf_with_fds(desc, buf, fds).await;
    }

    mio::send_iobuf_with_fds(desc, buf, fds).await
}

pub async fn recv_iobuf_with_fds<B: AsIoBufs + Unpin + 'static>(
    desc: &Arc<SafeDescriptor>,
    buf: B,
    fds: &mut [RawFd],
) -> (anyhow::Result<(usize, usize)>, B) {
    #[cfg(feature = "uring")]
    if use_uring() {
        return uring::recv_iobuf_with_fds(desc, buf, fds).await;
    }

    mio::recv_iobuf_with_fds(desc, buf, fds).await
}

pub async fn accept(desc: &Arc<SafeDescriptor>) -> anyhow::Result<SafeDescriptor> {
    #[cfg(feature = "uring")]
    if use_uring() {
        return uring::accept(desc).await;
    }

    mio::accept(desc).await
}

pub async fn wait_readable(desc: &Arc<SafeDescriptor>) -> anyhow::Result<()> {
    #[cfg(feature = "uring")]
    if use_uring() {
        return uring::wait_readable(desc).await;
    }

    mio::wait_readable(desc).await
}

pub async fn wait_writable(desc: &Arc<SafeDescriptor>) -> anyhow::Result<()> {
    #[cfg(feature = "uring")]
    if use_uring() {
        return uring::wait_writable(desc).await;
    }

    mio::wait_writable(desc).await
}
