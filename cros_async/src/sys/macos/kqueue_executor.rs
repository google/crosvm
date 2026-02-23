// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::future::Future;
use std::io;
use std::mem;
use std::os::fd::AsRawFd;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Weak;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;

use base::add_fd_flags;
use base::warn;
use base::AsRawDescriptor;
use base::AsRawDescriptors;
use base::Event;
use base::EventType;
use base::RawDescriptor;
use base::WaitContext;
use remain::sorted;
use slab::Slab;
use sync::Mutex;
use thiserror::Error as ThisError;

use crate::common_executor::RawExecutor;
use crate::common_executor::RawTaskHandle;
use crate::common_executor::Reactor;
use crate::waker::WakerToken;
use crate::AsyncResult;
use crate::IoSource;
use crate::TaskHandle;

#[sorted]
#[derive(Debug, ThisError)]
pub enum Error {
    #[error("Couldn't clear the wake eventfd")]
    CantClearWakeEvent(base::Error),
    #[error("Failed to clone the Event for waking the executor: {0}")]
    CloneEvent(base::Error),
    #[error("Failed to create the Event for waking the executor: {0}")]
    CreateEvent(base::Error),
    #[error("An error creating the fd waiting context: {0}")]
    CreatingContext(base::Error),
    #[error("Failed to copy the FD for the polling context: {0}")]
    DuplicatingFd(std::io::Error),
    #[error("Executor failed")]
    ExecutorError(anyhow::Error),
    #[error("The KqueueExecutor is gone")]
    ExecutorGone,
    #[error("An error occurred setting the FD non-blocking: {0}.")]
    SettingNonBlocking(base::Error),
    #[error("An error adding to the kqueue context: {0}")]
    SubmittingWaker(base::Error),
    #[error("Unknown waker")]
    UnknownWaker,
    #[error("WaitContext failure: {0}")]
    WaitContextError(base::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        use Error::*;
        match e {
            CantClearWakeEvent(e) => e.into(),
            CloneEvent(e) => e.into(),
            CreateEvent(e) => e.into(),
            DuplicatingFd(e) => e,
            ExecutorError(e) => io::Error::other(e),
            ExecutorGone => io::Error::other(e),
            CreatingContext(e) => e.into(),
            SettingNonBlocking(e) => e.into(),
            SubmittingWaker(e) => e.into(),
            UnknownWaker => io::Error::other(e),
            WaitContextError(e) => e.into(),
        }
    }
}

struct OpData {
    file: Arc<std::os::fd::OwnedFd>,
    waker: Option<Waker>,
}

enum OpStatus {
    Pending(OpData),
    Completed,
    WakeEvent,
}

pub struct RegisteredSource<F> {
    pub(crate) source: F,
    ex: Weak<RawExecutor<KqueueReactor>>,
    pub(crate) duped_fd: Arc<std::os::fd::OwnedFd>,
}

impl<F: AsRawDescriptor> RegisteredSource<F> {
    pub(crate) fn new(raw: &Arc<RawExecutor<KqueueReactor>>, f: F) -> Result<Self> {
        let raw_fd = f.as_raw_descriptor();
        assert_ne!(raw_fd, -1);

        add_fd_flags(raw_fd, libc::O_NONBLOCK).map_err(Error::SettingNonBlocking)?;

        let duped_fd = unsafe { std::os::fd::BorrowedFd::borrow_raw(raw_fd) }
            .try_clone_to_owned()
            .map_err(Error::DuplicatingFd)?;
        Ok(RegisteredSource {
            source: f,
            ex: Arc::downgrade(raw),
            duped_fd: Arc::new(duped_fd),
        })
    }

    pub fn wait_readable(&self) -> Result<PendingOperation> {
        let ex = self.ex.upgrade().ok_or(Error::ExecutorGone)?;

        let token = ex
            .reactor
            .add_operation(Arc::clone(&self.duped_fd), EventType::Read)?;

        Ok(PendingOperation {
            token: Some(token),
            ex: self.ex.clone(),
        })
    }

    pub fn wait_writable(&self) -> Result<PendingOperation> {
        let ex = self.ex.upgrade().ok_or(Error::ExecutorGone)?;

        let token = ex
            .reactor
            .add_operation(Arc::clone(&self.duped_fd), EventType::Write)?;

        Ok(PendingOperation {
            token: Some(token),
            ex: self.ex.clone(),
        })
    }
}

pub struct PendingOperation {
    token: Option<WakerToken>,
    ex: Weak<RawExecutor<KqueueReactor>>,
}

impl Future for PendingOperation {
    type Output = Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let token = self
            .token
            .as_ref()
            .expect("PendingOperation polled after returning Poll::Ready");
        if let Some(ex) = self.ex.upgrade() {
            if ex.reactor.is_ready(token, cx) {
                self.token = None;
                Poll::Ready(Ok(()))
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
        if let Some(token) = self.token.take() {
            if let Some(ex) = self.ex.upgrade() {
                let _ = ex.reactor.cancel_operation(token);
            }
        }
    }
}

pub struct KqueueReactor {
    poll_ctx: WaitContext<usize>,
    ops: Mutex<Slab<OpStatus>>,
    wake_event: Event,
}

impl KqueueReactor {
    fn new() -> Result<Self> {
        let reactor = KqueueReactor {
            poll_ctx: WaitContext::new().map_err(Error::CreatingContext)?,
            ops: Mutex::new(Slab::with_capacity(64)),
            wake_event: {
                let wake_event = Event::new().map_err(Error::CreateEvent)?;
                add_fd_flags(wake_event.as_raw_descriptor(), libc::O_NONBLOCK)
                    .map_err(Error::SettingNonBlocking)?;
                wake_event
            },
        };

        {
            let mut ops = reactor.ops.lock();
            let entry = ops.vacant_entry();
            let next_token = entry.key();
            reactor
                .poll_ctx
                .add_for_event(&reactor.wake_event, EventType::Read, next_token)
                .map_err(Error::SubmittingWaker)?;
            entry.insert(OpStatus::WakeEvent);
        }

        Ok(reactor)
    }

    fn add_operation(
        &self,
        file: Arc<std::os::fd::OwnedFd>,
        event_type: EventType,
    ) -> Result<WakerToken> {
        let mut ops = self.ops.lock();
        let entry = ops.vacant_entry();
        let next_token = entry.key();
        self.poll_ctx
            .add_for_event(&base::Descriptor(file.as_raw_fd()), event_type, next_token)
            .map_err(Error::SubmittingWaker)?;
        entry.insert(OpStatus::Pending(OpData { file, waker: None }));
        Ok(WakerToken(next_token))
    }

    fn is_ready(&self, token: &WakerToken, cx: &mut Context) -> bool {
        let mut ops = self.ops.lock();

        let op = ops
            .get_mut(token.0)
            .expect("`is_ready` called on unknown operation");
        match op {
            OpStatus::Pending(data) => {
                data.waker = Some(cx.waker().clone());
                false
            }
            OpStatus::Completed => {
                ops.remove(token.0);
                true
            }
            OpStatus::WakeEvent => unreachable!(),
        }
    }

    fn cancel_operation(&self, token: WakerToken) -> Result<()> {
        match self.ops.lock().remove(token.0) {
            OpStatus::Pending(data) => self
                .poll_ctx
                .delete(&base::Descriptor(data.file.as_raw_fd()))
                .map_err(Error::WaitContextError),
            OpStatus::Completed => Ok(()),
            OpStatus::WakeEvent => unreachable!(),
        }
    }
}

impl Reactor for KqueueReactor {
    fn new() -> std::io::Result<Self> {
        Ok(KqueueReactor::new()?)
    }

    fn wake(&self) {
        if let Err(e) = self.wake_event.signal() {
            warn!("Failed to notify executor that a future is ready: {}", e);
        }
    }

    fn on_executor_drop<'a>(&'a self) -> Pin<Box<dyn Future<Output = ()> + 'a>> {
        for op in self.ops.lock().drain() {
            match op {
                OpStatus::Pending(mut data) => {
                    if let Some(waker) = data.waker.take() {
                        waker.wake();
                    }

                    if let Err(e) = self
                        .poll_ctx
                        .delete(&base::Descriptor(data.file.as_raw_fd()))
                    {
                        warn!("Failed to remove file from WaitContext: {}", e);
                    }
                }
                OpStatus::Completed => {}
                OpStatus::WakeEvent => {}
            }
        }

        Box::pin(async {})
    }

    fn wait_for_work(&self, set_processing: impl Fn()) -> std::io::Result<()> {
        let events = self.poll_ctx.wait().map_err(Error::WaitContextError)?;

        set_processing();
        for e in events.iter() {
            let token = e.token;
            let mut ops = self.ops.lock();

            if let Some(op) = ops.get_mut(token) {
                let (file, waker) = match mem::replace(op, OpStatus::Completed) {
                    OpStatus::Pending(OpData { file, waker }) => (file, waker),
                    OpStatus::Completed => panic!("poll operation completed more than once"),
                    OpStatus::WakeEvent => {
                        *op = OpStatus::WakeEvent;
                        match self.wake_event.wait() {
                            Ok(_) => {}
                            Err(e) if e.errno() == libc::EWOULDBLOCK => {}
                            Err(e) => return Err(e.into()),
                        }
                        continue;
                    }
                };

                mem::drop(ops);

                self.poll_ctx
                    .delete(&base::Descriptor(file.as_raw_fd()))
                    .map_err(Error::WaitContextError)?;

                if let Some(waker) = waker {
                    waker.wake();
                }
            }
        }
        Ok(())
    }

    fn new_source<F: AsRawDescriptor>(
        &self,
        ex: &Arc<RawExecutor<Self>>,
        f: F,
    ) -> AsyncResult<IoSource<F>> {
        Ok(IoSource::Kqueue(super::KqueueSource::new(f, ex)?))
    }

    fn wrap_task_handle<R>(task: RawTaskHandle<KqueueReactor, R>) -> TaskHandle<R> {
        TaskHandle::Kqueue(task)
    }
}

impl AsRawDescriptors for KqueueReactor {
    fn as_raw_descriptors(&self) -> Vec<RawDescriptor> {
        vec![
            self.poll_ctx.as_raw_descriptor(),
            self.wake_event.as_raw_descriptor(),
        ]
    }
}
