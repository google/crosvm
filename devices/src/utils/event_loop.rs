// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::error::{Error, Result};
use std::collections::BTreeMap;
use std::mem::drop;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::{Arc, Weak};
use std::thread;
use sync::Mutex;
use sys_util::{error, warn, EpollContext, EpollEvents, EventFd, PollToken, WatchingEvents};

/// A fail handle will do the clean up when we cannot recover from some error.
pub trait FailHandle: Send + Sync {
    /// Fail the code.
    fn fail(&self);
    /// Returns true if already failed.
    fn failed(&self) -> bool;
}

impl FailHandle for Option<Arc<dyn FailHandle>> {
    fn fail(&self) {
        match self {
            Some(handle) => handle.fail(),
            None => error!("event loop trying to fail without a fail handle"),
        }
    }

    fn failed(&self) -> bool {
        match self {
            Some(handle) => handle.failed(),
            None => false,
        }
    }
}

/// Fd is a wrapper of RawFd. It implements AsRawFd trait and PollToken trait for RawFd.
/// It does not own the fd, thus won't close the fd when dropped.
struct Fd(pub RawFd);
impl AsRawFd for Fd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

impl PollToken for Fd {
    fn as_raw_token(&self) -> u64 {
        self.0 as u64
    }

    fn from_raw_token(data: u64) -> Self {
        Fd(data as RawFd)
    }
}

/// EpollEventLoop is an event loop blocked on a set of fds. When a monitered events is triggered,
/// event loop will invoke the mapped handler.
pub struct EventLoop {
    fail_handle: Option<Arc<dyn FailHandle>>,
    poll_ctx: Arc<EpollContext<Fd>>,
    handlers: Arc<Mutex<BTreeMap<RawFd, Weak<dyn EventHandler>>>>,
    stop_evt: EventFd,
}

/// Interface for event handler.
pub trait EventHandler: Send + Sync {
    fn on_event(&self) -> std::result::Result<(), ()>;
}

impl EventLoop {
    /// Start an event loop. An optional fail handle could be passed to the event loop.
    pub fn start(
        name: String,
        fail_handle: Option<Arc<dyn FailHandle>>,
    ) -> Result<(EventLoop, thread::JoinHandle<()>)> {
        let (self_stop_evt, stop_evt) = EventFd::new()
            .and_then(|e| Ok((e.try_clone()?, e)))
            .map_err(Error::CreateEventFd)?;

        let fd_callbacks: Arc<Mutex<BTreeMap<RawFd, Weak<dyn EventHandler>>>> =
            Arc::new(Mutex::new(BTreeMap::new()));
        let poll_ctx: EpollContext<Fd> = EpollContext::new()
            .and_then(|pc| pc.add(&stop_evt, Fd(stop_evt.as_raw_fd())).and(Ok(pc)))
            .map_err(Error::CreatePollContext)?;

        let poll_ctx = Arc::new(poll_ctx);
        let event_loop = EventLoop {
            fail_handle: fail_handle.clone(),
            poll_ctx: poll_ctx.clone(),
            handlers: fd_callbacks.clone(),
            stop_evt: self_stop_evt,
        };

        let handle = thread::Builder::new()
            .name(name)
            .spawn(move || {
                let event_loop = EpollEvents::new();
                loop {
                    if fail_handle.failed() {
                        error!("xhci controller already failed, stopping event ring");
                        return;
                    }
                    let events = match poll_ctx.wait(&event_loop) {
                        Ok(events) => events,
                        Err(e) => {
                            error!("cannot poll {:?}", e);
                            fail_handle.fail();
                            return;
                        }
                    };
                    for event in &events {
                        if event.token().as_raw_fd() == stop_evt.as_raw_fd() {
                            return;
                        } else {
                            let fd = event.token().as_raw_fd();
                            let mut locked = fd_callbacks.lock();
                            let weak_handler = match locked.get(&fd) {
                                Some(cb) => cb.clone(),
                                None => {
                                    warn!("callback for fd {} already removed", fd);
                                    continue;
                                }
                            };
                            match weak_handler.upgrade() {
                                Some(handler) => {
                                    // Drop lock before triggering the event.
                                    drop(locked);
                                    match handler.on_event() {
                                        Ok(()) => {}
                                        Err(_) => {
                                            error!("event loop stopping due to handle event error");
                                            fail_handle.fail();
                                            return;
                                        }
                                    };
                                }
                                // If the handler is already gone, we remove the fd.
                                None => {
                                    let _ = poll_ctx.delete(&Fd(fd));
                                    if locked.remove(&fd).is_none() {
                                        error!("fail to remove handler for file descriptor {}", fd);
                                    }
                                }
                            };
                        }
                    }
                }
            })
            .map_err(Error::StartThread)?;

        Ok((event_loop, handle))
    }

    /// Add a new event to event loop. The event handler will be invoked when `event` happens on
    /// `fd`.
    ///
    /// If the same `fd` is added multiple times, the old handler will be replaced.
    /// EventLoop will not keep `handler` alive, if handler is dropped when `event` is triggered,
    /// the event will be removed.
    pub fn add_event(
        &self,
        fd: &dyn AsRawFd,
        events: WatchingEvents,
        handler: Weak<dyn EventHandler>,
    ) -> Result<()> {
        if self.fail_handle.failed() {
            return Err(Error::EventLoopAlreadyFailed);
        }
        self.handlers.lock().insert(fd.as_raw_fd(), handler);
        // This might fail due to epoll syscall. Check epoll_ctl(2).
        self.poll_ctx
            .add_fd_with_events(fd, events, Fd(fd.as_raw_fd()))
            .map_err(Error::PollContextAddFd)
    }

    /// Removes event for this `fd`. This function returns false if it fails.
    ///
    /// EventLoop does not guarantee all events for `fd` is handled.
    pub fn remove_event_for_fd(&self, fd: &dyn AsRawFd) -> Result<()> {
        if self.fail_handle.failed() {
            return Err(Error::EventLoopAlreadyFailed);
        }
        // This might fail due to epoll syscall. Check epoll_ctl(2).
        self.poll_ctx
            .delete(fd)
            .map_err(Error::PollContextDeleteFd)?;
        self.handlers.lock().remove(&fd.as_raw_fd());
        Ok(())
    }

    /// Stops this event loop asynchronously. Previous events might not be handled.
    pub fn stop(&self) {
        match self.stop_evt.write(1) {
            Ok(_) => {}
            Err(_) => {
                error!("fail to send event loop stop event, it might already stopped");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Condvar, Mutex};
    use sys_util::EventFd;

    struct EventLoopTestHandler {
        val: Mutex<u8>,
        cvar: Condvar,
        evt: EventFd,
    }

    impl EventHandler for EventLoopTestHandler {
        fn on_event(&self) -> std::result::Result<(), ()> {
            self.evt.read().unwrap();
            *self.val.lock().unwrap() += 1;
            self.cvar.notify_one();
            Ok(())
        }
    }

    #[test]
    fn event_loop_test() {
        let (l, j) = EventLoop::start("test".to_string(), None).unwrap();
        let (self_evt, evt) = match EventFd::new().and_then(|e| Ok((e.try_clone()?, e))) {
            Ok(v) => v,
            Err(e) => {
                error!("failed creating EventFd pair: {:?}", e);
                return;
            }
        };
        let h = Arc::new(EventLoopTestHandler {
            val: Mutex::new(0),
            cvar: Condvar::new(),
            evt,
        });
        let t: Arc<EventHandler> = h.clone();
        l.add_event(
            &h.evt,
            WatchingEvents::empty().set_read(),
            Arc::downgrade(&t),
        )
        .unwrap();
        self_evt.write(1).unwrap();
        let _ = h.cvar.wait(h.val.lock().unwrap()).unwrap();
        l.stop();
        j.join().unwrap();
        assert_eq!(*(h.val.lock().unwrap()), 1);
    }
}
