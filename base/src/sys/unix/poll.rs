// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp::min;
use std::fs::File;
use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::ptr::null_mut;
use std::time::Duration;

use libc::c_int;
use libc::epoll_create1;
use libc::epoll_ctl;
use libc::epoll_event;
use libc::epoll_wait;
use libc::EPOLLHUP;
use libc::EPOLLIN;
use libc::EPOLLOUT;
use libc::EPOLLRDHUP;
use libc::EPOLL_CLOEXEC;
use libc::EPOLL_CTL_ADD;
use libc::EPOLL_CTL_DEL;
use libc::EPOLL_CTL_MOD;
use smallvec::SmallVec;

use super::errno_result;
use super::Result;
use crate::AsRawDescriptor;
use crate::EventToken;
use crate::EventType;
use crate::FromRawDescriptor;
use crate::RawDescriptor;
use crate::TriggeredEvent;

const EVENT_CONTEXT_MAX_EVENTS: usize = 16;

impl From<EventType> for u32 {
    fn from(et: EventType) -> u32 {
        let v = match et {
            EventType::None => 0,
            EventType::Read => EPOLLIN,
            EventType::Write => EPOLLOUT,
            EventType::ReadWrite => EPOLLIN | EPOLLOUT,
        };
        v as u32
    }
}

/// Used to poll multiple objects that have file descriptors.
///
/// See [`crate::WaitContext`] for an example that uses the cross-platform wrapper.
pub struct EventContext<T> {
    epoll_ctx: File,
    // Needed to satisfy usage of T
    tokens: PhantomData<[T]>,
}

impl<T: EventToken> EventContext<T> {
    /// Creates a new `EventContext`.
    pub fn new() -> Result<EventContext<T>> {
        // Safe because we check the return value.
        let epoll_fd = unsafe { epoll_create1(EPOLL_CLOEXEC) };
        if epoll_fd < 0 {
            return errno_result();
        }
        Ok(EventContext {
            epoll_ctx: unsafe { File::from_raw_descriptor(epoll_fd) },
            tokens: PhantomData,
        })
    }

    /// Creates a new `EventContext` and adds the slice of `fd` and `token` tuples to the new
    /// context.
    ///
    /// This is equivalent to calling `new` followed by `add_many`. If there is an error, this will
    /// return the error instead of the new context.
    pub fn build_with(fd_tokens: &[(&dyn AsRawDescriptor, T)]) -> Result<EventContext<T>> {
        let ctx = EventContext::new()?;
        ctx.add_many(fd_tokens)?;
        Ok(ctx)
    }

    /// Adds the given slice of `fd` and `token` tuples to this context.
    ///
    /// This is equivalent to calling `add` with each `fd` and `token`. If there are any errors,
    /// this method will stop adding `fd`s and return the first error, leaving this context in a
    /// undefined state.
    pub fn add_many(&self, fd_tokens: &[(&dyn AsRawDescriptor, T)]) -> Result<()> {
        for (fd, token) in fd_tokens {
            self.add(*fd, T::from_raw_token(token.as_raw_token()))?;
        }
        Ok(())
    }

    /// Adds the given `fd` to this context and associates the given `token` with the `fd`'s
    /// readable events.
    ///
    /// A `fd` can only be added once and does not need to be kept open. If the `fd` is dropped and
    /// there were no duplicated file descriptors (i.e. adding the same descriptor with a different
    /// FD number) added to this context, events will not be reported by `wait` anymore.
    pub fn add(&self, fd: &dyn AsRawDescriptor, token: T) -> Result<()> {
        self.add_for_event(fd, EventType::Read, token)
    }

    /// Adds the given `descriptor` to this context, watching for the specified events and
    /// associates the given 'token' with those events.
    ///
    /// A `descriptor` can only be added once and does not need to be kept open. If the `descriptor`
    /// is dropped and there were no duplicated file descriptors (i.e. adding the same descriptor
    /// with a different FD number) added to this context, events will not be reported by `wait`
    /// anymore.
    pub fn add_for_event(
        &self,
        descriptor: &dyn AsRawDescriptor,
        event_type: EventType,
        token: T,
    ) -> Result<()> {
        let mut evt = epoll_event {
            events: event_type.into(),
            u64: token.as_raw_token(),
        };
        // Safe because we give a valid epoll FD and FD to watch, as well as a valid epoll_event
        // structure. Then we check the return value.
        let ret = unsafe {
            epoll_ctl(
                self.epoll_ctx.as_raw_descriptor(),
                EPOLL_CTL_ADD,
                descriptor.as_raw_descriptor(),
                &mut evt,
            )
        };
        if ret < 0 {
            return errno_result();
        };
        Ok(())
    }

    /// If `fd` was previously added to this context, the watched events will be replaced with
    /// `event_type` and the token associated with it will be replaced with the given `token`.
    pub fn modify(&self, fd: &dyn AsRawDescriptor, event_type: EventType, token: T) -> Result<()> {
        let mut evt = epoll_event {
            events: event_type.into(),
            u64: token.as_raw_token(),
        };
        // Safe because we give a valid epoll FD and FD to modify, as well as a valid epoll_event
        // structure. Then we check the return value.
        let ret = unsafe {
            epoll_ctl(
                self.epoll_ctx.as_raw_descriptor(),
                EPOLL_CTL_MOD,
                fd.as_raw_descriptor(),
                &mut evt,
            )
        };
        if ret < 0 {
            return errno_result();
        };
        Ok(())
    }

    /// Deletes the given `fd` from this context.
    ///
    /// If an `fd`'s token shows up in the list of hangup events, it should be removed using this
    /// method or by closing/dropping (if and only if the fd was never dup()'d/fork()'d) the `fd`.
    /// Failure to do so will cause the `wait` method to always return immediately, causing ~100%
    /// CPU load.
    pub fn delete(&self, fd: &dyn AsRawDescriptor) -> Result<()> {
        // Safe because we give a valid epoll FD and FD to stop watching. Then we check the return
        // value.
        let ret = unsafe {
            epoll_ctl(
                self.epoll_ctx.as_raw_descriptor(),
                EPOLL_CTL_DEL,
                fd.as_raw_descriptor(),
                null_mut(),
            )
        };
        if ret < 0 {
            return errno_result();
        };
        Ok(())
    }

    /// Waits for any events to occur in FDs that were previously added to this context.
    ///
    /// The events are level-triggered, meaning that if any events are unhandled (i.e. not reading
    /// for readable events and not closing for hungup events), subsequent calls to `wait` will
    /// return immediately. The consequence of not handling an event perpetually while calling
    /// `wait` is that the callers loop will degenerated to busy loop polling, pinning a CPU to
    /// ~100% usage.
    pub fn wait(&self) -> Result<SmallVec<[TriggeredEvent<T>; 16]>> {
        self.wait_timeout(Duration::new(i64::MAX as u64, 0))
    }

    /// Like `wait` except will only block for a maximum of the given `timeout`.
    ///
    /// This may return earlier than `timeout` with zero events if the duration indicated exceeds
    /// system limits.
    pub fn wait_timeout(&self, timeout: Duration) -> Result<SmallVec<[TriggeredEvent<T>; 16]>> {
        // SAFETY:
        // `MaybeUnint<T>` has the same layout as plain `T` (`epoll_event` in our case).
        // We submit an uninitialized array to the `epoll_wait` system call, which returns how many
        // elements it initialized, and then we convert only the initialized `MaybeUnint` values
        // into `epoll_event` structures after the call.
        let mut epoll_events: [MaybeUninit<epoll_event>; EVENT_CONTEXT_MAX_EVENTS] =
            unsafe { MaybeUninit::uninit().assume_init() };

        let timeout_millis = if timeout.as_secs() as i64 == i64::max_value() {
            // We make the convenient assumption that 2^63 seconds is an effectively unbounded time
            // frame. This is meant to mesh with `wait` calling us with no timeout.
            -1
        } else {
            // In cases where we the number of milliseconds would overflow an i32, we substitute the
            // maximum timeout which is ~24.8 days.
            let millis = timeout
                .as_secs()
                .checked_mul(1_000)
                .and_then(|ms| ms.checked_add(u64::from(timeout.subsec_nanos()) / 1_000_000))
                .unwrap_or(i32::max_value() as u64);
            min(i32::max_value() as u64, millis) as i32
        };
        let ret = {
            let max_events = epoll_events.len() as c_int;
            // Safe because we give an epoll context and a properly sized epoll_events array
            // pointer, which we trust the kernel to fill in properly. The `transmute` is safe,
            // since `MaybeUnint<T>` has the same layout as `T`, and the `epoll_wait` syscall will
            // initialize as many elements of the `epoll_events` array as it returns.
            unsafe {
                handle_eintr_errno!(epoll_wait(
                    self.epoll_ctx.as_raw_descriptor(),
                    std::mem::transmute(&mut epoll_events[0]),
                    max_events,
                    timeout_millis
                ))
            }
        };
        if ret < 0 {
            return errno_result();
        }
        let count = ret as usize;

        let events = epoll_events[0..count]
            .iter()
            .map(|e| {
                // SAFETY:
                // Converting `MaybeUninit<epoll_event>` into `epoll_event` is safe here, since we
                // are only iterating over elements that the `epoll_wait` system call initialized.
                let e = unsafe { e.assume_init() };
                TriggeredEvent {
                    token: T::from_raw_token(e.u64),
                    is_readable: e.events & (EPOLLIN as u32) != 0,
                    is_writable: e.events & (EPOLLOUT as u32) != 0,
                    is_hungup: e.events & ((EPOLLHUP | EPOLLRDHUP) as u32) != 0,
                }
            })
            .collect();
        Ok(events)
    }
}

impl<T: EventToken> AsRawDescriptor for EventContext<T> {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.epoll_ctx.as_raw_descriptor()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use base_event_token_derive::EventToken;

    use super::super::PlatformEvent;
    use super::*;

    #[test]
    fn event_context() {
        let evt1 = PlatformEvent::new().unwrap();
        let evt2 = PlatformEvent::new().unwrap();
        evt1.write(1).unwrap();
        evt2.write(1).unwrap();
        let ctx: EventContext<u32> = EventContext::build_with(&[(&evt1, 1), (&evt2, 2)]).unwrap();

        let mut evt_count = 0;
        while evt_count < 2 {
            for event in ctx.wait().unwrap().iter().filter(|e| e.is_readable) {
                evt_count += 1;
                match event.token {
                    1 => {
                        evt1.read().unwrap();
                        ctx.delete(&evt1).unwrap();
                    }
                    2 => {
                        evt2.read().unwrap();
                        ctx.delete(&evt2).unwrap();
                    }
                    _ => panic!("unexpected token"),
                };
            }
        }
        assert_eq!(evt_count, 2);
    }

    #[test]
    fn event_context_overflow() {
        const EVT_COUNT: usize = EVENT_CONTEXT_MAX_EVENTS * 2 + 1;
        let ctx: EventContext<usize> = EventContext::new().unwrap();
        let mut evts = Vec::with_capacity(EVT_COUNT);
        for i in 0..EVT_COUNT {
            let evt = PlatformEvent::new().unwrap();
            evt.write(1).unwrap();
            ctx.add(&evt, i).unwrap();
            evts.push(evt);
        }
        let mut evt_count = 0;
        while evt_count < EVT_COUNT {
            for event in ctx.wait().unwrap().iter().filter(|e| e.is_readable) {
                evts[event.token].read().unwrap();
                evt_count += 1;
            }
        }
    }

    #[test]
    fn event_context_timeout() {
        let ctx: EventContext<u32> = EventContext::new().unwrap();
        let dur = Duration::from_millis(10);
        let start_inst = Instant::now();
        ctx.wait_timeout(dur).unwrap();
        assert!(start_inst.elapsed() >= dur);
    }

    #[test]
    #[allow(dead_code)]
    fn event_token_derive() {
        #[derive(EventToken)]
        enum EmptyToken {}

        #[derive(PartialEq, Debug, EventToken)]
        enum Token {
            Alpha,
            Beta,
            // comments
            Gamma(u32),
            Delta { index: usize },
            Omega,
        }

        assert_eq!(
            Token::from_raw_token(Token::Alpha.as_raw_token()),
            Token::Alpha
        );
        assert_eq!(
            Token::from_raw_token(Token::Beta.as_raw_token()),
            Token::Beta
        );
        assert_eq!(
            Token::from_raw_token(Token::Gamma(55).as_raw_token()),
            Token::Gamma(55)
        );
        assert_eq!(
            Token::from_raw_token(Token::Delta { index: 100 }.as_raw_token()),
            Token::Delta { index: 100 }
        );
        assert_eq!(
            Token::from_raw_token(Token::Omega.as_raw_token()),
            Token::Omega
        );
    }
}
