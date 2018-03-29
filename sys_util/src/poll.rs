// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::{RefCell, Cell, Ref};
use std::cmp::min;
use std::fs::File;
use std::i32;
use std::i64;
use std::marker::PhantomData;
use std::os::unix::io::{RawFd, AsRawFd, IntoRawFd, FromRawFd};
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::ptr::{null, null_mut};
use std::slice;
use std::thread;
use std::time::Duration;

use libc::{c_int, c_long, timespec, time_t, nfds_t, sigset_t, pollfd, syscall, SYS_ppoll, POLLIN,
           POLLHUP, EPOLL_CLOEXEC, EPOLLIN, EPOLLHUP, EPOLL_CTL_ADD, EPOLL_CTL_MOD, EPOLL_CTL_DEL,
           epoll_create1, epoll_ctl, epoll_wait, epoll_event};

use {Result, errno_result};

const POLL_CONTEXT_MAX_EVENTS: usize = 16;

// The libc wrapper suppresses the kernel's changes to timeout, so we use the syscall directly.
unsafe fn ppoll(fds: *mut pollfd,
                nfds: nfds_t,
                timeout: *mut timespec,
                sigmask: *const sigset_t,
                sigsetsize: usize)
                -> c_int {
    syscall(SYS_ppoll, fds, nfds, timeout, sigmask, sigsetsize) as c_int
}

/// Trait for file descriptors that can be polled for input.
///
/// This is marked unsafe because the implementation must promise that the returned RawFd is valid
/// for polling purposes and that the lifetime of the returned fd is at least that of the trait
/// object.
pub unsafe trait Pollable {
    /// Gets the file descriptor that can be polled for input.
    fn pollable_fd(&self) -> RawFd;
}

unsafe impl Pollable for UnixStream {
    fn pollable_fd(&self) -> RawFd {
        self.as_raw_fd()
    }
}

unsafe impl Pollable for UnixDatagram {
    fn pollable_fd(&self) -> RawFd {
        self.as_raw_fd()
    }
}

/// Used to poll multiple `Pollable` objects at once.
///
/// # Example
///
/// ```
/// # use sys_util::{Result, EventFd, Poller, Pollable};
/// # fn test() -> Result<()> {
///     let evt1 = EventFd::new()?;
///     let evt2 = EventFd::new()?;
///     evt2.write(1)?;
///
///     let pollables: Vec<(u32, &Pollable)> = vec![(1, &evt1), (2, &evt2)];
///
///     let mut poller = Poller::new(2);
///     assert_eq!(poller.poll(&pollables[..]), Ok([2].as_ref()));
/// #   Ok(())
/// # }
/// ```
pub struct Poller {
    pollfds: Vec<pollfd>,
    tokens: Vec<u32>,
}

impl Poller {
    /// Constructs a new poller object with the given `capacity` of Pollable objects pre-allocated.
    pub fn new(capacity: usize) -> Poller {
        Poller {
            pollfds: Vec::with_capacity(capacity),
            tokens: Vec::with_capacity(capacity),
        }
    }

    /// Waits for any of the given slice of `token`-`Pollable` tuples to be readable without
    /// blocking and returns the `token` of each that is readable.
    ///
    /// This is guaranteed to not allocate if `pollables.len()` is less than the `capacity` given in
    /// `Poller::new`.
    pub fn poll(&mut self, pollables: &[(u32, &Pollable)]) -> Result<&[u32]> {
        self.poll_timeout(pollables, &mut Duration::new(time_t::max_value() as u64, 0))
    }

    /// Waits for up to the given timeout for any of the given slice of `token`-`Pollable` tuples to
    /// be readable without blocking and returns the `token` of each that is readable.
    ///
    /// If a timeout duration is given, the duration will be modified to the unused portion of the
    /// timeout, even if an error is returned.
    ///
    /// This is guaranteed to not allocate if `pollables.len()` is less than the `capacity` given in
    /// `Poller::new`.
    pub fn poll_timeout(&mut self,
                        pollables: &[(u32, &Pollable)],
                        timeout: &mut Duration)
                        -> Result<&[u32]> {
        self.pollfds.clear();
        for pollable in pollables.iter() {
            self.pollfds
                .push(pollfd {
                          fd: pollable.1.pollable_fd(),
                          events: POLLIN,
                          revents: 0,
                      });
        }

        let mut timeout_spec = timespec {
            tv_sec: timeout.as_secs() as time_t,
            tv_nsec: timeout.subsec_nanos() as c_long,
        };
        // Safe because poll is given the correct length of properly initialized pollfds, and we
        // check the return result.
        let ret = unsafe {
            handle_eintr_errno!(ppoll(self.pollfds.as_mut_ptr(),
                                      self.pollfds.len() as nfds_t,
                                      &mut timeout_spec,
                                      null(),
                                      0))
        };

        *timeout = Duration::new(timeout_spec.tv_sec as u64, timeout_spec.tv_nsec as u32);

        if ret < 0 {
            return errno_result();
        }

        self.tokens.clear();
        for (pollfd, pollable) in self.pollfds.iter().zip(pollables.iter()) {
            if (pollfd.revents & (POLLIN | POLLHUP)) != 0 {
                self.tokens.push(pollable.0);
            }
        }

        Ok(&self.tokens)
    }
}

/// Trait for a token that can be associated with an `fd` in a `PollContext`.
///
/// Simple enums that have no or primitive variant data data can use the `#[derive(PollToken)]`
/// custom derive to implement this trait. See
/// [poll_token_derive::poll_token](../poll_token_derive/fn.poll_token.html) for details.
pub trait PollToken {
    /// Converts this token into a u64 that can be turned back into a token via `from_raw_token`.
    fn as_raw_token(&self) -> u64;

    /// Converts a raw token as returned from `as_raw_token` back into a token.
    ///
    /// It is invalid to give a raw token that was not returned via `as_raw_token` from the same
    /// `Self`. The implementation can expect that this will never happen as a result of its usage
    /// in `PollContext`.
    fn from_raw_token(data: u64) -> Self;
}

impl PollToken for usize {
    fn as_raw_token(&self) -> u64 {
        *self as u64
    }

    fn from_raw_token(data: u64) -> Self {
        data as Self
    }
}

impl PollToken for u64 {
    fn as_raw_token(&self) -> u64 {
        *self as u64
    }

    fn from_raw_token(data: u64) -> Self {
        data as Self
    }
}

impl PollToken for u32 {
    fn as_raw_token(&self) -> u64 {
        *self as u64
    }

    fn from_raw_token(data: u64) -> Self {
        data as Self
    }
}

impl PollToken for u16 {
    fn as_raw_token(&self) -> u64 {
        *self as u64
    }

    fn from_raw_token(data: u64) -> Self {
        data as Self
    }
}

impl PollToken for u8 {
    fn as_raw_token(&self) -> u64 {
        *self as u64
    }

    fn from_raw_token(data: u64) -> Self {
        data as Self
    }
}

impl PollToken for () {
    fn as_raw_token(&self) -> u64 {
        0
    }

    fn from_raw_token(_data: u64) -> Self {}
}

/// An event returned by `PollContext::wait`.
pub struct PollEvent<'a, T> {
    event: &'a epoll_event,
    token: PhantomData<T>, // Needed to satisfy usage of T
}

impl<'a, T: PollToken> PollEvent<'a, T> {
    /// Gets the token associated in `PollContext::add` with this event.
    pub fn token(&self) -> T {
        T::from_raw_token(self.event.u64)
    }

    /// True if the `fd` associated with this token in `PollContext::add` is readable.
    pub fn readable(&self) -> bool {
        self.event.events & (EPOLLIN as u32) != 0
    }

    /// True if the `fd` associated with this token in `PollContext::add` has been hungup on.
    pub fn hungup(&self) -> bool {
        self.event.events & (EPOLLHUP as u32) != 0
    }
}

/// An iterator over some (sub)set of events returned by `PollContext::wait`.
pub struct PollEventIter<'a, I, T>
    where I: Iterator<Item = &'a epoll_event>
{
    mask: u32,
    iter: I,
    tokens: PhantomData<[T]>, // Needed to satisfy usage of T
}

impl<'a, I, T> Iterator for PollEventIter<'a, I, T>
    where I: Iterator<Item = &'a epoll_event>,
          T: PollToken
{
    type Item = PollEvent<'a, T>;
    fn next(&mut self) -> Option<Self::Item> {
        let mask = self.mask;
        self.iter
            .find(|event| (event.events & mask) != 0)
            .map(|event| {
                     PollEvent {
                         event,
                         token: PhantomData,
                     }
                 })
    }
}

/// The list of event returned by `PollContext::wait`.
pub struct PollEvents<'a, T> {
    count: usize,
    events: Ref<'a, [epoll_event; POLL_CONTEXT_MAX_EVENTS]>,
    tokens: PhantomData<[T]>, // Needed to satisfy usage of T
}

impl<'a, T: PollToken> PollEvents<'a, T> {
    /// Iterates over each event.
    pub fn iter(&self) -> PollEventIter<slice::Iter<epoll_event>, T> {
        PollEventIter {
            mask: 0xffffffff,
            iter: self.events[..self.count].iter(),
            tokens: PhantomData,
        }
    }

    /// Iterates over each readable event.
    pub fn iter_readable(&self) -> PollEventIter<slice::Iter<epoll_event>, T> {
        PollEventIter {
            mask: EPOLLIN as u32,
            iter: self.events[..self.count].iter(),
            tokens: PhantomData,
        }
    }

    /// Iterates over each hungup event.
    pub fn iter_hungup(&self) -> PollEventIter<slice::Iter<epoll_event>, T> {
        PollEventIter {
            mask: EPOLLHUP as u32,
            iter: self.events[..self.count].iter(),
            tokens: PhantomData,
        }
    }
}

/// Used to poll multiple objects that have file descriptors.
///
/// # Example
///
/// ```
/// # use sys_util::{Result, EventFd, PollContext, PollEvents};
/// # fn test() -> Result<()> {
///     let evt1 = EventFd::new()?;
///     let evt2 = EventFd::new()?;
///     evt2.write(1)?;
///
///     let ctx: PollContext<u32> = PollContext::new()?;
///     ctx.add(&evt1, 1)?;
///     ctx.add(&evt2, 2)?;
///
///     let pollevents: PollEvents<u32> = ctx.wait()?;
///     let tokens: Vec<u32> = pollevents.iter_readable().map(|e| e.token()).collect();
///     assert_eq!(&tokens[..], &[2]);
/// #   Ok(())
/// # }
/// ```
pub struct PollContext<T> {
    epoll_ctx: File,

    // We use a RefCell here so that the `wait` method only requires an immutable self reference
    // while returning the events (encapsulated by PollEvents). Without the RefCell, `wait` would
    // hold a mutable reference that lives as long as its returned reference (i.e. the PollEvents),
    // even though that reference is immutable. This is terribly inconvenient for the caller because
    // the borrow checking would prevent them from using `delete` and `add` while the events are in
    // scope.
    events: RefCell<[epoll_event; POLL_CONTEXT_MAX_EVENTS]>,

    // Hangup busy loop detection variables. See `check_for_hungup_busy_loop`.
    hangups: Cell<usize>,
    max_hangups: Cell<usize>,

    // Needed to satisfy usage of T
    tokens: PhantomData<[T]>,
}

impl<T: PollToken> PollContext<T> {
    /// Creates a new `PollContext`.
    pub fn new() -> Result<PollContext<T>> {
        // Safe because we check the return value.
        let epoll_fd = unsafe { epoll_create1(EPOLL_CLOEXEC) };
        if epoll_fd < 0 {
            return errno_result();
        }
        Ok(PollContext {
               epoll_ctx: unsafe { File::from_raw_fd(epoll_fd) },
               events: RefCell::new([epoll_event { events: 0, u64: 0 }; POLL_CONTEXT_MAX_EVENTS]),
               hangups: Cell::new(0),
               max_hangups: Cell::new(0),
               // Safe because the `epoll_fd` is valid and we hold unique ownership.
               tokens: PhantomData,
           })
    }

    /// Adds the given `fd` to this context and associates the given `token` with the `fd`'s events.
    ///
    /// A `fd` can only be added once and does not need to be kept open. If the `fd` is dropped and
    /// there were no duplicated file descriptors (i.e. adding the same descriptor with a different
    /// FD number) added to this context, events will not be reported by `wait` anymore.
    pub fn add(&self, fd: &AsRawFd, token: T) -> Result<()> {
        let mut evt = epoll_event {
            events: EPOLLIN as u32,
            u64: token.as_raw_token(),
        };
        // Safe because we give a valid epoll FD and FD to watch, as well as a valid epoll_event
        // structure. Then we check the return value.
        let ret = unsafe {
            epoll_ctl(self.epoll_ctx.as_raw_fd(),
                      EPOLL_CTL_ADD,
                      fd.as_raw_fd(),
                      &mut evt)
        };
        if ret < 0 {
            return errno_result();
        };

        // Used to detect busy loop waits caused by unhandled hangup events.
        self.hangups.set(0);
        self.max_hangups.set(self.max_hangups.get() + 1);
        Ok(())
    }

    /// If `fd` was previously added to this context, the token associated with it will be replaced
    /// with the given `token`.
    pub fn modify(&self, fd: &AsRawFd, token: T) -> Result<()> {
        let mut evt = epoll_event {
            events: EPOLLIN as u32,
            u64: token.as_raw_token(),
        };
        // Safe because we give a valid epoll FD and FD to modify, as well as a valid epoll_event
        // structure. Then we check the return value.
        let ret = unsafe {
            epoll_ctl(self.epoll_ctx.as_raw_fd(),
                      EPOLL_CTL_MOD,
                      fd.as_raw_fd(),
                      &mut evt)
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
    pub fn delete(&self, fd: &AsRawFd) -> Result<()> {
        // Safe because we give a valid epoll FD and FD to stop watching. Then we check the return
        // value.
        let ret = unsafe {
            epoll_ctl(self.epoll_ctx.as_raw_fd(),
                      EPOLL_CTL_DEL,
                      fd.as_raw_fd(),
                      null_mut())
        };
        if ret < 0 {
            return errno_result();
        };

        // Used to detect busy loop waits caused by unhandled hangup events.
        self.hangups.set(0);
        self.max_hangups.set(self.max_hangups.get() - 1);
        Ok(())
    }

    // This method determines if the the user of wait is misusing the `PollContext` by leaving FDs
    // in this `PollContext` that have been shutdown or hungup on. Such an FD will cause `wait` to
    // return instantly with a hungup event. If that FD is perpetually left in this context, a busy
    // loop burning ~100% of one CPU will silently occur with no human visible malfunction.
    //
    // How do we know if the client of this context is ignoring hangups? A naive implementation
    // would trigger if consecutive wait calls yield hangup events, but there are legitimate cases
    // for this, such as two distinct sockets becoming hungup across two consecutive wait calls. A
    // smarter implementation would only trigger if `delete` wasn't called between waits that
    // yielded hangups. Sadly `delete` isn't the only way to remove an FD from this context. The
    // other way is for the client to close the hungup FD, which automatically removes it from this
    // context. Assuming that the client always uses close, this implementation would too eagerly
    // trigger.
    //
    // The implementation used here keeps an upper bound of FDs in this context using a counter
    // hooked into add/delete (which is imprecise because close can also remove FDs without us
    // knowing). The number of consecutive (no add or delete in between) hangups yielded by wait
    // calls is counted and compared to the upper bound. If the upper bound is exceeded by the
    // consecutive hangups, the implementation triggers the check and logs.
    //
    // This implementation has false negatives because the upper bound can be completely too high,
    // in the worst case caused by only using close instead of delete. However, this method has the
    // advantage of always triggering eventually genuine busy loop cases, requires no dynamic
    // allocations, is fast and constant time to compute, and has no false positives.
    fn check_for_hungup_busy_loop(&self, new_hangups: usize) {
        let old_hangups = self.hangups.get();
        let max_hangups = self.max_hangups.get();
        if old_hangups <= max_hangups && old_hangups + new_hangups > max_hangups {
            warn!("busy poll wait loop with hungup FDs detected on thread {}",
                  thread::current().name().unwrap_or(""));
            // This panic is helpful for tests of this functionality.
            #[cfg(test)]
            panic!("hungup busy loop detected");
        }
        self.hangups.set(old_hangups + new_hangups);
    }

    /// Waits for any events to occur in FDs that were previously added to this context.
    ///
    /// The events are level-triggered, meaning that if any events are unhandled (i.e. not reading
    /// for readable events and not closing for hungup events), subsequent calls to `wait` will
    /// return immediately. The consequence of not handling an event perpetually while calling
    /// `wait` is that the callers loop will degenerated to busy loop polling, pinning a CPU to
    /// ~100% usage.
    ///
    /// # Panics
    /// Panics if the returned `PollEvents` structure is not dropped before subsequent `wait` calls.
    pub fn wait(&self) -> Result<PollEvents<T>> {
        self.wait_timeout(Duration::new(i64::MAX as u64, 0))
    }

    /// Like `wait` except will only block for a maximum of the given `timeout`.
    ///
    /// This may return earlier than `timeout` with zero events if the duration indicated exceeds
    /// system limits.
    pub fn wait_timeout(&self, timeout: Duration) -> Result<PollEvents<T>> {
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
                .and_then(|ms| ms.checked_add(timeout.subsec_nanos() as u64 / 1_000_000))
                .unwrap_or(i32::max_value() as u64);
            min(i32::max_value() as u64, millis) as i32
        };
        let ret = {
            let mut epoll_events = self.events.borrow_mut();
            let max_events = epoll_events.len() as c_int;
            // Safe because we give an epoll context and a properly sized epoll_events array
            // pointer, which we trust the kernel to fill in properly.
            unsafe {
                epoll_wait(self.epoll_ctx.as_raw_fd(),
                           &mut epoll_events[0],
                           max_events,
                           timeout_millis)
            }
        };
        if ret < 0 {
            return errno_result();
        }
        let epoll_events = self.events.borrow();
        let events = PollEvents {
            count: ret as usize,
            events: epoll_events,
            tokens: PhantomData,
        };
        let hangups = events.iter_hungup().count();
        self.check_for_hungup_busy_loop(hangups);
        Ok(events)
    }
}

impl<T: PollToken> AsRawFd for PollContext<T> {
    fn as_raw_fd(&self) -> RawFd {
        self.epoll_ctx.as_raw_fd()
    }
}

impl<T: PollToken> IntoRawFd for PollContext<T> {
    fn into_raw_fd(self) -> RawFd {
        self.epoll_ctx.into_raw_fd()
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    use EventFd;

    #[test]
    fn poller() {
        let evt1 = EventFd::new().unwrap();
        let evt2 = EventFd::new().unwrap();
        evt2.write(1).unwrap();

        let pollables: Vec<(u32, &Pollable)> = vec![(1, &evt1), (2, &evt2)];

        let mut poller = Poller::new(2);
        assert_eq!(poller.poll(&pollables[..]), Ok([2].as_ref()));
    }

    #[test]
    fn poller_multi() {
        let evt1 = EventFd::new().unwrap();
        let evt2 = EventFd::new().unwrap();
        evt1.write(1).unwrap();
        evt2.write(1).unwrap();

        let pollables: Vec<(u32, &Pollable)> = vec![(1, &evt1), (2, &evt2)];

        let mut poller = Poller::new(2);
        assert_eq!(poller.poll(&pollables[..]), Ok([1, 2].as_ref()));
    }

    #[test]
    fn timeout() {
        let evt1 = EventFd::new().unwrap();
        let initial_dur = Duration::from_millis(10);
        let mut timeout_dur = initial_dur;
        let mut poller = Poller::new(0);
        assert_eq!(poller.poll_timeout(&[(1, &evt1)], &mut timeout_dur),
                   Ok([].as_ref()));
        assert_eq!(timeout_dur, Duration::from_secs(0));
        evt1.write(1).unwrap();
        timeout_dur = initial_dur;
        assert_eq!(poller.poll_timeout(&[(1, &evt1)], &mut timeout_dur),
                   Ok([1].as_ref()));
        assert!(timeout_dur < initial_dur);
    }

    #[test]
    fn poll_context() {
        let evt1 = EventFd::new().unwrap();
        let evt2 = EventFd::new().unwrap();
        evt1.write(1).unwrap();
        evt2.write(1).unwrap();
        let ctx: PollContext<u32> = PollContext::new().unwrap();
        ctx.add(&evt1, 1).unwrap();
        ctx.add(&evt2, 2).unwrap();

        let mut evt_count = 0;
        while evt_count < 2 {
            for event in ctx.wait().unwrap().iter_readable() {
                evt_count += 1;
                match event.token() {
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
    fn poll_context_overflow() {
        const EVT_COUNT: usize = POLL_CONTEXT_MAX_EVENTS * 2 + 1;
        let ctx: PollContext<usize> = PollContext::new().unwrap();
        let mut evts = Vec::with_capacity(EVT_COUNT);
        for i in 0..EVT_COUNT {
            let evt = EventFd::new().unwrap();
            evt.write(1).unwrap();
            ctx.add(&evt, i).unwrap();
            evts.push(evt);
        }
        let mut evt_count = 0;
        while evt_count < EVT_COUNT {
            for event in ctx.wait().unwrap().iter_readable() {
                evts[event.token()].read().unwrap();
                evt_count += 1;
            }
        }
    }

    #[test]
    #[should_panic]
    fn poll_context_hungup() {
        let (s1, s2) = UnixStream::pair().unwrap();
        let ctx: PollContext<u32> = PollContext::new().unwrap();
        ctx.add(&s1, 1).unwrap();

        // Causes s1 to receive hangup events, which we purposefully ignore to trip the detection
        // logic in `PollContext`.
        drop(s2);

        // Should easily panic within this many iterations.
        for _ in 0..1000 {
            ctx.wait().unwrap();
        }
    }

    #[test]
    fn poll_context_timeout() {
        let ctx: PollContext<u32> = PollContext::new().unwrap();
        let dur = Duration::from_millis(10);
        let start_inst = Instant::now();
        ctx.wait_timeout(dur).unwrap();
        assert!(start_inst.elapsed() >= dur);
    }

    #[test]
    #[allow(dead_code)]
    fn poll_token_derive() {
        #[derive(PollToken)]
        enum EmptyToken {}

        #[derive(PartialEq, Debug, PollToken)]
        enum Token {
            Alpha,
            Beta,
            // comments
            Gamma(u32),
            Delta { index: usize },
            Omega,
        }

        assert_eq!(Token::from_raw_token(Token::Alpha.as_raw_token()),
                   Token::Alpha);
        assert_eq!(Token::from_raw_token(Token::Beta.as_raw_token()),
                   Token::Beta);
        assert_eq!(Token::from_raw_token(Token::Gamma(55).as_raw_token()),
                   Token::Gamma(55));
        assert_eq!(Token::from_raw_token(Token::Delta { index: 100 }.as_raw_token()),
                   Token::Delta { index: 100 });
        assert_eq!(Token::from_raw_token(Token::Omega.as_raw_token()),
                   Token::Omega);
    }
}
