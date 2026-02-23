// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::time::Duration;

use smallvec::SmallVec;

use crate::descriptor::AsRawDescriptor;
use crate::sys::unix::RawDescriptor;
use crate::EventToken;
use crate::EventType;
use crate::TriggeredEvent;

/// Tracked fd entry for poll-based EventContext.
struct PollEntry {
    fd: RawDescriptor,
    token_raw: u64,
    want_read: bool,
    want_write: bool,
}

/// EventContext provides poll-based event multiplexing for macOS.
/// Uses poll(2) instead of kqueue due to compatibility issues with the
/// Rust libc crate's kevent() binding on macOS aarch64.
pub struct EventContext<T> {
    entries: std::sync::Mutex<Vec<PollEntry>>,
    _phantom: std::marker::PhantomData<[T]>,
}

// SAFETY: The Mutex provides interior synchronization
unsafe impl<T> Send for EventContext<T> {}
// SAFETY: The Mutex provides interior synchronization
unsafe impl<T> Sync for EventContext<T> {}

impl<T: EventToken> EventContext<T> {
    /// Creates a new EventContext.
    pub fn new() -> crate::errno::Result<EventContext<T>> {
        Ok(EventContext {
            entries: std::sync::Mutex::new(Vec::new()),
            _phantom: std::marker::PhantomData,
        })
    }

    /// Creates a new EventContext with initial file descriptors and tokens.
    pub fn build_with(
        fd_tokens: &[(&dyn AsRawDescriptor, T)],
    ) -> crate::errno::Result<EventContext<T>> {
        let ctx = EventContext::new()?;
        ctx.add_many(fd_tokens)?;
        Ok(ctx)
    }

    /// Adds multiple fd/token pairs to this context.
    pub fn add_many(&self, fd_tokens: &[(&dyn AsRawDescriptor, T)]) -> crate::errno::Result<()> {
        for (fd, token) in fd_tokens {
            self.add(*fd, T::from_raw_token(token.as_raw_token()))?;
        }
        Ok(())
    }

    /// Adds a file descriptor to this context, watching for readable events.
    pub fn add(
        &self,
        descriptor: &dyn AsRawDescriptor,
        token: T,
    ) -> crate::errno::Result<()> {
        self.add_for_event(descriptor, EventType::Read, token)
    }

    /// Adds a file descriptor to the EventContext with the specified event type.
    pub fn add_for_event(
        &self,
        descriptor: &dyn AsRawDescriptor,
        event_type: EventType,
        token: T,
    ) -> crate::errno::Result<()> {
        let fd = descriptor.as_raw_descriptor();
        let token_raw = token.as_raw_token();

        if matches!(event_type, EventType::None) {
            return self.delete(descriptor);
        }

        let entry = PollEntry {
            fd,
            token_raw,
            want_read: matches!(event_type, EventType::Read | EventType::ReadWrite),
            want_write: matches!(event_type, EventType::Write | EventType::ReadWrite),
        };

        let mut entries = self.entries.lock().unwrap();
        entries.retain(|e| e.fd != fd);
        entries.push(entry);
        Ok(())
    }

    /// Modifies an existing file descriptor in the EventContext.
    pub fn modify(
        &self,
        fd: &dyn AsRawDescriptor,
        event_type: EventType,
        token: T,
    ) -> crate::errno::Result<()> {
        self.add_for_event(fd, event_type, token)
    }

    /// Removes a file descriptor from the EventContext.
    pub fn delete(&self, fd: &dyn AsRawDescriptor) -> crate::errno::Result<()> {
        let raw_fd = fd.as_raw_descriptor();
        let mut entries = self.entries.lock().unwrap();
        entries.retain(|e| e.fd != raw_fd);
        Ok(())
    }

    /// Waits for events indefinitely.
    pub fn wait(&self) -> crate::errno::Result<SmallVec<[TriggeredEvent<T>; 16]>> {
        self.wait_timeout_impl(None)
    }

    /// Waits for events with a timeout.
    pub fn wait_timeout(
        &self,
        timeout: Duration,
    ) -> crate::errno::Result<SmallVec<[TriggeredEvent<T>; 16]>> {
        self.wait_timeout_impl(Some(timeout))
    }

    fn wait_timeout_impl(
        &self,
        timeout: Option<Duration>,
    ) -> crate::errno::Result<SmallVec<[TriggeredEvent<T>; 16]>> {
        let entries = self.entries.lock().unwrap();

        if entries.is_empty() {
            drop(entries);
            if let Some(d) = timeout {
                std::thread::sleep(d);
            } else {
                std::thread::sleep(Duration::from_millis(100));
            }
            return Ok(SmallVec::new());
        }

        let mut pollfds: Vec<libc::pollfd> = entries
            .iter()
            .map(|e| {
                let mut events: libc::c_short = 0;
                if e.want_read {
                    events |= libc::POLLIN;
                }
                if e.want_write {
                    events |= libc::POLLOUT;
                }
                libc::pollfd {
                    fd: e.fd,
                    events,
                    revents: 0,
                }
            })
            .collect();

        // Snapshot token info before releasing lock
        let token_info: Vec<u64> = entries.iter().map(|e| e.token_raw).collect();
        drop(entries);

        let timeout_ms = match timeout {
            Some(d) => d.as_millis() as libc::c_int,
            None => -1,
        };

        // SAFETY: pollfds is a valid array
        let ret = unsafe {
            libc::poll(pollfds.as_mut_ptr(), pollfds.len() as libc::nfds_t, timeout_ms)
        };

        if ret < 0 {
            return crate::errno::errno_result();
        }

        let mut triggered = SmallVec::new();
        for (i, pfd) in pollfds.iter().enumerate() {
            if pfd.revents == 0 || i >= token_info.len() {
                continue;
            }

            let is_readable = (pfd.revents & (libc::POLLIN | libc::POLLPRI)) != 0;
            let is_writable = (pfd.revents & libc::POLLOUT) != 0;
            let is_hungup = (pfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL)) != 0;

            if is_readable || is_writable || is_hungup {
                triggered.push(TriggeredEvent {
                    token: T::from_raw_token(token_info[i]),
                    is_readable: is_readable || is_hungup,
                    is_writable,
                    is_hungup,
                });
            }
        }

        Ok(triggered)
    }
}

impl<T> AsRawDescriptor for EventContext<T> {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        -1
    }
}

impl<T> Drop for EventContext<T> {
    fn drop(&mut self) {}
}
