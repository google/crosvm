// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::time::Duration;

use crate::descriptor::AsRawDescriptor;
use crate::{
    platform::{EventContext, PollToken},
    RawDescriptor, Result,
};
use smallvec::SmallVec;

// Typedef PollToken as EventToken for better adherance to base naming.
// As actual typdefing is experimental, define a new trait with the mirrored
// attributes.
pub trait EventToken: PollToken {}
impl<T: PollToken> EventToken for T {}

/// Represents an event that has been signaled and waited for via a wait function.
#[derive(Copy, Clone, Debug)]
pub struct TriggeredEvent<T: EventToken> {
    pub token: T,
    pub is_readable: bool,
    pub is_writable: bool,
    pub is_hungup: bool,
}

/// Represents types of events to watch for.
pub enum EventType {
    // Used to to temporarily stop waiting for events without
    // removing the associated descriptor from the WaitContext.
    // In most cases if a descriptor no longer needs to be
    // waited on, prefer removing it entirely with
    // WaitContext#delete
    None,
    Read,
    Write,
    ReadWrite,
}

/// Used to wait for multiple objects which are eligible for waiting.
///
/// # Example
///
/// ```
/// use base::{Event, PollToken, Result, WaitContext};
///
/// #[derive(PollToken, Copy, Clone, Debug, PartialEq)]
/// enum ExampleToken {
///    SomeEvent(u32),
///    AnotherEvent,
/// }
///
/// let evt1 = Event::new()?;
/// let evt2 = Event::new()?;
/// let another_evt = Event::new()?;
///
/// let ctx: WaitContext<ExampleToken> = WaitContext::build_with(&[
///     (&evt1, ExampleToken::SomeEvent(1)),
///     (&evt2, ExampleToken::SomeEvent(2)),
///     (&another_evt, ExampleToken::AnotherEvent),
/// ])?;
///
/// // Trigger one of the `SomeEvent` events.
/// evt2.write(1)?;
///
/// // Wait for an event to fire. `wait()` will return immediately in this example because `evt2`
/// // has already been triggered, but in normal use, `wait()` will block until at least one event
/// // is signaled by another thread or process.
/// let events = ctx.wait()?;
/// let tokens: Vec<ExampleToken> = events.iter().filter(|e| e.is_readable)
///     .map(|e| e.token).collect();
/// assert_eq!(tokens, [ExampleToken::SomeEvent(2)]);
///
/// // Reset evt2 so it doesn't trigger again in the next `wait()` call.
/// let _ = evt2.read()?;
///
/// // Trigger a different event.
/// another_evt.write(1)?;
///
/// let events = ctx.wait()?;
/// let tokens: Vec<ExampleToken> = events.iter().filter(|e| e.is_readable)
///     .map(|e| e.token).collect();
/// assert_eq!(tokens, [ExampleToken::AnotherEvent]);
///
/// let _ = another_evt.read()?;
/// # Ok::<(), base::Error>(())
/// ```
pub struct WaitContext<T: EventToken>(EventContext<T>);

impl<T: EventToken> WaitContext<T> {
    /// Creates a new WaitContext.
    pub fn new() -> Result<WaitContext<T>> {
        EventContext::new().map(WaitContext)
    }

    /// Creates a new WaitContext with the the associated triggers.
    pub fn build_with(triggers: &[(&dyn AsRawDescriptor, T)]) -> Result<WaitContext<T>> {
        let ctx = WaitContext::new()?;
        ctx.add_many(triggers)?;
        Ok(ctx)
    }

    /// Adds a trigger to the WaitContext.
    pub fn add(&self, descriptor: &dyn AsRawDescriptor, token: T) -> Result<()> {
        self.add_for_event(descriptor, EventType::Read, token)
    }

    /// Adds a trigger to the WaitContext watching for a specific type of event
    pub fn add_for_event(
        &self,
        descriptor: &dyn AsRawDescriptor,
        event_type: EventType,
        token: T,
    ) -> Result<()> {
        self.0.add_for_event(descriptor, event_type, token)
    }

    /// Adds multiple triggers to the WaitContext.
    pub fn add_many(&self, triggers: &[(&dyn AsRawDescriptor, T)]) -> Result<()> {
        for trigger in triggers {
            self.add(trigger.0, T::from_raw_token(trigger.1.as_raw_token()))?
        }
        Ok(())
    }

    /// Modifies a trigger already added to the WaitContext. If the descriptor is
    /// already registered, its associated token will be updated.
    pub fn modify(
        &self,
        descriptor: &dyn AsRawDescriptor,
        event_type: EventType,
        token: T,
    ) -> Result<()> {
        self.0.modify(descriptor, event_type, token)
    }

    /// Removes the given handle from triggers registered in the WaitContext if
    /// present.
    pub fn delete(&self, descriptor: &dyn AsRawDescriptor) -> Result<()> {
        self.0.delete(descriptor)
    }

    /// Waits for one or more of the registered triggers to become signaled.
    pub fn wait(&self) -> Result<SmallVec<[TriggeredEvent<T>; 16]>> {
        self.wait_timeout(Duration::new(i64::MAX as u64, 0))
    }
    /// Waits for one or more of the registered triggers to become signaled, failing if no triggers
    /// are signaled before the designated timeout has elapsed.
    pub fn wait_timeout(&self, timeout: Duration) -> Result<SmallVec<[TriggeredEvent<T>; 16]>> {
        let events = self.0.wait_timeout(timeout)?;
        Ok(events
            .iter()
            .map(|event| TriggeredEvent {
                token: event.token(),
                is_readable: event.readable(),
                is_writable: event.writable(),
                is_hungup: event.hungup(),
            })
            .collect())
    }
}

impl<T: PollToken> AsRawDescriptor for WaitContext<T> {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.0.as_raw_descriptor()
    }
}
