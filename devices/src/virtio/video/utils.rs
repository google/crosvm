// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Not all video backends make use of the tools in this module.
#![allow(dead_code)]

use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::time::Duration;

use base::AsRawDescriptor;
use base::Event;
use base::EventExt;
use sync::Mutex;
use thiserror::Error as ThisError;

use crate::virtio::video::resource::GuestResource;

/// Manages a pollable queue of events to be sent to the decoder or encoder.
pub struct EventQueue<T> {
    /// Pipe used to signal available events.
    event: Event,
    /// FIFO of all pending events.
    pending_events: VecDeque<T>,
}

impl<T> EventQueue<T> {
    /// Create a new event queue.
    pub fn new() -> base::Result<Self> {
        Ok(Self {
            // Use semaphore semantics so `eventfd` can be `read` as many times as it has been
            // `write`n to without blocking.
            event: Event::new()?,
            pending_events: Default::default(),
        })
    }

    /// Add `event` to the queue.
    pub fn queue_event(&mut self, event: T) -> base::Result<()> {
        self.pending_events.push_back(event);
        self.event.write_count(1)?;
        Ok(())
    }

    /// Read the next event, blocking until an event becomes available.
    pub fn dequeue_event(&mut self) -> base::Result<T> {
        // Wait until at least one event is written, if necessary.
        let cpt = self.event.read_count()?;
        let event = match self.pending_events.pop_front() {
            Some(event) => event,
            None => panic!("event signaled but no pending event - this is a bug."),
        };
        // If we have more than one event pending, write the remainder back into the event so it
        // keeps signalling.
        if cpt > 1 {
            self.event.write_count(cpt - 1)?;
        }

        Ok(event)
    }

    /// Remove all the posted events for which `predicate` returns `false`.
    pub fn retain<P: FnMut(&T) -> bool>(&mut self, predicate: P) {
        if !self.pending_events.is_empty() {
            let _ = self
                .event
                .wait_timeout(Duration::from_millis(0))
                .expect("wait_timeout failure");
        }

        self.pending_events.retain(predicate);

        let num_pending_events = self.pending_events.len();
        if num_pending_events > 0 {
            self.event
                .write_count(num_pending_events as u64)
                .expect("write failure");
        }
    }

    /// Returns the number of events currently pending on this queue, i.e. the number of times
    /// `dequeue_event` can be called without blocking.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.pending_events.len()
    }
}

impl<T> AsRawDescriptor for EventQueue<T> {
    fn as_raw_descriptor(&self) -> base::RawDescriptor {
        self.event.as_raw_descriptor()
    }
}

/// An `EventQueue` that is `Sync`, `Send`, and non-mut - i.e. that can easily be passed across
/// threads and wrapped into a `Rc` or `Arc`.
pub struct SyncEventQueue<T>(Mutex<EventQueue<T>>);

impl<T> From<EventQueue<T>> for SyncEventQueue<T> {
    fn from(queue: EventQueue<T>) -> Self {
        Self(Mutex::new(queue))
    }
}

impl<T> SyncEventQueue<T> {
    /// Add `event` to the queue.
    pub fn queue_event(&self, event: T) -> base::Result<()> {
        self.0.lock().queue_event(event)
    }

    /// Read the next event, blocking until an event becomes available.
    pub fn dequeue_event(&self) -> base::Result<T> {
        self.0.lock().dequeue_event()
    }

    /// Remove all the posted events for which `predicate` returns `false`.
    pub fn retain<P: FnMut(&T) -> bool>(&self, predicate: P) {
        self.0.lock().retain(predicate)
    }

    /// Returns the number of events currently pending on this queue, i.e. the number of times
    /// `dequeue_event` can be called without blocking.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.0.lock().len()
    }
}

impl<T> AsRawDescriptor for SyncEventQueue<T> {
    fn as_raw_descriptor(&self) -> base::RawDescriptor {
        self.0.lock().as_raw_descriptor()
    }
}

/// Queue of all the output buffers provided by crosvm.
pub struct OutputQueue {
    // Max number of output buffers that can be imported into this queue.
    num_buffers: usize,
    // Maps picture IDs to the corresponding guest resource.
    buffers: BTreeMap<u32, GuestResource>,
    // Picture IDs of output buffers we can write into.
    ready_buffers: VecDeque<u32>,
}

#[derive(Debug, ThisError)]
pub enum OutputBufferImportError {
    #[error("maximum number of imported buffers ({0}) already reached")]
    MaxBuffersReached(usize),
    #[error("a buffer with picture ID {0} is already imported")]
    AlreadyImported(u32),
}

#[derive(Debug, ThisError)]
pub enum OutputBufferReuseError {
    #[error("no buffer with picture ID {0} is imported at the moment")]
    NotYetImported(u32),
    #[error("buffer with picture ID {0} is already ready for use")]
    AlreadyUsed(u32),
}

impl OutputQueue {
    /// Creates a new output queue capable of containing `num_buffers` buffers.
    pub fn new(num_buffers: usize) -> Self {
        Self {
            num_buffers,
            buffers: Default::default(),
            ready_buffers: Default::default(),
        }
    }

    /// Import a buffer, i.e. associate the buffer's `resource` to a given `picture_buffer_id`, and
    /// make the buffer ready for use.
    ///
    /// A buffer with a given `picture_buffer_id` can only be imported once.
    pub fn import_buffer(
        &mut self,
        picture_buffer_id: u32,
        resource: GuestResource,
    ) -> Result<(), OutputBufferImportError> {
        if self.buffers.len() >= self.num_buffers {
            return Err(OutputBufferImportError::MaxBuffersReached(self.num_buffers));
        }

        match self.buffers.entry(picture_buffer_id) {
            Entry::Vacant(o) => {
                o.insert(resource);
            }
            Entry::Occupied(_) => {
                return Err(OutputBufferImportError::AlreadyImported(picture_buffer_id));
            }
        }

        self.ready_buffers.push_back(picture_buffer_id);

        Ok(())
    }

    /// Mark the previously-imported buffer with ID `picture_buffer_id` as ready for being used.
    pub fn reuse_buffer(&mut self, picture_buffer_id: u32) -> Result<(), OutputBufferReuseError> {
        if !self.buffers.contains_key(&picture_buffer_id) {
            return Err(OutputBufferReuseError::NotYetImported(picture_buffer_id));
        }

        if self.ready_buffers.contains(&picture_buffer_id) {
            return Err(OutputBufferReuseError::AlreadyUsed(picture_buffer_id));
        }

        self.ready_buffers.push_back(picture_buffer_id);

        Ok(())
    }

    /// Get a buffer ready to be decoded into, if any is available.
    pub fn try_get_ready_buffer(&mut self) -> Option<(u32, &mut GuestResource)> {
        let picture_buffer_id = self.ready_buffers.pop_front()?;
        // Unwrapping is safe here because our interface guarantees that ids in `ready_buffers` are
        // valid keys for `buffers`.
        Some((
            picture_buffer_id,
            self.buffers
                .get_mut(&picture_buffer_id)
                .expect("expected buffer not present in queue"),
        ))
    }

    pub fn clear_ready_buffers(&mut self) {
        self.ready_buffers.clear();
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use base::EventToken;
    use base::WaitContext;

    use super::*;
    use crate::virtio::video::error::VideoError;
    use crate::virtio::video::error::VideoResult;
    use crate::virtio::video::format::Rect;

    /// This is the same as DecoderEvent but copied here so that the test can be compiled
    /// without depending on the "video-decoder" feature.
    #[derive(Debug)]
    pub enum TestEvent {
        #[allow(dead_code)]
        ProvidePictureBuffers {
            min_num_buffers: u32,
            width: i32,
            height: i32,
            visible_rect: Rect,
        },
        PictureReady {
            picture_buffer_id: i32,
            timestamp: u64,
            visible_rect: Rect,
        },
        NotifyEndOfBitstreamBuffer(u32),
        #[allow(dead_code)]
        NotifyError(VideoError),
        #[allow(dead_code)]
        FlushCompleted(VideoResult<()>),
        #[allow(dead_code)]
        ResetCompleted(VideoResult<()>),
    }

    /// Test basic queue/dequeue functionality of `EventQueue`.
    #[test]
    fn event_queue() {
        let mut event_queue = EventQueue::new().unwrap();

        assert_eq!(
            event_queue.queue_event(TestEvent::NotifyEndOfBitstreamBuffer(1)),
            Ok(())
        );
        assert_eq!(event_queue.len(), 1);
        assert_eq!(
            event_queue.queue_event(TestEvent::PictureReady {
                picture_buffer_id: 0,
                timestamp: 42,
                visible_rect: Rect {
                    left: 0,
                    top: 0,
                    right: 320,
                    bottom: 240,
                },
            }),
            Ok(())
        );
        assert_eq!(event_queue.len(), 2);

        assert!(matches!(
            event_queue.dequeue_event(),
            Ok(TestEvent::NotifyEndOfBitstreamBuffer(1))
        ));
        assert_eq!(event_queue.len(), 1);
        assert!(matches!(
            event_queue.dequeue_event(),
            Ok(TestEvent::PictureReady {
                picture_buffer_id: 0,
                timestamp: 42,
                visible_rect: Rect {
                    left: 0,
                    top: 0,
                    right: 320,
                    bottom: 240,
                }
            })
        ));
        assert_eq!(event_queue.len(), 0);
    }

    /// Test polling of `TestEventQueue`'s `event_pipe`.
    #[test]
    fn decoder_event_queue_polling() {
        #[derive(EventToken)]
        enum Token {
            Event,
        }

        let mut event_queue = EventQueue::new().unwrap();
        let wait_context = WaitContext::build_with(&[(&event_queue, Token::Event)]).unwrap();

        // The queue is empty, so `event_pipe` should not signal.
        assert_eq!(wait_context.wait_timeout(Duration::ZERO).unwrap().len(), 0);

        // `event_pipe` should signal as long as the queue is not empty.
        event_queue
            .queue_event(TestEvent::NotifyEndOfBitstreamBuffer(1))
            .unwrap();
        assert_eq!(wait_context.wait_timeout(Duration::ZERO).unwrap().len(), 1);
        event_queue
            .queue_event(TestEvent::NotifyEndOfBitstreamBuffer(2))
            .unwrap();
        assert_eq!(wait_context.wait_timeout(Duration::ZERO).unwrap().len(), 1);
        event_queue
            .queue_event(TestEvent::NotifyEndOfBitstreamBuffer(3))
            .unwrap();
        assert_eq!(wait_context.wait_timeout(Duration::ZERO).unwrap().len(), 1);

        event_queue.dequeue_event().unwrap();
        assert_eq!(wait_context.wait_timeout(Duration::ZERO).unwrap().len(), 1);
        event_queue.dequeue_event().unwrap();
        assert_eq!(wait_context.wait_timeout(Duration::ZERO).unwrap().len(), 1);
        event_queue.dequeue_event().unwrap();

        // The queue is empty again, so `event_pipe` should not signal.
        assert_eq!(wait_context.wait_timeout(Duration::ZERO).unwrap().len(), 0);
    }
}
