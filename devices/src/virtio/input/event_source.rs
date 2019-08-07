// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::constants::*;
use super::evdev::{grab_evdev, ungrab_evdev};
use super::virtio_input_event;
use super::InputError;
use super::Result;
use data_model::DataInit;
use std::collections::VecDeque;
use std::io::Read;
use std::io::Write;
use std::mem::size_of;
use std::os::unix::io::{AsRawFd, RawFd};
use sys_util::{error, warn};

#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct input_event {
    timestamp_fields: [u64; 2],
    pub type_: u16,
    pub code: u16,
    pub value: u32,
}
// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for input_event {}

impl input_event {
    const EVENT_SIZE: usize = size_of::<input_event>();

    fn from_virtio_input_event(other: &virtio_input_event) -> input_event {
        input_event {
            timestamp_fields: [0, 0],
            type_: other.type_.into(),
            code: other.code.into(),
            value: other.value.into(),
        }
    }
}

/// Encapsulates a socket or device node into an abstract event source, providing a common
/// interface.
/// It supports read and write operations to provide and accept events just like an event device
/// node would, except that it handles virtio_input_event instead of input_event structures.
/// It's necessary to call receive_events() before events are available for read.
pub trait EventSource: AsRawFd {
    /// Perform any necessary initialization before receiving and sending events from/to the source.
    fn init(&mut self) -> Result<()> {
        Ok(())
    }
    /// Perform any necessary cleanup when the device will no longer be used.
    fn finalize(&mut self) -> Result<()> {
        Ok(())
    }

    /// Receive events from the source, filters them and stores them in a queue for future
    /// consumption by reading from this object. Returns the number of new non filtered events
    /// received. This function may block waiting for events to be available.
    fn receive_events(&mut self) -> Result<usize>;
    /// Returns the number of received events that have not been filtered or consumed yet.
    fn available_events_count(&self) -> usize;
    /// Returns the next available event
    fn pop_available_event(&mut self) -> Option<virtio_input_event>;
    /// Sends a status update event to the source
    fn send_event(&mut self, vio_evt: &virtio_input_event) -> Result<()>;
}

// Try to read 16 events at a time to match what the linux guest driver does.
const READ_BUFFER_SIZE: usize = 16 * size_of::<input_event>();

// The read buffer needs to be aligned to the alignment of input_event, which is aligned as u64
#[repr(align(8))]
pub struct ReadBuffer {
    buffer: [u8; READ_BUFFER_SIZE],
}

/// Encapsulates implementation details common to all kinds of event sources.
pub struct EventSourceImpl<T> {
    source: T,
    queue: VecDeque<virtio_input_event>,
    read_buffer: ReadBuffer,
    // The read index accounts for incomplete events read previously.
    read_idx: usize,
}

impl<T: AsRawFd> EventSourceImpl<T> {
    fn as_raw_fd(&self) -> RawFd {
        self.source.as_raw_fd()
    }
}

impl<T> EventSourceImpl<T>
where
    T: Read + Write,
{
    // Receive events from the source and store them in a queue, unless they should be filtered out.
    fn receive_events<F: Fn(&input_event) -> bool>(&mut self, event_filter: F) -> Result<usize> {
        let read = self
            .source
            .read(&mut self.read_buffer.buffer[self.read_idx..])
            .map_err(InputError::EventsReadError)?;
        let buff_size = read + self.read_idx;

        for evt_slice in self.read_buffer.buffer[..buff_size].chunks_exact(input_event::EVENT_SIZE)
        {
            let input_evt = match input_event::from_slice(evt_slice) {
                Some(x) => x,
                None => {
                    // This shouldn't happen because all slices (even the last one) are guaranteed
                    // to have the correct size and be properly aligned.
                    error!(
                        "Failed converting a slice of sice {} to input_event",
                        evt_slice.len()
                    );
                    // Skipping the event here effectively means no events will be received, because
                    // if from_slice fails once it will fail always.
                    continue;
                }
            };
            if !event_filter(&input_evt) {
                continue;
            }
            let vio_evt = virtio_input_event::from_input_event(input_evt);
            self.queue.push_back(vio_evt);
        }

        let remainder = buff_size % input_event::EVENT_SIZE;
        // If there is an incomplete event at the end of the buffer, it needs to be moved to the
        // beginning and the next read operation must write right after it.
        if remainder != 0 {
            warn!("read incomplete event from source");
            // The copy should only happen if there is at least one complete event in the buffer,
            // otherwise source and destination would be the same.
            if buff_size != remainder {
                let (des, src) = self.read_buffer.buffer.split_at_mut(buff_size - remainder);
                des[..remainder].copy_from_slice(&src[..remainder]);
            }
        }
        self.read_idx = remainder;

        let received_events = buff_size / input_event::EVENT_SIZE;

        Ok(received_events)
    }

    fn available_events(&self) -> usize {
        self.queue.len()
    }

    fn pop_available_event(&mut self) -> Option<virtio_input_event> {
        self.queue.pop_front()
    }

    fn send_event(&mut self, vio_evt: &virtio_input_event) -> Result<()> {
        let evt = input_event::from_virtio_input_event(vio_evt);
        // Miscellaneous events produced by the device are sent back to it by the kernel input
        // subsystem, but because these events are handled by the host kernel as well as the
        // guest the device would get them twice. Which would prompt the device to send the
        // event to the guest again entering an infinite loop.
        if evt.type_ != EV_MSC {
            self.source
                .write_all(evt.as_slice())
                .map_err(InputError::EventsWriteError)?;
        }
        Ok(())
    }

    fn new(source: T) -> EventSourceImpl<T> {
        EventSourceImpl {
            source,
            queue: VecDeque::new(),
            read_buffer: ReadBuffer {
                buffer: [0u8; READ_BUFFER_SIZE],
            },
            read_idx: 0,
        }
    }
}

/// Encapsulates a (unix) socket as an event source.
pub struct SocketEventSource<T> {
    evt_source_impl: EventSourceImpl<T>,
}

impl<T> SocketEventSource<T>
where
    T: Read + Write + AsRawFd,
{
    pub fn new(source: T) -> SocketEventSource<T> {
        SocketEventSource {
            evt_source_impl: EventSourceImpl::new(source),
        }
    }
}

impl<T: AsRawFd> AsRawFd for SocketEventSource<T> {
    fn as_raw_fd(&self) -> RawFd {
        self.evt_source_impl.as_raw_fd()
    }
}

impl<T> EventSource for SocketEventSource<T>
where
    T: Read + Write + AsRawFd,
{
    fn init(&mut self) -> Result<()> {
        Ok(())
    }

    fn finalize(&mut self) -> Result<()> {
        Ok(())
    }

    fn receive_events(&mut self) -> Result<usize> {
        self.evt_source_impl.receive_events(|_evt| true)
    }

    fn available_events_count(&self) -> usize {
        self.evt_source_impl.available_events()
    }

    fn pop_available_event(&mut self) -> Option<virtio_input_event> {
        self.evt_source_impl.pop_available_event()
    }

    fn send_event(&mut self, vio_evt: &virtio_input_event) -> Result<()> {
        self.evt_source_impl.send_event(vio_evt)
    }
}

/// Encapsulates an event device node as an event source
pub struct EvdevEventSource<T> {
    evt_source_impl: EventSourceImpl<T>,
}

impl<T> EvdevEventSource<T>
where
    T: Read + Write + AsRawFd,
{
    pub fn new(source: T) -> EvdevEventSource<T> {
        EvdevEventSource {
            evt_source_impl: EventSourceImpl::new(source),
        }
    }
}

impl<T: AsRawFd> AsRawFd for EvdevEventSource<T> {
    fn as_raw_fd(&self) -> RawFd {
        self.evt_source_impl.as_raw_fd()
    }
}

impl<T> EventSource for EvdevEventSource<T>
where
    T: Read + Write + AsRawFd,
{
    fn init(&mut self) -> Result<()> {
        grab_evdev(self)
    }

    fn finalize(&mut self) -> Result<()> {
        ungrab_evdev(self)
    }

    fn receive_events(&mut self) -> Result<usize> {
        self.evt_source_impl.receive_events(|_evt| true)
    }

    fn available_events_count(&self) -> usize {
        self.evt_source_impl.available_events()
    }

    fn pop_available_event(&mut self) -> Option<virtio_input_event> {
        self.evt_source_impl.pop_available_event()
    }

    fn send_event(&mut self, vio_evt: &virtio_input_event) -> Result<()> {
        self.evt_source_impl.send_event(vio_evt)
    }
}

#[cfg(test)]
mod tests {
    use crate::virtio::input::event_source::input_event;
    use crate::virtio::input::event_source::EventSourceImpl;
    use crate::virtio::input::virtio_input_event;
    use data_model::{DataInit, Le16, Le32};
    use std::cmp::min;
    use std::io::Read;
    use std::io::Write;

    struct SourceMock {
        events: Vec<u8>,
    }

    impl SourceMock {
        fn new(evts: &Vec<input_event>) -> SourceMock {
            let mut events: Vec<u8> = vec![];
            for evt in evts {
                for byte in evt.as_slice() {
                    events.push(byte.clone());
                }
            }
            SourceMock { events }
        }
    }

    impl Read for SourceMock {
        fn read(&mut self, buf: &mut [u8]) -> std::result::Result<usize, std::io::Error> {
            let copy_size = min(buf.len(), self.events.len());
            buf[..copy_size].copy_from_slice(&self.events[..copy_size]);
            Ok(copy_size)
        }
    }
    impl Write for SourceMock {
        fn write(&mut self, buf: &[u8]) -> std::result::Result<usize, std::io::Error> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::result::Result<(), std::io::Error> {
            Ok(())
        }
    }

    #[test]
    fn empty_new() {
        let mut source = EventSourceImpl::new(SourceMock::new(&vec![]));
        assert_eq!(
            source.available_events(),
            0,
            "zero events should be available"
        );
        assert_eq!(
            source.pop_available_event().is_none(),
            true,
            "no events should be available"
        );
    }

    #[test]
    fn empty_receive() {
        let mut source = EventSourceImpl::new(SourceMock::new(&vec![]));
        assert_eq!(
            source.receive_events(|_| true).unwrap(),
            0,
            "zero events should be received"
        );
        assert_eq!(
            source.pop_available_event().is_none(),
            true,
            "no events should be available"
        );
    }

    fn instantiate_input_events(count: usize) -> Vec<input_event> {
        let mut ret: Vec<input_event> = Vec::with_capacity(count);
        for idx in 0..count {
            ret.push(input_event {
                timestamp_fields: [0, 0],
                type_: 3 * (idx as u16) + 1,
                code: 3 * (idx as u16) + 2,
                value: 3 * (idx as u32) + 3,
            });
        }
        ret
    }

    fn assert_events_match(e1: &virtio_input_event, e2: &input_event) {
        assert_eq!(e1.type_, Le16::from(e2.type_), "type should match");
        assert_eq!(e1.code, Le16::from(e2.code), "code should match");
        assert_eq!(e1.value, Le32::from(e2.value), "value should match");
    }

    #[test]
    fn partial_pop() {
        let evts = instantiate_input_events(4usize);
        let mut source = EventSourceImpl::new(SourceMock::new(&evts));
        assert_eq!(
            source.receive_events(|_| true).unwrap(),
            evts.len(),
            "should receive all events"
        );
        let evt_opt = source.pop_available_event();
        assert_eq!(evt_opt.is_some(), true, "event should have been poped");
        let evt = evt_opt.unwrap();
        assert_events_match(&evt, &evts[0]);
    }

    #[test]
    fn total_pop() {
        const EVENT_COUNT: usize = 4;
        let evts = instantiate_input_events(EVENT_COUNT);
        let mut source = EventSourceImpl::new(SourceMock::new(&evts));
        assert_eq!(
            source.receive_events(|_| true).unwrap(),
            evts.len(),
            "should receive all events"
        );
        for idx in 0..EVENT_COUNT {
            let evt = source.pop_available_event().unwrap();
            assert_events_match(&evt, &evts[idx]);
        }
        assert_eq!(
            source.available_events(),
            0,
            "there should be no events left"
        );
        assert_eq!(
            source.pop_available_event().is_none(),
            true,
            "no events should pop"
        );
    }
}
