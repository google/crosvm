// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::VecDeque;
use std::io::Read;
use std::io::Write;

use base::warn;
use base::AsRawDescriptor;
use base::RawDescriptor;
use linux_input_sys::constants::*;
use linux_input_sys::input_event;
use linux_input_sys::virtio_input_event;
use linux_input_sys::InputEventDecoder;
use zerocopy::AsBytes;

use super::evdev::grab_evdev;
use super::evdev::ungrab_evdev;
use super::InputError;
use super::Result;

/// Encapsulates a socket or device node into an abstract event source, providing a common
/// interface.
/// It supports read and write operations to provide and accept events just like an event device
/// node would, except that it handles virtio_input_event instead of input_event structures.
/// It's necessary to call receive_events() before events are available for read.
pub trait EventSource: AsRawDescriptor {
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

/// Encapsulates implementation details common to all kinds of event sources.
pub struct EventSourceImpl<T> {
    source: T,
    queue: VecDeque<virtio_input_event>,
    read_buffer: Vec<u8>,
    read_idx: usize,
}

impl<T: AsRawDescriptor> EventSourceImpl<T> {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.source.as_raw_descriptor()
    }
}

impl<T> EventSourceImpl<T>
where
    T: Read + Write,
{
    // Receive events from the source and store them in a queue.
    fn receive_events<E: InputEventDecoder>(&mut self) -> Result<usize> {
        let read = self
            .source
            .read(&mut self.read_buffer[self.read_idx..])
            .map_err(InputError::EventsReadError)?;
        let buff_size = read + self.read_idx;

        for evt_slice in self.read_buffer[..buff_size].chunks_exact(E::SIZE) {
            self.queue.push_back(E::decode(evt_slice));
        }

        let remainder = buff_size % E::SIZE;
        // If there is an incomplete event at the end of the buffer, it needs to be moved to the
        // beginning and the next read operation must write right after it.
        if remainder != 0 {
            warn!("read incomplete event from source");
            // The copy should only happen if there is at least one complete event in the buffer,
            // otherwise source and destination would be the same.
            if buff_size != remainder {
                let (des, src) = self.read_buffer.split_at_mut(buff_size - remainder);
                des[..remainder].copy_from_slice(&src[..remainder]);
            }
        }
        self.read_idx = remainder;

        let received_events = buff_size / E::SIZE;

        Ok(received_events)
    }

    fn available_events(&self) -> usize {
        self.queue.len()
    }

    fn pop_available_event(&mut self) -> Option<virtio_input_event> {
        self.queue.pop_front()
    }

    fn send_event(&mut self, vio_evt: &virtio_input_event, encoding: EventType) -> Result<()> {
        // Miscellaneous events produced by the device are sent back to it by the kernel input
        // subsystem, but because these events are handled by the host kernel as well as the
        // guest the device would get them twice. Which would prompt the device to send the
        // event to the guest again entering an infinite loop.
        if vio_evt.type_ != EV_MSC {
            let evt;
            let event_bytes = match encoding {
                EventType::InputEvent => {
                    evt = input_event::from_virtio_input_event(vio_evt);
                    evt.as_bytes()
                }
                EventType::VirtioInputEvent => vio_evt.as_bytes(),
            };
            self.source
                .write_all(event_bytes)
                .map_err(InputError::EventsWriteError)?;
        }
        Ok(())
    }

    fn new(source: T, capacity: usize) -> EventSourceImpl<T> {
        EventSourceImpl {
            source,
            queue: VecDeque::new(),
            read_buffer: vec![0; capacity],
            read_idx: 0,
        }
    }
}

enum EventType {
    VirtioInputEvent,
    InputEvent,
}

/// Encapsulates a (unix) socket as an event source.
pub struct SocketEventSource<T> {
    evt_source_impl: EventSourceImpl<T>,
}

impl<T> SocketEventSource<T>
where
    T: Read + Write + AsRawDescriptor,
{
    pub fn new(source: T) -> SocketEventSource<T> {
        SocketEventSource {
            evt_source_impl: EventSourceImpl::new(source, 16 * virtio_input_event::SIZE),
        }
    }
}

impl<T: AsRawDescriptor> AsRawDescriptor for SocketEventSource<T> {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.evt_source_impl.as_raw_descriptor()
    }
}

impl<T> EventSource for SocketEventSource<T>
where
    T: Read + Write + AsRawDescriptor,
{
    fn init(&mut self) -> Result<()> {
        Ok(())
    }

    fn finalize(&mut self) -> Result<()> {
        Ok(())
    }

    fn receive_events(&mut self) -> Result<usize> {
        self.evt_source_impl.receive_events::<virtio_input_event>()
    }

    fn available_events_count(&self) -> usize {
        self.evt_source_impl.available_events()
    }

    fn pop_available_event(&mut self) -> Option<virtio_input_event> {
        self.evt_source_impl.pop_available_event()
    }

    fn send_event(&mut self, vio_evt: &virtio_input_event) -> Result<()> {
        self.evt_source_impl
            .send_event(vio_evt, EventType::VirtioInputEvent)
    }
}

/// Encapsulates an event device node as an event source
pub struct EvdevEventSource<T> {
    evt_source_impl: EventSourceImpl<T>,
}

impl<T> EvdevEventSource<T>
where
    T: Read + Write + AsRawDescriptor,
{
    pub fn new(source: T) -> EvdevEventSource<T> {
        EvdevEventSource {
            evt_source_impl: EventSourceImpl::new(source, 16 * input_event::SIZE),
        }
    }
}

impl<T: AsRawDescriptor> AsRawDescriptor for EvdevEventSource<T> {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.evt_source_impl.as_raw_descriptor()
    }
}

impl<T> EventSource for EvdevEventSource<T>
where
    T: Read + Write + AsRawDescriptor,
{
    fn init(&mut self) -> Result<()> {
        grab_evdev(self)
    }

    fn finalize(&mut self) -> Result<()> {
        ungrab_evdev(self)
    }

    fn receive_events(&mut self) -> Result<usize> {
        self.evt_source_impl.receive_events::<input_event>()
    }

    fn available_events_count(&self) -> usize {
        self.evt_source_impl.available_events()
    }

    fn pop_available_event(&mut self) -> Option<virtio_input_event> {
        self.evt_source_impl.pop_available_event()
    }

    fn send_event(&mut self, vio_evt: &virtio_input_event) -> Result<()> {
        self.evt_source_impl
            .send_event(vio_evt, EventType::InputEvent)
    }
}

#[cfg(test)]
mod tests {
    use std::cmp::min;
    use std::io::Read;
    use std::io::Write;

    use data_model::Le16;
    use data_model::SLe32;
    use linux_input_sys::InputEventDecoder;
    use zerocopy::AsBytes;

    use crate::virtio::input::event_source::input_event;
    use crate::virtio::input::event_source::virtio_input_event;
    use crate::virtio::input::event_source::EventSourceImpl;

    struct SourceMock {
        events: Vec<u8>,
    }

    impl SourceMock {
        fn new(evts: &[input_event]) -> SourceMock {
            let mut events: Vec<u8> = vec![];
            for evt in evts {
                for byte in evt.as_bytes() {
                    events.push(*byte);
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
        let mut source = EventSourceImpl::new(SourceMock::new(&[]), 128);
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
        let mut source = EventSourceImpl::new(SourceMock::new(&[]), 128);
        assert_eq!(
            source.receive_events::<input_event>().unwrap(),
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
                value: if idx % 2 == 0 {
                    3 * (idx as i32) + 3
                } else {
                    -3 * (idx as i32) - 3
                },
            });
        }
        ret
    }

    fn assert_events_match(e1: &virtio_input_event, e2: &input_event) {
        assert_eq!(e1.type_, Le16::from(e2.type_), "type should match");
        assert_eq!(e1.code, Le16::from(e2.code), "code should match");
        assert_eq!(e1.value, SLe32::from(e2.value), "value should match");
    }

    #[test]
    fn partial_pop() {
        let evts = instantiate_input_events(4usize);
        let mut source = EventSourceImpl::new(SourceMock::new(&evts), input_event::SIZE * 4);
        assert_eq!(
            source.receive_events::<input_event>().unwrap(),
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
        let mut source = EventSourceImpl::new(SourceMock::new(&evts), input_event::SIZE * 4);
        assert_eq!(
            source.receive_events::<input_event>().unwrap(),
            evts.len(),
            "should receive all events"
        );
        for expected_evt in evts[..EVENT_COUNT].iter() {
            let evt = source.pop_available_event().unwrap();
            assert_events_match(&evt, expected_evt);
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
