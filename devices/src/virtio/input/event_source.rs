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
pub trait EventSource: Read + Write + AsRawFd {
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

// Reads input events from the source.
// Events are originally read as input_event structs and converted to virtio_input_event internally.
impl<T: Read> EventSourceImpl<T> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut bytes = 0usize;
        for evt_slice in buf.chunks_exact_mut(virtio_input_event::EVENT_SIZE) {
            match self.queue.pop_front() {
                None => {
                    break;
                }
                Some(evt) => {
                    evt_slice.copy_from_slice(evt.as_slice());
                    bytes += evt_slice.len();
                }
            }
        }
        Ok(bytes)
    }
}

// Writes input events to the source.
// Events come as virtio_input_event structs and are converted to input_event internally.
impl<T: Write> EventSourceImpl<T> {
    fn write<F: Fn(&virtio_input_event) -> bool>(
        &mut self,
        buf: &[u8],
        event_filter: F,
    ) -> std::io::Result<usize> {
        for evt_slice in buf.chunks_exact(virtio_input_event::EVENT_SIZE) {
            // Don't use from_slice() here, the buffer is not guaranteed to be properly aligned.
            let mut vio_evt = virtio_input_event::new(0, 0, 0);
            vio_evt.as_mut_slice().copy_from_slice(evt_slice);
            if !event_filter(&vio_evt) {
                continue;
            }
            let evt = input_event::from_virtio_input_event(&vio_evt);
            self.source.write_all(evt.as_slice())?;
        }

        let len = buf.len() - buf.len() % virtio_input_event::EVENT_SIZE;
        Ok(len)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.source.flush()
    }
}

impl<T: AsRawFd> EventSourceImpl<T> {
    fn as_raw_fd(&self) -> RawFd {
        self.source.as_raw_fd()
    }
}

impl<T> EventSourceImpl<T>
where
    T: Read + Write + AsRawFd,
{
    // Receive events from the source and store them in a queue, unless they should be filtered out.
    fn receive_events<F: Fn(&input_event) -> bool>(&mut self, event_filter: F) -> Result<usize> {
        let read = self
            .source
            .read(&mut self.read_buffer.buffer[self.read_idx..])
            .map_err(|e| InputError::EventsReadError(e))?;
        let buff_size = read + self.read_idx;

        for evt_slice in self
            .read_buffer
            .buffer
            .chunks_exact(input_event::EVENT_SIZE)
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
                des[..remainder].copy_from_slice(src);
            }
        }
        self.read_idx = remainder;

        let received_events = buff_size / input_event::EVENT_SIZE;

        Ok(received_events)
    }

    fn available_events(&self) -> usize {
        self.queue.len()
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

impl<T: Read> Read for SocketEventSource<T> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.evt_source_impl.read(buf)
    }
}

impl<T> Write for SocketEventSource<T>
where
    T: Read + Write + AsRawFd,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.evt_source_impl.write(buf, |_evt| true)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.evt_source_impl.flush()
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

impl<T: Read> Read for EvdevEventSource<T> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.evt_source_impl.read(buf)
    }
}

impl<T> Write for EvdevEventSource<T>
where
    T: Read + Write + AsRawFd,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.evt_source_impl.write(buf, |evt| {
            // Miscellaneous events produced by the device are sent back to it by the kernel input
            // subsystem, but because these events are handled by the host kernel as well as the
            // guest the device would get them twice. Which would prompt the device to send the
            // event to the guest again entering an infinite loop.
            evt.type_ != EV_MSC
        })
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.evt_source_impl.flush()
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
}
