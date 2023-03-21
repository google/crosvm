// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Write;
use std::iter::ExactSizeIterator;

use base::AsRawDescriptor;
use base::RawDescriptor;
use base::StreamChannel;
use data_model::zerocopy_from_reader;
use linux_input_sys::virtio_input_event;
use linux_input_sys::InputEventDecoder;
use serde::Deserialize;
use serde::Serialize;
use zerocopy::AsBytes;

const EVENT_SIZE: usize = virtio_input_event::SIZE;
const EVENT_BUFFER_LEN_MAX: usize = 64 * EVENT_SIZE;

// /// Half-way build `EventDevice` with only the `event_socket` defined. Finish building the
// /// `EventDevice` by using `status_socket`.
// pub struct PartialEventDevice(UnixStream);

// impl PartialEventDevice {
//     /// Finish build `EventDevice` by providing the `status_socket`.
//     pub fn status_socket(self, status_socket: UnixStream) -> EventDevice {
//         EventDevice {
//             event_socket: self.0,
//             status_socket,
//         }
//     }
// }

#[derive(Copy, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum EventDeviceKind {
    /// Produces relative mouse motions, wheel, and button clicks while the real mouse is captured.
    Mouse,
    /// Produces absolute motion and touch events from the display window's events.
    Touchscreen,
    /// Produces key events while the display window has focus.
    Keyboard,
}

/// Encapsulates a virtual event device, such as a mouse or keyboard
#[derive(Deserialize, Serialize)]
pub struct EventDevice {
    kind: EventDeviceKind,
    event_buffer: VecDeque<u8>,
    event_socket: StreamChannel,
}

impl EventDevice {
    pub fn new(kind: EventDeviceKind, mut event_socket: StreamChannel) -> EventDevice {
        let _ = event_socket.set_nonblocking(true);
        EventDevice {
            kind,
            event_buffer: Default::default(),
            event_socket,
        }
    }

    #[inline]
    pub fn mouse(event_socket: StreamChannel) -> EventDevice {
        Self::new(EventDeviceKind::Mouse, event_socket)
    }

    #[inline]
    pub fn touchscreen(event_socket: StreamChannel) -> EventDevice {
        Self::new(EventDeviceKind::Touchscreen, event_socket)
    }

    #[inline]
    pub fn keyboard(event_socket: StreamChannel) -> EventDevice {
        Self::new(EventDeviceKind::Keyboard, event_socket)
    }

    #[inline]
    pub fn kind(&self) -> EventDeviceKind {
        self.kind
    }

    /// Flushes the buffered events that did not fit into the underlying transport, if any.
    ///
    /// Returns `Ok(true)` if, after this function returns, there all the buffer of events is
    /// empty.
    pub fn flush_buffered_events(&mut self) -> io::Result<bool> {
        while !self.event_buffer.is_empty() {
            let written = self.event_socket.write(self.event_buffer.as_slices().0)?;
            if written == 0 {
                return Ok(false);
            }
            self.event_buffer.drain(..written);
        }
        Ok(true)
    }

    pub fn is_buffered_events_empty(&self) -> bool {
        self.event_buffer.is_empty()
    }

    /// Determines if there is space in the event buffer for the given number
    /// of events. The buffer is capped at `EVENT_BUFFER_LEN_MAX`.
    #[inline]
    fn can_buffer_events(&self, num_events: usize) -> bool {
        let event_bytes = match EVENT_SIZE.checked_mul(num_events) {
            Some(bytes) => bytes,
            None => return false,
        };
        let free_bytes = EVENT_BUFFER_LEN_MAX.saturating_sub(self.event_buffer.len());

        free_bytes >= event_bytes
    }

    pub fn send_report<E: IntoIterator<Item = virtio_input_event>>(
        &mut self,
        events: E,
    ) -> io::Result<bool>
    where
        E::IntoIter: ExactSizeIterator,
    {
        let it = events.into_iter();

        if !self.can_buffer_events(it.len() + 1) {
            return Ok(false);
        }

        for event in it {
            let bytes = event.as_bytes();
            self.event_buffer.extend(bytes.iter());
        }

        self.event_buffer
            .extend(virtio_input_event::syn().as_bytes().iter());

        self.flush_buffered_events()
    }

    /// Sends the given `event`, returning `Ok(true)` if, after this function returns, there are no
    /// buffered events remaining.
    pub fn send_event_encoded(&mut self, event: virtio_input_event) -> io::Result<bool> {
        if !self.flush_buffered_events()? {
            return Ok(false);
        }

        let bytes = event.as_bytes();
        let written = self.event_socket.write(bytes)?;

        if written == bytes.len() {
            return Ok(true);
        }

        if self.can_buffer_events(1) {
            self.event_buffer.extend(bytes[written..].iter());
        }

        Ok(false)
    }

    pub fn recv_event_encoded(&self) -> io::Result<virtio_input_event> {
        zerocopy_from_reader::<_, virtio_input_event>(&self.event_socket)
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "failed to read virtio_input_event"))
    }
}

impl AsRawDescriptor for EventDevice {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.event_socket.as_raw_descriptor()
    }
}

impl fmt::Debug for EventDevice {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Event device ({:?})", self.kind)
    }
}
