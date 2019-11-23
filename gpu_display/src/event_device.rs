// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::iter::ExactSizeIterator;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;

const EVENT_SIZE: usize = 4;
const EVENT_BUFFER_LEN_MAX: usize = 16 * EVENT_SIZE;

const EV_SYN: u16 = 0x00;
const EV_KEY: u16 = 0x01;
const EV_REL: u16 = 0x02;
const EV_ABS: u16 = 0x03;
const SYN_REPORT: u16 = 0;
const REL_X: u16 = 0x00;
const REL_Y: u16 = 0x01;
const ABS_X: u16 = 0x00;
const ABS_Y: u16 = 0x01;

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

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum EventDeviceKind {
    /// Produces relative mouse motions, wheel, and button clicks while the real mouse is captured.
    Mouse,
    /// Produces absolute motion and touch events from the display window's events.
    Touchscreen,
    /// Produces key events while the display window has focus.
    Keyboard,
}

#[derive(Copy, Clone, Default, PartialEq, Eq, Debug)]
pub struct EventEncoded {
    pub type_: u16,
    pub code: u16,
    pub value: u32,
}

impl EventEncoded {
    #[inline]
    pub fn syn() -> EventEncoded {
        EventEncoded {
            type_: EV_SYN,
            code: SYN_REPORT,
            value: 0,
        }
    }

    #[inline]
    pub fn absolute(code: u16, value: u32) -> EventEncoded {
        EventEncoded {
            type_: EV_ABS,
            code,
            value,
        }
    }

    #[inline]
    pub fn absolute_x(x: u32) -> EventEncoded {
        Self::absolute(ABS_X, x)
    }

    #[inline]
    pub fn absolute_y(y: u32) -> EventEncoded {
        Self::absolute(ABS_Y, y)
    }

    #[inline]
    pub fn key(code: u16, pressed: bool) -> EventEncoded {
        EventEncoded {
            type_: EV_KEY,
            code,
            value: if pressed { 1 } else { 0 },
        }
    }

    #[inline]
    pub fn from_bytes(v: [u8; 8]) -> EventEncoded {
        EventEncoded {
            type_: u16::from_le_bytes([v[0], v[1]]),
            code: u16::from_le_bytes([v[2], v[3]]),
            value: u32::from_le_bytes([v[4], v[5], v[6], v[7]]),
        }
    }

    #[inline]
    pub fn to_bytes(&self) -> [u8; 8] {
        let a = self.type_.to_le_bytes();
        let b = self.code.to_le_bytes();
        let c = self.value.to_le_bytes();
        [a[0], a[1], b[0], b[1], c[0], c[1], c[2], c[3]]
    }
}

/// Encapsulates a virtual event device, such as a mouse or keyboard
pub struct EventDevice {
    kind: EventDeviceKind,
    event_buffer: VecDeque<u8>,
    event_socket: UnixStream,
}

impl EventDevice {
    pub fn new(kind: EventDeviceKind, event_socket: UnixStream) -> EventDevice {
        let _ = event_socket.set_nonblocking(true);
        EventDevice {
            kind,
            event_buffer: Default::default(),
            event_socket,
        }
    }

    #[inline]
    pub fn mouse(event_socket: UnixStream) -> EventDevice {
        Self::new(EventDeviceKind::Mouse, event_socket)
    }

    #[inline]
    pub fn touchscreen(event_socket: UnixStream) -> EventDevice {
        Self::new(EventDeviceKind::Touchscreen, event_socket)
    }

    #[inline]
    pub fn keyboard(event_socket: UnixStream) -> EventDevice {
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
            let written = self.event_socket.write(&self.event_buffer.as_slices().0)?;
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

    pub fn send_report<E: IntoIterator<Item = EventEncoded>>(
        &mut self,
        events: E,
    ) -> io::Result<bool>
    where
        E::IntoIter: ExactSizeIterator,
    {
        let it = events.into_iter();
        if self.event_buffer.len() > (EVENT_BUFFER_LEN_MAX - EVENT_SIZE * (it.len() + 1)) {
            return Ok(false);
        }

        for event in it {
            let bytes = event.to_bytes();
            self.event_buffer.extend(bytes.iter());
        }

        self.event_buffer
            .extend(EventEncoded::syn().to_bytes().iter());

        self.flush_buffered_events()
    }

    /// Sends the given `event`, returning `Ok(true)` if, after this function returns, there are no
    /// buffered events remaining.
    pub fn send_event_encoded(&mut self, event: EventEncoded) -> io::Result<bool> {
        if !self.flush_buffered_events()? {
            return Ok(false);
        }

        let bytes = event.to_bytes();
        let written = self.event_socket.write(&bytes)?;

        if written == bytes.len() {
            return Ok(true);
        }

        if self.event_buffer.len() <= (EVENT_BUFFER_LEN_MAX - EVENT_SIZE) {
            self.event_buffer.extend(bytes[written..].iter());
        }

        Ok(false)
    }

    pub fn recv_event_encoded(&self) -> io::Result<EventEncoded> {
        let mut event_bytes = [0; 8];
        (&self.event_socket).read_exact(&mut event_bytes)?;
        Ok(EventEncoded::from_bytes(event_bytes))
    }
}

impl AsRawFd for EventDevice {
    fn as_raw_fd(&self) -> RawFd {
        self.event_socket.as_raw_fd()
    }
}
