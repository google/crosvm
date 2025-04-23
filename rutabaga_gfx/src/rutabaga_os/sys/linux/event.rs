// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::convert::From;
use std::convert::TryFrom;
use std::os::fd::OwnedFd;

use nix::sys::eventfd::EfdFlags;
use nix::sys::eventfd::EventFd;
use nix::unistd::read;
use nix::unistd::write;

use crate::rutabaga_os::AsBorrowedDescriptor;
use crate::rutabaga_os::AsRawDescriptor;
use crate::rutabaga_os::OwnedDescriptor;
use crate::rutabaga_utils::RutabagaError;
use crate::rutabaga_utils::RutabagaErrorKind;
use crate::rutabaga_utils::RutabagaHandle;
use crate::rutabaga_utils::RutabagaResult;
use crate::rutabaga_utils::RUTABAGA_HANDLE_TYPE_SIGNAL_EVENT_FD;

pub struct Event {
    descriptor: OwnedDescriptor,
}

impl Event {
    pub fn new() -> RutabagaResult<Event> {
        let owned: OwnedFd = EventFd::from_flags(EfdFlags::empty())?.into();
        Ok(Event {
            descriptor: owned.into(),
        })
    }

    pub fn signal(&mut self) -> RutabagaResult<()> {
        let _ = write(&self.descriptor, &1u64.to_ne_bytes())?;
        Ok(())
    }

    pub fn wait(&self) -> RutabagaResult<()> {
        read(self.descriptor.as_raw_descriptor(), &mut 1u64.to_ne_bytes())?;
        Ok(())
    }

    pub fn try_clone(&self) -> RutabagaResult<Event> {
        let clone = self.descriptor.try_clone()?;
        Ok(Event { descriptor: clone })
    }
}

impl TryFrom<RutabagaHandle> for Event {
    type Error = RutabagaError;
    fn try_from(handle: RutabagaHandle) -> Result<Self, Self::Error> {
        if handle.handle_type != RUTABAGA_HANDLE_TYPE_SIGNAL_EVENT_FD {
            return Err(RutabagaErrorKind::InvalidRutabagaHandle.into());
        }

        Ok(Event {
            descriptor: handle.os_handle,
        })
    }
}

impl From<Event> for RutabagaHandle {
    fn from(evt: Event) -> Self {
        RutabagaHandle {
            os_handle: evt.descriptor,
            handle_type: RUTABAGA_HANDLE_TYPE_SIGNAL_EVENT_FD,
        }
    }
}

impl AsBorrowedDescriptor for Event {
    fn as_borrowed_descriptor(&self) -> &OwnedDescriptor {
        &self.descriptor
    }
}
