// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::convert::From;
use std::convert::TryFrom;
use std::fs::File;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::fd::OwnedFd;

use nix::sys::eventfd::EfdFlags;
use nix::sys::eventfd::EventFd;
use nix::unistd::read;

use crate::rutabaga_os::FromRawDescriptor;
use crate::rutabaga_os::IntoRawDescriptor;
use crate::rutabaga_os::OwnedDescriptor;
use crate::rutabaga_utils::RutabagaError;
use crate::rutabaga_utils::RutabagaHandle;
use crate::rutabaga_utils::RutabagaResult;
use crate::rutabaga_utils::RUTABAGA_FENCE_HANDLE_TYPE_EVENT_FD;

pub struct Event {
    file: File,
}

impl Event {
    pub fn new() -> RutabagaResult<Event> {
        let owned: OwnedFd = EventFd::from_flags(EfdFlags::empty())?.into();
        Ok(Event { file: owned.into() })
    }

    pub fn signal(&mut self) -> RutabagaResult<()> {
        let _ = self.file.write(&1u64.to_ne_bytes())?;
        Ok(())
    }

    pub fn wait(&self) -> RutabagaResult<()> {
        read(self.file.as_raw_fd(), &mut 1u64.to_ne_bytes())?;
        Ok(())
    }

    pub fn try_clone(&self) -> RutabagaResult<Event> {
        let clone = self.file.try_clone()?;
        Ok(Event { file: clone })
    }
}

impl TryFrom<RutabagaHandle> for Event {
    type Error = RutabagaError;
    fn try_from(handle: RutabagaHandle) -> Result<Self, Self::Error> {
        if handle.handle_type != RUTABAGA_FENCE_HANDLE_TYPE_EVENT_FD {
            return Err(RutabagaError::InvalidRutabagaHandle);
        }

        // SAFETY: Safe because the handle is valid and owned by us.
        let file = unsafe { File::from_raw_descriptor(handle.os_handle.into_raw_descriptor()) };
        Ok(Event { file })
    }
}

impl From<Event> for RutabagaHandle {
    fn from(evt: Event) -> Self {
        RutabagaHandle {
            // SAFETY: Safe because the file is valid and owned by us.
            os_handle: unsafe {
                OwnedDescriptor::from_raw_descriptor(evt.file.into_raw_descriptor())
            },
            handle_type: RUTABAGA_FENCE_HANDLE_TYPE_EVENT_FD,
        }
    }
}
