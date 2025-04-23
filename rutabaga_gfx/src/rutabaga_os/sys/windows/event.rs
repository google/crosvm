// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::convert::From;
use std::convert::TryFrom;

use crate::rutabaga_os::AsBorrowedDescriptor;
use crate::rutabaga_os::OwnedDescriptor;
use crate::rutabaga_utils::RutabagaError;
use crate::rutabaga_utils::RutabagaErrorKind;
use crate::rutabaga_utils::RutabagaHandle;
use crate::rutabaga_utils::RutabagaResult;

pub struct Event(());

impl Event {
    pub fn new() -> RutabagaResult<Event> {
        Err(RutabagaErrorKind::Unsupported.into())
    }

    pub fn signal(&mut self) -> RutabagaResult<()> {
        Err(RutabagaErrorKind::Unsupported.into())
    }

    pub fn wait(&self) -> RutabagaResult<()> {
        Err(RutabagaErrorKind::Unsupported.into())
    }

    pub fn try_clone(&self) -> RutabagaResult<Event> {
        Err(RutabagaErrorKind::Unsupported.into())
    }
}

impl TryFrom<RutabagaHandle> for Event {
    type Error = RutabagaError;
    fn try_from(_handle: RutabagaHandle) -> Result<Self, Self::Error> {
        Err(RutabagaErrorKind::Unsupported.into())
    }
}

impl From<Event> for RutabagaHandle {
    fn from(_evt: Event) -> Self {
        unimplemented!()
    }
}

impl AsBorrowedDescriptor for Event {
    fn as_borrowed_descriptor(&self) -> &OwnedDescriptor {
        unimplemented!()
    }
}
