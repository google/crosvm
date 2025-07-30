// Copyright 2025 Google
// SPDX-License-Identifier: MIT

use crate::AsBorrowedDescriptor;
use crate::MesaError;
use crate::MesaHandle;
use crate::MesaResult;
use crate::OwnedDescriptor;

pub struct Event;

impl Event {
    pub fn new() -> MesaResult<Event> {
        Err(MesaError::Unsupported)
    }

    pub fn signal(&mut self) -> MesaResult<()> {
        Err(MesaError::Unsupported)
    }

    pub fn wait(&self) -> MesaResult<()> {
        Err(MesaError::Unsupported)
    }

    pub fn try_clone(&self) -> MesaResult<Event> {
        Err(MesaError::Unsupported)
    }
}

impl TryFrom<MesaHandle> for Event {
    type Error = MesaError;
    fn try_from(_handle: MesaHandle) -> Result<Self, Self::Error> {
        Err(MesaError::Unsupported)
    }
}

impl From<Event> for MesaHandle {
    fn from(_evt: Event) -> Self {
        unimplemented!()
    }
}

impl AsBorrowedDescriptor for Event {
    fn as_borrowed_descriptor(&self) -> &OwnedDescriptor {
        unimplemented!()
    }
}
