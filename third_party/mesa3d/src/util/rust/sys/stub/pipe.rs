// Copyright 2025 Google
// SPDX-License-Identifier: MIT

use crate::AsBorrowedDescriptor;
use crate::AsRawDescriptor;
use crate::MesaError;
use crate::MesaResult;
use crate::OwnedDescriptor;
use crate::RawDescriptor;

pub struct ReadPipe;
pub struct WritePipe;

pub fn create_pipe() -> MesaResult<(ReadPipe, WritePipe)> {
    Err(MesaError::Unsupported)
}

impl ReadPipe {
    pub fn read(&self, _data: &mut [u8]) -> MesaResult<usize> {
        Err(MesaError::Unsupported)
    }
}

impl AsBorrowedDescriptor for ReadPipe {
    fn as_borrowed_descriptor(&self) -> &OwnedDescriptor {
        unimplemented!()
    }
}

impl WritePipe {
    pub fn new(_descriptor: RawDescriptor) -> WritePipe {
        unimplemented!()
    }

    pub fn write(&self, _data: &[u8]) -> MesaResult<usize> {
        Err(MesaError::Unsupported)
    }
}

impl AsBorrowedDescriptor for WritePipe {
    fn as_borrowed_descriptor(&self) -> &OwnedDescriptor {
        unimplemented!()
    }
}

impl AsRawDescriptor for WritePipe {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        unimplemented!()
    }
}
