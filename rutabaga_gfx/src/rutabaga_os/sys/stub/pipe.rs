// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::rutabaga_os::AsBorrowedDescriptor;
use crate::rutabaga_os::AsRawDescriptor;
use crate::rutabaga_os::OwnedDescriptor;
use crate::rutabaga_os::RawDescriptor;
use crate::rutabaga_utils::RutabagaErrorKind;
use crate::rutabaga_utils::RutabagaResult;

pub struct ReadPipeStub(());
pub struct WritePipeStub(());

pub type ReadPipe = ReadPipeStub;
pub type WritePipe = WritePipeStub;

pub fn create_pipe() -> RutabagaResult<(ReadPipe, WritePipe)> {
    Err(RutabagaErrorKind::Unsupported.into())
}

impl ReadPipe {
    pub fn read(&self, _data: &mut [u8]) -> RutabagaResult<usize> {
        Err(RutabagaErrorKind::Unsupported.into())
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

    pub fn write(&self, _data: &[u8]) -> RutabagaResult<usize> {
        Err(RutabagaErrorKind::Unsupported.into())
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
