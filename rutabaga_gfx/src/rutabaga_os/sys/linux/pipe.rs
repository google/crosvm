// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::os::fd::AsFd;

use nix::unistd::pipe;
use nix::unistd::read;
use nix::unistd::write;

use crate::rutabaga_os::AsBorrowedDescriptor;
use crate::rutabaga_os::AsRawDescriptor;
use crate::rutabaga_os::FromRawDescriptor;
use crate::rutabaga_os::OwnedDescriptor;
use crate::rutabaga_os::RawDescriptor;
use crate::rutabaga_utils::RutabagaResult;

pub struct ReadPipe {
    descriptor: OwnedDescriptor,
}

pub struct WritePipe {
    descriptor: OwnedDescriptor,
}

pub fn create_pipe() -> RutabagaResult<(ReadPipe, WritePipe)> {
    let (read_pipe, write_pipe) = pipe()?;
    Ok((
        ReadPipe {
            descriptor: read_pipe.into(),
        },
        WritePipe {
            descriptor: write_pipe.into(),
        },
    ))
}

impl ReadPipe {
    pub fn read(&self, data: &mut [u8]) -> RutabagaResult<usize> {
        let bytes_read = read(self.descriptor.as_raw_descriptor(), data)?;
        Ok(bytes_read)
    }
}

impl AsBorrowedDescriptor for ReadPipe {
    fn as_borrowed_descriptor(&self) -> &OwnedDescriptor {
        &self.descriptor
    }
}

impl WritePipe {
    pub fn new(descriptor: RawDescriptor) -> WritePipe {
        // SAFETY: Safe because we know the underlying OS descriptor is valid and
        // owned by us.
        let owned = unsafe { OwnedDescriptor::from_raw_descriptor(descriptor) };
        WritePipe { descriptor: owned }
    }

    pub fn write(&self, data: &[u8]) -> RutabagaResult<usize> {
        let bytes_written = write(self.descriptor.as_fd(), data)?;
        Ok(bytes_written)
    }
}

impl AsBorrowedDescriptor for WritePipe {
    fn as_borrowed_descriptor(&self) -> &OwnedDescriptor {
        &self.descriptor
    }
}

impl AsRawDescriptor for WritePipe {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.descriptor.as_raw_descriptor()
    }
}
