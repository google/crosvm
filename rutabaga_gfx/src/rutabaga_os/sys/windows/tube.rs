// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::path::Path;

use crate::rutabaga_os::AsBorrowedDescriptor;
use crate::rutabaga_os::OwnedDescriptor;
use crate::rutabaga_os::RawDescriptor;
use crate::rutabaga_os::TubeType;
use crate::rutabaga_utils::RutabagaErrorKind;
use crate::rutabaga_utils::RutabagaResult;

pub struct Stub(());
pub type Tube = Stub;
pub type Listener = Stub;

impl Tube {
    pub fn new<P: AsRef<Path>>(_path: P, _kind: TubeType) -> RutabagaResult<Tube> {
        Err(RutabagaErrorKind::Unsupported.into())
    }

    pub fn send(
        &self,
        _opaque_data: &[u8],
        _descriptors: &[RawDescriptor],
    ) -> RutabagaResult<usize> {
        Err(RutabagaErrorKind::Unsupported.into())
    }

    pub fn receive(
        &self,
        _opaque_data: &mut [u8],
    ) -> RutabagaResult<(usize, Vec<OwnedDescriptor>)> {
        Err(RutabagaErrorKind::Unsupported.into())
    }
}

impl AsBorrowedDescriptor for Tube {
    fn as_borrowed_descriptor(&self) -> &OwnedDescriptor {
        unimplemented!()
    }
}

impl Listener {
    /// Creates a new `Listener` bound to the given path.
    pub fn bind<P: AsRef<Path>>(_path: P) -> RutabagaResult<Listener> {
        Err(RutabagaErrorKind::Unsupported.into())
    }

    pub fn accept(&self) -> RutabagaResult<Tube> {
        Err(RutabagaErrorKind::Unsupported.into())
    }
}
