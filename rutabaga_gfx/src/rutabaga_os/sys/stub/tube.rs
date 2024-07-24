// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::path::Path;

use crate::rutabaga_os::RawDescriptor;
use crate::rutabaga_os::WaitTrait;
use crate::rutabaga_utils::RutabagaError;
use crate::rutabaga_utils::RutabagaResult;

pub struct Stub(());
pub type Tube = Stub;
pub type Listener = Stub;

impl Tube {
    pub fn new<P: AsRef<Path>>(_path: P) -> RutabagaResult<Tube> {
        Err(RutabagaError::Unsupported)
    }

    pub fn send(
        &self,
        _opaque_data: &[u8],
        _descriptors: &[RawDescriptor],
    ) -> RutabagaResult<usize> {
        Err(RutabagaError::Unsupported)
    }

    pub fn receive(&self, _opaque_data: &mut [u8]) -> RutabagaResult<(usize, Vec<File>)> {
        Err(RutabagaError::Unsupported)
    }
}

impl WaitTrait for Tube {}
impl WaitTrait for &Tube {}

impl Listener {
    /// Creates a new `Listener` bound to the given path.
    pub fn bind<P: AsRef<Path>>(_path: P) -> RutabagaResult<Listener> {
        Err(RutabagaError::Unsupported)
    }

    pub fn accept(&self) -> RutabagaResult<Tube> {
        Err(RutabagaError::Unsupported)
    }
}
