// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::rutabaga_os::OwnedDescriptor;
use crate::rutabaga_os::WaitEvent;
use crate::rutabaga_os::WaitTimeout;
use crate::rutabaga_utils::RutabagaError;
use crate::rutabaga_utils::RutabagaResult;

pub struct Stub(());
pub type WaitContext = Stub;

impl WaitContext {
    pub fn new() -> RutabagaResult<WaitContext> {
        Err(RutabagaError::Unsupported)
    }

    pub fn add(
        &mut self,
        _connection_id: u64,
        _descriptor: &OwnedDescriptor,
    ) -> RutabagaResult<()> {
        Err(RutabagaError::Unsupported)
    }

    pub fn wait(&mut self, _timeout: WaitTimeout) -> RutabagaResult<Vec<WaitEvent>> {
        Err(RutabagaError::Unsupported)
    }

    pub fn delete(&mut self, _descriptor: &OwnedDescriptor) -> RutabagaResult<()> {
        Err(RutabagaError::Unsupported)
    }
}
