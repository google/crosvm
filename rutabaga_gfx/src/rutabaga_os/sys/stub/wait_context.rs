// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::rutabaga_os::WaitEvent;
use crate::rutabaga_os::WaitTrait;
use crate::rutabaga_utils::RutabagaError;
use crate::rutabaga_utils::RutabagaResult;

pub struct Stub(());
pub type WaitContext = Stub;

impl WaitContext {
    pub fn new() -> RutabagaResult<WaitContext> {
        Err(RutabagaError::Unsupported)
    }

    pub fn add<Waitable: WaitTrait>(
        &mut self,
        _connection_id: u64,
        _waitable: Waitable,
    ) -> RutabagaResult<()> {
        Err(RutabagaError::Unsupported)
    }

    pub fn wait(&mut self) -> RutabagaResult<Vec<WaitEvent>> {
        Err(RutabagaError::Unsupported)
    }

    pub fn delete<Waitable: WaitTrait>(&mut self, _waitable: Waitable) -> RutabagaResult<()> {
        Err(RutabagaError::Unsupported)
    }
}
