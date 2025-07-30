// Copyright 2025 Google
// SPDX-License-Identifier: MIT

use crate::MesaError;
use crate::MesaResult;
use crate::OwnedDescriptor;
use crate::WaitEvent;
use crate::WaitTimeout;

pub struct WaitContext;

impl WaitContext {
    pub fn new() -> MesaResult<WaitContext> {
        Err(MesaError::Unsupported)
    }

    pub fn add(&mut self, _connection_id: u64, _descriptor: &OwnedDescriptor) -> MesaResult<()> {
        Err(MesaError::Unsupported)
    }

    pub fn wait(&mut self, _timeout: WaitTimeout) -> MesaResult<Vec<WaitEvent>> {
        Err(MesaError::Unsupported)
    }

    pub fn delete(&mut self, _descriptor: &OwnedDescriptor) -> MesaResult<()> {
        Err(MesaError::Unsupported)
    }
}
