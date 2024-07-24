// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;

use super::super::cross_domain_protocol::CrossDomainSendReceive;
use super::super::CrossDomainContext;
use crate::rutabaga_os::WaitTrait;
use crate::rutabaga_utils::RutabagaError;
use crate::rutabaga_utils::RutabagaResult;

pub struct Stub(());

// Determine type of OS-specific descriptor.
pub fn descriptor_analysis(
    _descriptor: &mut File,
    _descriptor_type: &mut u32,
    _size: &mut u32,
) -> RutabagaResult<()> {
    Err(RutabagaError::Unsupported)
}

impl CrossDomainContext {
    pub(crate) fn send(
        &self,
        _cmd_send: &CrossDomainSendReceive,
        _opaque_data: &[u8],
    ) -> RutabagaResult<()> {
        Err(RutabagaError::Unsupported)
    }
}

pub type Sender = Stub;
pub type Receiver = Stub;

impl WaitTrait for Stub {}
impl WaitTrait for &Stub {}
impl WaitTrait for File {}
impl WaitTrait for &File {}
impl WaitTrait for &mut File {}

pub fn channel_signal(_sender: &Sender) -> RutabagaResult<()> {
    Err(RutabagaError::Unsupported)
}

pub fn channel_wait(_receiver: &Receiver) -> RutabagaResult<()> {
    Err(RutabagaError::Unsupported)
}

pub fn read_volatile(_file: &File, _opaque_data: &mut [u8]) -> RutabagaResult<usize> {
    Err(RutabagaError::Unsupported)
}

pub fn write_volatile(_file: &File, _opaque_data: &[u8]) -> RutabagaResult<()> {
    Err(RutabagaError::Unsupported)
}

pub fn channel() -> RutabagaResult<(Sender, Receiver)> {
    Err(RutabagaError::Unsupported)
}
