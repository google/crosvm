// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;

use base::AsRawDescriptor;
use data_model::VolatileSlice;

use super::super::cross_domain::CrossDomainContext;
use super::super::cross_domain::CrossDomainState;
use super::super::cross_domain_protocol::CrossDomainInit;
use super::super::cross_domain_protocol::CrossDomainSendReceive;
use super::super::cross_domain_protocol::CROSS_DOMAIN_MAX_IDENTIFIERS;
use crate::RutabagaResult;

// SystemStream is never constructed on windows. This is a placeholder to make more code
// multi-platform.
// TODO(b:231309513): Tube with Sync and Send seems like a generic replacement for
// SystemStream, which can be used repo wide.
pub(crate) struct SystemStream {}

impl AsRawDescriptor for SystemStream {
    fn as_raw_descriptor(&self) -> base::RawDescriptor {
        unimplemented!("AsRawDescriptor is not implemented")
    }
}

// Determine type of OS-specific descriptor.
pub(crate) fn descriptor_analysis(
    _descriptor: &mut File,
    _descriptor_type: &mut u32,
    _size: &mut u32,
) -> RutabagaResult<()> {
    unimplemented!("descriptor_analysis not implemented")
}

impl CrossDomainState {
    pub(crate) fn receive_msg(
        &self,
        _opaque_data: &mut [u8],
        _descriptors: &mut [i32; CROSS_DOMAIN_MAX_IDENTIFIERS],
    ) -> RutabagaResult<(usize, Vec<File>)> {
        unimplemented!("receive_msg not implemented")
    }
}

impl CrossDomainContext {
    pub(crate) fn get_connection(
        &mut self,
        _cmd_init: &CrossDomainInit,
    ) -> RutabagaResult<Option<SystemStream>> {
        Ok(None)
    }

    pub(crate) fn send(
        &self,
        _cmd_send: &CrossDomainSendReceive,
        _opaque_data: &[VolatileSlice],
    ) -> RutabagaResult<()> {
        unimplemented!("send not implemented")
    }
}
