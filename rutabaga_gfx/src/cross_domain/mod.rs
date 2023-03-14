// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod cross_domain;
mod cross_domain_protocol;
mod sys;

#[allow(dead_code)]
const WAIT_CONTEXT_MAX: usize = 16;

pub struct CrossDomainEvent {
    token: CrossDomainToken,
    hung_up: bool,
    readable: bool,
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum CrossDomainToken {
    ContextChannel,
    WaylandReadPipe(u32),
    Resample,
    Kill,
}

pub use cross_domain::CrossDomain;
