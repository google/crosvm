// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;

use crate::ProtectionType;
use base::{Event, RawDescriptor};

/// Abstraction over serial-like devices that can be created given an event and optional input and
/// output streams.
pub trait SerialDevice {
    fn new(
        protected_vm: ProtectionType,
        interrupt_evt: Event,
        input: Option<Box<dyn io::Read + Send>>,
        output: Option<Box<dyn io::Write + Send>>,
        keep_rds: Vec<RawDescriptor>,
    ) -> Self;
}
