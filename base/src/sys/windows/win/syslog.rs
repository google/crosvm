// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implementation of the Syslog trait as a wrapper around Window's events

use super::super::{
    syslog::{Error, Facility, Priority, Syslog},
    RawDescriptor,
};

pub struct PlatformSyslog {
    enabled: bool,
}

impl Syslog for PlatformSyslog {
    fn new() -> Result<Self, Error> {
        Ok(Self { enabled: true })
    }

    fn enable(&mut self, enable: bool) -> Result<(), Error> {
        self.enabled = enable;
        Ok(())
    }

    fn push_descriptors(&self, _fds: &mut Vec<RawDescriptor>) {}

    fn log(
        &self,
        _proc_name: Option<&str>,
        _pri: Priority,
        _fac: Facility,
        _file_line: Option<(&str, u32)>,
        _args: std::fmt::Arguments,
    ) {
        // do nothing. We don't plan to support writing to windows system logs.
    }
}
