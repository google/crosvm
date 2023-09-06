// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use base::AsRawDescriptor;
use base::RawDescriptor;

use super::Error;
use super::Result;
use super::Vhost;

/// Handle for running VHOST_SCMI ioctls.
pub struct Scmi {
    descriptor: File,
}

impl Scmi {
    /// Open a handle to a new VHOST_SCMI instance.
    pub fn new(vhost_scmi_device_path: &Path) -> Result<Scmi> {
        Ok(Scmi {
            descriptor: OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
                .open(vhost_scmi_device_path)
                .map_err(Error::VhostOpen)?,
        })
    }
}

impl Vhost for Scmi {}

impl AsRawDescriptor for Scmi {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.descriptor.as_raw_descriptor()
    }
}
