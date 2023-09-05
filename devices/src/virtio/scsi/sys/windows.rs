// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::bail;
use anyhow::Context;
use disk::DiskFile;

use crate::virtio::scsi::ScsiOption;

impl ScsiOption {
    pub fn open(&self) -> anyhow::Result<Box<dyn DiskFile>> {
        bail!("ScsiOption::open() is yet to be implemented for windows.")
    }
}
