// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Software TPM backend using the TPM2 simulator from the `tpm2` crate.

use std::env;
use std::fs;
use std::path::Path;

use anyhow::Context;
use tpm2::Simulator;

use super::virtio::TpmBackend;

pub struct SoftwareTpm {
    simulator: Simulator,
}

impl SoftwareTpm {
    pub fn new<P: AsRef<Path>>(storage: P) -> anyhow::Result<Self> {
        fs::create_dir_all(storage.as_ref()).context("failed to create directory for simulator")?;
        env::set_current_dir(storage).context("failed to change into simulator directory")?;
        let simulator = Simulator::singleton_in_current_directory();
        Ok(SoftwareTpm { simulator })
    }
}

impl TpmBackend for SoftwareTpm {
    fn execute_command<'a>(&'a mut self, command: &[u8]) -> &'a [u8] {
        self.simulator.execute_command(command)
    }
}
