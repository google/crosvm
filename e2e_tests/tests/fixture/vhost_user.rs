// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Provides `VhostUserBackend`, a fixture of a vhost-user backend process.

use std::process;
use std::process::Command;
use std::process::Stdio;

use anyhow::Result;

use crate::fixture::utils::find_crosvm_binary;

#[derive(Default)]
pub struct Config {
    dev_name: String,

    extra_args: Vec<String>,
}

impl Config {
    pub fn new(name: &str) -> Self {
        Config {
            dev_name: name.to_string(),
            ..Default::default()
        }
    }

    /// Uses extra arguments for `crosvm devices $dev_name`.
    pub fn extra_args(mut self, args: Vec<String>) -> Self {
        self.extra_args = args;
        self
    }
}

#[derive(Default)]
pub struct VhostUserBackend {
    name: String,
    process: Option<process::Child>,
}

impl VhostUserBackend {
    pub fn new(cfg: Config) -> Result<Self> {
        let mut cmd = Command::new(find_crosvm_binary());
        cmd.args(&["device", &cfg.dev_name]);
        cmd.args(cfg.extra_args);

        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        println!("$ {:?}", cmd);

        let process = Some(cmd.spawn()?);

        Ok(Self {
            name: cfg.dev_name,
            process,
        })
    }
}

impl Drop for VhostUserBackend {
    fn drop(&mut self) {
        let output = self.process.take().unwrap().wait_with_output().unwrap();

        // Print both the crosvm's stdout/stderr to stdout so that they'll be shown when the test
        // is failed.
        println!(
            "VhostUserBackend {} stdout:\n{}",
            self.name,
            std::str::from_utf8(&output.stdout).unwrap()
        );
        println!(
            "VhostUserBackend {} stderr:\n{}",
            self.name,
            std::str::from_utf8(&output.stderr).unwrap()
        );

        if !output.status.success() {
            panic!(
                "VhostUserBackend {} exited illegally: {}",
                self.name, output.status
            );
        }
    }
}
