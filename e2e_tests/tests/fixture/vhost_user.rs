// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Provides `VhostUserBackend`, a fixture of a vhost-user backend process.

use std::process;
use std::process::Command;
use std::process::Stdio;

use anyhow::Result;

use crate::fixture::utils::find_crosvm_binary;

pub enum CmdType {
    /// `crosvm device` command
    Device,
    /// `crosvm devices` command that is newer and supports sandboxing and multiple device
    /// processes.
    Devices,
}

impl CmdType {
    fn to_subcommand(&self) -> &str {
        match self {
            // `crosvm device`
            CmdType::Device => "device",
            // `crosvm devices`
            CmdType::Devices => "devices",
        }
    }
}

pub struct Config {
    cmd_type: CmdType,
    dev_name: String,
    extra_args: Vec<String>,
}

impl Config {
    pub fn new(cmd_type: CmdType, name: &str) -> Self {
        Config {
            cmd_type,
            dev_name: name.to_string(),
            extra_args: Default::default(),
        }
    }

    /// Uses extra arguments for `crosvm (device|devices)`.
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
        cmd.args([cfg.cmd_type.to_subcommand()]);
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
