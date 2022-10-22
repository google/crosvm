// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! The root level module that includes the config and aggregate of the submodules for running said
//! configs.

pub mod cmdline;
pub mod config;
#[cfg(all(any(target_arch = "x86_64", target_arch = "aarch64"), feature = "gdb"))]
pub mod gdb;
#[cfg(feature = "gpu")]
mod gpu_config;
#[cfg(feature = "plugin")]
pub mod plugin;
pub mod sys;

pub mod argument;

#[cfg(all(
    not(any(target_arch = "x86_64", target_arch = "aarch64")),
    feature = "gdb"
))]
compile_error!("gdb feature is supported only on x86_64 and aarch64");
