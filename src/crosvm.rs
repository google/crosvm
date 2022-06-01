// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! The root level module that includes the config and aggregate of the submodules for running said
//! configs.

pub mod cmdline;
pub mod config;
#[cfg(all(target_arch = "x86_64", feature = "gdb"))]
pub mod gdb;
#[path = "crosvm/linux/mod.rs"]
pub mod platform;
#[cfg(feature = "plugin")]
pub mod plugin;
pub mod sys;

pub mod argument;

macro_rules! check_opt_path {
    ($struct:ident.$field:ident) => {
        if let Some(p) = &$struct.$field {
            if !p.exists() {
                return Err(format!(
                    "{} path {:?} does not exist",
                    stringify!($field),
                    p
                ));
            }
        }
    };
}

pub(crate) use check_opt_path;
