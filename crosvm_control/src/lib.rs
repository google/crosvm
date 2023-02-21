// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Provides parts of crosvm as a library to communicate with running crosvm instances.
//!
//! This crate is a programmatic alternative to invoking crosvm with subcommands that produce the
//! result on stdout.
//!
//! Downstream projects rely on this library maintaining a stable API surface.
//! Do not make changes to this library without consulting the crosvm externalization team.
//! Email: crosvm-dev@chromium.org
//! For more information see:
//! <https://crosvm.dev/book/running_crosvm/programmatic_interaction.html#usage>

pub use crosvm_control_rust::*;
