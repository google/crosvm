// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use argh::FromArgs;

#[derive(Debug, FromArgs)]
#[argh(subcommand)]
/// macOS Devices
pub enum DeviceSubcommand {}

#[derive(FromArgs)]
#[argh(subcommand)]
/// macOS-specific commands
pub enum Commands {}
