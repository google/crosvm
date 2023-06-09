// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(windows)]
use std::thread;

#[cfg(windows)]
use base::ProtoTube;
#[cfg(windows)]
use base::Tube;

pub fn setup_common_metric_invariants(
    _product_version: &Option<String>,
    _product_channel: &Option<String>,
    _use_vulkan: &Option<bool>,
) {
}

pub fn enable_vcpu_monitoring() -> bool {
    false
}

// This is a hard limit as it is used to set the Tube buffer size, and will
// deadlock if exceeded (b/223807352).
pub const MAX_CHALLENGE_SIZE: usize = 1;

#[cfg(windows)]
pub fn forward_security_challenge(_recv: &ProtoTube, _sender: &ProtoTube) {}
#[cfg(windows)]
pub fn forward_security_signal(_recv: &ProtoTube, _sender: &Tube) {}

pub struct SecurityContextWrapper {}
pub fn initialize_security_for_emulator() -> SecurityContextWrapper {
    SecurityContextWrapper {}
}

#[cfg(windows)]
pub fn spawn_dedicated_anti_tamper_thread(
    _security_context: SecurityContextWrapper,
    _tube_to_main_thread: base::ProtoTube,
) -> thread::JoinHandle<()> {
    thread::spawn(move || ())
}
