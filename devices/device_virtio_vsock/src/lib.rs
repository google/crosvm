// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This module implements the virtio vsock device.
//!
//! Currently, this is only implemented for Windows.
//! For Linux, please use the vhost-vsock device, which delegates the vsock
//! implementation to the kernel.

mod sys;
#[cfg(any(target_os = "android", target_os = "linux"))]
pub mod vhost;

pub use sys::VirtioVsockModule;
pub use sys::Vsock;
pub use sys::VsockConfig;
