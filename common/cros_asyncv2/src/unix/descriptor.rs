// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;

use sys_util::SafeDescriptor;

use super::io_driver;

/// An async version of SafeDescriptor.
// TODO: Remove this once we have converted all users to use the appropriate concrete async types.
pub struct Descriptor(Arc<SafeDescriptor>);

impl Descriptor {
    /// Creates a new `AsyncDescriptor` in a nonblocking state.
    pub fn new(fd: SafeDescriptor) -> anyhow::Result<Descriptor> {
        io_driver::prepare(&fd)?;
        Ok(Descriptor(Arc::new(fd)))
    }

    /// Waits for `self` to become readable. This function is edge-triggered rather than
    /// level-triggered so callers should make sure that the underlying descriptor has been fully
    /// drained before calling this method.
    pub async fn wait_readable(&self) -> anyhow::Result<()> {
        io_driver::wait_readable(&self.0).await
    }

    /// Waits for `self` to become writable. This function is edge-triggered rather than
    /// level-triggered so callers should make sure that the underlying descriptor is actually full
    /// before calling this method.
    pub async fn wait_writable(&self) -> anyhow::Result<()> {
        io_driver::wait_writable(&self.0).await
    }
}
