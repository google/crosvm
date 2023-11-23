// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use euclid::Box2D;
use euclid::Size2D;
use euclid::Transform2D;

use super::HostWindowSpace;
use super::VirtualDisplaySpace;

type HostWindowSize = Size2D<i32, HostWindowSpace>;
type VirtualDisplaySize = Size2D<i32, VirtualDisplaySpace>;
type HostToGuestTransform = Transform2D<f64, HostWindowSpace, VirtualDisplaySpace>;

/// This struct is managing the host window to guest display coordinates transform.
pub struct NoopVirtualDisplayManager {
    host_to_guest_transform: HostToGuestTransform,
}

impl NoopVirtualDisplayManager {
    pub fn new(
        _host_viewport_size: &HostWindowSize,
        _virtual_display_size: &VirtualDisplaySize,
    ) -> Self {
        Self {
            host_to_guest_transform: Default::default(),
        }
    }

    /// Returns the rectangle to show the virtual display in the host window coordinate.
    pub fn get_virtual_display_projection_box(&self) -> Box2D<i32, HostWindowSpace> {
        Default::default()
    }

    pub fn update_host_guest_transforms(&mut self, _host_viewport_size: &HostWindowSize) {}

    pub fn get_host_to_guest_transform(&self) -> &HostToGuestTransform {
        &self.host_to_guest_transform
    }
}
