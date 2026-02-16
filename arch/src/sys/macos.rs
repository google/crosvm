// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use devices::IommuDevType;

/// Platform bus resources for macOS.
/// Mirrors the Linux version but without VFIO support.
pub struct PlatformBusResources {
    pub dt_symbol: String,
    pub regions: Vec<(u64, u64)>,
    pub irqs: Vec<(u32, u32)>,
    pub iommus: Vec<(IommuDevType, Option<u32>, Vec<u32>)>,
    pub requires_power_domain: bool,
}
