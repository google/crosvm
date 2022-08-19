// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use bitflags::bitflags;

use crate::constants;

bitflags! {
    /// Gives the driver a hint of intended usage to optimize allocation (e.g. tiling).
    pub struct UsageHint: u32 {
        /// Surface usage not indicated.
        const USAGE_HINT_GENERIC = constants::VA_SURFACE_ATTRIB_USAGE_HINT_GENERIC;
        /// Surface used by video decoder.
        const USAGE_HINT_DECODER = constants::VA_SURFACE_ATTRIB_USAGE_HINT_DECODER;
        /// Surface used by video encoder.
        const USAGE_HINT_ENCODER = constants::VA_SURFACE_ATTRIB_USAGE_HINT_ENCODER;
        /// Surface read by video post-processing.
        const USAGE_HINT_VPP_READ = constants::VA_SURFACE_ATTRIB_USAGE_HINT_VPP_READ;
        /// Surface written by video post-processing.
        const USAGE_HINT_VPP_WRITE = constants::VA_SURFACE_ATTRIB_USAGE_HINT_VPP_WRITE;
        /// Surface used for display.
        const USAGE_HINT_DISPLAY = constants::VA_SURFACE_ATTRIB_USAGE_HINT_DISPLAY;
        /// Surface used for export to third-party APIs, e.g. via `vaExportSurfaceHandle()`.
        const USAGE_HINT_EXPORT = constants::VA_SURFACE_ATTRIB_USAGE_HINT_EXPORT;
    }
}
