// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use serde::Deserialize;
use serde::Serialize;

use crate::virtio::gpu::parameters::DisplayModeTrait;

// This struct is only used for argument parsing.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnixDisplayModeArg {
    Windowed,
}

#[derive(Clone, Debug)]
pub enum UnixDisplayMode {
    Windowed { width: u32, height: u32 },
}

impl DisplayModeTrait for UnixDisplayMode {
    fn get_virtual_display_size(&self) -> (u32, u32) {
        match self {
            Self::Windowed { width, height, .. } => (*width, *height),
        }
    }
}
