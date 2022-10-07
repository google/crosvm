// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use serde::Deserialize;
use serde::Serialize;

use crate::gpu::DisplayModeTrait;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnixDisplayMode {
    Windowed(u32, u32),
}

impl DisplayModeTrait for UnixDisplayMode {
    fn get_window_size(&self) -> (u32, u32) {
        match self {
            Self::Windowed(width, height) => (*width, *height),
        }
    }

    fn get_virtual_display_size(&self) -> (u32, u32) {
        self.get_window_size()
    }
}
