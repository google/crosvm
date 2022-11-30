// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::convert::TryFrom;
use std::result::Result as StdResult;
use std::slice::Iter;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use anyhow::anyhow;
use anyhow::Error as AnyError;
use anyhow::Result as AnyResult;
use serde::Deserialize;
use serde::Serialize;

#[derive(PartialEq, Eq, Clone, Copy, Serialize, Deserialize, Debug)]
pub enum WindowVisibility {
    Hidden,
    Minimized,
    Normal,
}

#[derive(PartialEq, Eq, Clone, Copy, Serialize, Deserialize, Debug)]
pub enum WindowMode {
    Unknown,
    Fullscreen,
    Windowed,
}

#[derive(PartialEq, Eq, Clone, Copy, Serialize, Deserialize, Debug)]
pub enum MouseMode {
    Unknown,
    Touchscreen,
    Relative,
}

impl WindowMode {
    pub fn clone_or_default(&self, default: Self) -> Self {
        match *self {
            Self::Unknown => default,
            _ => *self,
        }
    }

    pub fn next_mode(&self) -> AnyResult<Self> {
        match *self {
            Self::Unknown => Err(anyhow!("No next mode for {:?}", self)),
            Self::Fullscreen => Ok(Self::Windowed),
            Self::Windowed => Ok(Self::Fullscreen),
        }
    }
}

#[derive(PartialEq, Eq, Clone, Copy, Serialize, Deserialize, Debug)]
pub enum AspectRatio {
    Unknown,
    W16H9,
    W16H10,
    W3H2,
    W9H16,
}

impl AspectRatio {
    pub fn known_ratios_iter() -> Iter<'static, Self> {
        static KNOWN_RATIOS: [AspectRatio; 4] = [
            AspectRatio::W16H9,
            AspectRatio::W16H10,
            AspectRatio::W3H2,
            AspectRatio::W9H16,
        ];
        KNOWN_RATIOS.iter()
    }
}

impl TryFrom<AspectRatio> for f32 {
    type Error = AnyError;
    fn try_from(value: AspectRatio) -> StdResult<Self, Self::Error> {
        match value {
            AspectRatio::Unknown => Err(anyhow!("Cannot convert {:?} to f32", value)),
            AspectRatio::W16H9 => Ok(16.0 / 9.0),
            AspectRatio::W16H10 => Ok(16.0 / 10.0),
            AspectRatio::W3H2 => Ok(3.0 / 2.0),
            AspectRatio::W9H16 => Ok(9.0 / 16.0),
        }
    }
}

impl TryFrom<f32> for AspectRatio {
    type Error = AnyError;
    fn try_from(value: f32) -> StdResult<Self, Self::Error> {
        // To account for rounding errors, we allow the actual aspect ratio to differ from
        // expectation by at most 0.01.
        const EPSILON: f32 = 1e-2;
        for aspect_ratio in Self::known_ratios_iter() {
            if (value - f32::try_from(*aspect_ratio).unwrap()).abs() < EPSILON {
                return Ok(*aspect_ratio);
            }
        }
        Err(anyhow!(
            "Cannot convert {:.3} to any aspect ratio enum",
            value
        ))
    }
}

#[derive(PartialEq, Eq, Clone, Copy, Serialize, Deserialize, Debug)]
pub struct DisplaySize {
    pub width: i32,
    pub height: i32,
}

impl DisplaySize {
    pub fn new(width: i32, height: i32) -> Self {
        Self { width, height }
    }

    pub fn shorter_edge(&self) -> i32 {
        std::cmp::min(self.width, self.height)
    }
}

#[derive(PartialEq, Eq, Clone, Copy, Serialize, Deserialize, Debug)]
pub struct GuestDisplayDensity {
    pub static_landscape_dpi: i32,
    pub static_portrait_dpi: i32,
    pub dynamic_dpi: Option<i32>,
}

#[derive(PartialEq, Eq, Clone, Copy, Serialize, Deserialize, Debug)]
pub enum WindowEventCode {
    Unspecified,
    DisplaySettingsChange,
}

#[derive(PartialEq, Eq, Clone, Copy, Serialize, Deserialize, Debug)]
pub struct WindowEvent {
    pub event_code: WindowEventCode,
    pub report_timestamp_ms: i64,
}

impl WindowEvent {
    pub fn new(event_code: WindowEventCode) -> Self {
        Self {
            event_code,
            report_timestamp_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64,
        }
    }
}
