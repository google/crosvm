// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! A crate for handling 2D and 3D virtio-gpu hypercalls.

mod generated;
mod gfxstream;
mod renderer_utils;
mod rutabaga_2d;
mod rutabaga_core;
mod rutabaga_utils;
mod virgl_renderer;

pub use crate::rutabaga_core::{Rutabaga, RutabagaBuilder};
pub use crate::rutabaga_utils::*;
