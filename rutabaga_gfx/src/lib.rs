// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! A crate for handling 2D and 3D virtio-gpu hypercalls, along with graphics
//! swapchain allocation and mapping.

mod cross_domain;
mod generated;
mod gfxstream;
#[macro_use]
mod macros;
#[cfg(any(feature = "gfxstream", feature = "virgl_renderer"))]
mod renderer_utils;
mod rutabaga_2d;
mod rutabaga_core;
mod rutabaga_gralloc;
mod rutabaga_utils;
mod virgl_renderer;

pub use crate::rutabaga_core::{Rutabaga, RutabagaBuilder};
pub use crate::rutabaga_gralloc::{
    DrmFormat, ImageAllocationInfo, ImageMemoryRequirements, RutabagaGralloc, RutabagaGrallocFlags,
};
pub use crate::rutabaga_utils::*;
