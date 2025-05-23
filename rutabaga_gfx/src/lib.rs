// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! A crate for handling 2D and 3D virtio-gpu hypercalls, along with graphics
//! swapchain allocation and mapping.

mod cross_domain;
mod generated;
mod gfxstream;
mod gfxstream_stub;
#[macro_use]
mod macros;
#[cfg(any(feature = "gfxstream", feature = "virgl_renderer"))]
mod renderer_utils;
mod rutabaga_2d;
mod rutabaga_core;
mod rutabaga_gralloc;
mod rutabaga_utils;
mod snapshot;
mod virgl_renderer;

pub use mesa3d_util::FromRawDescriptor as RutabagaFromRawDescriptor;
pub use mesa3d_util::IntoRawDescriptor as RutabagaIntoRawDescriptor;
pub use mesa3d_util::MappedRegion as RutabagaMappedRegion;
pub use mesa3d_util::MesaError::Unsupported as RutabagaUnsupported;
pub use mesa3d_util::MesaHandle as RutabagaHandle;
pub use mesa3d_util::OwnedDescriptor as RutabagaDescriptor;
pub use mesa3d_util::RawDescriptor as RutabagaRawDescriptor;
pub use mesa3d_util::MESA_HANDLE_TYPE_MEM_DMABUF as RUTABAGA_HANDLE_TYPE_MEM_DMABUF;
pub use mesa3d_util::MESA_HANDLE_TYPE_MEM_OPAQUE_FD as RUTABAGA_HANDLE_TYPE_MEM_OPAQUE_FD;

pub use crate::rutabaga_core::calculate_capset_mask;
pub use crate::rutabaga_core::calculate_capset_names;
pub use crate::rutabaga_core::Rutabaga;
pub use crate::rutabaga_core::RutabagaBuilder;
pub use crate::rutabaga_gralloc::DrmFormat;
pub use crate::rutabaga_gralloc::ImageAllocationInfo;
pub use crate::rutabaga_gralloc::ImageMemoryRequirements;
pub use crate::rutabaga_gralloc::RutabagaGralloc;
pub use crate::rutabaga_gralloc::RutabagaGrallocBackendFlags;
pub use crate::rutabaga_gralloc::RutabagaGrallocFlags;
pub use crate::rutabaga_utils::*;
