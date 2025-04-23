// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! renderer_utils: Utility functions and structs used by virgl_renderer and gfxstream.

use crate::rutabaga_os::OwnedDescriptor;
use crate::rutabaga_utils::RutabagaDebugHandler;
use crate::rutabaga_utils::RutabagaErrorKind;
use crate::rutabaga_utils::RutabagaFenceHandler;
use crate::rutabaga_utils::RutabagaResult;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct VirglBox {
    pub x: u32,
    pub y: u32,
    pub z: u32,
    pub w: u32,
    pub h: u32,
    pub d: u32,
}

pub fn ret_to_res(ret: i32) -> RutabagaResult<()> {
    match ret {
        0 => Ok(()),
        _ => Err(RutabagaErrorKind::ComponentError(ret).into()),
    }
}

pub struct RutabagaCookie {
    pub render_server_fd: Option<OwnedDescriptor>,
    pub fence_handler: Option<RutabagaFenceHandler>,
    pub debug_handler: Option<RutabagaDebugHandler>,
}
