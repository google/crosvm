// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::mem::size_of;
use std::os::raw::c_void;
use std::slice::{from_raw_parts, from_raw_parts_mut};

use crate::generated::virgl_protocol::*;
use crate::Resource;

/// Helper struct for making a virgl command buffer.
#[derive(Default)]
pub struct CommandBufferBuilder {
    cbuf: Vec<u32>,
}

impl AsRef<[u8]> for CommandBufferBuilder {
    fn as_ref(&self) -> &[u8] {
        // Safe because the returned slice is a trivial reinterpretation of the same number of
        // bytes.
        unsafe {
            from_raw_parts(
                self.cbuf.as_ptr() as *const u8,
                self.cbuf.len() * size_of::<u32>(),
            )
        }
    }
}

impl AsMut<[u8]> for CommandBufferBuilder {
    fn as_mut(&mut self) -> &mut [u8] {
        // Safe because the returned slice is a trivial reinterpretation of the same number of
        // bytes.
        unsafe {
            from_raw_parts_mut(
                self.cbuf.as_mut_ptr() as *mut u8,
                self.cbuf.len() * size_of::<u32>(),
            )
        }
    }
}

impl CommandBufferBuilder {
    /// Constructs an empty command
    pub fn new() -> CommandBufferBuilder {
        Default::default()
    }

    fn push(&mut self, dw: u32) {
        self.cbuf.push(dw);
    }

    fn push_qw(&mut self, qw: u64) {
        self.cbuf.push(qw as u32);
        self.cbuf.push((qw >> 32) as u32);
    }

    fn push_cmd(&mut self, cmd: u32, obj_type: u32, len: u32) {
        self.cbuf
            .push((cmd & 0xff) | ((obj_type & 0xff) << 8) | ((len & 0xffff) << 16));
    }

    /// Gets the command buffer as a pointer to the beginning.
    pub fn as_mut_ptr(&mut self) -> *mut c_void {
        self.cbuf.as_mut_ptr() as *mut c_void
    }

    /// Gets the size of the command buffer content in dwords.
    pub fn dword_count(&self) -> usize {
        self.cbuf.len()
    }

    /// Clears the command buffer content.
    pub fn clear(&mut self) {
        self.cbuf.clear();
    }

    /// Checks that the command buffer is well formed.
    pub fn is_valid(&self) -> bool {
        let mut i = 0;
        while i < self.cbuf.len() {
            i += 1 + (self.cbuf[i] >> 16) as usize;
        }
        i == self.cbuf.len()
    }

    /// Pushes a clear command to this command buffer.
    pub fn e_clear(&mut self, buffers: u32, color: [f32; 4], depth: f64, stencil: u32) {
        self.push_cmd(VIRGL_CCMD_CLEAR, 0, VIRGL_OBJ_CLEAR_SIZE);
        self.push(buffers);
        for c in &color {
            self.push(c.to_bits())
        }
        self.push_qw(depth.to_bits());
        self.push(stencil);
        assert!(self.is_valid());
    }

    /// Pushes a create surface command to this command buffer.
    pub fn e_create_surface(
        &mut self,
        new_id: u32,
        res: &Resource,
        format: u32,
        level: u32,
        first_layer: u32,
        last_layer: u32,
    ) {
        self.push_cmd(
            VIRGL_CCMD_CREATE_OBJECT,
            VIRGL_OBJECT_SURFACE,
            VIRGL_OBJ_SURFACE_SIZE,
        );
        self.push(new_id);
        self.push(res.id());
        self.push(format);
        self.push(level);
        self.push(first_layer | (last_layer << 16));
        assert!(self.is_valid());
    }

    /// Pushes a set framebuffer state command to this command buffer.
    pub fn e_set_fb_state(&mut self, surface_handles: &[u32], zbuf: Option<u32>) {
        fn cmd_set_fb_state_size(surface_count: u32) -> u32 {
            2 + surface_count
        }
        self.push_cmd(
            VIRGL_CCMD_SET_FRAMEBUFFER_STATE,
            0,
            cmd_set_fb_state_size(surface_handles.len() as u32),
        );
        self.push(surface_handles.len() as u32);
        self.push(zbuf.unwrap_or(0));
        for &surface_handle in surface_handles {
            self.push(surface_handle);
        }
        assert!(self.is_valid());
    }
}
