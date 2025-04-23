// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ptr::NonNull;

use libc::c_void;

use crate::rutabaga_os::OwnedDescriptor;
use crate::rutabaga_utils::RutabagaErrorKind;
use crate::rutabaga_utils::RutabagaResult;

/// Wraps an anonymous shared memory mapping in the current process. Provides
/// RAII semantics including munmap when no longer needed.
#[derive(Debug)]
pub struct MemoryMapping {
    pub addr: NonNull<c_void>,
    pub size: usize,
}

impl MemoryMapping {
    pub fn from_safe_descriptor(
        _descriptor: OwnedDescriptor,
        _size: usize,
        _map_info: u32,
    ) -> RutabagaResult<MemoryMapping> {
        Err(RutabagaErrorKind::Unsupported.into())
    }
}
