// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Manages system resources that can be allocated to VMs and their devices.

#[cfg(feature = "wl-dmabuf")]
extern crate gpu_buffer;
extern crate libc;
extern crate sys_util;

mod address_allocator;
mod gpu_allocator;
mod system_allocator;

pub use address_allocator::AddressAllocator;
pub use gpu_allocator::{GpuMemoryAllocator, GpuMemoryDesc, GpuMemoryPlaneDesc};
pub use system_allocator::{AddressRanges, SystemAllocator};
