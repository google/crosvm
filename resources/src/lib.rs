// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Manages system resources that can be allocated to VMs and their devices.

mod address_allocator;
mod gpu_allocator;
mod system_allocator;

pub use crate::address_allocator::AddressAllocator;
pub use crate::gpu_allocator::{GpuMemoryAllocator, GpuMemoryDesc, GpuMemoryPlaneDesc};
pub use crate::system_allocator::{AddressRanges, SystemAllocator};
