// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Manages system resources that can be allocated to VMs and their devices.

extern crate sys_util;

mod address_allocator;
mod system_allocator;

pub use address_allocator::AddressAllocator;
pub use system_allocator::{AddressRanges, SystemAllocator};
