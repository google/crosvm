// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This crate provides a logic for creating an ext2 filesystem on memory.

#![cfg(any(target_os = "android", target_os = "linux"))]
#![deny(missing_docs)]

mod arena;
mod bitmap;
mod blockgroup;
mod fs;
mod inode;
mod superblock;

pub use fs::create_ext2_region;
pub use superblock::Config;
