// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Defines a struct to represent an ext2 filesystem and implements methods to create
// a filesystem in memory.

use anyhow::Context;
use anyhow::Result;
use base::MemoryMapping;
use base::MemoryMappingBuilder;
use zerocopy::AsBytes;

use crate::superblock::Config;
use crate::superblock::SuperBlock;

/// A struct to represent an ext2 filesystem.
pub struct Ext2 {
    sb: SuperBlock,
}

impl Ext2 {
    /// Create a new ext2 filesystem.

    pub fn new(cfg: &Config) -> Result<Self> {
        let sb = SuperBlock::new(cfg)?;
        Ok(Ext2 { sb })
    }

    /// Write a minimal ext2 filesystem to a memory region.
    pub fn write_to_memory(&self) -> Result<MemoryMapping> {
        let len = self.sb.disk_size() as usize;
        let mem = MemoryMappingBuilder::new(len).build()?;

        // Write the superblock.
        let offset = 1024;
        mem.write_slice(self.sb.as_bytes(), offset)?;
        mem.msync().context("failed to flush disk")?;
        Ok(mem)
    }
}
