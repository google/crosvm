// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Defines a struct to represent an ext2 filesystem and implements methods to create
// a filesystem in memory.

use anyhow::bail;
use anyhow::Result;
use base::MemoryMapping;
use base::MemoryMappingBuilder;

use crate::arena::Arena;
use crate::blockgroup::GroupMetaData;
use crate::blockgroup::BLOCK_SIZE;
use crate::superblock::Config;
use crate::superblock::SuperBlock;

/// A struct to represent an ext2 filesystem.
pub struct Ext2<'a> {
    _sb: &'a SuperBlock,
    // We support only one block group for now.
    // TODO(b/331764754): Support multiple block groups.
    _group_metadata: GroupMetaData<'a>,
}

impl<'a> Ext2<'a> {
    /// Create a new ext2 filesystem.
    fn new(cfg: &Config, arena: &'a Arena<'a>) -> Result<Self> {
        let sb = SuperBlock::new(arena, cfg)?;
        if sb.block_group_nr != 1 {
            bail!("multiple block group isn't supported");
        }
        let group_metadata = GroupMetaData::new(arena, sb)?;
        Ok(Ext2 {
            _sb: sb,
            _group_metadata: group_metadata,
        })
    }
}

/// Creates a memory mapping region where an ext2 filesystem is constructed.
pub fn create_ext2_region(cfg: &Config) -> Result<MemoryMapping> {
    let num_group = 1; // TODO(b/329359333): Support more than 1 group.
    let mut mem = MemoryMappingBuilder::new(cfg.blocks_per_group as usize * BLOCK_SIZE * num_group)
        .build()?;
    let arena = Arena::new(BLOCK_SIZE, &mut mem)?;
    let _ext2 = Ext2::new(cfg, &arena)?;
    mem.msync()?;
    Ok(mem)
}
