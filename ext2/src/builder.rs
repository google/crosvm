// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Provides structs and logic to build ext2 file system with configurations.

use std::path::Path;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use base::MappedRegion;
use base::MemoryMapping;
use base::MemoryMappingArena;
use base::MemoryMappingBuilder;
use base::Protection;

use crate::arena::Arena;
use crate::arena::FileMappingInfo;
use crate::fs::Ext2;
use crate::BLOCK_SIZE;

/// A struct to represent the configuration of an ext2 filesystem.
pub struct Builder {
    /// The number of blocks per group.
    pub blocks_per_group: u32,
    /// The number of inodes per group.
    pub inodes_per_group: u32,
    /// The size of the memory region.
    pub size: u32,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            blocks_per_group: 4096,
            inodes_per_group: 4096,
            size: 4096 * 4096,
        }
    }
}

impl Builder {
    /// Validates field values and adjusts them if needed.
    fn validate(&mut self) -> Result<()> {
        let block_group_size = BLOCK_SIZE as u32 * self.blocks_per_group;
        if self.size < block_group_size {
            bail!(
            "memory size {} is too small to have a block group: block_size={},  block_per_group={}",
            self.size,
            BLOCK_SIZE,
            block_group_size
        );
        }
        if self.size % block_group_size != 0 {
            // Round down to the largest multiple of block_group_size that is smaller than self.size
            self.size = self.size.next_multiple_of(block_group_size) - block_group_size
        };
        Ok(())
    }

    /// Allocates memory region with the given configuration.
    pub fn allocate_memory(mut self) -> Result<MemRegion> {
        self.validate()
            .context("failed to validate the ext2 config")?;
        let mem = MemoryMappingBuilder::new(self.size as usize)
            .build()
            .context("failed to allocate memory for ext2")?;
        Ok(MemRegion { cfg: self, mem })
    }
}

/// Memory region for ext2 with its config.
pub struct MemRegion {
    cfg: Builder,
    mem: MemoryMapping,
}

impl MemRegion {
    /// Constructs an ext2 metadata by traversing `src_dir`.
    pub fn build_mmap_info(mut self, src_dir: Option<&Path>) -> Result<MemRegionWithMappingInfo> {
        let arena = Arena::new(BLOCK_SIZE, &mut self.mem).context("failed to allocate arena")?;
        let mut ext2 = Ext2::new(&self.cfg, &arena).context("failed to create Ext2 struct")?;
        if let Some(dir) = src_dir {
            ext2.copy_dirtree(&arena, dir)
                .context("failed to copy directory tree")?;
        }
        ext2.copy_backup_metadata(&arena)
            .context("failed to copy metadata for backup")?;
        let mapping_info = arena.into_mapping_info();

        self.mem
            .msync()
            .context("failed to msyn of ext2's memory region")?;
        Ok(MemRegionWithMappingInfo {
            mem: self.mem,
            mapping_info,
        })
    }
}

/// Memory regions where ext2 metadata were written with information of mmap operations to be done.
pub struct MemRegionWithMappingInfo {
    mem: MemoryMapping,
    mapping_info: Vec<FileMappingInfo>,
}

impl MemRegionWithMappingInfo {
    /// Do mmap and returns the memory region where ext2 was created.
    pub fn do_mmap(self) -> Result<MemoryMappingArena> {
        let mut mmap_arena = MemoryMappingArena::from(self.mem);
        for FileMappingInfo {
            mem_offset,
            file,
            length,
            file_offset,
        } in self.mapping_info
        {
            mmap_arena
                .add_fd_mapping(
                    mem_offset,
                    length,
                    &file,
                    file_offset as u64, /* fd_offset */
                    Protection::read(),
                )
                .context("failed mmaping an fd for ext2")?;
        }

        Ok(mmap_arena)
    }
}
