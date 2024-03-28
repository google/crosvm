// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Defines the superblock structure.

use anyhow::Result;
use zerocopy::AsBytes;
use zerocopy_derive::FromBytes;
use zerocopy_derive::FromZeroes;

use crate::arena::Arena;

/// A struct to represent the configuration of an ext2 filesystem.
pub struct Config {
    /// The number of blocks per group.
    pub blocks_per_group: u32,
    /// The number of inodes per group.
    pub inodes_per_group: u32,
}

/// The ext2 superblock.
///
/// The field names are based on [the specification](https://www.nongnu.org/ext2-doc/ext2.html#superblock).
/// Note that this struct only holds the fields at the beginning of the superblock. All fields after
/// the fields supported by this structure are filled with zeros.
#[repr(C)]
#[derive(Default, Debug, Copy, Clone, FromZeroes, FromBytes, AsBytes)]
pub(crate) struct SuperBlock {
    inodes_count: u32,
    blocks_count: u32,
    _r_blocks_count: u32,
    pub free_blocks_count: u32,
    pub free_inodes_count: u32,
    _first_data_block: u32,
    pub log_block_size: u32,
    log_frag_size: u32,
    pub blocks_per_group: u32,
    frags_per_group: u32,
    pub inodes_per_group: u32,
    mtime: u32,
    wtime: u32,
    _mnt_count: u16,
    _max_mnt_count: u16,
    magic: u16,
    state: u16,
    errors: u16,
    _minor_rev_level: u16,
    _lastcheck: u32,
    _checkinterval: u32,
    _creator_os: u32,
    rev_level: u32,
    _def_resuid: u16,
    _def_resgid: u16,
    first_ino: u32,
    pub inode_size: u16,
    pub block_group_nr: u16,
    _feature_compat: u32,
    feature_incompat: u32,
    _feature_ro_compat: u32,
    uuid: [u8; 16],
    // Add more fields if needed.
}

impl SuperBlock {
    pub fn new<'a>(arena: &'a Arena<'a>, cfg: &Config) -> Result<&'a mut SuperBlock> {
        const EXT2_MAGIC_NUMBER: u16 = 0xEF53;

        // TODO(b/329359333): Support more than 1 groups for larger data.
        let block_group_nr = 1u16;
        let blocks_per_group = cfg.blocks_per_group;
        let inodes_per_group = cfg.inodes_per_group;

        let log_block_size = 2; // (1024 << log_block_size) = 4K bytes

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as u32;

        let uuid = uuid::Uuid::new_v4().into_bytes();
        let inodes_count = inodes_per_group * block_group_nr as u32;
        let blocks_count = blocks_per_group * block_group_nr as u32;

        // Reserve 10 inodes. Usually inode 11 is used for the lost+found directory.
        // <https://docs.kernel.org/filesystems/ext4/special_inodes.html>.
        let first_ino = 11;

        // TODO(b/329359333): Replace this with `std::mem::size_of()` once Inode struct is
        // defined.
        // TODO(b/333988434): Support larger inode size for extended attributes. Note that
        // COMPAT_RESIZE_INODE will also be required.
        let inode_size = 128;

        // Superblock is located at 1024 bytes in the first block.
        let sb = arena.allocate::<SuperBlock>(0, 1024)?;
        *sb = Self {
            inodes_count,
            blocks_count,
            free_blocks_count: blocks_count, // All blocks are free
            free_inodes_count: inodes_count, // All inodes are free
            log_block_size,
            log_frag_size: log_block_size,
            blocks_per_group,
            frags_per_group: blocks_per_group,
            inodes_per_group,
            mtime: now,
            wtime: now,
            magic: EXT2_MAGIC_NUMBER,
            state: 1,  // clean
            errors: 1, // continue on errors
            rev_level: 1,
            first_ino,
            inode_size,
            block_group_nr,
            feature_incompat: 0x2, // Directory entries contain a type field
            uuid,
            ..Default::default()
        };
        Ok(sb)
    }

    #[inline]
    pub fn block_size(&self) -> u64 {
        1024 << self.log_block_size
    }
}
