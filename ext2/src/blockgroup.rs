// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Defines structs for metadata of block groups.

use anyhow::bail;
use anyhow::Result;
use zerocopy::AsBytes;
use zerocopy_derive::FromBytes;
use zerocopy_derive::FromZeroes;

use crate::arena::Arena;
use crate::bitmap::BitMap;
use crate::superblock::SuperBlock;

/// The size of a block in bytes.
/// We only support 4K-byte blocks.
pub const BLOCK_SIZE: usize = 4096;

/// A block group descriptor.
///
/// See [the specification](https://www.nongnu.org/ext2-doc/ext2.html#block-group-descriptor-table) for the details.
#[repr(C)]
#[derive(Default, Debug, Copy, Clone, FromZeroes, FromBytes, AsBytes)]
pub(crate) struct BlockGroupDescriptor {
    /// Index of the first block of the block bitmap.
    pub block_bitmap: u32,
    /// Index of the first block of the inode bitmap.
    pub inode_bitmap: u32,
    /// Index of the first block of the inode table.
    inode_table: u32,
    /// Number of free blocks.
    free_blocks_count: u16,
    /// Number of free inodes.
    free_inodes_count: u16,
    /// Number of directories.
    used_dirs_count: u16,
    pad: u16,
    reserved: [u8; 12],
}

#[allow(dead_code)]
pub(crate) struct GroupMetaData<'a> {
    group_desc: &'a mut BlockGroupDescriptor,
    block_bitmap: BitMap<'a>,
    inode_bitmap: BitMap<'a>,
}

impl<'a> GroupMetaData<'a> {
    pub fn new(arena: &'a Arena<'a>, sb: &mut SuperBlock) -> Result<Self> {
        let gd_size = std::mem::size_of::<BlockGroupDescriptor>() as u32;
        let num_blocks_for_gds =
            (gd_size * sb.block_group_nr as u32).div_ceil(sb.block_size() as u32);

        let inodes_per_block = sb.block_size() / sb.inode_size as u64;
        let num_blocks_for_inode_table =
            (sb.inodes_per_group as usize).div_ceil(inodes_per_block as usize);

        // Assume we have only one block group.
        if sb.block_group_nr != 1 {
            bail!("multiple block groups are not supported");
        }

        // Allocate a block group descriptor at Block 1.
        let group_desc = arena.allocate::<BlockGroupDescriptor>(1, 0)?;

        // First blocks for superblock and group descriptors.
        let block_for_super_block = 0u32;
        let block_for_group_desc = 1u32;

        // First blocks for block_bitmap, inode_bitmap, and inode_table.
        group_desc.block_bitmap = block_for_group_desc + num_blocks_for_gds;
        group_desc.inode_bitmap = group_desc.block_bitmap + 1;
        group_desc.inode_table = group_desc.inode_bitmap + 1;

        // First free block is the one after inode table.
        let first_free_block = group_desc.inode_table as usize + num_blocks_for_inode_table;
        // Free blocks are from `first_free_block` to `blocks_per_group`, inclusive.
        group_desc.free_blocks_count = (sb.blocks_per_group - first_free_block as u32) as u16;
        sb.free_blocks_count = group_desc.free_blocks_count as u32;

        // 10 inodes should be reserved in ext2.
        let reserved_inode = 10;
        group_desc.free_inodes_count = (sb.inodes_per_group - reserved_inode) as u16;
        sb.free_inodes_count = group_desc.free_inodes_count as u32;

        group_desc.used_dirs_count = 1; // root dir

        // Initialize block bitmap block.
        let bmap = arena.allocate::<[u8; BLOCK_SIZE]>(group_desc.block_bitmap as usize, 0)?;
        let valid_bmap_bytes = (sb.blocks_per_group / 8) as usize;
        // Unused parts in the block is marked as 1.
        bmap[valid_bmap_bytes..].iter_mut().for_each(|x| *x = 0xff);
        // Interpret the region as BitMap and mask bits for blocks used for metadata.
        let mut block_bitmap = BitMap::from_slice_mut(&mut bmap[..valid_bmap_bytes]);
        block_bitmap.mark_first_elems(first_free_block - block_for_super_block as usize, true);

        let imap = arena.allocate::<[u8; BLOCK_SIZE]>(group_desc.inode_bitmap as usize, 0)?;
        let valid_imap_bytes = (sb.inodes_per_group / 8) as usize;
        // Unused parts in the block is marked as 1.
        imap[valid_imap_bytes..].iter_mut().for_each(|x| *x = 0xff);
        // Interpret the region as BitMap and mask bits for reserved inodes.
        let mut inode_bitmap =
            BitMap::from_slice_mut(&mut imap[..(sb.inodes_per_group / 8) as usize]);
        inode_bitmap.mark_first_elems(reserved_inode as usize, true);

        Ok(GroupMetaData {
            group_desc,
            block_bitmap,
            inode_bitmap,
        })
    }
}

#[cfg(test)]
mod test {
    use base::MemoryMappingBuilder;

    use super::*;
    use crate::superblock::Config;

    // Check if `GroupMetaData` is correctly initialized from `SuperBlock` with one block group.
    #[test]
    fn test_group_metadata_with_one_block_group() {
        let num_groups = 20;
        let mut mem = MemoryMappingBuilder::new(BLOCK_SIZE * num_groups)
            .build()
            .unwrap();
        let arena = Arena::new(BLOCK_SIZE, &mut mem).unwrap();
        let sb = SuperBlock::new(
            &arena,
            &Config {
                inodes_per_group: 1024,
                blocks_per_group: 1024,
            },
        )
        .unwrap();
        let group = GroupMetaData::new(&arena, sb).unwrap();

        // Assume we have only one block group.
        assert_eq!(sb.block_group_nr, 1);

        // First a few blocks are used for specific purposes.
        // Their indexes are arbitrary but we can assume the following values unless we use much
        // larger parameters:
        // 0: 1024-byte offset + superblock
        // 1: group descriptor(s)
        // 2: block bitmap
        // 3: inode bitmap
        // 4+ : inode table
        assert_eq!(group.group_desc.block_bitmap, 2);
        assert_eq!(group.group_desc.inode_bitmap, 3);
        assert_eq!(group.group_desc.inode_table, 4);

        assert_eq!(
            group.group_desc.free_blocks_count as u32,
            sb.free_blocks_count
        );
        assert_eq!(
            group.group_desc.free_inodes_count as u32,
            sb.free_inodes_count
        );
        assert_eq!(group.block_bitmap.len(), sb.blocks_per_group as usize);
        assert_eq!(
            group.block_bitmap.count_zeros(),
            group.group_desc.free_blocks_count as usize,
        );
        assert_eq!(
            group.inode_bitmap.count_zeros(),
            group.group_desc.free_inodes_count as usize,
        );
    }
}
