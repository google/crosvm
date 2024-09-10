// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Defines structs for metadata of block groups.

use std::collections::BTreeMap;

use anyhow::Result;
use zerocopy::AsBytes;
use zerocopy_derive::FromBytes;
use zerocopy_derive::FromZeroes;

use crate::arena::Arena;
use crate::arena::BlockId;
use crate::bitmap::BitMap;
use crate::inode::Inode;
use crate::inode::InodeNum;
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
    pub inode_table: u32,
    /// Number of free blocks.
    pub free_blocks_count: u16,
    /// Number of free inodes.
    pub free_inodes_count: u16,
    /// Number of directories.
    pub used_dirs_count: u16,
    pad: u16,
    reserved: [u8; 12],
}

pub(crate) struct GroupMetaData<'a> {
    pub group_desc: &'a mut BlockGroupDescriptor,
    pub block_bitmap: BitMap<'a>,
    pub inode_bitmap: BitMap<'a>,

    pub inode_table: BTreeMap<InodeNum, &'a mut Inode>,

    pub first_free_block: u32,
    pub first_free_inode: u32,
}

impl<'a> GroupMetaData<'a> {
    // Write GroupMetaData to the first block group.
    // This data need to be copied to other block gropups' descriptor tables.
    pub fn new(arena: &'a Arena<'a>, sb: &mut SuperBlock, group_id: u16) -> Result<Self> {
        let gd_size = std::mem::size_of::<BlockGroupDescriptor>() as u32;
        let num_blocks_for_gds = (gd_size * sb.num_groups() as u32).div_ceil(BLOCK_SIZE as u32);

        let inodes_per_block = BLOCK_SIZE as u64 / sb.inode_size as u64;
        let num_blocks_for_inode_table =
            (sb.inodes_per_group as usize).div_ceil(inodes_per_block as usize);

        // Allocate a block group descriptor at Block 1.
        let group_desc = arena.allocate::<BlockGroupDescriptor>(
            BlockId::from(1),
            std::mem::size_of::<BlockGroupDescriptor>() * group_id as usize,
        )?;

        // First blocks for block_bitmap, inode_bitmap, and inode_table.
        let super_block_id = group_id as u32 * sb.blocks_per_group;
        let group_desc_id = super_block_id + 1;
        group_desc.block_bitmap = group_desc_id + num_blocks_for_gds;
        group_desc.inode_bitmap = group_desc.block_bitmap + 1;
        group_desc.inode_table = group_desc.inode_bitmap + 1;

        // First free block is the one after inode table.
        let first_free_block = group_desc.inode_table + num_blocks_for_inode_table as u32;
        // Free blocks are from `first_free_block` to `blocks_per_group`, inclusive.
        group_desc.free_blocks_count =
            (sb.blocks_per_group * (group_id as u32 + 1) - first_free_block) as u16;
        sb.free_blocks_count += group_desc.free_blocks_count as u32;

        // 10 inodes should be reserved in ext2.
        let reserved_inode = if group_id == 0 { 10 } else { 0 };
        let first_free_inode = group_id as u32 * sb.inodes_per_group + reserved_inode + 1;
        group_desc.free_inodes_count = sb.inodes_per_group as u16 - reserved_inode as u16;
        sb.free_inodes_count -= reserved_inode;

        // Initialize block bitmap block.
        let bmap = arena.allocate::<[u8; BLOCK_SIZE]>(BlockId::from(group_desc.block_bitmap), 0)?;
        let valid_bmap_bytes = (sb.blocks_per_group / 8) as usize;
        // Unused parts in the block is marked as 1.
        bmap[valid_bmap_bytes..].iter_mut().for_each(|x| *x = 0xff);
        // Interpret the region as BitMap and mask bits for blocks used for metadata.
        let mut block_bitmap = BitMap::from_slice_mut(&mut bmap[..valid_bmap_bytes]);
        block_bitmap.mark_first_elems(
            (first_free_block - group_id as u32 * sb.blocks_per_group) as usize,
            true,
        );

        let imap = arena.allocate::<[u8; BLOCK_SIZE]>(BlockId::from(group_desc.inode_bitmap), 0)?;
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

            inode_table: BTreeMap::new(),

            first_free_block,
            first_free_inode,
        })
    }
}

#[cfg(test)]
mod test {
    use base::MemoryMappingBuilder;

    use super::*;
    use crate::Builder;

    // Check if `GroupMetaData` is correctly initialized from `SuperBlock` with one block group.
    #[test]
    fn test_group_metadata_with_one_block_group() {
        let blocks_per_group = 1024;
        let num_groups = 1;
        let size = BLOCK_SIZE as u32 * blocks_per_group * num_groups;
        let mut mem = MemoryMappingBuilder::new(size as usize).build().unwrap();
        let arena = Arena::new(BLOCK_SIZE, &mut mem).unwrap();
        let sb = SuperBlock::new(
            &arena,
            &Builder {
                inodes_per_group: 1024,
                blocks_per_group,
                size,
            },
        )
        .unwrap();
        let group = GroupMetaData::new(&arena, sb, 0).unwrap();

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

    #[test]
    fn test_group_metadata_with_multiple_block_groups() {
        let blocks_per_group = 1024u32;
        let num_groups = 10u32;
        let mem_size = BLOCK_SIZE as u32 * blocks_per_group * num_groups;
        let mut mem = MemoryMappingBuilder::new(mem_size as usize)
            .build()
            .unwrap();
        let arena = Arena::new(BLOCK_SIZE, &mut mem).unwrap();
        let sb = SuperBlock::new(
            &arena,
            &Builder {
                inodes_per_group: 512,
                blocks_per_group,
                size: mem_size,
            },
        )
        .unwrap();

        let groups = (0..num_groups)
            .map(|group_id| GroupMetaData::new(&arena, sb, group_id as u16).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            groups
                .iter()
                .map(|gd| gd.group_desc.free_blocks_count as u32)
                .sum::<u32>(),
            sb.free_blocks_count
        );
        assert_eq!(
            groups
                .iter()
                .map(|gd| gd.group_desc.free_inodes_count as u32)
                .sum::<u32>(),
            sb.free_inodes_count
        );
    }
}
