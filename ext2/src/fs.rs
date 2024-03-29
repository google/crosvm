// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Defines a struct to represent an ext2 filesystem and implements methods to create
// a filesystem in memory.

use std::collections::BTreeMap;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Result;
use base::MemoryMapping;
use base::MemoryMappingBuilder;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

use crate::arena::Arena;
use crate::blockgroup::GroupMetaData;
use crate::blockgroup::BLOCK_SIZE;
use crate::inode::Inode;
use crate::inode::InodeNum;
use crate::inode::InodeType;
use crate::superblock::Config;
use crate::superblock::SuperBlock;

#[repr(C)]
#[derive(Copy, Clone, FromZeroes, FromBytes, AsBytes, Debug)]
struct DirEntryRaw {
    inode: u32,
    rec_len: u16,
    name_len: u8,
    file_type: u8,
}

struct DirEntryWithName<'a> {
    de: &'a mut DirEntryRaw,
    name: String,
}

impl<'a> std::fmt::Debug for DirEntryWithName<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirEntry")
            .field("de", &self.de)
            .field("name", &self.name)
            .finish()
    }
}

impl<'a> DirEntryWithName<'a> {
    fn new(
        arena: &'a Arena<'a>,
        inode: InodeNum,
        typ: InodeType,
        name_str: &str,
        dblock: &mut DirEntryBlock,
    ) -> Result<Self> {
        if name_str.len() > 255 {
            anyhow::bail!("name length must not exceed 255: {}", name_str);
        }
        let cs = name_str.as_bytes();
        let name_len = cs.len();
        let aligned_name_len = name_len
            .checked_next_multiple_of(4)
            .expect("name length must be 4-byte aligned");

        // rec_len = |inode| + |file_type| + |name_len| + |rec_len| + name + padding
        //         = 4 + 1 + 1 + 2 + |name| + padding
        //         = 8 + |name| + padding
        // The padding is inserted because the name is 4-byte aligned.
        let rec_len = 8 + aligned_name_len as u16;

        let dir_entry_size = std::mem::size_of::<DirEntryRaw>();
        if dblock.offset + dir_entry_size + aligned_name_len > BLOCK_SIZE {
            bail!("sum of dir_entry size exceeds block size: {} + {dir_entry_size} + {aligned_name_len} > {BLOCK_SIZE}", dblock.offset);
        }

        let block_id = dblock.block_id as usize;
        let de = arena.allocate(block_id, dblock.offset)?;
        *de = DirEntryRaw {
            inode: inode.into(),
            rec_len,
            name_len: name_len as u8,
            file_type: typ.into_dir_entry_file_type(),
        };
        dblock.offset += dir_entry_size;

        let name_slice = arena.allocate_slice(block_id, dblock.offset, aligned_name_len)?;
        dblock.offset += aligned_name_len;
        name_slice[..cs.len()].copy_from_slice(cs);

        if dblock.entries.is_empty() {
            de.rec_len = BLOCK_SIZE as u16;
        } else {
            let last = dblock
                .entries
                .last_mut()
                .expect("parent_dir must not be empty");
            let last_rec_len = last.de.rec_len;
            last.de.rec_len = (8 + last.name.as_bytes().len() as u16)
                .checked_next_multiple_of(4)
                .expect("overflow to calculate rec_len");
            de.rec_len = last_rec_len - last.de.rec_len;
        }

        Ok(Self {
            de,
            name: name_str.to_owned(),
        })
    }
}

#[derive(Debug)]
struct DirEntryBlock<'a> {
    block_id: u32,
    offset: usize,
    entries: Vec<DirEntryWithName<'a>>,
}

/// A struct to represent an ext2 filesystem.
pub struct Ext2<'a> {
    sb: &'a mut SuperBlock,

    // We support only one block group for now.
    // TODO(b/331764754): Support multiple block groups.
    group_metadata: GroupMetaData<'a>,

    // TODO(b/331901633): To support larger directory,
    // the value should be `Vec<DirEntryBlock>`.
    dentries: BTreeMap<InodeNum, DirEntryBlock<'a>>,
}

impl<'a> Ext2<'a> {
    /// Create a new ext2 filesystem.
    fn new(cfg: &Config, arena: &'a Arena<'a>) -> Result<Self> {
        let sb = SuperBlock::new(arena, cfg)?;
        if sb.block_group_nr != 1 {
            bail!("multiple block group isn't supported");
        }

        let group_metadata = GroupMetaData::new(arena, sb)?;
        let mut ext2 = Ext2 {
            sb,
            group_metadata,
            dentries: BTreeMap::new(),
        };

        // Add rootdir
        let root_inode = InodeNum::new(2)?;
        ext2.add_dir(arena, root_inode, root_inode, "/")?;
        let lost_found_inode = ext2.allocate_inode()?;
        ext2.add_dir(arena, lost_found_inode, root_inode, "lost+found")?;

        Ok(ext2)
    }

    fn block_size(&self) -> u64 {
        // Minimal block size is 1024.
        1024 << self.sb.log_block_size
    }

    fn allocate_inode(&mut self) -> Result<InodeNum> {
        if self.sb.free_inodes_count == 0 {
            bail!(
                "no free inodes: run out of s_inodes_count={}",
                self.sb.inodes_count
            );
        }

        if self.group_metadata.group_desc.free_inodes_count == 0 {
            bail!("no free inodes in group 0");
        }

        let gm = &mut self.group_metadata;
        let alloc_inode = InodeNum::new(gm.first_free_inode)?;
        // (alloc_inode - 1) because inode is 1-indexed.
        gm.inode_bitmap
            .set(usize::from(alloc_inode) - 1usize, true)?;
        gm.first_free_inode += 1;
        gm.group_desc.free_inodes_count -= 1;
        self.sb.free_inodes_count -= 1;

        Ok(alloc_inode)
    }

    fn allocate_block(&mut self) -> Result<u32> {
        if self.sb.free_blocks_count == 0 {
            bail!(
                "no free blocks: run out of s_blocks_count={}",
                self.sb.blocks_count
            );
        }

        if self.group_metadata.group_desc.free_blocks_count == 0 {
            // TODO(b/331764754): Support multiple block groups.
            bail!("no free blocks in group 0. No multiple group support");
        }

        let gm = &mut self.group_metadata;
        let alloc_block = gm.first_free_block;
        gm.block_bitmap.set(alloc_block as usize, true)?;
        gm.first_free_block += 1;
        gm.group_desc.free_blocks_count -= 1;
        self.sb.free_blocks_count -= 1;

        Ok(alloc_block)
    }

    fn get_inode_mut(&mut self, num: InodeNum) -> Result<&mut &'a mut Inode> {
        self.group_metadata
            .inode_table
            .get_mut(&num)
            .ok_or_else(|| anyhow!("{:?} not found", num))
    }

    fn allocate_dir_entry(
        &mut self,
        arena: &'a Arena<'a>,
        parent: InodeNum,
        inode: InodeNum,
        typ: InodeType,
        name: &str,
    ) -> Result<()> {
        let block_size = self.block_size();

        // Disable false-positive `clippy::map_entry`.
        // https://github.com/rust-lang/rust-clippy/issues/9470
        #[allow(clippy::map_entry)]
        if !self.dentries.contains_key(&parent) {
            let block_id = self.allocate_block()?;
            let inode = self.get_inode_mut(parent)?;
            inode.block.set_block_id(0, block_id);
            inode.blocks = block_size as u32 / 512;
            self.dentries.insert(
                parent,
                DirEntryBlock {
                    block_id,
                    offset: 0,
                    entries: Vec::new(),
                },
            );
        }

        if typ == InodeType::Directory {
            let parent = self.get_inode_mut(parent)?;
            parent.links_count += 1;
        }

        let parent_dir = self
            .dentries
            .get_mut(&parent)
            .ok_or_else(|| anyhow!("parent {:?} not found for {:?}", parent, inode))?;

        let dir_entry = DirEntryWithName::new(arena, inode, typ, name, parent_dir)?;

        parent_dir.entries.push(dir_entry);

        Ok(())
    }

    fn add_inode(&mut self, num: InodeNum, inode: &'a mut Inode) -> Result<()> {
        let typ = inode.typ().ok_or_else(|| anyhow!("unknown inode type"))?;
        if self.group_metadata.inode_table.contains_key(&num) {
            bail!("inode {:?} already exists", &num);
        }

        if typ == InodeType::Directory {
            self.group_metadata.group_desc.used_dirs_count += 1;
        }

        self.group_metadata.inode_table.insert(num, inode);

        // TODO(b/331764754): To support multiple block groups, need to fix this calculation.
        self.group_metadata
            .inode_bitmap
            .set(num.to_table_index(), true)?;

        Ok(())
    }

    fn add_dir(
        &mut self,
        arena: &'a Arena<'a>,
        inode_num: InodeNum,
        parent_inode: InodeNum,
        name: &str,
    ) -> Result<()> {
        let block_size = self.sb.block_size();
        let inode = Inode::new(
            arena,
            &mut self.group_metadata,
            inode_num,
            InodeType::Directory,
            block_size as u32,
        )?;
        self.add_inode(inode_num, inode)?;

        self.allocate_dir_entry(arena, inode_num, inode_num, InodeType::Directory, ".")?;
        self.allocate_dir_entry(arena, inode_num, parent_inode, InodeType::Directory, "..")?;

        if inode_num != parent_inode {
            self.allocate_dir_entry(arena, parent_inode, inode_num, InodeType::Directory, name)?;
        }

        Ok(())
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
