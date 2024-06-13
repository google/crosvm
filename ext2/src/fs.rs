// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Defines a struct to represent an ext2 filesystem and implements methods to create
// a filesystem in memory.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::fs::DirEntry;
use std::fs::File;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use base::info;
use base::MappedRegion;
use base::MemoryMappingArena;
use base::MemoryMappingBuilder;
use base::Protection;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

use crate::arena::Arena;
use crate::arena::BlockId;
use crate::arena::FileMappingInfo;
use crate::blockgroup::BlockGroupDescriptor;
use crate::blockgroup::GroupMetaData;
use crate::blockgroup::BLOCK_SIZE;
use crate::inode::Inode;
use crate::inode::InodeBlock;
use crate::inode::InodeBlocksCount;
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
    name: OsString,
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
        name_str: &OsStr,
        dblock: &mut DirEntryBlock,
    ) -> Result<Self> {
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

        let de = arena.allocate(dblock.block_id, dblock.offset)?;
        *de = DirEntryRaw {
            inode: inode.into(),
            rec_len,
            name_len: name_len as u8,
            file_type: typ.into_dir_entry_file_type(),
        };
        dblock.offset += std::mem::size_of::<DirEntryRaw>();

        let name_slice = arena.allocate_slice(dblock.block_id, dblock.offset, aligned_name_len)?;
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
            last.de.rec_len = (8 + last.name.as_os_str().as_bytes().len() as u16)
                .checked_next_multiple_of(4)
                .expect("overflow to calculate rec_len");
            de.rec_len = last_rec_len - last.de.rec_len;
        }

        Ok(Self {
            de,
            name: name_str.into(),
        })
    }
}

#[derive(Debug)]
struct DirEntryBlock<'a> {
    block_id: BlockId,
    offset: usize,
    entries: Vec<DirEntryWithName<'a>>,
}

impl DirEntryBlock<'_> {
    fn has_enough_space(&self, name: &OsStr) -> bool {
        let dir_entry_size = std::mem::size_of::<DirEntryRaw>();
        let aligned_name_len = name
            .as_bytes()
            .len()
            .checked_next_multiple_of(4)
            .expect("length must be < 256 bytes so it must not overflow");
        self.offset + dir_entry_size + aligned_name_len <= BLOCK_SIZE
    }
}

/// A struct to represent an ext2 filesystem.
pub struct Ext2<'a> {
    sb: &'a mut SuperBlock,
    cur_block_group: usize,
    cur_inode_table: usize,

    group_metadata: Vec<GroupMetaData<'a>>,

    dir_entries: BTreeMap<InodeNum, Vec<DirEntryBlock<'a>>>,
}

impl<'a> Ext2<'a> {
    /// Create a new ext2 filesystem.
    fn new(cfg: &Config, arena: &'a Arena<'a>) -> Result<Self> {
        let sb = SuperBlock::new(arena, cfg)?;

        let mut group_metadata = vec![];
        for i in 0..sb.num_groups() {
            group_metadata.push(GroupMetaData::new(arena, sb, i)?);
        }

        let mut ext2 = Ext2 {
            sb,
            cur_block_group: 0,
            cur_inode_table: 0,
            group_metadata,
            dir_entries: BTreeMap::new(),
        };

        // Add rootdir
        let root_inode = InodeNum::new(2)?;
        ext2.add_reserved_dir(arena, root_inode, root_inode, OsStr::new("/"))?;
        let lost_found_inode = ext2.allocate_inode()?;
        ext2.add_reserved_dir(
            arena,
            lost_found_inode,
            root_inode,
            OsStr::new("lost+found"),
        )?;

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

        if self.group_metadata[self.cur_inode_table]
            .group_desc
            .free_inodes_count
            == 0
        {
            self.cur_inode_table += 1;
        }

        let gm = &mut self.group_metadata[self.cur_inode_table];
        let alloc_inode = InodeNum::new(gm.first_free_inode)?;
        // (alloc_inode - 1) because inode is 1-indexed.
        gm.inode_bitmap
            .set(
                (usize::from(alloc_inode) - 1) % self.sb.inodes_per_group as usize,
                true,
            )
            .context("failed to set inode bitmap")?;

        gm.first_free_inode += 1;
        gm.group_desc.free_inodes_count -= 1;
        self.sb.free_inodes_count -= 1;
        Ok(alloc_inode)
    }

    fn allocate_block(&mut self) -> Result<BlockId> {
        self.allocate_contiguous_blocks(1).map(|v| v[0][0])
    }

    fn allocate_contiguous_blocks(&mut self, n: u16) -> Result<Vec<Vec<BlockId>>> {
        if n == 0 {
            bail!("n must be positive");
        }
        if self.sb.free_blocks_count < n as u32 {
            bail!(
                "no free blocks: run out of free_blocks_count={} < {n}",
                self.sb.free_blocks_count
            );
        }

        let mut contig_blocks = vec![];
        let mut remaining = n;
        while remaining > 0 {
            let alloc_block_num = std::cmp::min(
                remaining,
                self.group_metadata[self.cur_block_group]
                    .group_desc
                    .free_blocks_count,
            ) as u32;

            let gm = &mut self.group_metadata[self.cur_block_group];
            let alloc_blocks = (gm.first_free_block..gm.first_free_block + alloc_block_num)
                .map(BlockId::from)
                .collect();
            gm.first_free_block += alloc_block_num;
            gm.group_desc.free_blocks_count -= alloc_block_num as u16;
            self.sb.free_blocks_count -= alloc_block_num;
            for &b in &alloc_blocks {
                let index = u32::from(b) as usize
                    - self.cur_block_group * self.sb.blocks_per_group as usize;
                gm.block_bitmap
                    .set(index, true)
                    .with_context(|| format!("failed to set block_bitmap at {index}"))?;
            }
            remaining -= alloc_block_num as u16;
            if self.group_metadata[self.cur_block_group]
                .group_desc
                .free_blocks_count
                == 0
            {
                self.cur_block_group += 1;
            }
            contig_blocks.push(alloc_blocks);
        }

        Ok(contig_blocks)
    }

    fn group_num_for_inode(&self, inode: InodeNum) -> usize {
        inode.to_table_index() / self.sb.inodes_per_group as usize
    }

    fn get_inode_mut(&mut self, num: InodeNum) -> Result<&mut &'a mut Inode> {
        let group_id = self.group_num_for_inode(num);
        self.group_metadata[group_id]
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
        name: &OsStr,
    ) -> Result<()> {
        if name.is_empty() {
            bail!("directory name must not be empty");
        } else if name.len() > 255 {
            bail!("name length must not exceed 255: {:?}", name);
        }

        let block_size = self.block_size();

        // Disable false-positive `clippy::map_entry`.
        // https://github.com/rust-lang/rust-clippy/issues/9470
        #[allow(clippy::map_entry)]
        if !self.dir_entries.contains_key(&parent) {
            let block_id = self.allocate_block()?;
            let inode = self.get_inode_mut(parent)?;
            inode.block.set_direct_blocks(&[block_id])?;
            inode.blocks = InodeBlocksCount::from_bytes_len(block_size as u32);
            self.dir_entries.insert(
                parent,
                vec![DirEntryBlock {
                    block_id,
                    offset: 0,
                    entries: Vec::new(),
                }],
            );
        }

        // Allocates  a new block for dir entries if needed.
        if !self
            .dir_entries
            .get(&parent)
            .ok_or_else(|| anyhow!("parent {:?} not found for {:?}", parent, inode))?
            .last()
            .expect("directory entries must not be empty")
            .has_enough_space(name)
        {
            let idx = self.dir_entries.get(&parent).unwrap().len();
            let block_id = self.allocate_block()?;
            let parent_inode = self.get_inode_mut(parent)?;
            parent_inode.block.set_block_id(idx, &block_id)?;
            parent_inode.blocks.add(block_size as u32);
            parent_inode.size += block_size as u32;
            self.dir_entries
                .get_mut(&parent)
                .unwrap()
                .push(DirEntryBlock {
                    block_id,
                    offset: 0,
                    entries: Vec::new(),
                });
        }

        if typ == InodeType::Directory {
            let parent = self.get_inode_mut(parent)?;
            parent.links_count += 1;
        }

        let parent_dir = self
            .dir_entries
            .get_mut(&parent)
            .ok_or_else(|| anyhow!("parent {:?} not found for {:?}", parent, inode))?
            .last_mut()
            .expect("directory entries must not be empty");

        let dir_entry = DirEntryWithName::new(arena, inode, typ, name, parent_dir)?;

        parent_dir.entries.push(dir_entry);

        Ok(())
    }

    fn add_inode(&mut self, num: InodeNum, inode: &'a mut Inode) -> Result<()> {
        let typ = inode.typ().ok_or_else(|| anyhow!("unknown inode type"))?;
        let group_id = self.group_num_for_inode(num);
        let gm = &mut self.group_metadata[group_id];
        if gm.inode_table.contains_key(&num) {
            bail!("inode {:?} already exists", &num);
        }

        if typ == InodeType::Directory {
            gm.group_desc.used_dirs_count += 1;
        }

        gm.inode_table.insert(num, inode);
        let inode_index = num.to_table_index() % self.sb.inodes_per_group as usize;
        gm.inode_bitmap
            .set(inode_index, true)
            .with_context(|| format!("failed to set inode bitmap at {}", num.to_table_index()))?;

        Ok(())
    }

    // Creates a reserved directory such as "root" or "lost+found".
    // So, inode is constructed from scratch.
    fn add_reserved_dir(
        &mut self,
        arena: &'a Arena<'a>,
        inode_num: InodeNum,
        parent_inode: InodeNum,
        name: &OsStr,
    ) -> Result<()> {
        let block_size = self.sb.block_size();
        let group_id = self.group_num_for_inode(inode_num);
        let inode = Inode::new(
            arena,
            &mut self.group_metadata[group_id],
            inode_num,
            InodeType::Directory,
            block_size as u32,
        )?;
        self.add_inode(inode_num, inode)?;

        self.allocate_dir_entry(
            arena,
            inode_num,
            inode_num,
            InodeType::Directory,
            OsStr::new("."),
        )?;
        self.allocate_dir_entry(
            arena,
            inode_num,
            parent_inode,
            InodeType::Directory,
            OsStr::new(".."),
        )?;

        if inode_num != parent_inode {
            self.allocate_dir_entry(arena, parent_inode, inode_num, InodeType::Directory, name)?;
        }

        Ok(())
    }

    fn add_dir(
        &mut self,
        arena: &'a Arena<'a>,
        inode_num: InodeNum,
        parent_inode: InodeNum,
        path: &Path,
    ) -> Result<()> {
        let block_size = self.sb.block_size();
        let group_id = self.group_num_for_inode(inode_num);

        let inode = Inode::from_metadata(
            arena,
            &mut self.group_metadata[group_id],
            inode_num,
            &std::fs::metadata(path)?,
            block_size as u32,
            0,
            InodeBlocksCount::from_bytes_len(0),
            InodeBlock::default(),
        )?;

        self.add_inode(inode_num, inode)?;

        self.allocate_dir_entry(
            arena,
            inode_num,
            inode_num,
            InodeType::Directory,
            OsStr::new("."),
        )?;
        self.allocate_dir_entry(
            arena,
            inode_num,
            parent_inode,
            InodeType::Directory,
            OsStr::new(".."),
        )?;

        if inode_num != parent_inode {
            let name = path
                .file_name()
                .ok_or_else(|| anyhow!("failed to get directory name"))?;
            self.allocate_dir_entry(arena, parent_inode, inode_num, InodeType::Directory, name)?;
        }

        Ok(())
    }

    /// Registers a file to be mmaped to the memory region.
    /// This function just reserves a region for mmap() on `arena` and doesn't call mmap().
    /// It's `arena`'s owner's responsibility to call mmap() for the registered files at the end.
    fn register_mmap_file(
        &mut self,
        arena: &'a Arena<'a>,
        block_num: usize,
        file: &File,
        file_size: usize,
        mut file_offset: usize,
    ) -> Result<(Vec<BlockId>, usize)> {
        let contig_blocks = self.allocate_contiguous_blocks(block_num as u16)?;

        let mut remaining = std::cmp::min(file_size - file_offset, block_num * BLOCK_SIZE);
        let mut written = 0;
        for blocks in &contig_blocks {
            if remaining == 0 {
                panic!("remaining == 0. This is a bug");
            }
            let length = std::cmp::min(remaining, BLOCK_SIZE * blocks.len());
            let start_block = blocks[0];
            // Reserve the region in arena to prevent from overwriting metadata.
            arena
                .reserve_for_mmap(
                    start_block,
                    length,
                    file.try_clone().context("failed to clone file")?,
                    file_offset,
                )
                .context("mmap for direct_block is already occupied")?;
            remaining -= length;
            written += length;
            file_offset += length;
        }
        Ok((contig_blocks.concat(), written))
    }

    fn fill_indirect_block(
        &mut self,
        arena: &'a Arena<'a>,
        indirect_table: BlockId,
        file: &File,
        file_size: usize,
        file_offset: usize,
    ) -> Result<usize> {
        let block_size = self.block_size() as usize;
        // We use a block as a table of indirect blocks.
        // So, the maximum number of blocks supported by single indirect blocks is limited by the
        // maximum number of entries in one block, which is (block_size / 4) where 4 is the size of
        // int.
        let max_num_blocks = block_size / 4;
        let max_data_len = max_num_blocks * block_size;

        let length = std::cmp::min(file_size - file_offset, max_data_len);
        let block_num = length.div_ceil(block_size);

        let (allocated_blocks, length) = self
            .register_mmap_file(arena, block_num, file, file_size, file_offset)
            .context("failed to reserve mmap regions on indirect block")?;

        let slice = arena.allocate_slice(indirect_table, 0, 4 * block_num)?;
        slice.copy_from_slice(allocated_blocks.as_bytes());

        Ok(length)
    }

    fn add_file(
        &mut self,
        arena: &'a Arena<'a>,
        parent_inode: InodeNum,
        path: &Path,
    ) -> Result<()> {
        let inode_num = self.allocate_inode()?;

        let name = path
            .file_name()
            .ok_or_else(|| anyhow!("failed to get directory name"))?;
        let file = File::open(path)?;
        let file_size = file.metadata()?.len() as usize;
        let block_size = self.block_size() as usize;
        let mut block = InodeBlock::default();

        let mut written = 0;
        let mut used_blocks = 0;

        if file_size > 0 {
            let block_num = std::cmp::min(
                file_size.div_ceil(block_size),
                InodeBlock::NUM_DIRECT_BLOCKS,
            );
            let (allocated_blocks, len) = self
                .register_mmap_file(arena, block_num, &file, file_size, 0)
                .context("failed to reserve mmap regions on direct block")?;

            block.set_direct_blocks(&allocated_blocks)?;
            written += len;
            used_blocks += block_num;
        }

        // Indirect data block
        if written < file_size {
            let indirect_table = self.allocate_block()?;
            block.set_indirect_block_table(&indirect_table)?;
            used_blocks += 1;

            let length =
                self.fill_indirect_block(arena, indirect_table, &file, file_size, written)?;
            written += length;
            used_blocks += length.div_ceil(block_size);
        }

        // Double-indirect data block
        // Supporting double-indirect data block allows storing ~4GB files if 4GB block size is
        // used.
        if written < file_size {
            let d_indirect_table = self.allocate_block()?;
            block.set_double_indirect_block_table(&d_indirect_table)?;
            used_blocks += 1;

            let mut indirect_blocks: Vec<BlockId> = vec![];
            // Iterate (block_size / 4) times, as each block id is 4-byte.
            for _ in 0..block_size / 4 {
                if written >= file_size {
                    break;
                }
                let indirect_table = self.allocate_block()?;
                indirect_blocks.push(indirect_table);
                used_blocks += 1;

                let length = self
                    .fill_indirect_block(arena, indirect_table, &file, file_size, written)
                    .context("failed to indirect block for doubly-indirect table")?;
                written += length;
                used_blocks += length.div_ceil(block_size);
            }

            let d_table = arena.allocate_slice(d_indirect_table, 0, indirect_blocks.len() * 4)?;
            d_table.copy_from_slice(indirect_blocks.as_bytes());
        }

        if written != file_size {
            unimplemented!("Triple-indirect block is not supported");
        }

        let blocks = InodeBlocksCount::from_bytes_len((used_blocks * block_size) as u32);
        let group_id = self.group_num_for_inode(inode_num);
        let size = file_size as u32;
        let inode = Inode::from_metadata(
            arena,
            &mut self.group_metadata[group_id],
            inode_num,
            &std::fs::metadata(path)?,
            size,
            1,
            blocks,
            block,
        )?;

        self.add_inode(inode_num, inode)?;

        self.allocate_dir_entry(arena, parent_inode, inode_num, InodeType::Regular, name)?;

        Ok(())
    }

    fn add_symlink(
        &mut self,
        arena: &'a Arena<'a>,
        parent: InodeNum,
        entry: &DirEntry,
    ) -> Result<()> {
        let link = entry.path();
        let dst_path = std::fs::read_link(&link)?;
        let dst = dst_path
            .to_str()
            .context("failed to convert symlink destination to str")?;

        if dst.len() >= InodeBlock::max_inline_symlink_len() {
            return self.add_long_symlink(arena, parent, &link, dst);
        }

        let inode_num = self.allocate_inode()?;
        let mut block = InodeBlock::default();
        block.set_inline_symlink(dst)?;
        let group_id = self.group_num_for_inode(inode_num);
        let inode = Inode::from_metadata(
            arena,
            &mut self.group_metadata[group_id],
            inode_num,
            &std::fs::symlink_metadata(&link)?,
            dst.len() as u32,
            1, //links_count,
            InodeBlocksCount::from_bytes_len(0),
            block,
        )?;
        self.add_inode(inode_num, inode)?;

        let link_name = link.file_name().context("failed to get symlink name")?;
        self.allocate_dir_entry(arena, parent, inode_num, InodeType::Symlink, link_name)?;

        Ok(())
    }

    fn add_long_symlink(
        &mut self,
        arena: &'a Arena<'a>,
        parent: InodeNum,
        link: &Path,
        dst: &str,
    ) -> Result<()> {
        let dst_len = dst.len();
        if dst_len > self.block_size() as usize {
            bail!("symlink longer than block size: {:?}", dst);
        }

        // Copy symlink's destination to the block.
        let symlink_block = self.allocate_block()?;
        let buf = arena.allocate_slice(symlink_block, 0, dst_len)?;
        buf.copy_from_slice(dst.as_bytes());

        let inode_num = self.allocate_inode()?;
        let mut block = InodeBlock::default();
        block.set_direct_blocks(&[symlink_block])?;

        let block_size = self.block_size() as u32;
        let group_id = self.group_num_for_inode(inode_num);
        let inode = Inode::from_metadata(
            arena,
            &mut self.group_metadata[group_id],
            inode_num,
            &std::fs::symlink_metadata(link)?,
            dst_len as u32,
            1, //links_count,
            InodeBlocksCount::from_bytes_len(block_size),
            block,
        )?;
        self.add_inode(inode_num, inode)?;

        let link_name = link.file_name().context("failed to get symlink name")?;
        self.allocate_dir_entry(arena, parent, inode_num, InodeType::Symlink, link_name)?;

        Ok(())
    }

    /// Walks through `src_dir` and copies directories and files to the new file system.
    fn copy_dirtree<P: AsRef<Path>>(&mut self, arena: &'a Arena<'a>, src_dir: P) -> Result<()> {
        self.copy_dirtree_rec(arena, InodeNum(2), src_dir)
    }

    fn copy_dirtree_rec<P: AsRef<Path>>(
        &mut self,
        arena: &'a Arena<'a>,
        parent_inode: InodeNum,
        src_dir: P,
    ) -> Result<()> {
        for entry in std::fs::read_dir(&src_dir)? {
            let entry = entry?;
            let ftype = entry.file_type()?;
            if ftype.is_dir() {
                // Since we creates `/lost+found` on the root directory, ignore the existing one.
                if parent_inode.0 == 2 && entry.path().file_name() == Some(OsStr::new("lost+found"))
                {
                    info!("ext2: Ignore the existing /lost+found directory");
                    continue;
                }
                let inode = self.allocate_inode()?;
                self.add_dir(arena, inode, parent_inode, &entry.path())
                    .with_context(|| {
                        format!(
                            "failed to add directory {:?} as inode={:?}",
                            entry.path(),
                            inode
                        )
                    })?;
                self.copy_dirtree_rec(arena, inode, entry.path())?;
            } else if ftype.is_file() {
                self.add_file(arena, parent_inode, &entry.path())
                    .with_context(|| {
                        format!(
                            "failed to add file {:?} in inode={:?}",
                            entry.path(),
                            parent_inode
                        )
                    })?;
            } else if ftype.is_symlink() {
                self.add_symlink(arena, parent_inode, &entry)?;
            } else {
                panic!("unknown file type: {:?}", ftype);
            }
        }

        Ok(())
    }

    fn copy_backup_metadata(self, arena: &'a Arena<'a>) -> Result<()> {
        // Copy superblock and group_metadata to every block group
        for i in 1..self.sb.num_groups() as usize {
            let super_block_id = BlockId::from(self.sb.blocks_per_group * i as u32);
            let bg_desc_block_id = BlockId::from(u32::from(super_block_id) + 1);
            self.sb.block_group_nr = i as u16;
            arena.write_to_mem(super_block_id, 0, self.sb)?;
            let mut offset = 0;
            for gm in &self.group_metadata {
                arena.write_to_mem(bg_desc_block_id, offset, gm.group_desc)?;
                offset += std::mem::size_of::<BlockGroupDescriptor>();
            }
        }
        Ok(())
    }
}

/// Creates a memory mapping region where an ext2 filesystem is constructed.
pub fn create_ext2_region(cfg: &Config, src_dir: Option<&Path>) -> Result<MemoryMappingArena> {
    let block_group_size = BLOCK_SIZE as u32 * cfg.blocks_per_group;
    if cfg.size < block_group_size {
        bail!(
            "memory size {} is too small to have a block group: block_size={},  block_per_group={}",
            cfg.size,
            BLOCK_SIZE,
            block_group_size
        );
    }
    let mem_size = if cfg.size % block_group_size == 0 {
        cfg.size
    } else {
        // Round down to the largest multiple of block_group_size that is smaller than cfg.size
        cfg.size.next_multiple_of(block_group_size) - block_group_size
    };

    let mut mem = MemoryMappingBuilder::new(mem_size as usize).build()?;

    let arena = Arena::new(BLOCK_SIZE, &mut mem)?;
    let mut ext2 = Ext2::new(cfg, &arena)?;
    if let Some(dir) = src_dir {
        ext2.copy_dirtree(&arena, dir)?;
    }
    ext2.copy_backup_metadata(&arena)?;
    let file_mappings = arena.into_mapping_info();

    mem.msync()?;
    let mut mmap_arena = MemoryMappingArena::from(mem);
    for FileMappingInfo {
        start_block,
        file,
        length,
        file_offset,
    } in file_mappings
    {
        mmap_arena.add_fd_mapping(
            u32::from(start_block) as usize * BLOCK_SIZE,
            length,
            &file,
            file_offset as u64, /* fd_offset */
            Protection::read(),
        )?;
    }

    Ok(mmap_arena)
}
