// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Defines the inode structure.

use std::os::linux::fs::MetadataExt;

use anyhow::bail;
use anyhow::Result;
use enumn::N;
use zerocopy::AsBytes;
use zerocopy_derive::FromBytes;
use zerocopy_derive::FromZeroes;

use crate::arena::Arena;
use crate::arena::BlockId;
use crate::blockgroup::GroupMetaData;

/// Types of inodes.
#[derive(Debug, PartialEq, Eq, Clone, Copy, N)]
pub enum InodeType {
    Fifo = 0x1,
    Char = 0x2,
    Directory = 0x4,
    Block = 0x6,
    Regular = 0x8,
    Symlink = 0xa,
    Socket = 0xc,
}

impl InodeType {
    /// Converts to a file type for directory entry.
    /// The value is defined in "Table 4.2. Defined Inode File Type Values" in the spec.
    pub fn into_dir_entry_file_type(self) -> u8 {
        match self {
            InodeType::Regular => 1,
            InodeType::Directory => 2,
            InodeType::Char => 3,
            InodeType::Block => 4,
            InodeType::Fifo => 5,
            InodeType::Socket => 6,
            InodeType::Symlink => 7,
        }
    }
}

// Represents an inode number.
// This is 1-indexed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct InodeNum(pub u32);

impl InodeNum {
    pub fn new(inode: u32) -> Result<Self> {
        if inode == 0 {
            bail!("inode number is 1-indexed");
        }
        Ok(Self(inode))
    }

    // Returns index in the inode table.
    pub fn to_table_index(self) -> usize {
        // (num - 1) because inode is 1-indexed.
        self.0 as usize - 1
    }
}

impl From<InodeNum> for u32 {
    fn from(inode: InodeNum) -> Self {
        inode.0
    }
}

impl From<InodeNum> for usize {
    fn from(inode: InodeNum) -> Self {
        inode.0 as usize
    }
}

/// Size of the `block` field in Inode.
const INODE_BLOCK_LEN: usize = 60;
/// Represents 60-byte region for block in Inode.
/// This region is used for various ways depending on the file type.
/// For regular files and directories, it's used for storing 32-bit indices of blocks.
///
/// This is a wrapper of `[u8; 60]` to implement `Default` manually.
#[repr(C)]
#[derive(Debug, Copy, Clone, FromZeroes, FromBytes, AsBytes)]
pub(crate) struct InodeBlock(pub [u8; INODE_BLOCK_LEN]);

impl Default for InodeBlock {
    fn default() -> Self {
        Self([0; INODE_BLOCK_LEN])
    }
}

impl InodeBlock {
    // Each inode contains 12 direct pointers (0-11), one singly indirect pointer (12), one
    // doubly indirect block pointer (13), and one triply indirect pointer (14).
    pub const NUM_DIRECT_BLOCKS: usize = 12;
    const INDIRECT_BLOCK_TABLE_ID: usize = Self::NUM_DIRECT_BLOCKS;
    const DOUBLE_INDIRECT_BLOCK_TABLE_ID: usize = 13;

    /// Set a block id at the given index.
    fn set_block_id(&mut self, index: usize, block_id: &BlockId) -> Result<()> {
        let offset = index * std::mem::size_of::<BlockId>();
        let bytes = block_id.as_bytes();
        if self.0.len() < offset + bytes.len() {
            bail!("index out of bounds when setting block_id to InodeBlock: index={index}, block_id: {:?}", block_id);
        }
        self.0[offset..offset + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }

    /// Set an array of direct block IDs.
    pub fn set_direct_blocks(&mut self, block_ids: &[BlockId]) -> Result<()> {
        let bytes = block_ids.as_bytes();
        if bytes.len() > self.0.len() {
            bail!(
                "length of direct blocks is {} bytes, but it must not exceed {}",
                bytes.len(),
                self.0.len()
            );
        }
        self.0[..bytes.len()].copy_from_slice(bytes);
        Ok(())
    }

    /// Set a block id to be used as the indirect block table.
    pub fn set_indirect_block_table(&mut self, block_id: &BlockId) -> Result<()> {
        self.set_block_id(Self::INDIRECT_BLOCK_TABLE_ID, block_id)
    }

    /// Set a block id to be used as the double indirect block table.
    pub fn set_double_indirect_block_table(&mut self, block_id: &BlockId) -> Result<()> {
        self.set_block_id(Self::DOUBLE_INDIRECT_BLOCK_TABLE_ID, block_id)
    }

    /// Returns the max length of symbolic links that can be stored in the inode data.
    /// This length contains the trailing `\0`.
    pub const fn max_inline_symlink_len() -> usize {
        INODE_BLOCK_LEN
    }

    /// Stores a given string as an inlined symbolic link data.
    pub fn set_inline_symlink(&mut self, symlink: &str) -> Result<()> {
        let bytes = symlink.as_bytes();
        if bytes.len() >= Self::max_inline_symlink_len() {
            bail!(
                "symlink '{symlink}' exceeds or equals tomax length: {} >= {}",
                bytes.len(),
                Self::max_inline_symlink_len()
            );
        }
        self.0[..bytes.len()].copy_from_slice(bytes);
        Ok(())
    }
}

/// The ext2 inode.
///
/// The field names are based on [the specification](https://www.nongnu.org/ext2-doc/ext2.html#inode-table).
#[repr(C)]
#[derive(Default, Debug, Copy, Clone, FromZeroes, FromBytes, AsBytes)]
pub(crate) struct Inode {
    mode: u16,
    _uid: u16,
    size: u32,
    atime: u32,
    ctime: u32,
    mtime: u32,
    _dtime: u32,
    _gid: u16,
    pub links_count: u16,
    pub blocks: InodeBlocksCount,
    _flags: u32,
    _osd1: u32,
    pub block: InodeBlock,
    _generation: u32,
    _file_acl: u32,
    _dir_acl: u32,
    _faddr: u32,
    _fragment_num: u8,
    _fragment_size: u8,
    _reserved1: u16,
    _uid_high: u16,
    _gid_high: u16,
    _reserved2: u32,
}

/// Used in `Inode` to represent how many 512-byte blocks are used by a file.
///
/// The block size '512' byte is fixed and not related to the actual block size of the file system.
/// For more details, see notes for `i_blocks_lo` in the specification.
#[repr(C)]
#[derive(Default, Debug, Copy, Clone, FromZeroes, FromBytes, AsBytes)]
pub struct InodeBlocksCount(u32);

impl InodeBlocksCount {
    pub fn from_bytes_len(len: u32) -> Self {
        Self(len / 512)
    }
}

impl Inode {
    /// Size of the inode record in bytes.
    /// Its return value must be stored in `Superblock` and used to calculate the size of
    /// inode tables.
    ///
    /// Note that inode "record" size can be larger that inode "structure" size.
    /// The gap between the end of the inode structure and the end of the inode record can be used
    /// to store extended attributes.
    pub fn inode_record_size() -> u16 {
        // TODO(b/333988434): Support larger inode size (258 bytes) for extended attributes.
        const EXT2_GOOD_OLD_INODE_SIZE: u16 = 128;
        EXT2_GOOD_OLD_INODE_SIZE
    }

    pub fn new<'a>(
        arena: &'a Arena<'a>,
        group: &mut GroupMetaData,
        inode_num: InodeNum,
        typ: InodeType,
        size: u32,
    ) -> Result<&'a mut Self> {
        const EXT2_S_IRUSR: u16 = 0x0100; // user read
        const EXT2_S_IXUSR: u16 = 0x0040; // user execute
        const EXT2_S_IRGRP: u16 = 0x0020; // group read
        const EXT2_S_IXGRP: u16 = 0x0008; // group execute
        const EXT2_S_IROTH: u16 = 0x0004; // others read
        const EXT2_S_IXOTH: u16 = 0x0001; // others execute

        let inode_offset = inode_num.to_table_index() * Inode::inode_record_size() as usize;
        let inode =
            arena.allocate::<Inode>(BlockId::from(group.group_desc.inode_table), inode_offset)?;

        // Give read and execute permissions
        let mode = ((typ as u16) << 12)
            | EXT2_S_IRUSR
            | EXT2_S_IXUSR
            | EXT2_S_IRGRP
            | EXT2_S_IXGRP
            | EXT2_S_IROTH
            | EXT2_S_IXOTH;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as u32;

        // SAFETY: geteuid never fail.
        let uid = unsafe { libc::geteuid() };
        let uid_high = (uid >> 16) as u16;
        let uid_low = uid as u16;
        // SAFETY: getegid never fail.
        let gid = unsafe { libc::getegid() };
        let gid_high = (gid >> 16) as u16;
        let gid_low = gid as u16;

        // TODO(b/333988434): Support extended attributes.
        *inode = Self {
            mode,
            size,
            atime: now,
            ctime: now,
            mtime: now,
            _uid: uid_low,
            _gid: gid_low,
            _uid_high: uid_high,
            _gid_high: gid_high,
            ..Default::default()
        };
        Ok(inode)
    }

    pub fn from_metadata<'a>(
        arena: &'a Arena<'a>,
        group: &mut GroupMetaData,
        inode_num: InodeNum,
        m: &std::fs::Metadata,
        size: u32,
        links_count: u16,
        blocks: InodeBlocksCount,
        block: InodeBlock,
    ) -> Result<&'a mut Self> {
        // (inode_num - 1) because inode is 1-indexed.
        let inode_offset = (usize::from(inode_num) - 1) * Inode::inode_record_size() as usize;
        let inode =
            arena.allocate::<Inode>(BlockId::from(group.group_desc.inode_table), inode_offset)?;

        let mode = m.st_mode() as u16;

        let uid = m.st_uid();
        let uid_high = (uid >> 16) as u16;
        let uid_low: u16 = uid as u16;
        let gid = m.st_gid();
        let gid_high = (gid >> 16) as u16;
        let gid_low: u16 = gid as u16;

        let atime = m.st_atime() as u32;
        let ctime = m.st_ctime() as u32;
        let mtime = m.st_mtime() as u32;

        *inode = Inode {
            mode,
            _uid: uid_low,
            _gid: gid_low,
            size,
            atime,
            ctime,
            mtime,
            links_count,
            blocks,
            block,

            _uid_high: uid_high,
            _gid_high: gid_high,

            ..Default::default()
        };
        Ok(inode)
    }

    pub fn typ(&self) -> Option<InodeType> {
        InodeType::n((self.mode >> 12) as u8)
    }
}
