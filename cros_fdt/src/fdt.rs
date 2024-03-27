// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This module writes Flattened Devicetree blobs as defined here:
//! <https://devicetree-specification.readthedocs.io/en/stable/flattened-format.html>

use std::collections::BTreeMap;
use std::convert::TryInto;
use std::io;

use indexmap::map::Entry;
use indexmap::IndexMap;
use remain::sorted;
use thiserror::Error as ThisError;

use crate::path::Path;
use crate::propval::FromFdtPropval;
use crate::propval::ToFdtPropval;

pub(crate) const SIZE_U32: usize = std::mem::size_of::<u32>();
pub(crate) const SIZE_U64: usize = std::mem::size_of::<u64>();

#[sorted]
#[derive(ThisError, Debug)]
pub enum Error {
    #[error("Error applying device tree overlay: {}", .0)]
    ApplyOverlayError(String),
    #[error("Binary size must fit in 32 bits")]
    BinarySizeTooLarge,
    #[error("Duplicate node {}", .0)]
    DuplicateNode(String),
    #[error("I/O error dumping FDT to file code={} path={}", .0, .1.display())]
    FdtDumpIoError(io::Error, std::path::PathBuf),
    #[error("Error writing FDT to guest memory")]
    FdtGuestMemoryWriteError,
    #[error("I/O error code={0}")]
    FdtIoError(io::Error),
    #[error("Parse error reading FDT parameters: {}", .0)]
    FdtParseError(String),
    #[error("Error applying FDT tree filter: {}", .0)]
    FilterError(String),
    #[error("Invalid name string: {}", .0)]
    InvalidName(String),
    #[error("Invalid path: {}", .0)]
    InvalidPath(String),
    #[error("Invalid string value {}", .0)]
    InvalidString(String),
    #[error("Expected phandle value for IOMMU of type: {}, id: {:?}", .0, .1)]
    MissingIommuPhandle(String, Option<u32>),
    #[error("Property value is not valid")]
    PropertyValueInvalid,
    #[error("Property value size must fit in 32 bits")]
    PropertyValueTooLarge,
    #[error("Total size must fit in 32 bits")]
    TotalSizeTooLarge,
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::FdtIoError(value)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
type Blob<'a> = &'a [u8];

const FDT_BEGIN_NODE: u32 = 0x00000001;
const FDT_END_NODE: u32 = 0x00000002;
const FDT_PROP: u32 = 0x00000003;
const FDT_NOP: u32 = 0x00000004;
const FDT_END: u32 = 0x00000009;

// Consume and return `n` bytes from the beginning of a slice.
fn consume<'a>(bytes: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
    let mid = n;
    if mid > bytes.len() {
        Err(Error::PropertyValueInvalid)
    } else {
        let (data_bytes, rest) = bytes.split_at(n);
        *(bytes) = rest;
        Ok(data_bytes)
    }
}

// Consume a u32 from a byte slice.
#[inline]
fn rdu32(data: &mut Blob) -> Result<u32> {
    Ok(u32::from_be_bytes(
        // Unwrap won't panic because the slice length is checked in consume().
        consume(data, SIZE_U32)?.try_into().unwrap(),
    ))
}

// Consume a u64 from a byte slice.
#[inline]
fn rdu64(data: &mut Blob) -> Result<u64> {
    Ok(u64::from_be_bytes(
        // Unwrap won't panic because the slice length is checked in consume().
        consume(data, SIZE_U64)?.try_into().unwrap(),
    ))
}

// Return the number of padding bytes required to align `size` to `alignment`.
#[inline]
fn align_pad_len(size: usize, alignment: usize) -> usize {
    (alignment - size % alignment) % alignment
}

// Pad a byte vector to given alignment.
#[inline]
fn align_data(data: &mut Vec<u8>, alignment: usize) {
    data.resize(align_pad_len(data.len(), alignment) + data.len(), 0u8);
}

// Construct a string from the start of a byte slice until the first null byte.
pub(crate) fn c_str_to_string(input: Blob) -> Option<String> {
    let size = input.iter().position(|&v| v == 0u8)?;
    String::from_utf8(input[..size].to_vec()).ok()
}

// Verify FDT property name.
fn is_valid_prop_name(name: &str) -> bool {
    const ALLOWED_SPECIAL_CHARS: [u8; 7] = [b'.', b',', b'_', b'+', b'?', b'#', b'-'];
    name.bytes()
        .all(|c| c.is_ascii_alphanumeric() || ALLOWED_SPECIAL_CHARS.contains(&c))
}

// Verify FDT node name.
fn is_valid_node_name(name: &str) -> bool {
    const ALLOWED_SPECIAL_CHARS: [u8; 6] = [b'.', b',', b'_', b'+', b'-', b'@'];
    const ADDR_SEP: u8 = b'@';
    // At most one `@` separating node-name and unit-address
    if name.bytes().filter(|&c| c == ADDR_SEP).count() > 1 {
        return false;
    }
    name.bytes()
        .all(|c| c.is_ascii_alphanumeric() || ALLOWED_SPECIAL_CHARS.contains(&c))
}

// An implementation of FDT header.
#[derive(Default, Debug)]
struct FdtHeader {
    magic: u32,             // magic word
    total_size: u32,        // total size of DT block
    off_dt_struct: u32,     // offset to structure
    off_dt_strings: u32,    // offset to strings
    off_mem_rsvmap: u32,    // offset to memory reserve map
    version: u32,           // format version
    last_comp_version: u32, // last compatible version
    boot_cpuid_phys: u32,   // Which physical CPU id we're booting on
    size_dt_strings: u32,   // size of the strings block
    size_dt_struct: u32,    // size of the structure block
}

impl FdtHeader {
    const MAGIC: u32 = 0xd00dfeed;
    const VERSION: u32 = 17;
    const LAST_COMP_VERSION: u32 = 16;
    const SIZE: usize = 10 * SIZE_U32;

    // Create a new FdtHeader instance.
    fn new(
        total_size: u32,
        off_dt_struct: u32,
        off_dt_strings: u32,
        off_mem_rsvmap: u32,
        boot_cpuid_phys: u32,
        size_dt_strings: u32,
        size_dt_struct: u32,
    ) -> Self {
        Self {
            magic: Self::MAGIC,
            total_size,
            off_dt_struct,
            off_dt_strings,
            off_mem_rsvmap,
            version: Self::VERSION,
            last_comp_version: Self::LAST_COMP_VERSION,
            boot_cpuid_phys,
            size_dt_strings,
            size_dt_struct,
        }
    }

    // Dump FDT header to a byte vector.
    fn write_blob(&self, buffer: &mut [u8]) -> Result<()> {
        assert_eq!(buffer.len(), Self::SIZE);
        for (chunk, val_u32) in buffer.chunks_exact_mut(SIZE_U32).zip(&[
            self.magic,
            self.total_size,
            self.off_dt_struct,
            self.off_dt_strings,
            self.off_mem_rsvmap,
            self.version,
            self.last_comp_version,
            self.boot_cpuid_phys,
            self.size_dt_strings,
            self.size_dt_struct,
        ]) {
            chunk.copy_from_slice(&val_u32.to_be_bytes());
        }
        Ok(())
    }

    // Load FDT header from a byte slice.
    fn from_blob(mut input: Blob) -> Result<Self> {
        if input.len() < Self::SIZE {
            return Err(Error::FdtParseError("invalid binary size".into()));
        }
        let input = &mut input;
        let header = Self {
            magic: rdu32(input)?,
            total_size: rdu32(input)?,
            off_dt_struct: rdu32(input)?,
            off_dt_strings: rdu32(input)?,
            off_mem_rsvmap: rdu32(input)?,
            version: rdu32(input)?,
            last_comp_version: rdu32(input)?,
            boot_cpuid_phys: rdu32(input)?,
            size_dt_strings: rdu32(input)?,
            size_dt_struct: rdu32(input)?,
        };
        if header.magic != Self::MAGIC {
            return Err(Error::FdtParseError("invalid header magic".into()));
        }
        if header.version < Self::VERSION {
            return Err(Error::FdtParseError("unsupported FDT version".into()));
        }
        if header.off_mem_rsvmap >= header.off_dt_strings
            || header.off_mem_rsvmap < FdtHeader::SIZE as u32
        {
            return Err(Error::FdtParseError(
                "invalid reserved memory offset".into(),
            ));
        }

        let off_dt_struct_end = header
            .off_dt_struct
            .checked_add(header.size_dt_struct)
            .ok_or_else(|| Error::FdtParseError("struct end offset must fit in 32 bits".into()))?;
        if off_dt_struct_end > header.off_dt_strings {
            return Err(Error::FdtParseError("struct and strings overlap".into()));
        }

        let off_dt_strings_end = header
            .off_dt_strings
            .checked_add(header.size_dt_strings)
            .ok_or_else(|| Error::FdtParseError("strings end offset must fit in 32 bits".into()))?;
        if off_dt_strings_end > header.total_size {
            return Err(Error::FdtParseError("strings data past total size".into()));
        }

        Ok(header)
    }
}

// An implementation of FDT strings block (property names)
#[derive(Default)]
struct FdtStrings {
    strings: Vec<u8>,
    string_offsets: BTreeMap<String, u32>,
}

impl FdtStrings {
    // Load the strings block from a byte slice.
    fn from_blob(input: Blob) -> Result<Self> {
        if input.last().map_or(false, |i| *i != 0) {
            return Err(Error::FdtParseError(
                "strings block missing null terminator".into(),
            ));
        }
        let mut string_offsets = BTreeMap::new();
        let mut offset = 0u32;
        for bytes in input.split(|&x| x == 0u8) {
            if bytes.is_empty() {
                break;
            }
            let string = String::from_utf8(bytes.to_vec())
                .map_err(|_| Error::FdtParseError("invalid value in strings block".into()))?;
            string_offsets.insert(string, offset);
            offset += u32::try_from(bytes.len() + 1).map_err(|_| Error::BinarySizeTooLarge)?;
        }
        Ok(Self {
            strings: input.to_vec(),
            string_offsets,
        })
    }

    // Find an existing instance of a string `s`, or add it to the strings block.
    // Returns the offset into the strings block.
    fn intern_string(&mut self, s: &str) -> u32 {
        if let Some(off) = self.string_offsets.get(s) {
            *off
        } else {
            let off = self.strings.len() as u32;
            self.strings.extend_from_slice(s.as_bytes());
            self.strings.push(0u8);
            self.string_offsets.insert(s.to_owned(), off);
            off
        }
    }

    // Write the strings blob to a `Write` object.
    fn write_blob(&self, mut writer: impl io::Write) -> Result<()> {
        Ok(writer.write_all(&self.strings)?)
    }

    // Return the string at given offset or `None` if such a string doesn't exist.
    fn at_offset(&self, off: u32) -> Option<String> {
        self.strings
            .get(off as usize..)
            .and_then(c_str_to_string)
            .filter(|s| !s.is_empty())
    }
}

/// Flattened device tree node.
///
/// This represents a single node from the FDT structure block. Every node may contain properties
/// and other (child) nodes.
#[derive(Debug, Clone)]
pub struct FdtNode {
    /// Node name
    pub(crate) name: String,
    pub(crate) props: IndexMap<String, Vec<u8>>,
    pub(crate) subnodes: IndexMap<String, FdtNode>,
}

impl FdtNode {
    // Create a new node with the given name, properties, and child nodes. Return an error if
    // node or property names do not satisfy devicetree naming criteria.
    pub(crate) fn new(
        name: String,
        props: IndexMap<String, Vec<u8>>,
        subnodes: IndexMap<String, FdtNode>,
    ) -> Result<Self> {
        if !is_valid_node_name(&name) {
            return Err(Error::InvalidName(name));
        }
        for pname in props.keys() {
            if !is_valid_prop_name(pname) {
                return Err(Error::InvalidName(pname.into()));
            }
        }
        Ok(Self {
            name,
            props,
            subnodes,
        })
    }

    // Create an empty node with the given name.
    pub(crate) fn empty(name: impl Into<String>) -> Result<Self> {
        FdtNode::new(name.into(), [].into(), [].into())
    }

    fn read_token(input: &mut Blob) -> Result<u32> {
        loop {
            let value = rdu32(input)?;
            if value != FDT_NOP {
                return Ok(value);
            }
        }
    }

    // Parse binary content of an FDT node.
    fn parse_node(input: &mut Blob, strings: &FdtStrings) -> Result<Self> {
        // Node name
        let name = c_str_to_string(input)
            .ok_or_else(|| Error::FdtParseError("could not parse node name".into()))?;
        let name_nbytes = name.len() + 1;
        consume(input, name_nbytes + align_pad_len(name_nbytes, SIZE_U32))?;

        // Node properties and subnodes
        let mut props = IndexMap::new();
        let mut subnodes = IndexMap::new();
        let mut encountered_subnode = false; // Properties must appear before subnodes

        loop {
            match Self::read_token(input)? {
                FDT_BEGIN_NODE => {
                    encountered_subnode = true;
                    let subnode = Self::parse_node(input, strings)?;
                    match subnodes.entry(subnode.name.clone()) {
                        Entry::Vacant(e) => e.insert(subnode),
                        Entry::Occupied(_) => return Err(Error::DuplicateNode(subnode.name)),
                    };
                }
                FDT_END_NODE => break,
                FDT_PROP => {
                    if encountered_subnode {
                        return Err(Error::FdtParseError(
                            "unexpected prop token after subnode".into(),
                        ));
                    }
                    let prop_len = rdu32(input)? as usize;
                    let prop_name_offset = rdu32(input)?;
                    let prop_blob = consume(input, prop_len + align_pad_len(prop_len, SIZE_U32))?;
                    let prop_name = strings.at_offset(prop_name_offset).ok_or_else(|| {
                        Error::FdtParseError(format!(
                            "invalid property name at {prop_name_offset:#x}",
                        ))
                    })?;
                    // Keep the original (non-aligned) size as property value
                    props.insert(prop_name, prop_blob[..prop_len].to_vec());
                }
                FDT_NOP => continue,
                FDT_END => return Err(Error::FdtParseError("unexpected END token".into())),
                t => return Err(Error::FdtParseError(format!("invalid FDT token {t}"))),
            }
        }
        FdtNode::new(name, props, subnodes)
    }

    // Load an `FdtNode` instance from a slice of bytes.
    fn from_blob(mut input: Blob, strings: &FdtStrings) -> Result<Self> {
        let input = &mut input;
        if Self::read_token(input)? != FDT_BEGIN_NODE {
            return Err(Error::FdtParseError("expected begin node token".into()));
        }
        let root = Self::parse_node(input, strings)?;
        if Self::read_token(input)? != FDT_END {
            Err(Error::FdtParseError("expected end node token".into()))
        } else {
            Ok(root)
        }
    }

    // Write binary contents of a node to a vector of bytes.
    fn write_blob(&self, writer: &mut impl io::Write, strings: &mut FdtStrings) -> Result<()> {
        // Token
        writer.write_all(&FDT_BEGIN_NODE.to_be_bytes())?;
        // Name
        writer.write_all(self.name.as_bytes())?;
        writer.write_all(&[0])?; // Node name terminator
        let pad_len = align_pad_len(self.name.len() + 1, SIZE_U32);
        writer.write_all(&vec![0; pad_len])?;
        // Properties
        for (propname, propblob) in self.props.iter() {
            // Prop token
            writer.write_all(&FDT_PROP.to_be_bytes())?;
            // Prop size
            writer.write_all(&(propblob.len() as u32).to_be_bytes())?;
            // Prop name offset
            writer.write_all(&strings.intern_string(propname).to_be_bytes())?;
            // Prop value
            writer.write_all(propblob)?;
            let pad_len = align_pad_len(propblob.len(), SIZE_U32);
            writer.write_all(&vec![0; pad_len])?;
        }
        // Subnodes
        for subnode in self.subnodes.values() {
            subnode.write_blob(writer, strings)?;
        }
        // Token
        writer.write_all(&FDT_END_NODE.to_be_bytes())?;
        Ok(())
    }

    // Iterate over property names defined for this node.
    pub(crate) fn prop_names(&self) -> impl std::iter::Iterator<Item = &str> {
        self.props.keys().map(|s| s.as_str())
    }

    // Return true if a property with the given name exists.
    pub(crate) fn has_prop(&self, name: &str) -> bool {
        self.props.contains_key(name)
    }

    /// Read property value if it exists.
    ///
    /// # Arguments
    ///
    /// `name` - name of the property.
    pub fn get_prop<T>(&self, name: &str) -> Option<T>
    where
        T: FromFdtPropval,
    {
        T::from_propval(self.props.get(name)?.as_slice())
    }

    // Read a phandle value (a `u32`) at some offset within a property value.
    // Returns `None` if a phandle value cannot be constructed.
    pub(crate) fn phandle_at_offset(&self, name: &str, offset: usize) -> Option<u32> {
        let data = self.props.get(name)?;
        data.get(offset..offset + SIZE_U32)
            .and_then(u32::from_propval)
    }

    // Overwrite a phandle value (a `u32`) at some offset within a property value.
    // Returns `Err` if the property doesn't exist, or if the property value is too short to
    // construct a `u32` at given offset. Does not change property value size.
    pub(crate) fn update_phandle_at_offset(
        &mut self,
        name: &str,
        offset: usize,
        phandle: u32,
    ) -> Result<()> {
        let propval = self
            .props
            .get_mut(name)
            .ok_or_else(|| Error::InvalidName(format!("property {name} does not exist")))?;
        if let Some(bytes) = propval.get_mut(offset..offset + SIZE_U32) {
            bytes.copy_from_slice(phandle.to_propval()?.as_slice());
            Ok(())
        } else {
            Err(Error::PropertyValueInvalid)
        }
    }

    /// Write a property.
    ///
    /// # Arguments
    ///
    /// `name` - name of the property; must be a valid property name according to DT spec.
    /// `val` - value of the property (raw byte array).
    pub fn set_prop<T>(&mut self, name: &str, value: T) -> Result<()>
    where
        T: ToFdtPropval,
    {
        if !is_valid_prop_name(name) {
            return Err(Error::InvalidName(name.into()));
        }
        let bytes = value.to_propval()?;
        // FDT property byte size must fit into a u32.
        u32::try_from(bytes.len()).map_err(|_| Error::PropertyValueTooLarge)?;
        self.props.insert(name.into(), bytes);
        Ok(())
    }

    /// Return a reference to an existing subnode with given name, or `None` if it doesn't exist.
    ///
    /// # Arguments
    ///
    /// `name` - name of the node.
    pub fn subnode(&self, name: &str) -> Option<&FdtNode> {
        self.subnodes.get(name)
    }

    /// Create a node if it doesn't already exist, and return a mutable reference to it. Return
    /// an error if the node name is not valid.
    ///
    /// # Arguments
    ///
    /// `name` - name of the node; must be a valid node name according to DT specification.
    pub fn subnode_mut(&mut self, name: &str) -> Result<&mut FdtNode> {
        if !self.subnodes.contains_key(name) {
            self.subnodes.insert(name.into(), FdtNode::empty(name)?);
        }
        Ok(self.subnodes.get_mut(name).unwrap())
    }

    // Iterate subnode references.
    pub(crate) fn iter_subnodes(&self) -> impl std::iter::Iterator<Item = &FdtNode> {
        self.subnodes.values()
    }

    // Iterate mutable subnode references.
    pub(crate) fn iter_subnodes_mut(&mut self) -> impl std::iter::Iterator<Item = &mut FdtNode> {
        self.subnodes.values_mut()
    }
}

/// Interface for creating and manipulating a Flattened Devicetree (FDT) and emitting
/// a Devicetree Blob (DTB).
///
/// # Example
///
/// ```rust
/// use cros_fdt::Fdt;
///
/// # fn main() -> cros_fdt::Result<()> {
/// let mut fdt = Fdt::new(&[]);
/// let root_node = fdt.root_mut();
/// root_node.set_prop("compatible", "linux,dummy-virt")?;
/// root_node.set_prop("#address-cells", 0x2u32)?;
/// root_node.set_prop("#size-cells", 0x2u32)?;
/// let chosen_node = root_node.subnode_mut("chosen")?;
/// chosen_node.set_prop("linux,pci-probe-only", 1u32)?;
/// chosen_node.set_prop("bootargs", "panic=-1 console=hvc0 root=/dev/vda")?;
/// let dtb = fdt.finish().unwrap();
/// # Ok(())
/// # }
/// ```
pub struct Fdt {
    pub(crate) reserved_memory: Vec<FdtReserveEntry>,
    pub(crate) root: FdtNode,
    strings: FdtStrings,
    boot_cpuid_phys: u32,
}

/// Reserved physical memory region.
///
/// This represents an area of physical memory reserved by the firmware and unusable by the OS.
/// For example, this could be used to preserve bootloader code or data used at runtime.
#[derive(Clone, PartialEq, Debug)]
pub struct FdtReserveEntry {
    /// Physical address of the beginning of the reserved region.
    pub address: u64,
    /// Size of the reserved region in bytes.
    pub size: u64,
}

// Last entry in the reserved memory section
const RESVMEM_TERMINATOR: FdtReserveEntry = FdtReserveEntry::new(0, 0);

impl FdtReserveEntry {
    /// Create a new FdtReserveEntry
    ///
    /// # Arguments
    ///
    /// `address` - start of reserved memory region.
    /// `size` - size of reserved memory region.
    pub const fn new(address: u64, size: u64) -> Self {
        Self { address, size }
    }

    // Load a reserved memory entry from a byte slice.
    fn from_blob(input: &mut Blob) -> Result<Self> {
        Ok(Self {
            address: rdu64(input)?,
            size: rdu64(input)?,
        })
    }

    // Dump the entry as a vector of bytes.
    fn write_blob(&self, mut writer: impl io::Write) -> Result<()> {
        writer.write_all(&self.address.to_be_bytes())?;
        writer.write_all(&self.size.to_be_bytes())?;
        Ok(())
    }
}

impl Fdt {
    /// Create a new flattened device tree instance with an initialized root node.
    ///
    /// # Arguments
    ///
    /// `mem_reservations` - reserved physical memory regions to list in the FDT header.
    pub fn new(mem_reservations: &[FdtReserveEntry]) -> Self {
        Self {
            reserved_memory: mem_reservations.to_vec(),
            root: FdtNode::empty("").unwrap(),
            strings: FdtStrings::default(),
            boot_cpuid_phys: 0u32,
        }
    }

    /// Set the `boot_cpuid_phys` field of the devicetree header.
    ///
    /// # Arguments
    ///
    /// `boot_cpuid_phys` - CPU ID
    pub fn set_boot_cpuid_phys(&mut self, boot_cpuid_phys: u32) {
        self.boot_cpuid_phys = boot_cpuid_phys;
    }

    // Parse the reserved memory block from a binary blob.
    fn parse_reserved_memory(mut input: Blob) -> Result<Vec<FdtReserveEntry>> {
        let mut entries = vec![];
        let input = &mut input;
        loop {
            let entry = FdtReserveEntry::from_blob(input)?;
            if entry == RESVMEM_TERMINATOR {
                break;
            }
            entries.push(entry);
        }
        Ok(entries)
    }

    // Write the reserved memory block to a buffer.
    fn write_reserved_memory(&self, mut writer: impl io::Write) -> Result<()> {
        for entry in &self.reserved_memory {
            entry.write_blob(&mut writer)?;
        }
        RESVMEM_TERMINATOR.write_blob(writer)
    }

    /// Load a flattened device tree from a byte slice.
    ///
    /// # Arguments
    ///
    /// `input` - byte slice from which to load the FDT.
    pub fn from_blob(input: Blob) -> Result<Self> {
        let header = input
            .get(..FdtHeader::SIZE)
            .ok_or_else(|| Error::FdtParseError("cannot extract header, input too small".into()))?;
        let header = FdtHeader::from_blob(header)?;
        if header.total_size as usize != input.len() {
            return Err(Error::FdtParseError("input size doesn't match".into()));
        }

        let reserved_mem_blob = &input[header.off_mem_rsvmap as usize..];
        let nodes_blob = &input[header.off_dt_struct as usize
            ..(header.off_dt_struct + header.size_dt_struct) as usize];
        let strings_blob = &input[header.off_dt_strings as usize
            ..(header.off_dt_strings + header.size_dt_strings) as usize];

        let reserved_memory = Self::parse_reserved_memory(reserved_mem_blob)?;
        let strings = FdtStrings::from_blob(strings_blob)?;
        let root = FdtNode::from_blob(nodes_blob, &strings)?;

        Ok(Self {
            reserved_memory,
            root,
            strings,
            boot_cpuid_phys: header.boot_cpuid_phys,
        })
    }

    // Write the structure block of the FDT
    fn write_struct(&mut self, mut writer: impl io::Write) -> Result<()> {
        self.root.write_blob(&mut writer, &mut self.strings)?;
        writer.write_all(&FDT_END.to_be_bytes())?;
        Ok(())
    }

    /// Finish writing the Devicetree Blob (DTB).
    ///
    /// Returns the DTB as a vector of bytes.
    pub fn finish(&mut self) -> Result<Vec<u8>> {
        let mut result = vec![0u8; FdtHeader::SIZE];
        align_data(&mut result, SIZE_U64);

        let off_mem_rsvmap = result.len();
        self.write_reserved_memory(&mut result)?;
        align_data(&mut result, SIZE_U64);

        let off_dt_struct = result.len();
        self.write_struct(&mut result)?;
        align_data(&mut result, SIZE_U32);

        let off_dt_strings = result.len();
        self.strings.write_blob(&mut result)?;
        let total_size = u32::try_from(result.len()).map_err(|_| Error::TotalSizeTooLarge)?;

        let header = FdtHeader::new(
            total_size,
            off_dt_struct as u32,
            off_dt_strings as u32,
            off_mem_rsvmap as u32,
            self.boot_cpuid_phys,
            total_size - off_dt_strings as u32, // strings size
            off_dt_strings as u32 - off_dt_struct as u32, // struct size
        );
        header.write_blob(&mut result[..FdtHeader::SIZE])?;
        Ok(result)
    }

    /// Return a mutable reference to the root node of the FDT.
    pub fn root_mut(&mut self) -> &mut FdtNode {
        &mut self.root
    }

    /// Return a reference to the node the path points to, or `None` if it doesn't exist.
    ///
    /// # Arguments
    ///
    /// `path` - device tree path of the target node.
    pub fn get_node<T: TryInto<Path>>(&self, path: T) -> Option<&FdtNode> {
        let mut result_node = &self.root;
        let path: Path = path.try_into().ok()?;
        for node_name in path.iter() {
            result_node = result_node.subnodes.get(node_name)?;
        }
        Some(result_node)
    }

    /// Return a mutable reference to the node the path points to, or `None` if it
    /// doesn't exist.
    ///
    /// # Arguments
    ///
    /// `path` - device tree path of the target node.
    pub fn get_node_mut<T: TryInto<Path>>(&mut self, path: T) -> Option<&mut FdtNode> {
        let mut result_node = &mut self.root;
        let path: Path = path.try_into().ok()?;
        for node_name in path.iter() {
            result_node = result_node.subnodes.get_mut(node_name)?;
        }
        Some(result_node)
    }

    /// Find a device tree path to the symbol exported by the FDT. The symbol must be a node label.
    ///
    /// # Arguments
    ///
    /// `symbol` - symbol to search for.
    pub fn symbol_to_path(&self, symbol: &str) -> Result<Path> {
        const SYMBOLS_NODE: &str = "__symbols__";
        let Some(symbols_node) = self.root.subnode(SYMBOLS_NODE) else {
            return Err(Error::InvalidPath("no symbols in fdt".into()));
        };
        symbols_node
            .get_prop::<String>(symbol)
            .ok_or_else(|| Error::InvalidName(format!("filter symbol {symbol} does not exist")))?
            .parse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FDT_BLOB_HEADER_ONLY: [u8; 0x48] = [
        0xd0, 0x0d, 0xfe, 0xed, // 0000: magic (0xd00dfeed)
        0x00, 0x00, 0x00, 0x48, // 0004: totalsize (0x48)
        0x00, 0x00, 0x00, 0x38, // 0008: off_dt_struct (0x38)
        0x00, 0x00, 0x00, 0x48, // 000C: off_dt_strings (0x48)
        0x00, 0x00, 0x00, 0x28, // 0010: off_mem_rsvmap (0x28)
        0x00, 0x00, 0x00, 0x11, // 0014: version (0x11 = 17)
        0x00, 0x00, 0x00, 0x10, // 0018: last_comp_version (0x10 = 16)
        0x00, 0x00, 0x00, 0x00, // 001C: boot_cpuid_phys (0)
        0x00, 0x00, 0x00, 0x00, // 0020: size_dt_strings (0)
        0x00, 0x00, 0x00, 0x10, // 0024: size_dt_struct (0x10)
        0x00, 0x00, 0x00, 0x00, // 0028: rsvmap terminator (address = 0 high)
        0x00, 0x00, 0x00, 0x00, // 002C: rsvmap terminator (address = 0 low)
        0x00, 0x00, 0x00, 0x00, // 0030: rsvmap terminator (size = 0 high)
        0x00, 0x00, 0x00, 0x00, // 0034: rsvmap terminator (size = 0 low)
        0x00, 0x00, 0x00, 0x01, // 0038: FDT_BEGIN_NODE
        0x00, 0x00, 0x00, 0x00, // 003C: node name ("") + padding
        0x00, 0x00, 0x00, 0x02, // 0040: FDT_END_NODE
        0x00, 0x00, 0x00, 0x09, // 0044: FDT_END
    ];

    const FDT_BLOB_RSVMAP: [u8; 0x68] = [
        0xd0, 0x0d, 0xfe, 0xed, // 0000: magic (0xd00dfeed)
        0x00, 0x00, 0x00, 0x68, // 0004: totalsize (0x68)
        0x00, 0x00, 0x00, 0x58, // 0008: off_dt_struct (0x58)
        0x00, 0x00, 0x00, 0x68, // 000C: off_dt_strings (0x68)
        0x00, 0x00, 0x00, 0x28, // 0010: off_mem_rsvmap (0x28)
        0x00, 0x00, 0x00, 0x11, // 0014: version (0x11 = 17)
        0x00, 0x00, 0x00, 0x10, // 0018: last_comp_version (0x10 = 16)
        0x00, 0x00, 0x00, 0x00, // 001C: boot_cpuid_phys (0)
        0x00, 0x00, 0x00, 0x00, // 0020: size_dt_strings (0)
        0x00, 0x00, 0x00, 0x10, // 0024: size_dt_struct (0x10)
        0x12, 0x34, 0x56, 0x78, // 0028: rsvmap entry 0 address high
        0xAA, 0xBB, 0xCC, 0xDD, // 002C: rsvmap entry 0 address low
        0x00, 0x00, 0x00, 0x00, // 0030: rsvmap entry 0 size high
        0x00, 0x00, 0x12, 0x34, // 0034: rsvmap entry 0 size low
        0x10, 0x20, 0x30, 0x40, // 0038: rsvmap entry 1 address high
        0x50, 0x60, 0x70, 0x80, // 003C: rsvmap entry 1 address low
        0x00, 0x00, 0x00, 0x00, // 0040: rsvmap entry 1 size high
        0x00, 0x00, 0x56, 0x78, // 0044: rsvmap entry 1 size low
        0x00, 0x00, 0x00, 0x00, // 0048: rsvmap terminator (address = 0 high)
        0x00, 0x00, 0x00, 0x00, // 004C: rsvmap terminator (address = 0 low)
        0x00, 0x00, 0x00, 0x00, // 0050: rsvmap terminator (size = 0 high)
        0x00, 0x00, 0x00, 0x00, // 0054: rsvmap terminator (size = 0 low)
        0x00, 0x00, 0x00, 0x01, // 0058: FDT_BEGIN_NODE
        0x00, 0x00, 0x00, 0x00, // 005C: node name ("") + padding
        0x00, 0x00, 0x00, 0x02, // 0060: FDT_END_NODE
        0x00, 0x00, 0x00, 0x09, // 0064: FDT_END
    ];

    const FDT_BLOB_STRINGS: [u8; 0x26] = [
        b'n', b'u', b'l', b'l', 0x00, b'u', b'3', b'2', 0x00, b'u', b'6', b'4', 0x00, b's', b't',
        b'r', 0x00, b's', b't', b'r', b'l', b's', b't', 0x00, b'a', b'r', b'r', b'u', b'3', b'2',
        0x00, b'a', b'r', b'r', b'u', b'6', b'4', 0x00,
    ];

    const EXPECTED_STRINGS: [&str; 7] = ["null", "u32", "u64", "str", "strlst", "arru32", "arru64"];

    const FDT_BLOB_NODES_ROOT_ONLY: [u8; 0x90] = [
        0x00, 0x00, 0x00, 0x01, // FDT_BEGIN_NODE
        0x00, 0x00, 0x00, 0x00, // node name ("") + padding
        0x00, 0x00, 0x00, 0x03, // FDT_PROP (null)
        0x00, 0x00, 0x00, 0x00, // prop len (0)
        0x00, 0x00, 0x00, 0x00, // prop nameoff (0)
        0x00, 0x00, 0x00, 0x03, // FDT_PROP (u32)
        0x00, 0x00, 0x00, 0x04, // prop len (4)
        0x00, 0x00, 0x00, 0x05, // prop nameoff (0x05)
        0x12, 0x34, 0x56, 0x78, // prop u32 value (0x12345678)
        0x00, 0x00, 0x00, 0x03, // FDT_PROP (u64)
        0x00, 0x00, 0x00, 0x08, // prop len (8)
        0x00, 0x00, 0x00, 0x09, // prop nameoff (0x09)
        0x12, 0x34, 0x56, 0x78, // prop u64 value high (0x12345678)
        0x87, 0x65, 0x43, 0x21, // prop u64 value low (0x87654321)
        0x00, 0x00, 0x00, 0x03, // FDT_PROP (string)
        0x00, 0x00, 0x00, 0x06, // prop len (6)
        0x00, 0x00, 0x00, 0x0D, // prop nameoff (0x0D)
        b'h', b'e', b'l', b'l', // prop str value ("hello") + padding
        b'o', 0x00, 0x00, 0x00, // "o\0" + padding
        0x00, 0x00, 0x00, 0x03, // FDT_PROP (string list)
        0x00, 0x00, 0x00, 0x07, // prop len (7)
        0x00, 0x00, 0x00, 0x11, // prop nameoff (0x11)
        b'h', b'i', 0x00, b'b', // prop value ("hi", "bye")
        b'y', b'e', 0x00, 0x00, // "ye\0" + padding
        0x00, 0x00, 0x00, 0x03, // FDT_PROP (u32 array)
        0x00, 0x00, 0x00, 0x08, // prop len (8)
        0x00, 0x00, 0x00, 0x18, // prop nameoff (0x18)
        0x12, 0x34, 0x56, 0x78, // prop value 0
        0xAA, 0xBB, 0xCC, 0xDD, // prop value 1
        0x00, 0x00, 0x00, 0x03, // FDT_PROP (u64 array)
        0x00, 0x00, 0x00, 0x08, // prop len (8)
        0x00, 0x00, 0x00, 0x1f, // prop nameoff (0x1F)
        0x12, 0x34, 0x56, 0x78, // prop u64 value 0 high
        0x87, 0x65, 0x43, 0x21, // prop u64 value 0 low
        0x00, 0x00, 0x00, 0x02, // FDT_END_NODE
        0x00, 0x00, 0x00, 0x09, // FDT_END
    ];

    /*
    Node structure:
    /
    |- nested
    |- nested2
       |- nested3
     */
    const FDT_BLOB_NESTED_NODES: [u8; 0x80] = [
        0x00, 0x00, 0x00, 0x01, // FDT_BEGIN_NODE
        0x00, 0x00, 0x00, 0x00, // node name ("") + padding
        0x00, 0x00, 0x00, 0x03, // FDT_PROP
        0x00, 0x00, 0x00, 0x04, // prop len (4)
        0x00, 0x00, 0x00, 0x00, // prop nameoff (0x00)
        0x13, 0x57, 0x90, 0x24, // prop u32 value (0x13579024)
        0x00, 0x00, 0x00, 0x01, // FDT_BEGIN_NODE
        b'n', b'e', b's', b't', // Node name ("nested")
        b'e', b'd', 0x00, 0x00, // "ed\0" + pad
        0x00, 0x00, 0x00, 0x03, // FDT_PROP
        0x00, 0x00, 0x00, 0x04, // prop len (4)
        0x00, 0x00, 0x00, 0x05, // prop nameoff (0x05)
        0x12, 0x12, 0x12, 0x12, // prop u32 value (0x12121212)
        0x00, 0x00, 0x00, 0x03, // FDT_PROP
        0x00, 0x00, 0x00, 0x04, // prop len (4)
        0x00, 0x00, 0x00, 0x18, // prop nameoff (0x18)
        0x13, 0x57, 0x90, 0x24, // prop u32 value (0x13579024)
        0x00, 0x00, 0x00, 0x02, // FDT_END_NODE ("nested")
        0x00, 0x00, 0x00, 0x01, // FDT_BEGIN_NODE
        b'n', b'e', b's', b't', // Node name ("nested2")
        b'e', b'd', b'2', 0x00, // "ed2\0"
        0x00, 0x00, 0x00, 0x03, // FDT_PROP
        0x00, 0x00, 0x00, 0x04, // prop len (0)
        0x00, 0x00, 0x00, 0x05, // prop nameoff (0x05)
        0x12, 0x12, 0x12, 0x12, // prop u32 value (0x12121212)
        0x00, 0x00, 0x00, 0x01, // FDT_BEGIN_NODE
        b'n', b'e', b's', b't', // Node name ("nested3")
        b'e', b'd', b'3', 0x00, // "ed3\0"
        0x00, 0x00, 0x00, 0x02, // FDT_END_NODE ("nested3")
        0x00, 0x00, 0x00, 0x02, // FDT_END_NODE ("nested2")
        0x00, 0x00, 0x00, 0x02, // FDT_END_NODE ("")
        0x00, 0x00, 0x00, 0x09, // FDT_END
    ];

    #[test]
    fn fdt_load_header() {
        let blob: &[u8] = &FDT_BLOB_HEADER_ONLY;
        let header = FdtHeader::from_blob(blob).unwrap();
        assert_eq!(header.magic, FdtHeader::MAGIC);
        assert_eq!(header.total_size, 0x48);
        assert_eq!(header.off_dt_struct, 0x38);
        assert_eq!(header.off_dt_strings, 0x48);
        assert_eq!(header.off_mem_rsvmap, 0x28);
        assert_eq!(header.version, 17);
        assert_eq!(header.last_comp_version, 16);
        assert_eq!(header.boot_cpuid_phys, 0);
        assert_eq!(header.size_dt_strings, 0);
        assert_eq!(header.size_dt_struct, 0x10);
    }

    #[test]
    fn fdt_load_invalid_header() {
        // HEADER is valid
        const HEADER: [u8; 40] = [
            0xd0, 0x0d, 0xfe, 0xed, // 0000: magic (0xd00dfeed)
            0x00, 0x00, 0x00, 0xda, // 0004: totalsize (0xda)
            0x00, 0x00, 0x00, 0x58, // 0008: off_dt_struct (0x58)
            0x00, 0x00, 0x00, 0xb2, // 000C: off_dt_strings (0xb2)
            0x00, 0x00, 0x00, 0x28, // 0010: off_mem_rsvmap (0x28)
            0x00, 0x00, 0x00, 0x11, // 0014: version (0x11 = 17)
            0x00, 0x00, 0x00, 0x10, // 0018: last_comp_version (0x10 = 16)
            0x00, 0x00, 0x00, 0x00, // 001C: boot_cpuid_phys (0)
            0x00, 0x00, 0x00, 0x28, // 0020: size_dt_strings (0x28)
            0x00, 0x00, 0x00, 0x5a, // 0024: size_dt_struct (0x5a)
        ];

        FdtHeader::from_blob(&HEADER).unwrap();

        // Header too small
        assert!(FdtHeader::from_blob(&HEADER[..FdtHeader::SIZE - 4]).is_err());
        assert!(FdtHeader::from_blob(&[]).is_err());

        let mut invalid_header = HEADER;
        invalid_header[0x00] = 0x00; // change magic to (0x000dfeed)
        FdtHeader::from_blob(&invalid_header).expect_err("invalid magic");

        let mut invalid_header = HEADER;
        invalid_header[0x07] = 0x10; // make totalsize too small
        FdtHeader::from_blob(&invalid_header).expect_err("invalid totalsize");

        let mut invalid_header = HEADER;
        invalid_header[0x0b] = 0x60; // increase off_dt_struct
        FdtHeader::from_blob(&invalid_header).expect_err("dt struct overlaps with strings");

        let mut invalid_header = HEADER;
        invalid_header[0x27] = 0x5c; // increase size_dt_struct
        FdtHeader::from_blob(&invalid_header).expect_err("dt struct overlaps with strings");

        let mut invalid_header = HEADER;
        invalid_header[0x13] = 0x20; // decrease off_mem_rsvmap
        FdtHeader::from_blob(&invalid_header).expect_err("reserved memory overlaps with header");

        let mut invalid_header = HEADER;
        invalid_header[0x0f] = 0x50; // decrease off_dt_strings
        FdtHeader::from_blob(&invalid_header).expect_err("strings start before struct");

        let mut invalid_header = HEADER;
        invalid_header[0x23] = 0x50; // increase size_dt_strings
        FdtHeader::from_blob(&invalid_header).expect_err("strings go past totalsize");
    }

    #[test]
    fn fdt_load_resv_map() {
        let blob: &[u8] = &FDT_BLOB_RSVMAP;
        let fdt = Fdt::from_blob(blob).unwrap();
        assert_eq!(fdt.reserved_memory.len(), 2);
        assert!(
            fdt.reserved_memory[0].address == 0x12345678AABBCCDD
                && fdt.reserved_memory[0].size == 0x1234
        );
        assert!(
            fdt.reserved_memory[1].address == 0x1020304050607080
                && fdt.reserved_memory[1].size == 0x5678
        );
    }

    #[test]
    fn fdt_test_node_props() {
        let mut node = FdtNode::empty("mynode").unwrap();
        node.set_prop("myprop", 1u32).unwrap();
        assert_eq!(node.get_prop::<u32>("myprop").unwrap(), 1u32);
        node.set_prop("myprop", 0xabcdef9876543210u64).unwrap();
        assert_eq!(
            node.get_prop::<u64>("myprop").unwrap(),
            0xabcdef9876543210u64
        );
        node.set_prop("myprop", ()).unwrap();
        assert_eq!(node.get_prop::<Vec<u8>>("myprop").unwrap(), []);
        node.set_prop("myprop", vec![1u8, 2u8, 3u8]).unwrap();
        assert_eq!(
            node.get_prop::<Vec<u8>>("myprop").unwrap(),
            vec![1u8, 2u8, 3u8]
        );
        node.set_prop("myprop", vec![1u32, 2u32, 3u32]).unwrap();
        assert_eq!(
            node.get_prop::<Vec<u32>>("myprop").unwrap(),
            vec![1u32, 2u32, 3u32]
        );
        node.set_prop("myprop", vec![1u64, 2u64, 3u64]).unwrap();
        assert_eq!(
            node.get_prop::<Vec<u64>>("myprop").unwrap(),
            vec![1u64, 2u64, 3u64]
        );
        node.set_prop("myprop", "myval".to_string()).unwrap();
        assert_eq!(
            node.get_prop::<String>("myprop").unwrap(),
            "myval".to_string()
        );
        node.set_prop(
            "myprop",
            vec![
                "myval1".to_string(),
                "myval2".to_string(),
                "myval3".to_string(),
            ],
        )
        .unwrap();
        assert_eq!(
            node.get_prop::<Vec<String>>("myprop").unwrap(),
            vec![
                "myval1".to_string(),
                "myval2".to_string(),
                "myval3".to_string()
            ]
        );
    }

    #[test]
    fn fdt_simple_use() {
        let mut fdt = Fdt::new(&[]);
        let root_node = fdt.root_mut();
        root_node
            .set_prop("compatible", "linux,dummy-virt")
            .unwrap();
        root_node.set_prop("#address-cells", 0x2u32).unwrap();
        root_node.set_prop("#size-cells", 0x2u32).unwrap();
        let chosen_node = root_node.subnode_mut("chosen").unwrap();
        chosen_node.set_prop("linux,pci-probe-only", 1u32).unwrap();
        chosen_node
            .set_prop("bootargs", "panic=-1 console=hvc0 root=/dev/vda")
            .unwrap();
        fdt.finish().unwrap();
    }

    #[test]
    fn fdt_load_strings() {
        let blob = &FDT_BLOB_STRINGS[..];
        let strings = FdtStrings::from_blob(blob).unwrap();
        let mut offset = 0u32;

        for s in EXPECTED_STRINGS {
            assert_eq!(strings.at_offset(offset).unwrap(), s);
            offset += strings.at_offset(offset).unwrap().len() as u32 + 1;
        }
    }

    #[test]
    fn fdt_load_strings_intern() {
        let strings_blob = &FDT_BLOB_STRINGS[..];
        let mut strings = FdtStrings::from_blob(strings_blob).unwrap();
        assert_eq!(strings.intern_string("null"), 0);
        assert_eq!(strings.intern_string("strlst"), 17);
        assert_eq!(strings.intern_string("arru64"), 31);
        assert_eq!(strings.intern_string("abc"), 38);
        assert_eq!(strings.intern_string("def"), 42);
        assert_eq!(strings.intern_string("strlst"), 17);
    }

    #[test]
    fn fdt_load_props() {
        const PROP_SIZES: [(&str, usize); 7] = [
            ("null", 0),
            ("u32", 4),
            ("u64", 8),
            ("str", 6),
            ("strlst", 7),
            ("arru32", 8),
            ("arru64", 8),
        ];

        let blob: &[u8] = &FDT_BLOB_STRINGS[..];
        let strings = FdtStrings::from_blob(blob).unwrap();
        let blob: &[u8] = &FDT_BLOB_NODES_ROOT_ONLY[..];
        let node = FdtNode::from_blob(blob, &strings).unwrap();

        assert_eq!(node.name, "");
        assert_eq!(node.subnodes.len(), 0);
        assert_eq!(node.props.len(), PROP_SIZES.len());

        for (pname, s) in PROP_SIZES.into_iter() {
            assert_eq!(node.get_prop::<Vec<u8>>(pname).unwrap().len(), s);
        }
    }

    #[test]
    fn fdt_load_nodes_nested() {
        let strings_blob = &FDT_BLOB_STRINGS[..];
        let strings = FdtStrings::from_blob(strings_blob).unwrap();
        let blob: &[u8] = &FDT_BLOB_NESTED_NODES[..];
        let root_node = FdtNode::from_blob(blob, &strings).unwrap();

        // Check root node
        assert_eq!(root_node.name, "");
        assert_eq!(root_node.subnodes.len(), 2);
        assert_eq!(root_node.props.len(), 1);

        // Check first nested node
        let nested_node = root_node.subnodes.get("nested").unwrap();
        assert_eq!(nested_node.name, "nested");
        assert_eq!(nested_node.subnodes.len(), 0);
        assert_eq!(nested_node.props.len(), 2);

        // Check second nested node
        let nested2_node = root_node.subnodes.get("nested2").unwrap();
        assert_eq!(nested2_node.name, "nested2");
        assert_eq!(nested2_node.subnodes.len(), 1);
        assert_eq!(nested2_node.props.len(), 1);

        // Check third nested node
        let nested3_node = nested2_node.subnodes.get("nested3").unwrap();
        assert_eq!(nested3_node.name, "nested3");
        assert_eq!(nested3_node.subnodes.len(), 0);
        assert_eq!(nested3_node.props.len(), 0);
    }

    #[test]
    fn fdt_get_node() {
        let fdt = Fdt::new(&[]);
        assert!(fdt.get_node("/").is_some());
        assert!(fdt.get_node("/a").is_none());
    }

    #[test]
    fn fdt_find_nested_node() {
        let mut fdt = Fdt::new(&[]);
        let node1 = fdt.root.subnode_mut("N1").unwrap();
        node1.subnode_mut("N1-1").unwrap();
        node1.subnode_mut("N1-2").unwrap();
        let node2 = fdt.root.subnode_mut("N2").unwrap();
        let node2_1 = node2.subnode_mut("N2-1").unwrap();
        node2_1.subnode_mut("N2-1-1").unwrap();

        assert!(fdt.get_node("/").is_some());
        assert!(fdt.get_node("/N1").is_some());
        assert!(fdt.get_node("/N2").is_some());
        assert!(fdt.get_node("/N1/N1-1").is_some());
        assert!(fdt.get_node("/N1/N1-2").is_some());
        assert!(fdt.get_node("/N2/N2-1").is_some());
        assert!(fdt.get_node("/N2/N2-1/N2-1-1").is_some());
        assert!(fdt.get_node("/N2/N2-1/A").is_none());
    }

    #[test]
    fn minimal() {
        let mut fdt = Fdt::new(&[]);
        assert_eq!(
            fdt.finish().unwrap(),
            [
                0xd0, 0x0d, 0xfe, 0xed, // 0000: magic (0xd00dfeed)
                0x00, 0x00, 0x00, 0x48, // 0004: totalsize (0x48)
                0x00, 0x00, 0x00, 0x38, // 0008: off_dt_struct (0x38)
                0x00, 0x00, 0x00, 0x48, // 000C: off_dt_strings (0x48)
                0x00, 0x00, 0x00, 0x28, // 0010: off_mem_rsvmap (0x28)
                0x00, 0x00, 0x00, 0x11, // 0014: version (0x11 = 17)
                0x00, 0x00, 0x00, 0x10, // 0018: last_comp_version (0x10 = 16)
                0x00, 0x00, 0x00, 0x00, // 001C: boot_cpuid_phys (0)
                0x00, 0x00, 0x00, 0x00, // 0020: size_dt_strings (0)
                0x00, 0x00, 0x00, 0x10, // 0024: size_dt_struct (0x10)
                0x00, 0x00, 0x00, 0x00, // 0028: rsvmap terminator (address = 0 high)
                0x00, 0x00, 0x00, 0x00, // 002C: rsvmap terminator (address = 0 low)
                0x00, 0x00, 0x00, 0x00, // 0030: rsvmap terminator (size = 0 high)
                0x00, 0x00, 0x00, 0x00, // 0034: rsvmap terminator (size = 0 low)
                0x00, 0x00, 0x00, 0x01, // 0038: FDT_BEGIN_NODE
                0x00, 0x00, 0x00, 0x00, // 003C: node name ("") + padding
                0x00, 0x00, 0x00, 0x02, // 0040: FDT_END_NODE
                0x00, 0x00, 0x00, 0x09, // 0044: FDT_END
            ]
        );
    }

    #[test]
    fn reservemap() {
        let mut fdt = Fdt::new(&[
            FdtReserveEntry {
                address: 0x12345678AABBCCDD,
                size: 0x1234,
            },
            FdtReserveEntry {
                address: 0x1020304050607080,
                size: 0x5678,
            },
        ]);
        assert_eq!(
            fdt.finish().unwrap(),
            [
                0xd0, 0x0d, 0xfe, 0xed, // 0000: magic (0xd00dfeed)
                0x00, 0x00, 0x00, 0x68, // 0004: totalsize (0x68)
                0x00, 0x00, 0x00, 0x58, // 0008: off_dt_struct (0x58)
                0x00, 0x00, 0x00, 0x68, // 000C: off_dt_strings (0x68)
                0x00, 0x00, 0x00, 0x28, // 0010: off_mem_rsvmap (0x28)
                0x00, 0x00, 0x00, 0x11, // 0014: version (0x11 = 17)
                0x00, 0x00, 0x00, 0x10, // 0018: last_comp_version (0x10 = 16)
                0x00, 0x00, 0x00, 0x00, // 001C: boot_cpuid_phys (0)
                0x00, 0x00, 0x00, 0x00, // 0020: size_dt_strings (0)
                0x00, 0x00, 0x00, 0x10, // 0024: size_dt_struct (0x10)
                0x12, 0x34, 0x56, 0x78, // 0028: rsvmap entry 0 address high
                0xAA, 0xBB, 0xCC, 0xDD, // 002C: rsvmap entry 0 address low
                0x00, 0x00, 0x00, 0x00, // 0030: rsvmap entry 0 size high
                0x00, 0x00, 0x12, 0x34, // 0034: rsvmap entry 0 size low
                0x10, 0x20, 0x30, 0x40, // 0038: rsvmap entry 1 address high
                0x50, 0x60, 0x70, 0x80, // 003C: rsvmap entry 1 address low
                0x00, 0x00, 0x00, 0x00, // 0040: rsvmap entry 1 size high
                0x00, 0x00, 0x56, 0x78, // 0044: rsvmap entry 1 size low
                0x00, 0x00, 0x00, 0x00, // 0048: rsvmap terminator (address = 0 high)
                0x00, 0x00, 0x00, 0x00, // 004C: rsvmap terminator (address = 0 low)
                0x00, 0x00, 0x00, 0x00, // 0050: rsvmap terminator (size = 0 high)
                0x00, 0x00, 0x00, 0x00, // 0054: rsvmap terminator (size = 0 low)
                0x00, 0x00, 0x00, 0x01, // 0058: FDT_BEGIN_NODE
                0x00, 0x00, 0x00, 0x00, // 005C: node name ("") + padding
                0x00, 0x00, 0x00, 0x02, // 0060: FDT_END_NODE
                0x00, 0x00, 0x00, 0x09, // 0064: FDT_END
            ]
        );
    }

    #[test]
    fn prop_null() {
        let mut fdt = Fdt::new(&[]);
        let root_node = fdt.root_mut();
        root_node.set_prop("null", ()).unwrap();
        assert_eq!(
            fdt.finish().unwrap(),
            [
                0xd0, 0x0d, 0xfe, 0xed, // 0000: magic (0xd00dfeed)
                0x00, 0x00, 0x00, 0x59, // 0004: totalsize (0x59)
                0x00, 0x00, 0x00, 0x38, // 0008: off_dt_struct (0x38)
                0x00, 0x00, 0x00, 0x54, // 000C: off_dt_strings (0x54)
                0x00, 0x00, 0x00, 0x28, // 0010: off_mem_rsvmap (0x28)
                0x00, 0x00, 0x00, 0x11, // 0014: version (0x11 = 17)
                0x00, 0x00, 0x00, 0x10, // 0018: last_comp_version (0x10 = 16)
                0x00, 0x00, 0x00, 0x00, // 001C: boot_cpuid_phys (0)
                0x00, 0x00, 0x00, 0x05, // 0020: size_dt_strings (0x05)
                0x00, 0x00, 0x00, 0x1c, // 0024: size_dt_struct (0x1C)
                0x00, 0x00, 0x00, 0x00, // 0028: rsvmap terminator (address = 0 high)
                0x00, 0x00, 0x00, 0x00, // 002C: rsvmap terminator (address = 0 low)
                0x00, 0x00, 0x00, 0x00, // 0030: rsvmap terminator (size = 0 high)
                0x00, 0x00, 0x00, 0x00, // 0034: rsvmap terminator (size = 0 low)
                0x00, 0x00, 0x00, 0x01, // 0038: FDT_BEGIN_NODE
                0x00, 0x00, 0x00, 0x00, // 003C: node name ("") + padding
                0x00, 0x00, 0x00, 0x03, // 0040: FDT_PROP
                0x00, 0x00, 0x00, 0x00, // 0044: prop len (0)
                0x00, 0x00, 0x00, 0x00, // 0048: prop nameoff (0)
                0x00, 0x00, 0x00, 0x02, // 004C: FDT_END_NODE
                0x00, 0x00, 0x00, 0x09, // 0050: FDT_END
                b'n', b'u', b'l', b'l', 0x00, // 0054: strings block
            ]
        );
    }

    #[test]
    fn prop_u32() {
        let mut fdt = Fdt::new(&[]);
        let root_node = fdt.root_mut();
        root_node.set_prop("u32", 0x12345678u32).unwrap();
        assert_eq!(
            fdt.finish().unwrap(),
            [
                0xd0, 0x0d, 0xfe, 0xed, // 0000: magic (0xd00dfeed)
                0x00, 0x00, 0x00, 0x5c, // 0004: totalsize (0x5C)
                0x00, 0x00, 0x00, 0x38, // 0008: off_dt_struct (0x38)
                0x00, 0x00, 0x00, 0x58, // 000C: off_dt_strings (0x58)
                0x00, 0x00, 0x00, 0x28, // 0010: off_mem_rsvmap (0x28)
                0x00, 0x00, 0x00, 0x11, // 0014: version (0x11 = 17)
                0x00, 0x00, 0x00, 0x10, // 0018: last_comp_version (0x10 = 16)
                0x00, 0x00, 0x00, 0x00, // 001C: boot_cpuid_phys (0)
                0x00, 0x00, 0x00, 0x04, // 0020: size_dt_strings (0x04)
                0x00, 0x00, 0x00, 0x20, // 0024: size_dt_struct (0x20)
                0x00, 0x00, 0x00, 0x00, // 0028: rsvmap terminator (address = 0 high)
                0x00, 0x00, 0x00, 0x00, // 002C: rsvmap terminator (address = 0 low)
                0x00, 0x00, 0x00, 0x00, // 0030: rsvmap terminator (size = 0 high)
                0x00, 0x00, 0x00, 0x00, // 0034: rsvmap terminator (size = 0 low)
                0x00, 0x00, 0x00, 0x01, // 0038: FDT_BEGIN_NODE
                0x00, 0x00, 0x00, 0x00, // 003C: node name ("") + padding
                0x00, 0x00, 0x00, 0x03, // 0040: FDT_PROP
                0x00, 0x00, 0x00, 0x04, // 0044: prop len (4)
                0x00, 0x00, 0x00, 0x00, // 0048: prop nameoff (0)
                0x12, 0x34, 0x56, 0x78, // 004C: prop u32 value (0x12345678)
                0x00, 0x00, 0x00, 0x02, // 0050: FDT_END_NODE
                0x00, 0x00, 0x00, 0x09, // 0054: FDT_END
                b'u', b'3', b'2', 0x00, // 0058: strings block
            ]
        );
    }

    #[test]
    fn all_props() {
        let mut fdt = Fdt::new(&[]);
        let root_node = fdt.root_mut();
        root_node
            .set_prop("arru32", &[0x12345678u32, 0xAABBCCDDu32])
            .unwrap();
        root_node
            .set_prop("arru64", &[0x1234567887654321u64])
            .unwrap();
        root_node.set_prop("null", ()).unwrap();
        root_node.set_prop("str", "hello").unwrap();
        root_node.set_prop("strlst", &["hi", "bye"]).unwrap();
        root_node.set_prop("u32", 0x12345678u32).unwrap();
        root_node.set_prop("u64", 0x1234567887654321u64).unwrap();
        assert_eq!(
            fdt.finish().unwrap(),
            [
                0xd0, 0x0d, 0xfe, 0xed, // 0000: magic (0xd00dfeed)
                0x00, 0x00, 0x00, 0xee, // 0004: totalsize (0xEE)
                0x00, 0x00, 0x00, 0x38, // 0008: off_dt_struct (0x38)
                0x00, 0x00, 0x00, 0xc8, // 000C: off_dt_strings (0xC8)
                0x00, 0x00, 0x00, 0x28, // 0010: off_mem_rsvmap (0x28)
                0x00, 0x00, 0x00, 0x11, // 0014: version (0x11 = 17)
                0x00, 0x00, 0x00, 0x10, // 0018: last_comp_version (0x10 = 16)
                0x00, 0x00, 0x00, 0x00, // 001C: boot_cpuid_phys (0)
                0x00, 0x00, 0x00, 0x26, // 0020: size_dt_strings (0x26)
                0x00, 0x00, 0x00, 0x90, // 0024: size_dt_struct (0x90)
                0x00, 0x00, 0x00, 0x00, // 0028: rsvmap terminator (address = 0 high)
                0x00, 0x00, 0x00, 0x00, // 002C: rsvmap terminator (address = 0 low)
                0x00, 0x00, 0x00, 0x00, // 0030: rsvmap terminator (size = 0 high)
                0x00, 0x00, 0x00, 0x00, // 0034: rsvmap terminator (size = 0 low)
                0x00, 0x00, 0x00, 0x01, // 0038: FDT_BEGIN_NODE
                0x00, 0x00, 0x00, 0x00, // 003C: node name ("") + padding
                0x00, 0x00, 0x00, 0x03, // 0040: FDT_PROP (u32 array)
                0x00, 0x00, 0x00, 0x08, // 0044: prop len (8)
                0x00, 0x00, 0x00, 0x00, // 0048: prop nameoff (0x00)
                0x12, 0x34, 0x56, 0x78, // 004C: prop value 0
                0xAA, 0xBB, 0xCC, 0xDD, // 0050: prop value 1
                0x00, 0x00, 0x00, 0x03, // 0054: FDT_PROP (u64 array)
                0x00, 0x00, 0x00, 0x08, // 0058: prop len (8)
                0x00, 0x00, 0x00, 0x07, // 005C: prop nameoff (0x07)
                0x12, 0x34, 0x56, 0x78, // 0060: prop u64 value 0 high
                0x87, 0x65, 0x43, 0x21, // 0064: prop u64 value 0 low
                0x00, 0x00, 0x00, 0x03, // 0068: FDT_PROP (null)
                0x00, 0x00, 0x00, 0x00, // 006C: prop len (0)
                0x00, 0x00, 0x00, 0x0E, // 0070: prop nameoff (0x0e)
                0x00, 0x00, 0x00, 0x03, // 0074: FDT_PROP (string)
                0x00, 0x00, 0x00, 0x06, // 0078: prop len (6)
                0x00, 0x00, 0x00, 0x13, // 007C: prop nameoff (0x13)
                b'h', b'e', b'l', b'l', // 0080: prop str value ("hello") + padding
                b'o', 0x00, 0x00, 0x00, // 0084: "o\0" + padding
                0x00, 0x00, 0x00, 0x03, // 0088: FDT_PROP (string list)
                0x00, 0x00, 0x00, 0x07, // 008C: prop len (7)
                0x00, 0x00, 0x00, 0x17, // 0090: prop nameoff (0x17)
                b'h', b'i', 0x00, b'b', // 0094: prop value ("hi", "bye")
                b'y', b'e', 0x00, 0x00, // 0098: "ye\0" + padding
                0x00, 0x00, 0x00, 0x03, // 009C: FDT_PROP (u32)
                0x00, 0x00, 0x00, 0x04, // 00A0: prop len (4)
                0x00, 0x00, 0x00, 0x1E, // 00A4: prop nameoff (0x1E)
                0x12, 0x34, 0x56, 0x78, // 00A8: prop u32 value (0x12345678)
                0x00, 0x00, 0x00, 0x03, // 00AC: FDT_PROP (u64)
                0x00, 0x00, 0x00, 0x08, // 00B0: prop len (8)
                0x00, 0x00, 0x00, 0x22, // 00B4: prop nameoff (0x22)
                0x12, 0x34, 0x56, 0x78, // 00B8: prop u64 value high (0x12345678)
                0x87, 0x65, 0x43, 0x21, // 00BC: prop u64 value low (0x87654321)
                0x00, 0x00, 0x00, 0x02, // 00C0: FDT_END_NODE
                0x00, 0x00, 0x00, 0x09, // 00C4: FDT_END
                b'a', b'r', b'r', b'u', b'3', b'2', 0x00, // 00C8: strings + 0x00: "arru32"
                b'a', b'r', b'r', b'u', b'6', b'4', 0x00, // 00CF: strings + 0x07: "arru64"
                b'n', b'u', b'l', b'l', 0x00, // 00D6: strings + 0x0E: "null"
                b's', b't', b'r', 0x00, // 00DB: strings + 0x13: "str"
                b's', b't', b'r', b'l', b's', b't', 0x00, // 00DF: strings + 0x17: "strlst"
                b'u', b'3', b'2', 0x00, // 00E6: strings + 0x1E: "u32"
                b'u', b'6', b'4', 0x00, // 00EA: strings + 0x22: "u64"
            ]
        );
    }

    #[test]
    fn node_order() {
        let expected: &[u8] = &[
            0xd0, 0x0d, 0xfe, 0xed, // 0000: magic (0xd00dfeed)
            0x00, 0x00, 0x00, 0x9C, // 0004: totalsize (0x9C)
            0x00, 0x00, 0x00, 0x38, // 0008: off_dt_struct (0x38)
            0x00, 0x00, 0x00, 0x9C, // 000C: off_dt_strings (0x9C)
            0x00, 0x00, 0x00, 0x28, // 0010: off_mem_rsvmap (0x28)
            0x00, 0x00, 0x00, 0x11, // 0014: version (0x11 = 17)
            0x00, 0x00, 0x00, 0x10, // 0018: last_comp_version (0x10 = 16)
            0x00, 0x00, 0x00, 0x00, // 001C: boot_cpuid_phys (0)
            0x00, 0x00, 0x00, 0x00, // 0020: size_dt_strings (0x00)
            0x00, 0x00, 0x00, 0x64, // 0024: size_dt_struct (0x64)
            0x00, 0x00, 0x00, 0x00, // 0028: rsvmap terminator (address = 0 high)
            0x00, 0x00, 0x00, 0x00, // 002C: rsvmap terminator (address = 0 low)
            0x00, 0x00, 0x00, 0x00, // 0030: rsvmap terminator (size = 0 high)
            0x00, 0x00, 0x00, 0x00, // 0034: rsvmap terminator (size = 0 low)
            0x00, 0x00, 0x00, 0x01, // 0038: FDT_BEGIN_NODE
            0x00, 0x00, 0x00, 0x00, // 003C: node name ("") + padding
            0x00, 0x00, 0x00, 0x01, // 0040: FDT_BEGIN_NODE
            b'B', 0x00, 0x00, 0x00, // 0044: node name ("B") + padding
            0x00, 0x00, 0x00, 0x02, // 0048: FDT_END_NODE
            0x00, 0x00, 0x00, 0x01, // 004C: FDT_BEGIN_NODE
            b'A', 0x00, 0x00, 0x00, // 0050: node name ("A") + padding
            0x00, 0x00, 0x00, 0x02, // 0054: FDT_END_NODE
            0x00, 0x00, 0x00, 0x01, // 0058: FDT_BEGIN_NODE
            b'C', 0x00, 0x00, 0x00, // 005C: node name ("C") + padding
            0x00, 0x00, 0x00, 0x01, // 0060: FDT_BEGIN_NODE
            b'D', 0x00, 0x00, 0x00, // 0064: node name ("D") + padding
            0x00, 0x00, 0x00, 0x02, // 0068: FDT_END_NODE
            0x00, 0x00, 0x00, 0x01, // 006C: FDT_BEGIN_NODE
            b'E', 0x00, 0x00, 0x00, // 0070: node name ("E") + padding
            0x00, 0x00, 0x00, 0x02, // 0074: FDT_END_NODE
            0x00, 0x00, 0x00, 0x01, // 0078: FDT_BEGIN_NODE
            b'B', 0x00, 0x00, 0x00, // 007C: node name ("B") + padding
            0x00, 0x00, 0x00, 0x02, // 0080: FDT_END_NODE
            0x00, 0x00, 0x00, 0x01, // 0084: FDT_BEGIN_NODE
            b'F', 0x00, 0x00, 0x00, // 0088: node name ("F") + padding
            0x00, 0x00, 0x00, 0x02, // 008C: FDT_END_NODE
            0x00, 0x00, 0x00, 0x02, // 0090: FDT_END_NODE
            0x00, 0x00, 0x00, 0x02, // 0094: FDT_END_NODE
            0x00, 0x00, 0x00, 0x09, // 0098: FDT_END
        ];

        let mut fdt = Fdt::new(&[]);
        let root = fdt.root_mut();
        let root_subnode_names = ["B", "A", "C"];
        let node_c_subnode_names = ["D", "E", "B", "F"];
        for n in root_subnode_names {
            root.subnode_mut(n).unwrap();
        }
        let node_c = root.subnode_mut("C").unwrap();
        for n in node_c_subnode_names {
            node_c.subnode_mut(n).unwrap();
        }

        assert!(root
            .iter_subnodes()
            .zip(root_subnode_names)
            .all(|(sn, n)| sn.name == n));
        assert!(root
            .subnode("C")
            .unwrap()
            .iter_subnodes()
            .zip(node_c_subnode_names)
            .all(|(sn, n)| sn.name == n));
        assert_eq!(fdt.finish().unwrap(), expected);
    }

    #[test]
    fn prop_order() {
        let expected: &[u8] = &[
            0xd0, 0x0d, 0xfe, 0xed, // 0000: magic (0xd00dfeed)
            0x00, 0x00, 0x00, 0x98, // 0004: totalsize (0x98)
            0x00, 0x00, 0x00, 0x38, // 0008: off_dt_struct (0x38)
            0x00, 0x00, 0x00, 0x88, // 000C: off_dt_strings (0x88)
            0x00, 0x00, 0x00, 0x28, // 0010: off_mem_rsvmap (0x28)
            0x00, 0x00, 0x00, 0x11, // 0014: version (0x11 = 17)
            0x00, 0x00, 0x00, 0x10, // 0018: last_comp_version (0x10 = 16)
            0x00, 0x00, 0x00, 0x00, // 001C: boot_cpuid_phys (0)
            0x00, 0x00, 0x00, 0x10, // 0020: size_dt_strings (0x10)
            0x00, 0x00, 0x00, 0x50, // 0024: size_dt_struct (0x50)
            0x00, 0x00, 0x00, 0x00, // 0028: rsvmap terminator (address = 0 high)
            0x00, 0x00, 0x00, 0x00, // 002C: rsvmap terminator (address = 0 low)
            0x00, 0x00, 0x00, 0x00, // 0030: rsvmap terminator (size = 0 high)
            0x00, 0x00, 0x00, 0x00, // 0034: rsvmap terminator (size = 0 low)
            0x00, 0x00, 0x00, 0x01, // 0038: FDT_BEGIN_NODE
            0x00, 0x00, 0x00, 0x00, // 003C: node name ("") + padding
            0x00, 0x00, 0x00, 0x03, // 0040: FDT_PROP (u32)
            0x00, 0x00, 0x00, 0x04, // 0044: prop len (4)
            0x00, 0x00, 0x00, 0x00, // 0048: prop nameoff (0x00)
            0x76, 0x61, 0x6c, 0x00, // 004C: prop string value ("val")
            0x00, 0x00, 0x00, 0x03, // 0050: FDT_PROP (u32)
            0x00, 0x00, 0x00, 0x04, // 0054: prop len (4)
            0x00, 0x00, 0x00, 0x04, // 0058: prop nameoff (0x04)
            0x00, 0x00, 0x00, 0x02, // 005C: prop u32 high (0x2)
            0x00, 0x00, 0x00, 0x03, // 0060: FDT_PROP (u32)
            0x00, 0x00, 0x00, 0x04, // 0064: prop len (4)
            0x00, 0x00, 0x00, 0x08, // 0068: prop nameoff (0x08)
            0x00, 0x00, 0x00, 0x01, // 006C: prop u32 value (0x1)
            0x00, 0x00, 0x00, 0x03, // 0070: FDT_PROP (u32)
            0x00, 0x00, 0x00, 0x04, // 0074: prop len (4)
            0x00, 0x00, 0x00, 0x0C, // 0078: prop nameoff (0x0B)
            0x00, 0x00, 0x00, 0x03, // 007C: prop u32 value (0x3)
            0x00, 0x00, 0x00, 0x02, // 0080: FDT_END_NODE
            0x00, 0x00, 0x00, 0x09, // 0084: FDT_END
            b'g', b'h', b'i', 0x00, // 0088: strings + 0x00: "ghi"
            b'd', b'e', b'f', 0x00, // 008C: strings + 0x04: "def"
            b'a', b'b', b'c', 0x00, // 0090: strings + 0x08: "abc"
            b'b', b'c', b'd', 0x00, // 0094: strings + 0x0C: "bcd"
        ];

        let mut fdt = Fdt::new(&[]);
        let root_node = fdt.root_mut();
        root_node.set_prop("ghi", "val").unwrap();
        root_node.set_prop("def", 2u32).unwrap();
        root_node.set_prop("abc", 1u32).unwrap();
        root_node.set_prop("bcd", 3u32).unwrap();

        assert_eq!(
            root_node.prop_names().collect::<Vec<_>>(),
            ["ghi", "def", "abc", "bcd"]
        );
        assert_eq!(fdt.finish().unwrap(), expected);
    }

    #[test]
    fn nested_nodes() {
        let mut fdt = Fdt::new(&[]);
        let root_node = fdt.root_mut();
        root_node.set_prop("abc", 0x13579024u32).unwrap();
        let nested_node = root_node.subnode_mut("nested").unwrap();
        nested_node.set_prop("def", 0x12121212u32).unwrap();
        assert_eq!(
            fdt.finish().unwrap(),
            [
                0xd0, 0x0d, 0xfe, 0xed, // 0000: magic (0xd00dfeed)
                0x00, 0x00, 0x00, 0x80, // 0004: totalsize (0x80)
                0x00, 0x00, 0x00, 0x38, // 0008: off_dt_struct (0x38)
                0x00, 0x00, 0x00, 0x78, // 000C: off_dt_strings (0x78)
                0x00, 0x00, 0x00, 0x28, // 0010: off_mem_rsvmap (0x28)
                0x00, 0x00, 0x00, 0x11, // 0014: version (0x11 = 17)
                0x00, 0x00, 0x00, 0x10, // 0018: last_comp_version (0x10 = 16)
                0x00, 0x00, 0x00, 0x00, // 001C: boot_cpuid_phys (0)
                0x00, 0x00, 0x00, 0x08, // 0020: size_dt_strings (0x08)
                0x00, 0x00, 0x00, 0x40, // 0024: size_dt_struct (0x40)
                0x00, 0x00, 0x00, 0x00, // 0028: rsvmap terminator (address = 0 high)
                0x00, 0x00, 0x00, 0x00, // 002C: rsvmap terminator (address = 0 low)
                0x00, 0x00, 0x00, 0x00, // 0030: rsvmap terminator (size = 0 high)
                0x00, 0x00, 0x00, 0x00, // 0034: rsvmap terminator (size = 0 low)
                0x00, 0x00, 0x00, 0x01, // 0038: FDT_BEGIN_NODE
                0x00, 0x00, 0x00, 0x00, // 003C: node name ("") + padding
                0x00, 0x00, 0x00, 0x03, // 0040: FDT_PROP
                0x00, 0x00, 0x00, 0x04, // 0044: prop len (4)
                0x00, 0x00, 0x00, 0x00, // 0048: prop nameoff (0x00)
                0x13, 0x57, 0x90, 0x24, // 004C: prop u32 value (0x13579024)
                0x00, 0x00, 0x00, 0x01, // 0050: FDT_BEGIN_NODE
                b'n', b'e', b's', b't', // 0054: Node name ("nested")
                b'e', b'd', 0x00, 0x00, // 0058: "ed\0" + pad
                0x00, 0x00, 0x00, 0x03, // 005C: FDT_PROP
                0x00, 0x00, 0x00, 0x04, // 0060: prop len (4)
                0x00, 0x00, 0x00, 0x04, // 0064: prop nameoff (0x04)
                0x12, 0x12, 0x12, 0x12, // 0068: prop u32 value (0x12121212)
                0x00, 0x00, 0x00, 0x02, // 006C: FDT_END_NODE ("nested")
                0x00, 0x00, 0x00, 0x02, // 0070: FDT_END_NODE ("")
                0x00, 0x00, 0x00, 0x09, // 0074: FDT_END
                b'a', b'b', b'c', 0x00, // 0078: strings + 0x00: "abc"
                b'd', b'e', b'f', 0x00, // 007C: strings + 0x04: "def"
            ]
        );
    }

    #[test]
    fn prop_name_string_reuse() {
        let mut fdt = Fdt::new(&[]);
        let root_node = fdt.root_mut();
        root_node.set_prop("abc", 0x13579024u32).unwrap();
        let nested = root_node.subnode_mut("nested").unwrap();
        nested.set_prop("abc", 0x12121212u32).unwrap(); // This should reuse the "abc" string.
        nested.set_prop("def", 0x12121212u32).unwrap();
        assert_eq!(
            fdt.finish().unwrap(),
            [
                0xd0, 0x0d, 0xfe, 0xed, // 0000: magic (0xd00dfeed)
                0x00, 0x00, 0x00, 0x90, // 0004: totalsize (0x90)
                0x00, 0x00, 0x00, 0x38, // 0008: off_dt_struct (0x38)
                0x00, 0x00, 0x00, 0x88, // 000C: off_dt_strings (0x88)
                0x00, 0x00, 0x00, 0x28, // 0010: off_mem_rsvmap (0x28)
                0x00, 0x00, 0x00, 0x11, // 0014: version (0x11 = 17)
                0x00, 0x00, 0x00, 0x10, // 0018: last_comp_version (0x10 = 16)
                0x00, 0x00, 0x00, 0x00, // 001C: boot_cpuid_phys (0)
                0x00, 0x00, 0x00, 0x08, // 0020: size_dt_strings (0x08)
                0x00, 0x00, 0x00, 0x50, // 0024: size_dt_struct (0x50)
                0x00, 0x00, 0x00, 0x00, // 0028: rsvmap terminator (address = 0 high)
                0x00, 0x00, 0x00, 0x00, // 002C: rsvmap terminator (address = 0 low)
                0x00, 0x00, 0x00, 0x00, // 0030: rsvmap terminator (size = 0 high)
                0x00, 0x00, 0x00, 0x00, // 0034: rsvmap terminator (size = 0 low)
                0x00, 0x00, 0x00, 0x01, // 0038: FDT_BEGIN_NODE
                0x00, 0x00, 0x00, 0x00, // 003C: node name ("") + padding
                0x00, 0x00, 0x00, 0x03, // 0040: FDT_PROP
                0x00, 0x00, 0x00, 0x04, // 0044: prop len (4)
                0x00, 0x00, 0x00, 0x00, // 0048: prop nameoff (0x00)
                0x13, 0x57, 0x90, 0x24, // 004C: prop u32 value (0x13579024)
                0x00, 0x00, 0x00, 0x01, // 0050: FDT_BEGIN_NODE
                b'n', b'e', b's', b't', // 0054: Node name ("nested")
                b'e', b'd', 0x00, 0x00, // 0058: "ed\0" + pad
                0x00, 0x00, 0x00, 0x03, // 005C: FDT_PROP
                0x00, 0x00, 0x00, 0x04, // 0060: prop len (4)
                0x00, 0x00, 0x00, 0x00, // 0064: prop nameoff (0x00 - reuse)
                0x12, 0x12, 0x12, 0x12, // 0068: prop u32 value (0x12121212)
                0x00, 0x00, 0x00, 0x03, // 006C: FDT_PROP
                0x00, 0x00, 0x00, 0x04, // 0070: prop len (4)
                0x00, 0x00, 0x00, 0x04, // 0074: prop nameoff (0x04)
                0x12, 0x12, 0x12, 0x12, // 0078: prop u32 value (0x12121212)
                0x00, 0x00, 0x00, 0x02, // 007C: FDT_END_NODE ("nested")
                0x00, 0x00, 0x00, 0x02, // 0080: FDT_END_NODE ("")
                0x00, 0x00, 0x00, 0x09, // 0084: FDT_END
                b'a', b'b', b'c', 0x00, // 0088: strings + 0x00: "abc"
                b'd', b'e', b'f', 0x00, // 008C: strings + 0x04: "def"
            ]
        );
    }

    #[test]
    fn invalid_node_name_nul() {
        let mut fdt = Fdt::new(&[]);
        let root_node = fdt.root_mut();
        root_node
            .subnode_mut("abc\0def")
            .expect_err("node name with embedded NUL");
    }

    #[test]
    fn invalid_prop_name_nul() {
        let mut fdt = Fdt::new(&[]);
        let root_node = fdt.root_mut();
        root_node
            .set_prop("abc\0def", 0u32)
            .expect_err("property name with embedded NUL");
    }

    #[test]
    fn invalid_prop_string_value_nul() {
        let mut fdt = Fdt::new(&[]);
        let root_node = fdt.root_mut();
        root_node
            .set_prop("mystr", "abc\0def")
            .expect_err("string property value with embedded NUL");
    }

    #[test]
    fn invalid_prop_string_list_value_nul() {
        let mut fdt = Fdt::new(&[]);
        let root_node = fdt.root_mut();
        let strs = ["test", "abc\0def"];
        root_node
            .set_prop("mystr", &strs)
            .expect_err("stringlist property value with embedded NUL");
    }
}
