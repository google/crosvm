// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This module writes Flattened Devicetree blobs as defined here:
//! <https://devicetree-specification.readthedocs.io/en/stable/flattened-format.html>

use std::collections::BTreeMap;
use std::convert::TryInto;
use std::ffi::CString;
use std::io;
use std::mem::size_of;

use thiserror::Error as ThisError;

#[derive(ThisError, Debug)]
pub enum Error {
    #[error("Properties may not be added after a node has been ended")]
    PropertyAfterEndNode,
    #[error("Property value size must fit in 32 bits")]
    PropertyValueTooLarge,
    #[error("Total size must fit in 32 bits")]
    TotalSizeTooLarge,
    #[error("Strings cannot contain NUL")]
    InvalidString,
    #[error("Attempted to end a node that was not the most recent")]
    OutOfOrderEndNode,
    #[error("Attempted to call finish without ending all nodes")]
    UnclosedNode,
    #[error("Error writing FDT to guest memory")]
    FdtGuestMemoryWriteError,
    #[error("Parse error reading FDT parameters")]
    FdtFileParseError,
    #[error("I/O error reading FDT parameters code={0}")]
    FdtIoError(io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

const FDT_HEADER_SIZE: usize = 40;
const FDT_VERSION: u32 = 17;
const FDT_LAST_COMP_VERSION: u32 = 16;

const FDT_MAGIC: u32 = 0xd00dfeed;

const FDT_BEGIN_NODE: u32 = 0x00000001;
const FDT_END_NODE: u32 = 0x00000002;
const FDT_PROP: u32 = 0x00000003;
const FDT_END: u32 = 0x00000009;

/// Interface for writing a Flattened Devicetree (FDT) and emitting a Devicetree Blob (DTB).
///
/// # Example
///
/// ```rust
/// use arch::fdt::FdtWriter;
///
/// # fn main() -> arch::fdt::Result<()> {
/// let mut fdt = FdtWriter::new(&[]);
/// let root_node = fdt.begin_node("")?;
/// fdt.property_string("compatible", "linux,dummy-virt")?;
/// fdt.property_u32("#address-cells", 0x2)?;
/// fdt.property_u32("#size-cells", 0x2)?;
/// let chosen_node = fdt.begin_node("chosen")?;
/// fdt.property_u32("linux,pci-probe-only", 1)?;
/// fdt.property_string("bootargs", "panic=-1 console=hvc0 root=/dev/vda")?;
/// fdt.end_node(chosen_node)?;
/// fdt.end_node(root_node)?;
/// let dtb = fdt.finish(0x1000)?;
/// # Ok(())
/// # }
/// ```
pub struct FdtWriter {
    data: Vec<u8>,
    off_mem_rsvmap: u32,
    off_dt_struct: u32,
    strings: Vec<u8>,
    string_offsets: BTreeMap<CString, u32>,
    node_depth: usize,
    node_ended: bool,
    boot_cpuid_phys: u32,
}

/// Reserved physical memory region.
///
/// This represents an area of physical memory reserved by the firmware and unusable by the OS.
/// For example, this could be used to preserve bootloader code or data used at runtime.
pub struct FdtReserveEntry {
    /// Physical address of the beginning of the reserved region.
    pub address: u64,
    /// Size of the reserved region in bytes.
    pub size: u64,
}

/// Handle to an open node created by `FdtWriter::begin_node`.
///
/// This must be passed back to `FdtWriter::end_node` to close the nodes.
/// Nodes must be closed in reverse order as they were opened, matching the nesting structure
/// of the devicetree.
#[derive(Debug)]
pub struct FdtWriterNode {
    depth: usize,
}

impl FdtWriter {
    /// Create a new Flattened Devicetree writer instance.
    ///
    /// # Arguments
    ///
    /// `mem_reservations` - reserved physical memory regions to list in the FDT header.
    pub fn new(mem_reservations: &[FdtReserveEntry]) -> Self {
        let data = vec![0u8; FDT_HEADER_SIZE]; // Reserve space for header.

        let mut fdt = FdtWriter {
            data,
            off_mem_rsvmap: 0,
            off_dt_struct: 0,
            strings: Vec::new(),
            string_offsets: BTreeMap::new(),
            node_depth: 0,
            node_ended: false,
            boot_cpuid_phys: 0,
        };

        fdt.align(8);
        fdt.off_mem_rsvmap = fdt.data.len() as u32;
        fdt.write_mem_rsvmap(mem_reservations);

        fdt.align(4);
        fdt.off_dt_struct = fdt.data.len() as u32;

        fdt
    }

    fn write_mem_rsvmap(&mut self, mem_reservations: &[FdtReserveEntry]) {
        for rsv in mem_reservations {
            self.append_u64(rsv.address);
            self.append_u64(rsv.size);
        }

        self.append_u64(0);
        self.append_u64(0);
    }

    /// Set the `boot_cpuid_phys` field of the devicetree header.
    pub fn set_boot_cpuid_phys(&mut self, boot_cpuid_phys: u32) {
        self.boot_cpuid_phys = boot_cpuid_phys;
    }

    // Append `num_bytes` padding bytes (0x00).
    fn pad(&mut self, num_bytes: usize) {
        self.data.extend(std::iter::repeat(0).take(num_bytes));
    }

    // Append padding bytes (0x00) until the length of data is a multiple of `alignment`.
    fn align(&mut self, alignment: usize) {
        let offset = self.data.len() % alignment;
        if offset != 0 {
            self.pad(alignment - offset);
        }
    }

    // Rewrite the value of a big-endian u32 within data.
    fn update_u32(&mut self, offset: usize, val: u32) {
        let data_slice = &mut self.data[offset..offset + 4];
        data_slice.copy_from_slice(&val.to_be_bytes());
    }

    fn append_u32(&mut self, val: u32) {
        self.data.extend_from_slice(&val.to_be_bytes());
    }

    fn append_u64(&mut self, val: u64) {
        self.data.extend_from_slice(&val.to_be_bytes());
    }

    /// Open a new FDT node.
    ///
    /// The node must be closed using `end_node`.
    ///
    /// # Arguments
    ///
    /// `name` - name of the node; must not contain any NUL bytes.
    pub fn begin_node(&mut self, name: &str) -> Result<FdtWriterNode> {
        let name_cstr = CString::new(name).map_err(|_| Error::InvalidString)?;
        self.append_u32(FDT_BEGIN_NODE);
        self.data.extend(name_cstr.to_bytes_with_nul());
        self.align(4);
        self.node_depth += 1;
        self.node_ended = false;
        Ok(FdtWriterNode {
            depth: self.node_depth,
        })
    }

    /// Close a node previously opened with `begin_node`.
    pub fn end_node(&mut self, node: FdtWriterNode) -> Result<()> {
        if node.depth != self.node_depth {
            return Err(Error::OutOfOrderEndNode);
        }

        self.append_u32(FDT_END_NODE);
        self.node_depth -= 1;
        self.node_ended = true;
        Ok(())
    }

    // Find an existing instance of a string `s`, or add it to the strings block.
    // Returns the offset into the strings block.
    fn intern_string(&mut self, s: CString) -> u32 {
        if let Some(off) = self.string_offsets.get(&s) {
            *off
        } else {
            let off = self.strings.len() as u32;
            self.strings.extend_from_slice(s.to_bytes_with_nul());
            self.string_offsets.insert(s, off);
            off
        }
    }

    /// Write a property.
    ///
    /// # Arguments
    ///
    /// `name` - name of the property; must not contain any NUL bytes.
    /// `val` - value of the property (raw byte array).
    pub fn property(&mut self, name: &str, val: &[u8]) -> Result<()> {
        if self.node_ended {
            return Err(Error::PropertyAfterEndNode);
        }

        let name_cstr = CString::new(name).map_err(|_| Error::InvalidString)?;

        let len = val
            .len()
            .try_into()
            .map_err(|_| Error::PropertyValueTooLarge)?;

        let nameoff = self.intern_string(name_cstr);
        self.append_u32(FDT_PROP);
        self.append_u32(len);
        self.append_u32(nameoff);
        self.data.extend_from_slice(val);
        self.align(4);
        Ok(())
    }

    /// Write an empty property.
    pub fn property_null(&mut self, name: &str) -> Result<()> {
        self.property(name, &[])
    }

    /// Write a string property.
    pub fn property_string(&mut self, name: &str, val: &str) -> Result<()> {
        let cstr_value = CString::new(val).map_err(|_| Error::InvalidString)?;
        self.property(name, cstr_value.to_bytes_with_nul())
    }

    /// Write a stringlist property.
    pub fn property_string_list(&mut self, name: &str, values: Vec<String>) -> Result<()> {
        let mut bytes = Vec::new();
        for s in values {
            let cstr = CString::new(s).map_err(|_| Error::InvalidString)?;
            bytes.extend_from_slice(&cstr.to_bytes_with_nul());
        }
        self.property(name, &bytes)
    }

    /// Write a 32-bit unsigned integer property.
    pub fn property_u32(&mut self, name: &str, val: u32) -> Result<()> {
        self.property(name, &val.to_be_bytes())
    }

    /// Write a 64-bit unsigned integer property.
    pub fn property_u64(&mut self, name: &str, val: u64) -> Result<()> {
        self.property(name, &val.to_be_bytes())
    }

    /// Write a property containing an array of 32-bit unsigned integers.
    pub fn property_array_u32(&mut self, name: &str, cells: &[u32]) -> Result<()> {
        let mut arr = Vec::with_capacity(cells.len() * size_of::<u32>());
        for &c in cells {
            arr.extend(&c.to_be_bytes());
        }
        self.property(name, &arr)
    }

    /// Write a property containing an array of 64-bit unsigned integers.
    pub fn property_array_u64(&mut self, name: &str, cells: &[u64]) -> Result<()> {
        let mut arr = Vec::with_capacity(cells.len() * size_of::<u64>());
        for &c in cells {
            arr.extend(&c.to_be_bytes());
        }
        self.property(name, &arr)
    }

    /// Finish writing the Devicetree Blob (DTB).
    ///
    /// Returns the DTB as a vector of bytes, consuming the `FdtWriter`.
    /// The DTB is always padded up to `max_size` with zeroes, so the returned
    /// value will either be exactly `max_size` bytes long, or an error will
    /// be returned if the DTB does not fit in `max_size` bytes.
    ///
    /// # Arguments
    ///
    /// `max_size` - Maximum size of the finished DTB in bytes.
    pub fn finish(mut self, max_size: usize) -> Result<Vec<u8>> {
        if self.node_depth > 0 {
            return Err(Error::UnclosedNode);
        }

        self.append_u32(FDT_END);
        let size_dt_struct = self.data.len() as u32 - self.off_dt_struct;

        let totalsize = self.data.len() + self.strings.len();

        let totalsize = totalsize.try_into().map_err(|_| Error::TotalSizeTooLarge)?;
        let off_dt_strings = self
            .data
            .len()
            .try_into()
            .map_err(|_| Error::TotalSizeTooLarge)?;
        let size_dt_strings = self
            .strings
            .len()
            .try_into()
            .map_err(|_| Error::TotalSizeTooLarge)?;

        // Finalize the header.
        self.update_u32(0, FDT_MAGIC);
        self.update_u32(1 * 4, totalsize);
        self.update_u32(2 * 4, self.off_dt_struct);
        self.update_u32(3 * 4, off_dt_strings);
        self.update_u32(4 * 4, self.off_mem_rsvmap);
        self.update_u32(5 * 4, FDT_VERSION);
        self.update_u32(6 * 4, FDT_LAST_COMP_VERSION);
        self.update_u32(7 * 4, self.boot_cpuid_phys);
        self.update_u32(8 * 4, size_dt_strings);
        self.update_u32(9 * 4, size_dt_struct);

        // Add the strings block.
        self.data.append(&mut self.strings);

        if self.data.len() > max_size {
            Err(Error::TotalSizeTooLarge)
        } else {
            // Fill remaining data up to `max_size` with zeroes.
            self.pad(max_size - self.data.len());
            Ok(self.data)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal() {
        let mut fdt = FdtWriter::new(&[]);
        let root_node = fdt.begin_node("").unwrap();
        fdt.end_node(root_node).unwrap();
        assert_eq!(
            fdt.finish(0x48).unwrap(),
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
        let mut fdt = FdtWriter::new(&[
            FdtReserveEntry {
                address: 0x12345678AABBCCDD,
                size: 0x1234,
            },
            FdtReserveEntry {
                address: 0x1020304050607080,
                size: 0x5678,
            },
        ]);
        let root_node = fdt.begin_node("").unwrap();
        fdt.end_node(root_node).unwrap();
        assert_eq!(
            fdt.finish(0x68).unwrap(),
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
        let mut fdt = FdtWriter::new(&[]);
        let root_node = fdt.begin_node("").unwrap();
        fdt.property_null("null").unwrap();
        fdt.end_node(root_node).unwrap();
        assert_eq!(
            fdt.finish(0x59).unwrap(),
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
        let mut fdt = FdtWriter::new(&[]);
        let root_node = fdt.begin_node("").unwrap();
        fdt.property_u32("u32", 0x12345678).unwrap();
        fdt.end_node(root_node).unwrap();
        assert_eq!(
            fdt.finish(0x5C).unwrap(),
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
        let mut fdt = FdtWriter::new(&[]);
        let root_node = fdt.begin_node("").unwrap();
        fdt.property_null("null").unwrap();
        fdt.property_u32("u32", 0x12345678).unwrap();
        fdt.property_u64("u64", 0x1234567887654321).unwrap();
        fdt.property_string("str", "hello").unwrap();
        fdt.property_string_list("strlst", vec!["hi".into(), "bye".into()])
            .unwrap();
        fdt.property_array_u32("arru32", &[0x12345678, 0xAABBCCDD])
            .unwrap();
        fdt.property_array_u64("arru64", &[0x1234567887654321])
            .unwrap();
        fdt.end_node(root_node).unwrap();
        assert_eq!(
            fdt.finish(0xEE).unwrap(),
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
                0x00, 0x00, 0x00, 0x03, // 0040: FDT_PROP (null)
                0x00, 0x00, 0x00, 0x00, // 0044: prop len (0)
                0x00, 0x00, 0x00, 0x00, // 0048: prop nameoff (0)
                0x00, 0x00, 0x00, 0x03, // 004C: FDT_PROP (u32)
                0x00, 0x00, 0x00, 0x04, // 0050: prop len (4)
                0x00, 0x00, 0x00, 0x05, // 0054: prop nameoff (0x05)
                0x12, 0x34, 0x56, 0x78, // 0058: prop u32 value (0x12345678)
                0x00, 0x00, 0x00, 0x03, // 005C: FDT_PROP (u64)
                0x00, 0x00, 0x00, 0x08, // 0060: prop len (8)
                0x00, 0x00, 0x00, 0x09, // 0064: prop nameoff (0x09)
                0x12, 0x34, 0x56, 0x78, // 0068: prop u64 value high (0x12345678)
                0x87, 0x65, 0x43, 0x21, // 006C: prop u64 value low (0x87654321)
                0x00, 0x00, 0x00, 0x03, // 0070: FDT_PROP (string)
                0x00, 0x00, 0x00, 0x06, // 0074: prop len (6)
                0x00, 0x00, 0x00, 0x0D, // 0078: prop nameoff (0x0D)
                b'h', b'e', b'l', b'l', // 007C: prop str value ("hello") + padding
                b'o', 0x00, 0x00, 0x00, // 0080: "o\0" + padding
                0x00, 0x00, 0x00, 0x03, // 0084: FDT_PROP (string list)
                0x00, 0x00, 0x00, 0x07, // 0088: prop len (7)
                0x00, 0x00, 0x00, 0x11, // 008C: prop nameoff (0x11)
                b'h', b'i', 0x00, b'b', // 0090: prop value ("hi", "bye")
                b'y', b'e', 0x00, 0x00, // 0094: "ye\0" + padding
                0x00, 0x00, 0x00, 0x03, // 0098: FDT_PROP (u32 array)
                0x00, 0x00, 0x00, 0x08, // 009C: prop len (8)
                0x00, 0x00, 0x00, 0x18, // 00A0: prop nameoff (0x18)
                0x12, 0x34, 0x56, 0x78, // 00A4: prop value 0
                0xAA, 0xBB, 0xCC, 0xDD, // 00A8: prop value 1
                0x00, 0x00, 0x00, 0x03, // 00AC: FDT_PROP (u64 array)
                0x00, 0x00, 0x00, 0x08, // 00B0: prop len (8)
                0x00, 0x00, 0x00, 0x1f, // 00B4: prop nameoff (0x1F)
                0x12, 0x34, 0x56, 0x78, // 00B8: prop u64 value 0 high
                0x87, 0x65, 0x43, 0x21, // 00BC: prop u64 value 0 low
                0x00, 0x00, 0x00, 0x02, // 00C0: FDT_END_NODE
                0x00, 0x00, 0x00, 0x09, // 00C4: FDT_END
                b'n', b'u', b'l', b'l', 0x00, // 00C8: strings + 0x00: "null""
                b'u', b'3', b'2', 0x00, // 00CD: strings + 0x05: "u32"
                b'u', b'6', b'4', 0x00, // 00D1: strings + 0x09: "u64"
                b's', b't', b'r', 0x00, // 00D5: strings + 0x0D: "str"
                b's', b't', b'r', b'l', b's', b't', 0x00, // 00D9: strings + 0x11: "strlst"
                b'a', b'r', b'r', b'u', b'3', b'2', 0x00, // 00E0: strings + 0x18: "arru32"
                b'a', b'r', b'r', b'u', b'6', b'4', 0x00, // 00E7: strings + 0x1F: "arru64"
            ]
        );
    }

    #[test]
    fn nested_nodes() {
        let mut fdt = FdtWriter::new(&[]);
        let root_node = fdt.begin_node("").unwrap();
        fdt.property_u32("abc", 0x13579024).unwrap();
        let nested_node = fdt.begin_node("nested").unwrap();
        fdt.property_u32("def", 0x12121212).unwrap();
        fdt.end_node(nested_node).unwrap();
        fdt.end_node(root_node).unwrap();
        assert_eq!(
            fdt.finish(0x80).unwrap(),
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
        let mut fdt = FdtWriter::new(&[]);
        let root_node = fdt.begin_node("").unwrap();
        fdt.property_u32("abc", 0x13579024).unwrap();
        let nested_node = fdt.begin_node("nested").unwrap();
        fdt.property_u32("def", 0x12121212).unwrap();
        fdt.property_u32("abc", 0x12121212).unwrap(); // This should reuse the "abc" string.
        fdt.end_node(nested_node).unwrap();
        fdt.end_node(root_node).unwrap();
        assert_eq!(
            fdt.finish(0x90).unwrap(),
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
                0x00, 0x00, 0x00, 0x04, // 0064: prop nameoff (0x04)
                0x12, 0x12, 0x12, 0x12, // 0068: prop u32 value (0x12121212)
                0x00, 0x00, 0x00, 0x03, // 006C: FDT_PROP
                0x00, 0x00, 0x00, 0x04, // 0070: prop len (4)
                0x00, 0x00, 0x00, 0x00, // 0074: prop nameoff (0x00 - reuse)
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
        let mut fdt = FdtWriter::new(&[]);
        fdt.begin_node("abc\0def")
            .expect_err("node name with embedded NUL");
    }

    #[test]
    fn invalid_prop_name_nul() {
        let mut fdt = FdtWriter::new(&[]);
        fdt.property_u32("abc\0def", 0)
            .expect_err("property name with embedded NUL");
    }

    #[test]
    fn invalid_prop_string_value_nul() {
        let mut fdt = FdtWriter::new(&[]);
        fdt.property_string("mystr", "abc\0def")
            .expect_err("string property value with embedded NUL");
    }

    #[test]
    fn invalid_prop_string_list_value_nul() {
        let mut fdt = FdtWriter::new(&[]);
        let strs = vec!["test".into(), "abc\0def".into()];
        fdt.property_string_list("mystr", strs)
            .expect_err("stringlist property value with embedded NUL");
    }

    #[test]
    fn invalid_prop_after_end_node() {
        let mut fdt = FdtWriter::new(&[]);
        let _root_node = fdt.begin_node("").unwrap();
        fdt.property_u32("ok_prop", 1234).unwrap();
        let nested_node = fdt.begin_node("mynode").unwrap();
        fdt.property_u32("ok_nested_prop", 5678).unwrap();
        fdt.end_node(nested_node).unwrap();
        fdt.property_u32("bad_prop_after_end_node", 1357)
            .expect_err("property after end_node");
    }

    #[test]
    fn invalid_end_node_out_of_order() {
        let mut fdt = FdtWriter::new(&[]);
        let root_node = fdt.begin_node("").unwrap();
        fdt.property_u32("ok_prop", 1234).unwrap();
        let _nested_node = fdt.begin_node("mynode").unwrap();
        fdt.end_node(root_node)
            .expect_err("end node while nested node is open");
    }

    #[test]
    fn invalid_finish_while_node_open() {
        let mut fdt = FdtWriter::new(&[]);
        let _root_node = fdt.begin_node("").unwrap();
        fdt.property_u32("ok_prop", 1234).unwrap();
        let _nested_node = fdt.begin_node("mynode").unwrap();
        fdt.property_u32("ok_nested_prop", 5678).unwrap();
        fdt.finish(0x100)
            .expect_err("finish without ending all nodes");
    }
}
