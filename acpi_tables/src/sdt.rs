// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::io::ErrorKind;
use std::io::Read;
use std::io::Result;
use std::path::Path;

use zerocopy::AsBytes;
use zerocopy::FromBytes;

/// SDT represents for System Description Table. The structure SDT is a
/// generic format for creating various ACPI tables like DSDT/FADT/MADT.
#[derive(Clone)]
pub struct SDT {
    data: Vec<u8>,
}

pub const HEADER_LEN: u32 = 36;
const LENGTH_OFFSET: usize = 4;
const CHECKSUM_OFFSET: usize = 9;

#[allow(clippy::len_without_is_empty)]
impl SDT {
    /// Set up the ACPI table header at the front of the SDT.
    /// The arguments correspond to the elements in the ACPI
    /// table headers.
    pub fn new(
        signature: [u8; 4],
        length: u32,
        revision: u8,
        oem_id: [u8; 6],
        oem_table: [u8; 8],
        oem_revision: u32,
    ) -> Self {
        // The length represents for the length of the entire table
        // which includes this header. And the header is 36 bytes, so
        // lenght should be >= 36. For the case who gives a number less
        // than the header len, use the header len directly.
        let len: u32 = if length < HEADER_LEN {
            HEADER_LEN
        } else {
            length
        };
        let mut data = Vec::with_capacity(length as usize);
        data.extend_from_slice(&signature);
        data.extend_from_slice(&len.to_le_bytes());
        data.push(revision);
        data.push(0); // checksum
        data.extend_from_slice(&oem_id);
        data.extend_from_slice(&oem_table);
        data.extend_from_slice(&oem_revision.to_le_bytes());
        data.extend_from_slice(b"CROS");
        data.extend_from_slice(&0u32.to_le_bytes());

        data.resize(length as usize, 0);
        let mut sdt = SDT { data };

        sdt.update_checksum();
        sdt
    }

    /// Set up the ACPI table from file content. Verify file checksum.
    pub fn from_file(path: &Path) -> Result<Self> {
        let mut file = File::open(path)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        let checksum = super::generate_checksum(data.as_slice());
        if checksum == 0 {
            Ok(SDT { data })
        } else {
            Err(ErrorKind::InvalidData.into())
        }
    }

    pub fn is_signature(&self, signature: &[u8; 4]) -> bool {
        self.data[0..4] == *signature
    }

    fn update_checksum(&mut self) {
        self.data[CHECKSUM_OFFSET] = 0;
        let checksum = super::generate_checksum(self.data.as_slice());
        self.data[CHECKSUM_OFFSET] = checksum;
    }

    pub fn as_slice(&self) -> &[u8] {
        self.data.as_slice()
    }

    pub fn append<T: AsBytes>(&mut self, value: T) {
        self.data.extend_from_slice(value.as_bytes());
        self.write(LENGTH_OFFSET, self.data.len() as u32);
    }

    pub fn append_slice(&mut self, value: &[u8]) {
        self.data.extend_from_slice(value);
        self.write(LENGTH_OFFSET, self.data.len() as u32);
    }

    /// Read a value at the given offset
    pub fn read<T: FromBytes + AsBytes + Default>(&self, offset: usize) -> T {
        let value_len = std::mem::size_of::<T>();
        T::read_from(
            self.as_slice()
                .get(offset..offset + value_len)
                .unwrap_or(T::default().as_bytes()),
        )
        .unwrap()
    }

    /// Write a value at the given offset
    pub fn write<T: AsBytes>(&mut self, offset: usize, value: T) {
        let value_len = std::mem::size_of::<T>();
        if (offset + value_len) > self.data.len() {
            return;
        }
        self.data[offset..offset + value_len].copy_from_slice(value.as_bytes());
        self.update_checksum();
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::SDT;

    #[test]
    fn test_sdt() {
        let mut sdt = SDT::new(*b"TEST", 40, 1, *b"CROSVM", *b"TESTTEST", 1);
        let sum: u8 = sdt
            .as_slice()
            .iter()
            .fold(0u8, |acc, x| acc.wrapping_add(*x));
        assert_eq!(sum, 0);
        sdt.write(36, 0x12345678_u32);
        let sum: u8 = sdt
            .as_slice()
            .iter()
            .fold(0u8, |acc, x| acc.wrapping_add(*x));
        assert_eq!(sum, 0);
    }

    #[test]
    fn test_sdt_read_write() -> Result<(), std::io::Error> {
        let temp_file = NamedTempFile::new()?;
        let expected_sdt = SDT::new(*b"TEST", 40, 1, *b"CROSVM", *b"TESTTEST", 1);

        // Write SDT to file.
        {
            let mut writer = temp_file.as_file();
            writer.write_all(expected_sdt.as_slice())?;
        }

        // Read it back and verify.
        let actual_sdt = SDT::from_file(temp_file.path())?;
        assert!(actual_sdt.is_signature(b"TEST"));
        assert_eq!(actual_sdt.as_slice(), expected_sdt.as_slice());
        Ok(())
    }
}
