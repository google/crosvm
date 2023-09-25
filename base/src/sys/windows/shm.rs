// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;

use serde::ser;
use serde::Deserialize;
use serde::Serialize;
use serde::Serializer;

use super::RawDescriptor;
use super::Result;
use crate::descriptor::AsRawDescriptor;
use crate::descriptor::IntoRawDescriptor;
use crate::descriptor::SafeDescriptor;
use crate::MemoryMapping;

/// A shared memory file descriptor and its size.
#[derive(Debug, Deserialize)]
#[serde(try_from = "SerializedSharedMemory")]
pub struct SharedMemory {
    pub descriptor: SafeDescriptor,
    pub size: u64,

    // Elements used internally to perform File-like operations on this Shared Memory
    pub mapping: MemoryMapping,
    pub cursor: usize,
}

impl SharedMemory {
    /// Gets the size in bytes of the shared memory.
    ///
    /// The size returned here does not reflect changes by other interfaces or users of the shared
    /// memory file descriptor.
    pub fn size(&self) -> u64 {
        self.size
    }
}

// Ideally we'd use Serde's "into" attribute on SharedMemory to convert into SerializedSharedMemory
// prior to serialization; however, this requires SharedMemory to implement Clone, which does not
// make sense for all its fields.
impl Serialize for SharedMemory {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = SerializedSharedMemory {
            descriptor: self.descriptor.try_clone().map_err(|e| {
                ser::Error::custom(format!(
                    "Error cloning SharedMemory::descriptor while serializing SharedMemory: {}",
                    e
                ))
            })?,
            size: self.size,
        };
        s.serialize(serializer)
    }
}

/// Serialization helper for SharedMemory.
///
/// SharedMemory::mapping cannot be serialized because when sent across processes. This is because
/// the memory region it refers may change. To solve that, we serialize SharedMemory as
/// SerializedSharedMemory instead, and on deserialization, Serde uses TryFrom to create a
/// SharedMemory, which creates a brand new MemoryMapping (in SharedMemory::mapping) from the
/// descriptor.
#[derive(Serialize, Deserialize)]
struct SerializedSharedMemory {
    #[serde(with = "crate::with_as_descriptor")]
    pub descriptor: SafeDescriptor,
    pub size: u64,
}

impl TryFrom<SerializedSharedMemory> for SharedMemory {
    type Error = crate::Error;

    fn try_from(shm: SerializedSharedMemory) -> Result<Self> {
        SharedMemory::from_safe_descriptor(shm.descriptor, shm.size)
    }
}

/// USE THIS CAUTIOUSLY. The returned handle is not a file handle and cannot be
/// used as if it were one. It is a handle to a the associated file mapping object
/// and should only be used for memory-mapping the file view.
impl AsRawDescriptor for SharedMemory {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.descriptor.as_raw_descriptor()
    }
}

impl IntoRawDescriptor for SharedMemory {
    fn into_raw_descriptor(self) -> RawDescriptor {
        self.descriptor.into_raw_descriptor()
    }
}

impl Read for SharedMemory {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let result = match self.mapping.read_slice(buf, self.cursor) {
            Ok(result) => result,
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("Unable to read from shared memory: {}", e),
                ));
            }
        };
        let size_read = result;
        self.cursor += size_read;
        Ok(size_read)
    }
}

impl Write for SharedMemory {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let result = match self.mapping.write_slice(buf, self.cursor) {
            Ok(result) => result,
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("Unable to write to shared memory: {}", e),
                ));
            }
        };
        let size_written = result;
        self.cursor += size_written;
        Ok(size_written)
    }

    fn flush(&mut self) -> io::Result<()> {
        // No buffering is used, no flushing required
        Ok(())
    }
}

impl Seek for SharedMemory {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_cursor: i64 = match pos {
            SeekFrom::Start(offset) => offset as i64,
            SeekFrom::End(offset) => self.size as i64 + offset,
            SeekFrom::Current(offset) => self.cursor as i64 + offset,
        };

        if new_cursor < 0 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Cannot seek to a negative value",
            ));
        }

        self.cursor = new_cursor as usize;
        Ok(self.cursor as u64)
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;

    use super::*;

    #[test]
    fn new() {
        let shm = SharedMemory::new(&CString::new("name").unwrap(), 1028)
            .expect("failed to create shared memory");
        assert_eq!(shm.size(), 1028);
    }
}
