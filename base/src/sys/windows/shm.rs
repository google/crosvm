// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use serde::Deserialize;
use serde::Serialize;

use crate::descriptor::AsRawDescriptor;
use crate::descriptor::IntoRawDescriptor;
use crate::descriptor::SafeDescriptor;
use crate::RawDescriptor;

/// A shared memory file descriptor and its size.
#[derive(Debug, Deserialize, Serialize)]
pub struct SharedMemory {
    #[serde(with = "crate::with_as_descriptor")]
    pub descriptor: SafeDescriptor,
    pub size: u64,
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
