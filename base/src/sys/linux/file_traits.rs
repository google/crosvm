// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This module exposes Linux's off64_t, pread*64, and pwrite*64 identifiers as the non-64 POSIX
//! versions, similar to defining _FILE_OFFSET_BITS=64 in a C program.

use std::fs::File;
use std::io::Error;
use std::io::Result;

use super::fallocate;
use super::FallocateMode;
use crate::FileAllocate;

impl FileAllocate for File {
    fn allocate(&self, offset: u64, len: u64) -> Result<()> {
        fallocate(self, FallocateMode::Allocate, offset, len)
            .map_err(|e| Error::from_raw_os_error(e.errno()))
    }
}

// This module allows the macros in unix/file_traits.rsto refer to $crate::platform::X and ensures
// other crates don't need to add additional crates to their Cargo.toml.
pub mod lib {
    pub use libc::off64_t as off_t;
    pub use libc::pread64 as pread;
    pub use libc::preadv64 as preadv;
    pub use libc::pwrite64 as pwrite;
    pub use libc::pwritev64 as pwritev;
}
