// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::io::Result;

/// A trait for flushing the contents of a file to disk.
/// This is equivalent to File's `sync_all` method, but
/// wrapped in a trait so that it can be implemented for
/// other types.
pub trait FileSync {
    // Flush buffers related to this file to disk.
    fn fsync(&mut self) -> Result<()>;
}

impl FileSync for File {
    fn fsync(&mut self) -> Result<()> {
        self.sync_all()
    }
}
