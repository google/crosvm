// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::{PunchHole, WriteZeroesAt};
use std::{cmp::min, fs::File, io, os::windows::fs::FileExt};

impl WriteZeroesAt for File {
    // TODO(b/195151495): Fix so that this will extend a file size if needed.
    fn write_zeroes_at(&mut self, offset: u64, length: usize) -> io::Result<usize> {
        // Try to punch a hole first.
        if let Ok(()) = self.punch_hole(offset, length as u64) {
            return Ok(length);
        }

        // fall back to write()
        // punch_hole() failed; fall back to writing a buffer of zeroes
        // until we have written up to length.
        let buf_size = min(length, 0x10000);
        let buf = vec![0u8; buf_size];
        let mut nwritten: usize = 0;
        while nwritten < length {
            let remaining = length - nwritten;
            let write_size = min(remaining, buf_size);
            nwritten += self.seek_write(&buf[0..write_size], offset + nwritten as u64)?;
        }
        Ok(length)
    }
}
