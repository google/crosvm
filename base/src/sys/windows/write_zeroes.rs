// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp::min;
use std::fs::File;
use std::io;
use std::os::windows::fs::FileExt;

use crate::PunchHole;

// TODO(b/195151495): Fix so that this will extend a file size if needed.
pub(crate) fn file_write_zeroes_at(file: &File, offset: u64, length: usize) -> io::Result<usize> {
    // Try to punch a hole first.
    if let Ok(()) = file.punch_hole(offset, length as u64) {
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
        nwritten += file.seek_write(&buf[0..write_size], offset + nwritten as u64)?;
    }
    Ok(length)
}
