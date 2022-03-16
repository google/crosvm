// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::Result;
use std::fs::File;

pub fn get_filesystem_type(_file: &File) -> Result<i64> {
    // TODO (b/203574110): create a windows equivalent to get the filesystem type like fstatfs
    Ok(0)
}
