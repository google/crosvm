// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;

use super::Result;

pub fn get_filesystem_type(_file: &File) -> Result<i64> {
    // TODO (b/203574110): create a windows equivalent to get the filesystem type like fstatfs
    Ok(0)
}
