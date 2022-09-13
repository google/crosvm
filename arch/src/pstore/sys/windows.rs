// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::OpenOptions;
use std::os::windows::fs::OpenOptionsExt;

use winapi::um::winnt::FILE_SHARE_READ;

pub fn set_extra_open_opts(opts: &mut OpenOptions) {
    // Allow other applications to read the memory region. This is useful when
    // folks want to tail the pstore file, and would fail without this setting.
    opts.share_mode(FILE_SHARE_READ);
}
