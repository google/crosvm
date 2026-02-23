// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::OpenOptions;

pub fn set_extra_open_opts(_opts: &mut OpenOptions) {
    // unix does not require extra options.
}
