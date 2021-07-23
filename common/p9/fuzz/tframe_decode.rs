// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![no_main]

use cros_fuzz::fuzz_target;
use p9::fuzzing::tframe_decode;

fuzz_target!(|bytes: &[u8]| {
    tframe_decode(bytes);
});
