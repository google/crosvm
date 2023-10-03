// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(not(test))]
#![no_main]
#![allow(unused_variables)]

use crosvm_fuzz::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    p9::fuzzing::tframe_decode(bytes);
});
