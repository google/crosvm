// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod shm_streams;
mod shm_vios;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub use self::shm_streams::*;

pub use self::shm_vios::*;
