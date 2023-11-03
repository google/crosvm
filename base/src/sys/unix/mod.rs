// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod descriptor;
pub mod file_traits;
#[macro_use]
pub mod handle_eintr;

pub use descriptor::*;
