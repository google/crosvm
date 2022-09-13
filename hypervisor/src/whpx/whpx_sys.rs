// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! System definitions and bindings for interacting with WHPX.

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

#[allow(clippy::all)]
pub mod bindings;
pub use bindings::*;

pub mod hyperv_tlfs;
pub use hyperv_tlfs::*;
