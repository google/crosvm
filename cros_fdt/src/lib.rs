// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Flattened device tree writer.

mod fdt;
mod propval;

pub use fdt::Error;
pub use fdt::Fdt;
pub use fdt::FdtNode;
pub use fdt::Result;
