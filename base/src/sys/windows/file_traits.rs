// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::io::Error;
use std::io::Result;

use data_model::VolatileSlice;

pub use super::win::file_traits::*;
use crate::descriptor::AsRawDescriptor;
use crate::FileReadWriteAtVolatile;
use crate::FileReadWriteVolatile;

crate::volatile_impl!(File);
crate::volatile_at_impl!(File);
