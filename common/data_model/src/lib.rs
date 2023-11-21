// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod endian;
pub use crate::endian::*;

mod flexible_array;
pub use flexible_array::vec_with_array_field;
pub use flexible_array::FlexibleArray;
pub use flexible_array::FlexibleArrayWrapper;
