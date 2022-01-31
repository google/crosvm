// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Small system utility modules for usage by other higher level system
//! utility modules like sys_util(on unix/linux) and win_sys_util(on windows).
//!
//! Crates other than sys_util and win_sys_util should not depend directly on
//! sys_util_core.
//!
//! sys_util_core contains system utilities that are strictly platform/os
//! independent. Platform dependent, conditionally compiled, code should
//! not be added to sys_util_core.
//!

mod alloc;
mod external_mapping;

pub use crate::alloc::LayoutAllocation;
pub use crate::external_mapping::Error as ExternalMappingError;
pub use crate::external_mapping::Result as ExternalMappingResult;
pub use crate::external_mapping::*;
