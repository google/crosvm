// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Macros that assert properties of code at compile time.
//!
//! A static assertion is particularly appropriate when unsafe code relies on
//! two types to have the same size, or on some type to have a particular size.

#[doc(hidden)]
pub mod mechanism;

// Re-export so that these types appear with a more concise name in error
// messages.
#[doc(hidden)]
pub use crate::mechanism::*;

/// Macro that fails to compile if a given const expression is not true.
///
/// # Example
///
/// ```rust
/// use assertions::const_assert;
///
/// fn main() {
///     const_assert!(std::mem::size_of::<String>() == 24);
/// }
/// ```
///
/// # Example that fails to compile
///
/// ```rust,compile_fail
/// use assertions::const_assert;
///
/// fn main() {
///     // fails to compile:
///     const_assert!(std::mem::size_of::<String>() == 8);
/// }
/// ```
#[macro_export]
macro_rules! const_assert {
    ($e:expr) => {
        let _: $crate::Assert<[(); $e as bool as usize]>;
    };
}
