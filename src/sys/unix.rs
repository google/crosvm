// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub(crate) mod main;
#[cfg(not(feature = "crash-report"))]
mod panic_hook;

#[cfg(not(feature = "crash-report"))]
pub(crate) use panic_hook::set_panic_hook;
