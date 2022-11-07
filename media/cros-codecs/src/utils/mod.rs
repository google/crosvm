// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(test)]
pub(crate) mod dummy;
#[cfg(feature = "vaapi")]
pub mod vaapi;
