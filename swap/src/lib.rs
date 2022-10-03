// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! crate for the vmm-swap feature.

// TODO(kawasin): warn dead_code again after swap feature is done.
#![allow(dead_code)]
#![deny(missing_docs)]

mod file;
// this is public only for integration tests.
pub mod page_handler;
mod processes;
// this is public only for integration tests.
pub mod userfaultfd;
