// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Extensions using cros_async and futures-rs to add asynchronous operations to sys_util features.
//! Provides basic `Futures` implementations for some of the interfaces provided by the `sys_util`
//! crate.

mod eventfd;

pub use eventfd::EventFd;
