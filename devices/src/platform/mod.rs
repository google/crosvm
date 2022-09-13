// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implements platform devices and busses.

mod vfio_platform;

pub use self::vfio_platform::VfioPlatformDevice;
