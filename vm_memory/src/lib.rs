// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Virtual machine guest memory abstraction.

mod guest_address;
pub mod guest_memory;

cfg_if::cfg_if! {
    if #[cfg(all(unix, feature = "udmabuf"))] {
        pub mod udmabuf;
        mod udmabuf_bindings;
    }
}

pub use guest_address::*;
pub use guest_memory::Error as GuestMemoryError;
pub use guest_memory::*;
