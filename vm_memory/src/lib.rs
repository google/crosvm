// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Virtual machine guest memory abstraction.

mod guest_address;
pub mod guest_memory;
pub mod udmabuf;
mod udmabuf_bindings;

pub use guest_address::*;
pub use guest_memory::Error as GuestMemoryError;
pub use guest_memory::*;
