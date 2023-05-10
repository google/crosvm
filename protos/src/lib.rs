// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Generated protobuf bindings.

mod generated {
    include!(concat!(env!("OUT_DIR"), "/generated.rs"));
}

#[cfg(feature = "plugin")]
pub mod plugin;

#[cfg(feature = "composite-disk")]
pub use generated::cdisk_spec;

#[cfg(feature = "registered_events")]
pub use generated::registered_events;
