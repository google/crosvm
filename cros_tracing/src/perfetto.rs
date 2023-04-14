// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub use cros_tracing_types::static_strings::StaticString;
pub use perfetto::*;

setup_perfetto!(
    cros_tracing,
    crosvm,
    "General crosvm trace points",
    perfetto_tags!(),
    block,
    "Block device trace points",
    perfetto_tags!("devices"),
    gpu,
    "GPU device trace points",
    perfetto_tags!("devices"),
    virtqueue,
    "General virtqueue trace points",
    perfetto_tags!("devices"),
    net,
    "Net device trace points",
    perfetto_tags!("devices"),
    future,
    "Async trace points",
    perfetto_tags!()
);

// We offset host builtin clock values by 32 so they can be correctly translated to guest clocks.
// See go/bstar-perfetto
pub const HOST_GUEST_CLOCK_ID_OFFSET: u32 = 32;

pub fn init() {
    register_categories();
    // This tracing crate only supports system backend for now. If we want crosvm to start/end
    // a trace then we'd want to add some functions in this crate for that.
    perfetto::init_tracing(perfetto::BackendType::System);
}

pub fn init_in_process() {
    register_categories();
    perfetto::init_tracing(perfetto::BackendType::InProcess);
}

// TODO(b/263902691): implement push_descriptors.
#[macro_export]
macro_rules! push_descriptors {
    ($fd_vec:expr) => {};
}
