// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Provides noop implementations of metrics interfaces, to be used by builds which don't wish
//! to log metrics.

mod client;
mod periodic_logger;
mod request_handler;

mod metrics_cleanup;

use std::time::Duration;

#[cfg(test)]
pub use client::force_initialize;
pub use client::get_destructor;
pub use client::initialize;
pub use client::is_initialized;
pub use client::log_descriptor;
pub use client::log_event;
pub use client::log_event_with_details;
pub use client::log_high_frequency_descriptor_event;
pub use client::log_histogram_metric;
pub use client::log_metric;
pub use client::merge_session_invariants;
pub use client::push_descriptors;
pub use client::set_auth_token;
pub use client::set_graphics_api;
pub use client::set_package_name;
pub use metrics_cleanup::MetricsClientDestructor;
pub use periodic_logger::PeriodicLogger;
pub use request_handler::MetricsRequestHandler;

pub const METRICS_UPLOAD_INTERVAL: Duration = Duration::from_secs(60);
