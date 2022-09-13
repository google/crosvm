// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Provides noop implementations of metrics interfaces, to be used by builds which don't wish
//! to log metrics.

mod client;
mod periodic_logger;
mod request_handler;

pub use client::*;
pub use periodic_logger::PeriodicLogger;
pub use request_handler::NoopMetricsRequestHandler;
