// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This crate serves to provide metrics bindings to be used throughout the codebase.
//! For binaries that wish to use metrics, the intention is that an independent metrics
//! process will run (main loop in the controller mod), and receive requests via a tube from
//! another process.
//!
//! At head, metrics requests are ignored. However, a branching codebase can choose to implement
//! their own handler which processes and uploads metrics requests as it sees fit, by setting the
//! appropriate RequestHandler.

mod controller;
mod local_stats;
pub mod sys;

pub use controller::MetricsController;
pub use metrics_product::MetricEventType;
pub use metrics_product::*;

pub type RequestHandler = MetricsRequestHandler;

pub use local_stats::collect_scoped_byte_latency_stat;
pub use local_stats::timed_scope;
pub use local_stats::BytesLatencyStats;
pub use local_stats::CallOnDrop;
pub use local_stats::DetailedHistogram;
pub use local_stats::GetStatsForOp;
pub use local_stats::Histogram;
pub use local_stats::Limits;
pub use local_stats::NumberType;
pub use local_stats::SimpleStat;
pub use local_stats::SummaryStats;
