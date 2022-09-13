// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::controller::MetricsRequestHandler;
use crate::metrics_requests::MetricsRequest;

pub struct NoopMetricsRequestHandler;
impl MetricsRequestHandler for NoopMetricsRequestHandler {
    fn new() -> Self {
        NoopMetricsRequestHandler
    }
    fn handle_request(&self, _req: MetricsRequest) {}
    fn shutdown(&self) {}
}
