// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::metrics_requests::MetricsRequest;

#[derive(Default)]
pub struct MetricsRequestHandler;
impl MetricsRequestHandler {
    pub fn new() -> Self {
        MetricsRequestHandler
    }
    pub fn handle_request(&self, _req: MetricsRequest) {}
    pub fn shutdown(&self) {}
}
