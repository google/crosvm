// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::RecvTube;

#[derive(Default)]
pub struct MetricsRequestHandler;
impl MetricsRequestHandler {
    pub fn new() -> Self {
        MetricsRequestHandler
    }
    pub fn handle_tube_readable(&self, _tube: &RecvTube) {
        unreachable!();
    }
    pub fn shutdown(&self) {}
}
