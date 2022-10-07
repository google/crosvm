// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::windows::system_metrics::CoreWinMetrics;
use crate::windows::Error;
use crate::windows::Result;

static INSTANCE_EXISTS: AtomicBool = AtomicBool::new(false);

/// Used by gpu_display to show metrics in the crosvm performance overlay.
pub struct Metrics {
    metrics: Vec<Box<dyn ToString + Send + Sync>>,
    // more_metrics is for metrics which have multiple owners (e.g., device dependent).
    more_metrics: Vec<Arc<dyn ToString + Send + Sync>>,
}

impl Metrics {
    pub fn new() -> Result<Self> {
        if INSTANCE_EXISTS
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(Error::InstanceAlreadyExists);
        }
        Ok(Metrics {
            metrics: vec![
                #[cfg(windows)]
                Box::new(CoreWinMetrics::new()?),
            ],
            more_metrics: vec![],
        })
    }

    pub fn add_gpu_metrics(&mut self, t: Arc<dyn ToString + Send + Sync>) {
        self.more_metrics.push(t);
    }

    pub fn get_metric_string(&self) -> String {
        let mut buf = String::new();
        for collector in self.metrics.iter() {
            buf.push_str(&collector.to_string());
            buf.push('\n');
        }
        for collector in self.more_metrics.iter() {
            buf.push_str(&collector.to_string());
            buf.push('\n');
        }
        buf
    }
}
