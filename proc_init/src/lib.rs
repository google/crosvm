// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This crate provides functions to call very early from the entry point to customize the process
//! for setting up Rust processes. It was built originally for CrosVM, but can be useful in other
//! Rust products too.
//!
//! For example:
//! * Check for singleton.
//! * Logger initialization.
//! * Metrics initialization.
//! * Crash reporting initialization.
//! * Tracing initialization.
//! * Entry for downstream to custom other possible process wise initialization.

use std::fs::File;
use std::fs::OpenOptions;
use std::path::PathBuf;

use anyhow::Context;
use base::enable_high_res_timers;
use base::syslog;
use base::syslog::LogArgs;
use base::EnabledHighResTimer;
use base::FromRawDescriptor;
use base::IntoRawDescriptor;
use base::SafeDescriptor;
use base::SendTube;
#[cfg(feature = "process-invariants")]
pub use proc_init_product::init_broker_process_invariants;
use proc_init_product::init_child_crash_reporting;
use proc_init_product::product_child_setup;
#[cfg(feature = "process-invariants")]
pub use proc_init_product::EmulatorProcessInvariants;
use proc_init_product::ProductAttributes;
use proc_init_product::ProductProcessState;
use serde::Deserialize;
use serde::Serialize;

/// Arguments that are common to all devices & helper processes.
#[derive(Serialize, Deserialize)]
pub struct CommonChildStartupArgs {
    log_args: LogArgs,
    syslog_file: Option<SafeDescriptor>,
    metrics_tube: Option<SendTube>,
    product_attrs: ProductAttributes,
}

impl CommonChildStartupArgs {
    #[allow(clippy::new_without_default)]
    pub fn new(
        log_args: &LogArgs,
        syslog_path: Option<PathBuf>,
        #[cfg(feature = "crash-report")] _crash_attrs: crash_report::CrashReportAttributes,
        #[cfg(feature = "process-invariants")] _process_invariants: EmulatorProcessInvariants,
        metrics_tube: Option<SendTube>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            log_args: log_args.clone(),
            product_attrs: ProductAttributes {},
            metrics_tube,
            syslog_file: log_file_from_path(syslog_path)?,
        })
    }
}

pub struct ChildLifecycleCleanup {
    _timer_resolution: Box<dyn EnabledHighResTimer>,
    _product_state: ProductProcessState,
}

/// Initializes crash reporting, metrics, logging, and product specific features
/// for a process.
///
/// Returns a value that should be dropped when the process exits.
pub fn common_child_setup(args: CommonChildStartupArgs) -> anyhow::Result<ChildLifecycleCleanup> {
    // Logging must initialize first in case there are other startup errors.
    let mut cfg = syslog::LogConfig {
        log_args: args.log_args,
        ..Default::default()
    };
    if let Some(log_file_descriptor) = args.syslog_file {
        let log_file =
            // SAFETY:
            // Safe because we are taking ownership of a SafeDescriptor.
            unsafe { File::from_raw_descriptor(log_file_descriptor.into_raw_descriptor()) };
        cfg.pipe = Some(Box::new(log_file));
        cfg.log_args.stderr = false;
    } else {
        cfg.log_args.stderr = true;
    }
    syslog::init_with(cfg)?;

    // Crash reporting should start as early as possible, in case other startup tasks fail.
    init_child_crash_reporting(&args.product_attrs);

    // Initialize anything product specific.
    let product_proc_state = product_child_setup(&args.product_attrs)?;

    if let Some(metrics_tube) = args.metrics_tube {
        metrics::initialize(metrics_tube);
    }

    let timer_resolution = enable_high_res_timers().context("failed to enable high res timer")?;

    Ok(ChildLifecycleCleanup {
        _timer_resolution: timer_resolution,
        _product_state: product_proc_state,
    })
}

pub(crate) fn log_file_from_path(path: Option<PathBuf>) -> anyhow::Result<Option<SafeDescriptor>> {
    Ok(match path {
        Some(path) => Some(SafeDescriptor::from(
            OpenOptions::new()
                .append(true)
                .create(true)
                .open(path.as_path())
                .with_context(|| format!("failed to open log file {}", path.display()))?,
        )),
        None => None,
    })
}
