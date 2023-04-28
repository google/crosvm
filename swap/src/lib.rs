// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! crate for the vmm-swap feature.

#![deny(missing_docs)]

cfg_if::cfg_if! {
    if #[cfg(all(unix, feature = "enable"))] {
        mod controller;
        mod file;
        mod logger;
        mod pagesize;
        mod present_list;
        // this is public only for integration tests.
        pub mod page_handler;
        mod processes;
        mod staging;
        // this is public only for integration tests.
        pub mod userfaultfd;
        // this is public only for integration tests.
        pub mod worker;

        pub use crate::controller::SwapController;
    }
}

use serde::Deserialize;
use serde::Serialize;

/// Current state of vmm-swap.
///
/// This should not contain fields but be a plain enum because this will be displayed to user using
/// `serde_json` crate.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum State {
    /// vmm-swap is ready. userfaultfd is disabled until vmm-swap is enabled.
    Ready,
    /// Pages in guest memory are moved to the staging memory.
    Pending,
    /// Trimming staging memory.
    TrimInProgress,
    /// swap-out is in progress.
    SwapOutInProgress,
    /// swap out succeeded.
    Active,
    /// swap-in is in progress.
    SwapInInProgress,
    /// swap out failed.
    Failed,
}

/// Latency and number of pages of swap operations (move to staging, swap out, swap in).
///
/// The meaning of `StateTransition` depends on `State`.
///
/// | `State`             | `StateTransition`                            |
/// |---------------------|----------------------------------------------|
/// | `Ready`             | empty or transition record of `swap disable` |
/// | `Pending`           | transition record of `swap enable`           |
/// | `SwapOutInProgress` | transition record of `swap out`              |
/// | `Active`            | transition record of `swap out`              |
/// | `SwapInInProgress`  | transition record of `swap disable`          |
/// | `Failed`            | empty                                        |
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default)]
pub struct StateTransition {
    /// The number of pages moved for the state transition.
    pub pages: usize,
    /// Time taken for the state transition.
    pub time_ms: u128,
}

/// Current metrics of vmm-swap.
///
/// This is only available while vmm-swap is enabled.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Metrics {
    /// count of pages on RAM.
    pub resident_pages: usize,
    /// count of pages copied from the vmm-swap file.
    pub copied_from_file_pages: usize,
    /// count of pages copied from the staging memory.
    pub copied_from_staging_pages: usize,
    /// count of pages initialized with zero.
    pub zeroed_pages: usize,
    /// count of pages which were already initialized on page faults. This can happen when several
    /// threads/processes access the uninitialized/removed page at the same time.
    pub redundant_pages: usize,
    /// count of pages in staging memory.
    pub staging_pages: usize,
    /// count of pages in swap files.
    pub swap_pages: usize,
}

/// The response to `crosvm swap status` command.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Status {
    /// Current vmm-swap [State].
    pub state: State,
    /// Current [Metrics] of vmm-swap.
    pub metrics: Metrics,
    /// Latency and number of pages for current [State]. See [StateTransition] for details.
    pub state_transition: StateTransition,
}

impl Status {
    /// Creates dummy [Status].
    pub fn dummy() -> Self {
        Status {
            state: State::Pending,
            metrics: Metrics::default(),
            state_transition: StateTransition::default(),
        }
    }
}
