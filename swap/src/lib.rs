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
        mod uffd_list;
        // this is public only for integration tests.
        pub mod userfaultfd;
        // this is public only for integration tests.
        pub mod worker;

        pub use crate::controller::SwapDeviceHelper;
        pub use crate::controller::PrepareFork;
        pub use crate::controller::SwapController;
        pub use crate::controller::SwapDeviceUffdSender;
    }
}

use serde::Deserialize;
use serde::Serialize;

/// Current state of vmm-swap.
///
/// This should not contain fields but be a plain enum because this will be displayed to user using
/// `serde_json` crate.
#[repr(C)]
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub enum SwapState {
    /// vmm-swap is ready. userfaultfd is disabled until vmm-swap is enabled.
    Ready = 0,
    /// swap out failed.
    Failed = 1,
    /// Pages in guest memory are moved to the staging memory.
    Pending = 2,
    /// Trimming staging memory.
    TrimInProgress = 3,
    /// swap-out is in progress.
    SwapOutInProgress = 4,
    /// swap out succeeded.
    Active = 5,
    /// swap-in is in progress.
    SwapInInProgress = 6,
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
#[repr(C)]
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default)]
pub struct SwapStateTransition {
    /// The number of pages moved for the state transition.
    pub pages: u64,
    /// Time taken for the state transition.
    pub time_ms: u64,
}

/// Current metrics of vmm-swap.
///
/// This is only available while vmm-swap is enabled.
#[repr(C)]
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default)]
pub struct SwapMetrics {
    /// count of pages on RAM.
    pub resident_pages: u64,
    /// count of pages copied from the vmm-swap file.
    pub copied_from_file_pages: u64,
    /// count of pages copied from the staging memory.
    pub copied_from_staging_pages: u64,
    /// count of pages initialized with zero.
    pub zeroed_pages: u64,
    /// count of pages which were already initialized on page faults. This can happen when several
    /// threads/processes access the uninitialized/removed page at the same time.
    pub redundant_pages: u64,
    /// count of pages in staging memory.
    pub staging_pages: u64,
    /// count of pages in swap files.
    pub swap_pages: u64,
}

/// The response to `crosvm swap status` command.
#[repr(C)]
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct SwapStatus {
    /// Current vmm-swap [SwapState].
    pub state: SwapState,
    /// Current [SwapMetrics] of vmm-swap.
    pub metrics: SwapMetrics,
    /// Latency and number of pages for current [SwapState]. See [SwapStateTransition] for details.
    pub state_transition: SwapStateTransition,
}

impl SwapStatus {
    /// Creates dummy [SwapStatus].
    pub fn dummy() -> Self {
        SwapStatus {
            state: SwapState::Pending,
            metrics: SwapMetrics::default(),
            state_transition: SwapStateTransition::default(),
        }
    }
}
