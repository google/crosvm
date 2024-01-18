// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use serde::Deserialize;
use serde::Serialize;

/// An enum to express the kind of the backend of `Executor`
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, serde_keyvalue::FromKeyValues,
)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub enum ExecutorKindSys {
    Handle,
    Overlapped,
}
