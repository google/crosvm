// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::sys::ExecutorKindSys;

#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    serde_keyvalue::FromKeyValues,
)]
#[serde(deny_unknown_fields, rename_all = "kebab-case", untagged)]
pub enum ExecutorKind {
    SysVariants(ExecutorKindSys),
}

impl Default for ExecutorKind {
    fn default() -> ExecutorKind {
        ExecutorKind::SysVariants(ExecutorKindSys::default())
    }
}

impl From<ExecutorKindSys> for ExecutorKind {
    fn from(e: ExecutorKindSys) -> ExecutorKind {
        ExecutorKind::SysVariants(e)
    }
}

// TODO: schuffelen - Remove after adding a platform-independent Executor
impl From<ExecutorKind> for ExecutorKindSys {
    fn from(e: ExecutorKind) -> ExecutorKindSys {
        match e {
            ExecutorKind::SysVariants(inner) => inner,
        }
    }
}
