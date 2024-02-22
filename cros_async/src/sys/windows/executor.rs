// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/// An enum to express the kind of the backend of `Executor`
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde_keyvalue::FromKeyValues)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub enum ExecutorKindSys {
    Handle,
    Overlapped { concurrency: Option<u32> },
}

impl serde::Serialize for ExecutorKindSys {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&match self {
            ExecutorKindSys::Handle => "handle".to_string(),
            ExecutorKindSys::Overlapped { concurrency: None } => "overlapped".to_string(),
            ExecutorKindSys::Overlapped {
                concurrency: Some(n),
            } => format!("overlapped,concurrency={}", n),
        })
    }
}
