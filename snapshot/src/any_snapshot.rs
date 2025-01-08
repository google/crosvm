// Copyright 2025 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/// A type erased snapshot value. Or, alternatively, you can think of it as a partially
/// (de)serialized value that can be nested in other values without incurring double encoding in
/// the final output.
///
/// There is a performance and code size cost to this type, so only use it if really needed, for
/// example, in traits that must be dyn compatible.
///
/// If the intermediate representation and the final serialization format don't match, for example,
/// if `AnySnapshot` was implemented with `serde_json::Value` but then written to a file as CBOR,
/// it will technically work, but the result might not match what you'd get if you directly
/// serialized the original value. That should be OK as long as the serialization and
/// deserialization paths make symmetric use of `AnySnapshot`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AnySnapshot(serde_json::Value);

impl AnySnapshot {
    pub fn to_any(x: impl serde::Serialize) -> anyhow::Result<Self> {
        Ok(AnySnapshot(serde_json::to_value(x)?))
    }

    pub fn from_any<T: serde::de::DeserializeOwned>(x: Self) -> anyhow::Result<T> {
        Ok(serde_json::from_value(x.0)?)
    }
}
