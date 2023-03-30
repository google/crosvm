// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Library for custom implementations of serialize/deserialize.

use std::result::Result;
use std::sync::Arc;

use serde::de::Error;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use sync::Mutex;

/// Serialize data T inside an Arc<Mutex<T>>. T must be serializable.
///
/// NOTE: This does not validate already serialized Mutexes and data. If multiple structs contain a
/// clone of the Arc, and they are all being serialized, this will result in the same data being
/// serialized, once per clone.
pub fn serialize_arc_mutex<S, T: ?Sized>(
    item: &Arc<Mutex<T>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Serialize,
{
    let lock = item.lock();
    serde::Serialize::serialize(&*lock, serializer)
}

/// Serialize data T inside arrays as a seq instead of a tuple. T must be serializable.
/// When deserializing, an array size validation is required to transform the slice to an array.
///
/// This approach is used to go around serde's limitation of serializable array sizes.
pub fn serialize_arr<S, T: Sized + Serialize, const SIZE: usize>(
    data: &[T; SIZE],
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serde::Serialize::serialize(&data[..], serializer)
}

/// Deserialize sequence of T into an Array of SIZE == Size of sequence.
/// This function is a workaround to the serde limitation on array size (32) deserialization.
pub fn deserialize_seq_to_arr<
    'de,
    D,
    T: Sized + Deserialize<'de> + std::fmt::Debug,
    const SIZE: usize,
>(
    deserializer: D,
) -> Result<[T; SIZE], D::Error>
where
    D: Deserializer<'de>,
{
    let vals_vec: Vec<T> = serde::Deserialize::deserialize(deserializer)?;
    let vals_arr: [T; SIZE] = vals_vec.try_into().map_err(|_| {
        <D as Deserializer>::Error::custom("failed to convert vector to array while deserializing")
    })?;
    Ok(vals_arr)
}
