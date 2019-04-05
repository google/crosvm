// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use protobuf::Message;

/// Asserts that a given protobuf message object can be serialized to bytes and
/// read back into a value of the same type, preserving equality between the
/// original object and the one read back.
///
/// This is helpful for confirming that proto files have been compiled
/// successfully and are exposed as intended by the public API of the parent
/// crate. It also lets us exercise the full set of methods we intend to use for
/// building particular proto objects so that we notice breakage early in the
/// event that a proto external to this repository would make a breaking change.
///
/// Note: assumes that the given `message` is not just `T::new` so that we can
/// tell that deserialization has happened successfully.
///
/// # Example
///
/// ```ignore
/// let mut request = SendCommandRequest::new();
/// request.set_command(b"...".to_vec());
/// test_round_trip(request);
/// ```
pub fn test_round_trip<T: Message + PartialEq>(message: T) {
    let serialized = message.write_to_bytes().unwrap();

    let mut back = T::new();
    assert_ne!(message, back);

    back.merge_from_bytes(&serialized).unwrap();
    assert_eq!(message, back);
}
