// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(feature = "trunks")]

mod common;

use crate::common::test_round_trip;
use protos::trunks::{SendCommandRequest, SendCommandResponse};

#[test]
fn send_command_request() {
    let mut request = SendCommandRequest::new();
    request.set_command(b"...".to_vec());
    test_round_trip(request);
}

#[test]
fn send_command_response() {
    let mut response = SendCommandResponse::new();
    response.set_response(b"...".to_vec());
    test_round_trip(response);
}
