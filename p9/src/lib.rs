// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[macro_use]
extern crate wire_format_derive;

mod protocol;

#[derive(P9WireFormat)]
struct Test {
    a: u32,
    b: u16,
}
