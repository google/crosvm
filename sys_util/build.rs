// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

extern crate gcc;

fn main() {
    gcc::compile_library("libsock_ctrl_msg.a", &["sock_ctrl_msg.c"]);
}
