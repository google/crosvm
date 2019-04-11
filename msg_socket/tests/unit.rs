// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use msg_socket::*;

#[test]
fn sock_send_recv_unit() {
    let (req, res) = pair::<(), ()>().unwrap();
    req.send(&()).unwrap();
    let _ = res.recv().unwrap();
}
