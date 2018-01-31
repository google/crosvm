// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

extern crate qcow_utils_test;

#[test]
fn test_create() {
    qcow_utils_test::run_c_test(include_str!("create.c"));
}
