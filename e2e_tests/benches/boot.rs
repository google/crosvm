// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use fixture::vm::Config;
use fixture::vm::TestVm;

#[test]
fn boot_test_vm() -> anyhow::Result<()> {
    let mut vm = TestVm::new(Config::new()).unwrap();
    assert_eq!(vm.exec_in_guest("echo 42")?.trim(), "42");
    Ok(())
}
