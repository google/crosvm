// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod fixture;
use fixture::vm::Config;
use fixture::vm::TestVm;

#[test]
fn boot_test_vm() {
    let mut vm = TestVm::new(Config::new()).unwrap();
    assert_eq!(vm.exec_in_guest("echo 42").unwrap().trim(), "42");
}

#[test]
fn boot_test_vm_odirect() {
    let mut vm = TestVm::new(Config::new().o_direct()).unwrap();
    assert_eq!(vm.exec_in_guest("echo 42").unwrap().trim(), "42");
}

#[test]
fn boot_test_vm_config_file() {
    let mut vm = TestVm::new_with_config_file(Config::new()).unwrap();
    assert_eq!(vm.exec_in_guest("echo 42").unwrap().trim(), "42");
}

#[test]
fn boot_test_suspend_resume() {
    // There is no easy way for us to check if the VM is actually suspended. But at
    // least exercise the code-path.
    let mut vm = TestVm::new(Config::new()).unwrap();
    vm.suspend().unwrap();
    vm.resume().unwrap();
    assert_eq!(vm.exec_in_guest("echo 42").unwrap().trim(), "42");
}
