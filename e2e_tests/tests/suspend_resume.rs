// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod fixture;
use crate::fixture::vm::Config;
use crate::fixture::vm::TestVm;

use tempfile::tempdir;

// Tests for suspend/resume.
//
// System-wide suspend/resume, snapshot/restore.
// Tests below check for snapshot/restore functionality, and suspend/resume.

#[test]
fn suspend_snapshot_restore_resume() -> anyhow::Result<()> {
    let mut vm = TestVm::new(Config::new()).unwrap();
    suspend_resume_system(&mut vm)
}

#[test]
fn suspend_snapshot_restore_resume_disable_sandbox() -> anyhow::Result<()> {
    let mut vm = TestVm::new(Config::new().disable_sandbox()).unwrap();
    suspend_resume_system(&mut vm)
}

fn suspend_resume_system(vm: &mut TestVm) -> anyhow::Result<()> {
    // WARNING: Suspend/resume is only partially implemented, some aspects of these tests only work
    // by chance. Still, the tests are useful to avoid backslide. If a seemingly unrelated change
    // breaks this test, it is probably reasonable to disable the test.

    // Verify RAM is saved and restored by interacting with a filesystem pinned in RAM (i.e. tmpfs
    // with swap disabled).
    vm.exec_in_guest("swapoff -a").unwrap();
    vm.exec_in_guest("mount -t tmpfs none /tmp").unwrap();

    vm.exec_in_guest("echo foo > /tmp/foo").unwrap();
    assert_eq!("foo", vm.exec_in_guest("cat /tmp/foo").unwrap().trim());

    // Take snapshot of original VM state
    println!("snapshotting VM - clean state");
    let dir = tempdir().unwrap();
    let snap1_path = dir.path().join("snapshot.bkp");
    vm.snapshot(&snap1_path).unwrap();

    vm.exec_in_guest("echo bar > /tmp/foo").unwrap();
    assert_eq!("bar", vm.exec_in_guest("cat /tmp/foo").unwrap().trim());

    // suspend VM
    vm.suspend().unwrap();
    let snap2_path = dir.path().join("snapshot2.bkp");

    // Write command to VM
    // This command will get queued and not run while the VM is suspended. The command is saved in
    // the serial device. After the snapshot is taken, the VM is resumed. At that point, the
    // command runs and is validated.
    vm.exec_command_async("echo 42", |vm| {
        // Take snapshot of modified VM
        println!("snapshotting VM - mod state");
        vm.snapshot(&snap2_path).unwrap();

        vm.resume().unwrap();
    })
    .unwrap();
    assert_eq!("42", vm.wait_for_guest().unwrap());

    // suspend VM
    vm.suspend().unwrap();
    // restore VM
    println!("restoring VM - to clean state");
    vm.restore(&snap1_path).unwrap();

    // snapshot VM after restore
    println!("snapshotting VM - clean state restored");
    let snap3_path = dir.path().join("snapshot3.bkp");
    vm.snapshot(&snap3_path).unwrap();
    vm.resume().unwrap();

    assert_eq!("foo", vm.exec_in_guest("cat /tmp/foo").unwrap().trim());

    let snap1 = std::fs::read_to_string(&snap1_path).unwrap();
    let snap2 = std::fs::read_to_string(&snap2_path).unwrap();
    let snap3 = std::fs::read_to_string(&snap3_path).unwrap();
    assert_ne!(snap1, snap2);
    assert_eq!(snap1, snap3);
    Ok(())
}
