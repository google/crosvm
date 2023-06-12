// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(unix)]

use std::path::Path;

use base::test_utils::call_test_with_sudo;
use fixture::utils::create_vu_block_config;
use fixture::utils::prepare_disk_img;
use fixture::vhost_user::CmdType;
use fixture::vhost_user::Config as VuConfig;
use fixture::vhost_user::VhostUserBackend;
use fixture::vm::Config;
use fixture::vm::TestVm;
use tempfile::tempdir;
use tempfile::NamedTempFile;

// Tests for suspend/resume.
//
// System-wide suspend/resume, snapshot/restore.
// Tests below check for snapshot/restore functionality, and suspend/resume.

#[ignore]
#[test]
fn suspend_snapshot_restore_resume() -> anyhow::Result<()> {
    let mut vm = TestVm::new(Config::new()).unwrap();
    suspend_resume_system(&mut vm)
}

#[ignore]
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
    let echo_cmd = vm.exec_in_guest_async("echo 42").unwrap();
    // Take snapshot of modified VM
    println!("snapshotting VM - mod state");
    vm.snapshot(&snap2_path).unwrap();

    vm.resume().unwrap();
    assert_eq!("42", echo_cmd.wait(vm).unwrap());

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

#[ignore]
#[test]
fn snapshot_vhost_user_root() {
    call_test_with_sudo("snapshot_vhost_user")
}

// This test will fail/hang if ran by its self.
#[ignore = "Only to be called by snapshot_vhost_user_root"]
#[test]
fn snapshot_vhost_user() {
    let block_socket = NamedTempFile::new().unwrap();
    let disk = prepare_disk_img();

    // Spin up block vhost user process
    let block_vu_config = create_vu_block_config(CmdType::Device, block_socket.path(), disk.path());
    let _block_vu_device = VhostUserBackend::new(block_vu_config);

    // Spin up net vhost user process.
    // Queue handlers don't get activated currently.
    let net_socket = NamedTempFile::new().unwrap();
    let net_config = create_net_config(net_socket.path());
    let _net_vu_device = VhostUserBackend::new(net_config).unwrap();

    let mut config = Config::new();
    config = config.extra_args(vec![
        "--vhost-user-blk".to_string(),
        block_socket.path().to_str().unwrap().to_string(),
        "--vhost-user-net".to_string(),
        net_socket.path().to_str().unwrap().to_string(),
    ]);
    let mut vm = TestVm::new(config).unwrap();

    let dir = tempdir().unwrap();
    let snap_path = dir.path().join("snapshot.bkp");
    vm.snapshot(&snap_path).unwrap();

    let snapshot_json = std::fs::read_to_string(snap_path).unwrap();

    assert!(snapshot_json.contains("\"device_name\":\"virtio-block\""));
    assert!(snapshot_json.contains("\"paused_queue\":{\"activated\":true,\"avail_ring\":"));
}

fn create_net_config(socket: &Path) -> VuConfig {
    let socket_path = socket.to_str().unwrap();
    println!("socket={socket_path}");
    VuConfig::new(CmdType::Device, "net").extra_args(vec![
        "net".to_string(),
        "--device".to_string(),
        format!(
            "{},{},{},{}",
            socket_path, "192.168.10.1", "255.255.255.0", "12:34:56:78:9a:bc"
        ),
    ])
}
