// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(any(target_os = "android", target_os = "linux"))]

use std::io::Write;
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

fn compare_snapshots(a: &Path, b: &Path) -> (bool, String) {
    let result = std::process::Command::new("diff")
        .arg("-qr")
        // vcpu and irqchip have timestamps that differ even if a freshly restored VM is
        // snapshotted before it starts running again.
        .arg("--exclude")
        .arg("vcpu*")
        .arg("--exclude")
        .arg("irqchip")
        .arg(a)
        .arg(b)
        .output()
        .unwrap();
    (
        result.status.success(),
        String::from_utf8(result.stdout).unwrap(),
    )
}

#[test]
fn suspend_snapshot_restore_resume() -> anyhow::Result<()> {
    suspend_resume_system(false)
}

#[test]
fn suspend_snapshot_restore_resume_disable_sandbox() -> anyhow::Result<()> {
    suspend_resume_system(true)
}

fn suspend_resume_system(disabled_sandbox: bool) -> anyhow::Result<()> {
    let mut pmem_file = NamedTempFile::new().unwrap();
    pmem_file.write_all(&[0; 4096]).unwrap();
    pmem_file.as_file_mut().sync_all().unwrap();

    let new_config = || {
        let mut config = Config::new();
        config = config.with_stdout_hardware("legacy-virtio-console");
        config = config.extra_args(vec![
            "--pmem-device".to_string(),
            pmem_file.path().display().to_string(),
        ]);
        // TODO: Remove once USB has snapshot/restore support.
        config = config.extra_args(vec!["--no-usb".to_string()]);
        if disabled_sandbox {
            config = config.disable_sandbox();
        }
        config
    };

    let mut vm = TestVm::new(new_config()).unwrap();

    // Verify RAM is saved and restored by interacting with a filesystem pinned in RAM (i.e. tmpfs
    // with swap disabled).
    vm.exec_in_guest("swapoff -a").unwrap();
    vm.exec_in_guest("mount -t tmpfs none /tmp").unwrap();

    vm.exec_in_guest("echo foo > /tmp/foo").unwrap();
    assert_eq!(
        "foo",
        vm.exec_in_guest("cat /tmp/foo").unwrap().stdout.trim()
    );

    vm.suspend_full().unwrap();
    // Take snapshot of original VM state
    println!("snapshotting VM - clean state");
    let dir = tempdir().unwrap();
    let snap1_path = dir.path().join("snapshot.bkp");
    vm.snapshot(&snap1_path).unwrap();
    vm.resume_full().unwrap();

    vm.exec_in_guest("echo bar > /tmp/foo").unwrap();
    assert_eq!(
        "bar",
        vm.exec_in_guest("cat /tmp/foo").unwrap().stdout.trim()
    );

    vm.suspend_full().unwrap();
    let snap2_path = dir.path().join("snapshot2.bkp");

    // Write command to VM
    // This command will get queued and not run while the VM is suspended. The command is saved in
    // the serial device. After the snapshot is taken, the VM is resumed. At that point, the
    // command runs and is validated.
    let echo_cmd = vm.exec_in_guest_async("echo 42").unwrap();
    // Take snapshot of modified VM
    println!("snapshotting VM - mod state");
    vm.snapshot(&snap2_path).unwrap();

    vm.resume_full().unwrap();
    assert_eq!("42", echo_cmd.wait_ok(&mut vm).unwrap().stdout.trim());

    println!("restoring VM - to clean state");

    // shut down VM
    drop(vm);
    // Start up VM with cold restore.
    let mut vm = TestVm::new_restore_suspended(new_config().extra_args(vec![
        "--restore".to_string(),
        snap1_path.to_str().unwrap().to_string(),
        "--suspended".to_string(),
    ]))
    .unwrap();

    // snapshot VM after restore
    println!("snapshotting VM - clean state restored");
    let snap3_path = dir.path().join("snapshot3.bkp");
    vm.snapshot(&snap3_path).unwrap();
    vm.resume_full().unwrap();

    assert_eq!(
        "foo",
        vm.exec_in_guest("cat /tmp/foo").unwrap().stdout.trim()
    );

    let (equal, output) = compare_snapshots(&snap1_path, &snap2_path);
    assert!(
        !equal,
        "1st and 2nd snapshot are unexpectedly equal:\n{output}"
    );

    let (equal, output) = compare_snapshots(&snap1_path, &snap3_path);
    assert!(equal, "1st and 3rd snapshot are not equal:\n{output}");

    Ok(())
}

#[test]
fn snapshot_vhost_user_root() {
    call_test_with_sudo("snapshot_vhost_user")
}

// This test will fail/hang if ran by its self.
#[ignore = "Only to be called by snapshot_vhost_user_root"]
#[test]
fn snapshot_vhost_user() {
    fn spin_up_vhost_user_devices() -> (
        VhostUserBackend,
        VhostUserBackend,
        NamedTempFile,
        NamedTempFile,
    ) {
        let block_socket = NamedTempFile::new().unwrap();
        let disk = prepare_disk_img();

        // Spin up block vhost user process
        let block_vu_config =
            create_vu_block_config(CmdType::Device, block_socket.path(), disk.path());
        let block_vu_device = VhostUserBackend::new(block_vu_config).unwrap();

        // Spin up net vhost user process.
        // Queue handlers don't get activated currently.
        let net_socket = NamedTempFile::new().unwrap();
        let net_config = create_net_config(net_socket.path());
        let net_vu_device = VhostUserBackend::new(net_config).unwrap();

        (block_vu_device, net_vu_device, block_socket, net_socket)
    }

    let dir = tempdir().unwrap();
    let snap_path = dir.path().join("snapshot.bkp");

    {
        let (_block_vu_device, _net_vu_device, block_socket, net_socket) =
            spin_up_vhost_user_devices();

        let mut config = Config::new();
        config = config.with_stdout_hardware("legacy-virtio-console");
        config = config.with_vhost_user("block", block_socket.path());
        config = config.with_vhost_user("net", net_socket.path());
        config = config.extra_args(vec!["--no-usb".to_string()]);
        let mut vm = TestVm::new(config).unwrap();

        // suspend VM
        vm.suspend_full().unwrap();
        vm.snapshot(&snap_path).unwrap();
        drop(vm);
    }

    let (_block_vu_device, _net_vu_device, block_socket, net_socket) = spin_up_vhost_user_devices();

    let mut config = Config::new();
    // Start up VM with cold restore.
    config = config.with_stdout_hardware("legacy-virtio-console");
    config = config.with_vhost_user("block", block_socket.path());
    config = config.with_vhost_user("net", net_socket.path());
    config = config.extra_args(vec![
        "--restore".to_string(),
        snap_path.to_str().unwrap().to_string(),
        "--no-usb".to_string(),
    ]);
    let _vm = TestVm::new_restore(config).unwrap();
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
