// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Testing virtio-fs.

#![cfg(any(target_os = "android", target_os = "linux"))]

use std::path::Path;

use fixture::vhost_user::CmdType;
use fixture::vhost_user::Config as VuConfig;
use fixture::vhost_user::VhostUserBackend;
use fixture::vm::Config;
use fixture::vm::TestVm;
use tempfile::NamedTempFile;
use tempfile::TempDir;

/// Tests file copy
///
/// 1. Create `original.txt` on a temporal directory.
/// 2. Start a VM with a virtiofs device for the temporal directory.
/// 3. Copy `original.txt` to `new.txt` in the guest.
/// 4. Check that `new.txt` is created in the host.
fn copy_file(mut vm: TestVm, tag: &str, dir: TempDir) {
    const ORIGINAL_FILE_NAME: &str = "original.txt";
    const NEW_FILE_NAME: &str = "new.txt";
    const TEST_DATA: &str = "virtiofs works!";

    let orig_file = dir.path().join(ORIGINAL_FILE_NAME);

    std::fs::write(orig_file, TEST_DATA).unwrap();

    // TODO(b/269137600): Split this into multiple lines instead of connecting commands with `&&`.
    vm.exec_in_guest(&format!(
        "mount -t virtiofs {tag} /mnt && cp /mnt/{} /mnt/{} && sync",
        ORIGINAL_FILE_NAME, NEW_FILE_NAME,
    ))
    .unwrap();

    let new_file = dir.path().join(NEW_FILE_NAME);
    let contents = std::fs::read(new_file).unwrap();
    assert_eq!(TEST_DATA.as_bytes(), &contents);
}

/// Tests mount/read/create/write
/// 1. Create `read_file.txt` with test data in host's temporal directory.
/// 2. Start a VM with a virtiofs device for the temporal directory.
/// 3. Guest reads read_file.txt file & verify the content is test data
/// 4. Guest creates a write_file.txt file in shared directory
/// 5. Host reads file from host's temporal directory & verify content is test data
fn mount_rw(mut vm: TestVm, tag: &str, dir: TempDir) {
    const READ_FILE_NAME: &str = "read_test.txt";
    const WRITE_FILE_NAME: &str = "write_test.txt";
    const TEST_DATA: &str = "hello world";

    let read_test_file = dir.path().join(READ_FILE_NAME);
    let write_test_file = dir.path().join(WRITE_FILE_NAME);
    std::fs::write(read_test_file, TEST_DATA).unwrap();

    assert_eq!(
        vm.exec_in_guest(&format!(
            "mount -t virtiofs {tag} /mnt && cat /mnt/read_test.txt"
        ))
        .unwrap()
        .stdout
        .trim(),
        TEST_DATA
    );

    const IN_FS_WRITE_FILE_PATH: &str = "/mnt/write_test.txt";
    let _ = vm.exec_in_guest(&format!("echo -n {TEST_DATA} > {IN_FS_WRITE_FILE_PATH}"));
    let read_contents = std::fs::read(write_test_file).unwrap();
    assert_eq!(TEST_DATA.as_bytes(), &read_contents);
}

#[test]
fn fs_copy_file() {
    let tag = "mtdtest";
    let temp_dir = tempfile::tempdir().unwrap();

    let config = Config::new().extra_args(vec![
        "--shared-dir".to_string(),
        format!(
            "{}:{tag}:type=fs:cache=auto",
            temp_dir.path().to_str().unwrap()
        ),
    ]);

    let vm = TestVm::new(config).unwrap();
    copy_file(vm, tag, temp_dir)
}

#[test]
fn fs_mount_rw() {
    let tag = "mtdtest";
    let temp_dir = tempfile::tempdir().unwrap();

    let config = Config::new().extra_args(vec![
        "--shared-dir".to_string(),
        format!(
            "{}:{tag}:type=fs:cache=auto",
            temp_dir.path().to_str().unwrap()
        ),
    ]);

    let vm = TestVm::new(config).unwrap();
    mount_rw(vm, tag, temp_dir)
}

/// Tests file ownership seen by the VM.
///
/// 1. Create `user_file.txt` owned by the current user of the host on a temporal directory.
/// 2. Set virtiofs options: uidmap=<mapped-uid> <current-uid> 1, uid=<mapped-uid>.
/// 3. Start a VM with a virtiofs device for the temporal directory.
/// 4. Check that `user_file.txt`'s uid is <mapped-uid> in the VM.
/// 5. Verify gid similarly.
#[test]
fn file_ugid() {
    const FILE_NAME: &str = "user_file.txt";
    let uid = base::geteuid();
    let gid = base::getegid();
    let mapped_uid: u32 = rand::random();
    let mapped_gid: u32 = rand::random();
    let uid_map: String = format!("{} {} 1", mapped_uid, uid);
    let gid_map = format!("{} {} 1", mapped_gid, gid);

    let temp_dir = tempfile::tempdir().unwrap();
    let orig_file = temp_dir.path().join(FILE_NAME);

    std::fs::write(orig_file, "").unwrap();

    let tag = "mtdtest";

    let config = Config::new().extra_args(vec![
        "--shared-dir".to_string(),
        format!(
            "{}:{tag}:type=fs:uidmap={}:gidmap={}:uid={}:gid={}",
            temp_dir.path().to_str().unwrap(),
            uid_map,
            gid_map,
            mapped_uid,
            mapped_gid
        ),
    ]);

    let mut vm = TestVm::new(config).unwrap();
    vm.exec_in_guest(&format!("mount -t virtiofs {tag} /mnt"))
        .unwrap();
    let output = vm
        .exec_in_guest(&format!("stat /mnt/{}", FILE_NAME,))
        .unwrap();
    // stat output example:
    // File: /mnt/user_file.txt
    // Size: 0                 Blocks: 0          IO Block: 4096   regular empty file
    // Device: 0,11    Inode: 11666031    Links: 1
    // Access: (0640/-rw-r-----)  Uid: (2350626183/ UNKNOWN)   Gid: (949179291/ UNKNOWN)
    // Access: 2023-04-05 03:06:27.110144457 +0000
    // Modify: 2023-04-05 03:06:27.110144457 +0000
    // Change: 2023-04-05 03:06:27.110144457 +0000
    assert!(output.stdout.contains(&format!("Uid: ({}/", mapped_uid)));
    assert!(output.stdout.contains(&format!("Gid: ({}/", mapped_gid)));
}

pub fn create_vu_fs_config(socket: &Path, shared_dir: &Path, tag: &str) -> VuConfig {
    let uid = base::geteuid();
    let gid = base::getegid();
    let socket_path = socket.to_str().unwrap();
    let shared_dir_path = shared_dir.to_str().unwrap();
    println!("socket={socket_path}, tag={tag}, shared_dir={shared_dir_path}");
    VuConfig::new(CmdType::Device, "vhost-user-fs").extra_args(vec![
        "fs".to_string(),
        format!("--socket={socket_path}"),
        format!("--shared-dir={shared_dir_path}"),
        format!("--tag={tag}"),
        format!("--uid-map=0 {uid} 1"),
        format!("--gid-map=0 {gid} 1"),
    ])
}

/// Tests vhost-user fs device copy file.
#[test]
fn vhost_user_fs_copy_file() {
    let socket = NamedTempFile::new().unwrap();
    let temp_dir = tempfile::tempdir().unwrap();

    let config = Config::new();
    let tag = "mtdtest";

    let vu_config = create_vu_fs_config(socket.path(), temp_dir.path(), tag);
    let _vu_device = VhostUserBackend::new(vu_config).unwrap();

    let config = config.with_vhost_user_fs(socket.path(), tag);
    let vm = TestVm::new(config).unwrap();

    copy_file(vm, tag, temp_dir);
}

/// Tests vhost-user fs device mount and read write.
#[test]
fn vhost_user_fs_mount_rw() {
    let socket = NamedTempFile::new().unwrap();
    let temp_dir = tempfile::tempdir().unwrap();

    let config = Config::new();
    let tag = "mtdtest";

    let vu_config = create_vu_fs_config(socket.path(), temp_dir.path(), tag);
    let _vu_device = VhostUserBackend::new(vu_config).unwrap();

    let config = config.with_vhost_user_fs(socket.path(), tag);
    let vm = TestVm::new(config).unwrap();

    mount_rw(vm, tag, temp_dir);
}
