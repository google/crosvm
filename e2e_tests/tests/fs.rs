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
        "mount -t virtiofs {tag} /mnt && cp /mnt/{ORIGINAL_FILE_NAME} /mnt/{NEW_FILE_NAME} && sync",
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
    let uid_map: String = format!("{mapped_uid} {uid} 1");
    let gid_map = format!("{mapped_gid} {gid} 1");

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
        .exec_in_guest(&format!("stat /mnt/{FILE_NAME}",))
        .unwrap();
    // stat output example:
    // File: /mnt/user_file.txt
    // Size: 0                 Blocks: 0          IO Block: 4096   regular empty file
    // Device: 0,11    Inode: 11666031    Links: 1
    // Access: (0640/-rw-r-----)  Uid: (2350626183/ UNKNOWN)   Gid: (949179291/ UNKNOWN)
    // Access: 2023-04-05 03:06:27.110144457 +0000
    // Modify: 2023-04-05 03:06:27.110144457 +0000
    // Change: 2023-04-05 03:06:27.110144457 +0000
    assert!(output.stdout.contains(&format!("Uid: ({mapped_uid}/")));
    assert!(output.stdout.contains(&format!("Gid: ({mapped_gid}/")));
}

pub fn create_vu_fs_config(socket: &Path, shared_dir: &Path, tag: &str) -> VuConfig {
    let uid = base::geteuid();
    let gid = base::getegid();
    let socket_path = socket.to_str().unwrap();
    let shared_dir_path = shared_dir.to_str().unwrap();
    println!("socket={socket_path}, tag={tag}, shared_dir={shared_dir_path}");
    VuConfig::new(CmdType::Device, "vhost-user-fs").extra_args(vec![
        "fs".to_string(),
        format!("--socket-path={socket_path}"),
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

    let config = config.with_vhost_user("fs", socket.path());
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

    let config = config.with_vhost_user("fs", socket.path());
    let vm = TestVm::new(config).unwrap();

    mount_rw(vm, tag, temp_dir);
}

fn copy_file_validate_ugid_mapping(
    mut vm: TestVm,
    tag: &str,
    dir: TempDir,
    mapped_uid: u32,
    mapped_gid: u32,
) {
    use std::os::linux::fs::MetadataExt;
    const ORIGINAL_FILE_NAME: &str = "original.txt";
    const NEW_FILE_NAME: &str = "new.txt";
    const TEST_DATA: &str = "Hello world!";

    let orig_file = dir.path().join(ORIGINAL_FILE_NAME);

    std::fs::write(orig_file, TEST_DATA).unwrap();

    vm.exec_in_guest(&format!(
        "mount -t virtiofs {tag} /mnt && cp /mnt/{ORIGINAL_FILE_NAME} /mnt/{NEW_FILE_NAME} && sync",
    ))
    .unwrap();

    let output = vm
        .exec_in_guest(&format!("stat /mnt/{ORIGINAL_FILE_NAME}",))
        .unwrap();

    assert!(output.stdout.contains(&format!("Uid: ({mapped_uid}/")));
    assert!(output.stdout.contains(&format!("Gid: ({mapped_gid}/")));

    let new_file = dir.path().join(NEW_FILE_NAME);
    let output_stat = std::fs::metadata(new_file.clone());

    assert_eq!(
        output_stat
            .as_ref()
            .expect("stat of new_file failed")
            .st_uid(),
        base::geteuid()
    );
    assert_eq!(
        output_stat
            .as_ref()
            .expect("stat of new_file failed")
            .st_gid(),
        base::getegid()
    );

    let contents = std::fs::read(new_file).unwrap();
    assert_eq!(TEST_DATA.as_bytes(), &contents);
}

pub fn create_ugid_map_config(
    socket: &Path,
    shared_dir: &Path,
    tag: &str,
    mapped_uid: u32,
    mapped_gid: u32,
) -> VuConfig {
    let socket_path = socket.to_str().unwrap();
    let shared_dir_path = shared_dir.to_str().unwrap();

    let uid = base::geteuid();
    let gid = base::getegid();
    let ugid_map_value = format!("{mapped_uid} {mapped_gid} {uid} {gid} 7 /",);

    let cfg_arg = format!("writeback=true,ugid_map='{ugid_map_value}'");

    println!("socket={socket_path}, tag={tag}, shared_dir={shared_dir_path}");

    VuConfig::new(CmdType::Device, "vhost-user-fs").extra_args(vec![
        "fs".to_string(),
        format!("--socket-path={socket_path}"),
        format!("--shared-dir={shared_dir_path}"),
        format!("--tag={tag}"),
        format!("--cfg={cfg_arg}"),
        format!("--disable-sandbox"),
        format!("--skip-pivot-root=true"),
    ])
}

/// Tests file copy with disabled sandbox
///
/// 1. Create `original.txt` on a temporal directory.
/// 2. Setup ugid_map for vhost-user-fs backend
/// 3. Start a VM with a virtiofs device for the temporal directory.
/// 4. Copy `original.txt` to `new.txt` in the guest.
/// 5. Check that `new.txt` is created in the host.
/// 6. Verify the UID/GID of the files both in the guest and the host.
#[test]
fn vhost_user_fs_without_sandbox_and_pivot_root() {
    let socket = NamedTempFile::new().unwrap();
    let temp_dir = tempfile::tempdir().unwrap();

    let config = Config::new();
    let tag = "android";

    let mapped_uid = 123456;
    let mapped_gid = 12345;
    let vu_config =
        create_ugid_map_config(socket.path(), temp_dir.path(), tag, mapped_uid, mapped_gid);

    let _vu_device = VhostUserBackend::new(vu_config).unwrap();

    let config = config.with_vhost_user("fs", socket.path());
    let vm = TestVm::new(config).unwrap();

    copy_file_validate_ugid_mapping(vm, tag, temp_dir, mapped_uid, mapped_gid);
}

pub fn create_allowlist_fs_config(
    socket: &Path,
    shared_dir: &Path,
    tag: &str,
    allowlist_socket_path: &Path,
) -> VuConfig {
    let uid = base::geteuid();
    let gid = base::getegid();
    let socket_path = socket.to_str().unwrap();
    let shared_dir_path = shared_dir.to_str().unwrap();
    let allowlist_socket_path_str = allowlist_socket_path.to_str().unwrap();

    let ugid_map_value = format!("0 0 {uid} {gid} 7 /");
    let cfg_arg = format!("timeout=0,ugid_map='{ugid_map_value}'");

    VuConfig::new(CmdType::Device, "vhost-user-fs").extra_args(vec![
        "fs".to_string(),
        format!("--socket-path={socket_path}"),
        format!("--shared-dir={shared_dir_path}"),
        format!("--tag={tag}"),
        format!("--allowlist-socket-path={allowlist_socket_path_str}"),
        format!("--cfg={cfg_arg}"),
        "--disable-sandbox".to_string(),
        "--skip-pivot-root=true".to_string(),
    ])
}

/// Tests dynamic path filtering allowlist over control Unix socket.
///
/// Scenario:
/// 1. Create directories named "allowed" (to be registered) and "blocked" (to remain blocked) on
///    the host, each containing a test file.
/// 2. Initialize a Unix socket pair for allowlist control.
/// 3. Start the vhost-user-fs backend with the allowlist socket enabled, and boot a VM.
/// 4. Mount the virtiofs share in the guest.
/// 5. Verify that the "allowed" directory is initially inaccessible because the allowlist starts
///    empty.
/// 6. Dynamically grant access to `/allowed` via the control socket.
/// 7. Verify that:
///    - Reading the file inside `/allowed` (now accessible) succeeds.
///    - Creating a new file inside `/allowed` (now writable) succeeds.
///    - Reading the file inside `/blocked` (still inaccessible) fails.
///    - Creating a new file inside `/blocked` (still non-writable) fails.
/// 8. Dynamically revoke (remove) `/allowed` from the allowlist via the control socket.
/// 9. Verify that the `/allowed` directory becomes inaccessible again.
#[test]
fn vhost_user_fs_allowlist() {
    use base::Tube;
    use base::UnixSeqpacket;
    use vm_control::FsAllowlistCommand;
    use vm_control::FsAllowlistResponse;

    let socket = NamedTempFile::new().unwrap();
    let temp_dir = tempfile::tempdir().unwrap();

    // Create allowed and blocked directories and files
    let allowed_dir = temp_dir.path().join("allowed");
    std::fs::create_dir(&allowed_dir).unwrap();
    let allowed_file = allowed_dir.join("a.txt");
    std::fs::write(&allowed_file, "allowed data").unwrap();

    let blocked_dir = temp_dir.path().join("blocked");
    std::fs::create_dir(&blocked_dir).unwrap();
    let blocked_file = blocked_dir.join("b.txt");
    std::fs::write(&blocked_file, "blocked data").unwrap();

    // Create allowlist socket path
    let allowlist_socket_path = temp_dir.path().join("allowlist.sock");

    let config = Config::new();
    let tag = "mtdtest";

    let vu_config =
        create_allowlist_fs_config(socket.path(), temp_dir.path(), tag, &allowlist_socket_path);
    let _vu_device = VhostUserBackend::new(vu_config).unwrap();

    let client_socket = UnixSeqpacket::connect(&allowlist_socket_path).unwrap();
    let parent_tube = Tube::try_from(client_socket).unwrap();

    let config = config.with_vhost_user("fs", socket.path());
    let mut vm = TestVm::new(config).unwrap();

    // Mount the directory
    vm.exec_in_guest("mount -t virtiofs mtdtest /mnt").unwrap();

    // Dynamic allowlist starts enabled but completely empty.
    // So even '/allowed' should be inaccessible at first!
    let lookup_initial = vm.exec_in_guest("cat /mnt/allowed/a.txt");
    assert!(lookup_initial.is_err());

    // Now let's dynamically grant access to (allow) the '/allowed' path!
    // Note that PassthroughFs allowlist uses absolute paths starting with '/' relative to the root
    // of the share. So the path of the allowed directory relative to the shared_dir root is
    // "/allowed".
    parent_tube
        .send(&FsAllowlistCommand::AddPaths {
            paths: vec!["/allowed".into()],
        })
        .unwrap();
    let resp: FsAllowlistResponse = parent_tube.recv().unwrap();
    assert!(matches!(resp, FsAllowlistResponse::Ok));

    // Reading the file inside the now-accessible `/allowed` directory should succeed!
    let lookup_allowed = vm.exec_in_guest("cat /mnt/allowed/a.txt").unwrap();
    assert_eq!(lookup_allowed.stdout.trim(), "allowed data");

    // Reading the blocked file should still fail (NotFound)!
    let lookup_blocked = vm.exec_in_guest("cat /mnt/blocked/b.txt");
    assert!(lookup_blocked.is_err());

    // Creating a file inside the now-writable `/allowed` directory should succeed!
    vm.exec_in_guest("echo -n 'new data' > /mnt/allowed/new.txt")
        .unwrap();
    let new_file_host = allowed_dir.join("new.txt");
    assert_eq!(std::fs::read_to_string(new_file_host).unwrap(), "new data");

    // Creating a file inside the blocked directory should fail!
    let create_blocked = vm.exec_in_guest("echo -n 'new data' > /mnt/blocked/new.txt");
    assert!(create_blocked.is_err());

    // Dynamically revoke (remove) the `/allowed` path!
    parent_tube
        .send(&FsAllowlistCommand::RemovePaths {
            paths: vec!["/allowed".into()],
        })
        .unwrap();
    let resp: FsAllowlistResponse = parent_tube.recv().unwrap();
    assert!(matches!(resp, FsAllowlistResponse::Ok));

    // Now reading the file inside `/allowed` should fail again as it is no longer accessible!
    let lookup_allowed_removed = vm.exec_in_guest("cat /mnt/allowed/a.txt");
    assert!(lookup_allowed_removed.is_err());

    // Sending an invalid path (traverses above root) should fail and return Err
    parent_tube
        .send(&FsAllowlistCommand::AddPaths {
            paths: vec!["/allowed/../../..".into()],
        })
        .unwrap();
    let resp: FsAllowlistResponse = parent_tube.recv().unwrap();
    assert!(matches!(resp, FsAllowlistResponse::Err(_)));

    // Removing a non-existent path should fail and return Err
    parent_tube
        .send(&FsAllowlistCommand::RemovePaths {
            paths: vec!["/non_existent".into()],
        })
        .unwrap();
    let resp: FsAllowlistResponse = parent_tube.recv().unwrap();
    assert!(matches!(resp, FsAllowlistResponse::Err(_)));

    // Removing an invalid path should fail and return Err
    parent_tube
        .send(&FsAllowlistCommand::RemovePaths {
            paths: vec!["/allowed/../../..".into()],
        })
        .unwrap();
    let resp: FsAllowlistResponse = parent_tube.recv().unwrap();
    assert!(matches!(resp, FsAllowlistResponse::Err(_)));
}
