// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Testing virtio-fs.

use fixture::vm::Config;
use fixture::vm::TestVm;

/// Tests file copy on virtiofs
///
/// 1. Create `original.txt` on a temporal directory.
/// 2. Start a VM with a virtiofs device for the temporal directory.
/// 3. Copy `original.txt` to `new.txt` in the guest.
/// 4. Check that `new.txt` is created in the host.
#[test]
fn copy_file() {
    const ORIGINAL_FILE_NAME: &str = "original.txt";
    const NEW_FILE_NAME: &str = "new.txt";
    const TEST_DATA: &str = "virtiofs works!";

    let temp_dir = tempfile::tempdir().unwrap();
    let orig_file = temp_dir.path().join(ORIGINAL_FILE_NAME);

    std::fs::write(orig_file, TEST_DATA).unwrap();

    let tag = "mtdtest";

    let config = Config::new().extra_args(vec![
        "--shared-dir".to_string(),
        format!(
            "{}:{tag}:type=fs:cache=auto",
            temp_dir.path().to_str().unwrap()
        ),
    ]);

    let mut vm = TestVm::new(config).unwrap();
    // TODO(b/269137600): Split this into multiple lines instead of connecting commands with `&&`.
    vm.exec_in_guest(&format!(
        "mount -t virtiofs {tag} /mnt && cp /mnt/{} /mnt/{} && sync",
        ORIGINAL_FILE_NAME, NEW_FILE_NAME,
    ))
    .unwrap();

    let new_file = temp_dir.path().join(NEW_FILE_NAME);
    let contents = std::fs::read(new_file).unwrap();
    assert_eq!(TEST_DATA.as_bytes(), &contents);
}

/// Tests file ownership seen by the VM.
///
/// 1. Create `user_file.txt` owned by the current user of the host on a
///    temporal directory.
/// 2. Set virtiofs options: uidmap=<mapped-uid> <current-uid> 1,
///    uid=<mapped-uid>.
/// 3. Start a VM with a virtiofs device for the temporal directory.
/// 4. Check that `user_file.txt`'s uid is <mapped-uid> in the VM.
/// 5. Verify gid similarly.
#[cfg(unix)]
#[test]
fn file_ugid() {
    const FILE_NAME: &str = "user_file.txt";
    let uid = base::geteuid();
    let gid = base::getegid();
    let mapped_uid: u32 = rand::random();
    let mapped_gid: u32 = rand::random();
    let uid_map = format!("{} {} 1", mapped_uid, uid);
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
    assert!(output.contains(&format!("Uid: ({}/", mapped_uid)));
    assert!(output.contains(&format!("Gid: ({}/", mapped_gid)));
}
