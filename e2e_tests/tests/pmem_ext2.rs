// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Testing pmem-ext2 device.

#![cfg(any(target_os = "android", target_os = "linux"))]

use std::os::unix::fs::symlink;

use fixture::vm::Config;
use fixture::vm::TestVm;

/// Check file contents on pmem-ext2
#[test]
fn pmem_ext2() -> anyhow::Result<()> {
    // /temp_dir/
    // ├── a.txt
    // └── dir
    //     ├── b.txt
    //     └── symlink_a -> ../a.txt

    const A_TXT_NAME: &str = "a.txt";
    const A_TXT_DATA: &str = "Hello!";
    const DIR_NAME: &str = "dir";
    const B_TXT_NAME: &str = "b.txt";
    const B_TXT_DATA: &str = "test test test\ntest test test";
    const SYMLINK_A_NAME: &str = "symlink_a";
    const SYMLINK_A_DEST: &str = "../a.txt";

    let temp_dir = tempfile::tempdir()?;
    let a_txt = temp_dir.path().join(A_TXT_NAME);
    std::fs::write(a_txt, A_TXT_DATA)?;
    let dir = temp_dir.path().join(DIR_NAME);
    std::fs::create_dir(&dir)?;
    let b_txt = dir.join(B_TXT_NAME);
    std::fs::write(b_txt, B_TXT_DATA)?;
    let symlink_a = dir.join(SYMLINK_A_NAME);
    symlink(SYMLINK_A_DEST, symlink_a)?;

    let config = Config::new().extra_args(vec![
        "--pmem-ext2".to_string(),
        temp_dir.path().to_str().unwrap().to_string(),
    ]);

    let mut vm = TestVm::new(config)?;
    vm.exec_in_guest("mount -t ext2 /dev/pmem0 /mnt/")?;

    // List all files
    let find_result = vm
        .exec_in_guest_async("find /mnt/ | sort")?
        .with_timeout(std::time::Duration::from_secs(1))
        .wait_ok(&mut vm)?;
    assert_eq!(
        find_result.stdout.trim(),
        r"/mnt/
/mnt/a.txt
/mnt/dir
/mnt/dir/b.txt
/mnt/dir/symlink_a
/mnt/lost+found"
    );

    let a_result = vm
        .exec_in_guest_async(&format!("cat /mnt/{A_TXT_NAME}"))?
        .with_timeout(std::time::Duration::from_secs(1))
        .wait_ok(&mut vm)?;
    assert_eq!(a_result.stdout.trim(), A_TXT_DATA);
    let b_result = vm
        .exec_in_guest_async(&format!("cat /mnt/{DIR_NAME}/{B_TXT_NAME}"))?
        .with_timeout(std::time::Duration::from_secs(1))
        .wait_ok(&mut vm)?;
    assert_eq!(b_result.stdout.trim(), B_TXT_DATA);

    // Trying to read a non-existent file should return an error
    let non_existent_result = vm
        .exec_in_guest_async(&format!("cat /mnt/{DIR_NAME}/non-existent"))?
        .with_timeout(std::time::Duration::from_secs(1))
        .wait_ok(&mut vm);
    assert!(non_existent_result.is_err());

    let readlink_result = vm
        .exec_in_guest_async(&format!("readlink /mnt/{DIR_NAME}/{SYMLINK_A_NAME}"))?
        .with_timeout(std::time::Duration::from_secs(1))
        .wait_ok(&mut vm)?;
    assert_eq!(readlink_result.stdout.trim(), SYMLINK_A_DEST);

    let symlink_a_result = vm
        .exec_in_guest_async(&format!("cat /mnt/{DIR_NAME}/{SYMLINK_A_NAME}"))?
        .with_timeout(std::time::Duration::from_secs(1))
        .wait_ok(&mut vm)?;
    assert_eq!(symlink_a_result.stdout.trim(), A_TXT_DATA);

    Ok(())
}

/// Check a case with 1000 files in a directory.
#[test]
fn pmem_ext2_manyfiles() -> anyhow::Result<()> {
    // /temp_dir/
    // ├── 0.txt
    // ...
    // └── 999.txt

    let temp_dir = tempfile::tempdir()?;
    for i in 0..1000 {
        let f = temp_dir.path().join(&format!("{i}.txt"));
        std::fs::write(f, &format!("{i}"))?;
    }

    let config = Config::new().extra_args(vec![
        "--pmem-ext2".to_string(),
        temp_dir.path().to_str().unwrap().to_string(),
    ]);

    let mut vm = TestVm::new(config)?;
    vm.exec_in_guest("mount -t ext2 /dev/pmem0 /mnt/")?;

    // `ls -l` returns 1002 lines because 1000 files + 'lost+found' and the total line.
    let ls_result = vm
        .exec_in_guest_async("ls -l /mnt/ | wc -l")?
        .with_timeout(std::time::Duration::from_secs(1))
        .wait_ok(&mut vm)?;
    assert_eq!(ls_result.stdout.trim(), "1002");

    Ok(())
}

/// Starts pmem-ext2 device with the given uid/gid setting and share a file created by the current
/// user with the guest. Returns (uid, gid) in the guest.
fn start_with_ugid_map(
    uid: u32,
    uid_map: &str,
    gid: u32,
    gid_map: &str,
) -> anyhow::Result<(u32, u32)> {
    let temp_dir = tempfile::tempdir()?;
    let a = temp_dir.path().join("a.txt");
    std::fs::write(a, "A")?;

    let dir_path = temp_dir.path().to_str().unwrap().to_string();
    let config = Config::new().extra_args(vec![
        "--pmem-ext2".to_string(),
        format!("{dir_path}:uidmap={uid_map}:gidmap={gid_map}:uid={uid}:gid={gid}"),
    ]);

    let mut vm = TestVm::new(config)?;
    vm.exec_in_guest("mount -t ext2 /dev/pmem0 /mnt/")?;

    let result = vm
        .exec_in_guest_async("stat --printf '%u %g' /mnt/a.txt")?
        .with_timeout(std::time::Duration::from_secs(1))
        .wait_ok(&mut vm)?;
    let out = result.stdout.trim();
    println!("guest ugid: {out}");
    let ids = out
        .split(" ")
        .map(|s| s.parse::<u32>())
        .collect::<Result<Vec<u32>, _>>()
        .unwrap();
    assert_eq!(ids.len(), 2);
    Ok((ids[0], ids[1])) // (uid, gid)
}

fn geteugid() -> (u32, u32) {
    // SAFETY: geteuid never fails.
    let euid = unsafe { libc::geteuid() };
    // SAFETY: getegid never fails.
    let egid = unsafe { libc::getegid() };
    (euid, egid)
}

/// Maps to the same id in the guest.
#[test]
fn pmem_ext2_ugid_map_identical() {
    let (host_uid, host_gid) = geteugid();

    let uid_map = format!("{host_uid} {host_uid} 1");
    let gid_map = format!("{host_gid} {host_gid} 1");
    let (guest_uid, guest_gid) =
        start_with_ugid_map(host_uid, &uid_map, host_gid, &gid_map).unwrap();
    assert_eq!(host_uid, guest_uid);
    assert_eq!(host_gid, guest_gid);
}

/// Maps to the root in the guest.
#[test]
fn pmem_ext2_ugid_map_to_root() {
    let (host_uid, host_gid) = geteugid();

    let uid_map = format!("0 {host_uid} 1");
    let gid_map = format!("0 {host_gid} 1");
    let (guest_uid, guest_gid) = start_with_ugid_map(0, &uid_map, 0, &gid_map).unwrap();
    assert_eq!(guest_uid, 0);
    assert_eq!(guest_gid, 0);
}

/// Maps to fake ids in the guest.
#[test]
fn pmem_ext2_ugid_map_fake_ids() {
    let (host_uid, host_gid) = geteugid();

    let fake_uid = 1234;
    let fake_gid = 5678;

    let uid_map = format!("{fake_uid} {host_uid} 1");
    let gid_map = format!("{fake_gid} {host_gid} 1");
    let (guest_uid, guest_gid) =
        start_with_ugid_map(fake_uid, &uid_map, fake_gid, &gid_map).unwrap();
    assert_eq!(guest_uid, fake_uid);
    assert_eq!(guest_gid, fake_gid);
}
