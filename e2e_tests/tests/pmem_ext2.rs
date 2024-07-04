// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Testing pmem-ext2 device.

#![cfg(any(target_os = "android", target_os = "linux"))]

use std::os::unix::fs::symlink;

use anyhow::bail;
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

fn set_num_files_limit(num_files: u64) -> anyhow::Result<()> {
    let mut buf = std::mem::MaybeUninit::<libc::rlimit64>::zeroed();
    // SAFETY: Safe because this will only modify `buf` and we check the return value.
    let res =
        unsafe { libc::prlimit64(0, libc::RLIMIT_NOFILE, std::ptr::null(), buf.as_mut_ptr()) };
    if res != 0 {
        bail!("failed to call prlimit64");
    }

    // SAFETY: Safe because the kernel guarantees that the struct is fully initialized.
    let mut limit = unsafe { buf.assume_init() };
    if limit.rlim_max < num_files {
        bail!("rlim_max < num_files: {} < {}", limit.rlim_max, num_files);
    }

    limit.rlim_cur = num_files;
    // SAFETY: Safe because limit is properly initialized.
    let res = unsafe { libc::setrlimit64(libc::RLIMIT_NOFILE, &limit) };
    if res != 0 {
        bail!("failed to call setrlimit64");
    }

    Ok(())
}

/// Check a case with 1000 files in a directory.
#[test]
fn pmem_ext2_manyfiles() -> anyhow::Result<()> {
    // /temp_dir/
    // ├── 0.txt
    // ...
    // └── 999.txt

    // TODO(crrev.com/c/5644847): Remove `set_num_files_limi` once we add a logic to fork a separate
    // process for ext2 creation with larger files limit.
    set_num_files_limit(2048)?;

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
