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
