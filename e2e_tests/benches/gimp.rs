// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::time::Duration;

use fixture::vm::Config;
use fixture::vm::TestVm;

#[test]
fn gimp() -> anyhow::Result<()> {
    let cfg = Config::from_env()
    .with_kernel("https://storage.googleapis.com/crosvm/integration_tests/guest-bzimage-x86_64-r0009")
    .with_initrd("https://storage.googleapis.com/crosvm/integration_tests/benchmarks/custom-initramfs.cpio.gz-r0005")
    // Created by e2e_tests/guest_under_test/rootfs_benches/gimp/make.sh
    .with_rootfs("https://storage.googleapis.com/crosvm/integration_tests/benchmarks/gimp-rootfs.img.zst-r0001").rootfs_is_rw().rootfs_is_compressed()
    .with_stdout_hardware("serial").extra_args(vec!["--mem".to_owned(), "1024".to_owned()]);
    let mut vm = TestVm::new(cfg).unwrap();
    assert_eq!(
        vm.exec_in_guest_async("echo 42")?
            .with_timeout(Duration::from_secs(500))
            .wait_ok(&mut vm)?
            .stdout
            .trim(),
        "42"
    );
    vm.exec_in_guest("cd /workdir")?;
    // Time initializing all plugins and execute action
    vm.exec_in_guest(
        r#"/usr/bin/gimp -i -b '(let* ((image (car (gimp-file-load RUN-NONINTERACTIVE "/workdir/test1.png" "/workdir/test1.png")))(drawable (car (gimp-image-get-active-layer image)))) (plug-in-mblur RUN-NONINTERACTIVE image drawable 1 0 45 200 200) (gimp-file-save RUN-NONINTERACTIVE image drawable "/workdir/out1.png" "/workdir/out1.png"))' -b '(gimp-quit 0)'"#,
    )?;
    // Time executing action only
    vm.exec_in_guest(
        r#"/usr/bin/gimp -i -b '(let* ((image (car (gimp-file-load RUN-NONINTERACTIVE "/workdir/test2.png" "/workdir/test2.png")))(drawable (car (gimp-image-get-active-layer image)))) (plug-in-mblur RUN-NONINTERACTIVE image drawable 1 0 45 200 200) (gimp-file-save RUN-NONINTERACTIVE image drawable "/workdir/out2.png" "/workdir/out2.png"))' -b '(gimp-quit 0)'"#,
    )?;
    Ok(())
}
