// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::time::Duration;

use fixture::vm::Config;
use fixture::vm::TestVm;

#[test]
fn psql() -> anyhow::Result<()> {
    let cfg = Config::from_env()
    .with_kernel("https://storage.googleapis.com/crosvm/integration_tests/guest-bzimage-x86_64-r0009")
    .with_initrd("https://storage.googleapis.com/crosvm/integration_tests/benchmarks/custom-initramfs.cpio.gz-r0005")
    // Created by e2e_tests/guest_under_test/rootfs_benches/postgres.sh
    .with_rootfs("https://storage.googleapis.com/crosvm/integration_tests/benchmarks/postgres-rootfs.img.zst-r0001").rootfs_is_rw().rootfs_is_compressed()
    .with_stdout_hardware("serial").extra_args(vec!["--mem".to_owned(), "512".to_owned()]);
    let mut vm = TestVm::new(cfg).unwrap();
    assert_eq!(
        vm.exec_in_guest_async("echo 42")?
            .with_timeout(Duration::from_secs(500))
            .wait_ok(&mut vm)?
            .stdout
            .trim(),
        "42"
    );
    vm.exec_in_guest("cd /root")?;
    vm.exec_in_guest("PATH=$PATH:/usr/lib/postgresql/15/bin PGDATA=/var/lib/postgresql/data POSTGRES_PASSWORD=mysecretpassword nohup /usr/local/bin/docker-entrypoint.sh postgres > /dev/null 2>&1 </dev/null &")?;
    vm.exec_in_guest("sleep 5")?;
    vm.exec_in_guest("pgbench -U postgres -i -s 10 postgres")?;
    vm.exec_in_guest("pgbench -U postgres -c 1 -j 1 -t 1000 postgres 1>&2")?;
    Ok(())
}
