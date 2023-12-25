// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::time::Duration;

use fixture::vm::Config;
use fixture::vm::TestVm;

#[test]
fn boot_test_vm() -> anyhow::Result<()> {
    let mut vm = TestVm::new(Config::new()).unwrap();
    assert_eq!(vm.exec_in_guest("echo 42")?.stdout.trim(), "42");
    Ok(())
}

#[test]
fn boot_custom_vm_kernel_initrd() -> anyhow::Result<()> {
    let cfg = Config::new()
    .with_kernel("https://storage.googleapis.com/crosvm/integration_tests/benchmarks/custom-guest-bzimage-x86_64-r0001")
    .with_initrd("https://storage.googleapis.com/crosvm/integration_tests/benchmarks/custom-initramfs.cpio.gz-r0005")
    // Use a non-sense file as rootfs to prove delegate correctly function in initrd
    .with_rootfs("https://storage.googleapis.com/crosvm/integration_tests/guest-bzimage-aarch64-r0007")
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
    Ok(())
}

#[test]
fn boot_test_vm_uring() -> anyhow::Result<()> {
    let mut vm = TestVm::new(
        Config::new().extra_args(vec!["--async-executor".to_string(), "uring".to_string()]),
    )
    .unwrap();
    assert_eq!(vm.exec_in_guest("echo 42")?.stdout.trim(), "42");
    Ok(())
}

#[cfg(any(target_os = "android", target_os = "linux"))]
#[test]
fn boot_test_vm_odirect() {
    let mut vm = TestVm::new(Config::new().o_direct()).unwrap();
    assert_eq!(vm.exec_in_guest("echo 42").unwrap().stdout.trim(), "42");
}

#[cfg(any(target_os = "android", target_os = "linux"))]
#[test]
fn boot_test_vm_config_file() {
    let mut vm = TestVm::new_with_config_file(Config::new()).unwrap();
    assert_eq!(vm.exec_in_guest("echo 42").unwrap().stdout.trim(), "42");
}

/*
 * VCPU-level suspend/resume tests (which does NOT suspend the devices)
 */

#[cfg(any(target_os = "android", target_os = "linux"))]
#[test]
fn vcpu_suspend_resume_succeeds() {
    // There is no easy way for us to check if the VM is actually suspended. But at
    // least exercise the code-path.
    let mut vm = TestVm::new(Config::new()).unwrap();
    vm.suspend().unwrap();
    vm.resume().unwrap();
    assert_eq!(vm.exec_in_guest("echo 42").unwrap().stdout.trim(), "42");
}

#[cfg(any(target_os = "android", target_os = "linux"))]
#[test]
fn vcpu_suspend_resume_succeeds_with_pvclock() {
    // There is no easy way for us to check if the VM is actually suspended. But at
    // least exercise the code-path.
    let mut config = Config::new();
    config = config.extra_args(vec!["--pvclock".to_string()]);
    let mut vm = TestVm::new(config).unwrap();
    vm.suspend().unwrap();
    vm.resume().unwrap();
    assert_eq!(vm.exec_in_guest("echo 42").unwrap().stdout.trim(), "42");
}

/*
 * Full suspend/resume tests (which suspend the devices and vcpus)
 */

#[cfg(any(target_os = "android", target_os = "linux"))]
#[test]
fn full_suspend_resume_test_suspend_resume_full() {
    // There is no easy way for us to check if the VM is actually suspended. But at
    // least exercise the code-path.
    let mut config = Config::new();
    config = config.with_stdout_hardware("legacy-virtio-console");
    // Why this test is called "full"? Can anyone explain...?
    config = config.extra_args(vec![
        "--no-usb".to_string(),
        "--no-balloon".to_string(),
        "--no-rng".to_string(),
    ]);
    let mut vm = TestVm::new(config).unwrap();
    vm.suspend_full().unwrap();
    vm.resume_full().unwrap();
    assert_eq!(vm.exec_in_guest("echo 42").unwrap().stdout.trim(), "42");
}

#[cfg(any(target_os = "android", target_os = "linux"))]
#[test]
fn full_suspend_resume_with_pvclock() {
    // There is no easy way for us to check if the VM is actually suspended. But at
    // least exercise the code-path.
    let mut config = Config::new();
    config = config.with_stdout_hardware("legacy-virtio-console");
    config = config.extra_args(vec![
        "--no-usb".to_string(),
        "--no-balloon".to_string(),
        "--no-rng".to_string(),
        "--pvclock".to_string(),
    ]);
    let mut vm = TestVm::new(config).unwrap();
    vm.suspend_full().unwrap();
    vm.resume_full().unwrap();
    assert_eq!(vm.exec_in_guest("echo 42").unwrap().stdout.trim(), "42");
}

#[cfg(any(target_os = "android", target_os = "linux"))]
#[test]
fn vcpu_suspend_resume_with_pvclock_adjusts_guest_clocks() {
    use readclock::ClockValues;

    // SUSPEND_DURATION defines how long the VM should be suspended
    const SUSPEND_DURATION: Duration = Duration::from_secs(2);
    const ALLOWANCE: Duration = Duration::from_secs(1);

    // Launch a VM with pvclock option
    let mut config = Config::new();
    config = config.with_stdout_hardware("legacy-virtio-console");
    config = config.extra_args(vec![
        "--no-usb".to_string(),
        "--no-balloon".to_string(),
        "--no-rng".to_string(),
        "--pvclock".to_string(),
    ]);
    let mut vm = TestVm::new(config).unwrap();

    // Mount the proc fs
    vm.exec_in_guest("mount proc /proc -t proc").unwrap();
    // Ensure that the kernel has virtio-pvclock
    assert_eq!(
        vm.exec_in_guest("cat /proc/config.gz | gunzip | grep '^CONFIG_VIRTIO_PVCLOCK'")
            .unwrap()
            .stdout
            .trim(),
        "CONFIG_VIRTIO_PVCLOCK=y"
    );

    let guest_clocks_before = vm.guest_clock_values().unwrap();
    let host_clocks_before = ClockValues::now();
    vm.suspend().unwrap();
    println!("Sleeping {SUSPEND_DURATION:?}...");
    std::thread::sleep(SUSPEND_DURATION);
    vm.resume().unwrap();
    // Sleep a bit, to give the guest a chance to move the CLOCK_BOOTTIME value forward.
    std::thread::sleep(SUSPEND_DURATION);
    let guest_clocks_after = vm.guest_clock_values().unwrap();
    let host_clocks_after = ClockValues::now();
    // Calculating in f64 since the result may be negative
    let guest_mono_diff = guest_clocks_after.clock_monotonic().as_secs_f64()
        - guest_clocks_before.clock_monotonic().as_secs_f64();
    let guest_boot_diff = guest_clocks_after.clock_boottime().as_secs_f64()
        - guest_clocks_before.clock_boottime().as_secs_f64();
    let host_boot_diff = host_clocks_after.clock_boottime().as_secs_f64()
        - host_clocks_before.clock_boottime().as_secs_f64();

    assert!(host_boot_diff > SUSPEND_DURATION.as_secs_f64());
    // Although the BOOTTIME and MONOTONIC behavior varies in general for some real-world factors
    // like the implementation of the kernel, the virtualization platforms and hardware issues,
    // when virtio-pvclock is in use, crosvm does its best effort to maintain the following
    // invariants to make the guest's userland peaceful:

    // Invariants 1: Guest's MONOTONIC behaves as if they are stopped during the VM is suspended in
    // terms of crosvm's VM instance running state. In other words, the guest's monotonic
    // difference is smaller than the "real" time experienced by the host by SUSPEND_DURATION.
    let monotonic_error = guest_mono_diff + SUSPEND_DURATION.as_secs_f64() - host_boot_diff;
    assert!(monotonic_error < ALLOWANCE.as_secs_f64());

    // Invariants 2: Subtracting Guest's MONOTONIC from the Guest's BOOTTIME should be
    // equal to the total duration that the VM was in the "suspended" state as noted
    // in the Invariants 1.
    let guest_suspend_duration = guest_boot_diff - guest_mono_diff;
    let boottime_error = (guest_suspend_duration - SUSPEND_DURATION.as_secs_f64()).abs();
    assert!(boottime_error < ALLOWANCE.as_secs_f64());
}

#[cfg(any(target_os = "android", target_os = "linux"))]
#[test]
fn boot_test_vm_disable_sandbox() {
    let mut vm = TestVm::new(Config::new().disable_sandbox()).unwrap();
    assert_eq!(vm.exec_in_guest("echo 42").unwrap().stdout.trim(), "42");
}

#[cfg(any(target_os = "android", target_os = "linux"))]
#[test]
fn boot_test_vm_disable_sandbox_odirect() {
    let mut vm = TestVm::new(Config::new().disable_sandbox().o_direct()).unwrap();
    assert_eq!(vm.exec_in_guest("echo 42").unwrap().stdout.trim(), "42");
}

#[cfg(any(target_os = "android", target_os = "linux"))]
#[test]
fn boot_test_vm_disable_sandbox_config_file() {
    let mut vm = TestVm::new_with_config_file(Config::new().disable_sandbox()).unwrap();
    assert_eq!(vm.exec_in_guest("echo 42").unwrap().stdout.trim(), "42");
}

#[cfg(any(target_os = "android", target_os = "linux"))]
#[test]
fn boot_test_disable_sandbox_suspend_resume() {
    // There is no easy way for us to check if the VM is actually suspended. But at
    // least exercise the code-path.
    let mut vm = TestVm::new(Config::new().disable_sandbox()).unwrap();
    vm.suspend().unwrap();
    vm.resume().unwrap();
    assert_eq!(vm.exec_in_guest("echo 42").unwrap().stdout.trim(), "42");
}
