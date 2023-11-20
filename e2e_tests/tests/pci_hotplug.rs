// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Integration test for hotplug of tap devices as virtio-net.

#![cfg(all(unix, target_arch = "x86_64"))]

use std::net::Ipv4Addr;
use std::process::Command;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use base::sys::linux::ioctl_with_val;
use base::test_utils::call_test_with_sudo;
use fixture::vm::Config;
use fixture::vm::TestVm;
use net_util::sys::linux::Tap;
use net_util::sys::linux::TapTLinux;
use net_util::MacAddress;
use net_util::TapTCommon;

/// Count the number of virtio-net devices.
fn count_virtio_net_devices(vm: &mut TestVm) -> usize {
    let lspci_result = vm.exec_in_guest("lspci -n").unwrap();
    // Count occurance for virtio net device: 1af4:1041
    lspci_result.stdout.matches("1af4:1041").count()
}

/// Poll func until it returns true, or timeout is exceeded.
fn poll_until_true<F>(vm: &mut TestVm, func: F, timeout: Duration) -> bool
where
    F: Fn(&mut TestVm) -> bool,
{
    let poll_interval = Duration::from_millis(100);
    let start_time = Instant::now();
    while !func(vm) {
        if start_time.elapsed() > timeout {
            return false;
        }
        thread::sleep(poll_interval);
    }
    true
}

/// setup a tap device for test
fn setup_tap_device(tap_name: &[u8], ip_addr: Ipv4Addr, netmask: Ipv4Addr, mac_addr: MacAddress) {
    let tap = Tap::new_with_name(tap_name, true, false).unwrap();
    // ioctl is safe since we call it with a valid tap fd and check the return value.
    let ret = unsafe { ioctl_with_val(&tap, net_sys::TUNSETPERSIST(), 1) };
    if ret < 0 {
        panic!("Failed to persist tap interface");
    }
    tap.set_ip_addr(ip_addr).unwrap();
    tap.set_netmask(netmask).unwrap();
    tap.set_mac_address(mac_addr).unwrap();
    tap.set_vnet_hdr_size(16).unwrap();
    tap.set_offload(0).unwrap();
    tap.enable().unwrap();
    // Release tap to be used by the VM.
    drop(tap);
}

/// Implementation for tap_hotplug_two
///
/// This test will fail by itself due to permission.
#[ignore = "Only to be called by tap_hotplug_two"]
#[test]
fn tap_hotplug_two_impl() {
    let wait_timeout = Duration::from_secs(5);
    // Setup VM start parameter.
    let config = Config::new().extra_args(vec!["--pci-hotplug-slots".to_owned(), "2".to_owned()]);
    let mut vm = TestVm::new(config).unwrap();

    //Setup test taps.
    let tap1_name = "test_tap1";
    setup_tap_device(
        tap1_name.as_bytes(),
        "100.115.92.15".parse().unwrap(),
        "255.255.255.252".parse().unwrap(),
        "a0:b0:c0:d0:e0:f1".parse().unwrap(),
    );
    let tap2_name = "test_tap2";
    setup_tap_device(
        tap2_name.as_bytes(),
        "100.115.92.25".parse().unwrap(),
        "255.255.255.252".parse().unwrap(),
        "a0:b0:c0:d0:e0:f2".parse().unwrap(),
    );

    // Check number of virtio-net devices after each hotplug.
    assert!(poll_until_true(
        &mut vm,
        |vm| { count_virtio_net_devices(vm) == 0 },
        wait_timeout
    ));
    vm.hotplug_tap(tap1_name).unwrap();
    assert!(poll_until_true(
        &mut vm,
        |vm| { count_virtio_net_devices(vm) == 1 },
        wait_timeout
    ));
    vm.hotplug_tap(tap2_name).unwrap();
    assert!(poll_until_true(
        &mut vm,
        |vm| { count_virtio_net_devices(vm) == 2 },
        wait_timeout
    ));

    // Check number of devices after each removal.
    vm.remove_pci_device(1).unwrap();
    assert!(poll_until_true(
        &mut vm,
        |vm| { count_virtio_net_devices(vm) == 1 },
        wait_timeout
    ));
    vm.remove_pci_device(2).unwrap();
    assert!(poll_until_true(
        &mut vm,
        |vm| { count_virtio_net_devices(vm) == 0 },
        wait_timeout
    ));

    drop(vm);
    Command::new("ip")
        .args(["link", "delete", tap1_name])
        .status()
        .unwrap();
    Command::new("ip")
        .args(["link", "delete", tap2_name])
        .status()
        .unwrap();
}

/// Checks hotplug works with two tap devices.
#[test]
fn tap_hotplug_two() {
    call_test_with_sudo("tap_hotplug_two_impl");
}

/// Implementation for tap_hotplug_add_remove_add
///
/// This test will fail by itself due to permission.
#[ignore = "Only to be called by tap_hotplug_add_remove_add"]
#[test]
fn tap_hotplug_add_remove_add_impl() {
    let wait_timeout = Duration::from_secs(5);
    // Setup VM start parameter.
    let config = Config::new().extra_args(vec!["--pci-hotplug-slots".to_owned(), "1".to_owned()]);
    let mut vm = TestVm::new(config).unwrap();

    //Setup test tap
    let tap_name = "test_tap";
    setup_tap_device(
        tap_name.as_bytes(),
        "100.115.92.5".parse().unwrap(),
        "255.255.255.252".parse().unwrap(),
        "a0:b0:c0:d0:e0:f0".parse().unwrap(),
    );

    assert!(poll_until_true(
        &mut vm,
        |vm| { count_virtio_net_devices(vm) == 0 },
        wait_timeout
    ));
    // Hotplug tap.
    vm.hotplug_tap(tap_name).unwrap();
    // Wait until virtio-net device appears in guest OS.
    assert!(poll_until_true(
        &mut vm,
        |vm| { count_virtio_net_devices(vm) == 1 },
        wait_timeout
    ));

    // Remove hotplugged tap device.
    vm.remove_pci_device(1).unwrap();
    // Wait until virtio-net device disappears from guest OS.
    assert!(poll_until_true(
        &mut vm,
        |vm| { count_virtio_net_devices(vm) == 0 },
        wait_timeout
    ));

    // Hotplug tap again.
    vm.hotplug_tap(tap_name).unwrap();
    // Wait until virtio-net device appears in guest OS.
    assert!(poll_until_true(
        &mut vm,
        |vm| { count_virtio_net_devices(vm) == 1 },
        wait_timeout
    ));

    drop(vm);
    Command::new("ip")
        .args(["link", "delete", tap_name])
        .status()
        .unwrap();
}

/// Checks tap hotplug works with a device added, removed, then added again.
#[test]
fn tap_hotplug_add_remove_add() {
    call_test_with_sudo("tap_hotplug_add_remove_add_impl");
}
