// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(any(target_os = "android", target_os = "linux"))]

use std::net;

use base::test_utils::call_test_with_sudo;
use net_util::sys::linux::Tap;
use net_util::sys::linux::TapTLinux;
use net_util::MacAddress;
use net_util::TapTCommon;

#[test]
fn tap_create() {
    call_test_with_sudo("tap_create_impl")
}

#[test]
#[ignore = "Only to be called by tap_create"]
fn tap_create_impl() {
    Tap::new(true, false).unwrap();
}

#[test]
fn tap_configure() {
    call_test_with_sudo("tap_configure_impl")
}

#[test]
#[ignore = "Only to be called by tap_configure"]
fn tap_configure_impl() {
    let tap = Tap::new(true, false).unwrap();
    let ip_addr: net::Ipv4Addr = "100.115.92.5".parse().unwrap();
    let netmask: net::Ipv4Addr = "255.255.255.252".parse().unwrap();
    let mac_addr: MacAddress = "a2:06:b9:3d:68:4d".parse().unwrap();

    tap.set_ip_addr(ip_addr).unwrap();
    tap.set_netmask(netmask).unwrap();
    tap.set_mac_address(mac_addr).unwrap();
    tap.set_vnet_hdr_size(16).unwrap();
    tap.set_offload(0).unwrap();
}

#[test]
fn tap_enable() {
    call_test_with_sudo("tap_enable_impl")
}

#[test]
#[ignore = "Only to be called by tap_enable"]
fn tap_enable_impl() {
    let tap = Tap::new(true, false).unwrap();

    tap.enable().unwrap();
}
