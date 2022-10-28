// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(unix)]

use std::net;

use net_util::sys::unix::Tap;
use net_util::MacAddress;
use net_util::TapTCommon;

#[test]
#[ignore = "Requires root privileges"]
fn tap_create() {
    Tap::new(true, false).unwrap();
}

#[test]
#[ignore = "Requires root privileges"]
fn tap_configure() {
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
#[ignore = "Requires root privileges"]
fn tap_enable() {
    let tap = Tap::new(true, false).unwrap();

    tap.enable().unwrap();
}
