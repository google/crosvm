// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// TODO(225193541): Enable/add tests for windows.
#![cfg(unix)]

use std::path::PathBuf;
use std::result;

use base::Event;
use net_util::sys::unix::fakes::FakeTap;
use vhost::net::fakes::FakeNet;
use vhost::net::NetT;
use vhost::Error;
use vhost::Result;
use vhost::Vhost;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
use vm_memory::GuestMemoryError;

fn create_guest_memory() -> result::Result<GuestMemory, GuestMemoryError> {
    let start_addr1 = GuestAddress(0x0);
    let start_addr2 = GuestAddress(0x1000);
    GuestMemory::new(&[(start_addr1, 0x1000), (start_addr2, 0x4000)])
}

fn assert_ok_or_known_failure<T>(res: Result<T>) {
    match &res {
        // FakeNet won't respond to ioctl's
        Ok(_t) => {}
        Err(Error::IoctlError(ioe)) if ioe.raw_os_error().unwrap() == 25 => {}
        Err(e) => panic!("Unexpected Error:\n{}", e),
    }
}

fn create_fake_vhost_net() -> FakeNet<FakeTap> {
    FakeNet::<FakeTap>::new(&PathBuf::from("")).unwrap()
}

#[test]
fn test_create_fake_vhost_net() {
    create_fake_vhost_net();
}

#[test]
fn set_owner() {
    let vhost_net = create_fake_vhost_net();
    let res = vhost_net.set_owner();
    assert_ok_or_known_failure(res);
}

#[test]
fn get_features() {
    let vhost_net = create_fake_vhost_net();
    let res = vhost_net.get_features();
    assert_ok_or_known_failure(res);
}

#[test]
fn set_features() {
    let vhost_net = create_fake_vhost_net();
    let res = vhost_net.set_features(0);
    assert_ok_or_known_failure(res);
}

#[test]
fn set_mem_table() {
    let vhost_net = create_fake_vhost_net();
    let gm = create_guest_memory().unwrap();
    let res = vhost_net.set_mem_table(&gm);
    assert_ok_or_known_failure(res);
}

#[test]
fn set_vring_num() {
    let vhost_net = create_fake_vhost_net();
    let res = vhost_net.set_vring_num(0, 1);
    assert_ok_or_known_failure(res);
}

#[test]
fn set_vring_addr() {
    let vhost_net = create_fake_vhost_net();
    let gm = create_guest_memory().unwrap();
    let res = vhost_net.set_vring_addr(
        &gm,
        1,
        1,
        0,
        0x0,
        GuestAddress(0x0),
        GuestAddress(0x0),
        GuestAddress(0x0),
        None,
    );
    assert_ok_or_known_failure(res);
}

#[test]
fn set_vring_base() {
    let vhost_net = create_fake_vhost_net();
    let res = vhost_net.set_vring_base(0, 1);
    assert_ok_or_known_failure(res);
}

#[test]
fn set_vring_call() {
    let vhost_net = create_fake_vhost_net();
    let res = vhost_net.set_vring_call(0, &Event::new().unwrap());
    assert_ok_or_known_failure(res);
}

#[test]
fn set_vring_kick() {
    let vhost_net = create_fake_vhost_net();
    let res = vhost_net.set_vring_kick(0, &Event::new().unwrap());
    assert_ok_or_known_failure(res);
}
