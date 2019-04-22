// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use sys_util::EventFd;

use msg_socket::*;

#[derive(MsgOnSocket)]
struct DummyRequest {}

#[derive(MsgOnSocket)]
enum Response {
    A(u8),
    B,
    C(u32, EventFd),
    D([u8; 4]),
    E { f0: u8, f1: u32 },
}

#[test]
fn sock_send_recv_enum() {
    let (req, res) = pair::<DummyRequest, Response>().unwrap();
    let e0 = EventFd::new().unwrap();
    let e1 = e0.try_clone().unwrap();
    res.send(&Response::C(0xf0f0, e0)).unwrap();
    let r = req.recv().unwrap();
    match r {
        Response::C(v, efd) => {
            assert_eq!(v, 0xf0f0);
            efd.write(0x0f0f).unwrap();
        }
        _ => panic!("wrong type"),
    };
    assert_eq!(e1.read().unwrap(), 0x0f0f);

    res.send(&Response::B).unwrap();
    match req.recv().unwrap() {
        Response::B => {}
        _ => panic!("Wrong enum type"),
    };

    res.send(&Response::A(0x3)).unwrap();
    match req.recv().unwrap() {
        Response::A(v) => assert_eq!(v, 0x3),
        _ => panic!("Wrong enum type"),
    };

    res.send(&Response::D([0, 1, 2, 3])).unwrap();
    match req.recv().unwrap() {
        Response::D(v) => assert_eq!(v, [0, 1, 2, 3]),
        _ => panic!("Wrong enum type"),
    };

    res.send(&Response::E {
        f0: 0x12,
        f1: 0x0f0f,
    })
    .unwrap();
    match req.recv().unwrap() {
        Response::E { f0, f1 } => {
            assert_eq!(f0, 0x12);
            assert_eq!(f1, 0x0f0f);
        }
        _ => panic!("Wrong enum type"),
    };
}
