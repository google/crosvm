extern crate msg_on_socket_derive;
extern crate msg_socket;
extern crate sys_util;

use sys_util::EventFd;

use msg_socket::*;

#[derive(MsgOnSocket)]
struct Request {
    field0: u8,
    field1: EventFd,
    field2: u32,
}

#[derive(MsgOnSocket)]
struct DummyResponse {}

#[test]
fn sock_send_recv_struct() {
    let (req, res) = pair::<Request, DummyResponse>().unwrap();
    let e0 = EventFd::new().unwrap();
    let e1 = e0.try_clone().unwrap();
    req.send(&Request {
        field0: 2,
        field1: e0,
        field2: 0xf0f0,
    })
    .unwrap();
    let r = res.recv().unwrap();
    assert_eq!(r.field0, 2);
    assert_eq!(r.field2, 0xf0f0);
    r.field1.write(0x0f0f).unwrap();
    assert_eq!(e1.read().unwrap(), 0x0f0f);
}
