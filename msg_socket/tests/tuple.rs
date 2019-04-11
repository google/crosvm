use msg_socket::*;
use sys_util::EventFd;

#[derive(MsgOnSocket)]
struct Message(u8, u16, EventFd);

#[test]
fn sock_send_recv_tuple() {
    let (req, res) = pair::<Message, Message>().unwrap();
    let e0 = EventFd::new().unwrap();
    let e1 = e0.try_clone().unwrap();
    req.send(&Message(1, 0x12, e0)).unwrap();
    let r = res.recv().unwrap();
    assert_eq!(r.0, 1);
    assert_eq!(r.1, 0x12);
    r.2.write(0x0f0f).unwrap();
    assert_eq!(e1.read().unwrap(), 0x0f0f);
}
