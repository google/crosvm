use etherparse::{PacketBuilder, TcpOptionElement};
use libslirp;
use std::io;
use std::os::unix::io::RawFd;
use std::time::Instant;
use structopt::StructOpt;

impl libslirp::Handler for App {
    type Timer = usize;

    fn clock_get_ns(&mut self) -> i64 {
        const NANOS_PER_SEC: u64 = 1_000_000_000;
        let d = self.start.elapsed();
        (d.as_secs() * NANOS_PER_SEC + d.subsec_nanos() as u64) as i64
    }

    fn timer_new(&mut self, _func: Box<dyn FnMut()>) -> Box<Self::Timer> {
        Box::new(0)
    }

    fn timer_mod(&mut self, _timer: &mut Box<Self::Timer>, _expire_time: i64) {}

    fn timer_free(&mut self, timer: Box<Self::Timer>) {
        drop(timer);
    }

    fn send_packet(&mut self, buf: &[u8]) -> io::Result<usize> {
        //self.stream.send(buf).unwrap() as isize
        Ok(buf.len())
    }

    fn guest_error(&mut self, msg: &str) {
        eprintln!("guest error: {}", msg);
    }

    fn register_poll_fd(&mut self, fd: RawFd) {
        println!("register_poll_fd: fd={:?}", fd);
    }

    fn unregister_poll_fd(&mut self, fd: RawFd) {
        println!("unregister_poll_fd: fd={:?}", fd);
    }

    fn notify(&mut self) {
        println!("notify");
    }
}

struct App {
    start: Instant,
}

#[test]
fn ip() {
    let opt = libslirp::Opt::from_args();
    let app = App {
        start: Instant::now(),
    };
    let ctxt = libslirp::Context::new_with_opt(&opt, app);

    {
        let builder = PacketBuilder::ethernet2(
            [1, 2, 3, 4, 5, 6],    //source mac
            [7, 8, 9, 10, 11, 12], //destination mac
        )
        .ipv4(
            [192, 168, 1, 1], //source ip
            [192, 168, 1, 2], //desitination ip
            20,               //time to life
        )
        .udp(
            21,   //source port
            1234, //desitnation port
        );

        //payload of the udp packet
        let payload = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut buffer = Vec::<u8>::with_capacity(builder.size(payload.len()));
        builder.write(&mut buffer, &payload).unwrap();

        ctxt.input(&buffer);
    }

    {
        let builder = PacketBuilder::ethernet2(
            [1, 2, 3, 4, 5, 6],    //source mac
            [7, 8, 9, 10, 11, 12], //destionation mac
        )
        .ipv4(
            [192, 168, 1, 1], //source ip
            [192, 168, 1, 2], //desitionation ip
            20,               //time to life
        )
        .tcp(
            21,    //source port
            1234,  //desitnation port
            1,     //sequence number
            26180, //window size
        )
        //set additional tcp header fields
        .ns() //set the ns flag
        //supported flags: ns(), fin(), syn(), rst(), psh(), ece(), cwr()
        .ack(123) //ack flag + the ack number
        .urg(23) //urg flag + urgent pointer
        //tcp header options
        .options(&[
            TcpOptionElement::Nop,
            TcpOptionElement::MaximumSegmentSize(1234),
        ])
        .unwrap();

        //payload of the tcp packet
        let payload = [1, 2, 3, 4, 5, 6, 7, 8];
        //get some memory to store the result
        let mut buffer = Vec::<u8>::with_capacity(builder.size(payload.len()));
        builder.write(&mut buffer, &payload).unwrap();
        ctxt.input(&buffer);
    }
}
