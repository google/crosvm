// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::HashMap;
#[cfg(any(feature = "slirp-ring-capture", feature = "slirp-debug"))]
use std::fs::File;
use std::io;
#[cfg(any(feature = "slirp-ring-capture", feature = "slirp-debug"))]
use std::io::BufWriter;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::time::Duration;
use std::time::Instant;

use base::error;
use base::named_pipes::OverlappedWrapper;
use base::named_pipes::PipeConnection;
use base::warn;
use base::AsRawDescriptor;
use base::Descriptor;
use base::Error as SysError;
use base::Event;
use base::EventExt;
use base::EventToken;
use base::RawDescriptor;
use base::Timer;
use base::WaitContext;
use base::WaitContextExt;
use data_model::DataInit;
use metrics::MetricEventType;
use metrics::PeriodicLogger;
#[cfg(any(feature = "slirp-ring-capture", feature = "slirp-debug"))]
use pcap_file::pcap::PcapWriter;
use smallvec::SmallVec;
use virtio_sys::virtio_net::virtio_net_hdr;
use virtio_sys::virtio_net::virtio_net_hdr_mrg_rxbuf;
use winapi::shared::minwindef::MAKEWORD;
use winapi::um::winnt::LONG;
use winapi::um::winnt::SHORT;
use winapi::um::winsock2::WSACleanup;
use winapi::um::winsock2::WSAEventSelect;
use winapi::um::winsock2::WSAGetLastError;
use winapi::um::winsock2::WSAPoll;
use winapi::um::winsock2::WSAStartup;
use winapi::um::winsock2::FD_CLOSE;
use winapi::um::winsock2::FD_READ;
use winapi::um::winsock2::FD_WRITE;
use winapi::um::winsock2::POLLERR;
use winapi::um::winsock2::POLLHUP;
use winapi::um::winsock2::POLLRDBAND;
use winapi::um::winsock2::POLLRDNORM;
use winapi::um::winsock2::POLLWRNORM;
use winapi::um::winsock2::SOCKET;
use winapi::um::winsock2::SOCKET_ERROR;
use winapi::um::winsock2::WSADATA;
use winapi::um::winsock2::WSAPOLLFD;

use crate::slirp::context::CallbackHandler;
use crate::slirp::context::Context;
use crate::slirp::context::PollEvents;
#[cfg(feature = "slirp-ring-capture")]
use crate::slirp::packet_ring_buffer::PacketRingBuffer;
use crate::slirp::SlirpError;
use crate::slirp::ETHERNET_FRAME_SIZE;
use crate::Error;
use crate::Result;

#[cfg(any(feature = "slirp-ring-capture", feature = "slirp-debug"))]
const SLIRP_CAPTURE_FILE_NAME: &str = "slirp_capture.pcap";

#[cfg(any(feature = "slirp-ring-capture", feature = "slirp-debug"))]
const PCAP_FILE_BUFFER_SIZE: usize = 1024 * 1024; // 1MiB

const VETH_HEADER_LENGTH: usize = 12;

#[cfg(feature = "slirp-ring-capture")]
const PACKET_RING_BUFFER_SIZE_IN_BYTES: usize = 30000000; // 30MBs

struct Handler {
    start: Instant,
    pipe: PipeConnection,
    read_overlapped_wrapper: OverlappedWrapper,
    buf: [u8; ETHERNET_FRAME_SIZE],
    write_overlapped_wrapper: OverlappedWrapper,
    // Stores the actual timer (Event) and callback. Note that Event ownership is held by libslirp,
    // and created/released via `timer_new` and `timer_free`.
    timer_callbacks: HashMap<RawDescriptor, Box<dyn FnMut()>>,
    #[cfg(any(feature = "slirp-ring-capture", feature = "slirp-debug"))]
    pcap_writer: PcapWriter<BufWriter<File>>,
    #[cfg(feature = "slirp-ring-capture")]
    tx_packet_ring_buffer: PacketRingBuffer,
    #[cfg(feature = "slirp-ring-capture")]
    rx_packet_ring_buffer: PacketRingBuffer,
    tx_logger: PeriodicLogger,
    rx_logger: PeriodicLogger,
}

impl CallbackHandler for Handler {
    type Timer = base::Timer;

    fn clock_get_ns(&mut self) -> i64 {
        const NANOS_PER_SEC: u64 = 1_000_000_000;
        let running_duration = self.start.elapsed();
        (running_duration.as_secs() * NANOS_PER_SEC + running_duration.subsec_nanos() as u64) as i64
    }

    /// Sends a packet to the guest.
    fn send_packet(&mut self, buf: &[u8]) -> io::Result<usize> {
        let vnet_hdr = virtio_net_hdr_mrg_rxbuf {
            hdr: virtio_net_hdr {
                flags: 0,
                gso_size: 0,
                hdr_len: 0,
                csum_start: 0,
                csum_offset: 0,
                gso_type: virtio_sys::virtio_net::VIRTIO_NET_HDR_GSO_NONE as u8,
            },
            num_buffers: 1,
        };
        let send_buf = [vnet_hdr.as_slice(), buf].concat();

        #[cfg(any(feature = "slirp-ring-capture", feature = "slirp-debug"))]
        let d = self.start.elapsed();
        #[cfg(feature = "slirp-debug")]
        {
            self.pcap_writer
                .write(d.as_secs() as u32, d.subsec_nanos(), buf, buf.len() as u32)
                .unwrap();
        }
        #[cfg(feature = "slirp-ring-capture")]
        {
            self.tx_packet_ring_buffer
                .add_packet(buf, d)
                .expect("Failed to add packet.");
        }
        // Log as rx from the guest's perspective
        self.rx_logger.log(buf.len() as i64);
        self.pipe
            .write_overlapped(&send_buf, &mut self.write_overlapped_wrapper)?;
        self.pipe
            .get_overlapped_result(&mut self.write_overlapped_wrapper)
            .map(|x| x as usize)
    }

    // Not required per https://github.com/rootless-containers/slirp4netns/blob/7f6a4a654a84d4356c881a10417bab77fd5be325/slirp4netns.c
    fn register_poll_fd(&mut self, _fd: i32) {}
    fn unregister_poll_fd(&mut self, _fd: i32) {}

    fn guest_error(&mut self, msg: &str) {
        warn!("guest error: {}", msg);
    }

    // Not required per https://github.com/rootless-containers/slirp4netns/blob/7f6a4a654a84d4356c881a10417bab77fd5be325/slirp4netns.c
    fn notify(&mut self) {}

    fn timer_new(&mut self, callback: Box<dyn FnMut()>) -> Box<Self::Timer> {
        let timer = Timer::new().expect("failed to create network timer");
        self.timer_callbacks
            .insert(timer.as_raw_descriptor(), callback);
        Box::new(timer)
    }

    fn timer_mod(&mut self, timer: &mut Self::Timer, expire_time: i64) {
        // expire_time is a clock_get_ns relative deadline.
        let timer_duration = Duration::from_millis(expire_time as u64)
            - Duration::from_nanos(self.clock_get_ns() as u64);

        timer
            .reset(timer_duration, None)
            .expect("failed to modify network timer");
    }

    fn timer_free(&mut self, timer: Box<Self::Timer>) {
        self.timer_callbacks.remove(&timer.as_raw_descriptor());
        // The actual Timer is freed implicitly by the Box drop.
    }

    fn get_timers<'a>(&'a self) -> Box<dyn Iterator<Item = &RawDescriptor> + 'a> {
        Box::new(self.timer_callbacks.keys())
    }

    fn execute_timer(&mut self, timer: RawDescriptor) {
        let timer_callback = self
            .timer_callbacks
            .get_mut(&timer)
            .expect("tried to run timer that has no callback");
        timer_callback()
    }

    fn begin_read_from_guest(&mut self) -> io::Result<()> {
        // Safe because we are writing simple bytes.
        unsafe {
            self.pipe
                .read_overlapped(&mut self.buf, &mut self.read_overlapped_wrapper)
        }
    }

    fn end_read_from_guest(&mut self) -> io::Result<&[u8]> {
        #[cfg(any(feature = "slirp-ring-capture", feature = "slirp-debug"))]
        let d = self.start.elapsed();
        match self
            .pipe
            .try_get_overlapped_result(&mut self.read_overlapped_wrapper)
        {
            Ok(len) if len as usize >= VETH_HEADER_LENGTH => {
                // Skip over the veth header (12 bytes, created by the frontend per the
                // virtio spec).
                let ethernet_pkt = &self.buf[VETH_HEADER_LENGTH..len as usize];

                #[cfg(feature = "slirp-debug")]
                {
                    self.pcap_writer
                        .write(
                            d.as_secs() as u32,
                            d.subsec_nanos(),
                            ethernet_pkt,
                            (len - VETH_HEADER_LENGTH) as u32,
                        )
                        .unwrap();
                }
                #[cfg(feature = "slirp-ring-capture")]
                {
                    self.rx_packet_ring_buffer
                        .add_packet(ethernet_pkt, d)
                        .expect("Failed to add packet.");
                }
                // Log as tx from the guest's perspective
                self.tx_logger.log(len as i64);
                Ok(ethernet_pkt)
            }
            Ok(len) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Too few bytes ({}) read from the guest's virtio-net frontend.",
                    len
                ),
            )),
            Err(e) => Err(e),
        }
    }
}

#[cfg(feature = "slirp-ring-capture")]
impl Drop for Handler {
    fn drop(&mut self) {
        let packets = PacketRingBuffer::pop_ring_buffers_and_aggregate(
            &mut self.rx_packet_ring_buffer,
            &mut self.tx_packet_ring_buffer,
        );

        for packet in packets {
            self.pcap_writer
                .write(
                    packet.timestamp.as_secs() as u32,
                    packet.timestamp.subsec_nanos(),
                    &packet.buf,
                    packet.buf.len() as u32,
                )
                .unwrap()
        }
    }
}

fn last_wsa_error() -> io::Error {
    io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
}

fn poll_sockets(mut sockets: Vec<WSAPOLLFD>) -> io::Result<Vec<WSAPOLLFD>> {
    // Safe because sockets is guaranteed to be valid, and we handle error return codes below.
    let poll_result = unsafe {
        WSAPoll(
            sockets.as_mut_ptr() as *mut WSAPOLLFD,
            sockets.len() as u32,
            1, /* timeout in ms */
        )
    };

    match poll_result {
        SOCKET_ERROR => Err(last_wsa_error()),
        _ => Ok(sockets),
    }
}

/// Converts WSA poll events into the network event bitfield used by WSAEventSelect.
fn wsa_events_to_wsa_network_events(events: SHORT) -> LONG {
    let mut net_events = 0;
    if events & (POLLRDNORM | POLLRDBAND) != 0 {
        net_events |= FD_READ;
    }
    if events & POLLWRNORM > 0 {
        net_events |= FD_WRITE;
    }
    net_events
}

fn wsa_events_to_slirp_events(events: SHORT) -> PollEvents {
    // On Windows, revents have the following meaning:
    // Linux POLLIN == POLLRDBAND | POLLRDNORM
    // Linux POLLOUT == POLLWRNORM
    // Linux POLLERR == POLLERR
    // Windows: POLLPRI is not implemented.
    // POLLNVAL is not a supported Slirp polling flag.
    // Further details at
    //      https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsapoll
    let mut poll_events = PollEvents::empty();
    if events & (POLLRDNORM | POLLRDBAND) != 0 {
        poll_events |= PollEvents::poll_in();
    }
    if events & POLLWRNORM != 0 {
        poll_events |= PollEvents::poll_out();
    }
    if events & POLLERR != 0 {
        poll_events |= PollEvents::poll_err();
    }
    if events & POLLHUP != 0 {
        poll_events |= PollEvents::poll_hup();
    }
    poll_events
}

fn slirp_events_to_wsa_events(events: PollEvents) -> SHORT {
    // Note that the events that get sent into WSAPoll are a subset of the events that are returned
    // by WSAPoll. As such, this function is not an inverse of wsa_events_to_slirp_events.
    let mut wsa_events: SHORT = 0;
    if events.has_in() {
        wsa_events |= POLLRDNORM | POLLRDBAND;
    }
    if events.has_out() {
        wsa_events |= POLLWRNORM;
    }
    // NOTE: POLLHUP cannot be supplied to WSAPoll.

    wsa_events
}

#[derive(EventToken, Eq, PartialEq, Copy, Clone)]
enum Token {
    EventHandleReady(usize),
    SocketReady,
}

/// Associates a WSAPOLLFD's events with an Event object, disassociating on drop.
struct EventSelectedSocket<'a> {
    socket: WSAPOLLFD,
    event: &'a Event,
}

impl<'a> EventSelectedSocket<'a> {
    fn new(socket: WSAPOLLFD, event: &'a Event) -> Result<EventSelectedSocket> {
        // Safe because socket.fd exists, the event handle is guaranteed to exist, and we check the
        // return code below.
        let res = unsafe {
            WSAEventSelect(
                socket.fd as SOCKET,
                event.as_raw_descriptor(),
                // Because WSAPOLLFD cannot contain POLLHUP (even if libslirp wanted to specify it,
                // WSAPoll does not accept it), we assume it is always present.
                wsa_events_to_wsa_network_events(socket.events) | FD_CLOSE,
            )
        };
        if res == SOCKET_ERROR {
            return Err(Error::Slirp(SlirpError::SlirpIOPollError(last_wsa_error())));
        }
        Ok(EventSelectedSocket { socket, event })
    }
}

impl<'a> Drop for EventSelectedSocket<'a> {
    fn drop(&mut self) {
        // Safe because socket.fd exists, the event handle is guaranteed to exist, and we check the
        // return code below.
        let res = unsafe {
            WSAEventSelect(
                self.socket.fd as SOCKET,
                self.event.as_raw_descriptor(),
                /* listen for no events */ 0,
            )
        };
        if res == SOCKET_ERROR {
            warn!("failed to unselect socket: {}", last_wsa_error());
        }
    }
}

/// Rough equivalent of select(...) for Windows.
/// The following behavior is guaranteed:
///   1. The position of sockets in the sockets vector is maintained on return.
///   2. Sockets are always polled on any wakeup.
///
/// For optimization reasons, takes a utility event & WaitContext to avoid having to re-create
/// those objects if poll is called from an event loop. The Event and WaitContext MUST NOT be used
/// for any other purpose in between calls to `poll`.
fn poll<'a>(
    wait_ctx: &WaitContext<Token>,
    socket_event_handle: &Event,
    handles: Vec<&'a dyn AsRawDescriptor>,
    sockets: Vec<WSAPOLLFD>,
    timeout: Option<Duration>,
) -> Result<(Vec<&'a dyn AsRawDescriptor>, Vec<WSAPOLLFD>)> {
    let mut selected_sockets = Vec::with_capacity(sockets.len());
    for socket in sockets.iter() {
        selected_sockets.push(EventSelectedSocket::new(*socket, socket_event_handle)?);
    }

    wait_ctx
        .clear()
        .map_err(|e| Error::Slirp(SlirpError::SlirpPollError(e)))?;
    for (i, handle) in handles.iter().enumerate() {
        match wait_ctx.add(*handle, Token::EventHandleReady(i)) {
            Ok(v) => v,
            Err(e) => {
                return Err(Error::Slirp(SlirpError::SlirpPollError(e)));
            }
        }
    }
    match wait_ctx.add(socket_event_handle, Token::SocketReady) {
        Ok(v) => v,
        Err(e) => {
            return Err(Error::Slirp(SlirpError::SlirpPollError(e)));
        }
    }

    let events = if let Some(timeout) = timeout {
        wait_ctx
            .wait_timeout(timeout)
            .map_err(|e| Error::Slirp(SlirpError::SlirpPollError(e)))?
    } else {
        wait_ctx
            .wait()
            .map_err(|e| Error::Slirp(SlirpError::SlirpPollError(e)))?
    };

    let tokens: Vec<Token> = events
        .iter()
        .filter(|e| e.is_readable)
        .map(|e| e.token)
        .collect();
    let mut handle_results = Vec::new();
    for token in tokens {
        match token {
            Token::EventHandleReady(i) => {
                handle_results.push(handles[i]);
            }
            Token::SocketReady => {
                // We always call poll_sockets, so whether the token is present doesn't matter.
            }
        };
    }

    let socket_results = if sockets.is_empty() {
        Vec::new()
    } else {
        poll_sockets(sockets).map_err(|e| Error::Slirp(SlirpError::SlirpIOPollError(e)))?
    };

    Ok((handle_results, socket_results))
}

/// Opens a WSAStartup/WSACleanup context; in other words, while a context is held, winsock calls
/// can be made.
struct WSAContext {
    data: WSADATA,
}

impl WSAContext {
    fn new() -> Result<WSAContext> {
        // Trivially safe (initialization of this memory is not required).
        let mut ctx: WSAContext = unsafe { std::mem::zeroed() };

        // Safe because ctx.data is guaranteed to exist, and we check the return code.
        let err = unsafe { WSAStartup(MAKEWORD(2, 0), &mut ctx.data) };
        if err != 0 {
            Err(Error::Slirp(SlirpError::WSAStartupError(SysError::new(
                err,
            ))))
        } else {
            Ok(ctx)
        }
    }
}

impl Drop for WSAContext {
    fn drop(&mut self) {
        let err = unsafe { WSACleanup() };
        if err != 0 {
            error!("WSACleanup failed: {}", last_wsa_error())
        }
    }
}

/// Starts libslirp's main loop attached to host_pipe. Packets are exchanged between host_pipe and
/// the host's network stack.
///
/// host_pipe must be non blocking & in message mode.
pub fn start_slirp(
    host_pipe: PipeConnection,
    shutdown_event: Event,
    disable_access_to_host: bool,
    #[cfg(feature = "slirp-ring-capture")] slirp_capture_file: Option<String>,
) -> Result<()> {
    // This call is not strictly required because libslirp currently calls WSAStartup for us, but
    // relying on that is brittle and a potential source of bugs as we have our own socket code that
    // runs on the Rust side.
    let _wsa_context = WSAContext::new()?;

    let (mut context, host_pipe_notifier_handle) = create_slirp_context(
        host_pipe,
        disable_access_to_host,
        #[cfg(feature = "slirp-ring-capture")]
        slirp_capture_file,
    )?;
    let shutdown_event_handle = shutdown_event.as_raw_descriptor();

    // Stack data for the poll function.
    let wait_ctx: WaitContext<Token> =
        WaitContext::new().map_err(|e| Error::Slirp(SlirpError::SlirpPollError(e)))?;
    let socket_event_handle =
        Event::new_auto_reset().map_err(|e| Error::Slirp(SlirpError::SlirpPollError(e)))?;

    'slirp: loop {
        // Request the FDs that we should poll from Slirp. Slirp provides them to us by way of a
        // callback, which is invoked for each FD. This callback requires us to assign each FD an index
        // which will be used by a subsequent Slirp call to get the poll events for each FD. The data
        // flow can be thought of as follows:
        //    1. pollfds_fill creates a map of index -> fd inside Slirp based on the return values from
        //       the pollfds_fill callback.
        //    2. crosvm invokes poll on the FDs provided by Slirp.
        //    3. crosvm notifies Slirp via pollfds_poll that polling completed for the provided FDs.
        //    4. Slirp calls into crosvm via the pollfds_poll callback and asks for the statuses using
        //       the fd indicies registered in step #1.
        let mut poll_fds = Vec::new();
        // We'd like to sleep as long as possible (assuming no actionable notifications arrive).
        let mut timeout_ms: u32 = u32::MAX;
        context.pollfds_fill(&mut timeout_ms, |fd: i32, events: PollEvents| {
            poll_fds.push(WSAPOLLFD {
                fd: fd as usize,
                events: slirp_events_to_wsa_events(events),
                revents: 0,
            });
            (poll_fds.len() - 1) as i32
        });

        // There are relatively few concurrent timer_callbacks used by libslirp, so we set the small vector
        // size low.
        let timer_callbacks = context
            .get_timers()
            .map(|timer| Descriptor(*timer))
            .collect::<SmallVec<[Descriptor; 8]>>();
        let mut handles: Vec<&dyn AsRawDescriptor> = Vec::with_capacity(timer_callbacks.len() + 2);
        handles.extend(
            timer_callbacks
                .iter()
                .map(|timer| timer as &dyn AsRawDescriptor),
        );

        let host_pipe_notifier = Descriptor(host_pipe_notifier_handle);
        handles.push(&host_pipe_notifier);
        handles.push(&shutdown_event);

        let (handle_results, socket_results) = poll(
            &wait_ctx,
            &socket_event_handle,
            handles,
            poll_fds,
            Some(Duration::from_millis(timeout_ms.into())),
        )?;

        for handle in handle_results.iter() {
            match handle.as_raw_descriptor() {
                h if h == host_pipe_notifier_handle => {
                    // Collect input from the guest & inject into Slirp. It seems that this input
                    // step should be between pollfds_fill & pollfds_poll.
                    context.handle_guest_input()?;
                }
                h if h == shutdown_event_handle => {
                    break 'slirp;
                }
                timer_handle => {
                    // All other handles are timer_callbacks.
                    context.execute_timer(timer_handle);
                }
            }
        }

        // It's possible no socket notified and we got here from a timeout. This is fine, because
        // libslirp wants to be woken up if timeout has expired (even if no sockets are ready).
        context.pollfds_poll(false, |fd_index: i32| {
            wsa_events_to_slirp_events(socket_results[fd_index as usize].revents)
        })
    }

    // Never reached.
    Ok(())
}

/// Creates the slirp capture file.
///
/// Try to create a file in the user provided path. If no path is provided, or
/// if creation at that path fails, create in current directory (named
/// `SLIRP_CAPTURE_FILE_NAME`).
#[cfg(feature = "slirp-ring-capture")]
fn create_slirp_capture_file(slirp_capture_file: Option<String>) -> File {
    if let Some(slirp_capture_file) = slirp_capture_file {
        match File::create(&slirp_capture_file) {
            Ok(file) => file,
            Err(e) => {
                warn!(
                    "Unable to save slirp capture packets file to {}, \
                Saving file to current directory. Error: {}",
                    slirp_capture_file, e
                );
                File::create(SLIRP_CAPTURE_FILE_NAME).unwrap()
            }
        }
    } else {
        warn!(
            "run parameter --slirp-capture-file not specified. Saving file to current directory."
        );
        File::create(SLIRP_CAPTURE_FILE_NAME).unwrap()
    }
}

fn create_slirp_context(
    host_pipe: PipeConnection,
    disable_access_to_host: bool,
    #[cfg(feature = "slirp-ring-capture")] slirp_capture_file: Option<String>,
) -> Result<(Box<Context<Handler>>, RawDescriptor)> {
    #[cfg(feature = "slirp-ring-capture")]
    let slirp_captured_packets_file = create_slirp_capture_file(slirp_capture_file);
    #[cfg(all(not(feature = "slirp-ring-capture"), feature = "slirp-debug"))]
    let slirp_captured_packets_file = File::create(SLIRP_CAPTURE_FILE_NAME).unwrap();
    let overlapped_wrapper = OverlappedWrapper::new(true).unwrap();
    let read_notifier = overlapped_wrapper
        .get_h_event_ref()
        .unwrap()
        .as_raw_descriptor();
    let handler = Handler {
        start: Instant::now(),
        pipe: host_pipe,
        read_overlapped_wrapper: overlapped_wrapper,
        buf: [0; ETHERNET_FRAME_SIZE],
        write_overlapped_wrapper: OverlappedWrapper::new(true).unwrap(),
        timer_callbacks: HashMap::new(),
        #[cfg(any(feature = "slirp-ring-capture", feature = "slirp-debug"))]
        pcap_writer: PcapWriter::new(BufWriter::with_capacity(
            PCAP_FILE_BUFFER_SIZE,
            slirp_captured_packets_file,
        ))
        .unwrap(),
        #[cfg(feature = "slirp-ring-capture")]
        tx_packet_ring_buffer: PacketRingBuffer::new(PACKET_RING_BUFFER_SIZE_IN_BYTES),
        #[cfg(feature = "slirp-ring-capture")]
        rx_packet_ring_buffer: PacketRingBuffer::new(PACKET_RING_BUFFER_SIZE_IN_BYTES),
        tx_logger: PeriodicLogger::new(MetricEventType::NetworkTxRate, Duration::from_secs(1))
            .unwrap(),
        rx_logger: PeriodicLogger::new(MetricEventType::NetworkRxRate, Duration::from_secs(1))
            .unwrap(),
    };

    // Address & mask of the virtual network.
    let v4_network_addr = Ipv4Addr::new(10, 0, 2, 0);
    let v4_network_mask = Ipv4Addr::new(255, 255, 255, 0);

    // Address of the host machine on the virtual network (if the feature is enabled).
    let host_v4_addr = Ipv4Addr::new(10, 0, 2, 2);

    // Address of the libslirp provided DNS proxy (packets to this address are intercepted by
    // libslirp & routed to the first nameserver configured on the machine's NICs by libslirp).
    let dns_addr = Ipv4Addr::new(10, 0, 2, 3);

    // DHCP range should start *after* the statically assigned addresses.
    let dhcp_start_addr = Ipv4Addr::new(10, 0, 2, 4);

    // IPv6 network address. This is a ULA (unique local address) network, with a randomly generated
    // ID (0x13624603218). The "prefix" or network address is 64 bits, incorporating both the
    // network ID, and the subnet (0x0001).
    let v6_network_addr = Ipv6Addr::new(0xfd13, 0x6246, 0x3218, 0x0001, 0, 0, 0, 0);

    let v6_host_addr = Ipv6Addr::new(0xfd13, 0x6246, 0x3218, 0x0001, 0, 0, 0, 2);
    let v6_dns_addr = Ipv6Addr::new(0xfd13, 0x6246, 0x3218, 0x0001, 0, 0, 0, 3);
    Ok((
        Context::new(
            disable_access_to_host,
            /* IPv4 enabled */
            true,
            v4_network_addr,
            v4_network_mask,
            host_v4_addr,
            /* IPv6 enabled */ true,
            v6_network_addr,
            /* virtual_network_v6_prefix_len */ 64,
            /* host_v6_address */ v6_host_addr,
            /* host_hostname */ None,
            dhcp_start_addr,
            dns_addr,
            /* dns_server_v6_addr */ v6_dns_addr,
            /* virtual_network_dns_search_domains */ Vec::new(),
            /* dns_server_domain_name */ None,
            handler,
        )?,
        read_notifier,
    ))
}

#[cfg(test)]
mod tests {
    use std::net::UdpSocket;
    use std::os::windows::io::AsRawSocket;

    use base::named_pipes;
    use base::named_pipes::BlockingMode;
    use base::named_pipes::FramingMode;

    use super::super::SLIRP_BUFFER_SIZE;
    use super::*;

    fn create_socket() -> (UdpSocket, WSAPOLLFD) {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_nonblocking(true)
            .expect("Socket failed to set non_blocking.");

        let poll_fd = WSAPOLLFD {
            fd: socket.as_raw_socket() as usize,
            events: POLLRDNORM | POLLRDBAND, // POLLIN equivalent
            revents: 0,
        };

        (socket, poll_fd)
    }

    fn create_readable_socket() -> (UdpSocket, WSAPOLLFD) {
        let (socket, poll_fd) = create_socket();
        let receiving_addr = socket.local_addr().unwrap();
        let buf = [0; 10];
        socket.send_to(&buf, receiving_addr).unwrap();

        // Wait for the socket to really be readable before we return it back to the test. We've
        // seen cases in CI where send_to completes, but WSAPoll won't find the socket to be
        // readable.
        let mut sockets = vec![poll_fd];
        for _ in 0..5 {
            sockets = poll_sockets(sockets).expect("poll_sockets failed");
            if sockets[0].revents & (POLLRDNORM | POLLRDBAND) > 0 {
                return (socket, poll_fd);
            }
        }
        panic!("socket never became readable");
    }

    #[test]
    fn test_polling_timeout_works() {
        let wait_ctx: WaitContext<Token> = WaitContext::new().unwrap();
        let socket_event_handle = Event::new_auto_reset().unwrap();

        let (_socket, poll_fd) = create_socket();
        let event_fd = Event::new_auto_reset().unwrap();
        let (handles, sockets) = poll(
            &wait_ctx,
            &socket_event_handle,
            vec![&event_fd],
            vec![poll_fd],
            Some(Duration::from_millis(2)),
        )
        .unwrap();

        // Asserts that we woke up because of a timeout.
        assert_eq!(handles.len(), 0);
        assert_eq!(sockets[0].revents, 0);
    }

    #[test]
    fn test_polling_handle_only() {
        let wait_ctx: WaitContext<Token> = WaitContext::new().unwrap();
        let socket_event_handle = Event::new_auto_reset().unwrap();

        // Required to ensure winsock is ready (needed by poll).
        let (_sock, _poll_fd) = create_readable_socket();

        let event_fd = Event::new_auto_reset().unwrap();
        event_fd.signal().expect("Failed to write event");
        let (handles, _sockets) = poll(
            &wait_ctx,
            &socket_event_handle,
            vec![&event_fd],
            Vec::new(),
            None,
        )
        .unwrap();

        assert_eq!(handles.len(), 1);
        assert_eq!(handles[0].as_raw_descriptor(), event_fd.as_raw_descriptor());
    }

    #[test]
    fn test_polling_socket_only() {
        let wait_ctx: WaitContext<Token> = WaitContext::new().unwrap();
        let socket_event_handle = Event::new_auto_reset().unwrap();

        let (sock, poll_fd) = create_readable_socket();
        let (_handles, sockets) = poll(
            &wait_ctx,
            &socket_event_handle,
            Vec::new(),
            vec![poll_fd],
            None,
        )
        .unwrap();

        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].fd, sock.as_raw_socket() as usize);
    }

    #[test]
    fn test_polling_two_notifies() {
        let wait_ctx: WaitContext<Token> = WaitContext::new().unwrap();
        let socket_event_handle = Event::new_auto_reset().unwrap();

        let (sock, poll_fd) = create_readable_socket();
        let event_fd = Event::new_auto_reset().unwrap();
        event_fd.signal().expect("Failed to write event");

        let (handles, sockets) = poll(
            &wait_ctx,
            &socket_event_handle,
            vec![&event_fd],
            vec![poll_fd],
            None,
        )
        .unwrap();

        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].fd, sock.as_raw_socket() as usize);

        assert_eq!(handles.len(), 1);
        assert_eq!(handles[0].as_raw_descriptor(), event_fd.as_raw_descriptor());
    }

    #[test]
    fn test_slirp_stops_on_shutdown() {
        let event_fd = Event::new_auto_reset().unwrap();
        let (host_pipe, mut _guest_pipe) = named_pipes::pair_with_buffer_size(
            &FramingMode::Message,
            &BlockingMode::Wait,
            0,
            SLIRP_BUFFER_SIZE,
            true,
        )
        .unwrap();
        event_fd.signal().expect("Failed to write event");
        start_slirp(
            host_pipe,
            event_fd.try_clone().unwrap(),
            /* disable_access_to_host=*/ false,
            #[cfg(feature = "slirp-ring-capture")]
            None,
        )
        .expect("Failed to start slirp");
    }

    // A gratuitous ARP from 52:55:0A:00:02:0F for IP 10.0.2.15
    const VETH_ARP_ANNOUNCEMENT: [u8; 54] = [
        // VETH header
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // Ethernet frame
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x52, 0x55, 0x0a, 0x00, 0x02, 0x0f, 0x08, 0x06, 0x00,
        0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x52, 0x55, 0x0a, 0x00, 0x02, 0x0f, 0x0a, 0x00,
        0x02, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0a, 0x00, 0x02, 0x0f,
    ];

    // TCP SYN from 52:55:0A:00:02:0F to 52:55:0A:00:02:01 (latter MAC should be arbitrary with Slirp)
    // IP 10.0.2.15(5678) -> 127.0.0.1(19422)
    // Note: MAC addresses in Slirp are arbitrary
    const VETH_TCP_SYN: [u8; 66] = [
        // VETH header
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // Ethernet frame
        0x52, 0x55, 0x0a, 0x00, 0x02, 0x01, 0x52, 0x55, 0x0a, 0x00, 0x02, 0x0f, 0x08, 0x00, 0x45,
        0x00, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00, 0xff, 0x06, 0xde, 0x8b, 0x0a, 0x00, 0x02, 0x0f,
        0x7f, 0x00, 0x00, 0x01, 0x16, 0x2e, 0x4b, 0xde, 0x00, 0x00, 0x04, 0xd2, 0x00, 0x00, 0x0d,
        0x80, 0x50, 0x02, 0x0f, 0xa0, 0xa0, 0xd4, 0x00, 0x00,
    ];

    // This is built into the TCP_SYN packet above; changing it will require a change to the TCP
    // checksum
    const LOOPBACK_SOCKET: &str = "127.0.0.1:19422";

    const TIMEOUT_MILLIS: u64 = 400;

    #[test]
    fn test_send_tcp_syn() {
        use std::net::TcpListener;
        use std::thread;
        use std::time::Duration;

        let (mut guest_pipe, host_pipe) = named_pipes::pair_with_buffer_size(
            &FramingMode::Message,
            &BlockingMode::Wait,
            0,
            SLIRP_BUFFER_SIZE,
            true,
        )
        .unwrap();
        let mut overlapped_wrapper = OverlappedWrapper::new(true).unwrap();

        // Start Slirp in another thread
        let shutdown_sender = Event::new_auto_reset().unwrap();
        let shutdown_receiver = shutdown_sender.try_clone().unwrap();

        // Run the slirp handling in a background thread
        thread::spawn(move || {
            start_slirp(
                host_pipe,
                shutdown_receiver,
                /* disable_access_to_host=*/ false,
                #[cfg(feature = "slirp-ring-capture")]
                None,
            )
            .unwrap();
        });

        // Create a timeout thread so the test doesn't block forever if something is amiss
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(TIMEOUT_MILLIS));
            shutdown_sender
                .signal()
                .expect("Failed to write to shutdown sender");
        });

        // Start a local TCP server for our Slirp to connect to
        let _listener = TcpListener::bind(LOOPBACK_SOCKET).unwrap();

        // This ARP is required or else Slirp will send us an ARP request before it returns an ACK
        guest_pipe
            .write_overlapped(&VETH_ARP_ANNOUNCEMENT, &mut overlapped_wrapper)
            .expect("Failed to write ARP to guest pipe");
        guest_pipe
            .get_overlapped_result(&mut overlapped_wrapper)
            .unwrap();
        guest_pipe
            .write_overlapped(&VETH_TCP_SYN, &mut overlapped_wrapper)
            .expect("Failed to write SYN to guest pipe");
        guest_pipe
            .get_overlapped_result(&mut overlapped_wrapper)
            .unwrap();

        let mut recv_buffer: [u8; 512] = [0; 512];
        unsafe { guest_pipe.read_overlapped(&mut recv_buffer, &mut overlapped_wrapper) }.unwrap();
        let size = guest_pipe
            .get_overlapped_result(&mut overlapped_wrapper)
            .unwrap() as usize;

        // This output is printed to aid in debugging; it can be parsed with https://hpd.gasmi.net/
        println!("Received frame:");
        for byte in recv_buffer[0..size].iter() {
            print!("{:01$x} ", byte, 2);
        }
        println!();

        // This test expects a VETH header + SYN+ACK response. It doesn't inspect every byte of
        // the response frame because some fields may be dependent on the host or OS.
        assert_eq!(size, VETH_HEADER_LENGTH + 58);

        // Strip off the VETH header and ignore it
        recv_buffer.copy_within(VETH_HEADER_LENGTH.., 0);

        // Check Ethernet header
        const ETH_RESPONSE_HEADER: [u8; 14] = [
            0x52, 0x55, 0x0A, 0x00, 0x02, 0x0F, 0x52, 0x55, 0x0A, 0x00, 0x02, 0x02, 0x08, 0x00,
        ];
        assert_eq!(
            recv_buffer[0..ETH_RESPONSE_HEADER.len()],
            ETH_RESPONSE_HEADER
        );

        // Check source IP
        assert_eq!(recv_buffer[26..=29], [0x7f, 0x00, 0x00, 0x01]); // 127.0.0.1

        // Check dest IP
        assert_eq!(recv_buffer[30..=33], [0x0A, 0x00, 0x02, 0x0F]); // 10.0.2.15

        // Check source port
        assert_eq!(recv_buffer[34..=35], [0x4b, 0xde]); // 19422

        // Check destination port
        assert_eq!(recv_buffer[36..=37], [0x16, 0x2e]); // 5678

        // Check TCP flags are SYN+ACK
        assert_eq!(recv_buffer[47], 0x12);
    }
}
