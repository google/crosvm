// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp;
use std::fmt::{self, Display};
use std::mem;
use std::net::Ipv4Addr;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

use libc::EAGAIN;
use net_sys;
use net_util::{Error as TapError, MacAddress, TapT};
use sys_util::Error as SysError;
use sys_util::{error, warn, EventFd, GuestMemory, PollContext, PollToken};
use virtio_sys::virtio_net::virtio_net_hdr_v1;
use virtio_sys::{vhost, virtio_net};

use super::{Queue, VirtioDevice, INTERRUPT_STATUS_USED_RING, TYPE_NET};

/// The maximum buffer size when segmentation offload is enabled. This
/// includes the 12-byte virtio net header.
/// http://docs.oasis-open.org/virtio/virtio/v1.0/virtio-v1.0.html#x1-1740003
const MAX_BUFFER_SIZE: usize = 65562;
const QUEUE_SIZE: u16 = 256;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE, QUEUE_SIZE];

#[derive(Debug)]
pub enum NetError {
    /// Creating kill eventfd failed.
    CreateKillEventFd(SysError),
    /// Creating PollContext failed.
    CreatePollContext(SysError),
    /// Cloning kill eventfd failed.
    CloneKillEventFd(SysError),
    /// Open tap device failed.
    TapOpen(TapError),
    /// Setting tap IP failed.
    TapSetIp(TapError),
    /// Setting tap netmask failed.
    TapSetNetmask(TapError),
    /// Setting tap mac address failed.
    TapSetMacAddress(TapError),
    /// Setting tap interface offload flags failed.
    TapSetOffload(TapError),
    /// Setting vnet header size failed.
    TapSetVnetHdrSize(TapError),
    /// Enabling tap interface failed.
    TapEnable(TapError),
    /// Validating tap interface failed.
    TapValidate(String),
    /// Error while polling for events.
    PollError(SysError),
}

impl Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::NetError::*;

        match self {
            CreateKillEventFd(e) => write!(f, "failed to create kill eventfd: {}", e),
            CreatePollContext(e) => write!(f, "failed to create poll context: {}", e),
            CloneKillEventFd(e) => write!(f, "failed to clone kill eventfd: {}", e),
            TapOpen(e) => write!(f, "failed to open tap device: {}", e),
            TapSetIp(e) => write!(f, "failed to set tap IP: {}", e),
            TapSetNetmask(e) => write!(f, "failed to set tap netmask: {}", e),
            TapSetMacAddress(e) => write!(f, "failed to set tap mac address: {}", e),
            TapSetOffload(e) => write!(f, "failed to set tap interface offload flags: {}", e),
            TapSetVnetHdrSize(e) => write!(f, "failed to set vnet header size: {}", e),
            TapEnable(e) => write!(f, "failed to enable tap interface: {}", e),
            TapValidate(s) => write!(f, "failed to validate tap interface: {}", s),
            PollError(e) => write!(f, "error while polling for events: {}", e),
        }
    }
}

struct Worker<T: TapT> {
    mem: GuestMemory,
    rx_queue: Queue,
    tx_queue: Queue,
    tap: T,
    interrupt_status: Arc<AtomicUsize>,
    interrupt_evt: EventFd,
    interrupt_resample_evt: EventFd,
    rx_buf: [u8; MAX_BUFFER_SIZE],
    rx_count: usize,
    deferred_rx: bool,
    // TODO(smbarber): http://crbug.com/753630
    // Remove once MRG_RXBUF is supported and this variable is actually used.
    #[allow(dead_code)]
    acked_features: u64,
}

impl<T> Worker<T>
where
    T: TapT,
{
    fn signal_used_queue(&self) {
        self.interrupt_status
            .fetch_or(INTERRUPT_STATUS_USED_RING as usize, Ordering::SeqCst);
        self.interrupt_evt.write(1).unwrap();
    }

    // Copies a single frame from `self.rx_buf` into the guest. Returns true
    // if a buffer was used, and false if the frame must be deferred until a buffer
    // is made available by the driver.
    fn rx_single_frame(&mut self) -> bool {
        let mut next_desc = self.rx_queue.pop(&self.mem);

        if next_desc.is_none() {
            return false;
        }

        // We just checked that the head descriptor exists.
        let head_index = next_desc.as_ref().unwrap().index;
        let mut write_count = 0;

        // Copy from frame into buffer, which may span multiple descriptors.
        loop {
            match next_desc {
                Some(desc) => {
                    if !desc.is_write_only() {
                        break;
                    }
                    let limit = cmp::min(write_count + desc.len as usize, self.rx_count);
                    let source_slice = &self.rx_buf[write_count..limit];
                    let write_result = self.mem.write_at_addr(source_slice, desc.addr);

                    match write_result {
                        Ok(sz) => {
                            write_count += sz;
                        }
                        Err(e) => {
                            warn!("net: rx: failed to write slice: {}", e);
                            break;
                        }
                    };

                    if write_count >= self.rx_count {
                        break;
                    }
                    next_desc = desc.next_descriptor();
                }
                None => {
                    warn!(
                        "net: rx: buffer is too small to hold frame of size {}",
                        self.rx_count
                    );
                    break;
                }
            }
        }

        self.rx_queue
            .add_used(&self.mem, head_index, write_count as u32);

        // Interrupt the guest immediately for received frames to
        // reduce latency.
        self.signal_used_queue();

        true
    }

    fn process_rx(&mut self) {
        // Read as many frames as possible.
        loop {
            let res = self.tap.read(&mut self.rx_buf);
            match res {
                Ok(count) => {
                    self.rx_count = count;
                    if !self.rx_single_frame() {
                        self.deferred_rx = true;
                        break;
                    }
                }
                Err(e) => {
                    // The tap device is nonblocking, so any error aside from EAGAIN is
                    // unexpected.
                    if e.raw_os_error().unwrap() != EAGAIN {
                        warn!("net: rx: failed to read tap: {}", e);
                    }
                    break;
                }
            }
        }
    }

    fn process_tx(&mut self) {
        let mut frame = [0u8; MAX_BUFFER_SIZE];

        while let Some(avail_desc) = self.tx_queue.pop(&self.mem) {
            let head_index = avail_desc.index;
            let mut next_desc = Some(avail_desc);
            let mut read_count = 0;

            // Copy buffer from across multiple descriptors.
            while let Some(desc) = next_desc {
                if desc.is_write_only() {
                    break;
                }
                let limit = cmp::min(read_count + desc.len as usize, frame.len());
                let read_result = self
                    .mem
                    .read_at_addr(&mut frame[read_count..limit as usize], desc.addr);
                match read_result {
                    Ok(sz) => {
                        read_count += sz;
                    }
                    Err(e) => {
                        warn!("net: tx: failed to read slice: {}", e);
                        break;
                    }
                }
                next_desc = desc.next_descriptor();
            }

            let write_result = self.tap.write(&frame[..read_count as usize]);
            match write_result {
                Ok(_) => {}
                Err(e) => {
                    warn!("net: tx: error failed to write to tap: {}", e);
                }
            };

            self.tx_queue.add_used(&self.mem, head_index, 0);
        }

        self.signal_used_queue();
    }

    fn run(
        &mut self,
        rx_queue_evt: EventFd,
        tx_queue_evt: EventFd,
        kill_evt: EventFd,
    ) -> Result<(), NetError> {
        #[derive(PollToken)]
        enum Token {
            // A frame is available for reading from the tap device to receive in the guest.
            RxTap,
            // The guest has made a buffer available to receive a frame into.
            RxQueue,
            // The transmit queue has a frame that is ready to send from the guest.
            TxQueue,
            // Check if any interrupts need to be re-asserted.
            InterruptResample,
            // crosvm has requested the device to shut down.
            Kill,
        }

        let poll_ctx: PollContext<Token> = PollContext::new()
            .and_then(|pc| pc.add(&self.tap, Token::RxTap).and(Ok(pc)))
            .and_then(|pc| pc.add(&rx_queue_evt, Token::RxQueue).and(Ok(pc)))
            .and_then(|pc| pc.add(&tx_queue_evt, Token::TxQueue).and(Ok(pc)))
            .and_then(|pc| {
                pc.add(&self.interrupt_resample_evt, Token::InterruptResample)
                    .and(Ok(pc))
            })
            .and_then(|pc| pc.add(&kill_evt, Token::Kill).and(Ok(pc)))
            .map_err(NetError::CreatePollContext)?;

        'poll: loop {
            let events = poll_ctx.wait().map_err(NetError::PollError)?;
            for event in events.iter_readable() {
                match event.token() {
                    Token::RxTap => {
                        // Process a deferred frame first if available. Don't read from tap again
                        // until we manage to receive this deferred frame.
                        if self.deferred_rx {
                            if self.rx_single_frame() {
                                self.deferred_rx = false;
                            } else {
                                continue;
                            }
                        }
                        self.process_rx();
                    }
                    Token::RxQueue => {
                        if let Err(e) = rx_queue_evt.read() {
                            error!("net: error reading rx queue EventFd: {}", e);
                            break 'poll;
                        }
                        // There should be a buffer available now to receive the frame into.
                        if self.deferred_rx && self.rx_single_frame() {
                            self.deferred_rx = false;
                        }
                    }
                    Token::TxQueue => {
                        if let Err(e) = tx_queue_evt.read() {
                            error!("net: error reading tx queue EventFd: {}", e);
                            break 'poll;
                        }
                        self.process_tx();
                    }
                    Token::InterruptResample => {
                        let _ = self.interrupt_resample_evt.read();
                        if self.interrupt_status.load(Ordering::SeqCst) != 0 {
                            self.interrupt_evt.write(1).unwrap();
                        }
                    }
                    Token::Kill => break 'poll,
                }
            }
        }
        Ok(())
    }
}

pub struct Net<T: TapT> {
    workers_kill_evt: Option<EventFd>,
    kill_evt: EventFd,
    tap: Option<T>,
    avail_features: u64,
    acked_features: u64,
}

impl<T> Net<T>
where
    T: TapT,
{
    /// Create a new virtio network device with the given IP address and
    /// netmask.
    pub fn new(
        ip_addr: Ipv4Addr,
        netmask: Ipv4Addr,
        mac_addr: MacAddress,
    ) -> Result<Net<T>, NetError> {
        let tap: T = T::new(true).map_err(NetError::TapOpen)?;
        tap.set_ip_addr(ip_addr).map_err(NetError::TapSetIp)?;
        tap.set_netmask(netmask).map_err(NetError::TapSetNetmask)?;
        tap.set_mac_address(mac_addr)
            .map_err(NetError::TapSetMacAddress)?;

        tap.enable().map_err(NetError::TapEnable)?;

        Net::from(tap)
    }

    /// Creates a new virtio network device from a tap device that has already been
    /// configured.
    pub fn from(tap: T) -> Result<Net<T>, NetError> {
        // This would also validate a tap created by Self::new(), but that's a good thing as it
        // would ensure that any changes in the creation procedure are matched in the validation.
        // Plus we still need to set the offload and vnet_hdr_size values.
        validate_and_configure_tap(&tap)?;

        let avail_features = 1 << virtio_net::VIRTIO_NET_F_GUEST_CSUM
            | 1 << virtio_net::VIRTIO_NET_F_CSUM
            | 1 << virtio_net::VIRTIO_NET_F_GUEST_TSO4
            | 1 << virtio_net::VIRTIO_NET_F_GUEST_UFO
            | 1 << virtio_net::VIRTIO_NET_F_HOST_TSO4
            | 1 << virtio_net::VIRTIO_NET_F_HOST_UFO
            | 1 << vhost::VIRTIO_F_VERSION_1;

        let kill_evt = EventFd::new().map_err(NetError::CreateKillEventFd)?;
        Ok(Net {
            workers_kill_evt: Some(kill_evt.try_clone().map_err(NetError::CloneKillEventFd)?),
            kill_evt,
            tap: Some(tap),
            avail_features,
            acked_features: 0u64,
        })
    }
}

// Ensure that the tap interface has the correct flags and sets the offload and VNET header size
// to the appropriate values.
fn validate_and_configure_tap<T: TapT>(tap: &T) -> Result<(), NetError> {
    let flags = tap.if_flags();
    let required_flags = [
        (net_sys::IFF_TAP, "IFF_TAP"),
        (net_sys::IFF_NO_PI, "IFF_NO_PI"),
        (net_sys::IFF_VNET_HDR, "IFF_VNET_HDR"),
    ];
    let missing_flags = required_flags
        .iter()
        .filter_map(
            |(value, name)| {
                if value & flags == 0 {
                    Some(name)
                } else {
                    None
                }
            },
        )
        .collect::<Vec<_>>();

    if !missing_flags.is_empty() {
        return Err(NetError::TapValidate(format!(
            "Missing flags: {:?}",
            missing_flags
        )));
    }

    // Set offload flags to match the virtio features below.
    tap.set_offload(
        net_sys::TUN_F_CSUM | net_sys::TUN_F_UFO | net_sys::TUN_F_TSO4 | net_sys::TUN_F_TSO6,
    )
    .map_err(NetError::TapSetOffload)?;

    let vnet_hdr_size = mem::size_of::<virtio_net_hdr_v1>() as i32;
    tap.set_vnet_hdr_size(vnet_hdr_size)
        .map_err(NetError::TapSetVnetHdrSize)?;

    Ok(())
}

impl<T> Drop for Net<T>
where
    T: TapT,
{
    fn drop(&mut self) {
        // Only kill the child if it claimed its eventfd.
        if self.workers_kill_evt.is_none() {
            // Ignore the result because there is nothing we can do about it.
            let _ = self.kill_evt.write(1);
        }
    }
}

impl<T> VirtioDevice for Net<T>
where
    T: 'static + TapT,
{
    fn keep_fds(&self) -> Vec<RawFd> {
        let mut keep_fds = Vec::new();

        if let Some(tap) = &self.tap {
            keep_fds.push(tap.as_raw_fd());
        }

        if let Some(workers_kill_evt) = &self.workers_kill_evt {
            keep_fds.push(workers_kill_evt.as_raw_fd());
        }

        keep_fds
    }

    fn device_type(&self) -> u32 {
        TYPE_NET
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn features(&self) -> u64 {
        self.avail_features
    }

    fn ack_features(&mut self, value: u64) {
        let mut v = value;

        // Check if the guest is ACK'ing a feature that we didn't claim to have.
        let unrequested_features = v & !self.avail_features;
        if unrequested_features != 0 {
            warn!("net: virtio net got unknown feature ack: {:x}", v);

            // Don't count these features as acked.
            v &= !unrequested_features;
        }
        self.acked_features |= v;
    }

    fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt_evt: EventFd,
        interrupt_resample_evt: EventFd,
        status: Arc<AtomicUsize>,
        mut queues: Vec<Queue>,
        mut queue_evts: Vec<EventFd>,
    ) {
        if queues.len() != 2 || queue_evts.len() != 2 {
            error!("net: expected 2 queues, got {}", queues.len());
            return;
        }

        if let Some(tap) = self.tap.take() {
            if let Some(kill_evt) = self.workers_kill_evt.take() {
                let acked_features = self.acked_features;
                let worker_result =
                    thread::Builder::new()
                        .name("virtio_net".to_string())
                        .spawn(move || {
                            // First queue is rx, second is tx.
                            let rx_queue = queues.remove(0);
                            let tx_queue = queues.remove(0);
                            let mut worker = Worker {
                                mem,
                                rx_queue,
                                tx_queue,
                                tap,
                                interrupt_status: status,
                                interrupt_evt,
                                interrupt_resample_evt,
                                rx_buf: [0u8; MAX_BUFFER_SIZE],
                                rx_count: 0,
                                deferred_rx: false,
                                acked_features,
                            };
                            let rx_queue_evt = queue_evts.remove(0);
                            let tx_queue_evt = queue_evts.remove(0);
                            let result = worker.run(rx_queue_evt, tx_queue_evt, kill_evt);
                            if let Err(e) = result {
                                error!("net worker thread exited with error: {}", e);
                            }
                        });

                if let Err(e) = worker_result {
                    error!("failed to spawn virtio_net worker: {}", e);
                    return;
                }
            }
        }
    }
}
