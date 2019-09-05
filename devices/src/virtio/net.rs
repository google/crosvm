// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fmt::{self, Display};
use std::io::{self, Read, Write};
use std::mem;
use std::net::Ipv4Addr;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use sync::Mutex;

use crate::pci::MsixConfig;
use libc::{EAGAIN, EEXIST};
use net_sys;
use net_util::{Error as TapError, MacAddress, TapT};
use sys_util::Error as SysError;
use sys_util::{error, warn, EventFd, GuestMemory, PollContext, PollToken};
use virtio_sys::virtio_net::virtio_net_hdr_v1;
use virtio_sys::{vhost, virtio_net};

use super::{Queue, Reader, VirtioDevice, Writer, INTERRUPT_STATUS_USED_RING, TYPE_NET};

/// The maximum buffer size when segmentation offload is enabled. This
/// includes the 12-byte virtio net header.
/// http://docs.oasis-open.org/virtio/virtio/v1.0/virtio-v1.0.html#x1-1740003
const MAX_BUFFER_SIZE: usize = 65562;
const QUEUE_SIZE: u16 = 256;
const NUM_QUEUES: usize = 2;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE, QUEUE_SIZE];
const NUM_MSIX_VECTORS: u16 = NUM_QUEUES as u16;

#[derive(Debug)]
pub enum NetError {
    /// Creating kill eventfd failed.
    CreateKillEventFd(SysError),
    /// Creating PollContext failed.
    CreatePollContext(SysError),
    /// Cloning kill eventfd failed.
    CloneKillEventFd(SysError),
    /// Adding the tap fd back to the poll context failed.
    PollAddTap(SysError),
    /// Removing the tap fd from the poll context failed.
    PollDeleteTap(SysError),
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
            PollAddTap(e) => write!(f, "failed to add tap fd to poll context: {}", e),
            PollDeleteTap(e) => write!(f, "failed to remove tap fd from poll context: {}", e),
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
    msix_config: Option<Arc<Mutex<MsixConfig>>>,
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
    fn signal_used_queue(&self, vector: u16) {
        if let Some(msix_config) = &self.msix_config {
            let mut msix_config = msix_config.lock();
            if msix_config.enabled() {
                msix_config.trigger(vector);
                return;
            }
        }
        self.interrupt_status
            .fetch_or(INTERRUPT_STATUS_USED_RING as usize, Ordering::SeqCst);
        self.interrupt_evt.write(1).unwrap();
    }

    // Copies a single frame from `self.rx_buf` into the guest. Returns true
    // if a buffer was used, and false if the frame must be deferred until a buffer
    // is made available by the driver.
    fn rx_single_frame(&mut self) -> bool {
        let desc_chain = match self.rx_queue.pop(&self.mem) {
            Some(desc) => desc,
            None => return false,
        };

        let index = desc_chain.index;
        let bytes_written = match Writer::new(&self.mem, desc_chain) {
            Ok(mut writer) => {
                match writer.write_all(&self.rx_buf[0..self.rx_count]) {
                    Ok(()) => (),
                    Err(ref e) if e.kind() == io::ErrorKind::WriteZero => {
                        warn!(
                            "net: rx: buffer is too small to hold frame of size {}",
                            self.rx_count
                        );
                    }
                    Err(e) => {
                        warn!("net: rx: failed to write slice: {}", e);
                    }
                };

                writer.bytes_written() as u32
            }
            Err(e) => {
                error!("net: failed to create Writer: {}", e);
                0
            }
        };

        self.rx_queue.add_used(&self.mem, index, bytes_written);

        true
    }

    fn process_rx(&mut self) -> bool {
        let mut needs_interrupt = false;
        let mut first_frame = true;

        // Read as many frames as possible.
        loop {
            let res = self.tap.read(&mut self.rx_buf);
            match res {
                Ok(count) => {
                    self.rx_count = count;
                    if !self.rx_single_frame() {
                        self.deferred_rx = true;
                        break;
                    } else if first_frame {
                        self.signal_used_queue(self.rx_queue.vector);
                        first_frame = false;
                    } else {
                        needs_interrupt = true;
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

        needs_interrupt
    }

    fn process_tx(&mut self) {
        let mut frame = [0u8; MAX_BUFFER_SIZE];

        // Reads up to `buf.len()` bytes or until there is no more data in `r`, whichever
        // is smaller.
        fn read_to_end(mut r: Reader, buf: &mut [u8]) -> io::Result<usize> {
            let mut count = 0;
            while count < buf.len() {
                match r.read(&mut buf[count..]) {
                    Ok(0) => break,
                    Ok(n) => count += n,
                    Err(e) => return Err(e),
                }
            }

            Ok(count)
        }

        while let Some(desc_chain) = self.tx_queue.pop(&self.mem) {
            let index = desc_chain.index;

            match Reader::new(&self.mem, desc_chain) {
                Ok(reader) => {
                    match read_to_end(reader, &mut frame[..]) {
                        Ok(len) => {
                            // We need to copy frame into continuous buffer before writing it to tap
                            // because tap requires frame to complete in a single write.
                            if let Err(err) = self.tap.write_all(&frame[..len]) {
                                error!("net: tx: failed to write to tap: {}", err);
                            }
                        }
                        Err(e) => error!("net: tx: failed to read frame into buffer: {}", e),
                    }
                }
                Err(e) => error!("net: failed to create Reader: {}", e),
            }

            self.tx_queue.add_used(&self.mem, index, 0);
        }

        self.signal_used_queue(self.tx_queue.vector);
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

        let poll_ctx: PollContext<Token> = PollContext::build_with(&[
            (&self.tap, Token::RxTap),
            (&rx_queue_evt, Token::RxQueue),
            (&tx_queue_evt, Token::TxQueue),
            (&self.interrupt_resample_evt, Token::InterruptResample),
            (&kill_evt, Token::Kill),
        ])
        .map_err(NetError::CreatePollContext)?;

        'poll: loop {
            let events = poll_ctx.wait().map_err(NetError::PollError)?;
            for event in events.iter_readable() {
                let mut needs_interrupt_rx = false;
                match event.token() {
                    Token::RxTap => {
                        // Process a deferred frame first if available. Don't read from tap again
                        // until we manage to receive this deferred frame.
                        if self.deferred_rx {
                            if self.rx_single_frame() {
                                self.deferred_rx = false;
                                needs_interrupt_rx = true;
                            } else {
                                // There is an outstanding deferred frame and the guest has not yet
                                // made any buffers available. Remove the tapfd from the poll
                                // context until more are made available.
                                poll_ctx
                                    .delete(&self.tap)
                                    .map_err(NetError::PollDeleteTap)?;
                                continue;
                            }
                        }
                        needs_interrupt_rx |= self.process_rx();
                    }
                    Token::RxQueue => {
                        if let Err(e) = rx_queue_evt.read() {
                            error!("net: error reading rx queue EventFd: {}", e);
                            break 'poll;
                        }
                        // There should be a buffer available now to receive the frame into.
                        if self.deferred_rx && self.rx_single_frame() {
                            needs_interrupt_rx = true;

                            // The guest has made buffers available, so add the tap back to the
                            // poll context in case it was removed.
                            match poll_ctx.add(&self.tap, Token::RxTap) {
                                Ok(_) => {}
                                Err(e) if e.errno() == EEXIST => {}
                                Err(e) => {
                                    return Err(NetError::PollAddTap(e));
                                }
                            }
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

                if needs_interrupt_rx {
                    self.signal_used_queue(self.rx_queue.vector);
                }
            }
        }
        Ok(())
    }
}

pub struct Net<T: TapT> {
    workers_kill_evt: Option<EventFd>,
    kill_evt: EventFd,
    worker_thread: Option<thread::JoinHandle<()>>,
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
            worker_thread: None,
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

        if let Some(worker_thread) = self.worker_thread.take() {
            let _ = worker_thread.join();
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

    fn msix_vectors(&self) -> u16 {
        NUM_MSIX_VECTORS
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
        msix_config: Option<Arc<Mutex<MsixConfig>>>,
        status: Arc<AtomicUsize>,
        mut queues: Vec<Queue>,
        mut queue_evts: Vec<EventFd>,
    ) {
        if queues.len() != NUM_QUEUES || queue_evts.len() != NUM_QUEUES {
            error!("net: expected {} queues, got {}", NUM_QUEUES, queues.len());
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
                                msix_config,
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

                match worker_result {
                    Err(e) => {
                        error!("failed to spawn virtio_net worker: {}", e);
                        return;
                    }
                    Ok(join_handle) => {
                        self.worker_thread = Some(join_handle);
                    }
                }
            }
        }
    }
}
