// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io::{self, Write};
use std::mem;
use std::net::Ipv4Addr;
use std::os::raw::c_uint;
use std::result;
use std::sync::Arc;
use std::thread;

use base::Error as SysError;
use base::{error, warn, AsRawDescriptor, Event, EventType, PollToken, RawDescriptor, WaitContext};
use data_model::{DataInit, Le16, Le64};
use net_util::{Error as TapError, MacAddress, TapT};
use remain::sorted;
use thiserror::Error as ThisError;
use virtio_sys::virtio_net;
use virtio_sys::virtio_net::{
    virtio_net_hdr_v1, VIRTIO_NET_CTRL_GUEST_OFFLOADS, VIRTIO_NET_CTRL_GUEST_OFFLOADS_SET,
    VIRTIO_NET_CTRL_MQ, VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET, VIRTIO_NET_ERR, VIRTIO_NET_OK,
};
use vm_memory::GuestMemory;

use super::{
    copy_config, DescriptorError, Interrupt, Queue, Reader, SignalableInterrupt, VirtioDevice,
    Writer, TYPE_NET,
};

const QUEUE_SIZE: u16 = 256;

#[sorted]
#[derive(ThisError, Debug)]
pub enum NetError {
    /// Cloning kill event failed.
    #[error("failed to clone kill event: {0}")]
    CloneKillEvent(SysError),
    /// Creating kill event failed.
    #[error("failed to create kill event: {0}")]
    CreateKillEvent(SysError),
    /// Creating WaitContext failed.
    #[error("failed to create wait context: {0}")]
    CreateWaitContext(SysError),
    /// Descriptor chain was invalid.
    #[error("failed to valildate descriptor chain: {0}")]
    DescriptorChain(DescriptorError),
    /// Error reading data from control queue.
    #[error("failed to read control message data: {0}")]
    ReadCtrlData(io::Error),
    /// Error reading header from control queue.
    #[error("failed to read control message header: {0}")]
    ReadCtrlHeader(io::Error),
    /// There are no more available descriptors to receive into.
    #[error("no rx descriptors available")]
    RxDescriptorsExhausted,
    /// Enabling tap interface failed.
    #[error("failed to enable tap interface: {0}")]
    TapEnable(TapError),
    /// Couldn't get the MTU from the tap device.
    #[error("failed to get tap interface MTU: {0}")]
    TapGetMtu(TapError),
    /// Open tap device failed.
    #[error("failed to open tap device: {0}")]
    TapOpen(TapError),
    /// Setting tap IP failed.
    #[error("failed to set tap IP: {0}")]
    TapSetIp(TapError),
    /// Setting tap mac address failed.
    #[error("failed to set tap mac address: {0}")]
    TapSetMacAddress(TapError),
    /// Setting tap netmask failed.
    #[error("failed to set tap netmask: {0}")]
    TapSetNetmask(TapError),
    /// Setting vnet header size failed.
    #[error("failed to set vnet header size: {0}")]
    TapSetVnetHdrSize(TapError),
    /// Validating tap interface failed.
    #[error("failed to validate tap interface: {0}")]
    TapValidate(String),
    /// Removing read event from the tap fd events failed.
    #[error("failed to disable EPOLLIN on tap fd: {0}")]
    WaitContextDisableTap(SysError),
    /// Adding read event to the tap fd events failed.
    #[error("failed to enable EPOLLIN on tap fd: {0}")]
    WaitContextEnableTap(SysError),
    /// Error while waiting for events.
    #[error("error while waiting for events: {0}")]
    WaitError(SysError),
    /// Failed writing an ack in response to a control message.
    #[error("failed to write control message ack: {0}")]
    WriteAck(io::Error),
    /// Writing to a buffer in the guest failed.
    #[error("failed to write to guest buffer: {0}")]
    WriteBuffer(io::Error),
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct virtio_net_ctrl_hdr {
    pub class: u8,
    pub cmd: u8,
}

// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for virtio_net_ctrl_hdr {}

/// Converts virtio-net feature bits to tap's offload bits.
pub fn virtio_features_to_tap_offload(features: u64) -> c_uint {
    let mut tap_offloads: c_uint = 0;
    if features & (1 << virtio_net::VIRTIO_NET_F_GUEST_CSUM) != 0 {
        tap_offloads |= net_sys::TUN_F_CSUM;
    }
    if features & (1 << virtio_net::VIRTIO_NET_F_GUEST_TSO4) != 0 {
        tap_offloads |= net_sys::TUN_F_TSO4;
    }
    if features & (1 << virtio_net::VIRTIO_NET_F_GUEST_TSO6) != 0 {
        tap_offloads |= net_sys::TUN_F_TSO6;
    }
    if features & (1 << virtio_net::VIRTIO_NET_F_GUEST_ECN) != 0 {
        tap_offloads |= net_sys::TUN_F_TSO_ECN;
    }
    if features & (1 << virtio_net::VIRTIO_NET_F_GUEST_UFO) != 0 {
        tap_offloads |= net_sys::TUN_F_UFO;
    }

    tap_offloads
}

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct VirtioNetConfig {
    mac: [u8; 6],
    status: Le16,
    max_vq_pairs: Le16,
    mtu: Le16,
}

// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for VirtioNetConfig {}

pub fn process_rx<I: SignalableInterrupt, T: TapT>(
    interrupt: &I,
    rx_queue: &mut Queue,
    mem: &GuestMemory,
    mut tap: &mut T,
) -> result::Result<(), NetError> {
    let mut needs_interrupt = false;
    let mut exhausted_queue = false;

    // Read as many frames as possible.
    loop {
        let desc_chain = match rx_queue.peek(mem) {
            Some(desc) => desc,
            None => {
                exhausted_queue = true;
                break;
            }
        };

        let index = desc_chain.index;
        let bytes_written = match Writer::new(mem.clone(), desc_chain) {
            Ok(mut writer) => {
                match writer.write_from(&mut tap, writer.available_bytes()) {
                    Ok(_) => {}
                    Err(ref e) if e.kind() == io::ErrorKind::WriteZero => {
                        warn!("net: rx: buffer is too small to hold frame");
                        break;
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        // No more to read from the tap.
                        break;
                    }
                    Err(e) => {
                        warn!("net: rx: failed to write slice: {}", e);
                        return Err(NetError::WriteBuffer(e));
                    }
                };

                writer.bytes_written() as u32
            }
            Err(e) => {
                error!("net: failed to create Writer: {}", e);
                0
            }
        };

        if bytes_written > 0 {
            rx_queue.pop_peeked(mem);
            rx_queue.add_used(mem, index, bytes_written);
            needs_interrupt = true;
        }
    }

    if needs_interrupt {
        rx_queue.trigger_interrupt(mem, interrupt);
    }

    if exhausted_queue {
        Err(NetError::RxDescriptorsExhausted)
    } else {
        Ok(())
    }
}

pub fn process_tx<I: SignalableInterrupt, T: TapT>(
    interrupt: &I,
    tx_queue: &mut Queue,
    mem: &GuestMemory,
    mut tap: &mut T,
) {
    while let Some(desc_chain) = tx_queue.pop(mem) {
        let index = desc_chain.index;

        match Reader::new(mem.clone(), desc_chain) {
            Ok(mut reader) => {
                let expected_count = reader.available_bytes();
                match reader.read_to(&mut tap, expected_count) {
                    Ok(count) => {
                        // Tap writes must be done in one call. If the entire frame was not
                        // written, it's an error.
                        if count != expected_count {
                            error!(
                                "net: tx: wrote only {} bytes of {} byte frame",
                                count, expected_count
                            );
                        }
                    }
                    Err(e) => error!("net: tx: failed to write frame to tap: {}", e),
                }
            }
            Err(e) => error!("net: failed to create Reader: {}", e),
        }

        tx_queue.add_used(mem, index, 0);
    }

    tx_queue.trigger_interrupt(mem, interrupt);
}

pub fn process_ctrl<I: SignalableInterrupt, T: TapT>(
    interrupt: &I,
    ctrl_queue: &mut Queue,
    mem: &GuestMemory,
    tap: &mut T,
    acked_features: u64,
    vq_pairs: u16,
) -> Result<(), NetError> {
    while let Some(desc_chain) = ctrl_queue.pop(mem) {
        let index = desc_chain.index;

        let mut reader =
            Reader::new(mem.clone(), desc_chain.clone()).map_err(NetError::DescriptorChain)?;
        let mut writer = Writer::new(mem.clone(), desc_chain).map_err(NetError::DescriptorChain)?;
        let ctrl_hdr: virtio_net_ctrl_hdr = reader.read_obj().map_err(NetError::ReadCtrlHeader)?;

        let mut write_error = || {
            writer
                .write_all(&[VIRTIO_NET_ERR as u8])
                .map_err(NetError::WriteAck)?;
            ctrl_queue.add_used(mem, index, writer.bytes_written() as u32);
            Ok(())
        };

        match ctrl_hdr.class as c_uint {
            VIRTIO_NET_CTRL_GUEST_OFFLOADS => {
                if ctrl_hdr.cmd != VIRTIO_NET_CTRL_GUEST_OFFLOADS_SET as u8 {
                    error!(
                        "invalid cmd for VIRTIO_NET_CTRL_GUEST_OFFLOADS: {}",
                        ctrl_hdr.cmd
                    );
                    write_error()?;
                    continue;
                }
                let offloads: Le64 = reader.read_obj().map_err(NetError::ReadCtrlData)?;
                let tap_offloads = virtio_features_to_tap_offload(offloads.into());
                if let Err(e) = tap.set_offload(tap_offloads) {
                    error!("Failed to set tap itnerface offload flags: {}", e);
                    write_error()?;
                    continue;
                }

                let ack = VIRTIO_NET_OK as u8;
                writer.write_all(&[ack]).map_err(NetError::WriteAck)?;
            }
            VIRTIO_NET_CTRL_MQ => {
                if ctrl_hdr.cmd == VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET as u8 {
                    let pairs: Le16 = reader.read_obj().map_err(NetError::ReadCtrlData)?;
                    // Simple handle it now
                    if acked_features & 1 << virtio_net::VIRTIO_NET_F_MQ == 0
                        || pairs.to_native() != vq_pairs
                    {
                        error!("Invalid VQ_PAIRS_SET cmd, driver request pairs: {}, device vq pairs: {}",
                                   pairs.to_native(), vq_pairs);
                        write_error()?;
                        continue;
                    }
                    let ack = VIRTIO_NET_OK as u8;
                    writer.write_all(&[ack]).map_err(NetError::WriteAck)?;
                }
            }
            _ => warn!(
                "unimplemented class for VIRTIO_NET_CTRL_GUEST_OFFLOADS: {}",
                ctrl_hdr.class
            ),
        }

        ctrl_queue.add_used(mem, index, writer.bytes_written() as u32);
    }

    ctrl_queue.trigger_interrupt(mem, interrupt);
    Ok(())
}

#[derive(PollToken, Debug, Clone)]
pub enum Token {
    // A frame is available for reading from the tap device to receive in the guest.
    RxTap,
    // The guest has made a buffer available to receive a frame into.
    RxQueue,
    // The transmit queue has a frame that is ready to send from the guest.
    TxQueue,
    // The control queue has a message.
    CtrlQueue,
    // Check if any interrupts need to be re-asserted.
    InterruptResample,
    // crosvm has requested the device to shut down.
    Kill,
}

struct Worker<T: TapT> {
    interrupt: Arc<Interrupt>,
    mem: GuestMemory,
    rx_queue: Queue,
    tx_queue: Queue,
    ctrl_queue: Option<Queue>,
    tap: T,
    acked_features: u64,
    vq_pairs: u16,
    kill_evt: Event,
}

impl<T> Worker<T>
where
    T: TapT,
{
    fn process_rx(&mut self) -> result::Result<(), NetError> {
        process_rx(
            self.interrupt.as_ref(),
            &mut self.rx_queue,
            &self.mem,
            &mut self.tap,
        )
    }

    fn process_tx(&mut self) {
        process_tx(
            self.interrupt.as_ref(),
            &mut self.tx_queue,
            &self.mem,
            &mut self.tap,
        )
    }

    fn process_ctrl(&mut self) -> Result<(), NetError> {
        let ctrl_queue = match self.ctrl_queue.as_mut() {
            Some(queue) => queue,
            None => return Ok(()),
        };

        process_ctrl(
            self.interrupt.as_ref(),
            ctrl_queue,
            &self.mem,
            &mut self.tap,
            self.acked_features,
            self.vq_pairs,
        )
    }

    fn run(
        &mut self,
        rx_queue_evt: Event,
        tx_queue_evt: Event,
        ctrl_queue_evt: Option<Event>,
    ) -> Result<(), NetError> {
        let wait_ctx: WaitContext<Token> = WaitContext::build_with(&[
            (&self.tap, Token::RxTap),
            (&rx_queue_evt, Token::RxQueue),
            (&tx_queue_evt, Token::TxQueue),
            (&self.kill_evt, Token::Kill),
        ])
        .map_err(NetError::CreateWaitContext)?;

        if let Some(ctrl_evt) = &ctrl_queue_evt {
            wait_ctx
                .add(ctrl_evt, Token::CtrlQueue)
                .map_err(NetError::CreateWaitContext)?;
            // Let CtrlQueue's thread handle InterruptResample also.
            if let Some(resample_evt) = self.interrupt.get_resample_evt() {
                wait_ctx
                    .add(resample_evt, Token::InterruptResample)
                    .map_err(NetError::CreateWaitContext)?;
            }
        }

        let mut tap_polling_enabled = true;
        'wait: loop {
            let events = wait_ctx.wait().map_err(NetError::WaitError)?;
            for event in events.iter().filter(|e| e.is_readable) {
                match event.token {
                    Token::RxTap => match self.process_rx() {
                        Ok(()) => {}
                        Err(NetError::RxDescriptorsExhausted) => {
                            wait_ctx
                                .modify(&self.tap, EventType::None, Token::RxTap)
                                .map_err(NetError::WaitContextDisableTap)?;
                            tap_polling_enabled = false;
                        }
                        Err(e) => return Err(e),
                    },
                    Token::RxQueue => {
                        if let Err(e) = rx_queue_evt.read() {
                            error!("net: error reading rx queue Event: {}", e);
                            break 'wait;
                        }
                        if !tap_polling_enabled {
                            wait_ctx
                                .modify(&self.tap, EventType::Read, Token::RxTap)
                                .map_err(NetError::WaitContextEnableTap)?;
                            tap_polling_enabled = true;
                        }
                    }
                    Token::TxQueue => {
                        if let Err(e) = tx_queue_evt.read() {
                            error!("net: error reading tx queue Event: {}", e);
                            break 'wait;
                        }
                        self.process_tx();
                    }
                    Token::CtrlQueue => {
                        if let Some(ctrl_evt) = &ctrl_queue_evt {
                            if let Err(e) = ctrl_evt.read() {
                                error!("net: error reading ctrl queue Event: {}", e);
                                break 'wait;
                            }
                        } else {
                            break 'wait;
                        }
                        if let Err(e) = self.process_ctrl() {
                            error!("net: failed to process control message: {}", e);
                            break 'wait;
                        }
                    }
                    Token::InterruptResample => {
                        // We can unwrap safely because interrupt must have the event.
                        let _ = self.interrupt.get_resample_evt().unwrap().read();
                        self.interrupt.do_interrupt_resample();
                    }
                    Token::Kill => {
                        let _ = self.kill_evt.read();
                        break 'wait;
                    }
                }
            }
        }
        Ok(())
    }
}

pub fn build_config(vq_pairs: u16, mtu: u16) -> VirtioNetConfig {
    VirtioNetConfig {
        max_vq_pairs: Le16::from(vq_pairs),
        mtu: Le16::from(mtu),
        // Other field has meaningful value when the corresponding feature
        // is enabled, but all these features aren't supported now.
        // So set them to default.
        ..Default::default()
    }
}

pub struct Net<T: TapT> {
    queue_sizes: Box<[u16]>,
    workers_kill_evt: Vec<Event>,
    kill_evts: Vec<Event>,
    worker_threads: Vec<thread::JoinHandle<Worker<T>>>,
    taps: Vec<T>,
    avail_features: u64,
    acked_features: u64,
    mtu: u16,
}

impl<T> Net<T>
where
    T: TapT,
{
    /// Create a new virtio network device with the given IP address and
    /// netmask.
    pub fn new(
        base_features: u64,
        ip_addr: Ipv4Addr,
        netmask: Ipv4Addr,
        mac_addr: MacAddress,
        vq_pairs: u16,
    ) -> Result<Net<T>, NetError> {
        let multi_queue = vq_pairs > 1;
        let tap: T = T::new(true, multi_queue).map_err(NetError::TapOpen)?;
        tap.set_ip_addr(ip_addr).map_err(NetError::TapSetIp)?;
        tap.set_netmask(netmask).map_err(NetError::TapSetNetmask)?;
        tap.set_mac_address(mac_addr)
            .map_err(NetError::TapSetMacAddress)?;

        tap.enable().map_err(NetError::TapEnable)?;

        Net::from(base_features, tap, vq_pairs)
    }

    /// Try to open the already-configured TAP interface `name` and to create a network device from
    /// it.
    pub fn new_from_name(
        base_features: u64,
        name: &[u8],
        vq_pairs: u16,
    ) -> Result<Net<T>, NetError> {
        let multi_queue = vq_pairs > 1;
        let tap: T = T::new_with_name(name, true, multi_queue).map_err(NetError::TapOpen)?;

        Net::from(base_features, tap, vq_pairs)
    }

    /// Creates a new virtio network device from a tap device that has already been
    /// configured.
    pub fn from(base_features: u64, tap: T, vq_pairs: u16) -> Result<Net<T>, NetError> {
        let taps = tap.into_mq_taps(vq_pairs).map_err(NetError::TapOpen)?;

        let mut mtu = u16::MAX;
        // This would also validate a tap created by Self::new(), but that's a good thing as it
        // would ensure that any changes in the creation procedure are matched in the validation.
        // Plus we still need to set the offload and vnet_hdr_size values.
        for tap in &taps {
            validate_and_configure_tap(tap, vq_pairs)?;
            mtu = std::cmp::min(mtu, tap.mtu().map_err(NetError::TapGetMtu)?);
        }

        let mut avail_features = base_features
            | 1 << virtio_net::VIRTIO_NET_F_GUEST_CSUM
            | 1 << virtio_net::VIRTIO_NET_F_CSUM
            | 1 << virtio_net::VIRTIO_NET_F_CTRL_VQ
            | 1 << virtio_net::VIRTIO_NET_F_CTRL_GUEST_OFFLOADS
            | 1 << virtio_net::VIRTIO_NET_F_GUEST_TSO4
            | 1 << virtio_net::VIRTIO_NET_F_GUEST_UFO
            | 1 << virtio_net::VIRTIO_NET_F_HOST_TSO4
            | 1 << virtio_net::VIRTIO_NET_F_HOST_UFO
            | 1 << virtio_net::VIRTIO_NET_F_MTU;

        if vq_pairs > 1 {
            avail_features |= 1 << virtio_net::VIRTIO_NET_F_MQ;
        }

        let mut kill_evts: Vec<Event> = Vec::new();
        let mut workers_kill_evt: Vec<Event> = Vec::new();
        for _ in 0..taps.len() {
            let kill_evt = Event::new().map_err(NetError::CreateKillEvent)?;
            let worker_kill_evt = kill_evt.try_clone().map_err(NetError::CloneKillEvent)?;
            kill_evts.push(kill_evt);
            workers_kill_evt.push(worker_kill_evt);
        }

        Ok(Net {
            queue_sizes: vec![QUEUE_SIZE; (vq_pairs * 2 + 1) as usize].into_boxed_slice(),
            workers_kill_evt,
            kill_evts,
            worker_threads: Vec::new(),
            taps,
            avail_features,
            acked_features: 0u64,
            mtu,
        })
    }
}

// Ensure that the tap interface has the correct flags and sets the offload and VNET header size
// to the appropriate values.
pub fn validate_and_configure_tap<T: TapT>(tap: &T, vq_pairs: u16) -> Result<(), NetError> {
    let flags = tap.if_flags();
    let mut required_flags = vec![
        (net_sys::IFF_TAP, "IFF_TAP"),
        (net_sys::IFF_NO_PI, "IFF_NO_PI"),
        (net_sys::IFF_VNET_HDR, "IFF_VNET_HDR"),
    ];
    if vq_pairs > 1 {
        required_flags.push((net_sys::IFF_MULTI_QUEUE, "IFF_MULTI_QUEUE"));
    }
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
        let len = self.kill_evts.len();
        for i in 0..len {
            // Only kill the child if it claimed its event.
            if self.workers_kill_evt.get(i).is_none() {
                if let Some(kill_evt) = self.kill_evts.get(i) {
                    // Ignore the result because there is nothing we can do about it.
                    let _ = kill_evt.write(1);
                }
            }
        }

        let len = self.worker_threads.len();
        for _ in 0..len {
            let _ = self.worker_threads.remove(0).join();
        }
    }
}

impl<T> VirtioDevice for Net<T>
where
    T: 'static + TapT,
{
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        let mut keep_rds = Vec::new();

        for tap in &self.taps {
            keep_rds.push(tap.as_raw_descriptor());
        }

        for worker_kill_evt in &self.workers_kill_evt {
            keep_rds.push(worker_kill_evt.as_raw_descriptor());
        }
        for kill_evt in &self.kill_evts {
            keep_rds.push(kill_evt.as_raw_descriptor());
        }

        keep_rds
    }

    fn device_type(&self) -> u32 {
        TYPE_NET
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.queue_sizes
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

        // Set offload flags to match acked virtio features.
        if let Some(tap) = self.taps.first() {
            if let Err(e) = tap.set_offload(virtio_features_to_tap_offload(self.acked_features)) {
                warn!(
                    "net: failed to set tap offload to match acked features: {}",
                    e
                );
            }
        }
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let vq_pairs = self.queue_sizes.len() / 2;
        let config_space = build_config(vq_pairs as u16, self.mtu);
        copy_config(data, 0, config_space.as_slice(), offset);
    }

    fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt: Interrupt,
        mut queues: Vec<Queue>,
        mut queue_evts: Vec<Event>,
    ) {
        if queues.len() != self.queue_sizes.len() || queue_evts.len() != self.queue_sizes.len() {
            error!(
                "net: expected {} queues, got {}",
                self.queue_sizes.len(),
                queues.len()
            );
            return;
        }

        let vq_pairs = self.queue_sizes.len() / 2;
        if self.taps.len() != vq_pairs {
            error!("net: expected {} taps, got {}", vq_pairs, self.taps.len());
            return;
        }
        if self.workers_kill_evt.len() != vq_pairs {
            error!(
                "net: expected {} worker_kill_evt, got {}",
                vq_pairs,
                self.workers_kill_evt.len()
            );
            return;
        }
        let interrupt_arc = Arc::new(interrupt);
        for i in 0..vq_pairs {
            let tap = self.taps.remove(0);
            let acked_features = self.acked_features;
            let interrupt = interrupt_arc.clone();
            let memory = mem.clone();
            let kill_evt = self.workers_kill_evt.remove(0);
            // Queues alternate between rx0, tx0, rx1, tx1, ..., rxN, txN, ctrl.
            let rx_queue = queues.remove(0);
            let tx_queue = queues.remove(0);
            let ctrl_queue = if i == 0 {
                Some(queues.remove(queues.len() - 1))
            } else {
                None
            };
            let pairs = vq_pairs as u16;
            let rx_queue_evt = queue_evts.remove(0);
            let tx_queue_evt = queue_evts.remove(0);
            let ctrl_queue_evt = if i == 0 {
                Some(queue_evts.remove(queue_evts.len() - 1))
            } else {
                None
            };
            let worker_result = thread::Builder::new()
                .name(format!("virtio_net worker {}", i))
                .spawn(move || {
                    let mut worker = Worker {
                        interrupt,
                        mem: memory,
                        rx_queue,
                        tx_queue,
                        ctrl_queue,
                        tap,
                        acked_features,
                        vq_pairs: pairs,
                        kill_evt,
                    };
                    let result = worker.run(rx_queue_evt, tx_queue_evt, ctrl_queue_evt);
                    if let Err(e) = result {
                        error!("net worker thread exited with error: {}", e);
                    }
                    worker
                });

            match worker_result {
                Err(e) => {
                    error!("failed to spawn virtio_net worker: {}", e);
                    return;
                }
                Ok(join_handle) => self.worker_threads.push(join_handle),
            }
        }
    }

    fn reset(&mut self) -> bool {
        let len = self.kill_evts.len();
        for i in 0..len {
            // Only kill the child if it claimed its event.
            if self.workers_kill_evt.get(i).is_none() {
                if let Some(kill_evt) = self.kill_evts.get(i) {
                    if kill_evt.write(1).is_err() {
                        error!("{}: failed to notify the kill event", self.debug_label());
                        return false;
                    }
                }
            }
        }

        let len = self.worker_threads.len();
        for _ in 0..len {
            match self.worker_threads.remove(0).join() {
                Err(_) => {
                    error!("{}: failed to get back resources", self.debug_label());
                    return false;
                }
                Ok(worker) => {
                    self.taps.push(worker.tap);
                    self.workers_kill_evt.push(worker.kill_evt);
                }
            }
        }

        true
    }
}
