// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod sys;

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::io::Write;
use std::mem;
use std::net::Ipv4Addr;
use std::os::raw::c_uint;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::anyhow;
use anyhow::Context;
use base::error;
#[cfg(windows)]
use base::named_pipes::OverlappedWrapper;
use base::warn;
use base::Error as SysError;
use base::Event;
use base::EventToken;
use base::RawDescriptor;
use base::ReadNotifier;
use base::WaitContext;
use base::WorkerThread;
use data_model::Le16;
use data_model::Le64;
use net_util::Error as TapError;
use net_util::MacAddress;
use net_util::TapT;
use remain::sorted;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error as ThisError;
use virtio_sys::virtio_config::VIRTIO_F_RING_PACKED;
use virtio_sys::virtio_net;
use virtio_sys::virtio_net::virtio_net_hdr_v1;
use virtio_sys::virtio_net::VIRTIO_NET_CTRL_GUEST_OFFLOADS;
use virtio_sys::virtio_net::VIRTIO_NET_CTRL_GUEST_OFFLOADS_SET;
use virtio_sys::virtio_net::VIRTIO_NET_CTRL_MQ;
use virtio_sys::virtio_net::VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET;
use virtio_sys::virtio_net::VIRTIO_NET_ERR;
use virtio_sys::virtio_net::VIRTIO_NET_OK;
use vm_memory::GuestMemory;
use zerocopy::AsBytes;
use zerocopy::FromBytes;

use super::copy_config;
use super::DeviceType;
use super::Interrupt;
use super::Queue;
use super::Reader;
use super::VirtioDevice;

/// The maximum buffer size when segmentation offload is enabled. This
/// includes the 12-byte virtio net header.
/// http://docs.oasis-open.org/virtio/virtio/v1.0/virtio-v1.0.html#x1-1740003
#[cfg(windows)]
pub(crate) const MAX_BUFFER_SIZE: usize = 65562;
const QUEUE_SIZE: u16 = 256;

#[cfg(unix)]
pub static VHOST_NET_DEFAULT_PATH: &str = "/dev/vhost-net";

pub(crate) use sys::process_rx;
pub(crate) use sys::process_tx;

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
    /// Adding the tap descriptor back to the event context failed.
    #[error("failed to add tap trigger to event context: {0}")]
    EventAddTap(SysError),
    /// Removing the tap descriptor from the event context failed.
    #[error("failed to remove tap trigger from event context: {0}")]
    EventRemoveTap(SysError),
    /// Invalid control command
    #[error("invalid control command")]
    InvalidCmd,
    /// Error reading data from control queue.
    #[error("failed to read control message data: {0}")]
    ReadCtrlData(io::Error),
    /// Error reading header from control queue.
    #[error("failed to read control message header: {0}")]
    ReadCtrlHeader(io::Error),
    /// There are no more available descriptors to receive into.
    #[cfg(unix)]
    #[error("no rx descriptors available")]
    RxDescriptorsExhausted,
    /// Failure creating the Slirp loop.
    #[cfg(windows)]
    #[error("error creating Slirp: {0}")]
    SlirpCreateError(net_util::Error),
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
    /// Setting tap offload failed.
    #[error("failed to set tap offload: {0}")]
    TapSetOffload(TapError),
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
    #[cfg(unix)]
    #[error("failed to write to guest buffer: {0}")]
    WriteBuffer(io::Error),
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(untagged, deny_unknown_fields)]
pub enum NetParametersMode {
    #[serde(rename_all = "kebab-case")]
    TapName {
        tap_name: String,
        mac: Option<MacAddress>,
    },
    #[serde(rename_all = "kebab-case")]
    TapFd {
        tap_fd: i32,
        mac: Option<MacAddress>,
    },
    #[serde(rename_all = "kebab-case")]
    RawConfig {
        host_ip: Ipv4Addr,
        netmask: Ipv4Addr,
        mac: MacAddress,
    },
}

#[cfg(unix)]
fn vhost_net_device_path_default() -> PathBuf {
    PathBuf::from(VHOST_NET_DEFAULT_PATH)
}

#[cfg(unix)]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct VhostNetParameters {
    #[serde(default = "vhost_net_device_path_default")]
    pub device: PathBuf,
}

#[cfg(unix)]
impl Default for VhostNetParameters {
    fn default() -> Self {
        Self {
            device: vhost_net_device_path_default(),
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct NetParameters {
    #[serde(flatten)]
    pub mode: NetParametersMode,
    pub vq_pairs: Option<u16>,
    // Style-guide asks to refrain against #[cfg] directives in structs, this is an exception due
    // to the fact this struct is used for argument parsing.
    #[cfg(unix)]
    pub vhost_net: Option<VhostNetParameters>,
    #[serde(default)]
    pub packed_queue: bool,
}

impl FromStr for NetParameters {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_keyvalue::from_key_values(s).map_err(|e| e.to_string())
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, AsBytes, FromBytes)]
pub struct virtio_net_ctrl_hdr {
    pub class: u8,
    pub cmd: u8,
}

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

#[derive(Debug, Clone, Copy, Default, AsBytes, FromBytes)]
#[repr(C)]
pub struct VirtioNetConfig {
    mac: [u8; 6],
    status: Le16,
    max_vq_pairs: Le16,
    mtu: Le16,
}

fn process_ctrl_request<T: TapT>(
    reader: &mut Reader,
    tap: &mut T,
    acked_features: u64,
    vq_pairs: u16,
) -> Result<(), NetError> {
    let ctrl_hdr: virtio_net_ctrl_hdr = reader.read_obj().map_err(NetError::ReadCtrlHeader)?;

    match ctrl_hdr.class as c_uint {
        VIRTIO_NET_CTRL_GUEST_OFFLOADS => {
            if ctrl_hdr.cmd != VIRTIO_NET_CTRL_GUEST_OFFLOADS_SET as u8 {
                error!(
                    "invalid cmd for VIRTIO_NET_CTRL_GUEST_OFFLOADS: {}",
                    ctrl_hdr.cmd
                );
                return Err(NetError::InvalidCmd);
            }
            let offloads: Le64 = reader.read_obj().map_err(NetError::ReadCtrlData)?;
            let tap_offloads = virtio_features_to_tap_offload(offloads.into());
            tap.set_offload(tap_offloads)
                .map_err(NetError::TapSetOffload)?;
        }
        VIRTIO_NET_CTRL_MQ => {
            if ctrl_hdr.cmd == VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET as u8 {
                let pairs: Le16 = reader.read_obj().map_err(NetError::ReadCtrlData)?;
                // Simple handle it now
                if acked_features & 1 << virtio_net::VIRTIO_NET_F_MQ == 0
                    || pairs.to_native() != vq_pairs
                {
                    error!(
                        "Invalid VQ_PAIRS_SET cmd, driver request pairs: {}, device vq pairs: {}",
                        pairs.to_native(),
                        vq_pairs
                    );
                    return Err(NetError::InvalidCmd);
                }
            }
        }
        _ => {
            warn!(
                "unimplemented class for VIRTIO_NET_CTRL_GUEST_OFFLOADS: {}",
                ctrl_hdr.class
            );
            return Err(NetError::InvalidCmd);
        }
    }

    Ok(())
}

pub fn process_ctrl<T: TapT>(
    interrupt: &Interrupt,
    ctrl_queue: &mut Queue,
    tap: &mut T,
    acked_features: u64,
    vq_pairs: u16,
) -> Result<(), NetError> {
    while let Some(mut desc_chain) = ctrl_queue.pop() {
        if let Err(e) = process_ctrl_request(&mut desc_chain.reader, tap, acked_features, vq_pairs)
        {
            error!("process_ctrl_request failed: {}", e);
            desc_chain
                .writer
                .write_all(&[VIRTIO_NET_ERR as u8])
                .map_err(NetError::WriteAck)?;
        } else {
            desc_chain
                .writer
                .write_all(&[VIRTIO_NET_OK as u8])
                .map_err(NetError::WriteAck)?;
        }
        let len = desc_chain.writer.bytes_written() as u32;
        ctrl_queue.add_used(desc_chain, len);
    }

    ctrl_queue.trigger_interrupt(interrupt);
    Ok(())
}

#[derive(EventToken, Debug, Clone)]
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

pub(super) struct Worker<T: TapT> {
    pub(super) interrupt: Interrupt,
    pub(super) rx_queue: Queue,
    pub(super) tx_queue: Queue,
    pub(super) ctrl_queue: Option<Queue>,
    pub(super) tap: T,
    #[cfg(windows)]
    pub(super) overlapped_wrapper: OverlappedWrapper,
    #[cfg(windows)]
    pub(super) rx_buf: [u8; MAX_BUFFER_SIZE],
    #[cfg(windows)]
    pub(super) rx_count: usize,
    #[cfg(windows)]
    pub(super) deferred_rx: bool,
    acked_features: u64,
    vq_pairs: u16,
    #[allow(dead_code)]
    kill_evt: Event,
}

impl<T> Worker<T>
where
    T: TapT + ReadNotifier,
{
    fn process_tx(&mut self) {
        process_tx(&self.interrupt, &mut self.tx_queue, &mut self.tap)
    }

    fn process_ctrl(&mut self) -> Result<(), NetError> {
        let ctrl_queue = match self.ctrl_queue.as_mut() {
            Some(queue) => queue,
            None => return Ok(()),
        };

        process_ctrl(
            &self.interrupt,
            ctrl_queue,
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
        handle_interrupt_resample: bool,
    ) -> Result<(), NetError> {
        let wait_ctx: WaitContext<Token> = WaitContext::build_with(&[
            // This doesn't use get_read_notifier() because of overlapped io; we
            // have overlapped wrapper separate from the TAP so that we can pass
            // the overlapped wrapper into the read function. This overlapped
            // wrapper's event is where we get the read notification.
            #[cfg(windows)]
            (
                self.overlapped_wrapper.get_h_event_ref().unwrap(),
                Token::RxTap,
            ),
            #[cfg(unix)]
            (self.tap.get_read_notifier(), Token::RxTap),
            (&rx_queue_evt, Token::RxQueue),
            (&tx_queue_evt, Token::TxQueue),
            (&self.kill_evt, Token::Kill),
        ])
        .map_err(NetError::CreateWaitContext)?;

        if let Some(ctrl_evt) = &ctrl_queue_evt {
            wait_ctx
                .add(ctrl_evt, Token::CtrlQueue)
                .map_err(NetError::CreateWaitContext)?;
        }

        if handle_interrupt_resample {
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
                    Token::RxTap => {
                        let _trace = cros_tracing::trace_event!(VirtioNet, "handle RxTap event");
                        self.handle_rx_token(&wait_ctx)?;
                        tap_polling_enabled = false;
                    }
                    Token::RxQueue => {
                        let _trace = cros_tracing::trace_event!(VirtioNet, "handle RxQueue event");
                        if let Err(e) = rx_queue_evt.wait() {
                            error!("net: error reading rx queue Event: {}", e);
                            break 'wait;
                        }
                        self.handle_rx_queue(&wait_ctx, tap_polling_enabled)?;
                        tap_polling_enabled = true;
                    }
                    Token::TxQueue => {
                        let _trace = cros_tracing::trace_event!(VirtioNet, "handle TxQueue event");
                        if let Err(e) = tx_queue_evt.wait() {
                            error!("net: error reading tx queue Event: {}", e);
                            break 'wait;
                        }
                        self.process_tx();
                    }
                    Token::CtrlQueue => {
                        let _trace =
                            cros_tracing::trace_event!(VirtioNet, "handle CtrlQueue event");
                        if let Some(ctrl_evt) = &ctrl_queue_evt {
                            if let Err(e) = ctrl_evt.wait() {
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
                        let _trace =
                            cros_tracing::trace_event!(VirtioNet, "handle InterruptResample event");
                        // We can unwrap safely because interrupt must have the event.
                        let _ = self.interrupt.get_resample_evt().unwrap().wait();
                        self.interrupt.do_interrupt_resample();
                    }
                    Token::Kill => {
                        let _ = self.kill_evt.wait();
                        break 'wait;
                    }
                }
            }
        }
        Ok(())
    }
}

pub fn build_config(vq_pairs: u16, mtu: u16, mac: Option<[u8; 6]>) -> VirtioNetConfig {
    VirtioNetConfig {
        max_vq_pairs: Le16::from(vq_pairs),
        mtu: Le16::from(mtu),
        mac: mac.unwrap_or_default(),
        // Other field has meaningful value when the corresponding feature
        // is enabled, but all these features aren't supported now.
        // So set them to default.
        ..Default::default()
    }
}

pub struct Net<T: TapT + ReadNotifier + 'static> {
    guest_mac: Option<[u8; 6]>,
    queue_sizes: Box<[u16]>,
    worker_threads: Vec<WorkerThread<Worker<T>>>,
    taps: Vec<T>,
    avail_features: u64,
    acked_features: u64,
    mtu: u16,
    #[cfg(windows)]
    slirp_kill_evt: Option<Event>,
}

#[derive(Serialize, Deserialize)]
struct NetSnapshot {
    avail_features: u64,
    acked_features: u64,
}

impl<T> Net<T>
where
    T: TapT + ReadNotifier,
{
    /// Creates a new virtio network device from a tap device that has already been
    /// configured.
    pub fn new(
        base_features: u64,
        tap: T,
        vq_pairs: u16,
        mac_addr: Option<MacAddress>,
        use_packed_queue: bool,
    ) -> Result<Net<T>, NetError> {
        let taps = tap.into_mq_taps(vq_pairs).map_err(NetError::TapOpen)?;

        let mut mtu = u16::MAX;
        // This would also validate a tap created by Self::new(), but that's a good thing as it
        // would ensure that any changes in the creation procedure are matched in the validation.
        // Plus we still need to set the offload and vnet_hdr_size values.
        for tap in &taps {
            validate_and_configure_tap(tap, vq_pairs)?;
            mtu = std::cmp::min(mtu, tap.mtu().map_err(NetError::TapGetMtu)?);
        }

        // Indicate that the TAP device supports a number of features, such as:
        // Partial checksum offload
        // TSO (TCP segmentation offload)
        // UFO (UDP fragmentation offload)
        // See the network device feature bits section for further details:
        //     http://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.html#x1-1970003
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

        if use_packed_queue {
            avail_features |= 1 << VIRTIO_F_RING_PACKED;
        }

        if mac_addr.is_some() {
            avail_features |= 1 << virtio_net::VIRTIO_NET_F_MAC;
        }

        Self::new_internal(
            taps,
            avail_features,
            mtu,
            mac_addr,
            #[cfg(windows)]
            None,
        )
    }

    pub(crate) fn new_internal(
        taps: Vec<T>,
        avail_features: u64,
        mtu: u16,
        mac_addr: Option<MacAddress>,
        #[cfg(windows)] slirp_kill_evt: Option<Event>,
    ) -> Result<Self, NetError> {
        let net = Self {
            guest_mac: mac_addr.map(|mac| mac.octets()),
            queue_sizes: vec![QUEUE_SIZE; taps.len() * 2 + 1].into_boxed_slice(),
            worker_threads: Vec::new(),
            taps,
            avail_features,
            acked_features: 0u64,
            mtu,
            #[cfg(windows)]
            slirp_kill_evt: None,
        };
        cros_tracing::trace_simple_print!("New Net device created: {:?}", net);
        Ok(net)
    }

    /// Returns the maximum number of receive/transmit queue pairs for this device.
    /// Only relevant when multi-queue support is negotiated.
    fn max_virtqueue_pairs(&self) -> usize {
        self.taps.len()
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
    T: TapT + ReadNotifier,
{
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            if let Some(slirp_kill_evt) = self.slirp_kill_evt.take() {
                let _ = slirp_kill_evt.signal();
            }
        }
    }
}

impl<T> VirtioDevice for Net<T>
where
    T: 'static + TapT + ReadNotifier,
{
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        let mut keep_rds = Vec::new();

        for tap in &self.taps {
            keep_rds.push(tap.as_raw_descriptor());
        }

        keep_rds
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::Net
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
        let config_space = build_config(vq_pairs as u16, self.mtu, self.guest_mac);
        copy_config(data, 0, config_space.as_bytes(), offset);
    }

    fn activate(
        &mut self,
        _mem: GuestMemory,
        interrupt: Interrupt,
        mut queues: BTreeMap<usize, (Queue, Event)>,
    ) -> anyhow::Result<()> {
        let ctrl_vq_enabled = self.acked_features & (1 << virtio_net::VIRTIO_NET_F_CTRL_VQ) != 0;
        let mq_enabled = self.acked_features & (1 << virtio_net::VIRTIO_NET_F_MQ) != 0;

        let vq_pairs = if mq_enabled {
            self.max_virtqueue_pairs()
        } else {
            1
        };

        let mut num_queues_expected = vq_pairs * 2;
        if ctrl_vq_enabled {
            num_queues_expected += 1;
        }

        if queues.len() != num_queues_expected {
            return Err(anyhow!(
                "net: expected {} queues, got {} queues",
                self.queue_sizes.len(),
                queues.len(),
            ));
        }

        if self.taps.len() < vq_pairs {
            return Err(anyhow!(
                "net: expected {} taps, got {}",
                vq_pairs,
                self.taps.len()
            ));
        }

        for i in 0..vq_pairs {
            let tap = self.taps.remove(0);
            let acked_features = self.acked_features;
            let interrupt = interrupt.clone();
            let first_queue = i == 0;
            // Queues alternate between rx0, tx0, rx1, tx1, ..., rxN, txN, ctrl.
            let (rx_queue, rx_queue_evt) = queues.pop_first().unwrap().1;
            let (tx_queue, tx_queue_evt) = queues.pop_first().unwrap().1;
            let (ctrl_queue, ctrl_queue_evt) = if first_queue && ctrl_vq_enabled {
                let (queue, evt) = queues.pop_last().unwrap().1;
                (Some(queue), Some(evt))
            } else {
                (None, None)
            };
            // Handle interrupt resampling on the first queue's thread.
            let handle_interrupt_resample = first_queue;
            let pairs = vq_pairs as u16;
            #[cfg(windows)]
            let overlapped_wrapper = OverlappedWrapper::new(true).unwrap();
            self.worker_threads
                .push(WorkerThread::start(format!("v_net:{i}"), move |kill_evt| {
                    let mut worker = Worker {
                        interrupt,
                        rx_queue,
                        tx_queue,
                        ctrl_queue,
                        tap,
                        #[cfg(windows)]
                        overlapped_wrapper,
                        acked_features,
                        vq_pairs: pairs,
                        #[cfg(windows)]
                        rx_buf: [0u8; MAX_BUFFER_SIZE],
                        #[cfg(windows)]
                        rx_count: 0,
                        #[cfg(windows)]
                        deferred_rx: false,
                        kill_evt,
                    };
                    let result = worker.run(
                        rx_queue_evt,
                        tx_queue_evt,
                        ctrl_queue_evt,
                        handle_interrupt_resample,
                    );
                    if let Err(e) = result {
                        error!("net worker thread exited with error: {}", e);
                    }
                    worker
                }));
        }
        cros_tracing::trace_simple_print!("Net device activated: {:?}", self);
        Ok(())
    }

    fn virtio_sleep(&mut self) -> anyhow::Result<Option<BTreeMap<usize, Queue>>> {
        if self.worker_threads.is_empty() {
            return Ok(None);
        }
        let mut queues = BTreeMap::new();
        let mut queue_index = 0;
        let mut ctrl_queue = None;
        for worker_thread in self.worker_threads.drain(..) {
            let mut worker = worker_thread.stop();
            if worker.ctrl_queue.is_some() {
                ctrl_queue = worker.ctrl_queue.take();
            }
            self.taps.push(worker.tap);
            queues.insert(queue_index + 0, worker.rx_queue);
            queues.insert(queue_index + 1, worker.tx_queue);
            queue_index += 2;
        }
        if let Some(ctrl_queue) = ctrl_queue {
            queues.insert(queue_index, ctrl_queue);
        }
        Ok(Some(queues))
    }

    fn virtio_wake(
        &mut self,
        device_state: Option<(GuestMemory, Interrupt, BTreeMap<usize, (Queue, Event)>)>,
    ) -> anyhow::Result<()> {
        match device_state {
            None => Ok(()),
            Some((mem, interrupt, queues)) => {
                // TODO: activate is just what we want at the moment, but we should probably move
                // it into a "start workers" function to make it obvious that it isn't strictly
                // used for activate events.
                self.activate(mem, interrupt, queues)?;
                Ok(())
            }
        }
    }

    fn virtio_snapshot(&self) -> anyhow::Result<serde_json::Value> {
        serde_json::to_value(NetSnapshot {
            acked_features: self.acked_features,
            avail_features: self.avail_features,
        })
        .context("failed to snapshot virtio Net device")
    }

    fn virtio_restore(&mut self, data: serde_json::Value) -> anyhow::Result<()> {
        let deser: NetSnapshot =
            serde_json::from_value(data).context("failed to deserialize Net device")?;
        anyhow::ensure!(
            self.avail_features == deser.avail_features,
            "Available features for net device do not match. expected: {},  got: {}",
            deser.avail_features,
            self.avail_features
        );
        self.acked_features = deser.acked_features;
        Ok(())
    }

    fn reset(&mut self) -> bool {
        for worker_thread in self.worker_threads.drain(..) {
            let worker = worker_thread.stop();
            self.taps.push(worker.tap);
        }

        true
    }
}

impl<T> std::fmt::Debug for Net<T>
where
    T: TapT + ReadNotifier,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Net")
            .field("guest_mac", &self.guest_mac)
            .field("queue_sizes", &self.queue_sizes)
            .field("worker_threads_size", &self.worker_threads.len())
            .field("taps_size", &self.taps.len())
            .field("avail_features", &self.avail_features)
            .field("acked_features", &self.acked_features)
            .field("mtu", &self.mtu)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use serde_keyvalue::*;

    use super::*;

    fn from_net_arg(options: &str) -> Result<NetParameters, ParseError> {
        from_key_values(options)
    }

    #[test]
    fn params_from_key_values() {
        let params = from_net_arg("");
        assert!(params.is_err());

        let params = from_net_arg("tap-name=tap").unwrap();
        assert_eq!(
            params,
            NetParameters {
                #[cfg(unix)]
                vhost_net: None,
                vq_pairs: None,
                mode: NetParametersMode::TapName {
                    tap_name: "tap".to_string(),
                    mac: None
                },
                packed_queue: false
            }
        );

        let params = from_net_arg("tap-name=tap,mac=\"3d:70:eb:61:1a:91\"").unwrap();
        assert_eq!(
            params,
            NetParameters {
                #[cfg(unix)]
                vhost_net: None,
                vq_pairs: None,
                mode: NetParametersMode::TapName {
                    tap_name: "tap".to_string(),
                    mac: Some(MacAddress::from_str("3d:70:eb:61:1a:91").unwrap())
                },
                packed_queue: false
            }
        );

        let params = from_net_arg("tap-fd=12").unwrap();
        assert_eq!(
            params,
            NetParameters {
                #[cfg(unix)]
                vhost_net: None,
                vq_pairs: None,
                mode: NetParametersMode::TapFd {
                    tap_fd: 12,
                    mac: None
                },
                packed_queue: false,
            }
        );

        let params = from_net_arg("tap-fd=12,mac=\"3d:70:eb:61:1a:91\"").unwrap();
        assert_eq!(
            params,
            NetParameters {
                #[cfg(unix)]
                vhost_net: None,
                vq_pairs: None,
                mode: NetParametersMode::TapFd {
                    tap_fd: 12,
                    mac: Some(MacAddress::from_str("3d:70:eb:61:1a:91").unwrap())
                },
                packed_queue: false
            }
        );

        let params = from_net_arg(
            "host-ip=\"192.168.10.1\",netmask=\"255.255.255.0\",mac=\"3d:70:eb:61:1a:91\"",
        )
        .unwrap();
        assert_eq!(
            params,
            NetParameters {
                #[cfg(unix)]
                vhost_net: None,
                vq_pairs: None,
                mode: NetParametersMode::RawConfig {
                    host_ip: Ipv4Addr::from_str("192.168.10.1").unwrap(),
                    netmask: Ipv4Addr::from_str("255.255.255.0").unwrap(),
                    mac: MacAddress::from_str("3d:70:eb:61:1a:91").unwrap(),
                },
                packed_queue: false
            }
        );

        // missing netmask
        assert!(from_net_arg("host-ip=\"192.168.10.1\",mac=\"3d:70:eb:61:1a:91\"").is_err());

        // invalid parameter
        assert!(from_net_arg("tap-name=tap,foomatic=true").is_err());
    }

    #[test]
    #[cfg(unix)]
    fn params_from_key_values_vhost_net() {
        let params = from_net_arg(
            "vhost-net=[device=/dev/foo],\
                host-ip=\"192.168.10.1\",\
                netmask=\"255.255.255.0\",\
                mac=\"3d:70:eb:61:1a:91\"",
        )
        .unwrap();
        assert_eq!(
            params,
            NetParameters {
                vhost_net: Some(VhostNetParameters {
                    device: PathBuf::from("/dev/foo")
                }),
                vq_pairs: None,
                mode: NetParametersMode::RawConfig {
                    host_ip: Ipv4Addr::from_str("192.168.10.1").unwrap(),
                    netmask: Ipv4Addr::from_str("255.255.255.0").unwrap(),
                    mac: MacAddress::from_str("3d:70:eb:61:1a:91").unwrap(),
                },
                packed_queue: false
            }
        );

        let params = from_net_arg("tap-fd=3,vhost-net").unwrap();
        assert_eq!(
            params,
            NetParameters {
                vhost_net: Some(Default::default()),
                vq_pairs: None,
                mode: NetParametersMode::TapFd {
                    tap_fd: 3,
                    mac: None
                },
                packed_queue: false
            }
        );

        let params = from_net_arg("vhost-net,tap-name=crosvm_tap").unwrap();
        assert_eq!(
            params,
            NetParameters {
                vhost_net: Some(Default::default()),
                vq_pairs: None,
                mode: NetParametersMode::TapName {
                    tap_name: "crosvm_tap".to_owned(),
                    mac: None
                },
                packed_queue: false
            }
        );

        let params =
            from_net_arg("vhost-net,mac=\"3d:70:eb:61:1a:91\",tap-name=crosvm_tap").unwrap();
        assert_eq!(
            params,
            NetParameters {
                vhost_net: Some(Default::default()),
                vq_pairs: None,
                mode: NetParametersMode::TapName {
                    tap_name: "crosvm_tap".to_owned(),
                    mac: Some(MacAddress::from_str("3d:70:eb:61:1a:91").unwrap())
                },
                packed_queue: false
            }
        );

        let params = from_net_arg("tap-name=tap,packed-queue=true").unwrap();
        assert_eq!(
            params,
            NetParameters {
                #[cfg(unix)]
                vhost_net: None,
                vq_pairs: None,
                mode: NetParametersMode::TapName {
                    tap_name: "tap".to_string(),
                    mac: None
                },
                packed_queue: true
            }
        );

        let params = from_net_arg("tap-name=tap,packed-queue").unwrap();
        assert_eq!(
            params,
            NetParameters {
                #[cfg(unix)]
                vhost_net: None,
                vq_pairs: None,
                mode: NetParametersMode::TapName {
                    tap_name: "tap".to_string(),
                    mac: None
                },
                packed_queue: true
            }
        );

        // mixed configs
        assert!(from_net_arg(
            "tap-name=tap,\
            vhost-net,\
            host-ip=\"192.168.10.1\",\
            netmask=\"255.255.255.0\",\
            mac=\"3d:70:eb:61:1a:91\"",
        )
        .is_err());
    }
}
