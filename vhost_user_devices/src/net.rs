// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::net::Ipv4Addr;
use std::str::FromStr;

use base::{error, warn, Event};
use cros_async::{AsyncError, EventAsync, Executor, IoSourceExt};
use data_model::DataInit;
use devices::virtio;
use devices::virtio::net::{
    build_config, process_rx, process_tx, validate_and_configure_tap,
    virtio_features_to_tap_offload, NetError,
};
use devices::ProtectionType;
use futures::future::{AbortHandle, Abortable};
use getopts::Options;
use net_util::{Error as NetUtilError, MacAddress, Tap, TapT};
use once_cell::sync::OnceCell;
use remain::sorted;
use thiserror::Error as ThisError;
use vhost_user_devices::{CallEvent, DeviceRequestHandler, VhostUserBackend};
use virtio_sys::virtio_net;
use vm_memory::GuestMemory;
use vmm_vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};

static NET_EXECUTOR: OnceCell<Executor> = OnceCell::new();

#[sorted]
#[derive(ThisError, Debug)]
enum Error {
    #[error("failed to clone tap device: {0}")]
    CloneTap(NetUtilError),
    #[error("failed to create async tap device: {0}")]
    CreateAsyncTap(AsyncError),
    #[error("failed to create EventAsync: {0}")]
    CreateEventAsync(AsyncError),
    #[error("invalid features are given: 0x{features:x}")]
    InvalidFeatures { features: u64 },
    #[error("invalid protocol features are given: 0x{features:x}")]
    InvalidProtocolFeatures { features: u64 },
    #[error("guest memory is not set for queue {idx}")]
    NoGuestMemory { idx: usize },
    #[error("failed to set tap offload to match acked features: {0}")]
    TapOffload(net_util::Error),
    #[error("attempted to start unknown queue: {0}")]
    UnknownQueue(usize),
}

async fn run_tx_queue(
    mut queue: virtio::Queue,
    mem: GuestMemory,
    mut tap: Tap,
    call_evt: CallEvent,
    kick_evt: EventAsync,
) {
    loop {
        if let Err(e) = kick_evt.next_val().await {
            error!("Failed to read kick event for tx queue: {}", e);
            break;
        }

        process_tx(&call_evt, &mut queue, &mem, &mut tap);
    }
}

async fn run_rx_queue(
    mut queue: virtio::Queue,
    mem: GuestMemory,
    mut tap: Box<dyn IoSourceExt<Tap>>,
    call_evt: CallEvent,
    kick_evt: EventAsync,
) {
    loop {
        if let Err(e) = tap.wait_readable().await {
            error!("Failed to wait for tap device to become readable: {}", e);
            break;
        }

        match process_rx(&call_evt, &mut queue, &mem, tap.as_source_mut()) {
            Ok(()) => {}
            Err(NetError::RxDescriptorsExhausted) => {
                if let Err(e) = kick_evt.next_val().await {
                    error!("Failed to read kick event for rx queue: {}", e);
                    break;
                }
            }
            Err(e) => {
                error!("Failed to process rx queue: {}", e);
                break;
            }
        }
    }
}

struct NetBackend {
    tap: Tap,
    avail_features: u64,
    acked_features: u64,
    acked_protocol_features: VhostUserProtocolFeatures,
    workers: [Option<AbortHandle>; Self::MAX_QUEUE_NUM],
}

impl NetBackend {
    pub fn new(host_ip: Ipv4Addr, netmask: Ipv4Addr, mac_address: MacAddress) -> Self {
        // TODO(keiichiw): Support CTRL_VQ and MQ.
        // Note that MQ cannot be enabled without CTRL_VQ.
        let avail_features = virtio::base_features(ProtectionType::Unprotected)
            | 1 << virtio_net::VIRTIO_NET_F_GUEST_CSUM
            | 1 << virtio_net::VIRTIO_NET_F_CSUM
            | 1 << virtio_net::VIRTIO_NET_F_CTRL_GUEST_OFFLOADS
            | 1 << virtio_net::VIRTIO_NET_F_GUEST_TSO4
            | 1 << virtio_net::VIRTIO_NET_F_GUEST_UFO
            | 1 << virtio_net::VIRTIO_NET_F_HOST_TSO4
            | 1 << virtio_net::VIRTIO_NET_F_HOST_UFO
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();

        let vq_pairs = Self::max_vq_pairs();

        // Create a tap device.
        let tap = Tap::new(true /* vnet_hdr */, true /* multi_queue */).expect("tap");
        tap.set_ip_addr(host_ip).expect("set IP address");
        tap.set_netmask(netmask).expect("set netmask");
        tap.set_mac_address(mac_address).expect("set MAC address");
        tap.enable().expect("enable tap");
        validate_and_configure_tap(&tap, vq_pairs as u16).expect("validate_and_configure_tap");

        Self {
            tap,
            avail_features,
            acked_features: 0,
            acked_protocol_features: VhostUserProtocolFeatures::empty(),
            workers: Default::default(),
        }
    }

    fn max_vq_pairs() -> usize {
        Self::MAX_QUEUE_NUM / 2
    }
}

impl VhostUserBackend for NetBackend {
    // TODO(keiichiw): Support multiple queue pairs.
    const MAX_QUEUE_NUM: usize = 2; /* 1 rx and 1 tx */
    const MAX_VRING_LEN: u16 = 256;

    type Error = Error;

    fn features(&self) -> u64 {
        self.avail_features
    }

    fn ack_features(&mut self, value: u64) -> std::result::Result<(), Error> {
        let unrequested_features = value & !self.avail_features;
        if unrequested_features != 0 {
            return Err(Error::InvalidFeatures {
                features: unrequested_features,
            });
        }

        self.acked_features |= value;

        self.tap
            .set_offload(virtio_features_to_tap_offload(self.acked_features))
            .map_err(Error::TapOffload)?;

        Ok(())
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        // TODO(keiichiw): Support MQ.
        VhostUserProtocolFeatures::CONFIG
    }

    fn ack_protocol_features(&mut self, features: u64) -> std::result::Result<(), Error> {
        let features = VhostUserProtocolFeatures::from_bits(features)
            .ok_or(Error::InvalidProtocolFeatures { features })?;
        let supported = self.protocol_features();
        self.acked_protocol_features = features & supported;
        Ok(())
    }

    fn acked_protocol_features(&self) -> u64 {
        self.acked_protocol_features.bits()
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let config_space = build_config(Self::max_vq_pairs() as u16);
        virtio::copy_config(data, 0, config_space.as_slice(), offset);
    }

    fn reset(&mut self) {}

    fn start_queue(
        &mut self,
        idx: usize,
        queue: virtio::Queue,
        mem: GuestMemory,
        call_evt: CallEvent,
        kick_evt: Event,
    ) -> std::result::Result<(), Self::Error> {
        if let Some(handle) = self.workers.get_mut(idx).and_then(Option::take) {
            warn!("Starting new queue handler without stopping old handler");
            handle.abort();
        }

        // Safe because the executor is initialized in main() below.
        let ex = NET_EXECUTOR.get().expect("Executor not initialized");

        let kick_evt = EventAsync::new(kick_evt.0, ex).map_err(Error::CreateEventAsync)?;
        let tap = self.tap.try_clone().map_err(Error::CloneTap)?;
        let (handle, registration) = AbortHandle::new_pair();
        match idx {
            0 => {
                let tap = ex.async_from(tap).map_err(Error::CreateAsyncTap)?;

                ex.spawn_local(Abortable::new(
                    run_rx_queue(queue, mem, tap, call_evt, kick_evt),
                    registration,
                ))
                .detach();
            }
            1 => {
                ex.spawn_local(Abortable::new(
                    run_tx_queue(queue, mem, tap, call_evt, kick_evt),
                    registration,
                ))
                .detach();
            }
            _ => return Err(Error::UnknownQueue(idx)),
        }

        self.workers[idx] = Some(handle);
        Ok(())
    }

    fn stop_queue(&mut self, idx: usize) {
        if let Some(handle) = self.workers.get_mut(idx).and_then(Option::take) {
            handle.abort();
        }
    }
}

struct TapConfig {
    host_ip: Ipv4Addr,
    netmask: Ipv4Addr,
    mac: MacAddress,
}

impl FromStr for TapConfig {
    type Err = String;

    fn from_str(arg: &str) -> Result<Self, Self::Err> {
        let args: Vec<&str> = arg.split(',').collect();
        if args.len() != 3 {
            return Err(format!(
                "TAP config must consist of 3 parts but {}",
                args.len()
            ));
        }
        let host_ip: Ipv4Addr = args[0]
            .parse()
            .map_err(|e| format!("invalid IP address: {}", e))?;
        let netmask: Ipv4Addr = args[1]
            .parse()
            .map_err(|e| format!("invalid net mask: {}", e))?;
        let mac: MacAddress = args[2]
            .parse()
            .map_err(|e| format!("invalid MAC address: {}", e))?;

        Ok(Self {
            host_ip,
            netmask,
            mac,
        })
    }
}

fn main() {
    if let Err(e) = base::syslog::init() {
        eprintln!("failed to initialize syslog: {}", e);
        return;
    }

    let args: Vec<String> = std::env::args().collect();
    let mut opts = Options::new();
    opts.optflag("h", "help", "print this help menu");
    opts.reqopt("", "socket", "path to a socket", "PATH");
    // TODO(keiichiw): Support tap-fd option.
    // TODO(keiichiw): Support multiple TAP devices.
    opts.reqopt(
        "",
        "tap",
        "TAP device config. (e.g. \"10.0.2.2,255.255.255.0,12:34:56:78:9a:bc\")",
        "IP_ADDR,NET_MASK,MAC_ADDR",
    );

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{}", e);
            eprintln!("{}", opts.short_usage(&args[0]));
            return;
        }
    };

    if matches.opt_present("h") {
        eprintln!("{}", opts.usage(&args[0]));
        return;
    }

    // We can unwrap after `opt_str()` safely because they are required options.
    let socket = matches.opt_str("socket").unwrap();
    let tap_cfg: TapConfig = match matches.opt_str("tap").unwrap().parse() {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("invalid TAP config: {}", e);
            return;
        }
    };

    let ex = Executor::new().expect("Failed to create executor");
    let _ = NET_EXECUTOR.set(ex.clone());

    let net = NetBackend::new(tap_cfg.host_ip, tap_cfg.netmask, tap_cfg.mac);
    let handler = DeviceRequestHandler::new(net);

    if let Err(e) = ex.run_until(handler.run(socket, &ex)) {
        error!("error occurred: {}", e);
    }
}
