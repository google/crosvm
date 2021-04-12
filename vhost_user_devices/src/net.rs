// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::net::Ipv4Addr;
use std::rc::Rc;
use std::str::FromStr;

use base::{error, AsRawDescriptor, EventType, WaitContext};
use data_model::DataInit;
use devices::virtio;
use devices::virtio::net::{
    build_config, process_rx, process_tx, validate_and_configure_tap,
    virtio_features_to_tap_offload, NetError, Token,
};
use devices::ProtectionType;
use getopts::Options;
use net_util::{MacAddress, Tap, TapT};
use remain::sorted;
use thiserror::Error as ThisError;
use vhost_user_devices::{DeviceRequestHandler, HandlerPollToken, VhostUserBackend, Vring};
use virtio_sys::virtio_net;
use vm_memory::GuestMemory;
use vmm_vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};

#[sorted]
#[derive(ThisError, Debug)]
enum Error {
    #[error("invalid features are given: 0x{features:x}")]
    InvalidFeatures { features: u64 },
    #[error("invalid protocol features are given: 0x{features:x}")]
    InvalidProtocolFeatures { features: u64 },
    #[error("call event is not set for vring {index}")]
    NoCallEvent { index: usize },
    #[error("guest memory is not set for vring {index}")]
    NoGuestMemory { index: usize },
    #[error("kill event is not set for vring {index}")]
    NoKillEvent { index: usize },
    #[error("failed to process rx queue: {0}")]
    ProcessRx(NetError),
    #[error("failed to read kick event for vring {index}: {err}")]
    ReadKickEvent { index: usize, err: base::Error },
    #[error("failed to set tap offload to match acked features: {0}")]
    TapOffload(net_util::Error),
    #[error("unexpected token is given: {0:?}")]
    UnexpectedToken(Token),
    #[error("failed to modify wait context: {0}")]
    WaitCtxModify(base::Error),
}

struct NetBackend {
    tap: Tap,
    mem: Option<GuestMemory>,
    tap_polling_enabled: bool,
    avail_features: u64,
    acked_features: u64,
    acked_protocol_features: VhostUserProtocolFeatures,
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
            mem: None,
            avail_features,
            acked_features: 0,
            acked_protocol_features: VhostUserProtocolFeatures::empty(),
            tap_polling_enabled: false,
        }
    }

    fn max_vq_pairs() -> usize {
        Self::MAX_QUEUE_NUM / 2
    }
}

impl VhostUserBackend for NetBackend {
    // TODO(keiichiw): Support multiple queue pairs.
    const MAX_QUEUE_NUM: usize = 2; /* 1 rx and 1 tx */
    const MAX_VRING_NUM: usize = 256;

    type EventToken = Token;
    type Error = Error;

    fn index_to_event_type(queue_index: usize) -> Option<Self::EventToken> {
        match queue_index {
            0 => Some(Token::RxQueue),
            1 => Some(Token::TxQueue),
            _ => None,
        }
    }

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

    fn set_guest_mem(&mut self, mem: GuestMemory) {
        self.mem = Some(mem);
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

    fn backend_event(&self) -> Option<(&dyn AsRawDescriptor, EventType, Self::EventToken)> {
        Some((
            &self.tap as &dyn AsRawDescriptor,
            EventType::None,
            Token::RxTap,
        ))
    }

    fn handle_event(
        &mut self,
        wait_ctx: &Rc<WaitContext<HandlerPollToken<Self>>>,
        token: &Self::EventToken,
        vrings: &[Rc<RefCell<Vring>>],
    ) -> std::result::Result<(), Error> {
        match token {
            Token::RxTap => {
                let index = 0;
                let mut vring = vrings[index].borrow_mut();

                if !vring.enabled {
                    return Ok(());
                }

                let Vring {
                    ref mut queue,
                    ref call_evt,
                    ..
                } = *vring;

                let call_evt = call_evt
                    .as_ref()
                    .ok_or(Error::NoCallEvent { index })?
                    .as_ref();

                let guest_mem = self.mem.as_ref().ok_or(Error::NoGuestMemory { index })?;

                match process_rx(call_evt, queue, &guest_mem, &mut self.tap) {
                    Ok(()) => Ok(()),
                    Err(NetError::RxDescriptorsExhausted) => {
                        wait_ctx
                            .modify(
                                &self.tap,
                                EventType::None,
                                HandlerPollToken::BackendToken(Token::RxTap),
                            )
                            .map_err(Error::WaitCtxModify)?;
                        self.tap_polling_enabled = false;

                        Ok(())
                    }
                    Err(e) => Err(Error::ProcessRx(e)),
                }
            }
            Token::RxQueue => {
                let index = 0;
                let vring = vrings[index].borrow();
                if !vring.enabled {
                    return Ok(());
                }

                let kick_evt = vring
                    .kick_evt
                    .as_ref()
                    .ok_or(Error::NoKillEvent { index })?;
                kick_evt
                    .read()
                    .map_err(|err| Error::ReadKickEvent { index, err })?;

                if !self.tap_polling_enabled {
                    wait_ctx
                        .modify(
                            &self.tap,
                            EventType::Read,
                            HandlerPollToken::BackendToken(Token::RxTap),
                        )
                        .map_err(Error::WaitCtxModify)?;
                    self.tap_polling_enabled = true;
                }
                Ok(())
            }
            Token::TxQueue => {
                let index = 1;
                let mut vring = vrings[index].borrow_mut();

                if !vring.enabled {
                    return Ok(());
                }

                let Vring {
                    ref mut queue,
                    ref call_evt,
                    ref kick_evt,
                    ..
                } = *vring;

                let call_evt = call_evt
                    .as_ref()
                    .ok_or(Error::NoCallEvent { index })?
                    .as_ref();

                let kick_evt = kick_evt.as_ref().ok_or(Error::NoKillEvent { index })?;
                if let Err(e) = kick_evt.read() {
                    error!("error reading tx queue Event: {}", e);
                }

                let guest_mem = self.mem.as_ref().ok_or(Error::NoGuestMemory { index })?;

                process_tx(call_evt, queue, &guest_mem, &mut self.tap);
                Ok(())
            }
            token => Err(Error::UnexpectedToken(token.clone())),
        }
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let config_space = build_config(Self::max_vq_pairs() as u16);
        virtio::copy_config(data, 0, config_space.as_slice(), offset);
    }

    fn reset(&mut self) {}
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

    let net = NetBackend::new(tap_cfg.host_ip, tap_cfg.netmask, tap_cfg.mac);
    let handler = DeviceRequestHandler::new(net).expect("new handler");
    if let Err(e) = handler.start(socket) {
        error!("error occurred: {}", e);
    }
}
