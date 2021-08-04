// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;
use std::thread;

use anyhow::{anyhow, bail, Context};
use base::{error, validate_raw_descriptor, warn, Event, RawDescriptor};
use cros_async::{EventAsync, Executor, IoSourceExt};
use data_model::DataInit;
use devices::virtio;
use devices::virtio::net::{
    build_config, process_ctrl, process_rx, process_tx, validate_and_configure_tap,
    virtio_features_to_tap_offload, NetError,
};
use devices::ProtectionType;
use futures::future::{AbortHandle, Abortable};
use getopts::Options;
use net_util::{MacAddress, Tap, TapT};
use once_cell::sync::OnceCell;
use sync::Mutex;
use vhost_user_devices::{CallEvent, DeviceRequestHandler, VhostUserBackend};
use virtio_sys::virtio_net;
use vm_memory::GuestMemory;
use vmm_vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};

thread_local! {
    static NET_EXECUTOR: OnceCell<Executor> = OnceCell::new();
}

async fn run_tx_queue(
    mut queue: virtio::Queue,
    mem: GuestMemory,
    mut tap: Tap,
    call_evt: Arc<Mutex<CallEvent>>,
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
    call_evt: Arc<Mutex<CallEvent>>,
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

async fn run_ctrl_queue(
    mut queue: virtio::Queue,
    mem: GuestMemory,
    mut tap: Tap,
    call_evt: Arc<Mutex<CallEvent>>,
    kick_evt: EventAsync,
    acked_features: u64,
    vq_pairs: u16,
) {
    loop {
        if let Err(e) = kick_evt.next_val().await {
            error!("Failed to read kick event for tx queue: {}", e);
            break;
        }

        if let Err(e) = process_ctrl(
            &call_evt,
            &mut queue,
            &mem,
            &mut tap,
            acked_features,
            vq_pairs,
        ) {
            error!("Failed to process ctrl queue: {}", e);
            break;
        }
    }
}

struct TapConfig {
    host_ip: Ipv4Addr,
    netmask: Ipv4Addr,
    mac: MacAddress,
}

impl FromStr for TapConfig {
    type Err = anyhow::Error;

    fn from_str(arg: &str) -> Result<Self, Self::Err> {
        let args: Vec<&str> = arg.split(',').collect();
        if args.len() != 3 {
            bail!("TAP config must consist of 3 parts but {}", args.len());
        }

        let host_ip: Ipv4Addr = args[0]
            .parse()
            .map_err(|e| anyhow!("invalid IP address: {}", e))?;
        let netmask: Ipv4Addr = args[1]
            .parse()
            .map_err(|e| anyhow!("invalid net mask: {}", e))?;
        let mac: MacAddress = args[2]
            .parse()
            .map_err(|e| anyhow!("invalid MAC address: {}", e))?;

        Ok(Self {
            host_ip,
            netmask,
            mac,
        })
    }
}

struct NetBackend {
    tap: Tap,
    avail_features: u64,
    acked_features: u64,
    acked_protocol_features: VhostUserProtocolFeatures,
    workers: [Option<AbortHandle>; Self::MAX_QUEUE_NUM],
    mtu: u16,
}

impl NetBackend {
    pub fn new_from_config(config: &TapConfig) -> anyhow::Result<Self> {
        // Create a tap device.
        let tap = Tap::new(true /* vnet_hdr */, false /* multi_queue */)
            .context("failed to create tap device")?;
        tap.set_ip_addr(config.host_ip)
            .context("failed to set IP address")?;
        tap.set_netmask(config.netmask)
            .context("failed to set netmask")?;
        tap.set_mac_address(config.mac)
            .context("failed to set MAC address")?;

        Self::new(tap)
    }

    pub fn new_from_tap_fd(tap_fd: RawDescriptor) -> anyhow::Result<Self> {
        let tap_fd = validate_raw_descriptor(tap_fd).context("failed to validate tap fd")?;
        // Safe because we ensure that we get a unique handle to the fd.
        let tap =
            unsafe { Tap::from_raw_descriptor(tap_fd).context("failed to create tap device")? };

        Self::new(tap)
    }

    fn new(tap: Tap) -> anyhow::Result<Self> {
        let vq_pairs = Self::max_vq_pairs();
        tap.enable().context("failed to enable tap")?;
        validate_and_configure_tap(&tap, vq_pairs as u16)
            .context("failed to validate and configure tap")?;

        let avail_features = virtio::base_features(ProtectionType::Unprotected)
            | 1 << virtio_net::VIRTIO_NET_F_GUEST_CSUM
            | 1 << virtio_net::VIRTIO_NET_F_CSUM
            | 1 << virtio_net::VIRTIO_NET_F_CTRL_VQ
            | 1 << virtio_net::VIRTIO_NET_F_CTRL_GUEST_OFFLOADS
            | 1 << virtio_net::VIRTIO_NET_F_GUEST_TSO4
            | 1 << virtio_net::VIRTIO_NET_F_GUEST_UFO
            | 1 << virtio_net::VIRTIO_NET_F_HOST_TSO4
            | 1 << virtio_net::VIRTIO_NET_F_HOST_UFO
            | 1 << virtio_net::VIRTIO_NET_F_MTU
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();

        let mtu = tap.mtu()?;

        Ok(Self {
            tap,
            avail_features,
            acked_features: 0,
            acked_protocol_features: VhostUserProtocolFeatures::empty(),
            workers: Default::default(),
            mtu,
        })
    }

    fn max_vq_pairs() -> usize {
        Self::MAX_QUEUE_NUM / 2
    }
}

impl VhostUserBackend for NetBackend {
    const MAX_QUEUE_NUM: usize = 3; /* rx, tx, ctrl */
    const MAX_VRING_LEN: u16 = 256;

    type Error = anyhow::Error;

    fn features(&self) -> u64 {
        self.avail_features
    }

    fn ack_features(&mut self, value: u64) -> anyhow::Result<()> {
        let unrequested_features = value & !self.avail_features;
        if unrequested_features != 0 {
            bail!("invalid features are given: {:#x}", unrequested_features);
        }

        self.acked_features |= value;

        self.tap
            .set_offload(virtio_features_to_tap_offload(self.acked_features))
            .context("failed to set tap offload to match features")?;

        Ok(())
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::CONFIG
    }

    fn ack_protocol_features(&mut self, features: u64) -> anyhow::Result<()> {
        let features = VhostUserProtocolFeatures::from_bits(features)
            .ok_or_else(|| anyhow!("invalid protocol features are given: {:#x}", features))?;
        let supported = self.protocol_features();
        self.acked_protocol_features = features & supported;
        Ok(())
    }

    fn acked_protocol_features(&self) -> u64 {
        self.acked_protocol_features.bits()
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let config_space = build_config(Self::max_vq_pairs() as u16, self.mtu);
        virtio::copy_config(data, 0, config_space.as_slice(), offset);
    }

    fn reset(&mut self) {}

    fn start_queue(
        &mut self,
        idx: usize,
        mut queue: virtio::Queue,
        mem: GuestMemory,
        call_evt: Arc<Mutex<CallEvent>>,
        kick_evt: Event,
    ) -> anyhow::Result<()> {
        if let Some(handle) = self.workers.get_mut(idx).and_then(Option::take) {
            warn!("Starting new queue handler without stopping old handler");
            handle.abort();
        }

        // Enable any virtqueue features that were negotiated (like VIRTIO_RING_F_EVENT_IDX).
        queue.ack_features(self.acked_features);

        NET_EXECUTOR.with(|ex| {
            // Safe because the executor is initialized in main() below.
            let ex = ex.get().expect("Executor not initialized");

            let kick_evt = EventAsync::new(kick_evt.0, ex)
                .context("failed to create EventAsync for kick_evt")?;
            let tap = self.tap.try_clone().context("failed to clone tap device")?;
            let (handle, registration) = AbortHandle::new_pair();
            match idx {
                0 => {
                    let tap = ex
                        .async_from(tap)
                        .context("failed to create async tap device")?;

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
                2 => {
                    ex.spawn_local(Abortable::new(
                        run_ctrl_queue(
                            queue,
                            mem,
                            tap,
                            call_evt,
                            kick_evt,
                            self.acked_features,
                            1, /* vq_pairs */
                        ),
                        registration,
                    ))
                    .detach();
                }
                _ => bail!("attempted to start unknown queue: {}", idx),
            }

            self.workers[idx] = Some(handle);
            Ok(())
        })
    }

    fn stop_queue(&mut self, idx: usize) {
        if let Some(handle) = self.workers.get_mut(idx).and_then(Option::take) {
            handle.abort();
        }
    }
}

fn main() -> anyhow::Result<()> {
    let mut opts = Options::new();
    opts.optflag("h", "help", "print this help menu");
    opts.optmulti(
        "",
        "device",
        "TAP device config. (e.g. \"/path/to/sock,10.0.2.2,255.255.255.0,12:34:56:78:9a:bc\")",
        "SOCKET_PATH,IP_ADDR,NET_MASK,MAC_ADDR",
    );
    opts.optmulti(
        "",
        "tap-fd",
        "TAP FD with a socket path",
        "SOCKET_PATH,TAP_FD",
    );

    let mut args = std::env::args();
    let program_name = args.next().expect("args is empty");
    let matches = match opts.parse(args) {
        Ok(m) => m,
        Err(e) => {
            println!("{}", e);
            println!("{}", opts.short_usage(&program_name));
            return Ok(());
        }
    };

    if matches.opt_present("h") {
        println!("{}", opts.usage(&program_name));
        return Ok(());
    }

    base::syslog::init().context("failed to initialize syslog")?;

    let device_args = matches.opt_strs("device");
    let tap_fd_args = matches.opt_strs("tap-fd");
    let num_devices = device_args.len() + tap_fd_args.len();
    if num_devices == 0 {
        bail!("no device option was passed");
    }

    let mut devices: Vec<(String, NetBackend)> = Vec::with_capacity(num_devices);

    for arg in device_args {
        let pos = match arg.find(',') {
            Some(p) => p,
            None => {
                bail!("device must take comma-separated argument");
            }
        };
        let socket = &arg[0..pos];
        let cfg = &arg[pos + 1..]
            .parse::<TapConfig>()
            .context("failed to parse tap config")?;
        let backend = NetBackend::new_from_config(&cfg).context("failed to create NetBackend")?;
        devices.push((socket.to_string(), backend));
    }

    for arg in tap_fd_args {
        let pos = match arg.find(',') {
            Some(p) => p,
            None => {
                bail!("'tap-fd' flag must take comma-separated argument");
            }
        };
        let socket = &arg[0..pos];
        let tap_fd = &arg[pos + 1..]
            .parse::<i32>()
            .context("failed to parse tap-fd")?;
        let backend =
            NetBackend::new_from_tap_fd(*tap_fd).context("failed to create NetBackend")?;
        devices.push((socket.to_string(), backend));
    }

    let mut threads = Vec::with_capacity(num_devices);
    for (socket, backend) in devices {
        let handler = DeviceRequestHandler::new(backend);
        let ex = Executor::new().context("failed to create executor")?;

        threads.push(thread::spawn(move || {
            NET_EXECUTOR.with(|thread_ex| {
                let _ = thread_ex.set(ex.clone());
            });
            if let Err(e) = ex.run_until(handler.run(&socket, &ex)) {
                error!("error occurred: {}", e);
            }
        }));
    }

    threads
        .into_iter()
        .try_for_each(thread::JoinHandle::join)
        .map_err(|e| anyhow!("failed to join threads: {:?}", e))
}
