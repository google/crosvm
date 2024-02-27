// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::net::Ipv4Addr;
use std::str::FromStr;
use std::thread;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use argh::FromArgs;
use base::error;
use base::info;
use base::validate_raw_descriptor;
use base::warn;
use base::RawDescriptor;
use cros_async::EventAsync;
use cros_async::Executor;
use cros_async::IntoAsync;
use cros_async::IoSource;
use futures::channel::oneshot;
use futures::select_biased;
use futures::FutureExt;
use hypervisor::ProtectionType;
use net_util::sys::linux::Tap;
use net_util::MacAddress;
use net_util::TapT;
use virtio_sys::virtio_net;
use vm_memory::GuestMemory;
use vmm_vhost::message::VhostUserProtocolFeatures;
use vmm_vhost::VHOST_USER_F_PROTOCOL_FEATURES;

use crate::virtio;
use crate::virtio::net::process_rx;
use crate::virtio::net::validate_and_configure_tap;
use crate::virtio::net::NetError;
use crate::virtio::vhost::user::device::handler::VhostUserDevice;
use crate::virtio::vhost::user::device::listener::sys::VhostUserListener;
use crate::virtio::vhost::user::device::listener::VhostUserListenerTrait;
use crate::virtio::vhost::user::device::net::run_ctrl_queue;
use crate::virtio::vhost::user::device::net::run_tx_queue;
use crate::virtio::vhost::user::device::net::NetBackend;
use crate::virtio::vhost::user::device::net::NET_EXECUTOR;
use crate::virtio::Interrupt;
use crate::virtio::Queue;

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

impl<T: 'static> NetBackend<T>
where
    T: TapT + IntoAsync,
{
    fn new_from_config(config: &TapConfig) -> anyhow::Result<Self> {
        // Create a tap device.
        let tap = T::new(true /* vnet_hdr */, false /* multi_queue */)
            .context("failed to create tap device")?;
        tap.set_ip_addr(config.host_ip)
            .context("failed to set IP address")?;
        tap.set_netmask(config.netmask)
            .context("failed to set netmask")?;
        tap.set_mac_address(config.mac)
            .context("failed to set MAC address")?;

        Self::new(tap)
    }

    fn new_from_name(name: &str) -> anyhow::Result<Self> {
        let tap = T::new_with_name(name.as_bytes(), true, false).map_err(NetError::TapOpen)?;
        Self::new(tap)
    }

    pub fn new_from_tap_fd(tap_fd: RawDescriptor) -> anyhow::Result<Self> {
        let tap_fd = validate_raw_descriptor(tap_fd).context("failed to validate tap fd")?;
        // SAFETY:
        // Safe because we ensure that we get a unique handle to the fd.
        let tap = unsafe { T::from_raw_descriptor(tap_fd).context("failed to create tap device")? };

        Self::new(tap)
    }

    pub fn new(tap: T) -> anyhow::Result<Self> {
        let vq_pairs = Self::max_vq_pairs();
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
            | 1 << VHOST_USER_F_PROTOCOL_FEATURES;

        let mtu = tap.mtu()?;

        Ok(Self {
            tap,
            avail_features,
            acked_features: 0,
            acked_protocol_features: VhostUserProtocolFeatures::empty(),
            mtu,
            workers: Default::default(),
        })
    }
}

async fn run_rx_queue<T: TapT>(
    mut queue: Queue,
    mut tap: IoSource<T>,
    doorbell: Interrupt,
    kick_evt: EventAsync,
    mut stop_rx: oneshot::Receiver<()>,
) -> Queue {
    loop {
        select_biased! {
            // `tap.wait_readable()` requires an immutable reference to `tap`, but `process_rx`
            // requires a mutable reference to `tap`, so this future needs to be recreated on
            // every iteration. If more arms are added that doesn't break out of the loop, then
            // this future could be recreated too many times.
            rx = tap.wait_readable().fuse() => {
                if let Err(e) = rx {
                    error!("Failed to wait for tap device to become readable: {}", e);
                    break;
                }
            }
            _ = stop_rx => {
                break;
            }
        }

        match process_rx(&doorbell, &mut queue, tap.as_source_mut()) {
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
    queue
}

/// Platform specific impl of VhostUserDevice::start_queue.
pub(in crate::virtio::vhost::user::device::net) fn start_queue<T: 'static + IntoAsync + TapT>(
    backend: &mut NetBackend<T>,
    idx: usize,
    queue: virtio::Queue,
    _mem: GuestMemory,
    doorbell: Interrupt,
) -> anyhow::Result<()> {
    if backend.workers[idx].is_some() {
        warn!("Starting new queue handler without stopping old handler");
        backend.stop_queue(idx)?;
    }

    NET_EXECUTOR.with(|ex| {
        // Safe because the executor is initialized in main() below.
        let ex = ex.get().expect("Executor not initialized");

        let kick_evt = queue
            .event()
            .try_clone()
            .context("failed to clone queue event")?;
        let kick_evt =
            EventAsync::new(kick_evt, ex).context("failed to create EventAsync for kick_evt")?;
        let tap = backend
            .tap
            .try_clone()
            .context("failed to clone tap device")?;
        let worker_tuple = match idx {
            0 => {
                let tap = ex
                    .async_from(tap)
                    .context("failed to create async tap device")?;

                let (stop_tx, stop_rx) = futures::channel::oneshot::channel();
                (
                    ex.spawn_local(run_rx_queue(queue, tap, doorbell, kick_evt, stop_rx)),
                    stop_tx,
                )
            }
            1 => {
                let (stop_tx, stop_rx) = futures::channel::oneshot::channel();
                (
                    ex.spawn_local(run_tx_queue(queue, tap, doorbell, kick_evt, stop_rx)),
                    stop_tx,
                )
            }
            2 => {
                let (stop_tx, stop_rx) = futures::channel::oneshot::channel();
                (
                    ex.spawn_local(run_ctrl_queue(
                        queue,
                        tap,
                        doorbell,
                        kick_evt,
                        backend.acked_features,
                        1, /* vq_pairs */
                        stop_rx,
                    )),
                    stop_tx,
                )
            }
            _ => bail!("attempted to start unknown queue: {}", idx),
        };

        backend.workers[idx] = Some(worker_tuple);
        Ok(())
    })
}

#[derive(FromArgs)]
#[argh(subcommand, name = "net")]
/// Net device
pub struct Options {
    #[argh(option, arg_name = "SOCKET_PATH,IP_ADDR,NET_MASK,MAC_ADDR")]
    /// TAP device config. (e.g. "path/to/sock,10.0.2.2,255.255.255.0,12:34:56:78:9a:bc")
    device: Vec<String>,
    #[argh(option, arg_name = "SOCKET_PATH,TAP_FD")]
    /// TAP FD with a socket path"
    tap_fd: Vec<String>,
    #[argh(option, arg_name = "SOCKET_PATH,TAP_NAME")]
    /// TAP NAME with a socket path
    tap_name: Vec<String>,
}

enum Connection {
    Socket(String),
}

fn new_backend_from_device_arg(arg: &str) -> anyhow::Result<(String, NetBackend<Tap>)> {
    let pos = match arg.find(',') {
        Some(p) => p,
        None => {
            bail!("device must take comma-separated argument");
        }
    };
    let conn = &arg[0..pos];
    let cfg = &arg[pos + 1..]
        .parse::<TapConfig>()
        .context("failed to parse tap config")?;
    let backend = NetBackend::<Tap>::new_from_config(cfg).context("failed to create NetBackend")?;
    Ok((conn.to_string(), backend))
}

fn new_backend_from_tap_name(arg: &str) -> anyhow::Result<(String, NetBackend<Tap>)> {
    let pos = match arg.find(',') {
        Some(p) => p,
        None => {
            bail!("device must take comma-separated argument");
        }
    };
    let conn = &arg[0..pos];
    let tap_name = &arg[pos + 1..];

    let backend =
        NetBackend::<Tap>::new_from_name(tap_name).context("failed to create NetBackend")?;
    Ok((conn.to_string(), backend))
}

fn new_backend_from_tapfd_arg(arg: &str) -> anyhow::Result<(String, NetBackend<Tap>)> {
    let pos = match arg.find(',') {
        Some(p) => p,
        None => {
            bail!("'tap-fd' flag must take comma-separated argument");
        }
    };
    let conn = &arg[0..pos];
    let tap_fd = &arg[pos + 1..]
        .parse::<i32>()
        .context("failed to parse tap-fd")?;
    let backend =
        NetBackend::<Tap>::new_from_tap_fd(*tap_fd).context("failed to create NetBackend")?;

    Ok((conn.to_string(), backend))
}

/// Starts a vhost-user net device.
/// Returns an error if the given `args` is invalid or the device fails to run.
pub fn start_device(opts: Options) -> anyhow::Result<()> {
    let num_devices = opts.device.len() + opts.tap_fd.len() + opts.tap_name.len();

    if num_devices == 0 {
        bail!("no device option was passed");
    }

    let mut devices: Vec<(Connection, NetBackend<Tap>)> = Vec::with_capacity(num_devices);

    // vhost-user
    for arg in opts.device.iter() {
        devices.push(
            new_backend_from_device_arg(arg)
                .map(|(s, backend)| (Connection::Socket(s), backend))?,
        );
    }

    for arg in opts.tap_name.iter() {
        devices.push(
            new_backend_from_tap_name(arg).map(|(s, backend)| (Connection::Socket(s), backend))?,
        );
    }
    for arg in opts.tap_fd.iter() {
        devices.push(
            new_backend_from_tapfd_arg(arg).map(|(s, backend)| (Connection::Socket(s), backend))?,
        );
    }

    let mut threads = Vec::with_capacity(num_devices);

    for (conn, backend) in devices {
        let ex = Executor::new().context("failed to create executor")?;

        match conn {
            Connection::Socket(socket) => {
                threads.push(thread::spawn(move || {
                    NET_EXECUTOR.with(|thread_ex| {
                        let _ = thread_ex.set(ex.clone());
                    });
                    let listener = VhostUserListener::new_socket(&socket, None)?;
                    // run_until() returns an Result<Result<..>> which the ? operator lets us
                    // flatten.
                    ex.run_until(listener.run_backend(backend, &ex))?
                }));
            }
        };
    }

    info!("vhost-user net device ready, loop threads started.");
    for t in threads {
        match t.join() {
            Ok(r) => r?,
            Err(e) => bail!("thread panicked: {:?}", e),
        }
    }
    Ok(())
}
