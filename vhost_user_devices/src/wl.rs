// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context};
use base::{
    clone_descriptor, error,
    net::{UnixSeqpacket, UnixSeqpacketListener, UnlinkUnixSeqpacketListener},
    warn, Event, FromRawDescriptor, SafeDescriptor, Tube,
};
use cros_async::{AsyncWrapper, EventAsync, Executor, IoSourceExt};
use devices::virtio::{base_features, wl, Queue};
use devices::ProtectionType;
use futures::future::{AbortHandle, Abortable};
use getopts::Options;
use once_cell::sync::OnceCell;
use sync::Mutex;
use vhost_user_devices::{CallEvent, DeviceRequestHandler, VhostUserBackend};
use vm_memory::GuestMemory;
use vmm_vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};

static WL_EXECUTOR: OnceCell<Executor> = OnceCell::new();

async fn run_out_queue(
    mut queue: Queue,
    mem: GuestMemory,
    call_evt: Arc<Mutex<CallEvent>>,
    kick_evt: EventAsync,
    wlstate: Rc<RefCell<wl::WlState>>,
) {
    loop {
        if let Err(e) = kick_evt.next_val().await {
            error!("Failed to read kick event for out queue: {}", e);
            break;
        }

        wl::process_out_queue(&call_evt, &mut queue, &mem, &mut wlstate.borrow_mut());
    }
}

async fn run_in_queue(
    mut queue: Queue,
    mem: GuestMemory,
    call_evt: Arc<Mutex<CallEvent>>,
    kick_evt: EventAsync,
    wlstate: Rc<RefCell<wl::WlState>>,
    wlstate_ctx: Box<dyn IoSourceExt<AsyncWrapper<SafeDescriptor>>>,
) {
    loop {
        if let Err(e) = wlstate_ctx.wait_readable().await {
            error!(
                "Failed to wait for inner WaitContext to become readable: {}",
                e
            );
            break;
        }

        if let Err(wl::DescriptorsExhausted) =
            wl::process_in_queue(&call_evt, &mut queue, &mem, &mut wlstate.borrow_mut())
        {
            if let Err(e) = kick_evt.next_val().await {
                error!("Failed to read kick event for in queue: {}", e);
                break;
            }
        }
    }
}

struct WlBackend {
    wayland_paths: Option<BTreeMap<String, PathBuf>>,
    vm_socket: Option<Tube>,
    resource_bridge: Option<Tube>,
    use_transition_flags: bool,
    use_send_vfd_v2: bool,
    features: u64,
    acked_features: u64,
    wlstate: Option<Rc<RefCell<wl::WlState>>>,
    workers: [Option<AbortHandle>; Self::MAX_QUEUE_NUM],
}

impl WlBackend {
    fn new(
        wayland_paths: BTreeMap<String, PathBuf>,
        vm_socket: Tube,
        resource_bridge: Option<Tube>,
    ) -> WlBackend {
        let features = base_features(ProtectionType::Unprotected)
            | 1 << wl::VIRTIO_WL_F_TRANS_FLAGS
            | 1 << wl::VIRTIO_WL_F_SEND_FENCES
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        WlBackend {
            wayland_paths: Some(wayland_paths),
            vm_socket: Some(vm_socket),
            resource_bridge,
            use_transition_flags: false,
            use_send_vfd_v2: false,
            features,
            acked_features: 0,
            wlstate: None,
            workers: Default::default(),
        }
    }
}

impl VhostUserBackend for WlBackend {
    const MAX_QUEUE_NUM: usize = wl::QUEUE_SIZES.len();
    const MAX_VRING_LEN: u16 = wl::QUEUE_SIZE;

    type Error = anyhow::Error;

    fn features(&self) -> u64 {
        self.features
    }

    fn ack_features(&mut self, value: u64) -> anyhow::Result<()> {
        let unrequested_features = value & !self.features();
        if unrequested_features != 0 {
            bail!("invalid features are given: {:#x}", unrequested_features);
        }

        self.acked_features |= value;

        if value & (1 << wl::VIRTIO_WL_F_TRANS_FLAGS) != 0 {
            self.use_transition_flags = true;
        }
        if value & (1 << wl::VIRTIO_WL_F_SEND_FENCES) != 0 {
            self.use_send_vfd_v2 = true;
        }

        Ok(())
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::empty()
    }

    fn ack_protocol_features(&mut self, features: u64) -> anyhow::Result<()> {
        if features != 0 {
            Err(anyhow!("Unexpected protocol features: {:#x}", features))
        } else {
            Ok(())
        }
    }

    fn acked_protocol_features(&self) -> u64 {
        VhostUserProtocolFeatures::empty().bits()
    }

    fn read_config(&self, _offset: u64, _dst: &mut [u8]) {}

    fn start_queue(
        &mut self,
        idx: usize,
        mut queue: Queue,
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

        // Safe because the executor is initialized in main() below.
        let ex = WL_EXECUTOR.get().expect("Executor not initialized");

        let kick_evt =
            EventAsync::new(kick_evt.0, ex).context("failed to create EventAsync for kick_evt")?;

        // We use this de-structuring let binding to separate borrows so that the compiler doesn't
        // think we're borrowing all of `self` in the closure below.
        let WlBackend {
            ref mut wayland_paths,
            ref mut vm_socket,
            ref mut resource_bridge,
            ref use_transition_flags,
            ref use_send_vfd_v2,
            ..
        } = self;
        let wlstate = self
            .wlstate
            .get_or_insert_with(|| {
                Rc::new(RefCell::new(wl::WlState::new(
                    wayland_paths.take().expect("WlState already initialized"),
                    vm_socket.take().expect("WlState already initialized"),
                    *use_transition_flags,
                    *use_send_vfd_v2,
                    resource_bridge.take(),
                )))
            })
            .clone();
        let (handle, registration) = AbortHandle::new_pair();
        match idx {
            0 => {
                let wlstate_ctx = clone_descriptor(wlstate.borrow().wait_ctx())
                    .map(|fd| {
                        // Safe because we just created this fd.
                        AsyncWrapper::new(unsafe { SafeDescriptor::from_raw_descriptor(fd) })
                    })
                    .context("failed to clone inner WaitContext for WlState")
                    .and_then(|ctx| {
                        ex.async_from(ctx)
                            .context("failed to create async WaitContext")
                    })?;

                ex.spawn_local(Abortable::new(
                    run_in_queue(queue, mem, call_evt, kick_evt, wlstate, wlstate_ctx),
                    registration,
                ))
                .detach();
            }
            1 => {
                ex.spawn_local(Abortable::new(
                    run_out_queue(queue, mem, call_evt, kick_evt, wlstate),
                    registration,
                ))
                .detach();
            }
            _ => bail!("attempted to start unknown queue: {}", idx),
        }
        self.workers[idx] = Some(handle);
        Ok(())
    }

    fn stop_queue(&mut self, idx: usize) {
        if let Some(handle) = self.workers.get_mut(idx).and_then(Option::take) {
            handle.abort();
        }
    }
    fn reset(&mut self) {
        for handle in self.workers.iter_mut().filter_map(Option::take) {
            handle.abort();
        }
    }
}

fn parse_wayland_sock(value: String) -> anyhow::Result<(String, PathBuf)> {
    let mut components = value.split(',');
    let path = PathBuf::from(
        components
            .next()
            .ok_or_else(|| anyhow!("missing socket path"))?,
    );
    let mut name = "";
    for c in components {
        let mut kv = c.splitn(2, '=');
        let (kind, value) = match (kv.next(), kv.next()) {
            (Some(kind), Some(value)) => (kind, value),
            _ => bail!("option must be of the form `kind=value`: {}", c),
        };
        match kind {
            "name" => name = value,
            _ => bail!("unrecognized option: {}", kind),
        }
    }

    Ok((name.to_string(), path))
}

fn main() -> anyhow::Result<()> {
    let mut opts = Options::new();
    opts.optflag("h", "help", "print this help menu");
    opts.reqopt(
        "",
        "socket",
        "path to bind a listening vhost-user socket",
        "PATH",
    );
    opts.reqopt(
        "",
        "vm-socket",
        "path to a socket for wayland-specific messages",
        "PATH",
    );
    opts.optmulti(
        "",
        "wayland-sock",
        "Path to one or more Wayland sockets. The unnamed socket is used for displaying virtual \
         screens while the named ones are used for IPC",
        "PATH[,name=NAME]",
    );
    opts.optopt(
        "",
        "resource-bridge",
        "path to the GPU resource bridge",
        "PATH",
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

    // We can safely `unwrap()` this because it is a required option.
    let socket = matches.opt_str("socket").unwrap();
    let wayland_paths = matches
        .opt_strs("wayland-sock")
        .into_iter()
        .map(parse_wayland_sock)
        .collect::<anyhow::Result<BTreeMap<_, _>>>()?;
    if wayland_paths.is_empty() {
        bail!("at least one wayland socket must be provided");
    }

    let resource_bridge = matches
        .opt_str("resource-bridge")
        .map(|p| UnixSeqpacket::connect(p).map(Tube::new))
        .transpose()
        .context("failed to connect to resource bridge socket")?;

    let ex = Executor::new().context("failed to create executor")?;
    let _ = WL_EXECUTOR.set(ex.clone());

    // We can safely `unwrap()` this because it is a required option.
    let vm_listener = UnixSeqpacketListener::bind(matches.opt_str("vm-socket").unwrap())
        .map(UnlinkUnixSeqpacketListener)
        .context("failed to create listening socket")?;
    let vm_socket = vm_listener
        .accept()
        .map(Tube::new)
        .context("failed to accept vm socket connection")?;
    let handler =
        DeviceRequestHandler::new(WlBackend::new(wayland_paths, vm_socket, resource_bridge));

    if let Err(e) = ex.run_until(handler.run(socket, &ex)) {
        error!("error occurred: {}", e);
    }

    Ok(())
}
