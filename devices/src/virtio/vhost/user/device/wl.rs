// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::rc::Rc;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use argh::FromArgs;
use base::clone_descriptor;
use base::error;
use base::warn;
use base::Event;
use base::FromRawDescriptor;
use base::SafeDescriptor;
use base::Tube;
use base::UnixSeqpacket;
use cros_async::AsyncWrapper;
use cros_async::EventAsync;
use cros_async::Executor;
use cros_async::IoSourceExt;
use futures::future::AbortHandle;
use futures::future::Abortable;
use hypervisor::ProtectionType;
#[cfg(feature = "minigbm")]
use rutabaga_gfx::RutabagaGralloc;
use vm_memory::GuestMemory;
use vmm_vhost::message::VhostUserProtocolFeatures;
use vmm_vhost::message::VhostUserVirtioFeatures;

use crate::virtio::base_features;
use crate::virtio::vhost::user::device::handler::sys::Doorbell;
use crate::virtio::vhost::user::device::handler::VhostBackendReqConnection;
use crate::virtio::vhost::user::device::handler::VhostBackendReqConnectionState;
use crate::virtio::vhost::user::device::handler::VhostUserBackend;
use crate::virtio::vhost::user::device::listener::sys::VhostUserListener;
use crate::virtio::vhost::user::device::listener::VhostUserListenerTrait;
use crate::virtio::wl;
use crate::virtio::Queue;
use crate::virtio::SharedMemoryRegion;

const MAX_QUEUE_NUM: usize = wl::QUEUE_SIZES.len();
const MAX_VRING_LEN: u16 = wl::QUEUE_SIZE;

async fn run_out_queue(
    mut queue: Queue,
    mem: GuestMemory,
    doorbell: Doorbell,
    kick_evt: EventAsync,
    wlstate: Rc<RefCell<wl::WlState>>,
) {
    loop {
        if let Err(e) = kick_evt.next_val().await {
            error!("Failed to read kick event for out queue: {}", e);
            break;
        }

        wl::process_out_queue(&doorbell, &mut queue, &mem, &mut wlstate.borrow_mut());
    }
}

async fn run_in_queue(
    mut queue: Queue,
    mem: GuestMemory,
    doorbell: Doorbell,
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

        if wl::process_in_queue(&doorbell, &mut queue, &mem, &mut wlstate.borrow_mut())
            == Err(wl::DescriptorsExhausted)
        {
            if let Err(e) = kick_evt.next_val().await {
                error!("Failed to read kick event for in queue: {}", e);
                break;
            }
        }
    }
}

struct WlBackend {
    ex: Executor,
    wayland_paths: Option<BTreeMap<String, PathBuf>>,
    resource_bridge: Option<Tube>,
    use_transition_flags: bool,
    use_send_vfd_v2: bool,
    use_shmem: bool,
    features: u64,
    acked_features: u64,
    wlstate: Option<Rc<RefCell<wl::WlState>>>,
    workers: [Option<AbortHandle>; MAX_QUEUE_NUM],
    backend_req_conn: VhostBackendReqConnectionState,
}

impl WlBackend {
    fn new(
        ex: &Executor,
        wayland_paths: BTreeMap<String, PathBuf>,
        resource_bridge: Option<Tube>,
    ) -> WlBackend {
        let features = base_features(ProtectionType::Unprotected)
            | 1 << wl::VIRTIO_WL_F_TRANS_FLAGS
            | 1 << wl::VIRTIO_WL_F_SEND_FENCES
            | 1 << wl::VIRTIO_WL_F_USE_SHMEM
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        WlBackend {
            ex: ex.clone(),
            wayland_paths: Some(wayland_paths),
            resource_bridge,
            use_transition_flags: false,
            use_send_vfd_v2: false,
            use_shmem: false,
            features,
            acked_features: 0,
            wlstate: None,
            workers: Default::default(),
            backend_req_conn: VhostBackendReqConnectionState::NoConnection,
        }
    }
}

impl VhostUserBackend for WlBackend {
    fn max_queue_num(&self) -> usize {
        return MAX_QUEUE_NUM;
    }

    fn max_vring_len(&self) -> u16 {
        return MAX_VRING_LEN;
    }

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
        if value & (1 << wl::VIRTIO_WL_F_USE_SHMEM) != 0 {
            self.use_shmem = true;
        }

        Ok(())
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::SLAVE_REQ
    }

    fn ack_protocol_features(&mut self, features: u64) -> anyhow::Result<()> {
        if features != VhostUserProtocolFeatures::SLAVE_REQ.bits() {
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
        doorbell: Doorbell,
        kick_evt: Event,
    ) -> anyhow::Result<()> {
        if let Some(handle) = self.workers.get_mut(idx).and_then(Option::take) {
            warn!("Starting new queue handler without stopping old handler");
            handle.abort();
        }

        // Enable any virtqueue features that were negotiated (like VIRTIO_RING_F_EVENT_IDX).
        queue.ack_features(self.acked_features);

        let kick_evt = EventAsync::new(kick_evt, &self.ex)
            .context("failed to create EventAsync for kick_evt")?;

        if !self.use_shmem {
            bail!("Incompatible driver: vhost-user-wl requires shmem support");
        }

        // We use this de-structuring let binding to separate borrows so that the compiler doesn't
        // think we're borrowing all of `self` in the closure below.
        let WlBackend {
            ref mut wayland_paths,
            ref mut resource_bridge,
            ref use_transition_flags,
            ref use_send_vfd_v2,
            ..
        } = self;

        let mapper = {
            match &mut self.backend_req_conn {
                VhostBackendReqConnectionState::Connected(request) => {
                    request.take_shmem_mapper()?
                }
                VhostBackendReqConnectionState::NoConnection => {
                    bail!("No backend request connection found")
                }
            }
        };
        #[cfg(feature = "minigbm")]
        let gralloc = RutabagaGralloc::new().context("Failed to initailize gralloc")?;
        let wlstate = self
            .wlstate
            .get_or_insert_with(|| {
                Rc::new(RefCell::new(wl::WlState::new(
                    wayland_paths.take().expect("WlState already initialized"),
                    mapper,
                    *use_transition_flags,
                    *use_send_vfd_v2,
                    resource_bridge.take(),
                    #[cfg(feature = "minigbm")]
                    gralloc,
                    None, /* address_offset */
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
                        self.ex
                            .async_from(ctx)
                            .context("failed to create async WaitContext")
                    })?;

                self.ex
                    .spawn_local(Abortable::new(
                        run_in_queue(queue, mem, doorbell, kick_evt, wlstate, wlstate_ctx),
                        registration,
                    ))
                    .detach();
            }
            1 => {
                self.ex
                    .spawn_local(Abortable::new(
                        run_out_queue(queue, mem, doorbell, kick_evt, wlstate),
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

    fn get_shared_memory_region(&self) -> Option<SharedMemoryRegion> {
        Some(SharedMemoryRegion {
            id: wl::WL_SHMEM_ID,
            length: wl::WL_SHMEM_SIZE,
        })
    }

    fn set_backend_req_connection(&mut self, conn: VhostBackendReqConnection) {
        if let VhostBackendReqConnectionState::Connected(_) = &self.backend_req_conn {
            warn!("connection already established. Overwriting");
        }

        self.backend_req_conn = VhostBackendReqConnectionState::Connected(conn);
    }
}

pub fn parse_wayland_sock(value: &str) -> Result<(String, PathBuf), String> {
    let mut components = value.split(',');
    let path = PathBuf::from(match components.next() {
        None => return Err("missing socket path".to_string()),
        Some(c) => c,
    });
    let mut name = "";
    for c in components {
        let mut kv = c.splitn(2, '=');
        let (kind, value) = match (kv.next(), kv.next()) {
            (Some(kind), Some(value)) => (kind, value),
            _ => return Err(format!("option must be of the form `kind=value`: {}", c)),
        };
        match kind {
            "name" => name = value,
            _ => return Err(format!("unrecognized option: {}", kind)),
        }
    }

    Ok((name.to_string(), path))
}

#[derive(FromArgs)]
#[argh(subcommand, name = "wl")]
/// Wayland device
pub struct Options {
    #[argh(option, arg_name = "PATH")]
    /// path to bind a listening vhost-user socket
    socket: Option<String>,
    #[argh(option, arg_name = "STRING")]
    /// VFIO-PCI device name (e.g. '0000:00:07.0')
    vfio: Option<String>,
    #[argh(option, from_str_fn(parse_wayland_sock), arg_name = "PATH[,name=NAME]")]
    /// path to one or more Wayland sockets. The unnamed socket is used for
    /// displaying virtual screens while the named ones are used for IPC
    wayland_sock: Vec<(String, PathBuf)>,
    #[argh(option, arg_name = "PATH")]
    /// path to the GPU resource bridge
    resource_bridge: Option<String>,
}

/// Starts a vhost-user wayland device.
/// Returns an error if the given `args` is invalid or the device fails to run.
pub fn run_wl_device(opts: Options) -> anyhow::Result<()> {
    let Options {
        wayland_sock,
        socket,
        vfio,
        resource_bridge,
    } = opts;

    let wayland_paths: BTreeMap<_, _> = wayland_sock.into_iter().collect();

    let resource_bridge = resource_bridge
        .map(|p| -> anyhow::Result<Tube> {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                match UnixSeqpacket::connect(&p) {
                    Ok(s) => return Ok(Tube::new_from_unix_seqpacket(s)),
                    Err(e) => {
                        if Instant::now() < deadline {
                            thread::sleep(Duration::from_millis(50));
                        } else {
                            return Err(anyhow::Error::new(e));
                        }
                    }
                }
            }
        })
        .transpose()
        .context("failed to connect to resource bridge socket")?;

    let ex = Executor::new().context("failed to create executor")?;

    let listener =
        VhostUserListener::new_from_socket_or_vfio(&socket, &vfio, wl::QUEUE_SIZES.len(), None)?;

    let backend = Box::new(WlBackend::new(&ex, wayland_paths, resource_bridge));
    // run_until() returns an Result<Result<..>> which the ? operator lets us flatten.
    ex.run_until(listener.run_backend(backend, &ex))?
}
