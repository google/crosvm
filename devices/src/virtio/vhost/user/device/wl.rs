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

use anyhow::bail;
use anyhow::Context;
use argh::FromArgs;
use base::clone_descriptor;
use base::error;
use base::warn;
use base::RawDescriptor;
use base::SafeDescriptor;
use base::Tube;
use base::UnixSeqpacket;
use cros_async::AsyncWrapper;
use cros_async::EventAsync;
use cros_async::Executor;
use cros_async::IoSource;
use hypervisor::ProtectionType;
#[cfg(feature = "gbm")]
use rutabaga_gfx::RutabagaGralloc;
#[cfg(feature = "gbm")]
use rutabaga_gfx::RutabagaGrallocBackendFlags;
use snapshot::AnySnapshot;
use vm_memory::GuestMemory;
use vmm_vhost::message::VhostUserProtocolFeatures;
use vmm_vhost::VHOST_USER_F_PROTOCOL_FEATURES;

use crate::virtio::base_features;
use crate::virtio::device_constants::wl::NUM_QUEUES;
use crate::virtio::device_constants::wl::VIRTIO_WL_F_SEND_FENCES;
use crate::virtio::device_constants::wl::VIRTIO_WL_F_TRANS_FLAGS;
use crate::virtio::device_constants::wl::VIRTIO_WL_F_USE_SHMEM;
use crate::virtio::vhost::user::device::handler::Error as DeviceError;
use crate::virtio::vhost::user::device::handler::VhostBackendReqConnection;
use crate::virtio::vhost::user::device::handler::VhostUserDevice;
use crate::virtio::vhost::user::device::handler::WorkerState;
use crate::virtio::vhost::user::device::BackendConnection;
use crate::virtio::wl;
use crate::virtio::Queue;
use crate::virtio::SharedMemoryRegion;

async fn run_out_queue(
    queue: Rc<RefCell<Queue>>,
    kick_evt: EventAsync,
    wlstate: Rc<RefCell<wl::WlState>>,
) {
    loop {
        if let Err(e) = kick_evt.next_val().await {
            error!("Failed to read kick event for out queue: {}", e);
            break;
        }

        wl::process_out_queue(&mut queue.borrow_mut(), &mut wlstate.borrow_mut());
    }
}

async fn run_in_queue(
    queue: Rc<RefCell<Queue>>,
    kick_evt: EventAsync,
    wlstate: Rc<RefCell<wl::WlState>>,
    wlstate_ctx: IoSource<AsyncWrapper<SafeDescriptor>>,
) {
    loop {
        if let Err(e) = wlstate_ctx.wait_readable().await {
            error!(
                "Failed to wait for inner WaitContext to become readable: {}",
                e
            );
            break;
        }

        if wl::process_in_queue(&mut queue.borrow_mut(), &mut wlstate.borrow_mut())
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
    workers: [Option<WorkerState<Rc<RefCell<Queue>>, ()>>; NUM_QUEUES],
    backend_req_conn: Option<VhostBackendReqConnection>,
}

impl WlBackend {
    fn new(
        ex: &Executor,
        wayland_paths: BTreeMap<String, PathBuf>,
        resource_bridge: Option<Tube>,
    ) -> WlBackend {
        let features = base_features(ProtectionType::Unprotected)
            | 1 << VIRTIO_WL_F_TRANS_FLAGS
            | 1 << VIRTIO_WL_F_SEND_FENCES
            | 1 << VIRTIO_WL_F_USE_SHMEM
            | 1 << VHOST_USER_F_PROTOCOL_FEATURES;
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
            backend_req_conn: None,
        }
    }
}

impl VhostUserDevice for WlBackend {
    fn max_queue_num(&self) -> usize {
        NUM_QUEUES
    }

    fn features(&self) -> u64 {
        self.features
    }

    fn ack_features(&mut self, value: u64) -> anyhow::Result<()> {
        self.acked_features |= value;

        if value & (1 << VIRTIO_WL_F_TRANS_FLAGS) != 0 {
            self.use_transition_flags = true;
        }
        if value & (1 << VIRTIO_WL_F_SEND_FENCES) != 0 {
            self.use_send_vfd_v2 = true;
        }
        if value & (1 << VIRTIO_WL_F_USE_SHMEM) != 0 {
            self.use_shmem = true;
        }

        Ok(())
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::BACKEND_REQ | VhostUserProtocolFeatures::SHARED_MEMORY_REGIONS
    }

    fn read_config(&self, _offset: u64, _dst: &mut [u8]) {}

    fn start_queue(&mut self, idx: usize, queue: Queue, _mem: GuestMemory) -> anyhow::Result<()> {
        if self.workers[idx].is_some() {
            warn!("Starting new queue handler without stopping old handler");
            self.stop_queue(idx)?;
        }

        let kick_evt = queue
            .event()
            .try_clone()
            .context("failed to clone queue event")?;
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

        #[cfg(feature = "gbm")]
        let gralloc = RutabagaGralloc::new(RutabagaGrallocBackendFlags::new())
            .context("Failed to initailize gralloc")?;
        let wlstate = match &self.wlstate {
            None => {
                let mapper = self
                    .backend_req_conn
                    .as_ref()
                    .context("No backend request connection found")?
                    .shmem_mapper()
                    .context("Shared memory mapper not available")?;

                let wlstate = Rc::new(RefCell::new(wl::WlState::new(
                    wayland_paths.take().expect("WlState already initialized"),
                    mapper,
                    *use_transition_flags,
                    *use_send_vfd_v2,
                    resource_bridge.take(),
                    #[cfg(feature = "gbm")]
                    gralloc,
                    None, /* address_offset */
                )));
                self.wlstate = Some(wlstate.clone());
                wlstate
            }
            Some(state) => state.clone(),
        };
        let queue = Rc::new(RefCell::new(queue));
        let queue_task = match idx {
            0 => {
                let wlstate_ctx = clone_descriptor(wlstate.borrow().wait_ctx())
                    .map(AsyncWrapper::new)
                    .context("failed to clone inner WaitContext for WlState")
                    .and_then(|ctx| {
                        self.ex
                            .async_from(ctx)
                            .context("failed to create async WaitContext")
                    })?;

                self.ex
                    .spawn_local(run_in_queue(queue.clone(), kick_evt, wlstate, wlstate_ctx))
            }
            1 => self
                .ex
                .spawn_local(run_out_queue(queue.clone(), kick_evt, wlstate)),
            _ => bail!("attempted to start unknown queue: {}", idx),
        };
        self.workers[idx] = Some(WorkerState { queue_task, queue });
        Ok(())
    }

    fn stop_queue(&mut self, idx: usize) -> anyhow::Result<Queue> {
        if let Some(worker) = self.workers.get_mut(idx).and_then(Option::take) {
            // Wait for queue_task to be aborted.
            let _ = self.ex.run_until(worker.queue_task.cancel());

            let queue = match Rc::try_unwrap(worker.queue) {
                Ok(queue_cell) => queue_cell.into_inner(),
                Err(_) => panic!("failed to recover queue from worker"),
            };

            Ok(queue)
        } else {
            Err(anyhow::Error::new(DeviceError::WorkerNotFound))
        }
    }

    fn reset(&mut self) {
        for worker in self.workers.iter_mut().filter_map(Option::take) {
            let _ = self.ex.run_until(worker.queue_task.cancel());
        }
    }

    fn get_shared_memory_region(&self) -> Option<SharedMemoryRegion> {
        Some(SharedMemoryRegion {
            id: wl::WL_SHMEM_ID,
            length: wl::WL_SHMEM_SIZE,
        })
    }

    fn set_backend_req_connection(&mut self, conn: VhostBackendReqConnection) {
        if self.backend_req_conn.is_some() {
            warn!("connection already established. Overwriting");
        }

        self.backend_req_conn = Some(conn);
    }

    fn enter_suspended_state(&mut self) -> anyhow::Result<()> {
        // No non-queue workers.
        Ok(())
    }

    fn snapshot(&mut self) -> anyhow::Result<AnySnapshot> {
        bail!("snapshot not implemented for vhost-user wl");
    }

    fn restore(&mut self, _data: AnySnapshot) -> anyhow::Result<()> {
        bail!("snapshot not implemented for vhost-user wl");
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
    #[argh(option, arg_name = "PATH", hidden_help)]
    /// deprecated - please use --socket-path instead
    socket: Option<String>,
    #[argh(option, arg_name = "PATH")]
    /// path to the vhost-user socket to bind to.
    /// If this flag is set, --fd cannot be specified.
    socket_path: Option<String>,
    #[argh(option, arg_name = "FD")]
    /// file descriptor of a connected vhost-user socket.
    /// If this flag is set, --socket-path cannot be specified.
    fd: Option<RawDescriptor>,

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
        socket_path,
        fd,
        resource_bridge,
    } = opts;

    let wayland_paths: BTreeMap<_, _> = wayland_sock.into_iter().collect();

    let resource_bridge = resource_bridge
        .map(|p| -> anyhow::Result<Tube> {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                match UnixSeqpacket::connect(&p) {
                    Ok(s) => return Ok(Tube::try_from(s).unwrap()),
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

    let conn = BackendConnection::from_opts(socket.as_deref(), socket_path.as_deref(), fd)?;

    let backend = WlBackend::new(&ex, wayland_paths, resource_bridge);
    // run_until() returns an Result<Result<..>> which the ? operator lets us flatten.
    ex.run_until(conn.run_backend(backend, &ex))?
}
