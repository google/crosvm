// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;

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
use base::UnixSeqpacketListener;
use base::UnlinkUnixSeqpacketListener;
use cros_async::AsyncWrapper;
use cros_async::EventAsync;
use cros_async::Executor;
use cros_async::IoSourceExt;
use futures::future::AbortHandle;
use futures::future::Abortable;
use hypervisor::ProtectionType;
use sync::Mutex;
use vm_memory::GuestMemory;
use vmm_vhost::message::VhostUserProtocolFeatures;
use vmm_vhost::message::VhostUserVirtioFeatures;

use crate::virtio;
use crate::virtio::gpu;
use crate::virtio::vhost::user::device::handler::sys::Doorbell;
use crate::virtio::vhost::user::device::handler::VhostBackendReqConnection;
use crate::virtio::vhost::user::device::handler::VhostBackendReqConnectionState;
use crate::virtio::vhost::user::device::handler::VhostUserBackend;
use crate::virtio::vhost::user::device::listener::sys::VhostUserListener;
use crate::virtio::vhost::user::device::listener::VhostUserListenerTrait;
use crate::virtio::vhost::user::device::wl::parse_wayland_sock;
use crate::virtio::DescriptorChain;
use crate::virtio::Gpu;
use crate::virtio::GpuDisplayParameters;
use crate::virtio::GpuParameters;
use crate::virtio::Queue;
use crate::virtio::QueueReader;
use crate::virtio::SharedMemoryRegion;
use crate::virtio::VirtioDevice;

const MAX_QUEUE_NUM: usize = gpu::QUEUE_SIZES.len();
const MAX_VRING_LEN: u16 = gpu::QUEUE_SIZES[0];

#[derive(Clone)]
struct SharedReader {
    queue: Arc<Mutex<Queue>>,
    doorbell: Doorbell,
}

impl gpu::QueueReader for SharedReader {
    fn pop(&self, mem: &GuestMemory) -> Option<DescriptorChain> {
        self.queue.lock().pop(mem)
    }

    fn add_used(&self, mem: &GuestMemory, desc_index: u16, len: u32) {
        self.queue.lock().add_used(mem, desc_index, len)
    }

    fn signal_used(&self, mem: &GuestMemory) {
        self.queue.lock().trigger_interrupt(mem, &self.doorbell);
    }
}

async fn run_ctrl_queue(
    reader: SharedReader,
    mem: GuestMemory,
    kick_evt: EventAsync,
    state: Rc<RefCell<gpu::Frontend>>,
) {
    loop {
        if let Err(e) = kick_evt.next_val().await {
            error!("Failed to read kick event for ctrl queue: {}", e);
            break;
        }

        let mut state = state.borrow_mut();
        let needs_interrupt = state.process_queue(&mem, &reader);

        if needs_interrupt {
            reader.signal_used(&mem);
        }
    }
}

async fn run_display(
    display: Box<dyn IoSourceExt<AsyncWrapper<SafeDescriptor>>>,
    state: Rc<RefCell<gpu::Frontend>>,
) {
    loop {
        if let Err(e) = display.wait_readable().await {
            error!(
                "Failed to wait for display context to become readable: {}",
                e
            );
            break;
        }

        if state.borrow_mut().process_display() {
            break;
        }
    }
}

async fn run_resource_bridge(tube: Box<dyn IoSourceExt<Tube>>, state: Rc<RefCell<gpu::Frontend>>) {
    loop {
        if let Err(e) = tube.wait_readable().await {
            error!(
                "Failed to wait for resource bridge tube to become readable: {}",
                e
            );
            break;
        }

        if let Err(e) = state.borrow_mut().process_resource_bridge(tube.as_source()) {
            error!("Failed to process resource bridge: {:#}", e);
            break;
        }
    }
}

struct GpuBackend {
    ex: Executor,
    gpu: Rc<RefCell<Gpu>>,
    resource_bridges: Arc<Mutex<Vec<Tube>>>,
    acked_protocol_features: u64,
    state: Option<Rc<RefCell<gpu::Frontend>>>,
    fence_state: Arc<Mutex<gpu::FenceState>>,
    display_worker: Option<AbortHandle>,
    workers: [Option<AbortHandle>; MAX_QUEUE_NUM],
    backend_req_conn: VhostBackendReqConnectionState,
}

impl VhostUserBackend for GpuBackend {
    fn max_queue_num(&self) -> usize {
        return MAX_QUEUE_NUM;
    }

    fn max_vring_len(&self) -> u16 {
        return MAX_VRING_LEN;
    }

    fn features(&self) -> u64 {
        self.gpu.borrow().features() | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
    }

    fn ack_features(&mut self, value: u64) -> anyhow::Result<()> {
        self.gpu.borrow_mut().ack_features(value);
        Ok(())
    }

    fn acked_features(&self) -> u64 {
        self.features()
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::CONFIG
            | VhostUserProtocolFeatures::SLAVE_REQ
            | VhostUserProtocolFeatures::MQ
            | VhostUserProtocolFeatures::SHARED_MEMORY_REGIONS
    }

    fn ack_protocol_features(&mut self, features: u64) -> anyhow::Result<()> {
        let unrequested_features = features & !self.protocol_features().bits();
        if unrequested_features != 0 {
            bail!("Unexpected protocol features: {:#x}", unrequested_features);
        }

        self.acked_protocol_features |= features;
        Ok(())
    }

    fn acked_protocol_features(&self) -> u64 {
        self.acked_protocol_features
    }

    fn read_config(&self, offset: u64, dst: &mut [u8]) {
        self.gpu.borrow().read_config(offset, dst)
    }

    fn write_config(&self, offset: u64, data: &[u8]) {
        self.gpu.borrow_mut().write_config(offset, data)
    }

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

        match idx {
            // ctrl queue.
            0 => {}
            // We don't currently handle the cursor queue.
            1 => return Ok(()),
            _ => bail!("attempted to start unknown queue: {}", idx),
        }

        // Enable any virtqueue features that were negotiated (like VIRTIO_RING_F_EVENT_IDX).
        queue.ack_features(self.acked_features());

        let kick_evt = EventAsync::new(kick_evt, &self.ex)
            .context("failed to create EventAsync for kick_evt")?;

        let reader = SharedReader {
            queue: Arc::new(Mutex::new(queue)),
            doorbell,
        };

        let state = if let Some(s) = self.state.as_ref() {
            s.clone()
        } else {
            let fence_handler =
                gpu::create_fence_handler(mem.clone(), reader.clone(), self.fence_state.clone());

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

            let state = Rc::new(RefCell::new(
                self.gpu
                    .borrow_mut()
                    .initialize_frontend(self.fence_state.clone(), fence_handler, mapper)
                    .ok_or_else(|| anyhow!("failed to initialize gpu frontend"))?,
            ));
            self.state = Some(state.clone());
            state
        };

        // Start handling the resource bridges, if we haven't already.
        for bridge in self.resource_bridges.lock().drain(..) {
            let tube = self
                .ex
                .async_from(bridge)
                .context("failed to create async tube")?;
            self.ex
                .spawn_local(run_resource_bridge(tube, state.clone()))
                .detach();
        }

        // Start handling the display, if we haven't already.
        if self.display_worker.is_none() {
            let display = clone_descriptor(&*state.borrow_mut().display().borrow())
                .map(|fd| {
                    // Safe because we just created this fd.
                    AsyncWrapper::new(unsafe { SafeDescriptor::from_raw_descriptor(fd) })
                })
                .context("failed to clone inner WaitContext for gpu display")
                .and_then(|ctx| {
                    self.ex
                        .async_from(ctx)
                        .context("failed to create async WaitContext")
                })?;

            let (handle, registration) = AbortHandle::new_pair();
            self.ex
                .spawn_local(Abortable::new(
                    run_display(display, state.clone()),
                    registration,
                ))
                .detach();
            self.display_worker = Some(handle);
        }

        // Start handling the control queue.
        let (handle, registration) = AbortHandle::new_pair();
        self.ex
            .spawn_local(Abortable::new(
                run_ctrl_queue(reader, mem, kick_evt, state),
                registration,
            ))
            .detach();

        self.workers[idx] = Some(handle);
        Ok(())
    }

    fn stop_queue(&mut self, idx: usize) {
        if let Some(handle) = self.workers.get_mut(idx).and_then(Option::take) {
            handle.abort();
        }
    }

    fn reset(&mut self) {
        if let Some(handle) = self.display_worker.take() {
            handle.abort();
        }

        for queue_num in 0..self.max_queue_num() {
            self.stop_queue(queue_num);
        }
    }

    fn get_shared_memory_region(&self) -> Option<SharedMemoryRegion> {
        self.gpu.borrow().get_shared_memory_region()
    }

    fn set_backend_req_connection(&mut self, conn: VhostBackendReqConnection) {
        if let VhostBackendReqConnectionState::Connected(_) = &self.backend_req_conn {
            warn!("connection already established. overwriting");
        }

        self.backend_req_conn = VhostBackendReqConnectionState::Connected(conn);
    }
}

fn gpu_parameters_from_str(input: &str) -> Result<GpuParameters, String> {
    serde_json::from_str(input).map_err(|e| e.to_string())
}

#[derive(FromArgs)]
/// GPU device
#[argh(subcommand, name = "gpu")]
pub struct Options {
    #[argh(option, arg_name = "PATH")]
    /// path to bind a listening vhost-user socket
    socket: Option<String>,
    #[argh(option, arg_name = "STRING")]
    /// VFIO-PCI device name (e.g. '0000:00:07.0')
    vfio: Option<String>,
    #[argh(option, from_str_fn(parse_wayland_sock), arg_name = "PATH[,name=NAME]")]
    /// path to one or more Wayland sockets. The unnamed socket is
    /// used for displaying virtual screens while the named ones are used for IPC
    wayland_sock: Vec<(String, PathBuf)>,
    #[argh(option, arg_name = "PATH")]
    /// path to one or more bridge sockets for communicating with
    /// other graphics devices (wayland, video, etc)
    resource_bridge: Vec<String>,
    #[argh(option, arg_name = "DISPLAY")]
    /// X11 display name to use
    x_display: Option<String>,
    #[argh(
        option,
        from_str_fn(gpu_parameters_from_str),
        default = "Default::default()",
        arg_name = "JSON"
    )]
    /// a JSON object of virtio-gpu parameters
    params: GpuParameters,
}

pub fn run_gpu_device(opts: Options) -> anyhow::Result<()> {
    let Options {
        x_display,
        params: mut gpu_parameters,
        resource_bridge,
        socket,
        vfio,
        wayland_sock,
    } = opts;

    let wayland_paths: BTreeMap<_, _> = wayland_sock.into_iter().collect();

    let resource_bridge_listeners = resource_bridge
        .into_iter()
        .map(|p| {
            UnixSeqpacketListener::bind(&p)
                .map(UnlinkUnixSeqpacketListener)
                .with_context(|| format!("failed to bind socket at path {}", p))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    if gpu_parameters.display_params.is_empty() {
        gpu_parameters
            .display_params
            .push(GpuDisplayParameters::default());
    }

    let ex = Executor::new().context("failed to create executor")?;

    // We don't know the order in which other devices are going to connect to the resource bridges
    // so start listening for all of them on separate threads. Any devices that connect after the
    // gpu device starts its queues will not have its resource bridges processed. In practice this
    // should be fine since the devices that use the resource bridge always try to connect to the
    // gpu device before handling messages from the VM.
    let resource_bridges = Arc::new(Mutex::new(Vec::with_capacity(
        resource_bridge_listeners.len(),
    )));
    for listener in resource_bridge_listeners {
        let resource_bridges = Arc::clone(&resource_bridges);
        ex.spawn_blocking(move || match listener.accept() {
            Ok(stream) => resource_bridges
                .lock()
                .push(Tube::new_from_unix_seqpacket(stream)),
            Err(e) => {
                let path = listener
                    .path()
                    .unwrap_or_else(|_| PathBuf::from("{unknown}"));
                error!(
                    "Failed to accept resource bridge connection for socket {}: {}",
                    path.display(),
                    e
                );
            }
        })
        .detach();
    }

    // TODO(b/232344535): Read side of the tube is ignored currently.
    // Complete the implementation by polling `exit_evt_rdtube` and
    // kill the sibling VM.
    let (exit_evt_wrtube, _) =
        Tube::directional_pair().context("failed to create vm event tube")?;

    let (gpu_control_tube, _) = Tube::pair().context("failed to create gpu control tube")?;

    let mut display_backends = vec![
        virtio::DisplayBackend::X(x_display),
        virtio::DisplayBackend::Stub,
    ];
    if let Some(p) = wayland_paths.get("") {
        display_backends.insert(0, virtio::DisplayBackend::Wayland(Some(p.to_owned())));
    }

    // These are only used when there is an input device.
    let event_devices = Vec::new();

    // The regular gpu device sets this to true when sandboxing is enabled. Assume that we
    // are always sandboxed.
    let external_blob = true;
    let base_features = virtio::base_features(ProtectionType::Unprotected);
    let channels = wayland_paths;

    let listener = VhostUserListener::new_from_socket_or_vfio(&socket, &vfio, MAX_QUEUE_NUM, None)?;

    let gpu = Rc::new(RefCell::new(Gpu::new(
        exit_evt_wrtube,
        gpu_control_tube,
        Vec::new(), // resource_bridges, handled separately by us
        display_backends,
        &gpu_parameters,
        #[cfg(feature = "virgl_renderer_next")]
        /* render_server_fd= */
        None,
        event_devices,
        external_blob,
        base_features,
        channels,
    )));

    let backend = Box::new(GpuBackend {
        ex: ex.clone(),
        gpu,
        resource_bridges,
        acked_protocol_features: 0,
        state: None,
        fence_state: Default::default(),
        display_worker: None,
        workers: Default::default(),
        backend_req_conn: VhostBackendReqConnectionState::NoConnection,
    });
    ex.run_until(listener.run_backend(backend, &ex))?
}
