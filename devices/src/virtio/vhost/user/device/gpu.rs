// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::{cell::RefCell, collections::BTreeMap, fs::File, path::PathBuf, rc::Rc, sync::Arc};

use anyhow::{anyhow, bail, Context};
use argh::FromArgs;
use async_task::Task;
use base::{
    clone_descriptor, error, warn, Event, FromRawDescriptor, IntoRawDescriptor, SafeDescriptor,
    Tube, UnixSeqpacketListener, UnlinkUnixSeqpacketListener,
};
use cros_async::{AsyncTube, AsyncWrapper, EventAsync, Executor, IoSourceExt};
use hypervisor::ProtectionType;
use sync::Mutex;
use vm_memory::GuestMemory;
use vmm_vhost::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};

use crate::virtio::{
    self, gpu,
    vhost::user::device::handler::{DeviceRequestHandler, Doorbell, VhostUserBackend},
    vhost::user::device::wl::parse_wayland_sock,
    DescriptorChain, Gpu, GpuDisplayParameters, GpuParameters, Queue, QueueReader, VirtioDevice,
};

#[derive(Clone)]
struct SharedReader {
    queue: Arc<Mutex<Queue>>,
    doorbell: Arc<Mutex<Doorbell>>,
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

fn cancel_task<R: 'static>(ex: &Executor, task: Task<R>) {
    ex.spawn_local(task.cancel()).detach()
}

struct GpuBackend {
    ex: Executor,
    gpu: Rc<RefCell<Gpu>>,
    resource_bridges: Arc<Mutex<Vec<Tube>>>,
    acked_protocol_features: u64,
    state: Option<Rc<RefCell<gpu::Frontend>>>,
    fence_state: Arc<Mutex<gpu::FenceState>>,
    display_worker: Option<Task<()>>,
    workers: [Option<Task<()>>; Self::MAX_QUEUE_NUM],
}

impl VhostUserBackend for GpuBackend {
    const MAX_QUEUE_NUM: usize = gpu::QUEUE_SIZES.len();
    const MAX_VRING_LEN: u16 = gpu::QUEUE_SIZES[0];

    type Error = anyhow::Error;

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

    fn set_device_request_channel(&mut self, channel: File) -> anyhow::Result<()> {
        let tube = AsyncTube::new(&self.ex, unsafe {
            Tube::from_raw_descriptor(channel.into_raw_descriptor())
        })
        .context("failed to create AsyncTube")?;

        // We need a PciAddress in order to initialize the pci bar but this isn't part of the
        // vhost-user protocol. Instead we expect this to be the first message the crosvm main
        // process sends us on the device tube.
        let gpu = Rc::clone(&self.gpu);
        self.ex
            .spawn_local(async move {
                let response = match tube.next().await {
                    Ok(addr) => gpu.borrow_mut().get_device_bars(addr),
                    Err(e) => {
                        error!("Failed to get `PciAddr` from tube: {}", e);
                        return;
                    }
                };

                if let Err(e) = tube.send(response).await {
                    error!("Failed to send `PciBarConfiguration`: {}", e);
                }

                let device_tube: Tube = match tube.next().await {
                    Ok(tube) => tube,
                    Err(e) => {
                        error!("Failed to get device tube: {}", e);
                        return;
                    }
                };

                gpu.borrow_mut().set_device_tube(device_tube);
            })
            .detach();

        Ok(())
    }

    fn start_queue(
        &mut self,
        idx: usize,
        queue: Queue,
        mem: GuestMemory,
        doorbell: Arc<Mutex<Doorbell>>,
        kick_evt: Event,
    ) -> anyhow::Result<()> {
        if let Some(task) = self.workers.get_mut(idx).and_then(Option::take) {
            warn!("Starting new queue handler without stopping old handler");
            cancel_task(&self.ex, task);
        }

        match idx {
            // ctrl queue.
            0 => {}
            // We don't currently handle the cursor queue.
            1 => return Ok(()),
            _ => bail!("attempted to start unknown queue: {}", idx),
        }

        let kick_evt = EventAsync::new(kick_evt.0, &self.ex)
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
            let state = Rc::new(RefCell::new(
                self.gpu
                    .borrow_mut()
                    .initialize_frontend(self.fence_state.clone(), fence_handler)
                    .ok_or_else(|| anyhow!("failed to initialize gpu frontend"))?,
            ));
            self.state = Some(state.clone());
            state
        };

        // Start handling the resource bridges if we haven't already.
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

            let task = self.ex.spawn_local(run_display(display, state.clone()));
            self.display_worker = Some(task);
        }

        let task = self
            .ex
            .spawn_local(run_ctrl_queue(reader, mem, kick_evt, state));
        self.workers[idx] = Some(task);
        Ok(())
    }

    fn stop_queue(&mut self, idx: usize) {
        if let Some(task) = self.workers.get_mut(idx).and_then(Option::take) {
            cancel_task(&self.ex, task)
        }
    }

    fn reset(&mut self) {
        if let Some(task) = self.display_worker.take() {
            cancel_task(&self.ex, task)
        }

        for task in self.workers.iter_mut().filter_map(Option::take) {
            cancel_task(&self.ex, task)
        }
    }
}

fn gpu_parameters_from_str(input: &str) -> Result<GpuParameters, String> {
    serde_json::from_str(input).map_err(|e| e.to_string())
}

#[derive(FromArgs)]
#[argh(description = "run gpu device")]
struct Options {
    #[argh(
        option,
        description = "path to bind a listening vhost-user socket",
        arg_name = "PATH"
    )]
    socket: String,
    #[argh(
        option,
        description = "path to one or more Wayland sockets. The unnamed socket is \
        used for displaying virtual screens while the named ones are used for IPC",
        from_str_fn(parse_wayland_sock),
        arg_name = "PATH[,name=NAME]"
    )]
    wayland_sock: Vec<(String, PathBuf)>,
    #[argh(
        option,
        description = "path to one or more bridge sockets for communicating with \
        other graphics devices (wayland, video, etc)",
        arg_name = "PATH"
    )]
    resource_bridge: Vec<String>,
    #[argh(option, description = " X11 display name to use", arg_name = "DISPLAY")]
    x_display: Option<String>,
    #[argh(
        option,
        from_str_fn(gpu_parameters_from_str),
        default = "Default::default()",
        description = "a JSON object of virtio-gpu parameters",
        arg_name = "JSON"
    )]
    params: GpuParameters,
}

pub fn run_gpu_device(program_name: &str, args: &[&str]) -> anyhow::Result<()> {
    let Options {
        x_display,
        params: mut gpu_parameters,
        resource_bridge,
        socket,
        wayland_sock,
    } = match Options::from_args(&[program_name], args) {
        Ok(opts) => opts,
        Err(e) => {
            if e.status.is_err() {
                bail!(e.output);
            } else {
                println!("{}", e.output);
            }
            return Ok(());
        }
    };

    base::syslog::init().context("failed to initialize syslog")?;

    let wayland_paths: BTreeMap<_, _> = wayland_sock.into_iter().collect();

    let resource_bridge_listeners = resource_bridge
        .into_iter()
        .map(|p| {
            UnixSeqpacketListener::bind(&p)
                .map(UnlinkUnixSeqpacketListener)
                .with_context(|| format!("failed to bind socket at path {}", p))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    if gpu_parameters.displays.is_empty() {
        gpu_parameters
            .displays
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
            Ok(stream) => resource_bridges.lock().push(Tube::new(stream)),
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

    let exit_evt = Event::new().context("failed to create Event")?;

    // Initialized later.
    let gpu_device_tube = None;

    let mut display_backends = vec![
        virtio::DisplayBackend::X(x_display),
        virtio::DisplayBackend::Stub,
    ];
    if let Some(p) = wayland_paths.get("") {
        display_backends.insert(0, virtio::DisplayBackend::Wayland(Some(p.to_owned())));
    }

    // These are only used when there is an input device.
    let event_devices = Vec::new();

    // This is only used in single-process mode, even for the regular gpu device.
    let map_request = Arc::new(Mutex::new(None));

    // The regular gpu device sets this to true when sandboxing is enabled. Assume that we
    // are always sandboxed.
    let external_blob = true;
    let base_features = virtio::base_features(ProtectionType::Unprotected);
    let channels = wayland_paths;

    let gpu = Rc::new(RefCell::new(Gpu::new(
        exit_evt,
        gpu_device_tube,
        Vec::new(), // resource_bridges, handled separately by us
        display_backends,
        &gpu_parameters,
        None,
        event_devices,
        map_request,
        external_blob,
        base_features,
        channels,
    )));

    let backend = GpuBackend {
        ex: ex.clone(),
        gpu,
        resource_bridges,
        acked_protocol_features: 0,
        state: None,
        fence_state: Default::default(),
        display_worker: None,
        workers: Default::default(),
    };

    let handler = DeviceRequestHandler::new(backend);
    // run_until() returns an Result<Result<..>> which the ? operator lets us flatten.
    ex.run_until(handler.run(socket, &ex))?
}
