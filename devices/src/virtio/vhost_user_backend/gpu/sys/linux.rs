// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;

use anyhow::Context;
use argh::FromArgs;
use base::clone_descriptor;
use base::error;
use base::RawDescriptor;
use base::SafeDescriptor;
use base::Tube;
use base::UnixSeqpacketListener;
use base::UnlinkUnixSeqpacketListener;
use cros_async::AsyncTube;
use cros_async::AsyncWrapper;
use cros_async::Executor;
use cros_async::IoSource;
use hypervisor::ProtectionType;
use sync::Mutex;
use vm_control::gpu::GpuControlResult;
use vm_control::VmRequest;
use vm_control::VmResponse;

use crate::sys::linux::parse_wayland_sock;
use crate::virtio;
use crate::virtio::gpu;
use crate::virtio::gpu::ProcessDisplayResult;
use crate::virtio::vhost_user_backend::gpu::GpuBackend;
use crate::virtio::vhost_user_backend::BackendConnection;
use crate::virtio::Gpu;
use crate::virtio::GpuDisplayParameters;
use crate::virtio::GpuParameters;
use crate::virtio::Interrupt;

async fn run_display(
    display: IoSource<AsyncWrapper<SafeDescriptor>>,
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

        match state.borrow_mut().process_display() {
            ProcessDisplayResult::Error(e) => {
                error!("Failed to process display events: {}", e);
                break;
            }
            ProcessDisplayResult::CloseRequested => break,
            ProcessDisplayResult::Success => {}
        }
    }
}

async fn run_resource_bridge(tube: IoSource<Tube>, state: Rc<RefCell<gpu::Frontend>>) {
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

/// The frontend state and interrupt of the running device, shared with the GPU control socket
/// handlers.
///
/// The handlers live as long as the process while the frontend only exists while the device is
/// running, so this is `None` until `start_platform_workers()` and again after the device stops.
pub type SharedGpuControlState = Rc<RefCell<Option<(Rc<RefCell<gpu::Frontend>>, Interrupt)>>>;

/// Handles a single GPU control request. Kept non-`async` so that the `state` borrow cannot be
/// held across an await point.
fn process_gpu_control_request(state: &SharedGpuControlState, req: VmRequest) -> VmResponse {
    let VmRequest::GpuCommand(cmd) = req else {
        return VmResponse::Err(base::Error::new(libc::EINVAL));
    };

    let state = state.borrow();
    let Some((frontend, interrupt)) = state.as_ref() else {
        // The device isn't running: not started yet, reset, or suspended.
        return VmResponse::Err(base::Error::new(libc::ENODEV));
    };

    let res = frontend.borrow_mut().process_gpu_control_command(cmd);
    if let GpuControlResult::DisplaysUpdated = &res {
        interrupt.signal_config_changed();
    }
    VmResponse::GpuResponse(res)
}

async fn run_gpu_control_command_handler(tube: AsyncTube, state: SharedGpuControlState) {
    loop {
        let req = match tube.next::<VmRequest>().await {
            Ok(req) => req,
            Err(_) => break,
        };

        let resp = process_gpu_control_request(&state, req);

        if let Err(e) = tube.send(resp).await {
            error!("GPU control socket failed to send response: {:#}", e);
            break;
        }
    }
}

async fn run_gpu_control_listener(
    ex: Executor,
    listener: IoSource<AsyncWrapper<UnlinkUnixSeqpacketListener>>,
    state: SharedGpuControlState,
) {
    loop {
        if let Err(e) = listener.wait_readable().await {
            error!("Failed to wait for control socket: {:#}", e);
            break;
        }
        match listener.as_source().accept() {
            Ok(stream) => match Tube::try_from(stream) {
                Ok(tube) => match AsyncTube::new(&ex, tube) {
                    Ok(async_tube) => {
                        // The handler never references the frontend state across an await point,
                        // so it doesn't need to be cancelled on reset; it exits when the client
                        // disconnects.
                        ex.spawn_local(run_gpu_control_command_handler(async_tube, state.clone()))
                            .detach();
                    }
                    Err(e) => {
                        error!("Failed to create AsyncTube for control socket: {:#}", e);
                    }
                },
                Err(e) => {
                    error!("Failed to create Tube for gpu control: {:#}", e);
                }
            },
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::Interrupted =>
            {
                continue;
            }
            Err(e) => {
                error!("Failed to accept gpu control connection: {:#}", e);
                break;
            }
        }
    }
}

impl GpuBackend {
    pub fn start_platform_workers(&mut self, interrupt: Interrupt) -> anyhow::Result<()> {
        let state = self
            .state
            .as_ref()
            .context("frontend state wasn't set")?
            .clone();

        // Start handling the resource bridges.
        for bridge in self.resource_bridges.lock().drain(..) {
            let tube = self
                .ex
                .async_from(bridge)
                .context("failed to create async tube")?;
            let task = self
                .ex
                .spawn_local(run_resource_bridge(tube, state.clone()));
            self.platform_worker_tx
                .unbounded_send(task)
                .context("sending the run_resource_bridge task")?;
        }

        // Start handling the display.
        let display = clone_descriptor(&*state.borrow_mut().display().borrow())
            .map(AsyncWrapper::new)
            .context("failed to clone inner WaitContext for gpu display")
            .and_then(|ctx| {
                self.ex
                    .async_from(ctx)
                    .context("failed to create async WaitContext")
            })?;

        let task = self.ex.spawn_local(run_display(display, state.clone()));
        self.platform_worker_tx
            .unbounded_send(task)
            .context("sending the run_display task")?;

        // Publish the state for the GPU control socket handlers, which are spawned once for the
        // lifetime of the process. Cleared again in `stop_non_queue_workers()`.
        self.gpu_control_state
            .borrow_mut()
            .replace((state, interrupt));

        Ok(())
    }
}
fn gpu_parameters_from_str(input: &str) -> Result<GpuParameters, String> {
    serde_json::from_str(input).map_err(|e| e.to_string())
}

#[derive(FromArgs)]
/// GPU device
#[argh(subcommand, name = "gpu")]
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
    #[argh(option, arg_name = "PATH")]
    /// path to the control socket to listen on for GPU commands
    control_socket_path: Option<PathBuf>,
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
        control_socket_path,
        params: mut gpu_parameters,
        resource_bridge,
        socket,
        socket_path,
        fd,
        wayland_sock,
    } = opts;

    // Standalone vhost-user GPU device runs out-of-process, so external_blob must be enforced
    // to allow blobs to be exported to descriptors for sharing with the hypervisor or host display.
    gpu_parameters.external_blob = true;

    let channels: BTreeMap<_, _> = wayland_sock.into_iter().collect();

    let resource_bridge_listeners = resource_bridge
        .into_iter()
        .map(|p| {
            UnixSeqpacketListener::bind(&p)
                .map(UnlinkUnixSeqpacketListener)
                .with_context(|| format!("failed to bind socket at path {p}"))
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
                .push(Tube::try_from(stream).unwrap()),
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
    #[cfg(feature = "android_display")]
    if let Some(service_name) = &gpu_parameters.android_display_service {
        display_backends.insert(0, virtio::DisplayBackend::Android(service_name.to_string()));
    }
    if let Some(p) = channels.get("") {
        display_backends.insert(0, virtio::DisplayBackend::Wayland(Some(p.to_owned())));
    }

    // These are only used when there is an input device.
    let event_devices = Vec::new();

    let base_features = virtio::base_features(ProtectionType::Unprotected);

    let conn = BackendConnection::from_opts(socket.as_deref(), socket_path.as_deref(), fd)?;

    let gpu = Rc::new(RefCell::new(Gpu::new(
        exit_evt_wrtube,
        gpu_control_tube,
        Vec::new(), // resource_bridges, handled separately by us
        display_backends,
        &gpu_parameters,
        /* rutabaga_server_descriptor */
        None,
        event_devices,
        base_features,
        &channels,
        /* gpu_cgroup_path */
        None,
    )));

    // The control socket is tied to the lifetime of this process, not of the device: the guest may
    // reset the device, reboot, reload the driver or suspend, and the socket must keep working.
    let gpu_control_state: SharedGpuControlState = Rc::new(RefCell::new(None));

    let control_listener_task = if let Some(path) = &control_socket_path {
        let listener = UnixSeqpacketListener::bind(path)
            .map(UnlinkUnixSeqpacketListener)
            .with_context(|| format!("failed to bind control socket at path {}", path.display()))?;
        listener
            .set_nonblocking(true)
            .context("failed to set nonblocking for control socket")?;
        let async_listener = ex
            .async_from(AsyncWrapper::new(listener))
            .context("failed to create async control socket listener")?;
        Some(ex.spawn_local(run_gpu_control_listener(
            ex.clone(),
            async_listener,
            gpu_control_state.clone(),
        )))
    } else {
        None
    };

    let (platform_worker_tx, platform_worker_rx) = futures::channel::mpsc::unbounded();
    let backend = GpuBackend {
        ex: ex.clone(),
        gpu,
        resource_bridges,
        state: None,
        fence_state: Default::default(),
        queue_workers: Default::default(),
        platform_worker_rx,
        platform_worker_tx,
        shmem_mapper: Arc::new(Mutex::new(None)),
        gpu_control_state,
    };

    // Run until the backend is finished.
    let res = ex.run_until(conn.run_backend(backend, &ex));

    if let Some(task) = control_listener_task {
        let _ = ex.run_until(task.cancel());
    }

    // Process any tasks from the backend's destructor.
    let _ = ex.run_until(async {});

    res?
}
