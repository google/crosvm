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
use cros_async::AsyncWrapper;
use cros_async::Executor;
use cros_async::IoSource;
use hypervisor::ProtectionType;
use sync::Mutex;

use crate::virtio;
use crate::virtio::gpu;
use crate::virtio::gpu::ProcessDisplayResult;
use crate::virtio::vhost_user_backend::gpu::GpuBackend;
use crate::virtio::vhost_user_backend::wl::parse_wayland_sock;
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

impl GpuBackend {
    pub fn start_platform_workers(&mut self, _interrupt: Interrupt) -> anyhow::Result<()> {
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

        let task = self.ex.spawn_local(run_display(display, state));
        self.platform_worker_tx
            .unbounded_send(task)
            .context("sending the run_display task")?;

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
        socket_path,
        fd,
        wayland_sock,
    } = opts;

    let channels: BTreeMap<_, _> = wayland_sock.into_iter().collect();

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
    };

    // Run until the backend is finished.
    let _ = ex.run_until(conn.run_backend(backend, &ex))?;

    // Process any tasks from the backend's destructor.
    Ok(ex.run_until(async {})?)
}
