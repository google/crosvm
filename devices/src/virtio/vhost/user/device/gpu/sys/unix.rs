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
use base::FromRawDescriptor;
use base::SafeDescriptor;
use base::Tube;
use base::UnixSeqpacketListener;
use base::UnlinkUnixSeqpacketListener;
use cros_async::AsyncWrapper;
use cros_async::Executor;
use cros_async::IoSourceExt;
use futures::future::AbortHandle;
use futures::future::Abortable;
use hypervisor::ProtectionType;
use sync::Mutex;

use crate::virtio;
use crate::virtio::gpu;
use crate::virtio::gpu::ProcessDisplayResult;
use crate::virtio::vhost::user::device::gpu::GpuBackend;
use crate::virtio::vhost::user::device::gpu::MAX_QUEUE_NUM;
use crate::virtio::vhost::user::device::listener::sys::VhostUserListener;
use crate::virtio::vhost::user::device::listener::VhostUserListenerTrait;
use crate::virtio::vhost::user::device::wl::parse_wayland_sock;
use crate::virtio::vhost::user::VhostBackendReqConnectionState;
use crate::virtio::Gpu;
use crate::virtio::GpuDisplayParameters;
use crate::virtio::GpuParameters;

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

impl GpuBackend {
    pub fn start_platform_workers(&mut self) -> anyhow::Result<()> {
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
            let (handle, registration) = AbortHandle::new_pair();
            self.ex
                .spawn_local(Abortable::new(
                    run_resource_bridge(tube, state.clone()),
                    registration,
                ))
                .detach();
            self.platform_workers.borrow_mut().push(handle);
        }

        // Start handling the display.
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
            .spawn_local(Abortable::new(run_display(display, state), registration))
            .detach();
        self.platform_workers.borrow_mut().push(handle);

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

    // Fallback for when external_blob is not available on the machine. Currently always off.
    let system_blob = false;

    let base_features = virtio::base_features(ProtectionType::Unprotected);
    let channels = wayland_paths;

    let listener = VhostUserListener::new_from_socket_or_vfio(&socket, &vfio, MAX_QUEUE_NUM, None)?;

    let gpu = Rc::new(RefCell::new(Gpu::new(
        exit_evt_wrtube,
        gpu_control_tube,
        Vec::new(), // resource_bridges, handled separately by us
        display_backends,
        &gpu_parameters,
        None,
        event_devices,
        external_blob,
        system_blob,
        base_features,
        channels,
        /* gpu_cgroup_path */
        None,
    )));

    let backend = Box::new(GpuBackend {
        ex: ex.clone(),
        gpu,
        resource_bridges,
        acked_protocol_features: 0,
        state: None,
        fence_state: Default::default(),
        queue_workers: Default::default(),
        platform_workers: Default::default(),
        backend_req_conn: VhostBackendReqConnectionState::NoConnection,
    });

    // Run until the backend is finished.
    let _ = ex.run_until(listener.run_backend(backend, &ex))?;

    // Process any tasks from the backend's destructor.
    Ok(ex.run_until(async {})?)
}
