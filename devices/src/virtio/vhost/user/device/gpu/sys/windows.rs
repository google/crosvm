// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;

use anyhow::bail;
use anyhow::Context;
use argh::FromArgs;
use base::error;
use base::info;
use base::Event;
use base::FromRawDescriptor;
use base::RawDescriptor;
use base::SafeDescriptor;
use base::SendTube;
use base::StreamChannel;
use base::Tube;
use broker_ipc::common_child_setup;
use broker_ipc::CommonChildStartupArgs;
use cros_async::AsyncWrapper;
use cros_async::EventAsync;
use cros_async::Executor;
use cros_async::IoSourceExt;
use futures::future::AbortHandle;
use futures::future::Abortable;
use gpu_display::EventDevice;
use gpu_display::EventDeviceKind;
use hypervisor::ProtectionType;
use serde::Deserialize;
use serde::Serialize;
use sync::Mutex;
use tube_transporter::TubeToken;

use crate::virtio;
use crate::virtio::gpu;
use crate::virtio::gpu::ProcessDisplayResult;
use crate::virtio::vhost::user::device::gpu::GpuBackend;
use crate::virtio::vhost::user::device::handler::sys::windows::read_from_tube_transporter;
use crate::virtio::vhost::user::device::handler::DeviceRequestHandler;
use crate::virtio::vhost::user::VhostBackendReqConnectionState;
use crate::virtio::Gpu;
use crate::virtio::GpuDisplayParameters;
use crate::virtio::GpuParameters;

async fn run_display(display: EventAsync, state: Rc<RefCell<gpu::Frontend>>) {
    loop {
        if let Err(e) = display.next_val().await {
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

impl GpuBackend {
    pub fn start_platform_workers(&mut self) -> anyhow::Result<()> {
        let state = self
            .state
            .as_ref()
            .context("frontend state wasn't set")?
            .clone();

        // Start handling the display.
        // Safe because the raw descriptor is valid, and an event.
        let display = unsafe {
            EventAsync::clone_raw_without_reset(&*state.borrow_mut().display().borrow(), &self.ex)
        }
        .context("failed to clone inner WaitContext for gpu display")?;

        let (handle, registration) = AbortHandle::new_pair();
        self.ex
            .spawn_local(Abortable::new(run_display(display, state), registration))
            .detach();
        self.platform_workers.borrow_mut().push(handle);

        return Ok(());
    }
}

#[derive(FromArgs)]
/// GPU device
#[argh(subcommand, name = "gpu", description = "")]
pub struct Options {
    #[argh(
        option,
        description = "pipe handle end for Tube Transporter",
        arg_name = "HANDLE"
    )]
    bootstrap: usize,
}

/// Main process end for a GPU device.
#[derive(Deserialize, Serialize)]
pub struct GpuVmmConfig {
    // Tube for setting up the vhost-user connection.
    pub vhost_user_tube: Option<Tube>,
    // Tube for service.
    pub gpu_main_service_tube: Option<Tube>,
    // Pipes to receive input events on.
    pub input_event_device_pipes: VecDeque<(EventDeviceKind, StreamChannel)>,
}

/// Config arguments passed through the bootstrap Tube from the broker to the Gpu backend
/// process.
#[derive(Deserialize, Serialize)]
pub struct GpuBackendConfig {
    // An event for an incoming exit request.
    pub exit_event: Event,
    // A tube to send an exit request.
    pub exit_evt_wrtube: SendTube,
    // Event devices to send input events to.
    pub event_devices: Vec<EventDevice>,
    // Tube for service.
    pub gpu_device_service_tube: Tube,
    // GPU parameters.
    pub params: GpuParameters,
}

pub fn run_gpu_device(opts: Options) -> anyhow::Result<()> {
    cros_tracing::init();

    let raw_transport_tube = opts.bootstrap as RawDescriptor;

    let mut tubes = read_from_tube_transporter(raw_transport_tube)?;

    let bootstrap_tube = tubes.get_tube(TubeToken::Bootstrap)?;
    let vhost_user_tube = tubes.get_tube(TubeToken::VhostUser)?;

    let startup_args: CommonChildStartupArgs = bootstrap_tube.recv::<CommonChildStartupArgs>()?;
    let _child_cleanup = common_child_setup(startup_args)?;

    let mut config: GpuBackendConfig = bootstrap_tube
        .recv()
        .context("failed to parse GPU backend config from bootstrap tube")?;

    if config.params.display_params.is_empty() {
        config
            .params
            .display_params
            .push(GpuDisplayParameters::default());
    }

    let display_backends = vec![virtio::DisplayBackend::WinApi(
        (&config.params.display_params[0]).into(),
    )];

    let wndproc_thread = virtio::gpu::start_wndproc_thread(
        #[cfg(feature = "kiwi")]
        config.params.display_params[0]
            .gpu_main_display_tube
            .clone(),
        #[cfg(not(feature = "kiwi"))]
        None,
    )
    .context("failed to start wndproc_thread")?;

    // Required to share memory across processes.
    let external_blob = true;
    let base_features = virtio::base_features(ProtectionType::Unprotected);

    let gpu = Rc::new(RefCell::new(Gpu::new(
        config.exit_evt_wrtube,
        /*resource_bridges=*/ Vec::new(),
        display_backends,
        &config.params,
        #[cfg(feature = "virgl_renderer_next")]
        /*render_server_fd=*/
        None,
        config.event_devices,
        external_blob,
        base_features,
        /*channels=*/ Default::default(),
        #[cfg(feature = "kiwi")]
        Some(config.gpu_device_service_tube),
        wndproc_thread,
    )));

    let ex = Executor::new().context("failed to create executor")?;

    let backend = Box::new(GpuBackend {
        ex: ex.clone(),
        gpu,
        resource_bridges: Default::default(),
        acked_protocol_features: 0,
        state: None,
        fence_state: Default::default(),
        queue_workers: Default::default(),
        platform_workers: Default::default(),
        backend_req_conn: VhostBackendReqConnectionState::NoConnection,
    });

    let handler = DeviceRequestHandler::new(backend);

    // TODO(b/213170185): Uncomment once sandbox is upstreamed.
    // if sandbox::is_sandbox_target() {
    //     sandbox::TargetServices::get()
    //         .expect("failed to get target services")
    //         .unwrap()
    //         .lower_token();
    // }

    info!("vhost-user gpu device ready, starting run loop...");
    if let Err(e) = ex.run_until(handler.run(vhost_user_tube, config.exit_event, &ex)) {
        bail!("error occurred: {}", e);
    }

    Ok(())
}
