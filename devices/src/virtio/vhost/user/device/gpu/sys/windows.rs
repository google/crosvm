// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::collections::BTreeMap;
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
use cros_async::AsyncTube;
use cros_async::AsyncWrapper;
use cros_async::EventAsync;
use cros_async::Executor;
use gpu_display::EventDevice;
use gpu_display::WindowProcedureThread;
use gpu_display::WindowProcedureThreadBuilder;
use hypervisor::ProtectionType;
use serde::Deserialize;
use serde::Serialize;
use sync::Mutex;
use tube_transporter::TubeToken;
use vm_control::gpu::GpuControlCommand;
use vm_control::gpu::GpuControlResult;

use crate::virtio;
use crate::virtio::gpu;
use crate::virtio::gpu::ProcessDisplayResult;
use crate::virtio::vhost::user::device::gpu::GpuBackend;
use crate::virtio::vhost::user::device::handler::sys::windows::read_from_tube_transporter;
use crate::virtio::vhost::user::device::handler::sys::windows::run_handler;
use crate::virtio::vhost::user::device::handler::DeviceRequestHandler;
use crate::virtio::Gpu;
use crate::virtio::GpuDisplayParameters;
use crate::virtio::GpuParameters;
use crate::virtio::Interrupt;

pub mod generic;
pub use generic as product;

async fn run_display(
    display: EventAsync,
    state: Rc<RefCell<gpu::Frontend>>,
    gpu: Rc<RefCell<gpu::Gpu>>,
) {
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
            ProcessDisplayResult::CloseRequested => {
                let res = gpu.borrow().send_exit_evt();
                if res.is_err() {
                    error!("Failed to send exit event: {:?}", res);
                }
                break;
            }
            ProcessDisplayResult::Success => {}
        }
    }
}

async fn run_gpu_control_command_handler(
    mut gpu_control_tube: AsyncTube,
    state: Rc<RefCell<gpu::Frontend>>,
    interrupt: Interrupt,
) {
    'wait: loop {
        let req = match gpu_control_tube.next::<GpuControlCommand>().await {
            Ok(req) => req,
            Err(e) => {
                error!("GPU control socket failed to recv: {:?}", e);
                break 'wait;
            }
        };

        let resp = state.borrow_mut().process_gpu_control_command(req);

        if let GpuControlResult::DisplaysUpdated = resp {
            info!("Signaling display config change");
            interrupt.signal_config_changed();
        }

        if let Err(e) = gpu_control_tube.send(resp).await {
            error!("Display control socket failed to send: {}", e);
            break 'wait;
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

        // Start handling the display.
        // SAFETY:
        // Safe because the raw descriptor is valid, and an event.
        let display = unsafe {
            EventAsync::clone_raw_without_reset(&*state.borrow_mut().display().borrow(), &self.ex)
        }
        .context("failed to clone inner WaitContext for gpu display")?;

        let task = self
            .ex
            .spawn_local(run_display(display, state.clone(), self.gpu.clone()));
        self.platform_workers.borrow_mut().push(task);

        let task = self.ex.spawn_local(run_gpu_control_command_handler(
            AsyncTube::new(
                &self.ex,
                self.gpu
                    .borrow_mut()
                    .gpu_control_tube
                    .take()
                    .expect("gpu control tube must exist"),
            )
            .expect("gpu control tube creation"),
            state,
            interrupt,
        ));
        self.platform_workers.borrow_mut().push(task);

        Ok(())
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

/// Main process end for input event devices.
#[derive(Deserialize, Serialize)]
pub struct InputEventVmmConfig {
    // Pipes to receive input events on.
    pub multi_touch_pipes: Vec<StreamChannel>,
    pub mouse_pipes: Vec<StreamChannel>,
    pub keyboard_pipes: Vec<StreamChannel>,
}

/// Backend process end for input event devices.
#[derive(Deserialize, Serialize)]
pub struct InputEventBackendConfig {
    // Event devices to send input events to.
    pub event_devices: Vec<EventDevice>,
}

/// Configuration for running input event devices, split by a part sent to the main VMM and a part
/// sent to the window thread (either main process or a vhost-user process).
#[derive(Deserialize, Serialize)]
pub struct InputEventSplitConfig {
    // Config sent to the backend.
    pub backend_config: Option<InputEventBackendConfig>,
    // Config sent to the main process.
    pub vmm_config: InputEventVmmConfig,
}

/// Main process end for a GPU device.
#[derive(Deserialize, Serialize)]
pub struct GpuVmmConfig {
    // Tube for setting up the vhost-user connection. May not exist if not using vhost-user.
    pub main_vhost_user_tube: Option<Tube>,
    // A tube to forward GPU control commands in the main process.
    pub gpu_control_host_tube: Option<Tube>,
    pub product_config: product::GpuVmmConfig,
}

/// Config arguments passed through the bootstrap Tube from the broker to the Gpu backend
/// process.
#[derive(Deserialize, Serialize)]
pub struct GpuBackendConfig {
    // Tube for setting up the vhost-user connection. May not exist if not using vhost-user.
    pub device_vhost_user_tube: Option<Tube>,
    // An event for an incoming exit request.
    pub exit_event: Event,
    // A tube to send an exit request.
    pub exit_evt_wrtube: SendTube,
    // A tube to handle GPU control commands in the GPU device.
    pub gpu_control_device_tube: Tube,
    // GPU parameters.
    pub params: GpuParameters,
    // Product related configurations.
    pub product_config: product::GpuBackendConfig,
}

#[derive(Deserialize, Serialize)]
pub struct WindowProcedureThreadVmmConfig {
    pub product_config: product::WindowProcedureThreadVmmConfig,
}

#[derive(Deserialize, Serialize)]
pub struct WindowProcedureThreadSplitConfig {
    // This is the config sent to the backend process.
    pub wndproc_thread_builder: Option<WindowProcedureThreadBuilder>,
    // Config sent to the main process.
    pub vmm_config: WindowProcedureThreadVmmConfig,
}

pub fn run_gpu_device(opts: Options) -> anyhow::Result<()> {
    cros_tracing::init();

    let raw_transport_tube = opts.bootstrap as RawDescriptor;

    let mut tubes = read_from_tube_transporter(raw_transport_tube)?;

    let bootstrap_tube = tubes.get_tube(TubeToken::Bootstrap)?;

    let startup_args: CommonChildStartupArgs = bootstrap_tube.recv::<CommonChildStartupArgs>()?;
    let _child_cleanup = common_child_setup(startup_args)?;

    let (mut config, input_event_backend_config, wndproc_thread_builder): (
        GpuBackendConfig,
        InputEventBackendConfig,
        WindowProcedureThreadBuilder,
    ) = bootstrap_tube
        .recv()
        .context("failed to parse GPU backend config from bootstrap tube")?;

    // TODO(b/213170185): Uncomment once sandbox is upstreamed.
    // if sandbox::is_sandbox_target() {
    //     sandbox::TargetServices::get()
    //         .expect("failed to get target services")
    //         .unwrap()
    //         .lower_token();
    // }

    let wndproc_thread = wndproc_thread_builder
        .start_thread()
        .context("Failed to create window procedure thread for vhost GPU")?;

    run_gpu_device_worker(
        config,
        input_event_backend_config.event_devices,
        wndproc_thread,
    )
}

/// Run the GPU device worker.
pub fn run_gpu_device_worker(
    mut config: GpuBackendConfig,
    event_devices: Vec<EventDevice>,
    wndproc_thread: WindowProcedureThread,
) -> anyhow::Result<()> {
    let vhost_user_tube = config
        .device_vhost_user_tube
        .expect("vhost-user gpu tube must be set");

    if config.params.display_params.is_empty() {
        config
            .params
            .display_params
            .push(GpuDisplayParameters::default());
    }

    let display_backends = vec![virtio::DisplayBackend::WinApi];

    let mut gpu_params = config.params.clone();

    // Fallback for when external_blob is not available on the machine. Currently always off.
    gpu_params.system_blob = false;

    let base_features = virtio::base_features(ProtectionType::Unprotected);

    let gpu = Rc::new(RefCell::new(Gpu::new(
        config.exit_evt_wrtube,
        config.gpu_control_device_tube,
        /* resource_bridges= */ Vec::new(),
        display_backends,
        &gpu_params,
        /* render_server_descriptor */ None,
        event_devices,
        base_features,
        /* channels= */ &Default::default(),
        wndproc_thread,
    )));

    let ex = Executor::new().context("failed to create executor")?;

    let backend = GpuBackend {
        ex: ex.clone(),
        gpu,
        resource_bridges: Default::default(),
        state: None,
        fence_state: Default::default(),
        queue_workers: Default::default(),
        platform_workers: Default::default(),
        shmem_mapper: Arc::new(Mutex::new(None)),
    };

    let handler = DeviceRequestHandler::new(backend);

    info!("vhost-user gpu device ready, starting run loop...");

    // Run until the backend is finished.
    if let Err(e) = ex.run_until(run_handler(
        Box::new(handler),
        vhost_user_tube,
        config.exit_event,
        &ex,
    )) {
        bail!("error occurred: {}", e);
    }

    // Process any tasks from the backend's destructor.
    Ok(ex.run_until(async {})?)
}
