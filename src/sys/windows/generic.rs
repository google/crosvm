// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::Result;
use arch::RunnableLinuxVm;
use arch::VcpuArch;
use arch::VirtioDeviceStub;
use base::info;
use base::AsRawDescriptor;
use base::CloseNotifier;
use base::Event;
use base::EventToken;
use base::ProtoTube;
use base::ReadNotifier;
use base::Tube;
use base::WaitContext;
#[cfg(feature = "gpu")]
use devices::virtio::vhost_user_backend::gpu::sys::windows::product::GpuBackendConfig as GpuBackendConfigProduct;
#[cfg(feature = "gpu")]
use devices::virtio::vhost_user_backend::gpu::sys::windows::product::GpuVmmConfig as GpuVmmConfigProduct;
#[cfg(feature = "gpu")]
use devices::virtio::vhost_user_backend::gpu::sys::windows::product::WindowProcedureThreadVmmConfig as WindowProcedureThreadVmmConfigProduct;
#[cfg(feature = "gpu")]
use devices::virtio::vhost_user_backend::gpu::sys::windows::GpuVmmConfig;
#[cfg(feature = "gpu")]
use devices::virtio::vhost_user_backend::gpu::sys::windows::InputEventVmmConfig;
#[cfg(feature = "gpu")]
use devices::virtio::vhost_user_backend::gpu::sys::windows::WindowProcedureThreadVmmConfig;
#[cfg(feature = "audio")]
use devices::virtio::vhost_user_backend::snd::sys::windows::product::SndBackendConfig as SndBackendConfigProduct;
#[cfg(feature = "audio")]
use devices::virtio::vhost_user_backend::snd::sys::windows::product::SndVmmConfig as SndVmmConfigProduct;
#[cfg(feature = "audio")]
use devices::virtio::vhost_user_backend::snd::sys::windows::SndVmmConfig;
#[cfg(feature = "gpu")]
use gpu_display::WindowProcedureThreadBuilder;
pub(crate) use metrics::log_descriptor;
pub(crate) use metrics::MetricEventType;
use sync::Mutex;
#[cfg(feature = "balloon")]
use vm_control::BalloonTube;
use vm_control::InitialAudioSessionState;
use vm_control::PvClockCommand;
use vm_control::VmRequest;
use vm_control::VmResponse;
use vm_control::VmRunMode;

use super::run_vcpu::VcpuRunMode;
use crate::crosvm::config::Config;
use crate::crosvm::sys::cmdline::RunMetricsCommand;
use crate::sys::windows::TaggedControlTube as SharedTaggedControlTube;

pub struct ServiceVmState {}

impl ServiceVmState {}

pub struct ServiceAudioStates {}

pub(super) struct RunControlArgs {}

#[derive(Debug)]
pub(super) enum TaggedControlTube {}

impl ReadNotifier for TaggedControlTube {
    fn get_read_notifier(&self) -> &dyn AsRawDescriptor {
        panic!("get_read_notifier called on generic tagged control: {self:?}")
    }
}

impl CloseNotifier for TaggedControlTube {
    fn get_close_notifier(&self) -> &dyn AsRawDescriptor {
        panic!("get_read_notifier called on generic tagged control: {self:?}")
    }
}

#[derive(EventToken, Debug)]
pub(super) enum Token {
    VmEvent,
    BrokerShutdown,
    VmControlServer,
    VmControl { id: usize },
    BalloonTube,
}

pub(super) fn setup_common_metric_invariants(_cfg: &Config) {}

pub(super) fn get_run_control_args(_cfg: &mut Config) -> RunControlArgs {
    RunControlArgs {}
}

// Handles sending command to pvclock device.
#[cfg(feature = "pvclock")]
pub(super) fn handle_pvclock_request(_tube: &Option<Tube>, _command: PvClockCommand) -> Result<()> {
    Ok(())
}

// Run ime thread.
pub(super) fn run_ime_thread(
    _product_args: &mut RunControlArgs,
    _exit_evt: &Event,
) -> Result<Option<JoinHandle<Result<()>>>> {
    Ok(None)
}

pub(super) fn create_snd_state_tube(
    _control_tubes: &mut [SharedTaggedControlTube],
) -> Result<Option<Tube>> {
    Ok(None)
}

pub(super) fn create_snd_mute_tube_pair() -> Result<(Option<Tube>, Option<Tube>)> {
    Ok((None, None))
}

// Returns two tubes and a handle to service_ipc. One for ipc_main_loop and another
// for proto_main_loop.
pub(super) fn start_service_ipc_listener(
    _service_pipe_name: Option<String>,
) -> Result<(Option<Tube>, Option<ProtoTube>, Option<()>)> {
    Ok((None, None, None))
}

pub(super) fn handle_tagged_control_tube_event(
    _product_tube: &TaggedControlTube,
    _virtio_snd_host_mute_tubes: &mut [Tube],
    _service_vm_state: &mut ServiceVmState,
    _ipc_main_loop_tube: Option<&Tube>,
) {
}

pub(super) fn push_triggers<'a>(
    _triggers: &mut [(&'a dyn AsRawDescriptor, Token)],
    ipc_tube: &'a Option<Tube>,
    proto_tube: &'a Option<ProtoTube>,
) {
    if ipc_tube.is_some() {
        panic!("trying to push non-none ipc tube in generic product");
    }
    if proto_tube.is_some() {
        panic!("trying to push non-none proto tube in generic product");
    }
}

pub(super) fn handle_received_token<'a, F>(
    token: &Token,
    _anti_tamper_main_thread_tube: &Option<ProtoTube>,
    #[cfg(feature = "balloon")] _balloon_tube: Option<&mut BalloonTube>,
    _control_tubes: &BTreeMap<usize, SharedTaggedControlTube>,
    _guest_os: &mut RunnableLinuxVm,
    _ipc_main_loop_tube: Option<&Tube>,
    _memory_size_mb: u64,
    _proto_main_loop_tube: Option<&ProtoTube>,
    #[cfg(feature = "pvclock")] _pvclock_host_tube: &Option<Tube>,
    _run_mode_arc: &VcpuRunMode,
    _service_vm_state: &mut ServiceVmState,
    _vcpu_boxes: &Mutex<Vec<Arc<dyn VcpuArch>>>,
    _virtio_snd_host_mute_tube: &mut [Tube],
    _execute_vm_request: F,
) -> Option<VmRunMode>
where
    F: FnMut(VmRequest, &'a mut RunnableLinuxVm) -> (VmResponse, Option<VmRunMode>),
{
    panic!("Received an unrecognized shared token to product specific handler: {token:?}")
}

pub(super) fn spawn_anti_tamper_thread(_wait_ctx: &WaitContext<Token>) -> Option<ProtoTube> {
    None
}

pub(super) fn create_service_vm_state(_memory_size_mb: u64) -> ServiceVmState {
    ServiceVmState {}
}

pub(super) fn create_service_audio_states_and_send_to_service(
    _initial_audio_session_states: Vec<InitialAudioSessionState>,
    _ipc_main_loop_tube: &Option<Tube>,
) -> Result<ServiceAudioStates> {
    Ok(ServiceAudioStates {})
}

#[cfg(feature = "gpu")]
pub(super) fn push_window_procedure_thread_control_tubes(
    #[allow(clippy::ptr_arg)]
    // The implementor can extend the size of this argument, so mutable slice is not enough.
    _control_tubes: &mut Vec<SharedTaggedControlTube>,
    _: &mut WindowProcedureThreadVmmConfig,
) {
}

#[cfg(feature = "gpu")]
pub(super) fn push_gpu_control_tubes(
    _control_tubes: &mut [SharedTaggedControlTube],
    _gpu_vmm_config: &mut GpuVmmConfig,
) {
}

#[cfg(feature = "audio")]
pub(super) fn push_snd_control_tubes(
    _control_tubes: &mut [SharedTaggedControlTube],
    _snd_vmm_config: &mut SndVmmConfig,
) {
}

#[cfg(feature = "audio")]
pub(crate) fn num_input_sound_devices(_cfg: &Config) -> u32 {
    0
}

#[cfg(feature = "audio")]
pub(crate) fn num_input_sound_streams(_cfg: &Config) -> u32 {
    0
}

#[cfg(feature = "gpu")]
pub(crate) fn get_gpu_product_configs(
    _cfg: &Config,
    _alias_pid: u32,
) -> Result<(GpuBackendConfigProduct, GpuVmmConfigProduct)> {
    Ok((GpuBackendConfigProduct {}, GpuVmmConfigProduct {}))
}

#[cfg(feature = "audio")]
pub(crate) fn get_snd_product_configs() -> Result<(SndBackendConfigProduct, SndVmmConfigProduct)> {
    Ok((SndBackendConfigProduct {}, SndVmmConfigProduct {}))
}

pub(crate) fn run_metrics(_args: RunMetricsCommand) -> Result<()> {
    info!("sleep forever. We will get killed by broker");
    thread::sleep(Duration::MAX);
    Ok(())
}

pub(crate) fn setup_metrics_reporting() -> Result<()> {
    Ok(())
}

pub(super) fn push_mouse_device(
    _cfg: &Config,
    #[cfg(feature = "gpu")] _input_event_vmm_config: &mut InputEventVmmConfig,
    _devs: &mut [VirtioDeviceStub],
) -> Result<()> {
    Ok(())
}

#[cfg(feature = "pvclock")]
pub(super) fn push_pvclock_device(
    _cfg: &Config,
    _devs: &mut [VirtioDeviceStub],
    _tsc_frequency: u64,
    _tube: Tube,
) {
}

#[cfg(feature = "gpu")]
pub(crate) fn get_window_procedure_thread_product_configs(
    _: &Config,
    _: &mut WindowProcedureThreadBuilder,
    _main_alias_pid: u32,
    _device_alias_pid: u32,
) -> Result<WindowProcedureThreadVmmConfigProduct> {
    Ok(WindowProcedureThreadVmmConfigProduct {})
}
