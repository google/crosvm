// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::path::PathBuf;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use argh::FromArgs;
use base::error;
use base::Event;
use base::RawDescriptor;
use base::Terminal;
use cros_async::Executor;
use hypervisor::ProtectionType;
use vm_memory::GuestMemory;
use vmm_vhost::message::VhostUserProtocolFeatures;
use vmm_vhost::VHOST_USER_F_PROTOCOL_FEATURES;

use crate::virtio::console::device::ConsoleDevice;
use crate::virtio::console::device::ConsoleSnapshot;
use crate::virtio::console::port::ConsolePort;
use crate::virtio::vhost::user::device::handler::DeviceRequestHandler;
use crate::virtio::vhost::user::device::handler::VhostUserDevice;
use crate::virtio::vhost::user::device::listener::sys::VhostUserListener;
use crate::virtio::vhost::user::device::listener::VhostUserListenerTrait;
use crate::virtio::vhost::user::device::VhostUserDeviceBuilder;
use crate::virtio::Interrupt;
use crate::virtio::Queue;
use crate::SerialHardware;
use crate::SerialParameters;
use crate::SerialType;

/// Console device for use with vhost-user. Will set stdin back to canon mode if we are getting
/// input from it.
pub struct VhostUserConsoleDevice {
    console: ConsoleDevice,
    /// Whether we should set stdin to raw mode because we are getting user input from there.
    raw_stdin: bool,
}

impl Drop for VhostUserConsoleDevice {
    fn drop(&mut self) {
        if self.raw_stdin {
            // Restore terminal capabilities back to what they were before
            match std::io::stdin().set_canon_mode() {
                Ok(()) => (),
                Err(e) => error!("failed to restore canonical mode for terminal: {:#}", e),
            }
        }
    }
}

impl VhostUserDeviceBuilder for VhostUserConsoleDevice {
    fn build(mut self: Box<Self>, _ex: &Executor) -> anyhow::Result<Box<dyn vmm_vhost::Backend>> {
        if self.raw_stdin {
            // Set stdin() to raw mode so we can send over individual keystrokes unbuffered
            std::io::stdin()
                .set_raw_mode()
                .context("failed to set terminal in raw mode")?;
        }

        self.console.start_input_threads();

        let backend = ConsoleBackend { device: *self };

        let handler = DeviceRequestHandler::new(backend);
        Ok(Box::new(handler))
    }
}

struct ConsoleBackend {
    device: VhostUserConsoleDevice,
}

impl VhostUserDevice for ConsoleBackend {
    fn max_queue_num(&self) -> usize {
        self.device.console.max_queues()
    }

    fn features(&self) -> u64 {
        self.device.console.features() | 1 << VHOST_USER_F_PROTOCOL_FEATURES
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::CONFIG
            | VhostUserProtocolFeatures::MQ
            | VhostUserProtocolFeatures::DEVICE_STATE
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        self.device.console.read_config(offset, data);
    }

    fn reset(&mut self) {
        if let Err(e) = self.device.console.reset() {
            error!("console reset failed: {:#}", e);
        }
    }

    fn start_queue(
        &mut self,
        idx: usize,
        queue: Queue,
        _mem: GuestMemory,
        doorbell: Interrupt,
    ) -> anyhow::Result<()> {
        self.device.console.start_queue(idx, queue, doorbell)
    }

    fn stop_queue(&mut self, idx: usize) -> anyhow::Result<Queue> {
        match self.device.console.stop_queue(idx) {
            Ok(Some(queue)) => Ok(queue),
            Ok(None) => Err(anyhow!("queue {idx} not started")),
            Err(e) => Err(e).with_context(|| format!("failed to stop queue {idx}")),
        }
    }

    fn enter_suspended_state(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    fn snapshot(&mut self) -> anyhow::Result<serde_json::Value> {
        let snap = self.device.console.snapshot()?;
        serde_json::to_value(snap).context("failed to snapshot vhost-user console")
    }

    fn restore(&mut self, data: serde_json::Value) -> anyhow::Result<()> {
        let snap: ConsoleSnapshot =
            serde_json::from_value(data).context("failed to deserialize vhost-user console")?;
        self.device.console.restore(&snap)
    }
}

#[derive(FromArgs)]
#[argh(subcommand, name = "console")]
/// Console device
pub struct Options {
    #[argh(option, arg_name = "PATH")]
    /// path to a vhost-user socket
    socket: String,
    #[argh(option, arg_name = "OUTFILE")]
    /// path to a file
    output_file: Option<PathBuf>,
    #[argh(option, arg_name = "INFILE")]
    /// path to a file
    input_file: Option<PathBuf>,
    /// whether we are logging to syslog or not
    #[argh(switch)]
    syslog: bool,
    #[argh(option, arg_name = "type=TYPE,[path=PATH,input=PATH,console]")]
    /// multiport parameters
    port: Vec<SerialParameters>,
}

fn create_vu_multi_port_device(
    params: &[SerialParameters],
    keep_rds: &mut Vec<RawDescriptor>,
) -> anyhow::Result<VhostUserConsoleDevice> {
    let ports = params
        .iter()
        .map(|x| {
            let port = x
                .create_serial_device::<ConsolePort>(
                    ProtectionType::Unprotected,
                    // We need to pass an event as per Serial Device API but we don't really use it
                    // anyway.
                    &Event::new()?,
                    keep_rds,
                )
                .expect("failed to create multiport console");

            Ok(port)
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let device = ConsoleDevice::new_multi_port(ProtectionType::Unprotected, ports);

    Ok(VhostUserConsoleDevice {
        console: device,
        raw_stdin: false, // currently we are not support stdin raw mode
    })
}

/// Starts a multiport enabled vhost-user console device.
/// Returns an error if the given `args` is invalid or the device fails to run.
fn run_multi_port_device(opts: Options) -> anyhow::Result<()> {
    if opts.port.is_empty() {
        bail!("console: must have at least one `--port`");
    }

    // We won't jail the device and can simply ignore `keep_rds`.
    let device = Box::new(create_vu_multi_port_device(&opts.port, &mut Vec::new())?);
    let ex = Executor::new().context("Failed to create executor")?;

    let listener = VhostUserListener::new_socket(&opts.socket, None)?;

    listener.run_device(ex, device)
}

/// Return a new vhost-user console device. `params` are the device's configuration, and `keep_rds`
/// is a vector into which `RawDescriptors` that need to survive a fork are added, in case the
/// device is meant to run within a child process.
pub fn create_vu_console_device(
    params: &SerialParameters,
    keep_rds: &mut Vec<RawDescriptor>,
) -> anyhow::Result<VhostUserConsoleDevice> {
    let device = params.create_serial_device::<ConsoleDevice>(
        ProtectionType::Unprotected,
        // We need to pass an event as per Serial Device API but we don't really use it anyway.
        &Event::new()?,
        keep_rds,
    )?;

    Ok(VhostUserConsoleDevice {
        console: device,
        raw_stdin: params.stdin,
    })
}

/// Starts a vhost-user console device.
/// Returns an error if the given `args` is invalid or the device fails to run.
pub fn run_console_device(opts: Options) -> anyhow::Result<()> {
    // try to start a multiport console first
    if !opts.port.is_empty() {
        return run_multi_port_device(opts);
    }

    // fall back to a multiport disabled console
    let type_ = match opts.output_file {
        Some(_) => {
            if opts.syslog {
                bail!("--output-file and --syslog options cannot be used together.");
            }
            SerialType::File
        }
        None => {
            if opts.syslog {
                SerialType::Syslog
            } else {
                SerialType::Stdout
            }
        }
    };

    let params = SerialParameters {
        type_,
        hardware: SerialHardware::VirtioConsole,
        // Required only if type_ is SerialType::File or SerialType::UnixSocket
        path: opts.output_file,
        input: opts.input_file,
        num: 1,
        console: true,
        earlycon: false,
        // We don't use stdin if syslog mode is enabled
        stdin: !opts.syslog,
        out_timestamp: false,
        ..Default::default()
    };

    // We won't jail the device and can simply ignore `keep_rds`.
    let device = Box::new(create_vu_console_device(&params, &mut Vec::new())?);
    let ex = Executor::new().context("Failed to create executor")?;

    let listener = VhostUserListener::new_socket(&opts.socket, None)?;

    listener.run_device(ex, device)
}
