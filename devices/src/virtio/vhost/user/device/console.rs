// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use argh::FromArgs;
use base::error;
use base::Event;
use base::RawDescriptor;
use base::Terminal;
use cros_async::Executor;
use data_model::Le32;
use hypervisor::ProtectionType;
use sync::Mutex;
use vm_memory::GuestMemory;
use vmm_vhost::message::VhostUserProtocolFeatures;
use vmm_vhost::VhostUserSlaveReqHandler;
use vmm_vhost::VHOST_USER_F_PROTOCOL_FEATURES;
use zerocopy::AsBytes;

use crate::virtio;
use crate::virtio::console::asynchronous::ConsoleDevice;
use crate::virtio::console::asynchronous::ConsolePort;
use crate::virtio::console::virtio_console_config;
use crate::virtio::copy_config;
use crate::virtio::vhost::user::device::handler::DeviceRequestHandler;
use crate::virtio::vhost::user::device::handler::Error as DeviceError;
use crate::virtio::vhost::user::device::handler::VhostUserBackend;
use crate::virtio::vhost::user::device::listener::sys::VhostUserListener;
use crate::virtio::vhost::user::device::listener::VhostUserListenerTrait;
use crate::virtio::vhost::user::device::VhostUserDevice;
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

impl VhostUserDevice for VhostUserConsoleDevice {
    fn max_queue_num(&self) -> usize {
        // The port 0 receive and transmit queues always exist;
        // other queues only exist if VIRTIO_CONSOLE_F_MULTIPORT is set.
        if self.console.is_multi_port() {
            let port_num = self.console.max_ports();

            // Extra 1 is for control port; each port has two queues (tx & rx)
            (port_num + 1) * 2
        } else {
            2
        }
    }

    fn into_req_handler(
        self: Box<Self>,
        ex: &Executor,
    ) -> anyhow::Result<Box<dyn VhostUserSlaveReqHandler>> {
        if self.raw_stdin {
            // Set stdin() to raw mode so we can send over individual keystrokes unbuffered
            std::io::stdin()
                .set_raw_mode()
                .context("failed to set terminal in raw mode")?;
        }

        let queue_num = self.max_queue_num();
        let active_queues = vec![None; queue_num];

        let backend = ConsoleBackend {
            device: *self,
            acked_features: 0,
            acked_protocol_features: VhostUserProtocolFeatures::empty(),
            ex: ex.clone(),
            active_queues,
        };

        let handler = DeviceRequestHandler::new(Box::new(backend));
        Ok(Box::new(handler))
    }
}

struct ConsoleBackend {
    device: VhostUserConsoleDevice,
    acked_features: u64,
    acked_protocol_features: VhostUserProtocolFeatures,
    ex: Executor,
    active_queues: Vec<Option<Arc<Mutex<Queue>>>>,
}

impl VhostUserBackend for ConsoleBackend {
    fn max_queue_num(&self) -> usize {
        self.device.max_queue_num()
    }

    fn features(&self) -> u64 {
        self.device.console.avail_features() | 1 << VHOST_USER_F_PROTOCOL_FEATURES
    }

    fn ack_features(&mut self, value: u64) -> anyhow::Result<()> {
        let unrequested_features = value & !self.features();
        if unrequested_features != 0 {
            bail!("invalid features are given: {:#x}", unrequested_features);
        }

        self.acked_features |= value;

        Ok(())
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::CONFIG | VhostUserProtocolFeatures::MQ
    }

    fn ack_protocol_features(&mut self, features: u64) -> anyhow::Result<()> {
        let features = VhostUserProtocolFeatures::from_bits(features)
            .ok_or_else(|| anyhow!("invalid protocol features are given: {:#x}", features))?;
        let supported = self.protocol_features();
        self.acked_protocol_features = features & supported;
        Ok(())
    }

    fn acked_protocol_features(&self) -> u64 {
        self.acked_protocol_features.bits()
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let max_nr_ports = self.device.console.max_ports();
        let config = virtio_console_config {
            max_nr_ports: Le32::from(max_nr_ports as u32),
            ..Default::default()
        };
        copy_config(data, 0, config.as_bytes(), offset);
    }

    fn reset(&mut self) {
        for queue_num in 0..self.max_queue_num() {
            if let Err(e) = self.stop_queue(queue_num) {
                error!("Failed to stop_queue during reset: {}", e);
            }
        }
    }

    fn start_queue(
        &mut self,
        idx: usize,
        queue: virtio::Queue,
        _mem: GuestMemory,
        doorbell: Interrupt,
    ) -> anyhow::Result<()> {
        let queue = Arc::new(Mutex::new(queue));
        let res = self
            .device
            .console
            .start_queue(&self.ex, idx, queue.clone(), doorbell);

        self.active_queues[idx].replace(queue);

        res
    }

    fn stop_queue(&mut self, idx: usize) -> anyhow::Result<virtio::Queue> {
        if let Err(e) = self.device.console.stop_queue(idx) {
            error!("error while stopping queue {}: {}", idx, e);
        }

        if let Some(active_queue) = self.active_queues[idx].take() {
            let queue = Arc::try_unwrap(active_queue)
                .expect("failed to recover queue from worker")
                .into_inner();
            Ok(queue)
        } else {
            Err(anyhow::Error::new(DeviceError::WorkerNotFound))
        }
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
    let mut ports = params
        .iter()
        .map(|x| {
            let port = x
                .create_serial_device::<ConsolePort>(
                    ProtectionType::Unprotected,
                    // We need to pass an event as per Serial Device API but we don't really use it anyway.
                    &Event::new()?,
                    keep_rds,
                )
                .expect("failed to create multiport console");

            Ok(port)
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let port0 = ports.remove(0);
    let device = ConsoleDevice::new_multi_port(ProtectionType::Unprotected, port0, ports);

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
