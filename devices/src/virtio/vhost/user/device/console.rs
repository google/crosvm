// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::{io::stdin, path::PathBuf, sync::Arc};

use anyhow::{anyhow, bail, Context};
use base::{error, Event, Terminal};
use cros_async::Executor;
use data_model::DataInit;

use argh::FromArgs;
use hypervisor::ProtectionType;
use sync::Mutex;
use vm_memory::GuestMemory;
use vmm_vhost::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};

use crate::{
    virtio::{
        self,
        console::{asynchronous::ConsoleDevice, virtio_console_config},
        copy_config,
        vhost::user::device::handler::{DeviceRequestHandler, Doorbell, VhostUserBackend},
        vhost::user::device::vvu::pci::VvuPciDevice,
    },
    SerialHardware, SerialParameters, SerialType,
};

const MAX_QUEUE_NUM: usize = 2 /* transmit and receive queues */;
const MAX_VRING_LEN: u16 = 256;

struct ConsoleBackend {
    ex: Executor,
    device: ConsoleDevice,
    acked_features: u64,
    acked_protocol_features: VhostUserProtocolFeatures,
}

impl ConsoleBackend {
    fn new(ex: &Executor, device: ConsoleDevice) -> Self {
        Self {
            ex: ex.clone(),
            device,
            acked_features: 0,
            acked_protocol_features: VhostUserProtocolFeatures::empty(),
        }
    }
}

impl VhostUserBackend for ConsoleBackend {
    fn max_queue_num(&self) -> usize {
        return MAX_QUEUE_NUM;
    }

    fn max_vring_len(&self) -> u16 {
        return MAX_VRING_LEN;
    }

    fn features(&self) -> u64 {
        self.device.avail_features() | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
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
        VhostUserProtocolFeatures::CONFIG
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
        let config = virtio_console_config {
            max_nr_ports: 1.into(),
            ..Default::default()
        };
        copy_config(data, 0, config.as_slice(), offset);
    }

    fn reset(&mut self) {
        for queue_num in 0..self.max_queue_num() {
            self.stop_queue(queue_num);
        }
    }

    fn start_queue(
        &mut self,
        idx: usize,
        mut queue: virtio::Queue,
        mem: GuestMemory,
        doorbell: Arc<Mutex<Doorbell>>,
        kick_evt: Event,
    ) -> anyhow::Result<()> {
        // Enable any virtqueue features that were negotiated (like VIRTIO_RING_F_EVENT_IDX).
        queue.ack_features(self.acked_features);

        match idx {
            // ReceiveQueue
            0 => self
                .device
                .start_receive_queue(&self.ex, mem, queue, doorbell, kick_evt),
            // TransmitQueue
            1 => self
                .device
                .start_transmit_queue(&self.ex, mem, queue, doorbell, kick_evt),
            _ => bail!("attempted to start unknown queue: {}", idx),
        }
    }

    fn stop_queue(&mut self, idx: usize) {
        match idx {
            0 => {
                if let Err(e) = self.device.stop_receive_queue() {
                    error!("error while stopping rx queue: {}", e);
                }
            }
            1 => {
                if let Err(e) = self.device.stop_transmit_queue() {
                    error!("error while stopping tx queue: {}", e);
                }
            }
            _ => error!("attempted to stop unknown queue: {}", idx),
        };
    }
}

#[derive(FromArgs)]
#[argh(subcommand, name = "console")]
/// Console device
pub struct Options {
    #[argh(option, arg_name = "PATH")]
    /// path to a vhost-user socket
    socket: Option<String>,
    #[argh(option, arg_name = "STRING")]
    /// VFIO-PCI device name (e.g. '0000:00:07.0')
    vfio: Option<String>,
    #[argh(option, arg_name = "OUTFILE")]
    /// path to a file
    output_file: Option<PathBuf>,
    #[argh(option, arg_name = "INFILE")]
    /// path to a file
    input_file: Option<PathBuf>,
}

/// Starts a vhost-user console device.
/// Returns an error if the given `args` is invalid or the device fails to run.
pub fn run_console_device(opts: Options) -> anyhow::Result<()> {
    let type_ = match opts.output_file {
        Some(_) => SerialType::File,
        None => SerialType::Stdout,
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
        // We do not support stdin-less mode
        stdin: true,
        out_timestamp: false,
        ..Default::default()
    };

    let console = match params.create_serial_device::<ConsoleDevice>(
        ProtectionType::Unprotected,
        // We need to pass an event as per Serial Device API but we don't really use it anyway.
        &Event::new()?,
        // Same for keep_rds, we don't really use this.
        &mut Vec::new(),
    ) {
        Ok(c) => c,
        Err(e) => bail!(e),
    };
    let ex = Executor::new().context("Failed to create executor")?;
    let backend = ConsoleBackend::new(&ex, console);
    let max_queue_num = backend.max_queue_num();
    let handler = DeviceRequestHandler::new(Box::new(backend));

    // Set stdin() in raw mode so we can send over individual keystrokes unbuffered
    stdin()
        .set_raw_mode()
        .context("Failed to set terminal raw mode")?;

    let res = match (opts.socket, opts.vfio) {
        (Some(socket), None) => {
            // run_until() returns an Result<Result<..>> which the ? operator lets us flatten.
            ex.run_until(handler.run(socket, &ex))?
        }
        (None, Some(vfio)) => {
            let device = VvuPciDevice::new(&vfio, max_queue_num)?;
            ex.run_until(handler.run_vvu(device, &ex))?
        }
        _ => Err(anyhow!("exactly one of `--socket` or `--vfio` is required")),
    };

    // Restore terminal capabilities back to what they were before
    stdin()
        .set_canon_mode()
        .context("Failed to restore canonical mode for terminal")?;

    res
}
