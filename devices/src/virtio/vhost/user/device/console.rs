// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::VecDeque;
use std::io::{self, stdin};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context};
use base::{error, AsRawDescriptor, Event, FileSync, RawDescriptor, Terminal};
use cros_async::{select2, AsyncResult, EventAsync, Executor, IntoAsync, IoSourceExt};
use data_model::DataInit;

use argh::FromArgs;
use futures::FutureExt;
use hypervisor::ProtectionType;
use sync::Mutex;
use vm_memory::GuestMemory;
use vmm_vhost::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};

use crate::serial_device::{
    SerialDevice, SerialHardware, SerialInput, SerialParameters, SerialType,
};
use crate::virtio::async_device::AsyncQueueState;
use crate::virtio::console::{
    handle_input, process_transmit_queue, virtio_console_config, ConsoleError,
};
use crate::virtio::vhost::user::device::handler::{
    DeviceRequestHandler, Doorbell, VhostUserBackend,
};
use crate::virtio::vhost::user::device::vvu::pci::VvuPciDevice;
use crate::virtio::{self, copy_config, SignalableInterrupt};

/// Wrapper that makes any `SerialInput` usable as an async source by providing an implementation of
/// `IntoAsync`.
struct AsyncSerialInput(Box<dyn SerialInput>);
impl AsRawDescriptor for AsyncSerialInput {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.0.as_raw_descriptor()
    }
}
impl IntoAsync for AsyncSerialInput {}

async fn run_tx_queue<I: SignalableInterrupt>(
    mut queue: virtio::Queue,
    mem: GuestMemory,
    doorbell: I,
    kick_evt: EventAsync,
    output: &mut Box<dyn io::Write + Send>,
) {
    loop {
        if let Err(e) = kick_evt.next_val().await {
            error!("Failed to read kick event for tx queue: {}", e);
            break;
        }
        process_transmit_queue(&mem, &doorbell, &mut queue, output.as_mut());
    }
}

async fn run_rx_queue<I: SignalableInterrupt>(
    mut queue: virtio::Queue,
    mem: GuestMemory,
    doorbell: I,
    kick_evt: EventAsync,
    input: &dyn IoSourceExt<AsyncSerialInput>,
) {
    // Staging buffer, required because of `handle_input`'s API. We can probably remove this once
    // the regular virtio device is switched to async.
    let mut in_buffer = VecDeque::<u8>::new();
    let mut rx_buf = vec![0u8; 4096];
    let mut input_offset = 0u64;

    loop {
        match input.read_to_vec(Some(input_offset), rx_buf).await {
            // Input source has closed.
            Ok((0, _)) => break,
            Ok((size, v)) => {
                in_buffer.extend(&v[0..size]);
                input_offset += size as u64;
                rx_buf = v;
            }
            Err(e) => {
                error!("Failed to read console input: {}", e);
                return;
            }
        }

        // Submit all the data obtained during this read.
        while !in_buffer.is_empty() {
            match handle_input(&mem, &doorbell, &mut in_buffer, &mut queue) {
                Ok(()) => {}
                Err(ConsoleError::RxDescriptorsExhausted) => {
                    // Wait until a descriptor becomes available and try again.
                    if let Err(e) = kick_evt.next_val().await {
                        error!("Failed to read kick event for rx queue: {}", e);
                        return;
                    }
                }
            }
        }
    }
}

struct ConsoleDevice {
    input: Option<AsyncQueueState<AsyncSerialInput>>,
    output: Option<AsyncQueueState<Box<dyn io::Write + Send>>>,
    avail_features: u64,
}

impl ConsoleDevice {
    fn start_receive_queue<I: SignalableInterrupt + 'static>(
        &mut self,
        ex: &Executor,
        mem: GuestMemory,
        queue: virtio::Queue,
        doorbell: I,
        kick_evt: Event,
    ) -> anyhow::Result<()> {
        let input_queue = match self.input.as_mut() {
            Some(input_queue) => input_queue,
            None => return Ok(()),
        };

        let kick_evt =
            EventAsync::new(kick_evt, ex).context("Failed to create EventAsync for kick_evt")?;

        let closure_ex = ex.clone();
        let rx_future = move |input, abort| {
            let async_input = closure_ex
                .async_from(input)
                .context("failed to create async input")?;

            Ok(async move {
                select2(
                    run_rx_queue(queue, mem, doorbell, kick_evt, async_input.as_ref())
                        .boxed_local(),
                    abort,
                )
                .await;

                async_input.into_source()
            })
        };

        input_queue.start(ex, rx_future)
    }

    fn stop_receive_queue(&mut self) -> AsyncResult<bool> {
        if let Some(queue) = self.input.as_mut() {
            queue.stop()
        } else {
            Ok(false)
        }
    }

    fn start_transmit_queue<I: SignalableInterrupt + 'static>(
        &mut self,
        ex: &Executor,
        mem: GuestMemory,
        queue: virtio::Queue,
        doorbell: I,
        kick_evt: Event,
    ) -> anyhow::Result<()> {
        let output_queue = match self.output.as_mut() {
            Some(output_queue) => output_queue,
            None => return Ok(()),
        };

        let kick_evt =
            EventAsync::new(kick_evt, ex).context("Failed to create EventAsync for kick_evt")?;

        let tx_future = |mut output, abort| {
            Ok(async move {
                select2(
                    run_tx_queue(queue, mem, doorbell, kick_evt, &mut output).boxed_local(),
                    abort,
                )
                .await;

                output
            })
        };

        output_queue.start(ex, tx_future)
    }

    fn stop_transmit_queue(&mut self) -> AsyncResult<bool> {
        if let Some(queue) = self.output.as_mut() {
            queue.stop()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

impl SerialDevice for ConsoleDevice {
    fn new(
        protected_vm: ProtectionType,
        _evt: Event,
        input: Option<Box<dyn SerialInput>>,
        output: Option<Box<dyn io::Write + Send>>,
        _sync: Option<Box<dyn FileSync + Send>>,
        _out_timestamp: bool,
        _keep_rds: Vec<RawDescriptor>,
    ) -> ConsoleDevice {
        let avail_features =
            virtio::base_features(protected_vm) | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        ConsoleDevice {
            input: input.map(AsyncSerialInput).map(AsyncQueueState::Stopped),
            output: output.map(AsyncQueueState::Stopped),
            avail_features,
        }
    }
}

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
    const MAX_QUEUE_NUM: usize = 2; /* transmit and receive queues */
    const MAX_VRING_LEN: u16 = 256;

    type Error = anyhow::Error;

    fn features(&self) -> u64 {
        self.device.avail_features
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
        for queue_num in 0..Self::MAX_QUEUE_NUM {
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
    let handler = DeviceRequestHandler::new(backend);

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
            let device = VvuPciDevice::new(&vfio, ConsoleBackend::MAX_QUEUE_NUM)?;
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
