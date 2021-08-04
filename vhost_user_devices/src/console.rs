// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io::{self, stdin};
use std::path::PathBuf;
use std::sync::mpsc::Receiver;
use std::sync::Arc;

use devices::virtio::copy_config;

use anyhow::{anyhow, bail, Context};
use arch::serial::{SerialHardware, SerialParameters, SerialType};
use base::{error, warn, Event, RawDescriptor, Terminal};
use cros_async::{EventAsync, Executor};
use data_model::DataInit;
use devices::serial_device::SerialDevice;
use devices::virtio;
use devices::virtio::console::{
    handle_input, process_transmit_queue, spawn_input_thread, virtio_console_config, ConsoleError,
};
use devices::ProtectionType;
use futures::future::{AbortHandle, Abortable};
use getopts::Options;
use once_cell::sync::OnceCell;
use sync::Mutex;
use vhost_user_devices::{CallEvent, DeviceRequestHandler, VhostUserBackend};
use vm_memory::GuestMemory;
use vmm_vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};

static CONSOLE_EXECUTOR: OnceCell<Executor> = OnceCell::new();

async fn run_tx_queue(
    mut queue: virtio::Queue,
    mem: GuestMemory,
    call_evt: Arc<Mutex<CallEvent>>,
    kick_evt: EventAsync,
    mut output: Box<dyn io::Write>,
) {
    loop {
        if let Err(e) = kick_evt.next_val().await {
            error!("Failed to read kick event for tx queue: {}", e);
            break;
        }
        process_transmit_queue(&mem, &call_evt, &mut queue, &mut output);
    }
}

async fn run_rx_queue(
    mut queue: virtio::Queue,
    mem: GuestMemory,
    call_evt: Arc<Mutex<CallEvent>>,
    kick_evt: EventAsync,
    in_channel: Receiver<Vec<u8>>,
    in_avail_evt: EventAsync,
) {
    loop {
        if let Err(e) = in_avail_evt.next_val().await {
            error!("Failed reading in_avail_evt: {}", e);
            break;
        }
        match handle_input(&mem, &call_evt, &in_channel, &mut queue) {
            Ok(()) => {}
            Err(ConsoleError::RxDescriptorsExhausted) => {
                if let Err(e) = kick_evt.next_val().await {
                    error!("Failed to read kick event for rx queue: {}", e);
                    break;
                }
            }
            Err(e) => {
                error!("Failed to process rx queue: {}", e);
                break;
            }
        }
    }
}

struct ConsoleBackend {
    input: Option<Box<dyn io::Read + Send>>,
    output: Option<Box<dyn io::Write + Send>>,
    avail_features: u64,
    acked_features: u64,
    acked_protocol_features: VhostUserProtocolFeatures,
    workers: [Option<AbortHandle>; Self::MAX_QUEUE_NUM],
}

impl SerialDevice for ConsoleBackend {
    fn new(
        protected_vm: ProtectionType,
        _evt: Event,
        input: Option<Box<dyn io::Read + Send>>,
        output: Option<Box<dyn io::Write + Send>>,
        _keep_rds: Vec<RawDescriptor>,
    ) -> ConsoleBackend {
        let avail_features = 1u64 << crate::virtio::VIRTIO_F_VERSION_1
            | virtio::base_features(protected_vm)
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        ConsoleBackend {
            input,
            output,
            avail_features,
            acked_features: 0,
            acked_protocol_features: VhostUserProtocolFeatures::empty(),
            workers: Default::default(),
        }
    }
}

impl VhostUserBackend for ConsoleBackend {
    const MAX_QUEUE_NUM: usize = 2; /* transmit and receive queues */
    const MAX_VRING_LEN: u16 = 256;

    type Error = anyhow::Error;

    fn features(&self) -> u64 {
        self.avail_features
    }

    fn ack_features(&mut self, value: u64) -> anyhow::Result<()> {
        let unrequested_features = value & !self.avail_features;
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
        for handle in self.workers.iter_mut().filter_map(Option::take) {
            handle.abort();
        }
    }

    fn start_queue(
        &mut self,
        idx: usize,
        mut queue: virtio::Queue,
        mem: GuestMemory,
        call_evt: Arc<Mutex<CallEvent>>,
        kick_evt: Event,
    ) -> anyhow::Result<()> {
        if let Some(handle) = self.workers.get_mut(idx).and_then(Option::take) {
            warn!("Starting new queue handler without stopping old handler");
            handle.abort();
        }

        // Enable any virtqueue features that were negotiated (like VIRTIO_RING_F_EVENT_IDX).
        queue.ack_features(self.acked_features);

        // Safe because the executor is initialized in main() below.
        let ex = CONSOLE_EXECUTOR.get().expect("Executor not initialized.");

        let kick_evt =
            EventAsync::new(kick_evt.0, ex).context("Failed to create EventAsync for kick_evt")?;
        let (handle, registration) = AbortHandle::new_pair();
        match idx {
            // ReceiveQueue
            0 => {
                // See explanation in devices/src/virtio/console.rs
                // We need a multithreaded input polling because io::Read only provides
                // a blocking interface which we cannot use in an async function.
                let in_avail_evt = match Event::new() {
                    Ok(evt) => evt,
                    Err(e) => {
                        bail!("Failed creating Event: {}", e);
                    }
                };

                let input_unpacked = self
                    .input
                    .take()
                    .ok_or_else(|| anyhow!("input source unavailable"))?;
                let in_channel = spawn_input_thread(input_unpacked, &in_avail_evt)
                    .take()
                    .ok_or_else(|| anyhow!("input channel unavailable"))?;

                // Create the async 'in' event so we can await on it.
                let in_avail_async_evt = EventAsync::new(in_avail_evt.0, ex)
                    .context("Failed to create EventAsync for in_avail_evt")?;

                ex.spawn_local(Abortable::new(
                    run_rx_queue(
                        queue,
                        mem,
                        call_evt,
                        kick_evt,
                        in_channel,
                        in_avail_async_evt,
                    ),
                    registration,
                ))
                .detach();
            }
            // TransmitQueue
            1 => {
                // Take ownership of output writer.
                // Safe because output should always be initialized to something
                let output_unwrapped: Box<dyn io::Write + Send> = self
                    .output
                    .take()
                    .ok_or_else(|| anyhow!("no output available"))?;
                ex.spawn_local(Abortable::new(
                    run_tx_queue(queue, mem, call_evt, kick_evt, output_unwrapped),
                    registration,
                ))
                .detach();
            }
            _ => bail!("attempted to start unknown queue: {}", idx),
        }

        self.workers[idx] = Some(handle);
        Ok(())
    }

    fn stop_queue(&mut self, idx: usize) {
        if let Some(handle) = self.workers.get_mut(idx).and_then(Option::take) {
            handle.abort();
        }
    }
}

fn run_console(params: &SerialParameters, socket: &String) -> anyhow::Result<()> {
    // We need to pass an event as per Serial Device API but we don't really use it anyway.
    let evt = Event::new()?;
    // Same for keep_rds, we don't really use this.
    let mut keep_rds = Vec::new();
    let console = match params.create_serial_device::<ConsoleBackend>(
        ProtectionType::Unprotected,
        &evt,
        &mut keep_rds,
    ) {
        Ok(c) => c,
        Err(e) => bail!(e),
    };

    let handler = DeviceRequestHandler::new(console);
    let ex = Executor::new().context("Failed to create executor")?;

    let _ = CONSOLE_EXECUTOR.set(ex.clone());

    if let Err(e) = ex.run_until(handler.run(socket, &ex)) {
        bail!(e);
    }
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args();
    let mut opts = Options::new();
    opts.optflag("h", "help", "print this help menu");
    opts.optopt("", "socket", "path to a socket", "PATH");
    opts.optopt("", "output-file", "path to a file", "OUTFILE");
    opts.optopt("", "input-file", "path to a file", "INFILE");

    let program_name = args.next().expect("empty args");

    let matches = match opts.parse(args) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{}", e);
            eprintln!("{}", opts.short_usage(&program_name));
            return Ok(());
        }
    };

    if matches.opt_present("h") {
        println!("{}", opts.usage(&program_name));
        return Ok(());
    }

    if !matches.opt_present("socket") {
        println!("Must specify the socket for the vhost user device.");
        println!("{}", opts.usage(&program_name));
        return Ok(());
    }

    // We can unwrap after `opt_str()` safely because we just checked for it being present.
    let socket = matches.opt_str("socket").unwrap();

    let output_file = matches.opt_str("output-file").map(PathBuf::from);
    let input_file = matches.opt_str("input-file").map(PathBuf::from);

    base::syslog::init().context("Failed to initialize syslog")?;

    // Set stdin() in raw mode so we can send over individual keystrokes unbuffered
    stdin()
        .set_raw_mode()
        .context("Failed to set terminal raw mode")?;

    let type_ = match output_file {
        Some(_) => SerialType::File,
        None => SerialType::Stdout,
    };

    let params = SerialParameters {
        type_,
        hardware: SerialHardware::VirtioConsole,
        // Required only if type_ is SerialType::File or SerialType::UnixSocket
        path: output_file,
        input: input_file,
        num: 1,
        console: true,
        earlycon: false,
        // We do not support stdin-less mode
        stdin: true,
    };

    if let Err(e) = run_console(&params, &socket) {
        error!("Failed to run console device: {}", e);
    }

    // Restore terminal capabilities back to what they were before
    stdin()
        .set_canon_mode()
        .context("Failed to restore canonical mode for terminal")?;

    Ok(())
}
