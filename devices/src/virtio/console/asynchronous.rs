// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Asynchronous console device which implementation can be shared by VMM and vhost-user.

use std::collections::VecDeque;
use std::io;
use std::thread;

use anyhow::anyhow;
use anyhow::Context;
use base::error;
use base::AsRawDescriptor;
use base::Event;
use base::FileSync;
use base::RawDescriptor;
use cros_async::select2;
use cros_async::AsyncResult;
use cros_async::EventAsync;
use cros_async::Executor;
use cros_async::IntoAsync;
use cros_async::IoSourceExt;
use futures::FutureExt;
use hypervisor::ProtectionType;
use vm_memory::GuestMemory;
use vmm_vhost::message::VhostUserVirtioFeatures;
use zerocopy::AsBytes;

use super::handle_input;
use super::process_transmit_queue;
use super::QUEUE_SIZES;
use crate::serial_device::SerialInput;
use crate::virtio;
use crate::virtio::async_device::AsyncQueueState;
use crate::virtio::async_utils;
use crate::virtio::base_features;
use crate::virtio::copy_config;
use crate::virtio::virtio_console_config;
use crate::virtio::ConsoleError;
use crate::virtio::DeviceType;
use crate::virtio::Interrupt;
use crate::virtio::Queue;
use crate::virtio::SignalableInterrupt;
use crate::virtio::VirtioDevice;
use crate::SerialDevice;
use crate::Suspendable;

/// Wrapper that makes any `SerialInput` usable as an async source by providing an implementation of
/// `IntoAsync`.
struct AsyncSerialInput(Box<dyn SerialInput>);
impl AsRawDescriptor for AsyncSerialInput {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.0.get_read_notifier().as_raw_descriptor()
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

    loop {
        match input.read_to_vec(None, rx_buf).await {
            // Input source has closed.
            Ok((0, _)) => break,
            Ok((size, v)) => {
                in_buffer.extend(&v[0..size]);
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

pub struct ConsoleDevice {
    input: Option<AsyncQueueState<AsyncSerialInput>>,
    output: AsyncQueueState<Box<dyn io::Write + Send>>,
    avail_features: u64,
}

impl ConsoleDevice {
    pub fn avail_features(&self) -> u64 {
        self.avail_features
    }

    pub fn start_receive_queue<I: SignalableInterrupt + 'static>(
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

    pub fn stop_receive_queue(&mut self) -> AsyncResult<bool> {
        if let Some(queue) = self.input.as_mut() {
            queue.stop()
        } else {
            Ok(false)
        }
    }

    pub fn start_transmit_queue<I: SignalableInterrupt + 'static>(
        &mut self,
        ex: &Executor,
        mem: GuestMemory,
        queue: virtio::Queue,
        doorbell: I,
        kick_evt: Event,
    ) -> anyhow::Result<()> {
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

        self.output.start(ex, tx_future)
    }

    pub fn stop_transmit_queue(&mut self) -> AsyncResult<bool> {
        self.output.stop()
    }
}

impl SerialDevice for ConsoleDevice {
    fn new(
        protection_type: ProtectionType,
        _evt: Event,
        input: Option<Box<dyn SerialInput>>,
        output: Option<Box<dyn io::Write + Send>>,
        _sync: Option<Box<dyn FileSync + Send>>,
        _out_timestamp: bool,
        _keep_rds: Vec<RawDescriptor>,
    ) -> ConsoleDevice {
        let avail_features = virtio::base_features(protection_type)
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        ConsoleDevice {
            input: input.map(AsyncSerialInput).map(AsyncQueueState::Stopped),
            output: AsyncQueueState::Stopped(output.unwrap_or_else(|| Box::new(io::sink()))),
            avail_features,
        }
    }
}

enum VirtioConsoleState {
    Stopped(ConsoleDevice),
    Running {
        kill_evt: Event,
        worker_thread: thread::JoinHandle<anyhow::Result<ConsoleDevice>>,
    },
    Broken,
}

/// Virtio console device.
pub struct AsyncConsole {
    state: VirtioConsoleState,
    base_features: u64,
    keep_rds: Vec<RawDescriptor>,
}

impl SerialDevice for AsyncConsole {
    fn new(
        protection_type: ProtectionType,
        evt: Event,
        input: Option<Box<dyn SerialInput>>,
        output: Option<Box<dyn io::Write + Send>>,
        sync: Option<Box<dyn FileSync + Send>>,
        out_timestamp: bool,
        keep_rds: Vec<RawDescriptor>,
    ) -> AsyncConsole {
        AsyncConsole {
            state: VirtioConsoleState::Stopped(ConsoleDevice::new(
                protection_type,
                evt,
                input,
                output,
                sync,
                out_timestamp,
                Default::default(),
            )),
            base_features: base_features(protection_type),
            keep_rds,
        }
    }
}

impl Drop for AsyncConsole {
    fn drop(&mut self) {
        let _ = self.reset();
    }
}

impl VirtioDevice for AsyncConsole {
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        self.keep_rds.clone()
    }

    fn features(&self) -> u64 {
        self.base_features
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::Console
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let config = virtio_console_config {
            max_nr_ports: 1.into(),
            ..Default::default()
        };
        copy_config(data, 0, config.as_bytes(), offset);
    }

    fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt: Interrupt,
        mut queues: Vec<(Queue, Event)>,
    ) -> anyhow::Result<()> {
        if queues.len() < 2 {
            return Err(anyhow!("expected 2 queues, got {}", queues.len()));
        }

        // Reset the device if it was already running.
        if matches!(self.state, VirtioConsoleState::Running { .. }) {
            self.reset();
        }

        let state = std::mem::replace(&mut self.state, VirtioConsoleState::Broken);
        let console = match state {
            VirtioConsoleState::Running { .. } => {
                return Err(anyhow!("device should not be running here. This is a bug."));
            }
            VirtioConsoleState::Stopped(console) => console,
            VirtioConsoleState::Broken => {
                return Err(anyhow!("device is broken and cannot be activated"));
            }
        };

        let (self_kill_evt, kill_evt) = Event::new()
            .and_then(|e| Ok((e.try_clone()?, e)))
            .context("failed creating kill Event pair")?;

        let ex = Executor::new().expect("failed to create an executor");
        let (receive_queue, receive_evt) = queues.remove(0);
        let (transmit_queue, transmit_evt) = queues.remove(0);

        let worker_thread = thread::Builder::new()
            .name("v_console".to_string())
            .spawn(move || {
                let mut console = console;

                console.start_receive_queue(
                    &ex,
                    mem.clone(),
                    receive_queue,
                    interrupt.clone(),
                    receive_evt,
                )?;

                console.start_transmit_queue(&ex, mem, transmit_queue, interrupt, transmit_evt)?;

                // Run until the kill event is signaled and cancel all tasks.
                ex.run_until(async {
                    async_utils::await_and_exit(&ex, kill_evt).await?;
                    if let Some(input) = console.input.as_mut() {
                        input.stop().context("failed to stop rx queue")?;
                    }
                    console.output.stop().context("failed to stop tx queue")?;

                    Ok(console)
                })?
            })
            .context("failed to spawn virtio_console worker")?;

        self.state = VirtioConsoleState::Running {
            kill_evt: self_kill_evt,
            worker_thread,
        };

        Ok(())
    }

    fn reset(&mut self) -> bool {
        match std::mem::replace(&mut self.state, VirtioConsoleState::Broken) {
            // Stopped console is already in reset state.
            state @ VirtioConsoleState::Stopped(_) => {
                self.state = state;
                true
            }
            // Stop the worker thread and go back to `Stopped` state.
            VirtioConsoleState::Running {
                kill_evt,
                worker_thread,
            } => match kill_evt.signal() {
                Ok(_) => {
                    let thread_res = match worker_thread.join() {
                        Ok(thread_res) => thread_res,
                        Err(_) => {
                            error!("worker thread has panicked");
                            return false;
                        }
                    };

                    match thread_res {
                        Ok(console) => {
                            self.state = VirtioConsoleState::Stopped(console);
                            true
                        }
                        Err(e) => {
                            error!("worker thread returned an error: {}", e);
                            false
                        }
                    }
                }
                Err(e) => {
                    error!("error while requesting worker thread to stop: {}", e);
                    error!("the worker thread will keep running");
                    false
                }
            },
            // We are broken and cannot reset properly.
            VirtioConsoleState::Broken => false,
        }
    }
}

impl Suspendable for AsyncConsole {}
