// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Asynchronous console device which implementation can be shared by VMM and vhost-user.

use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::io;
use std::sync::Arc;

use anyhow::anyhow;
use anyhow::Context;
use base::error;
#[cfg(windows)]
use base::named_pipes;
use base::AsRawDescriptor;
use base::Descriptor;
use base::Event;
use base::FileSync;
use base::RawDescriptor;
use base::WorkerThread;
use cros_async::select2;
use cros_async::AsyncResult;
use cros_async::EventAsync;
use cros_async::Executor;
use cros_async::IntoAsync;
use cros_async::IoSource;
use futures::FutureExt;
use hypervisor::ProtectionType;
use sync::Mutex;
use vm_memory::GuestMemory;
use vmm_vhost::VHOST_USER_F_PROTOCOL_FEATURES;
use zerocopy::AsBytes;

use super::handle_input;
use super::process_transmit_queue;
use super::QUEUE_SIZES;
use crate::serial_device::SerialInput;
use crate::serial_device::SerialOptions;
use crate::virtio;
use crate::virtio::async_device::AsyncQueueState;
use crate::virtio::async_utils;
use crate::virtio::base_features;
use crate::virtio::console::virtio_console_config;
use crate::virtio::console::ConsoleError;
use crate::virtio::copy_config;
use crate::virtio::DeviceType;
use crate::virtio::Interrupt;
use crate::virtio::Queue;
use crate::virtio::VirtioDevice;
use crate::SerialDevice;

/// Wrapper that makes any `SerialInput` usable as an async source by providing an implementation of
/// `IntoAsync`.
struct AsyncSerialInput(Box<dyn SerialInput>);
impl AsRawDescriptor for AsyncSerialInput {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.0.get_read_notifier().as_raw_descriptor()
    }
}
impl IntoAsync for AsyncSerialInput {}

async fn run_tx_queue(
    queue: &Arc<Mutex<virtio::Queue>>,
    doorbell: Interrupt,
    kick_evt: EventAsync,
    output: &mut Box<dyn io::Write + Send>,
) {
    loop {
        if let Err(e) = kick_evt.next_val().await {
            error!("Failed to read kick event for tx queue: {}", e);
            break;
        }
        process_transmit_queue(&doorbell, queue, output.as_mut());
    }
}

async fn run_rx_queue(
    queue: &Arc<Mutex<virtio::Queue>>,
    doorbell: Interrupt,
    kick_evt: EventAsync,
    input: &IoSource<AsyncSerialInput>,
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
            match handle_input(&doorbell, &mut in_buffer, queue) {
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

    pub fn start_receive_queue(
        &mut self,
        ex: &Executor,
        queue: Arc<Mutex<virtio::Queue>>,
        doorbell: Interrupt,
    ) -> anyhow::Result<()> {
        let input_queue = match self.input.as_mut() {
            Some(input_queue) => input_queue,
            None => return Ok(()),
        };

        let kick_evt = queue
            .lock()
            .event()
            .try_clone()
            .context("Failed to clone queue event")?;
        let kick_evt =
            EventAsync::new(kick_evt, ex).context("Failed to create EventAsync for kick_evt")?;

        let closure_ex = ex.clone();
        let rx_future = move |input, abort| {
            let async_input = closure_ex
                .async_from(input)
                .context("failed to create async input")?;

            Ok(async move {
                select2(
                    run_rx_queue(&queue, doorbell, kick_evt, &async_input).boxed_local(),
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

    pub fn start_transmit_queue(
        &mut self,
        ex: &Executor,
        queue: Arc<Mutex<virtio::Queue>>,
        doorbell: Interrupt,
    ) -> anyhow::Result<()> {
        let kick_evt = queue
            .lock()
            .event()
            .try_clone()
            .context("Failed to clone queue event")?;
        let kick_evt =
            EventAsync::new(kick_evt, ex).context("Failed to create EventAsync for kick_evt")?;

        let tx_future = |mut output, abort| {
            Ok(async move {
                select2(
                    run_tx_queue(&queue, doorbell, kick_evt, &mut output).boxed_local(),
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
        _options: SerialOptions,
        _keep_rds: Vec<RawDescriptor>,
    ) -> ConsoleDevice {
        let avail_features =
            virtio::base_features(protection_type) | 1 << VHOST_USER_F_PROTOCOL_FEATURES;
        ConsoleDevice {
            input: input.map(AsyncSerialInput).map(AsyncQueueState::Stopped),
            output: AsyncQueueState::Stopped(output.unwrap_or_else(|| Box::new(io::sink()))),
            avail_features,
        }
    }

    #[cfg(windows)]
    fn new_with_pipe(
        _protection_type: ProtectionType,
        _interrupt_evt: Event,
        _pipe_in: named_pipes::PipeConnection,
        _pipe_out: named_pipes::PipeConnection,
        _keep_rds: Vec<RawDescriptor>,
    ) -> ConsoleDevice {
        unimplemented!("new_with_pipe unimplemented for ConsoleDevice");
    }
}

enum VirtioConsoleState {
    Stopped(ConsoleDevice),
    Running(WorkerThread<anyhow::Result<ConsoleDevice>>),
    Broken,
}

/// Virtio console device.
pub struct AsyncConsole {
    state: VirtioConsoleState,
    base_features: u64,
    keep_descriptors: Vec<Descriptor>,
}

impl SerialDevice for AsyncConsole {
    fn new(
        protection_type: ProtectionType,
        evt: Event,
        input: Option<Box<dyn SerialInput>>,
        output: Option<Box<dyn io::Write + Send>>,
        sync: Option<Box<dyn FileSync + Send>>,
        options: SerialOptions,
        keep_rds: Vec<RawDescriptor>,
    ) -> AsyncConsole {
        AsyncConsole {
            state: VirtioConsoleState::Stopped(ConsoleDevice::new(
                protection_type,
                evt,
                input,
                output,
                sync,
                options,
                Default::default(),
            )),
            base_features: base_features(protection_type),
            keep_descriptors: keep_rds.iter().copied().map(Descriptor).collect(),
        }
    }

    #[cfg(windows)]
    fn new_with_pipe(
        _protection_type: ProtectionType,
        _interrupt_evt: Event,
        _pipe_in: named_pipes::PipeConnection,
        _pipe_out: named_pipes::PipeConnection,
        _keep_rds: Vec<RawDescriptor>,
    ) -> AsyncConsole {
        unimplemented!("new_with_pipe unimplemented for AsyncConsole");
    }
}

impl VirtioDevice for AsyncConsole {
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        self.keep_descriptors
            .iter()
            .map(Descriptor::as_raw_descriptor)
            .collect()
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
        _mem: GuestMemory,
        interrupt: Interrupt,
        mut queues: BTreeMap<usize, Queue>,
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

        let ex = Executor::new().expect("failed to create an executor");
        let receive_queue = queues.remove(&0).unwrap();
        let transmit_queue = queues.remove(&1).unwrap();

        self.state =
            VirtioConsoleState::Running(WorkerThread::start("v_console", move |kill_evt| {
                let mut console = console;
                let receive_queue = Arc::new(Mutex::new(receive_queue));
                let transmit_queue = Arc::new(Mutex::new(transmit_queue));

                console.start_receive_queue(&ex, receive_queue, interrupt.clone())?;

                console.start_transmit_queue(&ex, transmit_queue, interrupt)?;

                // Run until the kill event is signaled and cancel all tasks.
                ex.run_until(async {
                    async_utils::await_and_exit(&ex, kill_evt).await?;
                    if let Some(input) = console.input.as_mut() {
                        input.stop().context("failed to stop rx queue")?;
                    }
                    console.output.stop().context("failed to stop tx queue")?;

                    Ok(console)
                })?
            }));

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
            VirtioConsoleState::Running(worker_thread) => {
                let thread_res = worker_thread.stop();
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
            // We are broken and cannot reset properly.
            VirtioConsoleState::Broken => false,
        }
    }
}
