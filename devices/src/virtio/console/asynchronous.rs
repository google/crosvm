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
use crate::virtio::console::multiport::ConsolePortInfo;
use crate::virtio::console::multiport::ControlPort;
use crate::virtio::console::virtio_console_config;
use crate::virtio::console::ConsoleError;
use crate::virtio::copy_config;
use crate::virtio::device_constants::console::VIRTIO_CONSOLE_F_MULTIPORT;
use crate::virtio::DeviceType;
use crate::virtio::Interrupt;
use crate::virtio::Queue;
use crate::virtio::VirtioDevice;
use crate::PciAddress;
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

pub struct ConsolePort {
    input: Option<AsyncQueueState<AsyncSerialInput>>,
    output: AsyncQueueState<Box<dyn io::Write + Send>>,
    info: ConsolePortInfo,
}

impl SerialDevice for ConsolePort {
    fn new(
        _protection_type: ProtectionType,
        _evt: Event,
        input: Option<Box<dyn SerialInput>>,
        output: Option<Box<dyn io::Write + Send>>,
        _sync: Option<Box<dyn FileSync + Send>>,
        options: SerialOptions,
        _keep_rds: Vec<RawDescriptor>,
    ) -> ConsolePort {
        let input = input.map(AsyncSerialInput).map(AsyncQueueState::Stopped);
        let output = AsyncQueueState::Stopped(output.unwrap_or_else(|| Box::new(io::sink())));
        let info = ConsolePortInfo {
            console: options.console,
            name: options.name.unwrap_or_default(),
        };

        ConsolePort {
            input,
            output,
            info,
        }
    }

    #[cfg(windows)]
    fn new_with_pipe(
        _protection_type: ProtectionType,
        _interrupt_evt: Event,
        _pipe_in: named_pipes::PipeConnection,
        _pipe_out: named_pipes::PipeConnection,
        _options: SerialOptions,
        _keep_rds: Vec<RawDescriptor>,
    ) -> ConsolePort {
        unimplemented!("new_with_pipe unimplemented for ConsolePort");
    }
}

impl ConsolePort {
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

/// Console device with an optional control port to support for multiport
pub struct ConsoleDevice {
    avail_features: u64,
    // Port 0 always exists.
    port0: ConsolePort,
    // Control port, if multiport is in use.
    control_port: Option<ControlPort>,
    // Port 1..n, if they exist.
    extra_ports: Vec<ConsolePort>,
}

impl ConsoleDevice {
    /// Create a console device with the multiport feature enabled
    /// The multiport feature is referred to virtio spec.
    pub fn new_multi_port(
        protection_type: ProtectionType,
        port0: ConsolePort,
        extra_ports: Vec<ConsolePort>,
    ) -> ConsoleDevice {
        let avail_features =
            virtio::base_features(protection_type) | (1 << VIRTIO_CONSOLE_F_MULTIPORT);

        let info = std::iter::once(&port0)
            .chain(extra_ports.iter())
            .map(|port| port.info.clone())
            .collect::<Vec<_>>();

        ConsoleDevice {
            avail_features,
            port0,
            control_port: Some(ControlPort::new(info)),
            extra_ports,
        }
    }

    /// Return available features
    pub fn avail_features(&self) -> u64 {
        self.avail_features
    }

    /// Return whether current console device supports multiport feature
    pub fn is_multi_port(&self) -> bool {
        self.avail_features & (1 << VIRTIO_CONSOLE_F_MULTIPORT) != 0
    }

    /// Return the number of the port initiated by the console device
    pub fn max_ports(&self) -> usize {
        1 + self.extra_ports.len()
    }

    /// Returns the maximum number of queues supported by this device.
    pub fn max_queues(&self) -> usize {
        // The port 0 receive and transmit queues always exist;
        // other queues only exist if VIRTIO_CONSOLE_F_MULTIPORT is set.
        if self.is_multi_port() {
            let port_num = self.max_ports();

            // Extra 1 is for control port; each port has two queues (tx & rx)
            (port_num + 1) * 2
        } else {
            2
        }
    }

    /// Return the reference of the console port by port_id
    fn get_console_port(&mut self, port_id: usize) -> anyhow::Result<&mut ConsolePort> {
        match port_id {
            0 => Ok(&mut self.port0),
            port_id => self
                .extra_ports
                .get_mut(port_id - 1)
                .with_context(|| format!("failed to get console port {}", port_id)),
        }
    }

    /// Start the queue with the index `idx`
    pub fn start_queue(
        &mut self,
        ex: &Executor,
        idx: usize,
        queue: Arc<Mutex<virtio::Queue>>,
        doorbell: Interrupt,
    ) -> anyhow::Result<()> {
        match idx {
            // rxq (port0)
            0 => self.port0.start_receive_queue(ex, queue, doorbell),
            // txq (port0)
            1 => self.port0.start_transmit_queue(ex, queue, doorbell),
            // control port rxq
            2 => self
                .control_port
                .as_mut()
                .unwrap()
                .start_receive_queue(ex, queue, doorbell),
            // control port txq
            3 => self
                .control_port
                .as_mut()
                .unwrap()
                .start_transmit_queue(ex, queue, doorbell),
            // {4, 5} -> port1 {rxq, txq} if exist
            // {6, 7} -> port2 {rxq, txq} if exist
            // ...
            _ => {
                let port_id = idx / 2 - 1;
                let port = self.get_console_port(port_id)?;
                match idx % 2 {
                    0 => port.start_receive_queue(ex, queue, doorbell),
                    1 => port.start_transmit_queue(ex, queue, doorbell),
                    _ => unreachable!(),
                }
            }
        }
    }

    /// Stop the queue with the index `idx`
    pub fn stop_queue(&mut self, idx: usize) -> anyhow::Result<bool> {
        match idx {
            0 => self
                .port0
                .stop_receive_queue()
                .context("failed to stop rx queue"),
            1 => self
                .port0
                .stop_transmit_queue()
                .context("failed to stop tx queue"),
            2 => self.control_port.as_mut().unwrap().stop_receive_queue(),
            3 => self.control_port.as_mut().unwrap().stop_transmit_queue(),
            _ => {
                let port_id = idx / 2 - 1;
                let port = self.get_console_port(port_id)?;
                match idx % 2 {
                    0 => port.stop_receive_queue().context("failed to stop rx queue"),
                    1 => port
                        .stop_transmit_queue()
                        .context("failed to stop tx queue"),
                    _ => unreachable!(),
                }
            }
        }
    }
}

impl SerialDevice for ConsoleDevice {
    /// Create a default console device, without multiport support
    fn new(
        protection_type: ProtectionType,
        evt: Event,
        input: Option<Box<dyn SerialInput>>,
        output: Option<Box<dyn io::Write + Send>>,
        sync: Option<Box<dyn FileSync + Send>>,
        options: SerialOptions,
        keep_rds: Vec<RawDescriptor>,
    ) -> ConsoleDevice {
        let avail_features =
            virtio::base_features(protection_type) | 1 << VHOST_USER_F_PROTOCOL_FEATURES;
        let port0 = ConsolePort::new(protection_type, evt, input, output, sync, options, keep_rds);

        ConsoleDevice {
            avail_features,
            port0,
            control_port: None,
            extra_ports: vec![],
        }
    }

    #[cfg(windows)]
    fn new_with_pipe(
        _protection_type: ProtectionType,
        _interrupt_evt: Event,
        _pipe_in: named_pipes::PipeConnection,
        _pipe_out: named_pipes::PipeConnection,
        _options: SerialOptions,
        _keep_rds: Vec<RawDescriptor>,
    ) -> ConsoleDevice {
        unimplemented!("new_with_pipe unimplemented for ConsoleDevice");
    }
}

/// Virtio console device.
pub struct AsyncConsole {
    console_device: Option<ConsoleDevice>,
    worker_thread: Option<WorkerThread<anyhow::Result<ConsoleDevice>>>,
    base_features: u64,
    keep_descriptors: Vec<Descriptor>,
    pci_address: Option<PciAddress>,
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
        let pci_address = options.pci_address;
        AsyncConsole {
            console_device: Some(ConsoleDevice::new(
                protection_type,
                evt,
                input,
                output,
                sync,
                options,
                Default::default(),
            )),
            worker_thread: None,
            base_features: base_features(protection_type),
            keep_descriptors: keep_rds.iter().copied().map(Descriptor).collect(),
            pci_address,
        }
    }

    #[cfg(windows)]
    fn new_with_pipe(
        _protection_type: ProtectionType,
        _interrupt_evt: Event,
        _pipe_in: named_pipes::PipeConnection,
        _pipe_out: named_pipes::PipeConnection,
        _options: SerialOptions,
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

        let console = self.console_device.take().context("no console_device")?;

        let ex = Executor::new().expect("failed to create an executor");
        let receive_queue = queues.remove(&0).unwrap();
        let transmit_queue = queues.remove(&1).unwrap();

        self.worker_thread = Some(WorkerThread::start("v_console", move |kill_evt| {
            let mut console = console;
            let receive_queue = Arc::new(Mutex::new(receive_queue));
            let transmit_queue = Arc::new(Mutex::new(transmit_queue));

            // Start transmit queue of port 0
            console.start_queue(&ex, 0, receive_queue, interrupt.clone())?;
            // Start receive queue of port 0
            console.start_queue(&ex, 1, transmit_queue, interrupt.clone())?;

            // Run until the kill event is signaled and cancel all tasks.
            ex.run_until(async {
                async_utils::await_and_exit(&ex, kill_evt).await?;
                let port = &mut console.port0;
                if let Some(input) = port.input.as_mut() {
                    input
                        .stop_async()
                        .await
                        .context("failed to stop rx queue")?;
                }
                port.output
                    .stop_async()
                    .await
                    .context("failed to stop tx queue")?;

                Ok(console)
            })?
        }));

        Ok(())
    }

    fn pci_address(&self) -> Option<PciAddress> {
        self.pci_address
    }

    fn reset(&mut self) -> anyhow::Result<()> {
        if let Some(worker_thread) = self.worker_thread.take() {
            let console = worker_thread.stop()?;
            self.console_device = Some(console);
        }
        Ok(())
    }
}
