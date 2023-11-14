// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Legacy console device that uses a polling thread. This is kept because it is still used by
//! Windows ; outside of this use-case, please use [[asynchronous::AsyncConsole]] instead.

pub mod asynchronous;
mod sys;

use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::io;
use std::io::Read;
use std::io::Write;
use std::ops::DerefMut;
use std::result;
use std::sync::Arc;

use anyhow::anyhow;
use anyhow::Context;
use base::error;
use base::AsRawDescriptor;
use base::Descriptor;
use base::Event;
use base::EventToken;
use base::RawDescriptor;
#[cfg(windows)]
use base::ReadNotifier;
use base::WaitContext;
use base::WorkerThread;
use data_model::Le16;
use data_model::Le32;
use hypervisor::ProtectionType;
use remain::sorted;
use serde::Deserialize;
use serde::Serialize;
use sync::Mutex;
use thiserror::Error as ThisError;
use vm_memory::GuestMemory;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

use crate::serial::sys::InStreamType;
use crate::virtio::base_features;
use crate::virtio::copy_config;
use crate::virtio::DeviceType;
use crate::virtio::Interrupt;
use crate::virtio::Queue;
use crate::virtio::Reader;
use crate::virtio::VirtioDevice;

pub(crate) const QUEUE_SIZE: u16 = 256;

// For now, just implement port 0 (receiveq and transmitq).
// If VIRTIO_CONSOLE_F_MULTIPORT is implemented, more queues will be needed.
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE, QUEUE_SIZE];

#[sorted]
#[derive(ThisError, Debug)]
pub enum ConsoleError {
    /// There are no more available descriptors to receive into
    #[error("no rx descriptors available")]
    RxDescriptorsExhausted,
}

#[derive(Copy, Clone, Debug, Default, AsBytes, FromZeroes, FromBytes)]
#[repr(C)]
pub struct virtio_console_config {
    pub cols: Le16,
    pub rows: Le16,
    pub max_nr_ports: Le32,
    pub emerg_wr: Le32,
}

/// Checks for input from `buffer` and transfers it to the receive queue, if any.
///
/// # Arguments
///
/// * `interrupt` - Interrupt used to signal that the queue has been used
/// * `buffer` - Ring buffer providing data to put into the guest
/// * `receive_queue` - The receive virtio Queue
fn handle_input(
    interrupt: &Interrupt,
    buffer: &mut VecDeque<u8>,
    receive_queue: &Arc<Mutex<Queue>>,
) -> result::Result<(), ConsoleError> {
    let mut receive_queue = receive_queue
        .try_lock()
        .expect("Lock should not be unavailable");
    loop {
        let mut desc = receive_queue
            .peek()
            .ok_or(ConsoleError::RxDescriptorsExhausted)?;

        let writer = &mut desc.writer;
        while writer.available_bytes() > 0 && !buffer.is_empty() {
            let (buffer_front, buffer_back) = buffer.as_slices();
            let buffer_chunk = if !buffer_front.is_empty() {
                buffer_front
            } else {
                buffer_back
            };
            let written = writer.write(buffer_chunk).unwrap();
            drop(buffer.drain(..written));
        }

        let bytes_written = writer.bytes_written() as u32;

        if bytes_written > 0 {
            let desc = desc.pop();
            receive_queue.add_used(desc, bytes_written);
            receive_queue.trigger_interrupt(interrupt);
        }

        if bytes_written == 0 {
            return Ok(());
        }
    }
}

/// Writes the available data from the reader into the given output queue.
///
/// # Arguments
///
/// * `reader` - The Reader with the data we want to write.
/// * `output` - The output sink we are going to write the data to.
fn process_transmit_request(reader: &mut Reader, output: &mut dyn io::Write) -> io::Result<()> {
    let len = reader.available_bytes();
    let mut data = vec![0u8; len];
    reader.read_exact(&mut data)?;
    output.write_all(&data)?;
    output.flush()?;
    Ok(())
}

/// Processes the data taken from the given transmit queue into the output sink.
///
/// # Arguments
///
/// * `interrupt` - Interrupt used to signal (if required) that the queue has been used
/// * `transmit_queue` - The transmit virtio Queue
/// * `output` - The output sink we are going to write the data into
fn process_transmit_queue(
    interrupt: &Interrupt,
    transmit_queue: &Arc<Mutex<Queue>>,
    output: &mut dyn io::Write,
) {
    let mut needs_interrupt = false;
    let mut transmit_queue = transmit_queue
        .try_lock()
        .expect("Lock should not be unavailable");
    while let Some(mut avail_desc) = transmit_queue.pop() {
        process_transmit_request(&mut avail_desc.reader, output)
            .unwrap_or_else(|e| error!("console: process_transmit_request failed: {}", e));

        transmit_queue.add_used(avail_desc, 0);
        needs_interrupt = true;
    }

    if needs_interrupt {
        transmit_queue.trigger_interrupt(interrupt);
    }
}

struct Worker {
    interrupt: Interrupt,
    input: Option<Arc<Mutex<VecDeque<u8>>>>,
    output: Box<dyn io::Write + Send>,
    kill_evt: Event,
    in_avail_evt: Event,
    receive_queue: Arc<Mutex<Queue>>,
    transmit_queue: Arc<Mutex<Queue>>,
}

impl Worker {
    fn run(&mut self) -> anyhow::Result<()> {
        #[derive(EventToken)]
        enum Token {
            ReceiveQueueAvailable,
            TransmitQueueAvailable,
            InputAvailable,
            InterruptResample,
            Kill,
        }

        let wait_ctx: WaitContext<Token> = WaitContext::build_with(&[
            (
                self.transmit_queue.lock().event(),
                Token::TransmitQueueAvailable,
            ),
            (
                self.receive_queue.lock().event(),
                Token::ReceiveQueueAvailable,
            ),
            (&self.in_avail_evt, Token::InputAvailable),
            (&self.kill_evt, Token::Kill),
        ])?;
        if let Some(resample_evt) = self.interrupt.get_resample_evt() {
            wait_ctx.add(resample_evt, Token::InterruptResample)?;
        }

        let mut running = true;
        while running {
            let events = wait_ctx.wait()?;

            for event in events.iter().filter(|e| e.is_readable) {
                match event.token {
                    Token::TransmitQueueAvailable => {
                        self.transmit_queue
                            .lock()
                            .event()
                            .wait()
                            .context("failed reading transmit queue Event")?;
                        process_transmit_queue(
                            &self.interrupt,
                            &self.transmit_queue,
                            &mut self.output,
                        );
                    }
                    Token::ReceiveQueueAvailable => {
                        self.receive_queue
                            .lock()
                            .event()
                            .wait()
                            .context("failed reading receive queue Event")?;
                        if let Some(in_buf_ref) = self.input.as_ref() {
                            let _ = handle_input(
                                &self.interrupt,
                                in_buf_ref.lock().deref_mut(),
                                &self.receive_queue,
                            );
                        }
                    }
                    Token::InputAvailable => {
                        self.in_avail_evt
                            .wait()
                            .context("failed reading in_avail_evt")?;
                        if let Some(in_buf_ref) = self.input.as_ref() {
                            let _ = handle_input(
                                &self.interrupt,
                                in_buf_ref.lock().deref_mut(),
                                &self.receive_queue,
                            );
                        }
                    }
                    Token::InterruptResample => {
                        self.interrupt.interrupt_resample();
                    }
                    Token::Kill => running = false,
                }
            }
        }
        Ok(())
    }
}

/// Virtio console device.
pub struct Console {
    base_features: u64,
    in_avail_evt: Event,
    worker_thread: Option<WorkerThread<Worker>>,
    input: Option<InStreamType>,
    output: Option<Box<dyn io::Write + Send>>,
    keep_descriptors: Vec<Descriptor>,
    input_thread: Option<WorkerThread<InStreamType>>,
    // input_buffer is not continuously updated. It holds the state of the buffer when a snapshot
    // happens, or when a restore is performed. On a fresh startup, it will be empty. On a restore,
    // it will contain whatever data was remaining in the buffer in the snapshot.
    input_buffer: VecDeque<u8>,
}

#[derive(Serialize, Deserialize)]
struct ConsoleSnapshot {
    base_features: u64,
    input_buffer: VecDeque<u8>,
}

impl Console {
    fn new(
        protection_type: ProtectionType,
        input: Option<InStreamType>,
        output: Option<Box<dyn io::Write + Send>>,
        mut keep_rds: Vec<RawDescriptor>,
    ) -> Console {
        let in_avail_evt = Event::new().expect("failed creating Event");
        keep_rds.push(in_avail_evt.as_raw_descriptor());
        Console {
            base_features: base_features(protection_type),
            in_avail_evt,
            worker_thread: None,
            input,
            output,
            keep_descriptors: keep_rds.iter().map(|rd| Descriptor(*rd)).collect(),
            input_thread: None,
            input_buffer: VecDeque::new(),
        }
    }
}

impl VirtioDevice for Console {
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        // return the raw descriptors as opposed to descriptor.
        self.keep_descriptors
            .iter()
            .map(|descr| descr.as_raw_descriptor())
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

        let receive_queue = queues.remove(&0).unwrap();
        let transmit_queue = queues.remove(&1).unwrap();

        let in_avail_evt = self
            .in_avail_evt
            .try_clone()
            .context("failed creating input available Event pair")?;

        // Spawn a separate thread to poll self.input.
        // A thread is used because io::Read only provides a blocking interface, and there is no
        // generic way to add an io::Read instance to a poll context (it may not be backed by a file
        // descriptor).  Moving the blocking read call to a separate thread and sending data back to
        // the main worker thread with an event for notification bridges this gap.
        let input = match self.input.take() {
            Some(read) => {
                let (buffer, thread) = sys::spawn_input_thread(
                    read,
                    &self.in_avail_evt,
                    std::mem::take(&mut self.input_buffer),
                );
                self.input_thread = Some(thread);
                Some(buffer)
            }
            None => None,
        };
        let output = self.output.take().unwrap_or_else(|| Box::new(io::sink()));

        self.worker_thread = Some(WorkerThread::start("v_console", move |kill_evt| {
            let mut worker = Worker {
                interrupt,
                input,
                output,
                in_avail_evt,
                kill_evt,
                // Device -> driver
                receive_queue: Arc::new(Mutex::new(receive_queue)),
                // Driver -> device
                transmit_queue: Arc::new(Mutex::new(transmit_queue)),
            };
            if let Err(e) = worker.run() {
                error!("console run failure: {:?}", e);
            };
            worker
        }));
        Ok(())
    }

    fn reset(&mut self) -> bool {
        self.input = self.input_thread.take().map(|t| t.stop());
        if let Some(worker_thread) = self.worker_thread.take() {
            let worker = worker_thread.stop();
            // NOTE: Even though we are reseting the device, it still makes sense to preserve the
            // pending input bytes that the host sent but the guest hasn't accepted yet.
            self.input_buffer = worker
                .input
                .map_or(VecDeque::new(), |arc_mutex| arc_mutex.lock().clone());
            self.output = Some(worker.output);
            return true;
        }
        false
    }

    fn virtio_sleep(&mut self) -> anyhow::Result<Option<BTreeMap<usize, Queue>>> {
        self.input = self.input_thread.take().map(|t| t.stop());
        if let Some(worker_thread) = self.worker_thread.take() {
            let worker = worker_thread.stop();
            self.input_buffer = worker
                .input
                .map_or(VecDeque::new(), |arc_mutex| arc_mutex.lock().clone());
            self.output = Some(worker.output);
            let receive_queue = match Arc::try_unwrap(worker.receive_queue) {
                Ok(mutex) => mutex.into_inner(),
                Err(_) => return Err(anyhow!("failed to retrieve receive queue to sleep device.")),
            };
            let transmit_queue = match Arc::try_unwrap(worker.transmit_queue) {
                Ok(mutex) => mutex.into_inner(),
                Err(_) => {
                    return Err(anyhow!(
                        "failed to retrieve transmit queue to sleep device."
                    ))
                }
            };
            return Ok(Some(BTreeMap::from([
                (0, receive_queue),
                (1, transmit_queue),
            ])));
        }
        Ok(None)
    }

    fn virtio_wake(
        &mut self,
        queues_state: Option<(GuestMemory, Interrupt, BTreeMap<usize, Queue>)>,
    ) -> anyhow::Result<()> {
        match queues_state {
            None => Ok(()),
            Some((mem, interrupt, queues)) => {
                // TODO(khei): activate is just what we want at the moment, but we should probably move
                // it into a "start workers" function to make it obvious that it isn't strictly
                // used for activate events.
                self.activate(mem, interrupt, queues)?;
                Ok(())
            }
        }
    }

    fn virtio_snapshot(&mut self) -> anyhow::Result<serde_json::Value> {
        if let Some(read) = self.input.as_mut() {
            // If the device was not activated yet, we still read the input.
            // It's fine to do so since the the data is not lost. It will get queued in the
            // input_buffer and restored. When the device activates, the data will still be
            // available, and if there's any new data, that new data will get appended.
            let input_buffer = Arc::new(Mutex::new(std::mem::take(&mut self.input_buffer)));

            let kill_evt = Event::new().unwrap();
            let _ = kill_evt.signal();
            sys::read_input(read, &self.in_avail_evt, input_buffer.clone(), kill_evt);
            self.input_buffer = std::mem::take(&mut input_buffer.lock());
        };
        serde_json::to_value(ConsoleSnapshot {
            // Snapshot base_features as a safeguard when restoring the console device. Saving this
            // info allows us to validate that the proper config was used for the console.
            base_features: self.base_features,
            input_buffer: self.input_buffer.clone(),
        })
        .context("failed to snapshot virtio console")
    }

    fn virtio_restore(&mut self, data: serde_json::Value) -> anyhow::Result<()> {
        let deser: ConsoleSnapshot =
            serde_json::from_value(data).context("failed to deserialize virtio console")?;
        anyhow::ensure!(
            self.base_features == deser.base_features,
            "Virtio console incorrect base features for restore:\n Expected: {}, Actual: {}",
            self.base_features,
            deser.base_features,
        );
        self.input_buffer = deser.input_buffer;
        Ok(())
    }
}
