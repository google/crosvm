// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::ops::DerefMut;
use std::result;
use std::sync::Arc;
use std::thread;

use base::{error, Event, FileSync, PollToken, RawDescriptor, WaitContext};
use data_model::{DataInit, Le16, Le32};
use hypervisor::ProtectionType;
use remain::sorted;
use sync::Mutex;
use thiserror::Error as ThisError;
use vm_memory::GuestMemory;

use super::{
    base_features, copy_config, Interrupt, Queue, Reader, SignalableInterrupt, VirtioDevice,
    Writer, TYPE_CONSOLE,
};
use crate::SerialDevice;

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

#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct virtio_console_config {
    pub cols: Le16,
    pub rows: Le16,
    pub max_nr_ports: Le32,
    pub emerg_wr: Le32,
}

// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for virtio_console_config {}

/// Checks for input from `buffer` and transfers it to the receive queue, if any.
///
/// # Arguments
///
/// * `mem` - The GuestMemory to write the data into
/// * `interrupt` - SignalableInterrupt used to signal that the queue has been used
/// * `buffer` - Ring buffer providing data to put into the guest
/// * `receive_queue` - The receive virtio Queue
pub fn handle_input<I: SignalableInterrupt>(
    mem: &GuestMemory,
    interrupt: &I,
    buffer: &mut VecDeque<u8>,
    receive_queue: &mut Queue,
) -> result::Result<(), ConsoleError> {
    loop {
        let desc = receive_queue
            .peek(mem)
            .ok_or(ConsoleError::RxDescriptorsExhausted)?;
        let desc_index = desc.index;
        // TODO(morg): Handle extra error cases as Err(ConsoleError) instead of just returning.
        let mut writer = match Writer::new(mem.clone(), desc) {
            Ok(w) => w,
            Err(e) => {
                error!("console: failed to create Writer: {}", e);
                return Ok(());
            }
        };

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
            receive_queue.pop_peeked(mem);
            receive_queue.add_used(mem, desc_index, bytes_written);
            receive_queue.trigger_interrupt(mem, interrupt);
        }

        if bytes_written == 0 {
            return Ok(());
        }
    }
}

/// Processes the data taken from the given transmit queue into the output sink.
///
/// # Arguments
///
/// * `mem` - The GuestMemory to take the data from
/// * `interrupt` - SignalableInterrupt used to signal (if required) that the queue has been used
/// * `transmit_queue` - The transmit virtio Queue
/// * `output` - The output sink we are going to write the data into
pub fn process_transmit_queue<I: SignalableInterrupt>(
    mem: &GuestMemory,
    interrupt: &I,
    transmit_queue: &mut Queue,
    output: &mut dyn io::Write,
) {
    let mut needs_interrupt = false;
    while let Some(avail_desc) = transmit_queue.pop(mem) {
        let desc_index = avail_desc.index;

        let reader = match Reader::new(mem.clone(), avail_desc) {
            Ok(r) => r,
            Err(e) => {
                error!("console: failed to create reader: {}", e);
                transmit_queue.add_used(mem, desc_index, 0);
                needs_interrupt = true;
                continue;
            }
        };

        let len = match process_transmit_request(reader, output) {
            Ok(written) => written,
            Err(e) => {
                error!("console: process_transmit_request failed: {}", e);
                0
            }
        };

        transmit_queue.add_used(mem, desc_index, len);
        needs_interrupt = true;
    }

    if needs_interrupt {
        transmit_queue.trigger_interrupt(mem, interrupt);
    }
}

struct Worker {
    mem: GuestMemory,
    interrupt: Interrupt,
    input: Option<Arc<Mutex<VecDeque<u8>>>>,
    output: Box<dyn io::Write + Send>,
    kill_evt: Event,
    in_avail_evt: Event,
    receive_queue: Queue,
    receive_evt: Event,
    transmit_queue: Queue,
    transmit_evt: Event,
}

fn write_output(output: &mut dyn io::Write, data: &[u8]) -> io::Result<()> {
    output.write_all(data)?;
    output.flush()
}

/// Starts a thread that reads rx and sends the input back via the returned buffer.
///
/// The caller should listen on `in_avail_evt` for events. When `in_avail_evt` signals that data
/// is available, the caller should lock the returned `Mutex` and read data out of the inner
/// `VecDeque`. The data should be removed from the beginning of the `VecDeque` as it is processed.
///
/// # Arguments
///
/// * `rx` - Data source that the reader thread will wait on to send data back to the buffer
/// * `in_avail_evt` - Event triggered by the thread when new input is available on the buffer
pub fn spawn_input_thread(
    mut rx: Box<dyn io::Read + Send>,
    in_avail_evt: &Event,
) -> Option<Arc<Mutex<VecDeque<u8>>>> {
    let buffer = Arc::new(Mutex::new(VecDeque::<u8>::new()));
    let buffer_cloned = buffer.clone();

    let thread_in_avail_evt = match in_avail_evt.try_clone() {
        Ok(evt) => evt,
        Err(e) => {
            error!("failed to clone in_avail_evt: {}", e);
            return None;
        }
    };

    // The input thread runs in detached mode.
    let res = thread::Builder::new()
        .name("console_input".to_string())
        .spawn(move || {
            let mut rx_buf = [0u8; 1 << 12];
            loop {
                match rx.read(&mut rx_buf) {
                    Ok(0) => break, // Assume the stream of input has ended.
                    Ok(size) => {
                        buffer.lock().extend(&rx_buf[0..size]);
                        thread_in_avail_evt.write(1).unwrap();
                    }
                    Err(e) => {
                        // Being interrupted is not an error, but everything else is.
                        if e.kind() != io::ErrorKind::Interrupted {
                            error!(
                                "failed to read for bytes to queue into console device: {}",
                                e
                            );
                            break;
                        }
                    }
                }
            }
        });
    if let Err(e) = res {
        error!("failed to spawn input thread: {}", e);
        return None;
    }
    Some(buffer_cloned)
}

/// Writes the available data from the reader into the given output queue.
///
/// # Arguments
///
/// * `reader` - The Reader with the data we want to write.
/// * `output` - The output sink we are going to write the data to.
pub fn process_transmit_request(mut reader: Reader, output: &mut dyn io::Write) -> io::Result<u32> {
    let len = reader.available_bytes();
    let mut data = vec![0u8; len];
    reader.read_exact(&mut data)?;
    write_output(output, &data)?;
    Ok(0)
}

impl Worker {
    fn run(&mut self) {
        #[derive(PollToken)]
        enum Token {
            ReceiveQueueAvailable,
            TransmitQueueAvailable,
            InputAvailable,
            InterruptResample,
            Kill,
        }

        let wait_ctx: WaitContext<Token> = match WaitContext::build_with(&[
            (&self.transmit_evt, Token::TransmitQueueAvailable),
            (&self.receive_evt, Token::ReceiveQueueAvailable),
            (&self.in_avail_evt, Token::InputAvailable),
            (&self.kill_evt, Token::Kill),
        ]) {
            Ok(pc) => pc,
            Err(e) => {
                error!("failed creating WaitContext: {}", e);
                return;
            }
        };
        if let Some(resample_evt) = self.interrupt.get_resample_evt() {
            if wait_ctx
                .add(resample_evt, Token::InterruptResample)
                .is_err()
            {
                error!("failed adding resample event to WaitContext.");
                return;
            }
        }

        'wait: loop {
            let events = match wait_ctx.wait() {
                Ok(v) => v,
                Err(e) => {
                    error!("failed polling for events: {}", e);
                    break;
                }
            };

            for event in events.iter().filter(|e| e.is_readable) {
                match event.token {
                    Token::TransmitQueueAvailable => {
                        if let Err(e) = self.transmit_evt.read() {
                            error!("failed reading transmit queue Event: {}", e);
                            break 'wait;
                        }
                        process_transmit_queue(
                            &self.mem,
                            &self.interrupt,
                            &mut self.transmit_queue,
                            &mut self.output,
                        );
                    }
                    Token::ReceiveQueueAvailable => {
                        if let Err(e) = self.receive_evt.read() {
                            error!("failed reading receive queue Event: {}", e);
                            break 'wait;
                        }
                        if let Some(in_buf_ref) = self.input.as_ref() {
                            match handle_input(
                                &self.mem,
                                &self.interrupt,
                                in_buf_ref.lock().deref_mut(),
                                &mut self.receive_queue,
                            ) {
                                Ok(()) => {}
                                // Console errors are no-ops, so just continue.
                                Err(_) => {
                                    continue;
                                }
                            }
                        }
                    }
                    Token::InputAvailable => {
                        if let Err(e) = self.in_avail_evt.read() {
                            error!("failed reading in_avail_evt: {}", e);
                            break 'wait;
                        }
                        if let Some(in_buf_ref) = self.input.as_ref() {
                            match handle_input(
                                &self.mem,
                                &self.interrupt,
                                in_buf_ref.lock().deref_mut(),
                                &mut self.receive_queue,
                            ) {
                                Ok(()) => {}
                                // Console errors are no-ops, so just continue.
                                Err(_) => {
                                    continue;
                                }
                            }
                        }
                    }
                    Token::InterruptResample => {
                        self.interrupt.interrupt_resample();
                    }
                    Token::Kill => break 'wait,
                }
            }
        }
    }
}

enum ConsoleInput {
    FromRead(Box<dyn io::Read + Send>),
    FromThread(Arc<Mutex<VecDeque<u8>>>),
}

/// Virtio console device.
pub struct Console {
    base_features: u64,
    kill_evt: Option<Event>,
    in_avail_evt: Option<Event>,
    worker_thread: Option<thread::JoinHandle<Worker>>,
    input: Option<ConsoleInput>,
    output: Option<Box<dyn io::Write + Send>>,
    keep_rds: Vec<RawDescriptor>,
}

impl SerialDevice for Console {
    fn new(
        protected_vm: ProtectionType,
        _evt: Event,
        input: Option<Box<dyn io::Read + Send>>,
        output: Option<Box<dyn io::Write + Send>>,
        _sync: Option<Box<dyn FileSync + Send>>,
        _out_timestamp: bool,
        keep_rds: Vec<RawDescriptor>,
    ) -> Console {
        Console {
            base_features: base_features(protected_vm),
            in_avail_evt: None,
            kill_evt: None,
            worker_thread: None,
            input: input.map(ConsoleInput::FromRead),
            output,
            keep_rds,
        }
    }
}

impl Drop for Console {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }

        if let Some(worker_thread) = self.worker_thread.take() {
            let _ = worker_thread.join();
        }
    }
}

impl VirtioDevice for Console {
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        self.keep_rds.clone()
    }

    fn features(&self) -> u64 {
        self.base_features
    }

    fn device_type(&self) -> u32 {
        TYPE_CONSOLE
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let config = virtio_console_config {
            max_nr_ports: 1.into(),
            ..Default::default()
        };
        copy_config(data, 0, config.as_slice(), offset);
    }

    fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt: Interrupt,
        mut queues: Vec<Queue>,
        mut queue_evts: Vec<Event>,
    ) {
        if queues.len() < 2 || queue_evts.len() < 2 {
            return;
        }

        let (self_kill_evt, kill_evt) = match Event::new().and_then(|e| Ok((e.try_clone()?, e))) {
            Ok(v) => v,
            Err(e) => {
                error!("failed creating kill Event pair: {}", e);
                return;
            }
        };
        self.kill_evt = Some(self_kill_evt);

        if self.in_avail_evt.is_none() {
            self.in_avail_evt = match Event::new() {
                Ok(evt) => Some(evt),
                Err(e) => {
                    error!("failed creating Event: {}", e);
                    return;
                }
            };
        }
        let in_avail_evt = match self.in_avail_evt.as_ref().unwrap().try_clone() {
            Ok(v) => v,
            Err(e) => {
                error!("failed creating input available Event pair: {}", e);
                return;
            }
        };

        // Spawn a separate thread to poll self.input.
        // A thread is used because io::Read only provides a blocking interface, and there is no
        // generic way to add an io::Read instance to a poll context (it may not be backed by a file
        // descriptor).  Moving the blocking read call to a separate thread and sending data back to
        // the main worker thread with an event for notification bridges this gap.
        let input = match self.input.take() {
            Some(ConsoleInput::FromRead(read)) => {
                let buffer = spawn_input_thread(read, self.in_avail_evt.as_ref().unwrap());
                if buffer.is_none() {
                    error!("failed creating input thread");
                };
                buffer
            }
            Some(ConsoleInput::FromThread(buffer)) => Some(buffer),
            None => None,
        };
        let output = self.output.take().unwrap_or_else(|| Box::new(io::sink()));

        let worker_result = thread::Builder::new()
            .name("virtio_console".to_string())
            .spawn(move || {
                let mut worker = Worker {
                    mem,
                    interrupt,
                    input,
                    output,
                    in_avail_evt,
                    kill_evt,
                    // Device -> driver
                    receive_queue: queues.remove(0),
                    receive_evt: queue_evts.remove(0),
                    // Driver -> device
                    transmit_queue: queues.remove(0),
                    transmit_evt: queue_evts.remove(0),
                };
                worker.run();
                worker
            });

        match worker_result {
            Err(e) => {
                error!("failed to spawn virtio_console worker: {}", e);
            }
            Ok(join_handle) => {
                self.worker_thread = Some(join_handle);
            }
        }
    }

    fn reset(&mut self) -> bool {
        if let Some(kill_evt) = self.kill_evt.take() {
            if kill_evt.write(1).is_err() {
                error!("{}: failed to notify the kill event", self.debug_label());
                return false;
            }
        }

        if let Some(worker_thread) = self.worker_thread.take() {
            match worker_thread.join() {
                Err(_) => {
                    error!("{}: failed to get back resources", self.debug_label());
                    return false;
                }
                Ok(worker) => {
                    self.input = worker.input.map(ConsoleInput::FromThread);
                    self.output = Some(worker.output);
                    return true;
                }
            }
        }
        false
    }
}
