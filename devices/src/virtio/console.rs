// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io::{self, Read, Write};
use std::result;
use std::sync::mpsc::{channel, Receiver, TryRecvError};
use std::thread;

use base::{error, Event, PollToken, RawDescriptor, WaitContext};
use data_model::{DataInit, Le16, Le32};
use thiserror::Error as ThisError;
use vm_memory::GuestMemory;

use super::{
    base_features, copy_config, Interrupt, Queue, Reader, SignalableInterrupt, VirtioDevice,
    Writer, TYPE_CONSOLE,
};
use crate::{ProtectionType, SerialDevice};

pub(crate) const QUEUE_SIZE: u16 = 256;

// For now, just implement port 0 (receiveq and transmitq).
// If VIRTIO_CONSOLE_F_MULTIPORT is implemented, more queues will be needed.
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE, QUEUE_SIZE];

#[derive(ThisError, Debug)]
pub enum ConsoleError {
    /// There are no more available descriptors to receive into
    #[error("no rx descriptors available")]
    RxDescriptorsExhausted,
    /// Input channel has been disconnected
    #[error("input channel disconnected")]
    RxDisconnected,
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

/// Checks for input from `in_channel_opt` and transfers it to the receive queue, if any.
///
/// # Arguments
/// * `mem` - The GuestMemory to write the data into
/// * `interrupt` - SignalableInterrupt used to signal that the queue has been used
/// * `in_channel_opt` - Optional input channel to read data from
/// * `receive_queue` - The receive virtio Queue
pub fn handle_input<I: SignalableInterrupt>(
    mem: &GuestMemory,
    interrupt: &I,
    in_channel: &Receiver<Vec<u8>>,
    receive_queue: &mut Queue,
) -> result::Result<(), ConsoleError> {
    let mut exhausted_queue = false;

    loop {
        let desc = match receive_queue.peek(&mem) {
            Some(d) => d,
            None => {
                exhausted_queue = true;
                break;
            }
        };
        let desc_index = desc.index;
        // TODO(morg): Handle extra error cases as Err(ConsoleError) instead of just returning.
        let mut writer = match Writer::new(mem.clone(), desc) {
            Ok(w) => w,
            Err(e) => {
                error!("console: failed to create Writer: {}", e);
                break;
            }
        };

        let mut disconnected = false;
        while writer.available_bytes() > 0 {
            match in_channel.try_recv() {
                Ok(data) => {
                    writer.write_all(&data).unwrap();
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    disconnected = true;
                    break;
                }
            }
        }

        let bytes_written = writer.bytes_written() as u32;

        if bytes_written > 0 {
            receive_queue.pop_peeked(&mem);
            receive_queue.add_used(&mem, desc_index, bytes_written);
            receive_queue.trigger_interrupt(&mem, interrupt);
        }

        if disconnected {
            return Err(ConsoleError::RxDisconnected);
        }

        if bytes_written == 0 {
            break;
        }
    }

    if exhausted_queue {
        Err(ConsoleError::RxDescriptorsExhausted)
    } else {
        Ok(())
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
    while let Some(avail_desc) = transmit_queue.pop(&mem) {
        let desc_index = avail_desc.index;

        let reader = match Reader::new(mem.clone(), avail_desc) {
            Ok(r) => r,
            Err(e) => {
                error!("console: failed to create reader: {}", e);
                transmit_queue.add_used(&mem, desc_index, 0);
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

        transmit_queue.add_used(&mem, desc_index, len);
        needs_interrupt = true;
    }

    if needs_interrupt {
        transmit_queue.trigger_interrupt(mem, interrupt);
    }
}

struct Worker {
    mem: GuestMemory,
    interrupt: Interrupt,
    input: Option<Box<dyn io::Read + Send>>,
    output: Option<Box<dyn io::Write + Send>>,
}

fn write_output(output: &mut dyn io::Write, data: &[u8]) -> io::Result<()> {
    output.write_all(&data)?;
    output.flush()
}

/// Starts a thread that reads rx_input and sends the input back via the returned channel.
///
/// # Arguments
/// * `rx_input` - Data source that the reader thread will wait on to send data back to the channel
/// * `in_avail_evt` - Event triggered by the thread when new input is available on the channel
pub fn spawn_input_thread(
    mut rx: Box<dyn io::Read + Send>,
    in_avail_evt: &Event,
) -> Option<Receiver<Vec<u8>>> {
    let (send_channel, recv_channel) = channel();

    let thread_in_avail_evt = match in_avail_evt.try_clone() {
        Ok(evt) => evt,
        Err(e) => {
            error!("failed to clone in_avail_evt: {}", e);
            return None;
        }
    };

    // The input thread runs in detached mode and will exit when channel is disconnected because
    // the console device has been dropped.
    let res = thread::Builder::new()
        .name("console_input".to_string())
        .spawn(move || {
            loop {
                let mut rx_buf = vec![0u8; 1 << 12];
                match rx.read(&mut rx_buf) {
                    Ok(0) => break, // Assume the stream of input has ended.
                    Ok(size) => {
                        rx_buf.truncate(size);
                        if send_channel.send(rx_buf).is_err() {
                            // The receiver has disconnected.
                            break;
                        }
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
    Some(recv_channel)
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
    fn run(&mut self, mut queues: Vec<Queue>, mut queue_evts: Vec<Event>, kill_evt: Event) {
        #[derive(PollToken)]
        enum Token {
            ReceiveQueueAvailable,
            TransmitQueueAvailable,
            InputAvailable,
            InterruptResample,
            Kill,
        }

        // Device -> driver
        let (mut receive_queue, receive_evt) = (queues.remove(0), queue_evts.remove(0));

        // Driver -> device
        let (mut transmit_queue, transmit_evt) = (queues.remove(0), queue_evts.remove(0));

        let in_avail_evt = match Event::new() {
            Ok(evt) => evt,
            Err(e) => {
                error!("failed creating Event: {}", e);
                return;
            }
        };

        // Spawn a separate thread to poll self.input.
        // A thread is used because io::Read only provides a blocking interface, and there is no
        // generic way to add an io::Read instance to a poll context (it may not be backed by a file
        // descriptor).  Moving the blocking read call to a separate thread and sending data back to
        // the main worker thread with an event for notification bridges this gap.
        let mut in_channel = match self.input.take() {
            Some(input) => spawn_input_thread(input, &in_avail_evt),
            None => None,
        };

        let wait_ctx: WaitContext<Token> = match WaitContext::build_with(&[
            (&transmit_evt, Token::TransmitQueueAvailable),
            (&receive_evt, Token::ReceiveQueueAvailable),
            (&in_avail_evt, Token::InputAvailable),
            (&kill_evt, Token::Kill),
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

        let mut output: Box<dyn io::Write> = match self.output.take() {
            Some(o) => o,
            None => Box::new(io::sink()),
        };

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
                        if let Err(e) = transmit_evt.read() {
                            error!("failed reading transmit queue Event: {}", e);
                            break 'wait;
                        }
                        process_transmit_queue(
                            &self.mem,
                            &self.interrupt,
                            &mut transmit_queue,
                            &mut output,
                        );
                    }
                    Token::ReceiveQueueAvailable => {
                        if let Err(e) = receive_evt.read() {
                            error!("failed reading receive queue Event: {}", e);
                            break 'wait;
                        }
                        if let Some(ch) = in_channel.as_ref() {
                            match handle_input(&self.mem, &self.interrupt, ch, &mut receive_queue) {
                                Ok(()) => {}
                                Err(ConsoleError::RxDisconnected) => {
                                    // Set in_channel to None so that future handle_input calls exit early.
                                    in_channel.take();
                                }
                                // Other console errors are no-ops, so just continue.
                                Err(_) => {
                                    continue;
                                }
                            }
                        }
                    }
                    Token::InputAvailable => {
                        if let Err(e) = in_avail_evt.read() {
                            error!("failed reading in_avail_evt: {}", e);
                            break 'wait;
                        }
                        if let Some(ch) = in_channel.as_ref() {
                            match handle_input(&self.mem, &self.interrupt, ch, &mut receive_queue) {
                                Ok(()) => {}
                                Err(ConsoleError::RxDisconnected) => {
                                    // Set in_channel to None so that future handle_input calls exit early.
                                    in_channel.take();
                                }
                                // Other console errors are no-ops, so just continue.
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

/// Virtio console device.
pub struct Console {
    base_features: u64,
    kill_evt: Option<Event>,
    worker_thread: Option<thread::JoinHandle<Worker>>,
    input: Option<Box<dyn io::Read + Send>>,
    output: Option<Box<dyn io::Write + Send>>,
    keep_rds: Vec<RawDescriptor>,
}

impl SerialDevice for Console {
    fn new(
        protected_vm: ProtectionType,
        _evt: Event,
        input: Option<Box<dyn io::Read + Send>>,
        output: Option<Box<dyn io::Write + Send>>,
        keep_rds: Vec<RawDescriptor>,
    ) -> Console {
        Console {
            base_features: base_features(protected_vm),
            kill_evt: None,
            worker_thread: None,
            input,
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
        queues: Vec<Queue>,
        queue_evts: Vec<Event>,
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

        let input = self.input.take();
        let output = self.output.take();

        let worker_result = thread::Builder::new()
            .name("virtio_console".to_string())
            .spawn(move || {
                let mut worker = Worker {
                    mem,
                    interrupt,
                    input,
                    output,
                };
                worker.run(queues, queue_evts, kill_evt);
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
                    self.input = worker.input;
                    self.output = worker.output;
                    return true;
                }
            }
        }
        false
    }
}
