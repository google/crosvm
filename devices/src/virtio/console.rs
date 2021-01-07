// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io::{self, Read, Write};
use std::sync::mpsc::{channel, Receiver, TryRecvError};
use std::thread;

use base::{error, Event, PollToken, RawDescriptor, WaitContext};
use data_model::{DataInit, Le16, Le32};
use vm_memory::GuestMemory;

use super::{
    base_features, copy_config, Interrupt, Queue, Reader, SignalableInterrupt, VirtioDevice,
    Writer, TYPE_CONSOLE,
};
use crate::{ProtectionType, SerialDevice};

const QUEUE_SIZE: u16 = 256;

// For now, just implement port 0 (receiveq and transmitq).
// If VIRTIO_CONSOLE_F_MULTIPORT is implemented, more queues will be needed.
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE, QUEUE_SIZE];

#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
struct virtio_console_config {
    cols: Le16,
    rows: Le16,
    max_nr_ports: Le32,
    emerg_wr: Le32,
}

// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for virtio_console_config {}

struct Worker {
    mem: GuestMemory,
    interrupt: Interrupt,
    input: Option<Box<dyn io::Read + Send>>,
    output: Option<Box<dyn io::Write + Send>>,
}

fn write_output(output: &mut Box<dyn io::Write>, data: &[u8]) -> io::Result<()> {
    output.write_all(&data)?;
    output.flush()
}

impl Worker {
    fn process_transmit_request(
        mut reader: Reader,
        output: &mut Box<dyn io::Write>,
    ) -> io::Result<u32> {
        let len = reader.available_bytes();
        let mut data = vec![0u8; len];
        reader.read_exact(&mut data)?;
        write_output(output, &data)?;
        Ok(0)
    }

    fn process_transmit_queue(
        &mut self,
        transmit_queue: &mut Queue,
        output: &mut Box<dyn io::Write>,
    ) {
        let mut needs_interrupt = false;
        while let Some(avail_desc) = transmit_queue.pop(&self.mem) {
            let desc_index = avail_desc.index;

            let reader = match Reader::new(self.mem.clone(), avail_desc) {
                Ok(r) => r,
                Err(e) => {
                    error!("console: failed to create reader: {}", e);
                    transmit_queue.add_used(&self.mem, desc_index, 0);
                    needs_interrupt = true;
                    continue;
                }
            };

            let len = match Self::process_transmit_request(reader, output) {
                Ok(written) => written,
                Err(e) => {
                    error!("console: process_transmit_request failed: {}", e);
                    0
                }
            };

            transmit_queue.add_used(&self.mem, desc_index, len);
            needs_interrupt = true;
        }

        if needs_interrupt {
            self.interrupt.signal_used_queue(transmit_queue.vector);
        }
    }

    // Start a thread that reads self.input and sends the input back via the returned channel.
    //
    // `in_avail_evt` will be triggered by the thread when new input is available.
    fn spawn_input_thread(&mut self, in_avail_evt: &Event) -> Option<Receiver<Vec<u8>>> {
        let mut rx = match self.input.take() {
            Some(input) => input,
            None => return None,
        };

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

    // Check for input from `in_channel_opt` and transfer it to the receive queue, if any.
    fn handle_input(
        &mut self,
        in_channel_opt: &mut Option<Receiver<Vec<u8>>>,
        receive_queue: &mut Queue,
    ) {
        let in_channel = match in_channel_opt.as_ref() {
            Some(v) => v,
            None => return,
        };

        while let Some(desc) = receive_queue.peek(&self.mem) {
            let desc_index = desc.index;
            let mut writer = match Writer::new(self.mem.clone(), desc) {
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
                receive_queue.pop_peeked(&self.mem);
                receive_queue.add_used(&self.mem, desc_index, bytes_written);
                self.interrupt.signal_used_queue(receive_queue.vector);
            }

            if disconnected {
                // Set in_channel to None so that future handle_input calls exit early.
                in_channel_opt.take();
                return;
            }

            if bytes_written == 0 {
                break;
            }
        }
    }

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
        let mut in_channel = self.spawn_input_thread(&in_avail_evt);

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
                        self.process_transmit_queue(&mut transmit_queue, &mut output);
                    }
                    Token::ReceiveQueueAvailable => {
                        if let Err(e) = receive_evt.read() {
                            error!("failed reading receive queue Event: {}", e);
                            break 'wait;
                        }
                        self.handle_input(&mut in_channel, &mut receive_queue);
                    }
                    Token::InputAvailable => {
                        if let Err(e) = in_avail_evt.read() {
                            error!("failed reading in_avail_evt: {}", e);
                            break 'wait;
                        }
                        self.handle_input(&mut in_channel, &mut receive_queue);
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
