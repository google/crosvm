// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;
use std::io::Write;
use std::thread;

use base::error;
use base::warn;
use base::Event;
use base::EventToken;
use base::RawDescriptor;
use base::WaitContext;
use rand::rngs::OsRng;
use rand::RngCore;
use remain::sorted;
use thiserror::Error;
use vm_memory::GuestMemory;

use super::DeviceType;
use super::Interrupt;
use super::Queue;
use super::SignalableInterrupt;
use super::VirtioDevice;
use crate::virtio::Writer;

const QUEUE_SIZE: u16 = 256;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE];

#[sorted]
#[derive(Error, Debug)]
pub enum RngError {}
pub type Result<T> = std::result::Result<T, RngError>;

struct Worker {
    interrupt: Interrupt,
    queue: Queue,
    mem: GuestMemory,
}

impl Worker {
    fn process_queue(&mut self) -> bool {
        let queue = &mut self.queue;

        let mut needs_interrupt = false;
        while let Some(avail_desc) = queue.pop(&self.mem) {
            let index = avail_desc.index;

            let writer_or_err = Writer::new(self.mem.clone(), avail_desc)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e));
            let written_size = match writer_or_err {
                Ok(mut writer) => {
                    let avail_bytes = writer.available_bytes();

                    let mut rand_bytes = vec![0u8; avail_bytes];
                    OsRng.fill_bytes(&mut rand_bytes);

                    match writer.write_all(&rand_bytes) {
                        Ok(_) => rand_bytes.len(),
                        Err(e) => {
                            warn!("Failed to write random data to the guest: {}", e);
                            0usize
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to write random data to the guest: {}", e);
                    0usize
                }
            };
            queue.add_used(&self.mem, index, written_size as u32);
            needs_interrupt = true;
        }

        needs_interrupt
    }

    fn run(&mut self, queue_evt: Event, kill_evt: Event) {
        #[derive(EventToken)]
        enum Token {
            QueueAvailable,
            InterruptResample,
            Kill,
        }

        let wait_ctx: WaitContext<Token> = match WaitContext::build_with(&[
            (&queue_evt, Token::QueueAvailable),
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

        'wait: loop {
            let events = match wait_ctx.wait() {
                Ok(v) => v,
                Err(e) => {
                    error!("failed polling for events: {}", e);
                    break;
                }
            };

            let mut needs_interrupt = false;
            for event in events.iter().filter(|e| e.is_readable) {
                match event.token {
                    Token::QueueAvailable => {
                        if let Err(e) = queue_evt.wait() {
                            error!("failed reading queue Event: {}", e);
                            break 'wait;
                        }
                        needs_interrupt |= self.process_queue();
                    }
                    Token::InterruptResample => {
                        self.interrupt.interrupt_resample();
                    }
                    Token::Kill => break 'wait,
                }
            }
            if needs_interrupt {
                self.queue.trigger_interrupt(&self.mem, &self.interrupt);
            }
        }
    }
}

/// Virtio device for exposing entropy to the guest OS through virtio.
pub struct Rng {
    kill_evt: Option<Event>,
    worker_thread: Option<thread::JoinHandle<Worker>>,
    virtio_features: u64,
}

impl Rng {
    /// Create a new virtio rng device that gets random data from /dev/urandom.
    pub fn new(virtio_features: u64) -> Result<Rng> {
        Ok(Rng {
            kill_evt: None,
            worker_thread: None,
            virtio_features,
        })
    }
}

impl Drop for Rng {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.signal();
        }

        if let Some(worker_thread) = self.worker_thread.take() {
            let _ = worker_thread.join();
        }
    }
}

impl VirtioDevice for Rng {
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        Vec::new()
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::Rng
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn features(&self) -> u64 {
        self.virtio_features
    }

    fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt: Interrupt,
        mut queues: Vec<Queue>,
        mut queue_evts: Vec<Event>,
    ) {
        if queues.len() != 1 || queue_evts.len() != 1 {
            return;
        }

        let (self_kill_evt, kill_evt) = match Event::new().and_then(|e| Ok((e.try_clone()?, e))) {
            Ok(v) => v,
            Err(e) => {
                error!("failed to create kill Event pair: {}", e);
                return;
            }
        };
        self.kill_evt = Some(self_kill_evt);

        let queue = queues.remove(0);

        let worker_result =
            thread::Builder::new()
                .name("virtio_rng".to_string())
                .spawn(move || {
                    let mut worker = Worker {
                        interrupt,
                        queue,
                        mem,
                    };
                    worker.run(queue_evts.remove(0), kill_evt);
                    worker
                });

        match worker_result {
            Err(e) => {
                error!("failed to spawn virtio_rng worker: {}", e);
            }
            Ok(join_handle) => {
                self.worker_thread = Some(join_handle);
            }
        }
    }

    fn reset(&mut self) -> bool {
        if let Some(kill_evt) = self.kill_evt.take() {
            if kill_evt.signal().is_err() {
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
                Ok(_) => return true,
            }
        }
        false
    }
}
