// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std;
use std::fmt::{self, Display};
use std::fs::File;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

use sys_util::{error, EventFd, GuestMemory, PollContext, PollToken};

use super::{Queue, VirtioDevice, INTERRUPT_STATUS_USED_RING, TYPE_RNG};

const QUEUE_SIZE: u16 = 256;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE];

#[derive(Debug)]
pub enum RngError {
    /// Can't access /dev/urandom
    AccessingRandomDev(io::Error),
}
pub type Result<T> = std::result::Result<T, RngError>;

impl Display for RngError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::RngError::*;

        match self {
            AccessingRandomDev(e) => write!(f, "failed to access /dev/urandom: {}", e),
        }
    }
}

struct Worker {
    queue: Queue,
    mem: GuestMemory,
    random_file: File,
    interrupt_status: Arc<AtomicUsize>,
    interrupt_evt: EventFd,
    interrupt_resample_evt: EventFd,
}

impl Worker {
    fn process_queue(&mut self) -> bool {
        let queue = &mut self.queue;

        let mut needs_interrupt = false;
        while let Some(avail_desc) = queue.pop(&self.mem) {
            let mut len = 0;

            // Drivers can only read from the random device.
            if avail_desc.is_write_only() {
                // Fill the read with data from the random device on the host.
                if self
                    .mem
                    .read_to_memory(avail_desc.addr, &self.random_file, avail_desc.len as usize)
                    .is_ok()
                {
                    len = avail_desc.len;
                }
            }

            queue.add_used(&self.mem, avail_desc.index, len);
            needs_interrupt = true;
        }

        needs_interrupt
    }

    fn signal_used_queue(&self) {
        self.interrupt_status
            .fetch_or(INTERRUPT_STATUS_USED_RING as usize, Ordering::SeqCst);
        self.interrupt_evt.write(1).unwrap();
    }

    fn run(&mut self, queue_evt: EventFd, kill_evt: EventFd) {
        #[derive(PollToken)]
        enum Token {
            QueueAvailable,
            InterruptResample,
            Kill,
        }

        let poll_ctx: PollContext<Token> = match PollContext::new()
            .and_then(|pc| pc.add(&queue_evt, Token::QueueAvailable).and(Ok(pc)))
            .and_then(|pc| {
                pc.add(&self.interrupt_resample_evt, Token::InterruptResample)
                    .and(Ok(pc))
            })
            .and_then(|pc| pc.add(&kill_evt, Token::Kill).and(Ok(pc)))
        {
            Ok(pc) => pc,
            Err(e) => {
                error!("failed creating PollContext: {}", e);
                return;
            }
        };

        'poll: loop {
            let events = match poll_ctx.wait() {
                Ok(v) => v,
                Err(e) => {
                    error!("failed polling for events: {}", e);
                    break;
                }
            };

            let mut needs_interrupt = false;
            for event in events.iter_readable() {
                match event.token() {
                    Token::QueueAvailable => {
                        if let Err(e) = queue_evt.read() {
                            error!("failed reading queue EventFd: {}", e);
                            break 'poll;
                        }
                        needs_interrupt |= self.process_queue();
                    }
                    Token::InterruptResample => {
                        let _ = self.interrupt_resample_evt.read();
                        if self.interrupt_status.load(Ordering::SeqCst) != 0 {
                            self.interrupt_evt.write(1).unwrap();
                        }
                    }
                    Token::Kill => break 'poll,
                }
            }
            if needs_interrupt {
                self.signal_used_queue();
            }
        }
    }
}

/// Virtio device for exposing entropy to the guest OS through virtio.
pub struct Rng {
    kill_evt: Option<EventFd>,
    random_file: Option<File>,
}

impl Rng {
    /// Create a new virtio rng device that gets random data from /dev/urandom.
    pub fn new() -> Result<Rng> {
        let random_file = File::open("/dev/urandom").map_err(RngError::AccessingRandomDev)?;
        Ok(Rng {
            kill_evt: None,
            random_file: Some(random_file),
        })
    }
}

impl Drop for Rng {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }
    }
}

impl VirtioDevice for Rng {
    fn keep_fds(&self) -> Vec<RawFd> {
        let mut keep_fds = Vec::new();

        if let Some(random_file) = &self.random_file {
            keep_fds.push(random_file.as_raw_fd());
        }

        keep_fds
    }

    fn device_type(&self) -> u32 {
        TYPE_RNG
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt_evt: EventFd,
        interrupt_resample_evt: EventFd,
        status: Arc<AtomicUsize>,
        mut queues: Vec<Queue>,
        mut queue_evts: Vec<EventFd>,
    ) {
        if queues.len() != 1 || queue_evts.len() != 1 {
            return;
        }

        let (self_kill_evt, kill_evt) = match EventFd::new().and_then(|e| Ok((e.try_clone()?, e))) {
            Ok(v) => v,
            Err(e) => {
                error!("failed to create kill EventFd pair: {}", e);
                return;
            }
        };
        self.kill_evt = Some(self_kill_evt);

        let queue = queues.remove(0);

        if let Some(random_file) = self.random_file.take() {
            let worker_result =
                thread::Builder::new()
                    .name("virtio_rng".to_string())
                    .spawn(move || {
                        let mut worker = Worker {
                            queue,
                            mem,
                            random_file,
                            interrupt_status: status,
                            interrupt_evt,
                            interrupt_resample_evt,
                        };
                        worker.run(queue_evts.remove(0), kill_evt);
                    });

            if let Err(e) = worker_result {
                error!("failed to spawn virtio_rng worker: {}", e);
                return;
            }
        }
    }
}
