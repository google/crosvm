// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std;
use std::fs::File;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::spawn;

use sys_util::{EventFd, GuestMemory, Poller};

use super::{VirtioDevice, Queue, INTERRUPT_STATUS_USED_RING, TYPE_RNG};

const QUEUE_SIZE: u16 = 256;
const QUEUE_SIZES: &'static [u16] = &[QUEUE_SIZE];

#[derive(Debug)]
pub enum RngError {
    /// Can't access /dev/random
    AccessingRandomDev(io::Error),
}
pub type Result<T> = std::result::Result<T, RngError>;

struct Worker {
    queue: Queue,
    mem: GuestMemory,
    random_file: File,
    interrupt_status: Arc<AtomicUsize>,
    interrupt_evt: EventFd,
}

impl Worker {
    fn process_queue(&mut self) -> bool {
        let queue = &mut self.queue;

        let mut used_desc_heads = [(0, 0); QUEUE_SIZE as usize];
        let mut used_count = 0;
        for avail_desc in queue.iter(&self.mem) {
            let mut len = 0;

            // Drivers can only read from the random device.
            if avail_desc.is_write_only() {
                // Fill the read with data from the random device on the host.
                if self.mem.read_to_memory(avail_desc.addr,
                                           &mut self.random_file,
                                           avail_desc.len as usize)
                        .is_ok() {
                    len = avail_desc.len;
                }
            }

            used_desc_heads[used_count] = (avail_desc.index, len);
            used_count += 1;
        }

        for &(desc_index, len) in &used_desc_heads[..used_count] {
            queue.add_used(&self.mem, desc_index, len);
        }
        used_count > 0
    }

    fn signal_used_queue(&self) {
        self.interrupt_status
            .fetch_or(INTERRUPT_STATUS_USED_RING as usize, Ordering::SeqCst);
        self.interrupt_evt.write(1).unwrap();
    }

    fn run(&mut self, queue_evt: EventFd, kill_evt: EventFd) {
        const Q_AVAIL: u32 = 0;
        const KILL: u32 = 1;

        let mut poller = Poller::new(2);
        'poll: loop {
            let tokens = match poller.poll(&[(Q_AVAIL, &queue_evt), (KILL, &kill_evt)]) {
                Ok(v) => v,
                Err(e) => {
                    error!("failed polling for events: {:?}", e);
                    break;
                }
            };

            let mut needs_interrupt = false;
            for &token in tokens {
                match token {
                    Q_AVAIL => {
                        if let Err(e) = queue_evt.read() {
                            error!("failed reading queue EventFd: {:?}", e);
                            break 'poll;
                        }
                        needs_interrupt |= self.process_queue();
                    }
                    KILL => break 'poll,
                    _ => unreachable!(),
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
    /// Create a new virtio rng device that gets random data from /dev/random.
    pub fn new() -> Result<Rng> {
        let random_file = File::open("/dev/random")
            .map_err(RngError::AccessingRandomDev)?;
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

        if let Some(ref random_file) = self.random_file {
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

    fn activate(&mut self,
                mem: GuestMemory,
                interrupt_evt: EventFd,
                status: Arc<AtomicUsize>,
                mut queues: Vec<Queue>,
                mut queue_evts: Vec<EventFd>) {
        if queues.len() != 1 || queue_evts.len() != 1 {
            return;
        }

        let (self_kill_evt, kill_evt) =
            match EventFd::new().and_then(|e| Ok((e.try_clone()?, e))) {
                Ok(v) => v,
                Err(e) => {
                    error!("failed to create kill EventFd pair: {:?}", e);
                    return;
                }
            };
        self.kill_evt = Some(self_kill_evt);

        let queue = queues.remove(0);

        if let Some(random_file) = self.random_file.take() {
            spawn(move || {
                let mut worker = Worker {
                    queue: queue,
                    mem: mem,
                    random_file: random_file,
                    interrupt_status: status,
                    interrupt_evt: interrupt_evt,
                };
                worker.run(queue_evts.remove(0), kill_evt);
            });
        }
    }
}
