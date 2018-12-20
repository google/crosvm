// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::env;
use std::fs;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

use sys_util::{EventFd, GuestMemory, PollContext, PollToken};
use tpm2;

use super::{DescriptorChain, Queue, VirtioDevice, INTERRUPT_STATUS_USED_RING, TYPE_TPM};

const QUEUE_SIZE: u16 = 1;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE];

// Simply store TPM state in /tmp/tpm-simulator. Before shipping this feature,
// will need to move state under /run/vm instead. https://crbug.com/921841
const SIMULATOR_DIR: &str = "/tmp/tpm-simulator";

struct Worker {
    queue: Queue,
    mem: GuestMemory,
    interrupt_status: Arc<AtomicUsize>,
    interrupt_evt: EventFd,
    interrupt_resample_evt: EventFd,
    device: Device,
}

struct Device {
    simulator: tpm2::Simulator,
    response: Option<Vec<u8>>,
}

impl Device {
    fn perform_send(&mut self, mem: &GuestMemory, avail_desc: DescriptorChain) -> u32 {
        if self.response.is_some() {
            error!("vtpm encountered unexpected send");
            return 0;
        }

        let mut len = 0;
        let mut buf = vec![0u8; avail_desc.len as usize];
        match mem.read_exact_at_addr(&mut buf, avail_desc.addr) {
            Ok(()) => {
                let response = self.simulator.execute_command(&buf);
                self.response = Some(response.to_owned());
                len = avail_desc.len;
            }
            Err(err) => {
                error!("vtpm failed read from guest memory: {}", err);
            }
        }
        len
    }

    fn perform_recv(&mut self, mem: &GuestMemory, avail_desc: DescriptorChain) -> u32 {
        let buf = match self.response.take() {
            Some(buf) => buf,
            None => {
                error!("vtpm encountered unexpected recv");
                return 0;
            }
        };

        assert!(buf.len() <= avail_desc.len as usize);

        let mut len = 0;
        match mem.write_all_at_addr(&buf, avail_desc.addr) {
            Ok(()) => len = buf.len() as u32,
            Err(err) => {
                error!("vtpm failed write to guest memory: {}", err);
            }
        }
        len
    }
}

impl Worker {
    fn process_queue(&mut self) -> bool {
        let queue = &mut self.queue;

        let mut used_desc_heads = [(0, 0); QUEUE_SIZE as usize];
        let mut used_count = 0;
        for avail_desc in queue.iter(&self.mem) {
            let index = avail_desc.index;
            let len = if avail_desc.is_read_only() {
                self.device.perform_send(&self.mem, avail_desc)
            } else if avail_desc.is_write_only() {
                self.device.perform_recv(&self.mem, avail_desc)
            } else {
                error!("vtpm expected either read or write descriptor");
                0
            };

            used_desc_heads[used_count] = (index, len);
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
        let _ = self.interrupt_evt.write(1);
    }

    fn run(&mut self, queue_evt: EventFd, kill_evt: EventFd) {
        #[derive(PollToken, Debug)]
        enum Token {
            // A request is ready on the queue.
            QueueAvailable,
            // Check if any interrupts need to be re-asserted.
            InterruptResample,
            // The parent thread requested an exit.
            Kill,
        }

        let poll_ctx = match PollContext::new()
            .and_then(|pc| pc.add(&queue_evt, Token::QueueAvailable).and(Ok(pc)))
            .and_then(|pc| {
                pc.add(&self.interrupt_resample_evt, Token::InterruptResample)
                    .and(Ok(pc))
            })
            .and_then(|pc| pc.add(&kill_evt, Token::Kill).and(Ok(pc)))
        {
            Ok(pc) => pc,
            Err(e) => {
                error!("vtpm failed creating PollContext: {:?}", e);
                return;
            }
        };

        'poll: loop {
            let events = match poll_ctx.wait() {
                Ok(v) => v,
                Err(e) => {
                    error!("vtpm failed polling for events: {:?}", e);
                    break;
                }
            };

            let mut needs_interrupt = false;
            for event in events.iter_readable() {
                match event.token() {
                    Token::QueueAvailable => {
                        if let Err(e) = queue_evt.read() {
                            error!("vtpm failed reading queue EventFd: {:?}", e);
                            break 'poll;
                        }
                        needs_interrupt |= self.process_queue();
                    }
                    Token::InterruptResample => {
                        let _ = self.interrupt_resample_evt.read();
                        if self.interrupt_status.load(Ordering::SeqCst) != 0 {
                            let _ = self.interrupt_evt.write(1);
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

/// Virtio vTPM device.
pub struct Tpm {
    kill_evt: Option<EventFd>,
}

impl Tpm {
    pub fn new() -> Tpm {
        Tpm { kill_evt: None }
    }
}

impl Drop for Tpm {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.kill_evt.take() {
            let _ = kill_evt.write(1);
        }
    }
}

impl VirtioDevice for Tpm {
    fn keep_fds(&self) -> Vec<RawFd> {
        Vec::new()
    }

    fn device_type(&self) -> u32 {
        TYPE_TPM
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

        if let Err(err) = fs::create_dir_all(SIMULATOR_DIR) {
            error!("vtpm failed to create directory for simulator: {}", err);
            return;
        }
        if let Err(err) = env::set_current_dir(SIMULATOR_DIR) {
            error!("vtpm failed to change into simulator directory: {}", err);
            return;
        }
        let simulator = tpm2::Simulator::singleton_in_current_directory();

        let (self_kill_evt, kill_evt) = match EventFd::new().and_then(|e| Ok((e.try_clone()?, e))) {
            Ok(v) => v,
            Err(err) => {
                error!("vtpm failed to create kill EventFd pair: {:?}", err);
                return;
            }
        };
        self.kill_evt = Some(self_kill_evt);

        let queue = queues.remove(0);

        let worker_result =
            thread::Builder::new()
                .name("virtio_tpm".to_string())
                .spawn(move || {
                    let mut worker = Worker {
                        queue,
                        mem,
                        interrupt_status: status,
                        interrupt_evt,
                        interrupt_resample_evt,
                        device: Device {
                            simulator,
                            response: None,
                        },
                    };
                    worker.run(queue_evts.remove(0), kill_evt);
                });

        if let Err(e) = worker_result {
            error!("vtpm failed to spawn virtio_tpm worker: {}", e);
            return;
        }
    }
}
