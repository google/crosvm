// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::env;
use std::fmt::{self, Display};
use std::fs;
use std::ops::BitOrAssign;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

use sys_util::{EventFd, GuestMemory, GuestMemoryError, PollContext, PollToken};
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
    queue_evt: EventFd,
    kill_evt: EventFd,
    interrupt_evt: EventFd,
    interrupt_resample_evt: EventFd,
    device: Device,
}

struct Device {
    simulator: tpm2::Simulator,
    response: Option<Vec<u8>>,
}

impl Device {
    fn perform_work(&mut self, mem: &GuestMemory, desc: DescriptorChain) -> Result<u32> {
        if desc.is_read_only() {
            self.perform_send(&mem, desc)
        } else if desc.is_write_only() {
            self.perform_recv(&mem, desc)
        } else {
            Err(Error::ExpectedReadOrWrite)
        }
    }

    fn perform_send(&mut self, mem: &GuestMemory, desc: DescriptorChain) -> Result<u32> {
        if self.response.is_some() {
            return Err(Error::UnexpectedSend);
        }

        let mut buf = vec![0u8; desc.len as usize];
        mem.read_exact_at_addr(&mut buf, desc.addr)
            .map_err(Error::Read)?;

        let response = self.simulator.execute_command(&buf);
        self.response = Some(response.to_owned());
        Ok(desc.len)
    }

    fn perform_recv(&mut self, mem: &GuestMemory, desc: DescriptorChain) -> Result<u32> {
        let response = self.response.take().ok_or(Error::UnexpectedRecv)?;

        if response.len() > desc.len as usize {
            return Err(Error::SmallBuffer {
                size: desc.len as usize,
                required: response.len(),
            });
        }

        mem.write_all_at_addr(&response, desc.addr)
            .map_err(Error::Write)?;

        Ok(response.len() as u32)
    }
}

impl Worker {
    fn process_queue(&mut self) -> NeedsInterrupt {
        let avail_desc = match self.queue.iter(&self.mem).next() {
            Some(avail_desc) => avail_desc,
            None => return NeedsInterrupt::No,
        };

        let index = avail_desc.index;

        let len = match self.device.perform_work(&self.mem, avail_desc) {
            Ok(len) => len,
            Err(err) => {
                error!("{}", err);
                0
            }
        };

        self.queue.add_used(&self.mem, index, len);
        NeedsInterrupt::Yes
    }

    fn signal_used_queue(&self) {
        self.interrupt_status
            .fetch_or(INTERRUPT_STATUS_USED_RING as usize, Ordering::SeqCst);
        let _ = self.interrupt_evt.write(1);
    }

    fn run(mut self) {
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
            .and_then(|pc| pc.add(&self.queue_evt, Token::QueueAvailable).and(Ok(pc)))
            .and_then(|pc| {
                pc.add(&self.interrupt_resample_evt, Token::InterruptResample)
                    .and(Ok(pc))
            })
            .and_then(|pc| pc.add(&self.kill_evt, Token::Kill).and(Ok(pc)))
        {
            Ok(pc) => pc,
            Err(e) => {
                error!("vtpm failed creating PollContext: {}", e);
                return;
            }
        };

        'poll: loop {
            let events = match poll_ctx.wait() {
                Ok(v) => v,
                Err(e) => {
                    error!("vtpm failed polling for events: {}", e);
                    break;
                }
            };

            let mut needs_interrupt = NeedsInterrupt::No;
            for event in events.iter_readable() {
                match event.token() {
                    Token::QueueAvailable => {
                        if let Err(e) = self.queue_evt.read() {
                            error!("vtpm failed reading queue EventFd: {}", e);
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
            if needs_interrupt == NeedsInterrupt::Yes {
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
        interrupt_status: Arc<AtomicUsize>,
        mut queues: Vec<Queue>,
        mut queue_evts: Vec<EventFd>,
    ) {
        if queues.len() != 1 || queue_evts.len() != 1 {
            return;
        }
        let queue = queues.remove(0);
        let queue_evt = queue_evts.remove(0);

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
                error!("vtpm failed to create kill EventFd pair: {}", err);
                return;
            }
        };
        self.kill_evt = Some(self_kill_evt);

        let worker = Worker {
            queue,
            mem,
            interrupt_status,
            queue_evt,
            interrupt_evt,
            interrupt_resample_evt,
            kill_evt,
            device: Device {
                simulator,
                response: None,
            },
        };

        let worker_result = thread::Builder::new()
            .name("virtio_tpm".to_string())
            .spawn(|| worker.run());

        if let Err(e) = worker_result {
            error!("vtpm failed to spawn virtio_tpm worker: {}", e);
            return;
        }
    }
}

#[derive(PartialEq)]
enum NeedsInterrupt {
    Yes,
    No,
}

impl BitOrAssign for NeedsInterrupt {
    fn bitor_assign(&mut self, rhs: NeedsInterrupt) {
        if rhs == NeedsInterrupt::Yes {
            *self = NeedsInterrupt::Yes;
        }
    }
}

type Result<T> = std::result::Result<T, Error>;

enum Error {
    ExpectedReadOrWrite,
    UnexpectedSend,
    Read(GuestMemoryError),
    UnexpectedRecv,
    SmallBuffer { size: usize, required: usize },
    Write(GuestMemoryError),
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            ExpectedReadOrWrite => write!(f, "vtpm expected either read or write descriptor"),
            UnexpectedSend => write!(f, "vtpm encountered unexpected send"),
            Read(e) => write!(f, "vtpm failed to read from guest memory: {}", e),
            UnexpectedRecv => write!(f, "vtpm encountered unexpected recv"),
            SmallBuffer { size, required } => write!(
                f,
                "vtpm response buffer is too small: {} < {}",
                size, required
            ),
            Write(e) => write!(f, "vtpm failed to write to guest memory: {}", e),
        }
    }
}
