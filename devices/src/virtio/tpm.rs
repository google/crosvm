// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::io;
use std::io::Read;
use std::io::Write;
use std::ops::BitOrAssign;

use anyhow::anyhow;
use anyhow::Context;
use base::error;
use base::Event;
use base::EventToken;
use base::RawDescriptor;
use base::WaitContext;
use base::WorkerThread;
use remain::sorted;
use thiserror::Error;
use vm_memory::GuestMemory;

use super::DescriptorChain;
use super::DeviceType;
use super::Interrupt;
use super::Queue;
use super::VirtioDevice;

// A single queue of size 2. The guest kernel driver will enqueue a single
// descriptor chain containing one command buffer and one response buffer at a
// time.
const QUEUE_SIZE: u16 = 2;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE];

// Maximum command or response message size permitted by this device
// implementation. Named to match the equivalent constant in Linux's tpm.h.
// There is no hard requirement that the value is the same but it makes sense.
const TPM_BUFSIZE: usize = 4096;

struct Worker {
    interrupt: Interrupt,
    queue: Queue,
    backend: Box<dyn TpmBackend>,
}

pub trait TpmBackend: Send {
    fn execute_command<'a>(&'a mut self, command: &[u8]) -> &'a [u8];
}

impl Worker {
    fn perform_work(&mut self, desc: &mut DescriptorChain) -> Result<u32> {
        let available_bytes = desc.reader.available_bytes();
        if available_bytes > TPM_BUFSIZE {
            return Err(Error::CommandTooLong {
                size: available_bytes,
            });
        }

        let mut command = vec![0u8; available_bytes];
        desc.reader.read_exact(&mut command).map_err(Error::Read)?;

        let response = self.backend.execute_command(&command);

        if response.len() > TPM_BUFSIZE {
            return Err(Error::ResponseTooLong {
                size: response.len(),
            });
        }

        let writer_len = desc.writer.available_bytes();
        if response.len() > writer_len {
            return Err(Error::BufferTooSmall {
                size: writer_len,
                required: response.len(),
            });
        }

        desc.writer.write_all(response).map_err(Error::Write)?;

        Ok(desc.writer.bytes_written() as u32)
    }

    fn process_queue(&mut self) -> NeedsInterrupt {
        let mut needs_interrupt = NeedsInterrupt::No;
        while let Some(mut avail_desc) = self.queue.pop() {
            let len = match self.perform_work(&mut avail_desc) {
                Ok(len) => len,
                Err(err) => {
                    error!("{}", err);
                    0
                }
            };

            self.queue.add_used(avail_desc, len);
            needs_interrupt = NeedsInterrupt::Yes;
        }

        needs_interrupt
    }

    fn run(mut self, kill_evt: Event) -> anyhow::Result<()> {
        #[derive(EventToken, Debug)]
        enum Token {
            // A request is ready on the queue.
            QueueAvailable,
            // Check if any interrupts need to be re-asserted.
            InterruptResample,
            // The parent thread requested an exit.
            Kill,
        }

        let wait_ctx = WaitContext::build_with(&[
            (self.queue.event(), Token::QueueAvailable),
            (&kill_evt, Token::Kill),
        ])
        .context("WaitContext::build_with")?;

        if let Some(resample_evt) = self.interrupt.get_resample_evt() {
            wait_ctx
                .add(resample_evt, Token::InterruptResample)
                .context("WaitContext::add")?;
        }

        loop {
            let events = wait_ctx.wait().context("WaitContext::wait")?;
            let mut needs_interrupt = NeedsInterrupt::No;
            for event in events.iter().filter(|e| e.is_readable) {
                match event.token {
                    Token::QueueAvailable => {
                        self.queue.event().wait().context("Event::wait")?;
                        needs_interrupt |= self.process_queue();
                    }
                    Token::InterruptResample => {
                        self.interrupt.interrupt_resample();
                    }
                    Token::Kill => return Ok(()),
                }
            }
            if needs_interrupt == NeedsInterrupt::Yes {
                self.queue.trigger_interrupt(&self.interrupt);
            }
        }
    }
}

/// Virtio vTPM device.
pub struct Tpm {
    backend: Option<Box<dyn TpmBackend>>,
    worker_thread: Option<WorkerThread<()>>,
    features: u64,
}

impl Tpm {
    pub fn new(backend: Box<dyn TpmBackend>, base_features: u64) -> Tpm {
        Tpm {
            backend: Some(backend),
            worker_thread: None,
            features: base_features,
        }
    }
}

impl VirtioDevice for Tpm {
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        Vec::new()
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::Tpm
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn features(&self) -> u64 {
        self.features
    }

    fn activate(
        &mut self,
        _mem: GuestMemory,
        interrupt: Interrupt,
        mut queues: BTreeMap<usize, Queue>,
    ) -> anyhow::Result<()> {
        if queues.len() != 1 {
            return Err(anyhow!("expected 1 queue, got {}", queues.len()));
        }
        let queue = queues.pop_first().unwrap().1;

        let backend = self.backend.take().context("no backend in vtpm")?;

        let worker = Worker {
            interrupt,
            queue,
            backend,
        };

        self.worker_thread = Some(WorkerThread::start("v_tpm", |kill_evt| {
            if let Err(e) = worker.run(kill_evt) {
                error!("virtio-tpm worker failed: {:#}", e);
            }
        }));

        Ok(())
    }
}

#[derive(PartialEq, Eq)]
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

#[sorted]
#[derive(Error, Debug)]
enum Error {
    #[error("vtpm response buffer is too small: {size} < {required} bytes")]
    BufferTooSmall { size: usize, required: usize },
    #[error("vtpm command is too long: {size} > {} bytes", TPM_BUFSIZE)]
    CommandTooLong { size: usize },
    #[error("vtpm failed to read from guest memory: {0}")]
    Read(io::Error),
    #[error(
        "vtpm simulator generated a response that is unexpectedly long: {size} > {} bytes",
        TPM_BUFSIZE
    )]
    ResponseTooLong { size: usize },
    #[error("vtpm failed to write to guest memory: {0}")]
    Write(io::Error),
}
