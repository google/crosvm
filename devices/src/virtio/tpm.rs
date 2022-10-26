// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;
use std::io::Read;
use std::io::Write;
use std::ops::BitOrAssign;
use std::thread;

use base::error;
use base::Event;
use base::EventToken;
use base::RawDescriptor;
use base::WaitContext;
use remain::sorted;
use thiserror::Error;
use vm_memory::GuestMemory;

use super::DescriptorChain;
use super::DescriptorError;
use super::DeviceType;
use super::Interrupt;
use super::Queue;
use super::Reader;
use super::SignalableInterrupt;
use super::VirtioDevice;
use super::Writer;
use crate::Suspendable;

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
    mem: GuestMemory,
    queue_evt: Event,
    kill_evt: Event,
    backend: Box<dyn TpmBackend>,
}

pub trait TpmBackend: Send {
    fn execute_command<'a>(&'a mut self, command: &[u8]) -> &'a [u8];
}

impl Worker {
    fn perform_work(&mut self, desc: DescriptorChain) -> Result<u32> {
        let mut reader = Reader::new(self.mem.clone(), desc.clone()).map_err(Error::Descriptor)?;
        let mut writer = Writer::new(self.mem.clone(), desc).map_err(Error::Descriptor)?;

        let available_bytes = reader.available_bytes();
        if available_bytes > TPM_BUFSIZE {
            return Err(Error::CommandTooLong {
                size: available_bytes,
            });
        }

        let mut command = vec![0u8; available_bytes];
        reader.read_exact(&mut command).map_err(Error::Read)?;

        let response = self.backend.execute_command(&command);

        if response.len() > TPM_BUFSIZE {
            return Err(Error::ResponseTooLong {
                size: response.len(),
            });
        }

        let writer_len = writer.available_bytes();
        if response.len() > writer_len {
            return Err(Error::BufferTooSmall {
                size: writer_len,
                required: response.len(),
            });
        }

        writer.write_all(response).map_err(Error::Write)?;

        Ok(writer.bytes_written() as u32)
    }

    fn process_queue(&mut self) -> NeedsInterrupt {
        let mut needs_interrupt = NeedsInterrupt::No;
        while let Some(avail_desc) = self.queue.pop(&self.mem) {
            let index = avail_desc.index;

            let len = match self.perform_work(avail_desc) {
                Ok(len) => len,
                Err(err) => {
                    error!("{}", err);
                    0
                }
            };

            self.queue.add_used(&self.mem, index, len);
            needs_interrupt = NeedsInterrupt::Yes;
        }

        needs_interrupt
    }

    fn run(mut self) {
        #[derive(EventToken, Debug)]
        enum Token {
            // A request is ready on the queue.
            QueueAvailable,
            // Check if any interrupts need to be re-asserted.
            InterruptResample,
            // The parent thread requested an exit.
            Kill,
        }

        let wait_ctx = match WaitContext::build_with(&[
            (&self.queue_evt, Token::QueueAvailable),
            (&self.kill_evt, Token::Kill),
        ])
        .and_then(|wc| {
            if let Some(resample_evt) = self.interrupt.get_resample_evt() {
                wc.add(resample_evt, Token::InterruptResample)?;
            }
            Ok(wc)
        }) {
            Ok(pc) => pc,
            Err(e) => {
                error!("vtpm failed creating WaitContext: {}", e);
                return;
            }
        };

        'wait: loop {
            let events = match wait_ctx.wait() {
                Ok(v) => v,
                Err(e) => {
                    error!("vtpm failed waiting for events: {}", e);
                    break;
                }
            };

            let mut needs_interrupt = NeedsInterrupt::No;
            for event in events.iter().filter(|e| e.is_readable) {
                match event.token {
                    Token::QueueAvailable => {
                        if let Err(e) = self.queue_evt.wait() {
                            error!("vtpm failed reading queue Event: {}", e);
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
            if needs_interrupt == NeedsInterrupt::Yes {
                self.queue.trigger_interrupt(&self.mem, &self.interrupt);
            }
        }
    }
}

/// Virtio vTPM device.
pub struct Tpm {
    backend: Option<Box<dyn TpmBackend>>,
    kill_evt: Option<Event>,
    worker_thread: Option<thread::JoinHandle<()>>,
    features: u64,
}

impl Tpm {
    pub fn new(backend: Box<dyn TpmBackend>, base_features: u64) -> Tpm {
        Tpm {
            backend: Some(backend),
            kill_evt: None,
            worker_thread: None,
            features: base_features,
        }
    }
}

impl Drop for Tpm {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.kill_evt.take() {
            let _ = kill_evt.signal();
        }

        if let Some(worker_thread) = self.worker_thread.take() {
            let _ = worker_thread.join();
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
        mem: GuestMemory,
        interrupt: Interrupt,
        mut queues: Vec<Queue>,
        mut queue_evts: Vec<Event>,
    ) {
        if queues.len() != 1 || queue_evts.len() != 1 {
            return;
        }
        let queue = queues.remove(0);
        let queue_evt = queue_evts.remove(0);

        let backend = match self.backend.take() {
            Some(backend) => backend,
            None => {
                error!("no backend in vtpm");
                return;
            }
        };

        let (self_kill_evt, kill_evt) = match Event::new().and_then(|e| Ok((e.try_clone()?, e))) {
            Ok(v) => v,
            Err(err) => {
                error!("vtpm failed to create kill Event pair: {}", err);
                return;
            }
        };
        self.kill_evt = Some(self_kill_evt);

        let worker = Worker {
            interrupt,
            queue,
            mem,
            queue_evt,
            kill_evt,
            backend,
        };

        let worker_result = thread::Builder::new()
            .name("virtio_tpm".to_string())
            .spawn(|| worker.run());

        match worker_result {
            Err(e) => {
                error!("vtpm failed to spawn virtio_tpm worker: {}", e);
            }
            Ok(join_handle) => {
                self.worker_thread = Some(join_handle);
            }
        }
    }
}

impl Suspendable for Tpm {}

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

#[sorted]
#[derive(Error, Debug)]
enum Error {
    #[error("vtpm response buffer is too small: {size} < {required} bytes")]
    BufferTooSmall { size: usize, required: usize },
    #[error("vtpm command is too long: {size} > {} bytes", TPM_BUFSIZE)]
    CommandTooLong { size: usize },
    #[error("virtio descriptor error: {0}")]
    Descriptor(DescriptorError),
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
