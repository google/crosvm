// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::io::Write;

use anyhow::anyhow;
use base::error;
use base::warn;
use base::Event;
use base::EventToken;
use base::RawDescriptor;
use base::WaitContext;
use base::WorkerThread;
use rand::rngs::OsRng;
use rand::RngCore;
use remain::sorted;
use thiserror::Error;
use vm_memory::GuestMemory;

use super::DeviceType;
use super::Interrupt;
use super::Queue;
use super::VirtioDevice;

const QUEUE_SIZE: u16 = 256;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE];

#[sorted]
#[derive(Error, Debug)]
pub enum RngError {}
pub type Result<T> = std::result::Result<T, RngError>;

struct Worker {
    interrupt: Interrupt,
    queue: Queue,
    queue_evt: Event,
}

impl Worker {
    fn process_queue(&mut self) -> bool {
        let queue = &mut self.queue;

        let mut needs_interrupt = false;
        while let Some(mut avail_desc) = queue.pop() {
            let writer = &mut avail_desc.writer;
            let avail_bytes = writer.available_bytes();

            let mut rand_bytes = vec![0u8; avail_bytes];
            OsRng.fill_bytes(&mut rand_bytes);

            let written_size = match writer.write_all(&rand_bytes) {
                Ok(_) => rand_bytes.len(),
                Err(e) => {
                    warn!("Failed to write random data to the guest: {}", e);
                    0usize
                }
            };

            queue.add_used(avail_desc, written_size as u32);
            needs_interrupt = true;
        }

        needs_interrupt
    }

    fn run(mut self, kill_evt: Event) -> anyhow::Result<Vec<Queue>> {
        #[derive(EventToken)]
        enum Token {
            QueueAvailable,
            InterruptResample,
            Kill,
        }

        let wait_ctx: WaitContext<Token> = match WaitContext::build_with(&[
            (&self.queue_evt, Token::QueueAvailable),
            (&kill_evt, Token::Kill),
        ]) {
            Ok(pc) => pc,
            Err(e) => {
                return Err(anyhow!("failed creating WaitContext: {}", e));
            }
        };
        if let Some(resample_evt) = self.interrupt.get_resample_evt() {
            if wait_ctx
                .add(resample_evt, Token::InterruptResample)
                .is_err()
            {
                return Err(anyhow!("failed adding resample event to WaitContext."));
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
            let mut exiting = false;
            for event in events.iter().filter(|e| e.is_readable) {
                match event.token {
                    Token::QueueAvailable => {
                        if let Err(e) = self.queue_evt.wait() {
                            error!("failed reading queue Event: {}", e);
                            break 'wait;
                        }
                        needs_interrupt |= self.process_queue();
                    }
                    Token::InterruptResample => {
                        self.interrupt.interrupt_resample();
                    }
                    Token::Kill => exiting = true,
                }
            }
            if needs_interrupt {
                self.queue.trigger_interrupt(&self.interrupt);
            }
            if exiting {
                break;
            }
        }
        Ok(vec![self.queue])
    }
}

/// Virtio device for exposing entropy to the guest OS through virtio.
pub struct Rng {
    worker_thread: Option<WorkerThread<anyhow::Result<Vec<Queue>>>>,
    virtio_features: u64,
}

impl Rng {
    /// Create a new virtio rng device that gets random data from /dev/urandom.
    pub fn new(virtio_features: u64) -> Result<Rng> {
        Ok(Rng {
            worker_thread: None,
            virtio_features,
        })
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
        _mem: GuestMemory,
        interrupt: Interrupt,
        mut queues: BTreeMap<usize, (Queue, Event)>,
    ) -> anyhow::Result<()> {
        if queues.len() != 1 {
            return Err(anyhow!("expected 1 queue, got {}", queues.len()));
        }

        let (queue, queue_evt) = queues.remove(&0).unwrap();

        self.worker_thread = Some(WorkerThread::start("v_rng", move |kill_evt| {
            let worker = Worker {
                interrupt,
                queue,
                queue_evt,
            };
            worker.run(kill_evt)
        }));

        Ok(())
    }

    fn reset(&mut self) -> bool {
        if let Some(worker_thread) = self.worker_thread.take() {
            if let Err(e) = worker_thread.stop() {
                error!("rng worker failed: {:#}", e);
                return false;
            }
            return true;
        }
        false
    }

    fn virtio_sleep(&mut self) -> anyhow::Result<Option<BTreeMap<usize, Queue>>> {
        if let Some(worker_thread) = self.worker_thread.take() {
            let queues = worker_thread.stop()?;
            return Ok(Some(BTreeMap::from_iter(queues.into_iter().enumerate())));
        }
        Ok(None)
    }

    fn virtio_wake(
        &mut self,
        queues_state: Option<(GuestMemory, Interrupt, BTreeMap<usize, (Queue, Event)>)>,
    ) -> anyhow::Result<()> {
        if let Some((mem, interrupt, queues)) = queues_state {
            self.activate(mem, interrupt, queues)?;
        }
        Ok(())
    }

    fn virtio_snapshot(&self) -> anyhow::Result<serde_json::Value> {
        // `virtio_sleep` ensures there is no pending state, except for the `Queue`s, which are
        // handled at a higher layer.
        Ok(serde_json::Value::Null)
    }

    fn virtio_restore(&mut self, data: serde_json::Value) -> anyhow::Result<()> {
        anyhow::ensure!(
            data == serde_json::Value::Null,
            "unexpected snapshot data: should be null, got {}",
            data,
        );
        Ok(())
    }
}
