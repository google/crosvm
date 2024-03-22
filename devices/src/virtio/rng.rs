// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::io::Write;

use anyhow::anyhow;
use anyhow::Context;
use base::error;
use base::warn;
use base::Event;
use base::EventToken;
use base::RawDescriptor;
use base::WaitContext;
use base::WorkerThread;
use rand::rngs::OsRng;
use rand::RngCore;
use vm_memory::GuestMemory;

use super::DeviceType;
use super::Interrupt;
use super::Queue;
use super::VirtioDevice;

const QUEUE_SIZE: u16 = 256;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE];

struct Worker {
    interrupt: Interrupt,
    queue: Queue,
}

impl Worker {
    fn process_queue(&mut self) {
        let mut needs_interrupt = false;
        while let Some(mut avail_desc) = self.queue.pop() {
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

            self.queue.add_used(avail_desc, written_size as u32);
            needs_interrupt = true;
        }

        if needs_interrupt {
            self.queue.trigger_interrupt(&self.interrupt);
        }
    }

    fn run(&mut self, kill_evt: Event) -> anyhow::Result<()> {
        #[derive(EventToken)]
        enum Token {
            QueueAvailable,
            InterruptResample,
            Kill,
        }

        let wait_ctx = WaitContext::build_with(&[
            (self.queue.event(), Token::QueueAvailable),
            (&kill_evt, Token::Kill),
        ])
        .context("failed creating WaitContext")?;

        if let Some(resample_evt) = self.interrupt.get_resample_evt() {
            wait_ctx
                .add(resample_evt, Token::InterruptResample)
                .context("failed adding resample event to WaitContext.")?;
        }

        let mut exiting = false;
        while !exiting {
            let events = wait_ctx.wait().context("failed polling for events")?;
            for event in events.iter().filter(|e| e.is_readable) {
                match event.token {
                    Token::QueueAvailable => {
                        self.queue
                            .event()
                            .wait()
                            .context("failed reading queue Event")?;
                        self.process_queue();
                    }
                    Token::InterruptResample => {
                        self.interrupt.interrupt_resample();
                    }
                    Token::Kill => exiting = true,
                }
            }
        }

        Ok(())
    }
}

/// Virtio device for exposing entropy to the guest OS through virtio.
pub struct Rng {
    worker_thread: Option<WorkerThread<Worker>>,
    virtio_features: u64,
}

impl Rng {
    /// Create a new virtio rng device that gets random data from /dev/urandom.
    pub fn new(virtio_features: u64) -> anyhow::Result<Rng> {
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
        mut queues: BTreeMap<usize, Queue>,
    ) -> anyhow::Result<()> {
        if queues.len() != 1 {
            return Err(anyhow!("expected 1 queue, got {}", queues.len()));
        }

        let queue = queues.remove(&0).unwrap();

        self.worker_thread = Some(WorkerThread::start("v_rng", move |kill_evt| {
            let mut worker = Worker { interrupt, queue };
            if let Err(e) = worker.run(kill_evt) {
                error!("rng worker thread failed: {:#}", e);
            }
            worker
        }));

        Ok(())
    }

    fn reset(&mut self) -> anyhow::Result<()> {
        if let Some(worker_thread) = self.worker_thread.take() {
            let _worker = worker_thread.stop();
        }
        Ok(())
    }

    fn virtio_sleep(&mut self) -> anyhow::Result<Option<BTreeMap<usize, Queue>>> {
        if let Some(worker_thread) = self.worker_thread.take() {
            let worker = worker_thread.stop();
            return Ok(Some(BTreeMap::from([(0, worker.queue)])));
        }
        Ok(None)
    }

    fn virtio_wake(
        &mut self,
        queues_state: Option<(GuestMemory, Interrupt, BTreeMap<usize, Queue>)>,
    ) -> anyhow::Result<()> {
        if let Some((mem, interrupt, queues)) = queues_state {
            self.activate(mem, interrupt, queues)?;
        }
        Ok(())
    }

    fn virtio_snapshot(&mut self) -> anyhow::Result<serde_json::Value> {
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
