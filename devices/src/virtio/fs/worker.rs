// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;

use sys_util::{error, EventFd, GuestMemory, PollContext, PollToken};

use crate::virtio::fs::filesystem::FileSystem;
use crate::virtio::fs::server::Server;
use crate::virtio::fs::{Error, Result};
use crate::virtio::{Interrupt, Queue, Reader, Writer};

pub struct Worker<F: FileSystem + Sync> {
    mem: GuestMemory,
    queue: Queue,
    server: Arc<Server<F>>,
    irq: Arc<Interrupt>,
}

impl<F: FileSystem + Sync> Worker<F> {
    pub fn new(
        mem: GuestMemory,
        queue: Queue,
        server: Arc<Server<F>>,
        irq: Arc<Interrupt>,
    ) -> Worker<F> {
        Worker {
            mem,
            queue,
            server,
            irq,
        }
    }

    fn process_queue(&mut self) -> Result<()> {
        let mut needs_interrupt = false;
        while let Some(avail_desc) = self.queue.pop(&self.mem) {
            let reader = Reader::new(&self.mem, avail_desc.clone())
                .map_err(Error::InvalidDescriptorChain)?;
            let writer = Writer::new(&self.mem, avail_desc.clone())
                .map_err(Error::InvalidDescriptorChain)?;

            let total = self.server.handle_message(reader, writer)?;

            self.queue
                .add_used(&self.mem, avail_desc.index, total as u32);

            needs_interrupt = true;
        }

        if needs_interrupt {
            self.irq.signal_used_queue(self.queue.vector);
        }

        Ok(())
    }

    pub fn run(
        &mut self,
        queue_evt: EventFd,
        kill_evt: EventFd,
        watch_resample_event: bool,
    ) -> Result<()> {
        #[derive(PollToken)]
        enum Token {
            // A request is ready on the queue.
            QueueReady,
            // Check if any interrupts need to be re-asserted.
            InterruptResample,
            // The parent thread requested an exit.
            Kill,
        }

        let poll_ctx =
            PollContext::build_with(&[(&queue_evt, Token::QueueReady), (&kill_evt, Token::Kill)])
                .map_err(Error::CreatePollContext)?;

        if watch_resample_event {
            poll_ctx
                .add(self.irq.get_resample_evt(), Token::InterruptResample)
                .map_err(Error::CreatePollContext)?;
        }

        loop {
            let events = poll_ctx.wait().map_err(Error::PollError)?;
            for event in events.iter_readable() {
                match event.token() {
                    Token::QueueReady => {
                        queue_evt.read().map_err(Error::ReadQueueEventFd)?;
                        if let Err(e) = self.process_queue() {
                            error!("virtio-fs transport error: {}", e);
                            return Err(e);
                        }
                    }
                    Token::InterruptResample => {
                        self.irq.interrupt_resample();
                    }
                    Token::Kill => return Ok(()),
                }
            }
        }
    }
}
