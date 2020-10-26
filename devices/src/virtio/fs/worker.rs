// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::io;
use std::sync::Arc;

use base::{error, Event, PollToken, WaitContext};
use fuse::filesystem::{FileSystem, ZeroCopyReader, ZeroCopyWriter};
use vm_memory::GuestMemory;

use crate::virtio::fs::{Error, Result};
use crate::virtio::{Interrupt, Queue, Reader, Writer};

impl fuse::Reader for Reader {}

impl fuse::Writer for Writer {
    fn write_at<F>(&mut self, offset: usize, f: F) -> io::Result<usize>
    where
        F: Fn(&mut Self) -> io::Result<usize>,
    {
        let mut writer = Writer::split_at(self, offset);
        f(&mut writer)
    }

    fn has_sufficient_buffer(&self, size: u32) -> bool {
        self.available_bytes() >= size as usize
    }
}

impl ZeroCopyReader for Reader {
    fn read_to(&mut self, f: &mut File, count: usize, off: u64) -> io::Result<usize> {
        self.read_to_at(f, count, off)
    }
}

impl ZeroCopyWriter for Writer {
    fn write_from(&mut self, f: &mut File, count: usize, off: u64) -> io::Result<usize> {
        self.write_from_at(f, count, off)
    }
}
pub struct Worker<F: FileSystem + Sync> {
    mem: GuestMemory,
    queue: Queue,
    server: Arc<fuse::Server<F>>,
    irq: Arc<Interrupt>,
}

impl<F: FileSystem + Sync> Worker<F> {
    pub fn new(
        mem: GuestMemory,
        queue: Queue,
        server: Arc<fuse::Server<F>>,
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
            let reader = Reader::new(self.mem.clone(), avail_desc.clone())
                .map_err(Error::InvalidDescriptorChain)?;
            let writer = Writer::new(self.mem.clone(), avail_desc.clone())
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
        queue_evt: Event,
        kill_evt: Event,
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

        let wait_ctx =
            WaitContext::build_with(&[(&queue_evt, Token::QueueReady), (&kill_evt, Token::Kill)])
                .map_err(Error::CreateWaitContext)?;

        if watch_resample_event {
            wait_ctx
                .add(self.irq.get_resample_evt(), Token::InterruptResample)
                .map_err(Error::CreateWaitContext)?;
        }

        loop {
            let events = wait_ctx.wait().map_err(Error::WaitError)?;
            for event in events.iter().filter(|e| e.is_readable) {
                match event.token {
                    Token::QueueReady => {
                        queue_evt.read().map_err(Error::ReadQueueEvent)?;
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
