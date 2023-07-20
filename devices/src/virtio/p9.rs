// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;
use std::io::Write;
use std::mem;
use std::result;

use anyhow::anyhow;
use anyhow::Context;
use base::error;
use base::warn;
use base::Error as SysError;
use base::Event;
use base::EventToken;
use base::RawDescriptor;
use base::WaitContext;
use base::WorkerThread;
use remain::sorted;
use thiserror::Error;
use vm_memory::GuestMemory;

use super::copy_config;
use super::queue::Queue;
use super::DeviceType;
use super::Interrupt;
use super::VirtioDevice;

const QUEUE_SIZE: u16 = 128;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE];

// The only virtio_9p feature.
const VIRTIO_9P_MOUNT_TAG: u8 = 0;

/// Errors that occur during operation of a virtio 9P device.
#[sorted]
#[derive(Error, Debug)]
pub enum P9Error {
    /// Failed to create a 9p server.
    #[error("failed to create 9p server: {0}")]
    CreateServer(io::Error),
    /// Creating WaitContext failed.
    #[error("failed to create WaitContext: {0}")]
    CreateWaitContext(SysError),
    /// An internal I/O error occurred.
    #[error("P9 internal server error: {0}")]
    Internal(io::Error),
    /// A request is missing readable descriptors.
    #[error("request does not have any readable descriptors")]
    NoReadableDescriptors,
    /// A request is missing writable descriptors.
    #[error("request does not have any writable descriptors")]
    NoWritableDescriptors,
    /// Error while reading from the virtio queue's Event.
    #[error("failed to read from virtio queue Event: {0}")]
    ReadQueueEvent(SysError),
    /// Failed to signal the virio used queue.
    #[error("failed to signal used queue: {0}")]
    SignalUsedQueue(SysError),
    /// The tag for the 9P device was too large to fit in the config space.
    #[error("P9 device tag is too long: len = {0}, max = {}", ::std::u16::MAX)]
    TagTooLong(usize),
    /// Error while polling for events.
    #[error("failed to wait for events: {0}")]
    WaitError(SysError),
}

pub type P9Result<T> = result::Result<T, P9Error>;

struct Worker {
    interrupt: Interrupt,
    mem: GuestMemory,
    queue: Queue,
    queue_evt: Event,
    server: p9::Server,
}

impl Worker {
    fn process_queue(&mut self) -> P9Result<()> {
        while let Some(mut avail_desc) = self.queue.pop(&self.mem) {
            self.server
                .handle_message(&mut avail_desc.reader, &mut avail_desc.writer)
                .map_err(P9Error::Internal)?;

            let len = avail_desc.writer.bytes_written() as u32;

            self.queue.add_used(&self.mem, avail_desc, len);
        }
        self.queue.trigger_interrupt(&self.mem, &self.interrupt);

        Ok(())
    }

    fn run(&mut self, kill_evt: Event) -> P9Result<()> {
        #[derive(EventToken)]
        enum Token {
            // A request is ready on the queue.
            QueueReady,
            // Check if any interrupts need to be re-asserted.
            InterruptResample,
            // The parent thread requested an exit.
            Kill,
        }

        let wait_ctx: WaitContext<Token> = WaitContext::build_with(&[
            (&self.queue_evt, Token::QueueReady),
            (&kill_evt, Token::Kill),
        ])
        .map_err(P9Error::CreateWaitContext)?;
        if let Some(resample_evt) = self.interrupt.get_resample_evt() {
            wait_ctx
                .add(resample_evt, Token::InterruptResample)
                .map_err(P9Error::CreateWaitContext)?;
        }

        loop {
            let events = wait_ctx.wait().map_err(P9Error::WaitError)?;
            for event in events.iter().filter(|e| e.is_readable) {
                match event.token {
                    Token::QueueReady => {
                        self.queue_evt.wait().map_err(P9Error::ReadQueueEvent)?;
                        self.process_queue()?;
                    }
                    Token::InterruptResample => {
                        self.interrupt.interrupt_resample();
                    }
                    Token::Kill => return Ok(()),
                }
            }
        }
    }
}

/// Virtio device for sharing specific directories on the host system with the guest VM.
pub struct P9 {
    config: Vec<u8>,
    server: Option<p9::Server>,
    avail_features: u64,
    acked_features: u64,
    worker: Option<WorkerThread<P9Result<()>>>,
}

impl P9 {
    pub fn new(base_features: u64, tag: &str, p9_cfg: p9::Config) -> P9Result<P9> {
        if tag.len() > ::std::u16::MAX as usize {
            return Err(P9Error::TagTooLong(tag.len()));
        }

        let len = tag.len() as u16;
        let mut cfg = Vec::with_capacity(tag.len() + mem::size_of::<u16>());
        cfg.push(len as u8);
        cfg.push((len >> 8) as u8);

        cfg.write_all(tag.as_bytes()).map_err(P9Error::Internal)?;

        let server = p9::Server::with_config(p9_cfg).map_err(P9Error::CreateServer)?;
        Ok(P9 {
            config: cfg,
            server: Some(server),
            avail_features: base_features | 1 << VIRTIO_9P_MOUNT_TAG,
            acked_features: 0,
            worker: None,
        })
    }
}

impl VirtioDevice for P9 {
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        self.server
            .as_ref()
            .map(p9::Server::keep_fds)
            .unwrap_or_else(Vec::new)
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::P9
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn features(&self) -> u64 {
        self.avail_features
    }

    fn ack_features(&mut self, value: u64) {
        let mut v = value;

        // Check if the guest is ACK'ing a feature that we didn't claim to have.
        let unrequested_features = v & !self.avail_features;
        if unrequested_features != 0 {
            warn!("virtio_9p got unknown feature ack: {:x}", v);

            // Don't count these features as acked.
            v &= !unrequested_features;
        }
        self.acked_features |= v;
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        copy_config(data, 0, self.config.as_slice(), offset);
    }

    fn activate(
        &mut self,
        guest_mem: GuestMemory,
        interrupt: Interrupt,
        mut queues: Vec<(Queue, Event)>,
    ) -> anyhow::Result<()> {
        if queues.len() != 1 {
            return Err(anyhow!("expected 1 queue, got {}", queues.len()));
        }

        let (queue, queue_evt) = queues.remove(0);

        let server = self.server.take().context("missing server")?;

        self.worker = Some(WorkerThread::start("v_9p", move |kill_evt| {
            let mut worker = Worker {
                interrupt,
                mem: guest_mem,
                queue,
                queue_evt,
                server,
            };

            worker.run(kill_evt)
        }));

        Ok(())
    }
}
