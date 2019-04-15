// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::os::raw::c_ulonglong;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use sys_util::{EventFd, PollContext, PollToken};
use vhost::Vhost;

use super::{Error, Result};
use crate::virtio::{Queue, INTERRUPT_STATUS_USED_RING};

/// Worker that takes care of running the vhost device.  This mainly involves forwarding interrupts
/// from the vhost driver to the guest VM because crosvm only supports the virtio-mmio transport,
/// which requires a bit to be set in the interrupt status register before triggering the interrupt
/// and the vhost driver doesn't do this for us.
pub struct Worker<T: Vhost> {
    queues: Vec<Queue>,
    vhost_handle: T,
    vhost_interrupt: EventFd,
    interrupt_status: Arc<AtomicUsize>,
    interrupt_evt: EventFd,
    interrupt_resample_evt: EventFd,
    acked_features: u64,
}

impl<T: Vhost> Worker<T> {
    pub fn new(
        queues: Vec<Queue>,
        vhost_handle: T,
        vhost_interrupt: EventFd,
        interrupt_status: Arc<AtomicUsize>,
        interrupt_evt: EventFd,
        interrupt_resample_evt: EventFd,
        acked_features: u64,
    ) -> Worker<T> {
        Worker {
            queues,
            vhost_handle,
            vhost_interrupt,
            interrupt_status,
            interrupt_evt,
            interrupt_resample_evt,
            acked_features,
        }
    }

    fn signal_used_queue(&self) {
        self.interrupt_status
            .fetch_or(INTERRUPT_STATUS_USED_RING as usize, Ordering::SeqCst);
        self.interrupt_evt.write(1).unwrap();
    }

    pub fn run<F>(
        &mut self,
        queue_evts: Vec<EventFd>,
        queue_sizes: &[u16],
        kill_evt: EventFd,
        activate_vqs: F,
    ) -> Result<()>
    where
        F: FnOnce(&T) -> Result<()>,
    {
        // Preliminary setup for vhost net.
        self.vhost_handle
            .set_owner()
            .map_err(Error::VhostSetOwner)?;

        let avail_features = self
            .vhost_handle
            .get_features()
            .map_err(Error::VhostGetFeatures)?;

        let features: c_ulonglong = self.acked_features & avail_features;
        self.vhost_handle
            .set_features(features)
            .map_err(Error::VhostSetFeatures)?;

        self.vhost_handle
            .set_mem_table()
            .map_err(Error::VhostSetMemTable)?;

        for (queue_index, queue) in self.queues.iter().enumerate() {
            self.vhost_handle
                .set_vring_num(queue_index, queue.max_size)
                .map_err(Error::VhostSetVringNum)?;

            self.vhost_handle
                .set_vring_addr(
                    queue_sizes[queue_index],
                    queue.actual_size(),
                    queue_index,
                    0,
                    queue.desc_table,
                    queue.used_ring,
                    queue.avail_ring,
                    None,
                )
                .map_err(Error::VhostSetVringAddr)?;
            self.vhost_handle
                .set_vring_base(queue_index, 0)
                .map_err(Error::VhostSetVringBase)?;
            self.vhost_handle
                .set_vring_call(queue_index, &self.vhost_interrupt)
                .map_err(Error::VhostSetVringCall)?;
            self.vhost_handle
                .set_vring_kick(queue_index, &queue_evts[queue_index])
                .map_err(Error::VhostSetVringKick)?;
        }

        activate_vqs(&self.vhost_handle)?;

        #[derive(PollToken)]
        enum Token {
            VhostIrq,
            InterruptResample,
            Kill,
        }

        let poll_ctx: PollContext<Token> = PollContext::new()
            .and_then(|pc| pc.add(&self.vhost_interrupt, Token::VhostIrq).and(Ok(pc)))
            .and_then(|pc| {
                pc.add(&self.interrupt_resample_evt, Token::InterruptResample)
                    .and(Ok(pc))
            })
            .and_then(|pc| pc.add(&kill_evt, Token::Kill).and(Ok(pc)))
            .map_err(Error::CreatePollContext)?;

        'poll: loop {
            let events = poll_ctx.wait().map_err(Error::PollError)?;

            let mut needs_interrupt = false;
            for event in events.iter_readable() {
                match event.token() {
                    Token::VhostIrq => {
                        needs_interrupt = true;
                        self.vhost_interrupt.read().map_err(Error::VhostIrqRead)?;
                    }
                    Token::InterruptResample => {
                        let _ = self.interrupt_resample_evt.read();
                        if self.interrupt_status.load(Ordering::SeqCst) != 0 {
                            self.interrupt_evt.write(1).unwrap();
                        }
                    }
                    Token::Kill => break 'poll,
                }
            }
            if needs_interrupt {
                self.signal_used_queue();
            }
        }
        Ok(())
    }
}
