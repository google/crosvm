// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::os::raw::c_ulonglong;

use sys_util::{EventFd, PollContext, PollToken};
use vhost::Vhost;

use super::{Error, Result};
use crate::virtio::{Interrupt, Queue};

/// Worker that takes care of running the vhost device.  This mainly involves forwarding interrupts
/// from the vhost driver to the guest VM because crosvm only supports the virtio-mmio transport,
/// which requires a bit to be set in the interrupt status register before triggering the interrupt
/// and the vhost driver doesn't do this for us.
pub struct Worker<T: Vhost> {
    interrupt: Interrupt,
    queues: Vec<Queue>,
    pub vhost_handle: T,
    pub vhost_interrupt: Vec<EventFd>,
    acked_features: u64,
    pub kill_evt: EventFd,
}

impl<T: Vhost> Worker<T> {
    pub fn new(
        queues: Vec<Queue>,
        vhost_handle: T,
        vhost_interrupt: Vec<EventFd>,
        interrupt: Interrupt,
        acked_features: u64,
        kill_evt: EventFd,
    ) -> Worker<T> {
        Worker {
            interrupt,
            queues,
            vhost_handle,
            vhost_interrupt,
            acked_features,
            kill_evt,
        }
    }

    pub fn run<F1, F2>(
        &mut self,
        queue_evts: Vec<EventFd>,
        queue_sizes: &[u16],
        activate_vqs: F1,
        cleanup_vqs: F2,
    ) -> Result<()>
    where
        F1: FnOnce(&T) -> Result<()>,
        F2: FnOnce(&T) -> Result<()>,
    {
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
                .set_vring_call(queue_index, &self.vhost_interrupt[queue_index])
                .map_err(Error::VhostSetVringCall)?;
            self.vhost_handle
                .set_vring_kick(queue_index, &queue_evts[queue_index])
                .map_err(Error::VhostSetVringKick)?;
        }

        activate_vqs(&self.vhost_handle)?;

        #[derive(PollToken)]
        enum Token {
            VhostIrqi { index: usize },
            InterruptResample,
            Kill,
        }

        let poll_ctx: PollContext<Token> = PollContext::build_with(&[
            (self.interrupt.get_resample_evt(), Token::InterruptResample),
            (&self.kill_evt, Token::Kill),
        ])
        .map_err(Error::CreatePollContext)?;

        for (index, vhost_int) in self.vhost_interrupt.iter().enumerate() {
            poll_ctx
                .add(vhost_int, Token::VhostIrqi { index })
                .map_err(Error::CreatePollContext)?;
        }

        'poll: loop {
            let events = poll_ctx.wait().map_err(Error::PollError)?;

            for event in events.iter_readable() {
                match event.token() {
                    Token::VhostIrqi { index } => {
                        self.vhost_interrupt[index]
                            .read()
                            .map_err(Error::VhostIrqRead)?;
                        self.interrupt.signal_used_queue(self.queues[index].vector);
                    }
                    Token::InterruptResample => {
                        self.interrupt.interrupt_resample();
                    }
                    Token::Kill => {
                        let _ = self.kill_evt.read();
                        break 'poll;
                    }
                }
            }
        }
        cleanup_vqs(&self.vhost_handle)?;
        Ok(())
    }
}
