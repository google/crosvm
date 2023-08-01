// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;

use base::error;
use base::Error as SysError;
use base::Event;
use base::EventToken;
use base::Tube;
use base::WaitContext;
use libc::EIO;
use serde::Deserialize;
use serde::Serialize;
use vhost::Vhost;
use vm_memory::GuestMemory;

use super::control_socket::VhostDevRequest;
use super::control_socket::VhostDevResponse;
use super::Error;
use super::Result;
use crate::virtio::Interrupt;
use crate::virtio::Queue;
use crate::virtio::VIRTIO_F_ACCESS_PLATFORM;

#[derive(Clone, Serialize, Deserialize)]
pub struct VringBase {
    pub index: usize,
    pub base: u16,
}

/// Worker that takes care of running the vhost device.
pub struct Worker<T: Vhost> {
    interrupt: Interrupt,
    pub queues: BTreeMap<usize, Queue>,
    pub vhost_handle: T,
    pub vhost_interrupt: Vec<Event>,
    acked_features: u64,
    pub response_tube: Option<Tube>,
    uses_viommu: bool,
}

impl<T: Vhost> Worker<T> {
    pub fn new(
        queues: BTreeMap<usize, Queue>,
        vhost_handle: T,
        vhost_interrupt: Vec<Event>,
        interrupt: Interrupt,
        acked_features: u64,
        response_tube: Option<Tube>,
        uses_viommu: bool,
    ) -> Worker<T> {
        Worker {
            interrupt,
            queues,
            vhost_handle,
            vhost_interrupt,
            acked_features,
            response_tube,
            uses_viommu,
        }
    }

    pub fn init<F1>(
        &mut self,
        mem: GuestMemory,
        queue_sizes: &[u16],
        activate_vqs: F1,
        queue_vrings_base: Option<Vec<VringBase>>,
    ) -> Result<()>
    where
        F1: FnOnce(&T) -> Result<()>,
    {
        let avail_features = self
            .vhost_handle
            .get_features()
            .map_err(Error::VhostGetFeatures)?;

        let mut features = self.acked_features & avail_features;
        if self.acked_features & (1u64 << VIRTIO_F_ACCESS_PLATFORM) != 0 {
            // Crosvm doesn't implement the vhost IOTLB APIs.
            if self.uses_viommu {
                return Err(Error::VhostIotlbUnsupported);
            }
            // The vhost API is a bit poorly named, this flag in the context of vhost
            // means that it will do address translation via its IOTLB APIs. If the
            // underlying virtio device doesn't use viommu, it doesn't need vhost
            // translation.
            features &= !(1u64 << VIRTIO_F_ACCESS_PLATFORM);
        }

        self.vhost_handle
            .set_features(features)
            .map_err(Error::VhostSetFeatures)?;

        self.vhost_handle
            .set_mem_table(&mem)
            .map_err(Error::VhostSetMemTable)?;

        for (&queue_index, queue) in self.queues.iter() {
            self.vhost_handle
                .set_vring_num(queue_index, queue.size())
                .map_err(Error::VhostSetVringNum)?;

            self.vhost_handle
                .set_vring_addr(
                    &mem,
                    queue_sizes[queue_index],
                    queue.size(),
                    queue_index,
                    0,
                    queue.desc_table(),
                    queue.used_ring(),
                    queue.avail_ring(),
                    None,
                )
                .map_err(Error::VhostSetVringAddr)?;
            if let Some(vrings_base) = &queue_vrings_base {
                let base = if let Some(vring_base) = vrings_base
                    .iter()
                    .find(|vring_base| vring_base.index == queue_index)
                {
                    vring_base.base
                } else {
                    return Err(Error::VringBaseMissing);
                };
                self.vhost_handle
                    .set_vring_base(queue_index, base)
                    .map_err(Error::VhostSetVringBase)?;
            } else {
                self.vhost_handle
                    .set_vring_base(queue_index, 0)
                    .map_err(Error::VhostSetVringBase)?;
            }
            self.set_vring_call_for_entry(queue_index, queue.vector() as usize)?;
            self.vhost_handle
                .set_vring_kick(queue_index, queue.event())
                .map_err(Error::VhostSetVringKick)?;
        }

        activate_vqs(&self.vhost_handle)?;
        Ok(())
    }

    pub fn run<F1>(&mut self, cleanup_vqs: F1, kill_evt: Event) -> Result<()>
    where
        F1: FnOnce(&T) -> Result<()>,
    {
        #[derive(EventToken)]
        enum Token {
            VhostIrqi { index: usize },
            InterruptResample,
            Kill,
            ControlNotify,
        }

        let wait_ctx: WaitContext<Token> = WaitContext::build_with(&[(&kill_evt, Token::Kill)])
            .map_err(Error::CreateWaitContext)?;

        for (index, vhost_int) in self.vhost_interrupt.iter().enumerate() {
            wait_ctx
                .add(vhost_int, Token::VhostIrqi { index })
                .map_err(Error::CreateWaitContext)?;
        }
        if let Some(socket) = &self.response_tube {
            wait_ctx
                .add(socket, Token::ControlNotify)
                .map_err(Error::CreateWaitContext)?;
        }
        if let Some(resample_evt) = self.interrupt.get_resample_evt() {
            wait_ctx
                .add(resample_evt, Token::InterruptResample)
                .map_err(Error::CreateWaitContext)?;
        }

        'wait: loop {
            let events = wait_ctx.wait().map_err(Error::WaitError)?;

            for event in events.iter().filter(|e| e.is_readable) {
                match event.token {
                    Token::VhostIrqi { index } => {
                        self.vhost_interrupt[index]
                            .wait()
                            .map_err(Error::VhostIrqRead)?;
                        self.interrupt
                            .signal_used_queue(self.queues[&index].vector());
                    }
                    Token::InterruptResample => {
                        self.interrupt.interrupt_resample();
                    }
                    Token::Kill => {
                        let _ = kill_evt.wait();
                        break 'wait;
                    }
                    Token::ControlNotify => {
                        if let Some(socket) = &self.response_tube {
                            match socket.recv() {
                                Ok(VhostDevRequest::MsixEntryChanged(index)) => {
                                    let mut qindex = 0;
                                    for (&queue_index, queue) in self.queues.iter() {
                                        if queue.vector() == index as u16 {
                                            qindex = queue_index;
                                            break;
                                        }
                                    }
                                    let response =
                                        match self.set_vring_call_for_entry(qindex, index) {
                                            Ok(()) => VhostDevResponse::Ok,
                                            Err(e) => {
                                                error!(
                                                "Set vring call failed for masked entry {}: {:?}",
                                                index, e
                                            );
                                                VhostDevResponse::Err(SysError::new(EIO))
                                            }
                                        };
                                    if let Err(e) = socket.send(&response) {
                                        error!("Vhost failed to send VhostMsixEntryMasked Response for entry {}: {:?}", index, e);
                                    }
                                }
                                Ok(VhostDevRequest::MsixChanged) => {
                                    let response = match self.set_vring_calls() {
                                        Ok(()) => VhostDevResponse::Ok,
                                        Err(e) => {
                                            error!("Set vring calls failed: {:?}", e);
                                            VhostDevResponse::Err(SysError::new(EIO))
                                        }
                                    };
                                    if let Err(e) = socket.send(&response) {
                                        error!(
                                            "Vhost failed to send VhostMsixMasked Response: {:?}",
                                            e
                                        );
                                    }
                                }
                                Err(e) => {
                                    error!("Vhost failed to receive Control request: {:?}", e);
                                }
                            }
                        }
                    }
                }
            }
        }
        cleanup_vqs(&self.vhost_handle)?;
        Ok(())
    }

    fn set_vring_call_for_entry(&self, queue_index: usize, vector: usize) -> Result<()> {
        // No response_socket means it doesn't have any control related
        // with the msix. Due to this, cannot use the direct irq fd but
        // should fall back to indirect irq fd.
        if self.response_tube.is_some() {
            if let Some(msix_config) = self.interrupt.get_msix_config() {
                let msix_config = msix_config.lock();
                let msix_masked = msix_config.masked();
                if msix_masked {
                    return Ok(());
                }
                if !msix_config.table_masked(vector) {
                    if let Some(irqfd) = msix_config.get_irqfd(vector) {
                        self.vhost_handle
                            .set_vring_call(queue_index, irqfd)
                            .map_err(Error::VhostSetVringCall)?;
                    } else {
                        self.vhost_handle
                            .set_vring_call(queue_index, &self.vhost_interrupt[queue_index])
                            .map_err(Error::VhostSetVringCall)?;
                    }
                    return Ok(());
                }
            }
        }

        self.vhost_handle
            .set_vring_call(queue_index, &self.vhost_interrupt[queue_index])
            .map_err(Error::VhostSetVringCall)?;
        Ok(())
    }

    fn set_vring_calls(&self) -> Result<()> {
        if let Some(msix_config) = self.interrupt.get_msix_config() {
            let msix_config = msix_config.lock();
            if msix_config.masked() {
                for (&queue_index, _) in self.queues.iter() {
                    self.vhost_handle
                        .set_vring_call(queue_index, &self.vhost_interrupt[queue_index])
                        .map_err(Error::VhostSetVringCall)?;
                }
            } else {
                for (&queue_index, queue) in self.queues.iter() {
                    let vector = queue.vector() as usize;
                    if !msix_config.table_masked(vector) {
                        if let Some(irqfd) = msix_config.get_irqfd(vector) {
                            self.vhost_handle
                                .set_vring_call(queue_index, irqfd)
                                .map_err(Error::VhostSetVringCall)?;
                        } else {
                            self.vhost_handle
                                .set_vring_call(queue_index, &self.vhost_interrupt[queue_index])
                                .map_err(Error::VhostSetVringCall)?;
                        }
                    } else {
                        self.vhost_handle
                            .set_vring_call(queue_index, &self.vhost_interrupt[queue_index])
                            .map_err(Error::VhostSetVringCall)?;
                    }
                }
            }
        }
        Ok(())
    }
}
