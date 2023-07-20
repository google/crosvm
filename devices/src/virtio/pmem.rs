// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::fs::File;
use std::io;

use anyhow::anyhow;
use anyhow::Context;
use base::error;
use base::AsRawDescriptor;
use base::Error as SysError;
use base::Event;
use base::RawDescriptor;
use base::Result as SysResult;
use base::Tube;
use base::WorkerThread;
use cros_async::select3;
use cros_async::EventAsync;
use cros_async::Executor;
use data_model::Le32;
use data_model::Le64;
use futures::pin_mut;
use remain::sorted;
use thiserror::Error;
use vm_control::MemSlot;
use vm_control::VmMsyncRequest;
use vm_control::VmMsyncResponse;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
use zerocopy::AsBytes;
use zerocopy::FromBytes;

use super::async_utils;
use super::copy_config;
use super::DescriptorChain;
use super::DeviceType;
use super::Interrupt;
use super::Queue;
use super::VirtioDevice;

const QUEUE_SIZE: u16 = 256;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE];

const VIRTIO_PMEM_REQ_TYPE_FLUSH: u32 = 0;
const VIRTIO_PMEM_RESP_TYPE_OK: u32 = 0;
const VIRTIO_PMEM_RESP_TYPE_EIO: u32 = 1;

#[derive(Copy, Clone, Debug, Default, AsBytes, FromBytes)]
#[repr(C)]
struct virtio_pmem_config {
    start_address: Le64,
    size: Le64,
}

#[derive(Copy, Clone, Debug, Default, AsBytes, FromBytes)]
#[repr(C)]
struct virtio_pmem_resp {
    status_code: Le32,
}

#[derive(Copy, Clone, Debug, Default, AsBytes, FromBytes)]
#[repr(C)]
struct virtio_pmem_req {
    type_: Le32,
}

#[sorted]
#[derive(Error, Debug)]
enum Error {
    /// Failed to read from virtqueue.
    #[error("failed to read from virtqueue: {0}")]
    ReadQueue(io::Error),
    /// Failed to write to virtqueue.
    #[error("failed to write to virtqueue: {0}")]
    WriteQueue(io::Error),
}

type Result<T> = ::std::result::Result<T, Error>;

fn execute_request(
    request: virtio_pmem_req,
    pmem_device_tube: &Tube,
    mapping_arena_slot: u32,
    mapping_size: usize,
) -> u32 {
    match request.type_.to_native() {
        VIRTIO_PMEM_REQ_TYPE_FLUSH => {
            let request = VmMsyncRequest::MsyncArena {
                slot: mapping_arena_slot,
                offset: 0, // The pmem backing file is always at offset 0 in the arena.
                size: mapping_size,
            };

            if let Err(e) = pmem_device_tube.send(&request) {
                error!("failed to send request: {}", e);
                return VIRTIO_PMEM_RESP_TYPE_EIO;
            }

            match pmem_device_tube.recv() {
                Ok(response) => match response {
                    VmMsyncResponse::Ok => VIRTIO_PMEM_RESP_TYPE_OK,
                    VmMsyncResponse::Err(e) => {
                        error!("failed flushing disk image: {}", e);
                        VIRTIO_PMEM_RESP_TYPE_EIO
                    }
                },
                Err(e) => {
                    error!("failed to receive data: {}", e);
                    VIRTIO_PMEM_RESP_TYPE_EIO
                }
            }
        }
        _ => {
            error!("unknown request type: {}", request.type_.to_native());
            VIRTIO_PMEM_RESP_TYPE_EIO
        }
    }
}

fn handle_request(
    avail_desc: &mut DescriptorChain,
    pmem_device_tube: &Tube,
    mapping_arena_slot: u32,
    mapping_size: usize,
) -> Result<usize> {
    let status_code = avail_desc
        .reader
        .read_obj()
        .map(|request| execute_request(request, pmem_device_tube, mapping_arena_slot, mapping_size))
        .map_err(Error::ReadQueue)?;

    let response = virtio_pmem_resp {
        status_code: status_code.into(),
    };

    avail_desc
        .writer
        .write_obj(response)
        .map_err(Error::WriteQueue)?;

    Ok(avail_desc.writer.bytes_written())
}

async fn handle_queue(
    mem: &GuestMemory,
    queue: &mut Queue,
    mut queue_event: EventAsync,
    interrupt: Interrupt,
    pmem_device_tube: Tube,
    mapping_arena_slot: u32,
    mapping_size: usize,
) {
    loop {
        let mut avail_desc = match queue.next_async(mem, &mut queue_event).await {
            Err(e) => {
                error!("Failed to read descriptor {}", e);
                return;
            }
            Ok(d) => d,
        };

        let written = match handle_request(
            &mut avail_desc,
            &pmem_device_tube,
            mapping_arena_slot,
            mapping_size,
        ) {
            Ok(n) => n,
            Err(e) => {
                error!("pmem: failed to handle request: {}", e);
                0
            }
        };
        queue.add_used(mem, avail_desc, written as u32);
        queue.trigger_interrupt(mem, &interrupt);
    }
}

fn run_worker(
    queue_evt: Event,
    queue: &mut Queue,
    pmem_device_tube: Tube,
    interrupt: Interrupt,
    kill_evt: Event,
    mem: GuestMemory,
    mapping_arena_slot: u32,
    mapping_size: usize,
) {
    let ex = Executor::new().unwrap();

    let queue_evt = EventAsync::new(queue_evt, &ex).expect("failed to set up the queue event");

    // Process requests from the virtio queue.
    let queue_fut = handle_queue(
        &mem,
        queue,
        queue_evt,
        interrupt.clone(),
        pmem_device_tube,
        mapping_arena_slot,
        mapping_size,
    );
    pin_mut!(queue_fut);

    // Process any requests to resample the irq value.
    let resample = async_utils::handle_irq_resample(&ex, interrupt);
    pin_mut!(resample);

    // Exit if the kill event is triggered.
    let kill = async_utils::await_and_exit(&ex, kill_evt);
    pin_mut!(kill);

    if let Err(e) = ex.run_until(select3(queue_fut, resample, kill)) {
        error!("error happened in executor: {}", e);
    }
}

pub struct Pmem {
    worker_thread: Option<WorkerThread<Queue>>,
    base_features: u64,
    disk_image: Option<File>,
    mapping_address: GuestAddress,
    mapping_arena_slot: MemSlot,
    mapping_size: u64,
    pmem_device_tube: Option<Tube>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PmemSnapshot {
    mapping_address: GuestAddress,
    mapping_size: u64,
}

impl Pmem {
    pub fn new(
        base_features: u64,
        disk_image: File,
        mapping_address: GuestAddress,
        mapping_arena_slot: MemSlot,
        mapping_size: u64,
        pmem_device_tube: Option<Tube>,
    ) -> SysResult<Pmem> {
        if mapping_size > usize::max_value() as u64 {
            return Err(SysError::new(libc::EOVERFLOW));
        }

        Ok(Pmem {
            worker_thread: None,
            base_features,
            disk_image: Some(disk_image),
            mapping_address,
            mapping_arena_slot,
            mapping_size,
            pmem_device_tube,
        })
    }
}

impl VirtioDevice for Pmem {
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        let mut keep_rds = Vec::new();
        if let Some(disk_image) = &self.disk_image {
            keep_rds.push(disk_image.as_raw_descriptor());
        }

        if let Some(ref pmem_device_tube) = self.pmem_device_tube {
            keep_rds.push(pmem_device_tube.as_raw_descriptor());
        }
        keep_rds
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::Pmem
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn features(&self) -> u64 {
        self.base_features
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let config = virtio_pmem_config {
            start_address: Le64::from(self.mapping_address.offset()),
            size: Le64::from(self.mapping_size),
        };
        copy_config(data, 0, config.as_bytes(), offset);
    }

    fn activate(
        &mut self,
        memory: GuestMemory,
        interrupt: Interrupt,
        mut queues: BTreeMap<usize, (Queue, Event)>,
    ) -> anyhow::Result<()> {
        if queues.len() != 1 {
            return Err(anyhow!("expected 1 queue, got {}", queues.len()));
        }

        let (mut queue, queue_event) = queues.remove(&0).unwrap();

        let mapping_arena_slot = self.mapping_arena_slot;
        // We checked that this fits in a usize in `Pmem::new`.
        let mapping_size = self.mapping_size as usize;

        let pmem_device_tube = self
            .pmem_device_tube
            .take()
            .context("missing pmem device tube")?;

        self.worker_thread = Some(WorkerThread::start("v_pmem", move |kill_event| {
            run_worker(
                queue_event,
                &mut queue,
                pmem_device_tube,
                interrupt,
                kill_event,
                memory,
                mapping_arena_slot,
                mapping_size,
            );
            queue
        }));

        Ok(())
    }

    fn reset(&mut self) -> bool {
        if let Some(worker_thread) = self.worker_thread.take() {
            let _queue = worker_thread.stop();
            return true;
        }
        false
    }

    fn virtio_sleep(&mut self) -> anyhow::Result<Option<BTreeMap<usize, Queue>>> {
        if let Some(worker_thread) = self.worker_thread.take() {
            let queue = worker_thread.stop();
            return Ok(Some(BTreeMap::from([(0, queue)])));
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
        serde_json::to_value(PmemSnapshot {
            mapping_address: self.mapping_address,
            mapping_size: self.mapping_size,
        })
        .context("failed to serialize pmem snapshot")
    }

    fn virtio_restore(&mut self, data: serde_json::Value) -> anyhow::Result<()> {
        let snapshot: PmemSnapshot =
            serde_json::from_value(data).context("failed to deserialize pmem snapshot")?;
        anyhow::ensure!(
            snapshot.mapping_address == self.mapping_address
                && snapshot.mapping_size == self.mapping_size,
            "pmem snapshot doesn't match config: expected {:?}, got {:?}",
            (self.mapping_address, self.mapping_size),
            (snapshot.mapping_address, snapshot.mapping_size),
        );
        Ok(())
    }
}
