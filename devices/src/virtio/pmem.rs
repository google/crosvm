// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::fs::File;
use std::io;
use std::rc::Rc;
use std::thread;

use base::{error, AsRawDescriptor, Event, RawDescriptor, Tube};
use base::{Error as SysError, Result as SysResult};
use cros_async::{select3, EventAsync, Executor};
use data_model::{DataInit, Le32, Le64};
use futures::pin_mut;
use remain::sorted;
use thiserror::Error;
use vm_control::{MemSlot, VmMsyncRequest, VmMsyncResponse};
use vm_memory::{GuestAddress, GuestMemory};

use super::{
    async_utils, copy_config, DescriptorChain, DescriptorError, Interrupt, Queue, Reader,
    VirtioDevice, Writer, TYPE_PMEM,
};

const QUEUE_SIZE: u16 = 256;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE];

const VIRTIO_PMEM_REQ_TYPE_FLUSH: u32 = 0;
const VIRTIO_PMEM_RESP_TYPE_OK: u32 = 0;
const VIRTIO_PMEM_RESP_TYPE_EIO: u32 = 1;

#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
struct virtio_pmem_config {
    start_address: Le64,
    size: Le64,
}

// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for virtio_pmem_config {}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
struct virtio_pmem_resp {
    status_code: Le32,
}

// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for virtio_pmem_resp {}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
struct virtio_pmem_req {
    type_: Le32,
}

// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for virtio_pmem_req {}

#[sorted]
#[derive(Error, Debug)]
enum Error {
    /// Invalid virtio descriptor chain.
    #[error("virtio descriptor error: {0}")]
    Descriptor(DescriptorError),
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
    mem: &GuestMemory,
    avail_desc: DescriptorChain,
    pmem_device_tube: &Tube,
    mapping_arena_slot: u32,
    mapping_size: usize,
) -> Result<usize> {
    let mut reader = Reader::new(mem.clone(), avail_desc.clone()).map_err(Error::Descriptor)?;
    let mut writer = Writer::new(mem.clone(), avail_desc).map_err(Error::Descriptor)?;

    let status_code = reader
        .read_obj()
        .map(|request| execute_request(request, pmem_device_tube, mapping_arena_slot, mapping_size))
        .map_err(Error::ReadQueue)?;

    let response = virtio_pmem_resp {
        status_code: status_code.into(),
    };

    writer.write_obj(response).map_err(Error::WriteQueue)?;

    Ok(writer.bytes_written())
}

async fn handle_queue(
    mem: &GuestMemory,
    mut queue: Queue,
    mut queue_event: EventAsync,
    interrupt: Rc<RefCell<Interrupt>>,
    pmem_device_tube: Tube,
    mapping_arena_slot: u32,
    mapping_size: usize,
) {
    loop {
        let avail_desc = match queue.next_async(mem, &mut queue_event).await {
            Err(e) => {
                error!("Failed to read descriptor {}", e);
                return;
            }
            Ok(d) => d,
        };
        let index = avail_desc.index;
        let written = match handle_request(
            mem,
            avail_desc,
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
        queue.add_used(mem, index, written as u32);
        queue.trigger_interrupt(mem, &*interrupt.borrow());
    }
}

fn run_worker(
    queue_evt: Event,
    queue: Queue,
    pmem_device_tube: Tube,
    interrupt: Interrupt,
    kill_evt: Event,
    mem: GuestMemory,
    mapping_arena_slot: u32,
    mapping_size: usize,
) {
    // Wrap the interrupt in a `RefCell` so it can be shared between async functions.
    let interrupt = Rc::new(RefCell::new(interrupt));

    let ex = Executor::new().unwrap();

    let queue_evt = EventAsync::new(queue_evt.0, &ex).expect("failed to set up the queue event");

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
    kill_event: Option<Event>,
    worker_thread: Option<thread::JoinHandle<()>>,
    base_features: u64,
    disk_image: Option<File>,
    mapping_address: GuestAddress,
    mapping_arena_slot: MemSlot,
    mapping_size: u64,
    pmem_device_tube: Option<Tube>,
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
            kill_event: None,
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

impl Drop for Pmem {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.kill_event.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }

        if let Some(worker_thread) = self.worker_thread.take() {
            let _ = worker_thread.join();
        }
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

    fn device_type(&self) -> u32 {
        TYPE_PMEM
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
            size: Le64::from(self.mapping_size as u64),
        };
        copy_config(data, 0, config.as_slice(), offset);
    }

    fn activate(
        &mut self,
        memory: GuestMemory,
        interrupt: Interrupt,
        mut queues: Vec<Queue>,
        mut queue_events: Vec<Event>,
    ) {
        if queues.len() != 1 || queue_events.len() != 1 {
            return;
        }

        let queue = queues.remove(0);
        let queue_event = queue_events.remove(0);

        let mapping_arena_slot = self.mapping_arena_slot;
        // We checked that this fits in a usize in `Pmem::new`.
        let mapping_size = self.mapping_size as usize;

        if let Some(pmem_device_tube) = self.pmem_device_tube.take() {
            let (self_kill_event, kill_event) =
                match Event::new().and_then(|e| Ok((e.try_clone()?, e))) {
                    Ok(v) => v,
                    Err(e) => {
                        error!("failed creating kill Event pair: {}", e);
                        return;
                    }
                };
            self.kill_event = Some(self_kill_event);

            let worker_result = thread::Builder::new()
                .name("virtio_pmem".to_string())
                .spawn(move || {
                    run_worker(
                        queue_event,
                        queue,
                        pmem_device_tube,
                        interrupt,
                        kill_event,
                        memory,
                        mapping_arena_slot,
                        mapping_size,
                    )
                });

            match worker_result {
                Err(e) => {
                    error!("failed to spawn virtio_pmem worker: {}", e);
                    return;
                }
                Ok(join_handle) => {
                    self.worker_thread = Some(join_handle);
                }
            }
        }
    }
}
