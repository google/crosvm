// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fmt::{self, Display};
use std::fs::File;
use std::io;
use std::thread;

use base::{error, AsRawDescriptor, Event, PollToken, RawDescriptor, Tube, WaitContext};
use base::{Error as SysError, Result as SysResult};
use data_model::{DataInit, Le32, Le64};
use vm_control::{MemSlot, VmMsyncRequest, VmMsyncResponse};
use vm_memory::{GuestAddress, GuestMemory};

use super::{
    copy_config, DescriptorChain, DescriptorError, Interrupt, Queue, Reader, SignalableInterrupt,
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

#[derive(Debug)]
enum Error {
    /// Invalid virtio descriptor chain.
    Descriptor(DescriptorError),
    /// Failed to read from virtqueue.
    ReadQueue(io::Error),
    /// Failed to write to virtqueue.
    WriteQueue(io::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            Descriptor(e) => write!(f, "virtio descriptor error: {}", e),
            ReadQueue(e) => write!(f, "failed to read from virtqueue: {}", e),
            WriteQueue(e) => write!(f, "failed to write to virtqueue: {}", e),
        }
    }
}

impl ::std::error::Error for Error {}

type Result<T> = ::std::result::Result<T, Error>;

struct Worker {
    interrupt: Interrupt,
    queue: Queue,
    memory: GuestMemory,
    pmem_device_tube: Tube,
    mapping_arena_slot: MemSlot,
    mapping_size: usize,
}

impl Worker {
    fn execute_request(&self, request: virtio_pmem_req) -> u32 {
        match request.type_.to_native() {
            VIRTIO_PMEM_REQ_TYPE_FLUSH => {
                let request = VmMsyncRequest::MsyncArena {
                    slot: self.mapping_arena_slot,
                    offset: 0, // The pmem backing file is always at offset 0 in the arena.
                    size: self.mapping_size,
                };

                if let Err(e) = self.pmem_device_tube.send(&request) {
                    error!("failed to send request: {}", e);
                    return VIRTIO_PMEM_RESP_TYPE_EIO;
                }

                match self.pmem_device_tube.recv() {
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

    fn handle_request(&self, avail_desc: DescriptorChain) -> Result<usize> {
        let mut reader =
            Reader::new(self.memory.clone(), avail_desc.clone()).map_err(Error::Descriptor)?;
        let mut writer = Writer::new(self.memory.clone(), avail_desc).map_err(Error::Descriptor)?;

        let status_code = reader
            .read_obj()
            .map(|request| self.execute_request(request))
            .map_err(Error::ReadQueue)?;

        let response = virtio_pmem_resp {
            status_code: status_code.into(),
        };

        writer.write_obj(response).map_err(Error::WriteQueue)?;

        Ok(writer.bytes_written())
    }

    fn process_queue(&mut self) -> bool {
        let mut needs_interrupt = false;
        while let Some(avail_desc) = self.queue.pop(&self.memory) {
            let avail_desc_index = avail_desc.index;

            let bytes_written = match self.handle_request(avail_desc) {
                Ok(count) => count,
                Err(e) => {
                    error!("pmem: unable to handle request: {}", e);
                    0
                }
            };
            self.queue
                .add_used(&self.memory, avail_desc_index, bytes_written as u32);
            needs_interrupt = true;
        }

        needs_interrupt
    }

    fn run(&mut self, queue_evt: Event, kill_evt: Event) {
        #[derive(PollToken)]
        enum Token {
            QueueAvailable,
            InterruptResample,
            Kill,
        }

        let wait_ctx: WaitContext<Token> = match WaitContext::build_with(&[
            (&queue_evt, Token::QueueAvailable),
            (&kill_evt, Token::Kill),
        ]) {
            Ok(pc) => pc,
            Err(e) => {
                error!("failed creating WaitContext: {}", e);
                return;
            }
        };
        if let Some(resample_evt) = self.interrupt.get_resample_evt() {
            if wait_ctx
                .add(resample_evt, Token::InterruptResample)
                .is_err()
            {
                error!("failed adding resample event to WaitContext.");
                return;
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
            for event in events.iter().filter(|e| e.is_readable) {
                match event.token {
                    Token::QueueAvailable => {
                        if let Err(e) = queue_evt.read() {
                            error!("failed reading queue Event: {}", e);
                            break 'wait;
                        }
                        needs_interrupt |= self.process_queue();
                    }
                    Token::InterruptResample => {
                        self.interrupt.interrupt_resample();
                    }
                    Token::Kill => break 'wait,
                }
            }
            if needs_interrupt {
                self.queue.trigger_interrupt(&self.memory, &self.interrupt);
            }
        }
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
                    let mut worker = Worker {
                        interrupt,
                        memory,
                        queue,
                        pmem_device_tube,
                        mapping_arena_slot,
                        mapping_size,
                    };
                    worker.run(queue_event, kill_event);
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
