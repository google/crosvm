// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp;
use std::fmt::{self, Display};
use std::fs::File;
use std::io::Write;
use std::mem::{size_of, size_of_val};
use std::os::unix::io::{AsRawFd, RawFd};
use std::result;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

use sys_util::Result as SysResult;
use sys_util::{
    error, EventFd, GuestAddress, GuestMemory, GuestMemoryError, PollContext, PollToken,
};

use data_model::{DataInit, Le32, Le64};

use super::{
    DescriptorChain, Queue, VirtioDevice, INTERRUPT_STATUS_USED_RING, TYPE_PMEM, VIRTIO_F_VERSION_1,
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
enum ParseError {
    /// Guest gave us bad memory addresses.
    GuestMemory(GuestMemoryError),
    /// Guest gave us a write only descriptor that protocol says to read from.
    UnexpectedWriteOnlyDescriptor,
    /// Guest gave us a read only descriptor that protocol says to write to.
    UnexpectedReadOnlyDescriptor,
    /// Guest gave us too few descriptors in a descriptor chain.
    DescriptorChainTooShort,
    /// Guest gave us a buffer that was too short to use.
    BufferLengthTooSmall,
    /// Guest sent us invalid request.
    InvalidRequest,
}

impl Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::ParseError::*;

        match self {
            BufferLengthTooSmall => write!(f, "buffer length too small"),
            DescriptorChainTooShort => write!(f, "descriptor chain too short"),
            GuestMemory(e) => write!(f, "bad guest memory address: {}", e),
            InvalidRequest => write!(f, "invalid request"),
            UnexpectedReadOnlyDescriptor => write!(f, "unexpected read-only descriptor"),
            UnexpectedWriteOnlyDescriptor => write!(f, "unexpected write-only descriptor"),
        }
    }
}

enum Request {
    Flush { status_address: GuestAddress },
}

impl Request {
    fn parse(
        avail_desc: &DescriptorChain,
        memory: &GuestMemory,
    ) -> result::Result<Request, ParseError> {
        // The head contains the request type which MUST be readable.
        if avail_desc.is_write_only() {
            return Err(ParseError::UnexpectedWriteOnlyDescriptor);
        }

        if avail_desc.len as usize != size_of::<virtio_pmem_req>() {
            return Err(ParseError::InvalidRequest);
        }

        let request: virtio_pmem_req = memory
            .read_obj_from_addr(avail_desc.addr)
            .map_err(ParseError::GuestMemory)?;

        // Currently, there is only one virtio-pmem request, FLUSH.
        if request.type_ != VIRTIO_PMEM_REQ_TYPE_FLUSH {
            error!("unknown request type: {}", request.type_.to_native());
            return Err(ParseError::InvalidRequest);
        }

        let status_desc = avail_desc
            .next_descriptor()
            .ok_or(ParseError::DescriptorChainTooShort)?;

        // The status MUST always be writable
        if status_desc.is_read_only() {
            return Err(ParseError::UnexpectedReadOnlyDescriptor);
        }

        if (status_desc.len as usize) < size_of::<virtio_pmem_resp>() {
            return Err(ParseError::BufferLengthTooSmall);
        }

        Ok(Request::Flush {
            status_address: status_desc.addr,
        })
    }
}

struct Worker {
    queue: Queue,
    memory: GuestMemory,
    disk_image: File,
    interrupt_status: Arc<AtomicUsize>,
    interrupt_event: EventFd,
    interrupt_resample_event: EventFd,
}

impl Worker {
    fn process_queue(&mut self) -> bool {
        let mut needs_interrupt = false;
        while let Some(avail_desc) = self.queue.pop(&self.memory) {
            let len;
            match Request::parse(&avail_desc, &self.memory) {
                Ok(Request::Flush { status_address }) => {
                    let status_code = match self.disk_image.sync_all() {
                        Ok(()) => VIRTIO_PMEM_RESP_TYPE_OK,
                        Err(e) => {
                            error!("failed flushing disk image: {}", e);
                            VIRTIO_PMEM_RESP_TYPE_EIO
                        }
                    };

                    let response = virtio_pmem_resp {
                        status_code: status_code.into(),
                    };
                    len = match self.memory.write_obj_at_addr(response, status_address) {
                        Ok(_) => size_of::<virtio_pmem_resp>() as u32,
                        Err(e) => {
                            error!("bad guest memory address: {}", e);
                            0
                        }
                    }
                }
                Err(e) => {
                    error!("failed processing available descriptor chain: {}", e);
                    len = 0;
                }
            }
            self.queue.add_used(&self.memory, avail_desc.index, len);
            needs_interrupt = true;
        }

        needs_interrupt
    }

    fn signal_used_queue(&self) {
        self.interrupt_status
            .fetch_or(INTERRUPT_STATUS_USED_RING as usize, Ordering::SeqCst);
        self.interrupt_event.write(1).unwrap();
    }

    fn run(&mut self, queue_evt: EventFd, kill_evt: EventFd) {
        #[derive(PollToken)]
        enum Token {
            QueueAvailable,
            InterruptResample,
            Kill,
        }

        let poll_ctx: PollContext<Token> = match PollContext::new()
            .and_then(|pc| pc.add(&queue_evt, Token::QueueAvailable).and(Ok(pc)))
            .and_then(|pc| {
                pc.add(&self.interrupt_resample_event, Token::InterruptResample)
                    .and(Ok(pc))
            })
            .and_then(|pc| pc.add(&kill_evt, Token::Kill).and(Ok(pc)))
        {
            Ok(pc) => pc,
            Err(e) => {
                error!("failed creating PollContext: {}", e);
                return;
            }
        };

        'poll: loop {
            let events = match poll_ctx.wait() {
                Ok(v) => v,
                Err(e) => {
                    error!("failed polling for events: {}", e);
                    break;
                }
            };

            let mut needs_interrupt = false;
            for event in events.iter_readable() {
                match event.token() {
                    Token::QueueAvailable => {
                        if let Err(e) = queue_evt.read() {
                            error!("failed reading queue EventFd: {}", e);
                            break 'poll;
                        }
                        needs_interrupt |= self.process_queue();
                    }
                    Token::InterruptResample => {
                        let _ = self.interrupt_resample_event.read();
                        if self.interrupt_status.load(Ordering::SeqCst) != 0 {
                            self.interrupt_event.write(1).unwrap();
                        }
                    }
                    Token::Kill => break 'poll,
                }
            }
            if needs_interrupt {
                self.signal_used_queue();
            }
        }
    }
}

pub struct Pmem {
    kill_event: Option<EventFd>,
    disk_image: Option<File>,
    mapping_address: GuestAddress,
    mapping_size: u64,
}

impl Pmem {
    pub fn new(
        disk_image: File,
        mapping_address: GuestAddress,
        mapping_size: u64,
    ) -> SysResult<Pmem> {
        Ok(Pmem {
            kill_event: None,
            disk_image: Some(disk_image),
            mapping_address,
            mapping_size,
        })
    }
}

impl Drop for Pmem {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.kill_event.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }
    }
}

impl VirtioDevice for Pmem {
    fn keep_fds(&self) -> Vec<RawFd> {
        if let Some(disk_image) = &self.disk_image {
            vec![disk_image.as_raw_fd()]
        } else {
            vec![]
        }
    }

    fn device_type(&self) -> u32 {
        TYPE_PMEM
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn features(&self) -> u64 {
        1 << VIRTIO_F_VERSION_1
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config = virtio_pmem_config {
            start_address: Le64::from(self.mapping_address.offset()),
            size: Le64::from(self.mapping_size as u64),
        };
        let config_len = size_of_val(&config) as u64;
        if offset >= config_len {
            return;
        }

        if let Some(end) = offset.checked_add(data.len() as u64) {
            let offset = offset as usize;
            let end = cmp::min(end, config_len) as usize;
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(&config.as_slice()[offset..end]).unwrap();
        }
    }

    fn activate(
        &mut self,
        memory: GuestMemory,
        interrupt_event: EventFd,
        interrupt_resample_event: EventFd,
        status: Arc<AtomicUsize>,
        mut queues: Vec<Queue>,
        mut queue_events: Vec<EventFd>,
    ) {
        if queues.len() != 1 || queue_events.len() != 1 {
            return;
        }

        let queue = queues.remove(0);
        let queue_event = queue_events.remove(0);

        if let Some(disk_image) = self.disk_image.take() {
            let (self_kill_event, kill_event) =
                match EventFd::new().and_then(|e| Ok((e.try_clone()?, e))) {
                    Ok(v) => v,
                    Err(e) => {
                        error!("failed creating kill EventFd pair: {}", e);
                        return;
                    }
                };
            self.kill_event = Some(self_kill_event);

            let worker_result = thread::Builder::new()
                .name("virtio_pmem".to_string())
                .spawn(move || {
                    let mut worker = Worker {
                        memory,
                        disk_image,
                        queue,
                        interrupt_status: status,
                        interrupt_event,
                        interrupt_resample_event,
                    };
                    worker.run(queue_event, kill_event);
                });
            if let Err(e) = worker_result {
                error!("failed to spawn virtio_pmem worker: {}", e);
                return;
            }
        }
    }
}
