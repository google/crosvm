// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::io::{Seek, SeekFrom, Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::result;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::spawn;

use byteorder::{ByteOrder, LittleEndian};

use sys_util::Result as SysResult;
use sys_util::{EventFd, GuestAddress, GuestMemory, GuestMemoryError, Poller};

use super::{VirtioDevice, Queue, DescriptorChain, INTERRUPT_STATUS_USED_RING, TYPE_BLOCK};

const QUEUE_SIZE: u16 = 256;
const QUEUE_SIZES: &'static [u16] = &[QUEUE_SIZE];
const SECTOR_SHIFT: u8 = 9;

const VIRTIO_BLK_T_IN: u32 = 0;
const VIRTIO_BLK_T_OUT: u32 = 1;
const VIRTIO_BLK_T_FLUSH: u32 = 4;

const VIRTIO_BLK_S_OK: u8 = 0;
const VIRTIO_BLK_S_IOERR: u8 = 1;
const VIRTIO_BLK_S_UNSUPP: u8 = 2;

#[derive(PartialEq)]
enum RequestType {
    In,
    Out,
    Flush,
    Unsupported(u32),
}

#[derive(Debug)]
enum ParseError {
    /// Guest gave us bad memory addresses
    GuestMemory(GuestMemoryError),
    /// Guest gave us offsets that would have overflowed a usize.
    CheckedOffset(GuestAddress, usize),
    /// Guest gave us a write only descriptor that protocol says to read from.
    UnexpectedWriteOnlyDescriptor,
    /// Guest gave us a read only descriptor that protocol says to write to.
    UnexpectedReadOnlyDescriptor,
    /// Guest gave us too few descriptors in a descriptor chain.
    DescriptorChainTooShort,
    /// Guest gave us a descriptor that was too short to use.
    DescriptorLengthTooSmall,
}

fn request_type(mem: &GuestMemory,
                desc_addr: GuestAddress)
                -> result::Result<RequestType, ParseError> {
    let type_ = mem.read_obj_from_addr(desc_addr)
        .map_err(ParseError::GuestMemory)?;
    match type_ {
        VIRTIO_BLK_T_IN => Ok(RequestType::In),
        VIRTIO_BLK_T_OUT => Ok(RequestType::Out),
        VIRTIO_BLK_T_FLUSH => Ok(RequestType::Flush),
        t => Ok(RequestType::Unsupported(t)),
    }
}

fn sector(mem: &GuestMemory, desc_addr: GuestAddress) -> result::Result<u64, ParseError> {
    const SECTOR_OFFSET: usize = 8;
    let addr = match mem.checked_offset(desc_addr, SECTOR_OFFSET) {
        Some(v) => v,
        None => return Err(ParseError::CheckedOffset(desc_addr, SECTOR_OFFSET)),
    };

    mem.read_obj_from_addr(addr)
        .map_err(ParseError::GuestMemory)
}

#[derive(Debug)]
enum ExecuteError {
    Io,
    Unsupported(u32),
}

impl ExecuteError {
    fn status(&self) -> u8 {
        match self {
            &ExecuteError::Io => VIRTIO_BLK_S_IOERR,
            &ExecuteError::Unsupported(_) => VIRTIO_BLK_S_UNSUPP,
        }
    }
}

struct Request {
    request_type: RequestType,
    sector: u64,
    data_addr: GuestAddress,
    data_len: u32,
    status_addr: GuestAddress,
}

impl Request {
    fn parse(avail_desc: &DescriptorChain,
             mem: &GuestMemory)
             -> result::Result<Request, ParseError> {
        // The head contains the request type which MUST be readable.
        if avail_desc.is_write_only() {
            return Err(ParseError::UnexpectedWriteOnlyDescriptor);
        }

        let req_type = request_type(&mem, avail_desc.addr)?;
        let sector = sector(&mem, avail_desc.addr)?;
        let data_desc = avail_desc
            .next_descriptor()
            .ok_or(ParseError::DescriptorChainTooShort)?;
        let status_desc = data_desc
            .next_descriptor()
            .ok_or(ParseError::DescriptorChainTooShort)?;

        if data_desc.is_write_only() && req_type == RequestType::Out {
            return Err(ParseError::UnexpectedWriteOnlyDescriptor);
        }

        if !data_desc.is_write_only() && req_type == RequestType::In {
            return Err(ParseError::UnexpectedReadOnlyDescriptor);
        }

        // The status MUST always be writable
        if !status_desc.is_write_only() {
            return Err(ParseError::UnexpectedReadOnlyDescriptor);
        }

        if status_desc.len < 1 {
            return Err(ParseError::DescriptorLengthTooSmall);
        }

        Ok(Request {
               request_type: req_type,
               sector: sector,
               data_addr: data_desc.addr,
               data_len: data_desc.len,
               status_addr: status_desc.addr,
           })
    }

    fn execute<T: Seek + Read + Write>(&self,
                                       disk: &mut T,
                                       mem: &GuestMemory)
                                       -> result::Result<u32, ExecuteError> {
        // TODO(zachr): When VolatileMemory merges, make ExecuteError::Io more descriptive.
        disk.seek(SeekFrom::Start(self.sector << SECTOR_SHIFT))
            .map_err(|_| ExecuteError::Io)?;
        match self.request_type {
            RequestType::In => {
                mem.read_to_memory(self.data_addr, disk, self.data_len as usize)
                    .map_err(|_| ExecuteError::Io)?;
                return Ok(self.data_len);
            }
            RequestType::Out => {
                mem.write_from_memory(self.data_addr, disk, self.data_len as usize)
                    .map_err(|_| ExecuteError::Io)?
            }
            RequestType::Flush => disk.flush().map_err(|_| ExecuteError::Io)?,
            RequestType::Unsupported(t) => return Err(ExecuteError::Unsupported(t)),
        };
        Ok(0)
    }
}

struct Worker {
    queues: Vec<Queue>,
    mem: GuestMemory,
    disk_image: File,
    interrupt_status: Arc<AtomicUsize>,
    interrupt_evt: EventFd,
}

impl Worker {
    fn process_queue(&mut self, queue_index: usize) -> bool {
        let queue = &mut self.queues[queue_index];

        let mut used_desc_heads = [(0, 0); QUEUE_SIZE as usize];
        let mut used_count = 0;
        for avail_desc in queue.iter(&self.mem) {
            let len;
            match Request::parse(&avail_desc, &self.mem) {
                Ok(request) => {
                    let status = match request.execute(&mut self.disk_image, &self.mem) {
                        Ok(l) => {
                            len = l;
                            VIRTIO_BLK_S_OK
                        }
                        Err(e) => {
                            println!("block: error executing disk request: {:?}", e);
                            len = 1; // 1 byte for the status
                            e.status()
                        }
                    };
                    // We use unwrap because the request parsing process already checked that the
                    // status_addr was valid.
                    self.mem
                        .write_obj_at_addr(status, request.status_addr)
                        .unwrap();
                }
                Err(e) => {
                    println!("block: error processing available descriptor chain: {:?}",
                             e);
                    len = 0;
                }
            }
            used_desc_heads[used_count] = (avail_desc.index, len);
            used_count += 1;
        }

        for &(desc_index, len) in &used_desc_heads[..used_count] {
            queue.add_used(&self.mem, desc_index, len);
        }
        used_count > 0
    }

    fn signal_used_queue(&self) {
        self.interrupt_status
            .fetch_or(INTERRUPT_STATUS_USED_RING as usize, Ordering::SeqCst);
        self.interrupt_evt.write(1).unwrap();
    }

    fn run(&mut self, queue_evt: EventFd, kill_evt: EventFd) {
        const Q_AVAIL: u32 = 0;
        const KILL: u32 = 1;

        let mut poller = Poller::new(2);
        'poll: loop {
            let tokens = match poller.poll(&[(Q_AVAIL, &queue_evt), (KILL, &kill_evt)]) {
                Ok(v) => v,
                Err(e) => {
                    println!("block: error polling for events: {:?}", e);
                    break;
                }
            };

            let mut needs_interrupt = false;
            for &token in tokens {
                match token {
                    Q_AVAIL => {
                        if let Err(e) = queue_evt.read() {
                            println!("block: error reading queue EventFd: {:?}", e);
                            break 'poll;
                        }
                        needs_interrupt |= self.process_queue(0);
                    }
                    KILL => break 'poll,
                    _ => unreachable!(),
                }
            }
            if needs_interrupt {
                self.signal_used_queue();
            }
        }
    }
}

/// Virtio device for exposing block level read/write operations on a host file.
pub struct Block {
    kill_evt: Option<EventFd>,
    disk_size: u64,
    disk_image: Option<File>,
}

impl Block {
    /// Create a new virtio block device that operates on the given file.
    ///
    /// The given file must be seekable and sizable.
    pub fn new(mut disk_image: File) -> SysResult<Block> {
        let disk_size = disk_image.seek(SeekFrom::End(0))? as u64;
        Ok(Block {
               kill_evt: None,
               disk_size: disk_size,
               disk_image: Some(disk_image),
           })
    }
}

impl Drop for Block {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }
    }
}

impl VirtioDevice for Block {
    fn keep_fds(&self) -> Vec<RawFd> {
        let mut keep_fds = Vec::new();

        if let Some(ref disk_image) = self.disk_image {
            keep_fds.push(disk_image.as_raw_fd());
        }

        keep_fds
    }

    fn device_type(&self) -> u32 {
        TYPE_BLOCK
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        // We only support the first word of configuration space.
        let v = match offset {
            0 => ((self.disk_size + 0x511) >> SECTOR_SHIFT) as u32,
            _ => return,
        };

        LittleEndian::write_u32(data, v);
    }

    fn activate(&mut self,
                mem: GuestMemory,
                interrupt_evt: EventFd,
                status: Arc<AtomicUsize>,
                queues: Vec<Queue>,
                mut queue_evts: Vec<EventFd>) {
        if queues.len() != 1 || queue_evts.len() != 1 {
            return;
        }

        let (self_kill_evt, kill_evt) =
            match EventFd::new().and_then(|e| Ok((e.try_clone()?, e))) {
                Ok(v) => v,
                Err(e) => {
                    println!("block: error creating kill EventFd pair: {:?}", e);
                    return;
                }
            };
        self.kill_evt = Some(self_kill_evt);

        if let Some(disk_image) = self.disk_image.take() {
            spawn(move || {
                let mut worker = Worker {
                    queues: queues,
                    mem: mem,
                    disk_image: disk_image,
                    interrupt_status: status,
                    interrupt_evt: interrupt_evt,
                };
                worker.run(queue_evts.remove(0), kill_evt);
            });
        }
    }
}
