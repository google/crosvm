// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp;
use std::fmt::{self, Display};
use std::io::{self, Seek, SeekFrom, Write};
use std::mem::{size_of, size_of_val};
use std::os::unix::io::{AsRawFd, RawFd};
use std::result;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use std::u32;

use sync::Mutex;
use sys_util::Error as SysError;
use sys_util::Result as SysResult;
use sys_util::{
    error, info, warn, EventFd, FileReadWriteVolatile, FileSetLen, FileSync, GuestAddress,
    GuestMemory, GuestMemoryError, PollContext, PollToken, PunchHole, TimerFd, WriteZeroes,
};

use data_model::{DataInit, Le16, Le32, Le64, VolatileMemory, VolatileMemoryError};
use msg_socket::{MsgReceiver, MsgSender};
use vm_control::{DiskControlCommand, DiskControlResponseSocket, DiskControlResult};

use super::{
    DescriptorChain, Queue, VirtioDevice, INTERRUPT_STATUS_CONFIG_CHANGED,
    INTERRUPT_STATUS_USED_RING, TYPE_BLOCK, VIRTIO_F_VERSION_1,
};

const QUEUE_SIZE: u16 = 256;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE];
const SECTOR_SHIFT: u8 = 9;
const SECTOR_SIZE: u64 = 0x01 << SECTOR_SHIFT;
const MAX_DISCARD_SECTORS: u32 = u32::MAX;
const MAX_WRITE_ZEROES_SECTORS: u32 = u32::MAX;
// Hard-coded to 64 KiB (in 512-byte sectors) for now,
// but this should probably be based on cluster size for qcow.
const DISCARD_SECTOR_ALIGNMENT: u32 = 128;

const VIRTIO_BLK_T_IN: u32 = 0;
const VIRTIO_BLK_T_OUT: u32 = 1;
const VIRTIO_BLK_T_FLUSH: u32 = 4;
const VIRTIO_BLK_T_DISCARD: u32 = 11;
const VIRTIO_BLK_T_WRITE_ZEROES: u32 = 13;

const VIRTIO_BLK_S_OK: u8 = 0;
const VIRTIO_BLK_S_IOERR: u8 = 1;
const VIRTIO_BLK_S_UNSUPP: u8 = 2;

const VIRTIO_BLK_F_RO: u32 = 5;
const VIRTIO_BLK_F_BLK_SIZE: u32 = 6;
const VIRTIO_BLK_F_FLUSH: u32 = 9;
const VIRTIO_BLK_F_DISCARD: u32 = 13;
const VIRTIO_BLK_F_WRITE_ZEROES: u32 = 14;

#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
struct virtio_blk_geometry {
    cylinders: Le16,
    heads: u8,
    sectors: u8,
}

// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for virtio_blk_geometry {}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
struct virtio_blk_topology {
    physical_block_exp: u8,
    alignment_offset: u8,
    min_io_size: Le16,
    opt_io_size: Le32,
}

// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for virtio_blk_topology {}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
struct virtio_blk_config {
    capacity: Le64,
    size_max: Le32,
    seg_max: Le32,
    geometry: virtio_blk_geometry,
    blk_size: Le32,
    topology: virtio_blk_topology,
    writeback: u8,
    unused0: [u8; 3],
    max_discard_sectors: Le32,
    max_discard_seg: Le32,
    discard_sector_alignment: Le32,
    max_write_zeroes_sectors: Le32,
    max_write_zeroes_seg: Le32,
    write_zeroes_may_unmap: u8,
    unused1: [u8; 3],
}

// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for virtio_blk_config {}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
struct virtio_blk_discard_write_zeroes {
    sector: Le64,
    num_sectors: Le32,
    flags: Le32,
}

const VIRTIO_BLK_DISCARD_WRITE_ZEROES_FLAG_UNMAP: u32 = 1 << 0;

// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for virtio_blk_discard_write_zeroes {}

pub trait DiskFile:
    FileSetLen + FileSync + FileReadWriteVolatile + PunchHole + Seek + WriteZeroes
{
}
impl<D: FileSetLen + FileSync + PunchHole + FileReadWriteVolatile + Seek + WriteZeroes> DiskFile
    for D
{
}

#[derive(Copy, Clone, Debug, PartialEq)]
enum RequestType {
    In,
    Out,
    Flush,
    Discard,
    WriteZeroes,
    Unsupported(u32),
}

impl Display for RequestType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::RequestType::*;

        match self {
            In => write!(f, "in"),
            Out => write!(f, "out"),
            Flush => write!(f, "flush"),
            Discard => write!(f, "discard"),
            WriteZeroes => write!(f, "write zeroes"),
            Unsupported(n) => write!(f, "unsupported({})", n),
        }
    }
}

#[derive(Debug)]
enum ParseError {
    /// Guest gave us bad memory addresses
    GuestMemory(GuestMemoryError),
    /// Guest gave us offsets that would have overflowed a usize.
    CheckedOffset(GuestAddress, u64),
    /// Guest gave us a write only descriptor that protocol says to read from.
    UnexpectedWriteOnlyDescriptor,
    /// Guest gave us a read only descriptor that protocol says to write to.
    UnexpectedReadOnlyDescriptor,
    /// Guest gave us too few descriptors in a descriptor chain.
    DescriptorChainTooShort,
    /// Guest gave us a descriptor that was too short to use.
    DescriptorLengthTooSmall,
}

impl Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::ParseError::*;

        match self {
            GuestMemory(e) => write!(f, "bad guest memory address: {}", e),
            CheckedOffset(addr, offset) => write!(f, "{}+{} would overflow a usize", addr, offset),
            UnexpectedWriteOnlyDescriptor => write!(f, "unexpected write-only descriptor"),
            UnexpectedReadOnlyDescriptor => write!(f, "unexpected read-only descriptor"),
            DescriptorChainTooShort => write!(f, "descriptor chain too short"),
            DescriptorLengthTooSmall => write!(f, "descriptor length too small"),
        }
    }
}

fn request_type(
    mem: &GuestMemory,
    desc_addr: GuestAddress,
) -> result::Result<RequestType, ParseError> {
    let type_ = mem
        .read_obj_from_addr(desc_addr)
        .map_err(ParseError::GuestMemory)?;
    match type_ {
        VIRTIO_BLK_T_IN => Ok(RequestType::In),
        VIRTIO_BLK_T_OUT => Ok(RequestType::Out),
        VIRTIO_BLK_T_FLUSH => Ok(RequestType::Flush),
        VIRTIO_BLK_T_DISCARD => Ok(RequestType::Discard),
        VIRTIO_BLK_T_WRITE_ZEROES => Ok(RequestType::WriteZeroes),
        t => Ok(RequestType::Unsupported(t)),
    }
}

fn sector(mem: &GuestMemory, desc_addr: GuestAddress) -> result::Result<u64, ParseError> {
    const SECTOR_OFFSET: u64 = 8;
    let addr = match mem.checked_offset(desc_addr, SECTOR_OFFSET) {
        Some(v) => v,
        None => return Err(ParseError::CheckedOffset(desc_addr, SECTOR_OFFSET)),
    };

    mem.read_obj_from_addr(addr)
        .map_err(ParseError::GuestMemory)
}

fn discard_write_zeroes_segment(
    mem: &GuestMemory,
    seg_addr: GuestAddress,
) -> result::Result<virtio_blk_discard_write_zeroes, ParseError> {
    mem.read_obj_from_addr(seg_addr)
        .map_err(ParseError::GuestMemory)
}

#[derive(Debug)]
enum ExecuteError {
    /// Error arming the flush timer.
    Flush(io::Error),
    ReadVolatile {
        addr: GuestAddress,
        length: u32,
        sector: u64,
        volatile_memory_error: VolatileMemoryError,
    },
    ReadIo {
        addr: GuestAddress,
        length: u32,
        sector: u64,
        io_error: io::Error,
    },
    Seek {
        ioerr: io::Error,
        sector: u64,
    },
    TimerFd(SysError),
    WriteVolatile {
        addr: GuestAddress,
        length: u32,
        sector: u64,
        volatile_memory_error: VolatileMemoryError,
    },
    WriteIo {
        addr: GuestAddress,
        length: u32,
        sector: u64,
        io_error: io::Error,
    },
    DiscardWriteZeroes {
        ioerr: Option<io::Error>,
        sector: u64,
        num_sectors: u32,
        flags: u32,
    },
    ReadOnly {
        request_type: RequestType,
    },
    OutOfRange,
    Unsupported(u32),
}

impl Display for ExecuteError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::ExecuteError::*;

        match self {
            Flush(e) => write!(f, "failed to flush: {}", e),
            ReadVolatile {
                addr,
                length,
                sector,
                volatile_memory_error,
            } => write!(
                f,
                "memory error reading {} bytes from sector {} to address {}: {}",
                length, sector, addr, volatile_memory_error,
            ),
            ReadIo {
                addr,
                length,
                sector,
                io_error,
            } => write!(
                f,
                "io error reading {} bytes from sector {} to address {}: {}",
                length, sector, addr, io_error,
            ),
            Seek { ioerr, sector } => write!(f, "failed to seek to sector {}: {}", sector, ioerr),
            TimerFd(e) => write!(f, "{}", e),
            WriteVolatile {
                addr,
                length,
                sector,
                volatile_memory_error,
            } => write!(
                f,
                "memory error writing {} bytes from address {} to sector {}: {}",
                length, addr, sector, volatile_memory_error,
            ),
            WriteIo {
                addr,
                length,
                sector,
                io_error,
            } => write!(
                f,
                "io error writing {} bytes from address {} to sector {}: {}",
                length, addr, sector, io_error,
            ),
            DiscardWriteZeroes {
                ioerr: Some(ioerr),
                sector,
                num_sectors,
                flags,
            } => write!(
                f,
                "failed to perform discard or write zeroes; sector={} num_sectors={} flags={}; {}",
                sector, num_sectors, flags, ioerr,
            ),
            DiscardWriteZeroes {
                ioerr: None,
                sector,
                num_sectors,
                flags,
            } => write!(
                f,
                "failed to perform discard or write zeroes; sector={} num_sectors={} flags={}",
                sector, num_sectors, flags,
            ),
            ReadOnly { request_type } => write!(f, "read only; request_type={}", request_type),
            OutOfRange => write!(f, "out of range"),
            Unsupported(n) => write!(f, "unsupported ({})", n),
        }
    }
}

impl ExecuteError {
    fn status(&self) -> u8 {
        match self {
            ExecuteError::Flush(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::ReadIo { .. } => VIRTIO_BLK_S_IOERR,
            ExecuteError::ReadVolatile { .. } => VIRTIO_BLK_S_IOERR,
            ExecuteError::Seek { .. } => VIRTIO_BLK_S_IOERR,
            ExecuteError::TimerFd(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::WriteIo { .. } => VIRTIO_BLK_S_IOERR,
            ExecuteError::WriteVolatile { .. } => VIRTIO_BLK_S_IOERR,
            ExecuteError::DiscardWriteZeroes { .. } => VIRTIO_BLK_S_IOERR,
            ExecuteError::ReadOnly { .. } => VIRTIO_BLK_S_IOERR,
            ExecuteError::OutOfRange { .. } => VIRTIO_BLK_S_IOERR,
            ExecuteError::Unsupported(_) => VIRTIO_BLK_S_UNSUPP,
        }
    }
}

struct Request {
    request_type: RequestType,
    sector: u64,
    data_addr: GuestAddress,
    data_len: u32,
    status_addr: GuestAddress,
    discard_write_zeroes_seg: Option<virtio_blk_discard_write_zeroes>,
}

impl Request {
    fn parse(
        avail_desc: &DescriptorChain,
        mem: &GuestMemory,
    ) -> result::Result<Request, ParseError> {
        // The head contains the request type which MUST be readable.
        if avail_desc.is_write_only() {
            return Err(ParseError::UnexpectedWriteOnlyDescriptor);
        }

        let req_type = request_type(&mem, avail_desc.addr)?;
        if req_type == RequestType::Flush {
            Request::parse_flush(avail_desc, mem)
        } else if req_type == RequestType::Discard || req_type == RequestType::WriteZeroes {
            Request::parse_discard_write_zeroes(avail_desc, mem, req_type)
        } else {
            Request::parse_read_write(avail_desc, mem, req_type)
        }
    }

    fn parse_flush(
        avail_desc: &DescriptorChain,
        mem: &GuestMemory,
    ) -> result::Result<Request, ParseError> {
        let sector = sector(&mem, avail_desc.addr)?;
        let status_desc = avail_desc
            .next_descriptor()
            .ok_or(ParseError::DescriptorChainTooShort)?;

        // The status MUST always be writable
        if !status_desc.is_write_only() {
            return Err(ParseError::UnexpectedReadOnlyDescriptor);
        }

        if status_desc.len < 1 {
            return Err(ParseError::DescriptorLengthTooSmall);
        }

        Ok(Request {
            request_type: RequestType::Flush,
            sector,
            data_addr: GuestAddress(0),
            data_len: 0,
            status_addr: status_desc.addr,
            discard_write_zeroes_seg: None,
        })
    }

    fn parse_discard_write_zeroes(
        avail_desc: &DescriptorChain,
        mem: &GuestMemory,
        req_type: RequestType,
    ) -> result::Result<Request, ParseError> {
        let seg_desc = avail_desc
            .next_descriptor()
            .ok_or(ParseError::DescriptorChainTooShort)?;
        let status_desc = seg_desc
            .next_descriptor()
            .ok_or(ParseError::DescriptorChainTooShort)?;

        if seg_desc.is_write_only() {
            return Err(ParseError::UnexpectedWriteOnlyDescriptor);
        }

        // For simplicity, we currently only support a single segment
        // for discard and write zeroes commands.  This allows the
        // request to be represented as a single Request object.
        if seg_desc.len < size_of::<virtio_blk_discard_write_zeroes>() as u32 {
            return Err(ParseError::DescriptorLengthTooSmall);
        }

        let seg = discard_write_zeroes_segment(&mem, seg_desc.addr)?;

        // The status MUST always be writable
        if !status_desc.is_write_only() {
            return Err(ParseError::UnexpectedReadOnlyDescriptor);
        }

        if status_desc.len < 1 {
            return Err(ParseError::DescriptorLengthTooSmall);
        }

        Ok(Request {
            request_type: req_type,
            sector: 0,
            data_addr: GuestAddress(0),
            data_len: 0,
            status_addr: status_desc.addr,
            discard_write_zeroes_seg: Some(seg),
        })
    }

    fn parse_read_write(
        avail_desc: &DescriptorChain,
        mem: &GuestMemory,
        req_type: RequestType,
    ) -> result::Result<Request, ParseError> {
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
            sector,
            data_addr: data_desc.addr,
            data_len: data_desc.len,
            status_addr: status_desc.addr,
            discard_write_zeroes_seg: None,
        })
    }

    fn execute<T: DiskFile>(
        &self,
        read_only: bool,
        disk: &mut T,
        disk_size: u64,
        flush_timer: &mut TimerFd,
        flush_timer_armed: &mut bool,
        mem: &GuestMemory,
    ) -> result::Result<u32, ExecuteError> {
        // Delay after a write when the file is auto-flushed.
        let flush_delay = Duration::from_secs(60);

        if read_only && self.request_type != RequestType::In {
            return Err(ExecuteError::ReadOnly {
                request_type: self.request_type,
            });
        }

        /// Check that a request accesses only data within the disk's current size.
        /// All parameters are in units of bytes.
        fn check_range(
            io_start: u64,
            io_length: u64,
            disk_size: u64,
        ) -> result::Result<(), ExecuteError> {
            let io_end = io_start
                .checked_add(io_length)
                .ok_or(ExecuteError::OutOfRange)?;
            if io_end > disk_size {
                Err(ExecuteError::OutOfRange)
            } else {
                Ok(())
            }
        }

        match self.request_type {
            RequestType::In => {
                let offset = self
                    .sector
                    .checked_shl(u32::from(SECTOR_SHIFT))
                    .ok_or(ExecuteError::OutOfRange)?;
                check_range(offset, u64::from(self.data_len), disk_size)?;
                disk.seek(SeekFrom::Start(offset))
                    .map_err(|e| ExecuteError::Seek {
                        ioerr: e,
                        sector: self.sector,
                    })?;
                let mem_slice = mem
                    .get_slice(self.data_addr.0, self.data_len as u64)
                    .map_err(|volatile_memory_error| ExecuteError::ReadVolatile {
                        addr: self.data_addr,
                        length: self.data_len,
                        sector: self.sector,
                        volatile_memory_error,
                    })?;
                disk.read_exact_volatile(mem_slice)
                    .map_err(|io_error| ExecuteError::ReadIo {
                        addr: self.data_addr,
                        length: self.data_len,
                        sector: self.sector,
                        io_error,
                    })?;
                return Ok(self.data_len);
            }
            RequestType::Out => {
                let offset = self
                    .sector
                    .checked_shl(u32::from(SECTOR_SHIFT))
                    .ok_or(ExecuteError::OutOfRange)?;
                check_range(offset, u64::from(self.data_len), disk_size)?;
                disk.seek(SeekFrom::Start(offset))
                    .map_err(|e| ExecuteError::Seek {
                        ioerr: e,
                        sector: self.sector,
                    })?;
                let mem_slice = mem
                    .get_slice(self.data_addr.0, self.data_len as u64)
                    .map_err(|volatile_memory_error| ExecuteError::WriteVolatile {
                        addr: self.data_addr,
                        length: self.data_len,
                        sector: self.sector,
                        volatile_memory_error,
                    })?;
                disk.write_all_volatile(mem_slice)
                    .map_err(|io_error| ExecuteError::WriteIo {
                        addr: self.data_addr,
                        length: self.data_len,
                        sector: self.sector,
                        io_error,
                    })?;
                if !*flush_timer_armed {
                    flush_timer
                        .reset(flush_delay, None)
                        .map_err(ExecuteError::TimerFd)?;
                    *flush_timer_armed = true;
                }
            }
            RequestType::Discard | RequestType::WriteZeroes => {
                if let Some(seg) = self.discard_write_zeroes_seg {
                    let sector = seg.sector.to_native();
                    let num_sectors = seg.num_sectors.to_native();
                    let flags = seg.flags.to_native();

                    let valid_flags = if self.request_type == RequestType::WriteZeroes {
                        VIRTIO_BLK_DISCARD_WRITE_ZEROES_FLAG_UNMAP
                    } else {
                        0
                    };

                    if (flags & !valid_flags) != 0 {
                        return Err(ExecuteError::DiscardWriteZeroes {
                            ioerr: None,
                            sector,
                            num_sectors,
                            flags,
                        });
                    }

                    let offset = sector
                        .checked_shl(u32::from(SECTOR_SHIFT))
                        .ok_or(ExecuteError::OutOfRange)?;
                    let length = u64::from(num_sectors)
                        .checked_shl(u32::from(SECTOR_SHIFT))
                        .ok_or(ExecuteError::OutOfRange)?;
                    check_range(offset, length, disk_size)?;

                    if self.request_type == RequestType::Discard {
                        // Since Discard is just a hint and some filesystems may not implement
                        // FALLOC_FL_PUNCH_HOLE, ignore punch_hole errors.
                        let _ = disk.punch_hole(offset, length);
                    } else {
                        disk.seek(SeekFrom::Start(offset))
                            .map_err(|e| ExecuteError::Seek { ioerr: e, sector })?;
                        disk.write_zeroes(length as usize).map_err(|e| {
                            ExecuteError::DiscardWriteZeroes {
                                ioerr: Some(e),
                                sector,
                                num_sectors,
                                flags,
                            }
                        })?;
                    }
                }
            }
            RequestType::Flush => {
                disk.fsync().map_err(ExecuteError::Flush)?;
                flush_timer.clear().map_err(ExecuteError::TimerFd)?;
                *flush_timer_armed = false;
            }
            RequestType::Unsupported(t) => return Err(ExecuteError::Unsupported(t)),
        };
        Ok(0)
    }
}

struct Worker<T: DiskFile> {
    queues: Vec<Queue>,
    mem: GuestMemory,
    disk_image: T,
    disk_size: Arc<Mutex<u64>>,
    read_only: bool,
    interrupt_status: Arc<AtomicUsize>,
    interrupt_evt: EventFd,
    interrupt_resample_evt: EventFd,
}

impl<T: DiskFile> Worker<T> {
    fn process_queue(
        &mut self,
        queue_index: usize,
        flush_timer: &mut TimerFd,
        flush_timer_armed: &mut bool,
    ) -> bool {
        let queue = &mut self.queues[queue_index];

        let disk_size = self.disk_size.lock();

        let mut needs_interrupt = false;
        while let Some(avail_desc) = queue.pop(&self.mem) {
            let len;
            match Request::parse(&avail_desc, &self.mem) {
                Ok(request) => {
                    let status = match request.execute(
                        self.read_only,
                        &mut self.disk_image,
                        *disk_size,
                        flush_timer,
                        flush_timer_armed,
                        &self.mem,
                    ) {
                        Ok(l) => {
                            len = l;
                            VIRTIO_BLK_S_OK
                        }
                        Err(e) => {
                            error!("failed executing disk request: {}", e);
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
                    error!("failed processing available descriptor chain: {}", e);
                    len = 0;
                }
            }

            queue.add_used(&self.mem, avail_desc.index, len);
            needs_interrupt = true;
        }

        needs_interrupt
    }

    fn resize(&mut self, new_size: u64) -> DiskControlResult {
        if self.read_only {
            error!("Attempted to resize read-only block device");
            return DiskControlResult::Err(SysError::new(libc::EROFS));
        }

        info!("Resizing block device to {} bytes", new_size);

        if let Err(e) = self.disk_image.set_len(new_size) {
            error!("Resizing disk failed! {}", e);
            return DiskControlResult::Err(SysError::new(libc::EIO));
        }

        if let Ok(new_disk_size) = self.disk_image.seek(SeekFrom::End(0)) {
            let mut disk_size = self.disk_size.lock();
            *disk_size = new_disk_size;
        }
        DiskControlResult::Ok
    }

    fn signal_used_queue(&self) {
        self.interrupt_status
            .fetch_or(INTERRUPT_STATUS_USED_RING as usize, Ordering::SeqCst);
        self.interrupt_evt.write(1).unwrap();
    }

    fn signal_config_changed(&self) {
        self.interrupt_status
            .fetch_or(INTERRUPT_STATUS_CONFIG_CHANGED as usize, Ordering::SeqCst);
        self.interrupt_evt.write(1).unwrap();
    }

    fn run(
        &mut self,
        queue_evt: EventFd,
        kill_evt: EventFd,
        control_socket: DiskControlResponseSocket,
    ) {
        #[derive(PollToken)]
        enum Token {
            FlushTimer,
            QueueAvailable,
            ControlRequest,
            InterruptResample,
            Kill,
        }

        let mut flush_timer = match TimerFd::new() {
            Ok(t) => t,
            Err(e) => {
                error!("Failed to create the flush timer: {}", e);
                return;
            }
        };
        let mut flush_timer_armed = false;

        let poll_ctx: PollContext<Token> = match PollContext::new()
            .and_then(|pc| pc.add(&flush_timer, Token::FlushTimer).and(Ok(pc)))
            .and_then(|pc| pc.add(&queue_evt, Token::QueueAvailable).and(Ok(pc)))
            .and_then(|pc| pc.add(&control_socket, Token::ControlRequest).and(Ok(pc)))
            .and_then(|pc| {
                pc.add(&self.interrupt_resample_evt, Token::InterruptResample)
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
            let mut needs_config_interrupt = false;
            for event in events.iter_readable() {
                match event.token() {
                    Token::FlushTimer => {
                        if let Err(e) = self.disk_image.fsync() {
                            error!("Failed to flush the disk: {}", e);
                            break 'poll;
                        }
                        if let Err(e) = flush_timer.wait() {
                            error!("Failed to clear flush timer: {}", e);
                            break 'poll;
                        }
                    }
                    Token::QueueAvailable => {
                        if let Err(e) = queue_evt.read() {
                            error!("failed reading queue EventFd: {}", e);
                            break 'poll;
                        }
                        needs_interrupt |=
                            self.process_queue(0, &mut flush_timer, &mut flush_timer_armed);
                    }
                    Token::ControlRequest => {
                        let req = match control_socket.recv() {
                            Ok(req) => req,
                            Err(e) => {
                                error!("control socket failed recv: {}", e);
                                break 'poll;
                            }
                        };

                        let resp = match req {
                            DiskControlCommand::Resize { new_size } => {
                                needs_config_interrupt = true;
                                self.resize(new_size)
                            }
                        };

                        if let Err(e) = control_socket.send(&resp) {
                            error!("control socket failed send: {}", e);
                            break 'poll;
                        }
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
            if needs_config_interrupt {
                self.signal_config_changed();
            }
        }
    }
}

/// Virtio device for exposing block level read/write operations on a host file.
pub struct Block<T: DiskFile> {
    kill_evt: Option<EventFd>,
    disk_image: Option<T>,
    disk_size: Arc<Mutex<u64>>,
    avail_features: u64,
    read_only: bool,
    control_socket: Option<DiskControlResponseSocket>,
}

fn build_config_space(disk_size: u64) -> virtio_blk_config {
    virtio_blk_config {
        // If the image is not a multiple of the sector size, the tail bits are not exposed.
        capacity: Le64::from(disk_size >> SECTOR_SHIFT),
        blk_size: Le32::from(SECTOR_SIZE as u32),
        max_discard_sectors: Le32::from(MAX_DISCARD_SECTORS),
        discard_sector_alignment: Le32::from(DISCARD_SECTOR_ALIGNMENT),
        max_write_zeroes_sectors: Le32::from(MAX_WRITE_ZEROES_SECTORS),
        write_zeroes_may_unmap: 1,
        // Limit number of segments to 1 - see parse_discard_write_zeroes()
        max_discard_seg: Le32::from(1),
        max_write_zeroes_seg: Le32::from(1),
        ..Default::default()
    }
}

impl<T: DiskFile> Block<T> {
    /// Create a new virtio block device that operates on the given file.
    ///
    /// The given file must be seekable and sizable.
    pub fn new(
        mut disk_image: T,
        read_only: bool,
        control_socket: Option<DiskControlResponseSocket>,
    ) -> SysResult<Block<T>> {
        let disk_size = disk_image.seek(SeekFrom::End(0))? as u64;
        if disk_size % SECTOR_SIZE != 0 {
            warn!(
                "Disk size {} is not a multiple of sector size {}; \
                 the remainder will not be visible to the guest.",
                disk_size, SECTOR_SIZE
            );
        }

        let mut avail_features: u64 = 1 << VIRTIO_BLK_F_FLUSH;
        if read_only {
            avail_features |= 1 << VIRTIO_BLK_F_RO;
        } else {
            avail_features |= 1 << VIRTIO_BLK_F_DISCARD;
            avail_features |= 1 << VIRTIO_BLK_F_WRITE_ZEROES;
        }
        avail_features |= 1 << VIRTIO_F_VERSION_1;
        avail_features |= 1 << VIRTIO_BLK_F_BLK_SIZE;

        Ok(Block {
            kill_evt: None,
            disk_image: Some(disk_image),
            disk_size: Arc::new(Mutex::new(disk_size)),
            avail_features,
            read_only,
            control_socket,
        })
    }
}

impl<T: DiskFile> Drop for Block<T> {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }
    }
}

impl<T: 'static + AsRawFd + DiskFile + Send> VirtioDevice for Block<T> {
    fn keep_fds(&self) -> Vec<RawFd> {
        let mut keep_fds = Vec::new();

        if let Some(disk_image) = &self.disk_image {
            keep_fds.push(disk_image.as_raw_fd());
        }

        if let Some(control_socket) = &self.control_socket {
            keep_fds.push(control_socket.as_raw_fd());
        }

        keep_fds
    }

    fn features(&self) -> u64 {
        self.avail_features
    }

    fn device_type(&self) -> u32 {
        TYPE_BLOCK
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_space = {
            let disk_size = self.disk_size.lock();
            build_config_space(*disk_size)
        };
        let config_len = size_of_val(&config_space) as u64;
        if offset >= config_len {
            return;
        }

        if let Some(end) = offset.checked_add(data.len() as u64) {
            let offset = offset as usize;
            let end = cmp::min(end, config_len) as usize;
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(&config_space.as_slice()[offset..end])
                .unwrap();
        }
    }

    fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt_evt: EventFd,
        interrupt_resample_evt: EventFd,
        status: Arc<AtomicUsize>,
        queues: Vec<Queue>,
        mut queue_evts: Vec<EventFd>,
    ) {
        if queues.len() != 1 || queue_evts.len() != 1 {
            return;
        }

        let (self_kill_evt, kill_evt) = match EventFd::new().and_then(|e| Ok((e.try_clone()?, e))) {
            Ok(v) => v,
            Err(e) => {
                error!("failed creating kill EventFd pair: {}", e);
                return;
            }
        };
        self.kill_evt = Some(self_kill_evt);

        let read_only = self.read_only;
        let disk_size = self.disk_size.clone();
        if let Some(disk_image) = self.disk_image.take() {
            if let Some(control_socket) = self.control_socket.take() {
                let worker_result =
                    thread::Builder::new()
                        .name("virtio_blk".to_string())
                        .spawn(move || {
                            let mut worker = Worker {
                                queues,
                                mem,
                                disk_image,
                                disk_size,
                                read_only,
                                interrupt_status: status,
                                interrupt_evt,
                                interrupt_resample_evt,
                            };
                            worker.run(queue_evts.remove(0), kill_evt, control_socket);
                        });

                if let Err(e) = worker_result {
                    error!("failed to spawn virtio_blk worker: {}", e);
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{File, OpenOptions};
    use std::path::PathBuf;
    use sys_util::TempDir;

    use super::*;

    #[test]
    fn read_size() {
        let tempdir = TempDir::new("/tmp/block_read_test").unwrap();
        let mut path = PathBuf::from(tempdir.as_path().unwrap());
        path.push("disk_image");
        let f = File::create(&path).unwrap();
        f.set_len(0x1000).unwrap();

        let b = Block::new(f, true, None).unwrap();
        let mut num_sectors = [0u8; 4];
        b.read_config(0, &mut num_sectors);
        // size is 0x1000, so num_sectors is 8 (4096/512).
        assert_eq!([0x08, 0x00, 0x00, 0x00], num_sectors);
        let mut msw_sectors = [0u8; 4];
        b.read_config(4, &mut msw_sectors);
        // size is 0x1000, so msw_sectors is 0.
        assert_eq!([0x00, 0x00, 0x00, 0x00], msw_sectors);
    }

    #[test]
    fn read_features() {
        let tempdir = TempDir::new("/tmp/block_read_test").unwrap();
        let mut path = PathBuf::from(tempdir.as_path().unwrap());
        path.push("disk_image");

        // read-write block device
        {
            let f = File::create(&path).unwrap();
            let b = Block::new(f, false, None).unwrap();
            // writable device should set VIRTIO_BLK_F_FLUSH + VIRTIO_BLK_F_DISCARD
            // + VIRTIO_BLK_F_WRITE_ZEROES + VIRTIO_F_VERSION_1 + VIRTIO_BLK_F_BLK_SIZE
            assert_eq!(0x100006240, b.features());
        }

        // read-only block device
        {
            let f = File::create(&path).unwrap();
            let b = Block::new(f, true, None).unwrap();
            // read-only device should set VIRTIO_BLK_F_FLUSH and VIRTIO_BLK_F_RO
            // + VIRTIO_F_VERSION_1 + VIRTIO_BLK_F_BLK_SIZE
            assert_eq!(0x100000260, b.features());
        }
    }

    #[test]
    fn read_last_sector() {
        let tempdir = TempDir::new("/tmp/block_read_test").unwrap();
        let mut path = PathBuf::from(tempdir.as_path().unwrap());
        path.push("disk_image");
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .unwrap();
        let disk_size = 0x1000;
        f.set_len(disk_size).unwrap();

        let mem = GuestMemory::new(&[(GuestAddress(0u64), 4 * 1024 * 1024)])
            .expect("Creating guest memory failed.");

        let req = Request {
            request_type: RequestType::In,
            sector: 7, // Disk is 8 sectors long, so this is the last valid sector.
            data_addr: GuestAddress(0x1000),
            data_len: 512, // Read 1 sector of data.
            status_addr: GuestAddress(0),
            discard_write_zeroes_seg: None,
        };

        let mut flush_timer = TimerFd::new().expect("failed to create flush_timer");
        let mut flush_timer_armed = false;

        assert_eq!(
            512,
            req.execute(
                false,
                &mut f,
                disk_size,
                &mut flush_timer,
                &mut flush_timer_armed,
                &mem
            )
            .expect("execute failed"),
        );
    }

    #[test]
    fn read_beyond_last_sector() {
        let tempdir = TempDir::new("/tmp/block_read_test").unwrap();
        let mut path = PathBuf::from(tempdir.as_path().unwrap());
        path.push("disk_image");
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .unwrap();
        let disk_size = 0x1000;
        f.set_len(disk_size).unwrap();

        let mem = GuestMemory::new(&[(GuestAddress(0u64), 4 * 1024 * 1024)])
            .expect("Creating guest memory failed.");

        let req = Request {
            request_type: RequestType::In,
            sector: 7, // Disk is 8 sectors long, so this is the last valid sector.
            data_addr: GuestAddress(0x1000),
            data_len: 512 * 2, // Read 2 sectors of data (overlap the end of the disk).
            status_addr: GuestAddress(0),
            discard_write_zeroes_seg: None,
        };

        let mut flush_timer = TimerFd::new().expect("failed to create flush_timer");
        let mut flush_timer_armed = false;

        req.execute(
            false,
            &mut f,
            disk_size,
            &mut flush_timer,
            &mut flush_timer_armed,
            &mem,
        )
        .expect_err("execute was supposed to fail");
    }
}
