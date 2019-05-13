// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp::min;
use std::fmt::{self, Display};
use std::io::{self, Read, Write};
use std::iter::Peekable;
use std::mem;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::result;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

use p9;
use sys_util::{
    error, warn, Error as SysError, EventFd, GuestAddress, GuestMemory, PollContext, PollToken,
};
use virtio_sys::vhost::VIRTIO_F_VERSION_1;

use super::{DescriptorChain, Queue, VirtioDevice, INTERRUPT_STATUS_USED_RING, TYPE_9P};

const QUEUE_SIZE: u16 = 128;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE];

// The only virtio_9p feature.
const VIRTIO_9P_MOUNT_TAG: u8 = 0;

/// Errors that occur during operation of a virtio 9P device.
#[derive(Debug)]
pub enum P9Error {
    /// The tag for the 9P device was too large to fit in the config space.
    TagTooLong(usize),
    /// The root directory for the 9P server is not absolute.
    RootNotAbsolute(PathBuf),
    /// Creating PollContext failed.
    CreatePollContext(SysError),
    /// Error while polling for events.
    PollError(SysError),
    /// Error while reading from the virtio queue's EventFd.
    ReadQueueEventFd(SysError),
    /// A request is missing readable descriptors.
    NoReadableDescriptors,
    /// A request is missing writable descriptors.
    NoWritableDescriptors,
    /// A descriptor contained an invalid guest address range.
    InvalidGuestAddress(GuestAddress, u32),
    /// Failed to signal the virio used queue.
    SignalUsedQueue(SysError),
    /// An internal I/O error occurred.
    Internal(io::Error),
}

impl std::error::Error for P9Error {}

impl Display for P9Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::P9Error::*;

        match self {
            TagTooLong(len) => write!(
                f,
                "P9 device tag is too long: len = {}, max = {}",
                len,
                ::std::u16::MAX
            ),
            RootNotAbsolute(buf) => write!(
                f,
                "P9 root directory is not absolute: root = {}",
                buf.display()
            ),
            CreatePollContext(err) => write!(f, "failed to create PollContext: {}", err),
            PollError(err) => write!(f, "failed to poll events: {}", err),
            ReadQueueEventFd(err) => write!(f, "failed to read from virtio queue EventFd: {}", err),
            NoReadableDescriptors => write!(f, "request does not have any readable descriptors"),
            NoWritableDescriptors => write!(f, "request does not have any writable descriptors"),
            InvalidGuestAddress(addr, len) => write!(
                f,
                "descriptor contained invalid guest address range: address = {}, len = {}",
                addr, len
            ),
            SignalUsedQueue(err) => write!(f, "failed to signal used queue: {}", err),
            Internal(err) => write!(f, "P9 internal server error: {}", err),
        }
    }
}

pub type P9Result<T> = result::Result<T, P9Error>;

struct Reader<'a, I>
where
    I: Iterator<Item = DescriptorChain<'a>>,
{
    mem: &'a GuestMemory,
    offset: u32,
    iter: Peekable<I>,
}

impl<'a, I> Read for Reader<'a, I>
where
    I: Iterator<Item = DescriptorChain<'a>>,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let needs_advance = if let Some(current) = self.iter.peek() {
            self.offset >= current.len
        } else {
            false
        };

        if needs_advance {
            self.offset = 0;
            self.iter.next();
        }

        if let Some(current) = self.iter.peek() {
            debug_assert!(current.is_read_only());
            let addr = current
                .addr
                .checked_add(self.offset as u64)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        P9Error::InvalidGuestAddress(current.addr, current.len),
                    )
                })?;
            let len = min(buf.len(), (current.len - self.offset) as usize);
            let count = self
                .mem
                .read_at_addr(&mut buf[..len], addr)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            // |count| has to fit into a u32 because it must be less than or equal to
            // |current.len|, which does fit into a u32.
            self.offset += count as u32;

            Ok(count)
        } else {
            // Nothing left to read.
            Ok(0)
        }
    }
}

struct Writer<'a, I>
where
    I: Iterator<Item = DescriptorChain<'a>>,
{
    mem: &'a GuestMemory,
    bytes_written: u32,
    offset: u32,
    iter: Peekable<I>,
}

impl<'a, I> Write for Writer<'a, I>
where
    I: Iterator<Item = DescriptorChain<'a>>,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let needs_advance = if let Some(current) = self.iter.peek() {
            self.offset >= current.len
        } else {
            false
        };

        if needs_advance {
            self.offset = 0;
            self.iter.next();
        }

        if let Some(current) = self.iter.peek() {
            debug_assert!(current.is_write_only());
            let addr = current
                .addr
                .checked_add(self.offset as u64)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        P9Error::InvalidGuestAddress(current.addr, current.len),
                    )
                })?;

            let len = min(buf.len(), (current.len - self.offset) as usize);
            let count = self
                .mem
                .write_at_addr(&buf[..len], addr)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            // |count| has to fit into a u32 because it must be less than or equal to
            // |current.len|, which does fit into a u32.
            self.offset += count as u32;
            self.bytes_written += count as u32;

            Ok(count)
        } else {
            // No more room in the descriptor chain.
            Ok(0)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        // Nothing to flush since the writes go straight into the buffer.
        Ok(())
    }
}

struct Worker {
    mem: GuestMemory,
    queue: Queue,
    server: p9::Server,
    irq_status: Arc<AtomicUsize>,
    irq_evt: EventFd,
    interrupt_resample_evt: EventFd,
}

impl Worker {
    fn signal_used_queue(&self) -> P9Result<()> {
        self.irq_status
            .fetch_or(INTERRUPT_STATUS_USED_RING as usize, Ordering::SeqCst);
        self.irq_evt.write(1).map_err(P9Error::SignalUsedQueue)
    }

    fn process_queue(&mut self) -> P9Result<()> {
        while let Some(avail_desc) = self.queue.pop(&self.mem) {
            let mut reader = Reader {
                mem: &self.mem,
                offset: 0,
                iter: avail_desc.clone().into_iter().readable().peekable(),
            };
            let mut writer = Writer {
                mem: &self.mem,
                bytes_written: 0,
                offset: 0,
                iter: avail_desc.clone().into_iter().writable().peekable(),
            };

            self.server
                .handle_message(&mut reader, &mut writer)
                .map_err(P9Error::Internal)?;

            self.queue
                .add_used(&self.mem, avail_desc.index, writer.bytes_written);
        }

        self.signal_used_queue()?;

        Ok(())
    }

    fn run(&mut self, queue_evt: EventFd, kill_evt: EventFd) -> P9Result<()> {
        #[derive(PollToken)]
        enum Token {
            // A request is ready on the queue.
            QueueReady,
            // Check if any interrupts need to be re-asserted.
            InterruptResample,
            // The parent thread requested an exit.
            Kill,
        }

        let poll_ctx: PollContext<Token> = PollContext::new()
            .and_then(|pc| pc.add(&queue_evt, Token::QueueReady).and(Ok(pc)))
            .and_then(|pc| {
                pc.add(&self.interrupt_resample_evt, Token::InterruptResample)
                    .and(Ok(pc))
            })
            .and_then(|pc| pc.add(&kill_evt, Token::Kill).and(Ok(pc)))
            .map_err(P9Error::CreatePollContext)?;

        loop {
            let events = poll_ctx.wait().map_err(P9Error::PollError)?;
            for event in events.iter_readable() {
                match event.token() {
                    Token::QueueReady => {
                        queue_evt.read().map_err(P9Error::ReadQueueEventFd)?;
                        self.process_queue()?;
                    }
                    Token::InterruptResample => {
                        let _ = self.interrupt_resample_evt.read();
                        if self.irq_status.load(Ordering::SeqCst) != 0 {
                            self.irq_evt.write(1).unwrap();
                        }
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
    kill_evt: Option<EventFd>,
    avail_features: u64,
    acked_features: u64,
    worker: Option<thread::JoinHandle<P9Result<()>>>,
}

impl P9 {
    pub fn new<P: AsRef<Path>>(root: P, tag: &str) -> P9Result<P9> {
        if tag.len() > ::std::u16::MAX as usize {
            return Err(P9Error::TagTooLong(tag.len()));
        }

        if !root.as_ref().is_absolute() {
            return Err(P9Error::RootNotAbsolute(root.as_ref().into()));
        }

        let len = tag.len() as u16;
        let mut cfg = Vec::with_capacity(tag.len() + mem::size_of::<u16>());
        cfg.push(len as u8);
        cfg.push((len >> 8) as u8);

        cfg.write_all(tag.as_bytes()).map_err(P9Error::Internal)?;

        Ok(P9 {
            config: cfg,
            server: Some(p9::Server::new(root)),
            kill_evt: None,
            avail_features: 1 << VIRTIO_9P_MOUNT_TAG | 1 << VIRTIO_F_VERSION_1,
            acked_features: 0,
            worker: None,
        })
    }
}

impl VirtioDevice for P9 {
    fn keep_fds(&self) -> Vec<RawFd> {
        Vec::new()
    }

    fn device_type(&self) -> u32 {
        TYPE_9P
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
        if offset >= self.config.len() as u64 {
            // Nothing to see here.
            return;
        }

        // The config length cannot be more than ::std::u16::MAX + mem::size_of::<u16>(), which
        // is significantly smaller than ::std::usize::MAX on the architectures we care about so
        // if we reach this point then we know that `offset` will fit into a usize.
        let offset = offset as usize;
        let len = min(data.len(), self.config.len() - offset);
        data[..len].copy_from_slice(&self.config[offset..offset + len])
    }

    fn activate(
        &mut self,
        guest_mem: GuestMemory,
        interrupt_evt: EventFd,
        interrupt_resample_evt: EventFd,
        status: Arc<AtomicUsize>,
        mut queues: Vec<Queue>,
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

        if let Some(server) = self.server.take() {
            let worker_result =
                thread::Builder::new()
                    .name("virtio_9p".to_string())
                    .spawn(move || {
                        let mut worker = Worker {
                            mem: guest_mem,
                            queue: queues.remove(0),
                            server,
                            irq_status: status,
                            irq_evt: interrupt_evt,
                            interrupt_resample_evt,
                        };

                        worker.run(queue_evts.remove(0), kill_evt)
                    });

            match worker_result {
                Ok(worker) => self.worker = Some(worker),
                Err(e) => error!("failed to spawn virtio_9p worker: {}", e),
            }
        }
    }
}

impl Drop for P9 {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.kill_evt.take() {
            if let Err(e) = kill_evt.write(1) {
                error!("failed to kill virtio_9p worker thread: {}", e);
                return;
            }

            // Only wait on the child thread if we were able to send it a kill event.
            if let Some(worker) = self.worker.take() {
                match worker.join() {
                    Ok(r) => {
                        if let Err(e) = r {
                            error!("virtio_9p worker thread exited with error: {}", e)
                        }
                    }
                    Err(e) => error!("virtio_9p worker thread panicked: {:?}", e),
                }
            }
        }
    }
}
