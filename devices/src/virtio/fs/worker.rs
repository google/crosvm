// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::convert::{TryFrom, TryInto};
use std::fs::File;
use std::io;
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Mutex};

use base::{error, Event, PollToken, SafeDescriptor, Tube, WaitContext};
use fuse::filesystem::{FileSystem, ZeroCopyReader, ZeroCopyWriter};
use vm_control::{FsMappingRequest, VmResponse};
use vm_memory::GuestMemory;

use crate::virtio::fs::{Error, Result};
use crate::virtio::{Interrupt, Queue, Reader, SignalableInterrupt, Writer};

impl fuse::Reader for Reader {}

impl fuse::Writer for Writer {
    fn write_at<F>(&mut self, offset: usize, f: F) -> io::Result<usize>
    where
        F: Fn(&mut Self) -> io::Result<usize>,
    {
        let mut writer = Writer::split_at(self, offset);
        f(&mut writer)
    }

    fn has_sufficient_buffer(&self, size: u32) -> bool {
        self.available_bytes() >= size as usize
    }
}

impl ZeroCopyReader for Reader {
    fn read_to(&mut self, f: &mut File, count: usize, off: u64) -> io::Result<usize> {
        self.read_to_at(f, count, off)
    }
}

impl ZeroCopyWriter for Writer {
    fn write_from(&mut self, f: &mut File, count: usize, off: u64) -> io::Result<usize> {
        self.write_from_at(f, count, off)
    }
}

struct Mapper {
    tube: Arc<Mutex<Tube>>,
    slot: u32,
}

impl Mapper {
    fn new(tube: Arc<Mutex<Tube>>, slot: u32) -> Self {
        Self { tube, slot }
    }

    fn process_request(&self, request: &FsMappingRequest) -> io::Result<()> {
        let tube = self.tube.lock().map_err(|e| {
            error!("failed to lock tube: {}", e);
            io::Error::from_raw_os_error(libc::EINVAL)
        })?;

        tube.send(request).map_err(|e| {
            error!("failed to send request {:?}: {}", request, e);
            io::Error::from_raw_os_error(libc::EINVAL)
        })?;

        match tube.recv() {
            Ok(VmResponse::Ok) => Ok(()),
            Ok(VmResponse::Err(e)) => Err(e.into()),
            r => {
                error!("failed to process {:?}: {:?}", request, r);
                Err(io::Error::from_raw_os_error(libc::EIO))
            }
        }
    }
}

impl fuse::Mapper for Mapper {
    fn map(
        &self,
        mem_offset: u64,
        size: usize,
        fd: &dyn AsRawFd,
        file_offset: u64,
        prot: u32,
    ) -> io::Result<()> {
        let mem_offset: usize = mem_offset.try_into().map_err(|e| {
            error!("mem_offset {} is too big: {}", mem_offset, e);
            io::Error::from_raw_os_error(libc::EINVAL)
        })?;

        let fd = SafeDescriptor::try_from(fd)?;

        let request = FsMappingRequest::CreateMemoryMapping {
            slot: self.slot,
            fd,
            size,
            file_offset,
            prot,
            mem_offset,
        };

        self.process_request(&request)
    }

    fn unmap(&self, offset: u64, size: u64) -> io::Result<()> {
        let offset: usize = offset.try_into().map_err(|e| {
            error!("offset {} is too big: {}", offset, e);
            io::Error::from_raw_os_error(libc::EINVAL)
        })?;
        let size: usize = size.try_into().map_err(|e| {
            error!("size {} is too big: {}", size, e);
            io::Error::from_raw_os_error(libc::EINVAL)
        })?;

        let request = FsMappingRequest::RemoveMemoryMapping {
            slot: self.slot,
            offset,
            size,
        };

        self.process_request(&request)
    }
}

pub struct Worker<F: FileSystem + Sync> {
    mem: GuestMemory,
    queue: Queue,
    server: Arc<fuse::Server<F>>,
    irq: Arc<Interrupt>,
    tube: Arc<Mutex<Tube>>,
    slot: u32,
}

impl<F: FileSystem + Sync> Worker<F> {
    pub fn new(
        mem: GuestMemory,
        queue: Queue,
        server: Arc<fuse::Server<F>>,
        irq: Arc<Interrupt>,
        tube: Arc<Mutex<Tube>>,
        slot: u32,
    ) -> Worker<F> {
        Worker {
            mem,
            queue,
            server,
            irq,
            tube,
            slot,
        }
    }

    fn process_queue(&mut self) -> Result<()> {
        let mut needs_interrupt = false;

        let mapper = Mapper::new(Arc::clone(&self.tube), self.slot);
        while let Some(avail_desc) = self.queue.pop(&self.mem) {
            let reader = Reader::new(self.mem.clone(), avail_desc.clone())
                .map_err(Error::InvalidDescriptorChain)?;
            let writer = Writer::new(self.mem.clone(), avail_desc.clone())
                .map_err(Error::InvalidDescriptorChain)?;

            let total = self.server.handle_message(reader, writer, &mapper)?;

            self.queue
                .add_used(&self.mem, avail_desc.index, total as u32);

            needs_interrupt = true;
        }

        if needs_interrupt {
            self.irq.signal_used_queue(self.queue.vector);
        }

        Ok(())
    }

    pub fn run(
        &mut self,
        queue_evt: Event,
        kill_evt: Event,
        watch_resample_event: bool,
    ) -> Result<()> {
        // We need to set the no setuid fixup secure bit so that we don't drop capabilities when
        // changing the thread uid/gid. Without this, creating new entries can fail in some corner
        // cases.
        const SECBIT_NO_SETUID_FIXUP: i32 = 1 << 2;

        // Safe because this doesn't modify any memory and we check the return value.
        let mut securebits = unsafe { libc::prctl(libc::PR_GET_SECUREBITS) };
        if securebits < 0 {
            return Err(Error::GetSecurebits(io::Error::last_os_error()));
        }

        securebits |= SECBIT_NO_SETUID_FIXUP;

        // Safe because this doesn't modify any memory and we check the return value.
        let ret = unsafe { libc::prctl(libc::PR_SET_SECUREBITS, securebits) };
        if ret < 0 {
            return Err(Error::SetSecurebits(io::Error::last_os_error()));
        }

        #[derive(PollToken)]
        enum Token {
            // A request is ready on the queue.
            QueueReady,
            // Check if any interrupts need to be re-asserted.
            InterruptResample,
            // The parent thread requested an exit.
            Kill,
        }

        let wait_ctx =
            WaitContext::build_with(&[(&queue_evt, Token::QueueReady), (&kill_evt, Token::Kill)])
                .map_err(Error::CreateWaitContext)?;

        if watch_resample_event {
            if let Some(resample_evt) = self.irq.get_resample_evt() {
                wait_ctx
                    .add(resample_evt, Token::InterruptResample)
                    .map_err(Error::CreateWaitContext)?;
            }
        }

        loop {
            let events = wait_ctx.wait().map_err(Error::WaitError)?;
            for event in events.iter().filter(|e| e.is_readable) {
                match event.token {
                    Token::QueueReady => {
                        queue_evt.read().map_err(Error::ReadQueueEvent)?;
                        if let Err(e) = self.process_queue() {
                            error!("virtio-fs transport error: {}", e);
                            return Err(e);
                        }
                    }
                    Token::InterruptResample => {
                        self.irq.interrupt_resample();
                    }
                    Token::Kill => return Ok(()),
                }
            }
        }
    }
}
