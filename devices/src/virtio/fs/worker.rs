// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::convert::TryFrom;
use std::convert::TryInto;
use std::fs::File;
use std::io;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;

use base::error;
use base::syscall;
use base::Event;
use base::EventToken;
use base::Protection;
use base::SafeDescriptor;
use base::Tube;
use base::WaitContext;
use fuse::filesystem::FileSystem;
use fuse::filesystem::ZeroCopyReader;
use fuse::filesystem::ZeroCopyWriter;
use sync::Mutex;
use vm_control::FsMappingRequest;
use vm_control::VmResponse;
use vm_memory::GuestMemory;

use crate::virtio::fs::Error;
use crate::virtio::fs::Result;
use crate::virtio::Interrupt;
use crate::virtio::Queue;
use crate::virtio::Reader;
use crate::virtio::SignalableInterrupt;
use crate::virtio::Writer;

impl fuse::Reader for Reader {}

impl fuse::Writer for Writer {
    type ClosureWriter = Self;

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
        let tube = self.tube.lock();

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
            prot: Protection::from(prot as libc::c_int),
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
    irq: Interrupt,
    tube: Arc<Mutex<Tube>>,
    slot: u32,
}

pub fn process_fs_queue<I: SignalableInterrupt, F: FileSystem + Sync>(
    mem: &GuestMemory,
    interrupt: &I,
    queue: &mut Queue,
    server: &Arc<fuse::Server<F>>,
    tube: &Arc<Mutex<Tube>>,
    slot: u32,
) -> Result<()> {
    let mapper = Mapper::new(Arc::clone(tube), slot);
    while let Some(avail_desc) = queue.pop(mem) {
        let reader =
            Reader::new(mem.clone(), avail_desc.clone()).map_err(Error::InvalidDescriptorChain)?;
        let writer =
            Writer::new(mem.clone(), avail_desc.clone()).map_err(Error::InvalidDescriptorChain)?;

        let total = server.handle_message(reader, writer, &mapper)?;

        queue.add_used(mem, avail_desc.index, total as u32);
        queue.trigger_interrupt(mem, interrupt);
    }

    Ok(())
}

impl<F: FileSystem + Sync> Worker<F> {
    pub fn new(
        mem: GuestMemory,
        queue: Queue,
        server: Arc<fuse::Server<F>>,
        irq: Interrupt,
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
        let mut securebits = syscall!(unsafe { libc::prctl(libc::PR_GET_SECUREBITS) })
            .map_err(Error::GetSecurebits)?;

        securebits |= SECBIT_NO_SETUID_FIXUP;

        // Safe because this doesn't modify any memory and we check the return value.
        syscall!(unsafe { libc::prctl(libc::PR_SET_SECUREBITS, securebits) })
            .map_err(Error::SetSecurebits)?;

        // To avoid extra locking, unshare filesystem attributes from parent. This includes the
        // current working directory and umask.
        // Safe because this doesn't modify any memory and we check the return value.
        syscall!(unsafe { libc::unshare(libc::CLONE_FS) }).map_err(Error::UnshareFromParent)?;

        #[derive(EventToken)]
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
                        queue_evt.wait().map_err(Error::ReadQueueEvent)?;
                        if let Err(e) = process_fs_queue(
                            &self.mem,
                            &self.irq,
                            &mut self.queue,
                            &self.server,
                            &self.tube,
                            self.slot,
                        ) {
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
