// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::FromBytesWithNulError;
use std::fmt;
use std::io;
use std::mem;
use std::os::unix::io::RawFd;
use std::sync::Arc;
use std::thread;

use data_model::{DataInit, Le32};
use sys_util::{error, warn, Error as SysError, EventFd, GuestMemory};

use crate::virtio::{
    copy_config, DescriptorError, Interrupt, Queue, VirtioDevice, TYPE_FS, VIRTIO_F_VERSION_1,
};

mod filesystem;
#[allow(dead_code)]
mod fuse;
#[cfg(fuzzing)]
pub mod fuzzing;
mod multikey;
pub mod passthrough;
mod server;
mod worker;

use passthrough::PassthroughFs;
use server::Server;
use worker::Worker;

// The fs device does not have a fixed number of queues.
const QUEUE_SIZE: u16 = 1024;

/// The maximum allowable length of the tag used to identify a specific virtio-fs device.
pub const FS_MAX_TAG_LEN: usize = 36;

/// kernel/include/uapi/linux/virtio_fs.h
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Config {
    /// Filesystem name (UTF-8, not NUL-terminated, padded with NULs)
    tag: [u8; FS_MAX_TAG_LEN],
    /// Number of request queues
    num_queues: Le32,
}

// Safe because all members are plain old data and any value is valid.
unsafe impl DataInit for Config {}

/// Errors that may occur during the creation or operation of an Fs device.
#[derive(Debug)]
pub enum Error {
    /// The tag for the Fs device was too long to fit in the config space.
    TagTooLong(usize),
    /// Failed to create the file system.
    CreateFs(io::Error),
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
    /// Failed to signal the virio used queue.
    SignalUsedQueue(SysError),
    /// Failed to decode protocol messages.
    DecodeMessage(io::Error),
    /// Failed to encode protocol messages.
    EncodeMessage(io::Error),
    /// One or more parameters are missing.
    MissingParameter,
    /// A C string parameter is invalid.
    InvalidCString(FromBytesWithNulError),
    /// The `len` field of the header is too small.
    InvalidHeaderLength,
    /// A `DescriptorChain` contains invalid data.
    InvalidDescriptorChain(DescriptorError),
    /// The `size` field of the `SetxattrIn` message does not match the length
    /// of the decoded value.
    InvalidXattrSize((u32, usize)),
}

impl ::std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;
        match self {
            TagTooLong(len) => write!(
                f,
                "Fs device tag is too long: len = {}, max = {}",
                len, FS_MAX_TAG_LEN
            ),
            CreateFs(err) => write!(f, "failed to create file system: {}", err),
            CreatePollContext(err) => write!(f, "failed to create PollContext: {}", err),
            PollError(err) => write!(f, "failed to poll events: {}", err),
            ReadQueueEventFd(err) => write!(f, "failed to read from virtio queue EventFd: {}", err),
            NoReadableDescriptors => write!(f, "request does not have any readable descriptors"),
            NoWritableDescriptors => write!(f, "request does not have any writable descriptors"),
            SignalUsedQueue(err) => write!(f, "failed to signal used queue: {}", err),
            DecodeMessage(err) => write!(f, "failed to decode fuse message: {}", err),
            EncodeMessage(err) => write!(f, "failed to encode fuse message: {}", err),
            MissingParameter => write!(f, "one or more parameters are missing"),
            InvalidHeaderLength => write!(f, "the `len` field of the header is too small"),
            InvalidCString(err) => write!(f, "a c string parameter is invalid: {}", err),
            InvalidDescriptorChain(err) => write!(f, "DescriptorChain is invalid: {}", err),
            InvalidXattrSize((size, len)) => write!(
                f,
                "The `size` field of the `SetxattrIn` message does not match the length of the\
                 decoded value: size = {}, value.len() = {}",
                size, len
            ),
        }
    }
}

pub type Result<T> = ::std::result::Result<T, Error>;

pub struct Fs {
    cfg: Config,
    fs: Option<PassthroughFs>,
    queue_sizes: Box<[u16]>,
    avail_features: u64,
    acked_features: u64,
    workers: Vec<(EventFd, thread::JoinHandle<Result<()>>)>,
}

impl Fs {
    pub fn new(tag: &str, num_workers: usize, fs_cfg: passthrough::Config) -> Result<Fs> {
        if tag.len() > FS_MAX_TAG_LEN {
            return Err(Error::TagTooLong(tag.len()));
        }

        let mut cfg_tag = [0u8; FS_MAX_TAG_LEN];
        cfg_tag[..tag.len()].copy_from_slice(tag.as_bytes());

        let cfg = Config {
            tag: cfg_tag,
            num_queues: Le32::from(num_workers as u32),
        };

        let fs = PassthroughFs::new(fs_cfg).map_err(Error::CreateFs)?;

        // There is always a high priority queue in addition to the request queues.
        let num_queues = num_workers + 1;

        Ok(Fs {
            cfg,
            fs: Some(fs),
            queue_sizes: vec![QUEUE_SIZE; num_queues].into_boxed_slice(),
            avail_features: 1 << VIRTIO_F_VERSION_1,
            acked_features: 0,
            workers: Vec::with_capacity(num_workers + 1),
        })
    }

    fn stop_workers(&mut self) {
        for (kill_evt, handle) in mem::replace(&mut self.workers, Vec::new()) {
            if let Err(e) = kill_evt.write(1) {
                error!("failed to kill virtio-fs worker thread: {}", e);
                continue;
            }

            // Only wait on the child thread if we were able to send it a kill event.
            match handle.join() {
                Ok(r) => {
                    if let Err(e) = r {
                        error!("virtio-fs worker thread exited with error: {}", e)
                    }
                }
                Err(e) => error!("virtio-fs worker thread panicked: {:?}", e),
            }
        }
    }
}

impl VirtioDevice for Fs {
    fn keep_fds(&self) -> Vec<RawFd> {
        self.fs
            .as_ref()
            .map(PassthroughFs::keep_fds)
            .unwrap_or_else(Vec::new)
    }

    fn device_type(&self) -> u32 {
        TYPE_FS
    }

    fn msix_vectors(&self) -> u16 {
        self.queue_sizes.len() as u16
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.queue_sizes
    }

    fn features(&self) -> u64 {
        self.avail_features
    }

    fn ack_features(&mut self, mut v: u64) {
        // Check if the guest is ACK'ing a feature that we didn't claim to have.
        let unrequested_features = v & !self.avail_features;
        if unrequested_features != 0 {
            warn!("virtio_fs got unknown feature ack: {:x}", v);

            // Don't count these features as acked.
            v &= !unrequested_features;
        }
        self.acked_features |= v;
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        copy_config(data, 0, self.cfg.as_slice(), offset)
    }

    fn activate(
        &mut self,
        guest_mem: GuestMemory,
        interrupt: Interrupt,
        queues: Vec<Queue>,
        queue_evts: Vec<EventFd>,
    ) {
        if queues.len() != self.queue_sizes.len() || queue_evts.len() != self.queue_sizes.len() {
            return;
        }

        let fs = self.fs.take().expect("missing file system implementation");

        let server = Arc::new(Server::new(fs));
        let irq = Arc::new(interrupt);

        let mut watch_resample_event = true;
        for (idx, (queue, evt)) in queues.into_iter().zip(queue_evts.into_iter()).enumerate() {
            let (self_kill_evt, kill_evt) =
                match EventFd::new().and_then(|e| Ok((e.try_clone()?, e))) {
                    Ok(v) => v,
                    Err(e) => {
                        error!("fs: failed creating kill EventFd pair: {}", e);
                        self.stop_workers();
                        return;
                    }
                };

            let mem = guest_mem.clone();
            let server = server.clone();
            let irq = irq.clone();

            let worker_result = thread::Builder::new()
                .name(format!("virtio-fs worker {}", idx))
                .spawn(move || {
                    let mut worker = Worker::new(mem, queue, server, irq);
                    worker.run(evt, kill_evt, watch_resample_event)
                });

            if watch_resample_event {
                watch_resample_event = false;
            }

            match worker_result {
                Ok(worker) => self.workers.push((self_kill_evt, worker)),
                Err(e) => {
                    error!("fs: failed to spawn virtio_fs worker: {}", e);
                    self.stop_workers();
                    return;
                }
            }
        }
    }
}

impl Drop for Fs {
    fn drop(&mut self) {
        self.stop_workers()
    }
}
