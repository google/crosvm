// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;
use std::mem;
use std::sync::Arc;
use std::thread;

use anyhow::anyhow;
use anyhow::Context;
use base::error;
use base::warn;
use base::AsRawDescriptor;
use base::Error as SysError;
use base::Event;
use base::RawDescriptor;
use base::Tube;
use data_model::DataInit;
use data_model::Le32;
use remain::sorted;
use resources::Alloc;
use sync::Mutex;
use thiserror::Error;
use vm_control::FsMappingRequest;
use vm_control::VmResponse;
use vm_memory::GuestMemory;

use crate::pci::PciAddress;
use crate::pci::PciBarConfiguration;
use crate::pci::PciBarPrefetchable;
use crate::pci::PciBarRegionType;
use crate::pci::PciCapability;
use crate::virtio::copy_config;
use crate::virtio::DescriptorError;
use crate::virtio::DeviceType;
use crate::virtio::Interrupt;
use crate::virtio::PciCapabilityType;
use crate::virtio::Queue;
use crate::virtio::VirtioDevice;
use crate::virtio::VirtioPciShmCap;
use crate::Suspendable;

mod caps;
mod multikey;
pub mod passthrough;
mod read_dir;
mod worker;

use fuse::Server;
use passthrough::PassthroughFs;
pub use worker::process_fs_queue;
use worker::Worker;

// The fs device does not have a fixed number of queues.
pub const QUEUE_SIZE: u16 = 1024;

const FS_BAR_NUM: u8 = 4;
const FS_BAR_OFFSET: u64 = 0;
const FS_BAR_SIZE: u64 = 1 << 33;

/// Defined in kernel/include/uapi/linux/virtio_fs.h.
const VIRTIO_FS_SHMCAP_ID_CACHE: u8 = 0;

/// The maximum allowable length of the tag used to identify a specific virtio-fs device.
pub const FS_MAX_TAG_LEN: usize = 36;

/// kernel/include/uapi/linux/virtio_fs.h
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct virtio_fs_config {
    /// Filesystem name (UTF-8, not NUL-terminated, padded with NULs)
    pub tag: [u8; FS_MAX_TAG_LEN],
    /// Number of request queues
    pub num_request_queues: Le32,
}

// Safe because all members are plain old data and any value is valid.
unsafe impl DataInit for virtio_fs_config {}

/// Errors that may occur during the creation or operation of an Fs device.
#[sorted]
#[derive(Error, Debug)]
pub enum Error {
    /// Failed to create the file system.
    #[error("failed to create file system: {0}")]
    CreateFs(io::Error),
    /// Creating WaitContext failed.
    #[error("failed to create WaitContext: {0}")]
    CreateWaitContext(SysError),
    /// Error happened in FUSE.
    #[error("fuse error: {0}")]
    FuseError(fuse::Error),
    /// Failed to get the securebits for the worker thread.
    #[error("failed to get securebits for the worker thread: {0}")]
    GetSecurebits(SysError),
    /// The `len` field of the header is too small.
    #[error("DescriptorChain is invalid: {0}")]
    InvalidDescriptorChain(DescriptorError),
    /// A request is missing readable descriptors.
    #[error("request does not have any readable descriptors")]
    NoReadableDescriptors,
    /// A request is missing writable descriptors.
    #[error("request does not have any writable descriptors")]
    NoWritableDescriptors,
    /// Error while reading from the virtio queue's Event.
    #[error("failed to read from virtio queue Event: {0}")]
    ReadQueueEvent(SysError),
    /// Failed to set the securebits for the worker thread.
    #[error("failed to set securebits for the worker thread: {0}")]
    SetSecurebits(SysError),
    /// Failed to signal the virio used queue.
    #[error("failed to signal used queue: {0}")]
    SignalUsedQueue(SysError),
    /// The tag for the Fs device was too long to fit in the config space.
    #[error("Fs device tag is too long: len = {0}, max = {}", FS_MAX_TAG_LEN)]
    TagTooLong(usize),
    /// Calling unshare to disassociate FS attributes from parent failed.
    #[error("failed to unshare fs from parent: {0}")]
    UnshareFromParent(SysError),
    /// Error while polling for events.
    #[error("failed to wait for events: {0}")]
    WaitError(SysError),
}

impl From<fuse::Error> for Error {
    fn from(err: fuse::Error) -> Error {
        Error::FuseError(err)
    }
}

pub type Result<T> = ::std::result::Result<T, Error>;

pub struct Fs {
    cfg: virtio_fs_config,
    tag: String,
    fs: Option<PassthroughFs>,
    queue_sizes: Box<[u16]>,
    avail_features: u64,
    acked_features: u64,
    pci_bar: Option<Alloc>,
    tube: Option<Tube>,
    workers: Vec<(Event, thread::JoinHandle<Result<()>>)>,
}

impl Fs {
    pub fn new(
        base_features: u64,
        tag: &str,
        num_workers: usize,
        fs_cfg: passthrough::Config,
        tube: Tube,
    ) -> Result<Fs> {
        if tag.len() > FS_MAX_TAG_LEN {
            return Err(Error::TagTooLong(tag.len()));
        }

        let mut cfg_tag = [0u8; FS_MAX_TAG_LEN];
        cfg_tag[..tag.len()].copy_from_slice(tag.as_bytes());

        let cfg = virtio_fs_config {
            tag: cfg_tag,
            num_request_queues: Le32::from(num_workers as u32),
        };

        let fs = PassthroughFs::new(fs_cfg).map_err(Error::CreateFs)?;

        // There is always a high priority queue in addition to the request queues.
        let num_queues = num_workers + 1;

        Ok(Fs {
            cfg,
            tag: tag.to_string(),
            fs: Some(fs),
            queue_sizes: vec![QUEUE_SIZE; num_queues].into_boxed_slice(),
            avail_features: base_features,
            acked_features: 0,
            pci_bar: None,
            tube: Some(tube),
            workers: Vec::with_capacity(num_workers + 1),
        })
    }

    fn stop_workers(&mut self) {
        for (kill_evt, handle) in mem::take(&mut self.workers) {
            if let Err(e) = kill_evt.signal() {
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
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        let mut fds = self
            .fs
            .as_ref()
            .map(PassthroughFs::keep_rds)
            .unwrap_or_else(Vec::new);
        if let Some(rd) = self.tube.as_ref().map(|s| s.as_raw_descriptor()) {
            fds.push(rd);
        }

        fds
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::Fs
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
        queues: Vec<(Queue, Event)>,
    ) -> anyhow::Result<()> {
        if queues.len() != self.queue_sizes.len() {
            return Err(anyhow!(
                "expected {} queues, got {}",
                self.queue_sizes.len(),
                queues.len()
            ));
        }

        let fs = self.fs.take().expect("missing file system implementation");
        let use_dax = fs.cfg().use_dax;

        let server = Arc::new(Server::new(fs));
        let socket = self.tube.take().expect("missing mapping socket");
        let mut slot = 0;

        // Set up shared memory for DAX.
        // TODO(b/176129399): Remove cfg! once DAX is supported on ARM.
        if cfg!(any(target_arch = "x86", target_arch = "x86_64")) && use_dax {
            // Create the shared memory region now before we start processing requests.
            let request = FsMappingRequest::AllocateSharedMemoryRegion(
                self.pci_bar.as_ref().cloned().expect("No pci_bar"),
            );
            socket
                .send(&request)
                .expect("failed to send allocation message");
            slot = match socket.recv() {
                Ok(VmResponse::RegisterMemory { pfn: _, slot }) => slot,
                Ok(VmResponse::Err(e)) => panic!("failed to allocate shared memory region: {}", e),
                r => panic!(
                    "unexpected response to allocate shared memory region: {:?}",
                    r
                ),
            };
        }

        let socket = Arc::new(Mutex::new(socket));
        let mut watch_resample_event = true;
        for (idx, (queue, evt)) in queues.into_iter().enumerate() {
            let (self_kill_evt, kill_evt) = match Event::new().and_then(|e| Ok((e.try_clone()?, e)))
            {
                Ok(v) => v,
                Err(e) => {
                    self.stop_workers();
                    return Err(e).context("failed creating kill Event pair");
                }
            };

            let mem = guest_mem.clone();
            let server = server.clone();
            let irq = interrupt.clone();
            let socket = Arc::clone(&socket);

            let worker_result = thread::Builder::new()
                .name(format!("v_fs:{}:{}", self.tag, idx))
                .spawn(move || {
                    let mut worker = Worker::new(mem, queue, server, irq, socket, slot);
                    worker.run(evt, kill_evt, watch_resample_event)
                });

            if watch_resample_event {
                watch_resample_event = false;
            }

            match worker_result {
                Ok(worker) => self.workers.push((self_kill_evt, worker)),
                Err(e) => {
                    self.stop_workers();
                    return Err(e).context("failed to spawn virtio_fs worker");
                }
            }
        }
        Ok(())
    }

    fn get_device_bars(&mut self, address: PciAddress) -> Vec<PciBarConfiguration> {
        if self.fs.as_ref().map_or(false, |fs| !fs.cfg().use_dax) {
            return vec![];
        }

        self.pci_bar = Some(Alloc::PciBar {
            bus: address.bus,
            dev: address.dev,
            func: address.func,
            bar: FS_BAR_NUM,
        });

        vec![PciBarConfiguration::new(
            FS_BAR_NUM as usize,
            FS_BAR_SIZE,
            PciBarRegionType::Memory64BitRegion,
            PciBarPrefetchable::Prefetchable,
        )]
    }

    fn get_device_caps(&self) -> Vec<Box<dyn PciCapability>> {
        if self.fs.as_ref().map_or(false, |fs| !fs.cfg().use_dax) {
            return vec![];
        }

        vec![Box::new(VirtioPciShmCap::new(
            PciCapabilityType::SharedMemoryConfig,
            FS_BAR_NUM,
            FS_BAR_OFFSET,
            FS_BAR_SIZE,
            VIRTIO_FS_SHMCAP_ID_CACHE,
        ))]
    }
}

impl Suspendable for Fs {}

impl Drop for Fs {
    fn drop(&mut self) {
        self.stop_workers()
    }
}
