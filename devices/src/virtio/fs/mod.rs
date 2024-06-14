// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::io;
use std::sync::Arc;

use anyhow::anyhow;
use base::error;
use base::warn;
use base::AsRawDescriptor;
use base::Error as SysError;
use base::RawDescriptor;
use base::Tube;
use base::WorkerThread;
use data_model::Le32;
use remain::sorted;
use resources::Alloc;
use sync::Mutex;
use thiserror::Error;
use virtio_sys::virtio_fs::virtio_fs_config;
use virtio_sys::virtio_fs::VIRTIO_FS_SHMCAP_ID_CACHE;
use vm_control::FsMappingRequest;
use vm_control::VmResponse;
use vm_memory::GuestMemory;
use zerocopy::AsBytes;

use crate::pci::PciAddress;
use crate::pci::PciBarConfiguration;
use crate::pci::PciBarPrefetchable;
use crate::pci::PciBarRegionType;
use crate::pci::PciCapability;
use crate::virtio::copy_config;
use crate::virtio::device_constants::fs::FS_MAX_TAG_LEN;
use crate::virtio::DeviceType;
use crate::virtio::Interrupt;
use crate::virtio::PciCapabilityType;
use crate::virtio::Queue;
use crate::virtio::VirtioDevice;
use crate::virtio::VirtioPciShmCap;

#[cfg(feature = "arc_quota")]
mod arc_ioctl;
mod caps;
mod config;
mod expiring_map;
mod multikey;
pub mod passthrough;
mod read_dir;
mod worker;

pub use config::CachePolicy;
pub use config::Config;
use fuse::Server;
use passthrough::PassthroughFs;
pub use worker::process_fs_queue;
use worker::Worker;

const QUEUE_SIZE: u16 = 1024;

const FS_BAR_NUM: u8 = 4;
const FS_BAR_OFFSET: u64 = 0;
const FS_BAR_SIZE: u64 = 1 << 33;

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
    /// Failed to get the uids for the worker thread.
    #[error("failed to get uids for the worker thread: {0}")]
    GetResuid(SysError),
    /// Failed to get the securebits for the worker thread.
    #[error("failed to get securebits for the worker thread: {0}")]
    GetSecurebits(SysError),
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
    workers: Vec<WorkerThread<Result<()>>>,
}

impl Fs {
    pub fn new(
        base_features: u64,
        tag: &str,
        num_workers: usize,
        fs_cfg: Config,
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

        let fs = PassthroughFs::new(tag, fs_cfg).map_err(Error::CreateFs)?;

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
}

impl VirtioDevice for Fs {
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        let mut fds = self
            .fs
            .as_ref()
            .map(PassthroughFs::keep_rds)
            .unwrap_or_default();
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
        copy_config(data, 0, self.cfg.as_bytes(), offset)
    }

    fn activate(
        &mut self,
        _guest_mem: GuestMemory,
        interrupt: Interrupt,
        queues: BTreeMap<usize, Queue>,
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
        if cfg!(target_arch = "x86_64") && use_dax {
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

        self.workers = queues
            .into_iter()
            .map(|(idx, queue)| {
                let server = server.clone();
                let irq = interrupt.clone();
                let socket = Arc::clone(&socket);

                let worker =
                    WorkerThread::start(format!("v_fs:{}:{}", self.tag, idx), move |kill_evt| {
                        let mut worker = Worker::new(queue, server, irq, socket, slot);
                        worker.run(kill_evt, watch_resample_event)
                    });

                if watch_resample_event {
                    watch_resample_event = false;
                }

                worker
            })
            .collect();
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
            VIRTIO_FS_SHMCAP_ID_CACHE as u8,
        ))]
    }
}
