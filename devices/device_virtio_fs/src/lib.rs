// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(any(target_os = "android", target_os = "linux"))]

mod allowlist;
#[cfg(feature = "arc_quota")]
mod arc_ioctl;
mod caps;
pub mod config;
mod expiring_map;
mod multikey;
pub mod passthrough;
mod read_dir;
pub mod vhost_user;
mod worker;

use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

pub use allowlist::PathAllowlist;
use anyhow::anyhow;
use anyhow::Context;
use base::error;
use base::warn;
use base::AsRawDescriptor;
use base::Error as SysError;
use base::RawDescriptor;
use base::Tube;
use base::WorkerThread;
pub use config::CachePolicy;
pub use config::Config;
use data_model::Le32;
use devices::virtio::copy_config;
use devices::virtio::device_constants::fs::FS_MAX_TAG_LEN;
use devices::virtio::DeviceType;
use devices::virtio::Interrupt;
use devices::virtio::PciCapabilityType;
use devices::virtio::Queue;
use devices::virtio::VirtioDevice;
use devices::virtio::VirtioPciShmCap;
use devices::PciAddress;
use devices::PciBarConfiguration;
use devices::PciBarPrefetchable;
use devices::PciBarRegionType;
use devices::PciCapability;
use devices::VirtioDeviceArgs;
use devices::VirtioDeviceModule;
use fuse::Server;
pub use passthrough::PassthroughFs;
use remain::sorted;
use resources::Alloc;
use serde::Deserialize;
use serde::Serialize;
use sync::Mutex;
use thiserror::Error;
pub use vhost_user::run_fs_device;
pub use vhost_user::Options as FsOptions;
use virtio_sys::virtio_fs::virtio_fs_config;
use virtio_sys::virtio_fs::VIRTIO_FS_SHMCAP_ID_CACHE;
use vm_control::AnyControlTube;
use vm_control::FsMappingRequest;
use vm_control::VmResponse;
use vm_memory::GuestMemory;
pub use worker::Worker;
use zerocopy::IntoBytes;

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
    #[error("Fs device tag is too long: len = {0}, max = {FS_MAX_TAG_LEN}")]
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
    use_dax: bool,
    pci_bar: Option<Alloc>,
    tube: Option<Tube>,
    workers: Vec<WorkerThread<()>>,
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

        // TODO(b/176129399): Remove cfg! once DAX is supported on ARM.
        let use_dax = cfg!(target_arch = "x86_64") && fs.cfg().use_dax;

        Ok(Fs {
            cfg,
            tag: tag.to_string(),
            fs: Some(fs),
            queue_sizes: vec![QUEUE_SIZE; num_queues].into_boxed_slice(),
            avail_features: base_features,
            acked_features: 0,
            use_dax,
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
        _interrupt: Interrupt,
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

        let server = Arc::new(Server::new(fs));
        let socket = self.tube.take().expect("missing mapping socket");
        let mut slot = 0;

        // Set up shared memory for DAX.
        if let Some(pci_bar) = self.pci_bar {
            // Create the shared memory region now before we start processing requests.
            let request = FsMappingRequest::AllocateSharedMemoryRegion(pci_bar);
            socket
                .send(&request)
                .expect("failed to send allocation message");
            slot = match socket.recv() {
                Ok(VmResponse::RegisterMemory { slot }) => slot,
                Ok(VmResponse::Err(e)) => panic!("failed to allocate shared memory region: {e}"),
                r => panic!("unexpected response to allocate shared memory region: {r:?}"),
            };
        }

        let socket = Arc::new(Mutex::new(socket));

        self.workers = queues
            .into_iter()
            .map(|(idx, queue)| {
                let server = server.clone();
                let socket = Arc::clone(&socket);

                WorkerThread::start(format!("v_fs:{}:{}", self.tag, idx), move |kill_evt| {
                    let mut worker = Worker::new(queue, server, socket, slot);
                    if let Err(e) = worker.run(kill_evt) {
                        error!("virtio-fs worker failed: {e:#}");
                    }
                })
            })
            .collect();
        Ok(())
    }

    fn get_device_bars(&mut self, address: PciAddress) -> Vec<PciBarConfiguration> {
        if !self.use_dax {
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
        if !self.use_dax {
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VirtioFsModule {
    pub src: PathBuf,
    pub tag: String,
    pub ugid: (Option<u32>, Option<u32>),
    pub uid_map: String,
    pub gid_map: String,
    pub cfg: Config,
}

impl VirtioDeviceModule for VirtioFsModule {
    fn sort_name(&self) -> &'static str {
        "fs"
    }

    fn create(&self, cx: &mut VirtioDeviceArgs<'_>) -> anyhow::Result<Box<dyn VirtioDevice>> {
        let (host_tube, device_tube) = Tube::pair().context("failed to create tube")?;
        (cx.add_control_tube)(AnyControlTube::Fs(host_tube));

        let features = devices::virtio::base_features(cx.protection_type);
        // TODO(chirantan): Use more than one worker once the kernel driver has been fixed to not
        // panic when num_queues > 1.
        let dev = Fs::new(features, &self.tag, 1, self.cfg.clone(), device_tube)
            .context("failed to create fs device")?;

        Ok(Box::new(dev))
    }

    #[cfg(any(target_os = "android", target_os = "linux"))]
    fn create_jail(
        &self,
        jail_config: Option<&jail::JailConfig>,
    ) -> anyhow::Result<Option<minijail::Minijail>> {
        let max_open_files = base::linux::max_open_files()
            .context("failed to get max number of open files")?
            .rlim_max;
        let jail = if let Some(jail_config) = jail_config {
            let mut config = jail::SandboxConfig::new(jail_config, "fs_device");
            config.limit_caps = false;
            config.ugid_map = Some((&self.uid_map, &self.gid_map));
            // We want bind mounts from the parent namespaces to propagate into the fs device's
            // namespace.
            config.remount_mode = Some(libc::MS_SLAVE);
            config.run_as = if self.ugid == (None, None) {
                jail::RunAsUser::Unspecified
            } else {
                jail::RunAsUser::Specified(self.ugid.0.unwrap_or(0), self.ugid.1.unwrap_or(0))
            };
            jail::create_sandbox_minijail(&self.src, max_open_files, &config)?
        } else {
            jail::create_base_minijail(&self.src, max_open_files)?
        };
        Ok(Some(jail))
    }
}
