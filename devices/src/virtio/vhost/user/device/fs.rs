// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod sys;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::bail;
use argh::FromArgs;
use base::error;
use base::warn;
use base::RawDescriptor;
use base::Tube;
use base::WorkerThread;
use data_model::Le32;
use fuse::Server;
use hypervisor::ProtectionType;
use snapshot::AnySnapshot;
use sync::Mutex;
pub use sys::start_device as run_fs_device;
use virtio_sys::virtio_fs::virtio_fs_config;
use vm_memory::GuestMemory;
use vmm_vhost::message::VhostUserProtocolFeatures;
use vmm_vhost::VHOST_USER_F_PROTOCOL_FEATURES;
use zerocopy::IntoBytes;

use crate::virtio;
use crate::virtio::copy_config;
use crate::virtio::device_constants::fs::FS_MAX_TAG_LEN;
use crate::virtio::fs::passthrough::PassthroughFs;
use crate::virtio::fs::Config;
use crate::virtio::fs::Worker;
use crate::virtio::vhost::user::device::handler::Error as DeviceError;
use crate::virtio::vhost::user::device::handler::VhostUserDevice;
use crate::virtio::Queue;

const MAX_QUEUE_NUM: usize = 2; /* worker queue and high priority queue */

struct FsBackend {
    server: Arc<fuse::Server<PassthroughFs>>,
    tag: String,
    avail_features: u64,
    workers: BTreeMap<usize, WorkerThread<Queue>>,
    keep_rds: Vec<RawDescriptor>,
}

impl FsBackend {
    #[allow(unused_variables)]
    pub fn new(
        tag: &str,
        shared_dir: &str,
        skip_pivot_root: bool,
        cfg: Option<Config>,
    ) -> anyhow::Result<Self> {
        if tag.len() > FS_MAX_TAG_LEN {
            bail!(
                "fs tag is too long: {} (max supported: {})",
                tag.len(),
                FS_MAX_TAG_LEN
            );
        }

        let avail_features = virtio::base_features(ProtectionType::Unprotected)
            | 1 << VHOST_USER_F_PROTOCOL_FEATURES;

        // Use default passthroughfs config
        #[allow(unused_mut)]
        let mut fs = PassthroughFs::new(tag, cfg.unwrap_or_default())?;
        #[cfg(feature = "fs_runtime_ugid_map")]
        if skip_pivot_root {
            fs.set_root_dir(shared_dir.to_string())?;
        }

        let mut keep_rds: Vec<RawDescriptor> = [0, 1, 2].to_vec();
        keep_rds.append(&mut fs.keep_rds());

        let server = Arc::new(Server::new(fs));

        Ok(FsBackend {
            server,
            tag: tag.to_owned(),
            avail_features,
            workers: Default::default(),
            keep_rds,
        })
    }
}

impl VhostUserDevice for FsBackend {
    fn max_queue_num(&self) -> usize {
        MAX_QUEUE_NUM
    }

    fn features(&self) -> u64 {
        self.avail_features
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::CONFIG | VhostUserProtocolFeatures::MQ
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let mut config = virtio_fs_config {
            tag: [0; FS_MAX_TAG_LEN],
            num_request_queues: Le32::from(1),
        };
        config.tag[..self.tag.len()].copy_from_slice(self.tag.as_bytes());
        copy_config(data, 0, config.as_bytes(), offset);
    }

    fn reset(&mut self) {
        for worker in std::mem::take(&mut self.workers).into_values() {
            let _ = worker.stop();
        }
    }

    fn start_queue(
        &mut self,
        idx: usize,
        queue: virtio::Queue,
        _mem: GuestMemory,
    ) -> anyhow::Result<()> {
        if self.workers.contains_key(&idx) {
            warn!("Starting new queue handler without stopping old handler");
            self.stop_queue(idx)?;
        }

        let (_, fs_device_tube) = Tube::pair()?;
        let tube = Arc::new(Mutex::new(fs_device_tube));

        let server = self.server.clone();

        // Slot is always going to be 0 because we do not support DAX
        let slot: u32 = 0;

        let worker = WorkerThread::start(format!("v_fs:{}:{}", self.tag, idx), move |kill_evt| {
            let mut worker = Worker::new(queue, server, tube, slot);
            if let Err(e) = worker.run(kill_evt) {
                error!("vhost-user-fs worker failed: {e:#}");
            }
            worker.queue
        });
        self.workers.insert(idx, worker);

        Ok(())
    }

    fn stop_queue(&mut self, idx: usize) -> anyhow::Result<virtio::Queue> {
        if let Some(worker) = self.workers.remove(&idx) {
            let queue = worker.stop();
            Ok(queue)
        } else {
            Err(anyhow::Error::new(DeviceError::WorkerNotFound))
        }
    }

    fn enter_suspended_state(&mut self) -> anyhow::Result<()> {
        // No non-queue workers.
        Ok(())
    }

    fn snapshot(&mut self) -> anyhow::Result<AnySnapshot> {
        bail!("snapshot not implemented for vhost-user fs");
    }

    fn restore(&mut self, _data: AnySnapshot) -> anyhow::Result<()> {
        bail!("snapshot not implemented for vhost-user fs");
    }
}

#[derive(FromArgs)]
#[argh(subcommand, name = "fs")]
/// FS Device
pub struct Options {
    #[argh(option, arg_name = "PATH", hidden_help)]
    /// deprecated - please use --socket-path instead
    socket: Option<String>,
    #[argh(option, arg_name = "PATH")]
    /// path to the vhost-user socket to bind to.
    /// If this flag is set, --fd cannot be specified.
    socket_path: Option<String>,
    #[argh(option, arg_name = "FD")]
    /// file descriptor of a connected vhost-user socket.
    /// If this flag is set, --socket-path cannot be specified.
    fd: Option<RawDescriptor>,

    #[argh(option, arg_name = "TAG")]
    /// the virtio-fs tag
    tag: String,
    #[argh(option, arg_name = "DIR")]
    /// path to a directory to share
    shared_dir: PathBuf,
    #[argh(option, arg_name = "UIDMAP")]
    /// uid map to use
    uid_map: Option<String>,
    #[argh(option, arg_name = "GIDMAP")]
    /// gid map to use
    gid_map: Option<String>,
    #[argh(option, arg_name = "CFG")]
    /// colon-separated options for configuring a directory to be
    /// shared with the VM through virtio-fs. The format is the same as
    /// `crosvm run --shared-dir` flag except only the keys related to virtio-fs
    /// are valid here.
    cfg: Option<Config>,
    #[argh(option, arg_name = "UID", default = "0")]
    /// uid of the device process in the new user namespace created by minijail.
    /// These two options (uid/gid) are useful when the crosvm process cannot
    /// get CAP_SETGID/CAP_SETUID but an identity mapping of the current
    /// user/group between the VM and the host is required.
    /// Say the current user and the crosvm process has uid 5000, a user can use
    /// "uid=5000" and "uidmap=5000 5000 1" such that files owned by user 5000
    /// still appear to be owned by user 5000 in the VM. These 2 options are
    /// useful only when there is 1 user in the VM accessing shared files.
    /// If multiple users want to access the shared file, gid/uid options are
    /// useless. It'd be better to create a new user namespace and give
    /// CAP_SETUID/CAP_SETGID to the crosvm.
    /// Default: 0.
    uid: u32,
    #[argh(option, arg_name = "GID", default = "0")]
    /// gid of the device process in the new user namespace created by minijail.
    /// Default: 0.
    gid: u32,
    #[argh(switch)]
    /// disable-sandbox controls whether vhost-user-fs device uses minijail sandbox.
    /// By default, it is false, the vhost-user-fs will enter new mnt/user/pid/net
    /// namespace. If the this option is true, the vhost-user-fs device only create
    /// a new mount namespace and run without seccomp filter.
    /// Default: false.
    disable_sandbox: bool,
    #[argh(option, arg_name = "skip_pivot_root", default = "false")]
    /// disable pivot_root when process is jailed.
    ///
    /// virtio-fs typically uses mount namespaces and pivot_root for file system isolation,
    /// making the jailed process's root directory "/".
    ///
    /// Android's security model restricts crosvm's access to certain system capabilities,
    /// specifically those related to managing mount namespaces and using pivot_root.
    /// These capabilities are typically associated with the SYS_ADMIN capability.
    /// To maintain a secure environment, Android relies on mechanisms like SELinux to
    /// enforce isolation and control access to directories.
    #[allow(dead_code)]
    skip_pivot_root: bool,
}
