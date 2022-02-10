// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, bail, Context};
use argh::FromArgs;
use base::{error, get_max_open_files, warn, Event, RawDescriptor, Tube, UnlinkUnixListener};
use cros_async::{EventAsync, Executor};
use data_model::{DataInit, Le32};
use fuse::Server;
use futures::future::{AbortHandle, Abortable};
use hypervisor::ProtectionType;
use minijail::{self, Minijail};
use sync::Mutex;
use vm_memory::GuestMemory;
use vmm_vhost::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};

use crate::virtio;
use crate::virtio::copy_config;
use crate::virtio::fs::passthrough::PassthroughFs;
use crate::virtio::fs::{process_fs_queue, virtio_fs_config, FS_MAX_TAG_LEN};
use crate::virtio::vhost::user::device::handler::{
    DeviceRequestHandler, Doorbell, VhostUserBackend,
};

async fn handle_fs_queue(
    mut queue: virtio::Queue,
    mem: GuestMemory,
    doorbell: Arc<Mutex<Doorbell>>,
    kick_evt: EventAsync,
    server: Arc<fuse::Server<PassthroughFs>>,
    tube: Arc<Mutex<Tube>>,
) {
    // Slot is always going to be 0 because we do not support DAX
    let slot: u32 = 0;

    loop {
        if let Err(e) = kick_evt.next_val().await {
            error!("Failed to read kick event for fs queue: {}", e);
            break;
        }
        if let Err(e) = process_fs_queue(&mem, &doorbell, &mut queue, &server, &tube, slot) {
            error!("Process FS queue failed: {}", e);
            break;
        }
    }
}

fn default_uidmap() -> String {
    let euid = unsafe { libc::geteuid() };
    format!("{} {} 1", euid, euid)
}

fn default_gidmap() -> String {
    let egid = unsafe { libc::getegid() };
    format!("{} {} 1", egid, egid)
}

fn jail_and_fork(
    mut keep_rds: Vec<RawDescriptor>,
    dir_path: PathBuf,
    uid_map: Option<String>,
    gid_map: Option<String>,
) -> anyhow::Result<i32> {
    // Create new minijail sandbox
    let mut j = Minijail::new()?;

    j.namespace_pids();
    j.namespace_user();
    j.namespace_user_disable_setgroups();
    j.uidmap(&uid_map.unwrap_or_else(default_uidmap))?;
    j.gidmap(&gid_map.unwrap_or_else(default_gidmap))?;
    j.run_as_init();

    j.namespace_vfs();
    j.namespace_net();
    j.no_new_privs();

    // Only pivot_root if we are not re-using the current root directory.
    if dir_path != Path::new("/") {
        // It's safe to call `namespace_vfs` multiple times.
        j.namespace_vfs();
        j.enter_pivot_root(&dir_path)?;
    }
    j.set_remount_mode(libc::MS_SLAVE);

    let limit = get_max_open_files().context("failed to get max open files")?;
    j.set_rlimit(libc::RLIMIT_NOFILE as i32, limit, limit)?;

    // Make sure there are no duplicates in keep_rds
    keep_rds.dedup();

    // fork on the jail here
    let pid = unsafe { j.fork(Some(&keep_rds))? };

    if pid > 0 {
        unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) };
    }

    if pid < 0 {
        bail!("Fork error! {}", std::io::Error::last_os_error());
    }

    Ok(pid)
}

struct FsBackend {
    ex: Executor,
    server: Arc<fuse::Server<PassthroughFs>>,
    tag: [u8; FS_MAX_TAG_LEN],
    avail_features: u64,
    acked_features: u64,
    acked_protocol_features: VhostUserProtocolFeatures,
    workers: [Option<AbortHandle>; Self::MAX_QUEUE_NUM],
    keep_rds: Vec<RawDescriptor>,
}

impl FsBackend {
    pub fn new(ex: &Executor, tag: &str) -> anyhow::Result<Self> {
        if tag.len() > FS_MAX_TAG_LEN {
            bail!(
                "fs tag is too long: {} (max supported: {})",
                tag.len(),
                FS_MAX_TAG_LEN
            );
        }
        let mut fs_tag = [0u8; FS_MAX_TAG_LEN];
        fs_tag[..tag.len()].copy_from_slice(tag.as_bytes());

        let avail_features = virtio::base_features(ProtectionType::Unprotected)
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();

        // Use default passthroughfs config
        let fs = PassthroughFs::new(Default::default())?;

        let mut keep_rds: Vec<RawDescriptor> = [0, 1, 2].to_vec();
        keep_rds.append(&mut fs.keep_rds());

        let server = Arc::new(Server::new(fs));

        Ok(FsBackend {
            ex: ex.clone(),
            server,
            tag: fs_tag,
            avail_features,
            acked_features: 0,
            acked_protocol_features: VhostUserProtocolFeatures::empty(),
            workers: Default::default(),
            keep_rds,
        })
    }
}

impl VhostUserBackend for FsBackend {
    const MAX_QUEUE_NUM: usize = 2; /* worker queue and high priority queue */
    const MAX_VRING_LEN: u16 = 1024;

    type Error = anyhow::Error;

    fn features(&self) -> u64 {
        self.avail_features
    }

    fn ack_features(&mut self, value: u64) -> anyhow::Result<()> {
        let unrequested_features = value & !self.avail_features;
        if unrequested_features != 0 {
            bail!("invalid features are given: {:#x}", unrequested_features);
        }

        self.acked_features |= value;

        Ok(())
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::CONFIG | VhostUserProtocolFeatures::MQ
    }

    fn ack_protocol_features(&mut self, features: u64) -> anyhow::Result<()> {
        let features = VhostUserProtocolFeatures::from_bits(features)
            .ok_or_else(|| anyhow!("invalid protocol features are given: {:#x}", features))?;
        let supported = self.protocol_features();
        self.acked_protocol_features = features & supported;
        Ok(())
    }

    fn acked_protocol_features(&self) -> u64 {
        self.acked_protocol_features.bits()
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let config = virtio_fs_config {
            tag: self.tag,
            num_request_queues: Le32::from(1),
        };
        copy_config(data, 0, config.as_slice(), offset);
    }

    fn reset(&mut self) {
        for handle in self.workers.iter_mut().filter_map(Option::take) {
            handle.abort();
        }
    }

    fn start_queue(
        &mut self,
        idx: usize,
        mut queue: virtio::Queue,
        mem: GuestMemory,
        doorbell: Arc<Mutex<Doorbell>>,
        kick_evt: Event,
    ) -> anyhow::Result<()> {
        if let Some(handle) = self.workers.get_mut(idx).and_then(Option::take) {
            warn!("Starting new queue handler without stopping old handler");
            handle.abort();
        }

        // Enable any virtqueue features that were negotiated (like VIRTIO_RING_F_EVENT_IDX).
        queue.ack_features(self.acked_features);

        let kick_evt = EventAsync::new(kick_evt.0, &self.ex)
            .context("failed to create EventAsync for kick_evt")?;
        let (handle, registration) = AbortHandle::new_pair();
        let (_, fs_device_tube) = Tube::pair()?;

        self.ex
            .spawn_local(Abortable::new(
                handle_fs_queue(
                    queue,
                    mem,
                    doorbell,
                    kick_evt,
                    self.server.clone(),
                    Arc::new(Mutex::new(fs_device_tube)),
                ),
                registration,
            ))
            .detach();

        self.workers[idx] = Some(handle);
        Ok(())
    }

    fn stop_queue(&mut self, idx: usize) {
        if let Some(handle) = self.workers.get_mut(idx).and_then(Option::take) {
            handle.abort();
        }
    }
}

#[derive(FromArgs)]
#[argh(description = "")]
struct Options {
    #[argh(option, description = "path to a socket", arg_name = "PATH")]
    socket: String,
    #[argh(option, description = "the virtio-fs tag", arg_name = "TAG")]
    tag: String,
    #[argh(option, description = "path to a directory to share", arg_name = "DIR")]
    shared_dir: PathBuf,
    #[argh(option, description = "uid map to use", arg_name = "UIDMAP")]
    uid_map: Option<String>,
    #[argh(option, description = "gid map to use", arg_name = "GIDMAP")]
    gid_map: Option<String>,
}

/// Starts a vhost-user fs device.
/// Returns an error if the given `args` is invalid or the device fails to run.
pub fn run_fs_device(program_name: &str, args: &[&str]) -> anyhow::Result<()> {
    let opts = match Options::from_args(&[program_name], args) {
        Ok(opts) => opts,
        Err(e) => {
            if e.status.is_err() {
                bail!(e.output);
            } else {
                println!("{}", e.output);
            }
            return Ok(());
        }
    };

    base::syslog::init().context("Failed to initialize syslog")?;

    let ex = Executor::new().context("Failed to create executor")?;
    let fs_device = FsBackend::new(&ex, &opts.tag)?;

    // Create and bind unix socket
    let listener = UnixListener::bind(opts.socket).map(UnlinkUnixListener)?;
    let mut keep_rds = fs_device.keep_rds.clone();
    keep_rds.push(listener.as_raw_fd());
    base::syslog::push_descriptors(&mut keep_rds);

    let handler = DeviceRequestHandler::new(fs_device);

    let pid = jail_and_fork(keep_rds, opts.shared_dir, opts.uid_map, opts.gid_map)?;

    // Parent, nothing to do but wait and then exit
    if pid != 0 {
        unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
        return Ok(());
    }

    // We need to set the no setuid fixup secure bit so that we don't drop capabilities when
    // changing the thread uid/gid. Without this, creating new entries can fail in some corner
    // cases.
    const SECBIT_NO_SETUID_FIXUP: i32 = 1 << 2;
    // TODO(crbug.com/1199487): Remove this once libc provides the wrapper for all targets.
    #[cfg(target_os = "linux")]
    {
        // Safe because this doesn't modify any memory and we check the return value.
        let mut securebits = unsafe { libc::prctl(libc::PR_GET_SECUREBITS) };
        if securebits < 0 {
            bail!(io::Error::last_os_error());
        }
        securebits |= SECBIT_NO_SETUID_FIXUP;
        // Safe because this doesn't modify any memory and we check the return value.
        let ret = unsafe { libc::prctl(libc::PR_SET_SECUREBITS, securebits) };
        if ret < 0 {
            bail!(io::Error::last_os_error());
        }
    }

    // run_until() returns an Result<Result<..>> which the ? operator lets us flatten.
    ex.run_until(handler.run_with_listener(listener, &ex))?
}
