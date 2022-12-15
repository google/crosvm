// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;
use std::path::Path;
use std::path::PathBuf;

use anyhow::bail;
use anyhow::Context;
use base::get_max_open_files;
use base::RawDescriptor;
use cros_async::Executor;
use minijail::Minijail;

use crate::virtio::vhost::user::device::fs::FsBackend;
use crate::virtio::vhost::user::device::fs::Options;
use crate::virtio::vhost::user::device::handler::VhostUserBackend;
use crate::virtio::vhost::user::device::listener::sys::VhostUserListener;
use crate::virtio::vhost::user::device::listener::VhostUserListenerTrait;

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
    // vvu locks around 512k memory. Just give 1M.
    j.set_rlimit(libc::RLIMIT_MEMLOCK as i32, 1 << 20, 1 << 20)?;

    // Make sure there are no duplicates in keep_rds
    keep_rds.sort_unstable();
    keep_rds.dedup();

    let tz = std::env::var("TZ").unwrap_or_default();

    // fork on the jail here
    let pid = unsafe { j.fork(Some(&keep_rds))? };

    if pid > 0 {
        unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) };
    }

    if pid == 0 {
        // Preserve TZ for `chrono::Local` (b/257987535).
        std::env::set_var("TZ", tz);
    }

    if pid < 0 {
        bail!("Fork error! {}", std::io::Error::last_os_error());
    }

    Ok(pid)
}

/// Starts a vhost-user fs device.
/// Returns an error if the given `args` is invalid or the device fails to run.
pub fn start_device(opts: Options) -> anyhow::Result<()> {
    let ex = Executor::new().context("Failed to create executor")?;
    let fs_device = Box::new(FsBackend::new(&ex, &opts.tag)?);

    let mut keep_rds = fs_device.keep_rds.clone();
    let listener = VhostUserListener::new_from_socket_or_vfio(
        &opts.socket,
        &opts.vfio,
        fs_device.max_queue_num(),
        Some(&mut keep_rds),
    )?;

    base::syslog::push_descriptors(&mut keep_rds);

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
    ex.run_until(listener.run_backend(fs_device, &ex))?
}
