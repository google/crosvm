// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::path::Path;
use std::path::PathBuf;

use anyhow::bail;
use anyhow::Context;
use base::linux::max_open_files;
use base::AsRawDescriptor;
use base::AsRawDescriptors;
use base::RawDescriptor;
use cros_async::Executor;
use jail::create_base_minijail;
use jail::create_base_minijail_without_pivot_root;
use minijail::Minijail;

use crate::virtio::vhost::user::device::fs::FsBackend;
use crate::virtio::vhost::user::device::fs::Options;
use crate::virtio::vhost::user::device::BackendConnection;

fn default_uidmap() -> String {
    // SAFETY: trivially safe
    let euid = unsafe { libc::geteuid() };
    format!("{} {} 1", euid, euid)
}

fn default_gidmap() -> String {
    // SAFETY: trivially safe
    let egid = unsafe { libc::getegid() };
    format!("{} {} 1", egid, egid)
}

#[allow(clippy::unnecessary_cast)]
fn jail_and_fork(
    mut keep_rds: Vec<RawDescriptor>,
    dir_path: PathBuf,
    uid: u32,
    gid: u32,
    uid_map: Option<String>,
    gid_map: Option<String>,
    disable_sandbox: bool,
    pivot_root: bool,
) -> anyhow::Result<i32> {
    let limit = max_open_files()
        .context("failed to get max open files")?
        .rlim_max;
    // Create new minijail sandbox
    let jail = if disable_sandbox {
        if pivot_root {
            create_base_minijail(dir_path.as_path(), limit)
        } else {
            create_base_minijail_without_pivot_root(dir_path.as_path(), limit)
        }?
    } else {
        let mut j: Minijail = Minijail::new()?;
        j.namespace_pids();
        j.namespace_user();
        j.namespace_user_disable_setgroups();
        if uid != 0 {
            j.change_uid(uid);
        }
        if gid != 0 {
            j.change_gid(gid);
        }
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

        j.set_rlimit(libc::RLIMIT_NOFILE as i32, limit, limit)?;
        // vvu locks around 512k memory. Just give 1M.
        j.set_rlimit(libc::RLIMIT_MEMLOCK as i32, 1 << 20, 1 << 20)?;
        #[cfg(not(feature = "seccomp_trace"))]
        jail::set_embedded_bpf_program(&mut j, "fs_device_vhost_user")?;
        j.use_seccomp_filter();
        j
    };

    // Make sure there are no duplicates in keep_rds
    keep_rds.sort_unstable();
    keep_rds.dedup();

    // fork on the jail here
    // SAFETY: trivially safe
    let pid = unsafe { jail.fork(Some(&keep_rds))? };

    if pid > 0 {
        // Current FS driver jail does not use seccomp and jail_and_fork() does not have other
        // users, so we do nothing here for seccomp_trace
        // SAFETY: trivially safe
        unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) };
    }

    if pid < 0 {
        bail!("Fork error! {}", std::io::Error::last_os_error());
    }

    Ok(pid)
}

/// Starts a vhost-user fs device.
/// Returns an error if the given `args` is invalid or the device fails to run.
#[allow(unused_mut)]
pub fn start_device(mut opts: Options) -> anyhow::Result<()> {
    #[allow(unused_mut)]
    let mut is_pivot_root_required = true;
    #[cfg(feature = "fs_runtime_ugid_map")]
    if let Some(ref mut cfg) = opts.cfg {
        if !cfg.ugid_map.is_empty() && (!opts.disable_sandbox || !opts.skip_pivot_root) {
            bail!("uid_gid_map can only be set with disable sandbox and skip_pivot_root option");
        }

        if opts.skip_pivot_root {
            is_pivot_root_required = false;
        }
    }
    let ex = Executor::new().context("Failed to create executor")?;
    let fs_device = FsBackend::new(
        &opts.tag,
        opts.shared_dir
            .to_str()
            .expect("Failed to convert opts.shared_dir to str()"),
        opts.skip_pivot_root,
        opts.cfg,
    )?;

    let mut keep_rds = fs_device.keep_rds.clone();
    keep_rds.append(&mut ex.as_raw_descriptors());

    let conn =
        BackendConnection::from_opts(opts.socket.as_deref(), opts.socket_path.as_deref(), opts.fd)?;
    keep_rds.push(conn.as_raw_descriptor());

    base::syslog::push_descriptors(&mut keep_rds);
    cros_tracing::push_descriptors!(&mut keep_rds);
    metrics::push_descriptors(&mut keep_rds);
    let pid = jail_and_fork(
        keep_rds,
        opts.shared_dir,
        opts.uid,
        opts.gid,
        opts.uid_map,
        opts.gid_map,
        opts.disable_sandbox,
        is_pivot_root_required,
    )?;

    // Parent, nothing to do but wait and then exit
    if pid != 0 {
        // SAFETY: trivially safe
        unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
        return Ok(());
    }

    // run_until() returns an Result<Result<..>> which the ? operator lets us flatten.
    ex.run_until(conn.run_backend(fs_device, &ex))?
}
