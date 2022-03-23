// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::path::{Path, PathBuf};
use std::str;

use libc::{self, c_ulong, gid_t, uid_t};

use anyhow::{bail, Context, Result};
use base::*;
use minijail::{self, Minijail};

use crate::JailConfig;

pub(super) struct SandboxConfig<'a> {
    pub(super) limit_caps: bool,
    pub(super) log_failures: bool,
    pub(super) seccomp_policy: &'a Path,
    pub(super) uid_map: Option<&'a str>,
    pub(super) gid_map: Option<&'a str>,
    pub(super) remount_mode: Option<c_ulong>,
}

pub(crate) struct ScopedMinijail(pub Minijail);

impl Drop for ScopedMinijail {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

pub(super) fn create_base_minijail(
    root: &Path,
    r_limit: Option<u64>,
    config: Option<&SandboxConfig>,
) -> Result<Minijail> {
    // All child jails run in a new user namespace without any users mapped,
    // they run as nobody unless otherwise configured.
    let mut j = Minijail::new().context("failed to jail device")?;

    if let Some(config) = config {
        j.namespace_pids();
        j.namespace_user();
        j.namespace_user_disable_setgroups();
        if config.limit_caps {
            // Don't need any capabilities.
            j.use_caps(0);
        }
        if let Some(uid_map) = config.uid_map {
            j.uidmap(uid_map).context("error setting UID map")?;
        }
        if let Some(gid_map) = config.gid_map {
            j.gidmap(gid_map).context("error setting GID map")?;
        }
        // Run in a new mount namespace.
        j.namespace_vfs();

        // Run in an empty network namespace.
        j.namespace_net();

        // Don't allow the device to gain new privileges.
        j.no_new_privs();

        // By default we'll prioritize using the pre-compiled .bpf over the .policy
        // file (the .bpf is expected to be compiled using "trap" as the failure
        // behavior instead of the default "kill" behavior).
        // Refer to the code comment for the "seccomp-log-failures"
        // command-line parameter for an explanation about why the |log_failures|
        // flag forces the use of .policy files (and the build-time alternative to
        // this run-time flag).
        let bpf_policy_file = config.seccomp_policy.with_extension("bpf");
        if bpf_policy_file.exists() && !config.log_failures {
            j.parse_seccomp_program(&bpf_policy_file)
                .context("failed to parse precompiled seccomp policy")?;
        } else {
            // Use TSYNC only for the side effect of it using SECCOMP_RET_TRAP,
            // which will correctly kill the entire device process if a worker
            // thread commits a seccomp violation.
            j.set_seccomp_filter_tsync();
            if config.log_failures {
                j.log_seccomp_filter_failures();
            }
            j.parse_seccomp_filters(&config.seccomp_policy.with_extension("policy"))
                .context("failed to parse seccomp policy")?;
        }
        j.use_seccomp_filter();
        // Don't do init setup.
        j.run_as_init();
        // Set up requested remount mode instead of default MS_PRIVATE.
        if let Some(mode) = config.remount_mode {
            j.set_remount_mode(mode);
        }
    }

    // Only pivot_root if we are not re-using the current root directory.
    if root != Path::new("/") {
        // It's safe to call `namespace_vfs` multiple times.
        j.namespace_vfs();
        j.enter_pivot_root(root)
            .context("failed to pivot root device")?;
    }

    // Most devices don't need to open many fds.
    let limit = if let Some(r) = r_limit { r } else { 1024u64 };
    j.set_rlimit(libc::RLIMIT_NOFILE as i32, limit, limit)
        .context("error setting max open files")?;

    Ok(j)
}

pub(super) fn simple_jail(
    jail_config: &Option<JailConfig>,
    policy: &str,
) -> Result<Option<Minijail>> {
    if let Some(jail_config) = jail_config {
        // A directory for a jailed device's pivot root.
        if !jail_config.pivot_root.exists() {
            bail!(
                "{:?} doesn't exist, can't jail devices",
                jail_config.pivot_root
            );
        }
        let policy_path: PathBuf = jail_config.seccomp_policy_dir.join(policy);
        let config = SandboxConfig {
            limit_caps: true,
            log_failures: jail_config.seccomp_log_failures,
            seccomp_policy: &policy_path,
            uid_map: None,
            gid_map: None,
            remount_mode: None,
        };
        Ok(Some(create_base_minijail(
            &jail_config.pivot_root,
            None,
            Some(&config),
        )?))
    } else {
        Ok(None)
    }
}

/// Mirror-mount all the directories in `dirs` into `jail` on a best-effort basis.
///
/// This function will not return an error if any of the directories in `dirs` is missing.
#[cfg(any(feature = "gpu", feature = "video-decoder", feature = "video-encoder"))]
pub(super) fn jail_mount_bind_if_exists<P: AsRef<std::ffi::OsStr>>(
    jail: &mut Minijail,
    dirs: &[P],
) -> Result<()> {
    for dir in dirs {
        let dir_path = Path::new(dir);
        if dir_path.exists() {
            jail.mount_bind(dir_path, dir_path, false)?;
        }
    }

    Ok(())
}

#[derive(Copy, Clone)]
#[cfg_attr(not(feature = "tpm"), allow(dead_code))]
pub(super) struct Ids {
    pub(super) uid: uid_t,
    pub(super) gid: gid_t,
}

#[cfg(feature = "gpu")]
pub(super) fn add_current_user_as_root_to_jail(jail: &mut Minijail) -> Result<Ids> {
    let crosvm_uid = geteuid();
    let crosvm_gid = getegid();
    jail.uidmap(&format!("0 {0} 1", crosvm_uid))
        .context("error setting UID map")?;
    jail.gidmap(&format!("0 {0} 1", crosvm_gid))
        .context("error setting GID map")?;

    Ok(Ids {
        uid: crosvm_uid,
        gid: crosvm_gid,
    })
}

/// Set the uid/gid for the jailed process and give a basic id map. This is
/// required for bind mounts to work.
pub(super) fn add_current_user_to_jail(jail: &mut Minijail) -> Result<Ids> {
    let crosvm_uid = geteuid();
    let crosvm_gid = getegid();

    jail.uidmap(&format!("{0} {0} 1", crosvm_uid))
        .context("error setting UID map")?;
    jail.gidmap(&format!("{0} {0} 1", crosvm_gid))
        .context("error setting GID map")?;

    if crosvm_uid != 0 {
        jail.change_uid(crosvm_uid);
    }
    if crosvm_gid != 0 {
        jail.change_gid(crosvm_gid);
    }

    Ok(Ids {
        uid: crosvm_uid,
        gid: crosvm_gid,
    })
}
