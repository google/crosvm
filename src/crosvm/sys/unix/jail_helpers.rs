// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::path::Path;
use std::str;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use base::*;
use libc::c_ulong;
use libc::gid_t;
use libc::uid_t;
use minijail::Minijail;
use once_cell::sync::Lazy;

use crate::crosvm::config::JailConfig;

pub static EMBEDDED_BPFS: Lazy<std::collections::HashMap<&str, Vec<u8>>> =
    Lazy::new(|| include!(concat!(env!("OUT_DIR"), "/bpf_includes.in")));

pub(super) struct SandboxConfig<'a> {
    pub(super) limit_caps: bool,
    pub(super) log_failures: bool,
    pub(super) seccomp_policy_path: Option<&'a Path>,
    pub(super) seccomp_policy_name: &'a str,
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

        if let Some(seccomp_policy_path) = config.seccomp_policy_path {
            // By default we'll prioritize using the pre-compiled .bpf over the
            // .policy file (the .bpf is expected to be compiled using "trap" as the
            // failure behavior instead of the default "kill" behavior) when a policy
            // path is supplied in the command line arugments. Otherwise the built-in
            // pre-compiled policies will be used.
            // Refer to the code comment for the "seccomp-log-failures"
            // command-line parameter for an explanation about why the |log_failures|
            // flag forces the use of .policy files (and the build-time alternative to
            // this run-time flag).
            let bpf_policy_file = seccomp_policy_path.with_extension("bpf");
            if bpf_policy_file.exists() && !config.log_failures {
                j.parse_seccomp_program(&bpf_policy_file).with_context(|| {
                    format!(
                        "failed to parse precompiled seccomp policy: {}",
                        bpf_policy_file.display()
                    )
                })?;
            } else {
                // Use TSYNC only for the side effect of it using SECCOMP_RET_TRAP,
                // which will correctly kill the entire device process if a worker
                // thread commits a seccomp violation.
                j.set_seccomp_filter_tsync();
                if config.log_failures {
                    j.log_seccomp_filter_failures();
                }
                let bpf_policy_file = seccomp_policy_path.with_extension("policy");
                j.parse_seccomp_filters(&bpf_policy_file).with_context(|| {
                    format!(
                        "failed to parse seccomp policy: {}",
                        bpf_policy_file.display()
                    )
                })?;
            }
        } else {
            let bpf_program = EMBEDDED_BPFS
                .get(&config.seccomp_policy_name)
                .with_context(|| {
                    format!(
                        "failed to find embedded seccomp policy: {}",
                        &config.seccomp_policy_name
                    )
                })?;
            j.parse_seccomp_bytes(bpf_program).with_context(|| {
                format!(
                    "failed to parse embedded seccomp policy: {}",
                    &config.seccomp_policy_name
                )
            })?;
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

pub(super) fn simple_jail_ext(
    jail_config: &Option<JailConfig>,
    policy: &str,
    r_limit: Option<u64>,
) -> Result<Option<Minijail>> {
    if let Some(jail_config) = jail_config {
        // A directory for a jailed device's pivot root.
        if !jail_config.pivot_root.exists() {
            bail!(
                "{:?} doesn't exist, can't jail devices",
                jail_config.pivot_root
            );
        }
        let policy_path = jail_config
            .seccomp_policy_dir
            .as_ref()
            .map(|dir| dir.join(policy));
        let config = SandboxConfig {
            limit_caps: true,
            log_failures: jail_config.seccomp_log_failures,
            seccomp_policy_path: policy_path.as_deref(),
            seccomp_policy_name: policy,
            uid_map: None,
            gid_map: None,
            remount_mode: None,
        };
        Ok(Some(create_base_minijail(
            &jail_config.pivot_root,
            r_limit,
            Some(&config),
        )?))
    } else {
        Ok(None)
    }
}

pub(super) fn simple_jail(
    jail_config: &Option<JailConfig>,
    policy: &str,
) -> Result<Option<Minijail>> {
    simple_jail_ext(jail_config, policy, None)
}

pub(super) fn gpu_jail(jail_config: &Option<JailConfig>, policy: &str) -> Result<Option<Minijail>> {
    match simple_jail_ext(jail_config, policy, Some(32768))? {
        Some(mut jail) => {
            // Create a tmpfs in the device's root directory so that we can bind mount the
            // dri directory into it.  The size=67108864 is size=64*1024*1024 or size=64MB.
            jail.mount_with_data(
                Path::new("none"),
                Path::new("/"),
                "tmpfs",
                (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as usize,
                "size=67108864",
            )?;

            // Device nodes required for DRM.
            let sys_dev_char_path = Path::new("/sys/dev/char");
            jail.mount_bind(sys_dev_char_path, sys_dev_char_path, false)?;
            let sys_devices_path = Path::new("/sys/devices");
            jail.mount_bind(sys_devices_path, sys_devices_path, false)?;

            let drm_dri_path = Path::new("/dev/dri");
            if drm_dri_path.exists() {
                jail.mount_bind(drm_dri_path, drm_dri_path, false)?;
            }

            // If the ARM specific devices exist on the host, bind mount them in.
            let mali0_path = Path::new("/dev/mali0");
            if mali0_path.exists() {
                jail.mount_bind(mali0_path, mali0_path, true)?;
            }

            let pvr_sync_path = Path::new("/dev/pvr_sync");
            if pvr_sync_path.exists() {
                jail.mount_bind(pvr_sync_path, pvr_sync_path, true)?;
            }

            // If the udmabuf driver exists on the host, bind mount it in.
            let udmabuf_path = Path::new("/dev/udmabuf");
            if udmabuf_path.exists() {
                jail.mount_bind(udmabuf_path, udmabuf_path, true)?;
            }

            // Libraries that are required when mesa drivers are dynamically loaded.
            jail_mount_bind_if_exists(
                &mut jail,
                &[
                    "/usr/lib",
                    "/usr/lib64",
                    "/lib",
                    "/lib64",
                    "/usr/share/drirc.d",
                    "/usr/share/glvnd",
                    "/usr/share/vulkan",
                ],
            )?;

            // pvr driver requires read access to /proc/self/task/*/comm.
            let proc_path = Path::new("/proc");
            jail.mount(
                proc_path,
                proc_path,
                "proc",
                (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC | libc::MS_RDONLY) as usize,
            )?;

            // To enable perfetto tracing, we need to give access to the perfetto service IPC
            // endpoints.
            let perfetto_path = Path::new("/run/perfetto");
            if perfetto_path.exists() {
                jail.mount_bind(perfetto_path, perfetto_path, true)?;
            }

            Ok(Some(jail))
        }
        None => Ok(None),
    }
}

/// Mirror-mount all the directories in `dirs` into `jail` on a best-effort basis.
///
/// This function will not return an error if any of the directories in `dirs` is missing.
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

#[cfg(all(feature = "gpu", feature = "virgl_renderer_next"))]
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
