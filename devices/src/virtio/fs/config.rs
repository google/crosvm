// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::str::FromStr;
use std::time::Duration;

use serde::Deserialize;
use serde::Serialize;

/// The caching policy that the file system should report to the FUSE client. By default the FUSE
/// protocol uses close-to-open consistency. This means that any cached contents of the file are
/// invalidated the next time that file is opened.
#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
pub enum CachePolicy {
    /// The client should never cache file data and all I/O should be directly forwarded to the
    /// server. This policy must be selected when file contents may change without the knowledge of
    /// the FUSE client (i.e., the file system does not have exclusive access to the directory).
    Never,

    /// The client is free to choose when and how to cache file data. This is the default policy and
    /// uses close-to-open consistency as described in the enum documentation.
    #[default]
    Auto,

    /// The client should always cache file data. This means that the FUSE client will not
    /// invalidate any cached data that was returned by the file system the last time the file was
    /// opened. This policy should only be selected when the file system has exclusive access to the
    /// directory.
    Always,
}

impl FromStr for CachePolicy {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "never" | "Never" | "NEVER" => Ok(CachePolicy::Never),
            "auto" | "Auto" | "AUTO" => Ok(CachePolicy::Auto),
            "always" | "Always" | "ALWAYS" => Ok(CachePolicy::Always),
            _ => Err("invalid cache policy"),
        }
    }
}

/// Options that configure the behavior of the file system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// How long the FUSE client should consider directory entries and file/directory attributes to
    /// be valid.
    /// This value corresponds to `entry_timeout` and `attr_timeout` in
    /// [libfuse's `fuse_config`](https://libfuse.github.io/doxygen/structfuse__config.html), but
    /// we use the same value for the two.
    ///
    /// If the contents of a directory or the attributes of a file or directory can only be
    /// modified by the FUSE client (i.e., the file system has exclusive access), then this should
    /// be a large value.
    /// The default value for this option is 5 seconds.
    pub timeout: Duration,

    /// The caching policy the file system should use. See the documentation of `CachePolicy` for
    /// more details.
    pub cache_policy: CachePolicy,

    /// Whether the file system should enabled writeback caching. This can improve performance as it
    /// allows the FUSE client to cache and coalesce multiple writes before sending them to the file
    /// system. However, enabling this option can increase the risk of data corruption if the file
    /// contents can change without the knowledge of the FUSE client (i.e., the server does **NOT**
    /// have exclusive access). Additionally, the file system should have read access to all files
    /// in the directory it is serving as the FUSE client may send read requests even for files
    /// opened with `O_WRONLY`.
    ///
    /// Therefore callers should only enable this option when they can guarantee that: 1) the file
    /// system has exclusive access to the directory and 2) the file system has read permissions for
    /// all files in that directory.
    ///
    /// The default value for this option is `false`.
    pub writeback: bool,

    /// Controls whether security.* xattrs (except for security.selinux) are re-written. When this
    /// is set to true, the server will add a "user.virtiofs" prefix to xattrs in the security
    /// namespace. Setting these xattrs requires CAP_SYS_ADMIN in the namespace where the file
    /// system was mounted and since the server usually runs in an unprivileged user namespace, it's
    /// unlikely to have that capability.
    ///
    /// The default value for this option is `false`.
    pub rewrite_security_xattrs: bool,

    /// Use case-insensitive lookups for directory entries (ASCII only).
    ///
    /// The default value for this option is `false`.
    pub ascii_casefold: bool,

    // UIDs which are privileged to perform quota-related operations. We cannot perform a CAP_FOWNER
    // check so we consult this list when the VM tries to set the project quota and the process uid
    // doesn't match the owner uid. In that case, all uids in this list are treated as if they have
    // CAP_FOWNER.
    #[cfg(feature = "arc_quota")]
    pub privileged_quota_uids: Vec<libc::uid_t>,

    /// Use DAX for shared files.
    ///
    /// Enabling DAX can improve performance for frequently accessed files by mapping regions of the
    /// file directly into the VM's memory region, allowing direct access with the cost of slightly
    /// increased latency the first time the file is accessed. Additionally, since the mapping is
    /// shared directly from the host kernel's file cache, enabling DAX can improve performance even
    /// when the cache policy is `Never`.
    ///
    /// The default value for this option is `false`.
    pub use_dax: bool,

    /// Enable support for POSIX acls.
    ///
    /// Enable POSIX acl support for the shared directory. This requires that the underlying file
    /// system also supports POSIX acls.
    ///
    /// The default value for this option is `true`.
    pub posix_acl: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            timeout: Duration::from_secs(5),
            cache_policy: Default::default(),
            writeback: false,
            rewrite_security_xattrs: false,
            ascii_casefold: false,
            #[cfg(feature = "arc_quota")]
            privileged_quota_uids: Default::default(),
            use_dax: false,
            posix_acl: true,
        }
    }
}

impl FromStr for Config {
    type Err = &'static str;

    fn from_str(params: &str) -> Result<Self, Self::Err> {
        let mut cfg = Self::default();
        if params.is_empty() {
            return Ok(cfg);
        }
        for opt in params.split(':') {
            let mut o = opt.splitn(2, '=');
            let kind = o.next().ok_or("`cfg` options mut not be empty")?;
            let value = o
                .next()
                .ok_or("`cfg` options must be of the form `kind=value`")?;
            match kind {
                #[cfg(feature = "arc_quota")]
                "privileged_quota_uids" => {
                    cfg.privileged_quota_uids =
                        value.split(' ').map(|s| s.parse().unwrap()).collect();
                }
                "timeout" => {
                    let seconds = value.parse().map_err(|_| "`timeout` must be an integer")?;

                    let dur = Duration::from_secs(seconds);
                    cfg.timeout = dur;
                }
                "cache" => {
                    let policy = value
                        .parse()
                        .map_err(|_| "`cache` must be one of `never`, `always`, or `auto`")?;
                    cfg.cache_policy = policy;
                }
                "writeback" => {
                    let writeback = value.parse().map_err(|_| "`writeback` must be a boolean")?;
                    cfg.writeback = writeback;
                }
                "rewrite-security-xattrs" => {
                    let rewrite_security_xattrs = value
                        .parse()
                        .map_err(|_| "`rewrite-security-xattrs` must be a boolean")?;
                    cfg.rewrite_security_xattrs = rewrite_security_xattrs;
                }
                "ascii_casefold" => {
                    let ascii_casefold = value
                        .parse()
                        .map_err(|_| "`ascii_casefold` must be a boolean")?;
                    cfg.ascii_casefold = ascii_casefold;
                }
                "dax" => {
                    let use_dax = value.parse().map_err(|_| "`dax` must be a boolean")?;
                    cfg.use_dax = use_dax;
                }
                "posix_acl" => {
                    let posix_acl = value.parse().map_err(|_| "`posix_acl` must be a boolean")?;
                    cfg.posix_acl = posix_acl;
                }
                _ => return Err("unrecognized option for virtio-fs config"),
            }
        }
        Ok(cfg)
    }
}
