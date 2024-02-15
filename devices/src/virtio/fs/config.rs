// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::time::Duration;

#[cfg(feature = "arc_quota")]
use serde::de::Error;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde_keyvalue::FromKeyValues;

/// The caching policy that the file system should report to the FUSE client. By default the FUSE
/// protocol uses close-to-open consistency. This means that any cached contents of the file are
/// invalidated the next time that file is opened.
#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize, Deserialize, FromKeyValues)]
#[serde(rename_all = "kebab-case")]
pub enum CachePolicy {
    /// The client should never cache file data and all I/O should be directly forwarded to the
    /// server. This policy must be selected when file contents may change without the knowledge of
    /// the FUSE client (i.e., the file system does not have exclusive access to the directory).
    Never,

    /// The client is free to choose when and how to cache file data. This is the default policy
    /// and uses close-to-open consistency as described in the enum documentation.
    #[default]
    Auto,

    /// The client should always cache file data. This means that the FUSE client will not
    /// invalidate any cached data that was returned by the file system the last time the file was
    /// opened. This policy should only be selected when the file system has exclusive access to
    /// the directory.
    Always,
}

const fn config_default_timeout() -> Duration {
    Duration::from_secs(5)
}

const fn config_default_negative_timeout() -> Duration {
    Duration::ZERO
}

const fn config_default_posix_acl() -> bool {
    true
}

fn deserialize_timeout<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
    let secs = u64::deserialize(deserializer)?;

    Ok(Duration::from_secs(secs))
}

#[cfg(feature = "arc_quota")]
fn deserialize_privileged_quota_uids<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<libc::uid_t>, D::Error> {
    // space-separated list
    let s: &str = serde::Deserialize::deserialize(deserializer)?;
    s.split(" ")
        .map(|s| {
            s.parse::<libc::uid_t>().map_err(|e| {
                <D as Deserializer>::Error::custom(format!(
                    "failed to parse priviledged quota uid {s}: {e}"
                ))
            })
        })
        .collect()
}

/// Options that configure the behavior of the file system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, FromKeyValues)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
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
    #[serde(
        default = "config_default_timeout",
        deserialize_with = "deserialize_timeout"
    )]
    pub timeout: Duration,

    /// How long the FUSE client can cache negative lookup results.
    /// If a file lookup fails, the client can assume the file doesn't exist until the timeout and
    ///  won't send lookup.
    /// The value 0 means that negative lookup shouldn't be cached.
    ///
    /// If the contents of a directory can only be modified by the FUSE client (i.e., the file
    /// system has exclusive access), then this should be a large value.
    /// The default value for this option is 0 seconds (= no negative cache).
    #[serde(
        default = "config_default_negative_timeout",
        deserialize_with = "deserialize_timeout"
    )]
    pub negative_timeout: Duration,

    /// The caching policy the file system should use. See the documentation of `CachePolicy` for
    /// more details.
    #[serde(default, alias = "cache")]
    pub cache_policy: CachePolicy,

    /// Whether the file system should enabled writeback caching. This can improve performance as
    /// it allows the FUSE client to cache and coalesce multiple writes before sending them to
    /// the file system. However, enabling this option can increase the risk of data corruption
    /// if the file contents can change without the knowledge of the FUSE client (i.e., the
    /// server does **NOT** have exclusive access). Additionally, the file system should have
    /// read access to all files in the directory it is serving as the FUSE client may send
    /// read requests even for files opened with `O_WRONLY`.
    ///
    /// Therefore callers should only enable this option when they can guarantee that: 1) the file
    /// system has exclusive access to the directory and 2) the file system has read permissions
    /// for all files in that directory.
    ///
    /// The default value for this option is `false`.
    #[serde(default)]
    pub writeback: bool,

    /// Controls whether security.* xattrs (except for security.selinux) are re-written. When this
    /// is set to true, the server will add a "user.virtiofs" prefix to xattrs in the security
    /// namespace. Setting these xattrs requires CAP_SYS_ADMIN in the namespace where the file
    /// system was mounted and since the server usually runs in an unprivileged user namespace,
    /// it's unlikely to have that capability.
    ///
    /// The default value for this option is `false`.
    #[serde(default, alias = "rewrite-security-xattrs")]
    pub rewrite_security_xattrs: bool,

    /// Use case-insensitive lookups for directory entries (ASCII only).
    ///
    /// The default value for this option is `false`.
    #[serde(default)]
    pub ascii_casefold: bool,

    // UIDs which are privileged to perform quota-related operations. We cannot perform a
    // CAP_FOWNER check so we consult this list when the VM tries to set the project quota and
    // the process uid doesn't match the owner uid. In that case, all uids in this list are
    // treated as if they have CAP_FOWNER.
    #[cfg(feature = "arc_quota")]
    #[serde(default, deserialize_with = "deserialize_privileged_quota_uids")]
    pub privileged_quota_uids: Vec<libc::uid_t>,

    /// Use DAX for shared files.
    ///
    /// Enabling DAX can improve performance for frequently accessed files by mapping regions of
    /// the file directly into the VM's memory region, allowing direct access with the cost of
    /// slightly increased latency the first time the file is accessed. Additionally, since the
    /// mapping is shared directly from the host kernel's file cache, enabling DAX can improve
    /// performance even when the cache policy is `Never`.
    ///
    /// The default value for this option is `false`.
    #[serde(default, alias = "dax")]
    pub use_dax: bool,

    /// Enable support for POSIX acls.
    ///
    /// Enable POSIX acl support for the shared directory. This requires that the underlying file
    /// system also supports POSIX acls.
    ///
    /// The default value for this option is `true`.
    #[serde(default = "config_default_posix_acl")]
    pub posix_acl: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            timeout: config_default_timeout(),
            negative_timeout: config_default_negative_timeout(),
            cache_policy: Default::default(),
            writeback: false,
            rewrite_security_xattrs: false,
            ascii_casefold: false,
            #[cfg(feature = "arc_quota")]
            privileged_quota_uids: Default::default(),
            use_dax: false,
            posix_acl: config_default_posix_acl(),
        }
    }
}
