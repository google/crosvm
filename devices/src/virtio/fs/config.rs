// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(feature = "fs_permission_translation")]
use std::io;
#[cfg(feature = "fs_permission_translation")]
use std::str::FromStr;
use std::time::Duration;

#[cfg(feature = "fs_permission_translation")]
use libc;
#[allow(unused_imports)]
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

const fn config_default_security_ctx() -> bool {
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

/// Permission structure that is configured to map the UID-GID at runtime
#[cfg(feature = "fs_permission_translation")]
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct PermissionData {
    /// UID to be set for all the files in the path inside guest.
    pub guest_uid: libc::uid_t,

    /// GID to be set for all the files in the path inside guest.
    pub guest_gid: libc::gid_t,

    /// UID to be set for all the files in the path in the host.
    pub host_uid: libc::uid_t,

    /// GID to be set for all the files in the path in the host.
    pub host_gid: libc::gid_t,

    /// umask to be set at runtime for the files in the path.
    pub umask: libc::mode_t,

    /// This is the absolute path from the root of the shared directory.
    pub perm_path: String,
}

#[cfg(feature = "fs_runtime_ugid_map")]
fn process_ugid_map(result: Vec<Vec<String>>) -> Result<Vec<PermissionData>, io::Error> {
    let mut permissions = Vec::new();

    for inner_vec in result {
        let guest_uid = match libc::uid_t::from_str(&inner_vec[0]) {
            Ok(uid) => uid,
            Err(_) => {
                return Err(io::Error::from_raw_os_error(libc::EINVAL));
            }
        };

        let guest_gid = match libc::gid_t::from_str(&inner_vec[1]) {
            Ok(gid) => gid,
            Err(_) => {
                return Err(io::Error::from_raw_os_error(libc::EINVAL));
            }
        };

        let host_uid = match libc::uid_t::from_str(&inner_vec[2]) {
            Ok(uid) => uid,
            Err(_) => {
                return Err(io::Error::from_raw_os_error(libc::EINVAL));
            }
        };

        let host_gid = match libc::gid_t::from_str(&inner_vec[3]) {
            Ok(gid) => gid,
            Err(_) => {
                return Err(io::Error::from_raw_os_error(libc::EINVAL));
            }
        };

        let umask = match libc::mode_t::from_str(&inner_vec[4]) {
            Ok(mode) => mode,
            Err(_) => {
                return Err(io::Error::from_raw_os_error(libc::EINVAL));
            }
        };

        let perm_path = inner_vec[5].clone();

        // Create PermissionData and push it to the vector
        permissions.push(PermissionData {
            guest_uid,
            guest_gid,
            host_uid,
            host_gid,
            umask,
            perm_path,
        });
    }

    Ok(permissions)
}

#[cfg(feature = "fs_runtime_ugid_map")]
fn deserialize_ugid_map<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<PermissionData>, D::Error> {
    // space-separated list
    let s: &str = serde::Deserialize::deserialize(deserializer)?;

    let result: Vec<Vec<String>> = s
        .split(';')
        .map(|group| group.trim().split(' ').map(String::from).collect())
        .collect();

    // Length Validation for each inner vector
    for inner_vec in &result {
        if inner_vec.len() != 6 {
            return Err(D::Error::custom(
                "Invalid ugid_map format. Each group must have 6 elements.",
            ));
        }
    }

    let permissions = match process_ugid_map(result) {
        Ok(p) => p,
        Err(e) => {
            return Err(D::Error::custom(format!(
                "Error processing uid_gid_map: {}",
                e
            )));
        }
    };

    Ok(permissions)
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

    // Maximum number of dynamic permission paths.
    //
    // The dynamic permission paths are used to set specific paths certain uid/gid after virtiofs
    // device is created. It is for arcvm special usage, normal device should not support
    // this feature.
    //
    // The default value for this option is 0.
    #[serde(default)]
    pub max_dynamic_perm: usize,

    // Maximum number of dynamic xattr paths.
    //
    // The dynamic xattr paths are used to set specific paths certain xattr after virtiofs
    // device is created. It is for arcvm special usage, normal device should not support
    // this feature.
    //
    // The default value for this option is 0.
    #[serde(default)]
    pub max_dynamic_xattr: usize,

    // Controls whether fuse_security_context feature is enabled
    //
    // The FUSE_SECURITY_CONTEXT feature needs write data into /proc/thread-self/attr/fscreate.
    // For the hosts that prohibit the write operation, the option should be set to false to
    // disable the FUSE_SECURITY_CONTEXT feature. When FUSE_SECURITY_CONTEXT is disabled, the
    // security context won't be passed with fuse request, which makes guest created files/dir
    // having unlabeled security context or empty security context.
    //
    // The default value for this option is true
    #[serde(default = "config_default_security_ctx")]
    pub security_ctx: bool,

    // Specifies run-time UID/GID mapping that works without user namespaces.
    //
    // The virtio-fs usually does mapping of UIDs/GIDs between host and guest with user namespace.
    // In Android, however, user namespace isn't available for non-root users.
    // This allows mapping UIDs and GIDs without user namespace by intercepting FUSE
    // requests and translating UID/GID in virito-fs's process at runtime.
    //
    // The format is "guest-uid, guest-gid, host-uid, host-gid, umask, path;{repeat}"
    //
    // guest-uid: UID to be set for all the files in the path inside guest.
    // guest-gid: GID to be set for all the files in the path inside guest.
    // host-uid: UID to be set for all the files in the path in the host.
    // host-gid: GID to be set for all the files in the path in the host.
    // umask: umask to be set at runtime for the files in the path.
    // path: This is the absolute path from the root of the shared directory.
    //
    // This follows similar format to ARCVM IOCTL "FS_IOC_SETPERMISSION"
    #[cfg(feature = "fs_runtime_ugid_map")]
    #[serde(default, deserialize_with = "deserialize_ugid_map")]
    pub ugid_map: Vec<PermissionData>,
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
            max_dynamic_perm: 0,
            max_dynamic_xattr: 0,
            security_ctx: config_default_security_ctx(),
            #[cfg(feature = "fs_runtime_ugid_map")]
            ugid_map: Vec::new(),
        }
    }
}

#[cfg(all(test, feature = "fs_runtime_ugid_map"))]
mod tests {

    use super::*;
    #[test]
    fn test_deserialize_ugid_map_valid() {
        let input_string =
            "\"1000 1000 1000 1000 0022 /path/to/dir;2000 2000 2000 2000 0022 /path/to/other/dir\"";

        let mut deserializer = serde_json::Deserializer::from_str(input_string);
        let result = deserialize_ugid_map(&mut deserializer).unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(
            result,
            vec![
                PermissionData {
                    guest_uid: 1000,
                    guest_gid: 1000,
                    host_uid: 1000,
                    host_gid: 1000,
                    umask: 22,
                    perm_path: "/path/to/dir".to_string(),
                },
                PermissionData {
                    guest_uid: 2000,
                    guest_gid: 2000,
                    host_uid: 2000,
                    host_gid: 2000,
                    umask: 22,
                    perm_path: "/path/to/other/dir".to_string(),
                },
            ]
        );
    }

    #[test]
    fn test_process_ugid_map_valid() {
        let input_vec = vec![
            vec![
                "1000".to_string(),
                "1000".to_string(),
                "1000".to_string(),
                "1000".to_string(),
                "0022".to_string(),
                "/path/to/dir".to_string(),
            ],
            vec![
                "2000".to_string(),
                "2000".to_string(),
                "2000".to_string(),
                "2000".to_string(),
                "0022".to_string(),
                "/path/to/other/dir".to_string(),
            ],
        ];

        let result = process_ugid_map(input_vec).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(
            result,
            vec![
                PermissionData {
                    guest_uid: 1000,
                    guest_gid: 1000,
                    host_uid: 1000,
                    host_gid: 1000,
                    umask: 22,
                    perm_path: "/path/to/dir".to_string(),
                },
                PermissionData {
                    guest_uid: 2000,
                    guest_gid: 2000,
                    host_uid: 2000,
                    host_gid: 2000,
                    umask: 22,
                    perm_path: "/path/to/other/dir".to_string(),
                },
            ]
        );
    }

    #[test]
    fn test_deserialize_ugid_map_invalid_format() {
        let input_string = "\"1000 1000 1000 0022 /path/to/dir\""; // Missing one element

        // Create a Deserializer from the input string
        let mut deserializer = serde_json::Deserializer::from_str(input_string);
        let result = deserialize_ugid_map(&mut deserializer);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_ugid_map_invalid_guest_uid() {
        let input_string = "\"invalid 1000 1000 1000 0022 /path/to/dir\""; // Invalid guest-UID

        // Create a Deserializer from the input string
        let mut deserializer = serde_json::Deserializer::from_str(input_string);
        let result = deserialize_ugid_map(&mut deserializer);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_ugid_map_invalid_guest_gid() {
        let input_string = "\"1000 invalid 1000 1000 0022 /path/to/dir\""; // Invalid guest-GID

        // Create a Deserializer from the input string
        let mut deserializer = serde_json::Deserializer::from_str(input_string);
        let result = deserialize_ugid_map(&mut deserializer);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_ugid_map_invalid_umask() {
        let input_string = "\"1000 1000 1000 1000 invalid /path/to/dir\""; // Invalid umask

        // Create a Deserializer from the input string
        let mut deserializer = serde_json::Deserializer::from_str(input_string);
        let result = deserialize_ugid_map(&mut deserializer);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_ugid_map_invalid_host_uid() {
        let input_string = "\"1000 1000 invalid 1000 0022 /path/to/dir\""; // Invalid host-UID

        // Create a Deserializer from the input string
        let mut deserializer = serde_json::Deserializer::from_str(input_string);
        let result = deserialize_ugid_map(&mut deserializer);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_ugid_map_invalid_host_gid() {
        let input_string = "\"1000 1000 1000 invalid 0022 /path/to/dir\""; // Invalid host-UID

        // Create a Deserializer from the input string
        let mut deserializer = serde_json::Deserializer::from_str(input_string);
        let result = deserialize_ugid_map(&mut deserializer);
        assert!(result.is_err());
    }
}
