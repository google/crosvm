// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(windows)]
use std::num::NonZeroU32;
use std::path::PathBuf;

use cros_async::ExecutorKind;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;

fn block_option_sparse_default() -> bool {
    true
}
fn block_option_block_size_default() -> u32 {
    512
}
// TODO(b/237829580): Move to sys module once virtio block sys is refactored to
// match the style guide.
#[cfg(windows)]
fn block_option_io_concurrency_default() -> NonZeroU32 {
    NonZeroU32::new(1).unwrap()
}

/// Maximum length of a `DiskOption` identifier.
///
/// This is based on the virtio-block ID length limit.
pub const DISK_ID_LEN: usize = 20;

pub fn serialize_disk_id<S: Serializer>(
    id: &Option<[u8; DISK_ID_LEN]>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match id {
        None => serializer.serialize_none(),
        Some(id) => {
            // Find the first zero byte in the id.
            let len = id.iter().position(|v| *v == 0).unwrap_or(DISK_ID_LEN);
            serializer.serialize_some(
                std::str::from_utf8(&id[0..len])
                    .map_err(|e| serde::ser::Error::custom(e.to_string()))?,
            )
        }
    }
}

fn deserialize_disk_id<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<[u8; DISK_ID_LEN]>, D::Error> {
    let id = Option::<String>::deserialize(deserializer)?;

    match id {
        None => Ok(None),
        Some(id) => {
            if id.len() > DISK_ID_LEN {
                return Err(serde::de::Error::custom(format!(
                    "disk id must be {} or fewer characters",
                    DISK_ID_LEN
                )));
            }

            let mut ret = [0u8; DISK_ID_LEN];
            // Slicing id to value's length will never panic
            // because we checked that value will fit into id above.
            ret[..id.len()].copy_from_slice(id.as_bytes());
            Ok(Some(ret))
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, serde_keyvalue::FromKeyValues)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct DiskOption {
    pub path: PathBuf,
    #[serde(default, rename = "ro")]
    pub read_only: bool,
    #[serde(default)]
    /// Whether this disk should be the root device. Can only be set once. Only useful for adding
    /// specific command-line options.
    pub root: bool,
    #[serde(default = "block_option_sparse_default")]
    pub sparse: bool,
    // camel_case variant allowed for backward compatibility.
    #[serde(default, alias = "o_direct")]
    pub direct: bool,
    // camel_case variant allowed for backward compatibility.
    #[serde(default = "block_option_block_size_default", alias = "block_size")]
    pub block_size: u32,
    #[serde(
        default,
        serialize_with = "serialize_disk_id",
        deserialize_with = "deserialize_disk_id"
    )]
    pub id: Option<[u8; DISK_ID_LEN]>,
    // camel_case variant allowed for backward compatibility.
    #[cfg(windows)]
    #[serde(
        default = "block_option_io_concurrency_default",
        alias = "io_concurrency"
    )]
    pub io_concurrency: NonZeroU32,
    #[serde(default)]
    /// Experimental option to run multiple worker threads in parallel. If false, only single thread
    /// runs by default. Note this option is not effective for vhost-user blk device.
    pub multiple_workers: bool,
    #[serde(default, alias = "async_executor")]
    /// The async executor kind to simulate the block device with. This option takes
    /// precedence over the async executor kind specified by the subcommand's option.
    /// If None, the default or the specified by the subcommand's option would be used.
    pub async_executor: Option<ExecutorKind>,
}

#[cfg(test)]
mod tests {
    use serde_keyvalue::*;

    use super::*;

    fn from_block_arg(options: &str) -> Result<DiskOption, ParseError> {
        from_key_values(options)
    }

    #[test]
    fn params_from_key_values() {
        // Path argument is mandatory.
        let err = from_block_arg("").unwrap_err();
        assert_eq!(
            err,
            ParseError {
                kind: ErrorKind::SerdeError("missing field `path`".into()),
                pos: 0,
            }
        );

        // Path is the default argument.
        let params = from_block_arg("/path/to/disk.img").unwrap();
        assert_eq!(
            params,
            DiskOption {
                path: "/path/to/disk.img".into(),
                read_only: false,
                root: false,
                sparse: true,
                direct: false,
                block_size: 512,
                id: None,
                #[cfg(windows)]
                io_concurrency: NonZeroU32::new(1).unwrap(),
                multiple_workers: false,
                async_executor: None,
            }
        );

        // Explicitly-specified path.
        let params = from_block_arg("path=/path/to/disk.img").unwrap();
        assert_eq!(
            params,
            DiskOption {
                path: "/path/to/disk.img".into(),
                read_only: false,
                root: false,
                sparse: true,
                direct: false,
                block_size: 512,
                id: None,
                #[cfg(windows)]
                io_concurrency: NonZeroU32::new(1).unwrap(),
                multiple_workers: false,
                async_executor: None,
            }
        );

        // read_only
        let params = from_block_arg("/some/path.img,ro").unwrap();
        assert_eq!(
            params,
            DiskOption {
                path: "/some/path.img".into(),
                read_only: true,
                root: false,
                sparse: true,
                direct: false,
                block_size: 512,
                id: None,
                #[cfg(windows)]
                io_concurrency: NonZeroU32::new(1).unwrap(),
                multiple_workers: false,
                async_executor: None,
            }
        );

        // root
        let params = from_block_arg("/some/path.img,root").unwrap();
        assert_eq!(
            params,
            DiskOption {
                path: "/some/path.img".into(),
                read_only: false,
                root: true,
                sparse: true,
                direct: false,
                block_size: 512,
                id: None,
                #[cfg(windows)]
                io_concurrency: NonZeroU32::new(1).unwrap(),
                multiple_workers: false,
                async_executor: None,
            }
        );

        // sparse
        let params = from_block_arg("/some/path.img,sparse").unwrap();
        assert_eq!(
            params,
            DiskOption {
                path: "/some/path.img".into(),
                read_only: false,
                root: false,
                sparse: true,
                direct: false,
                block_size: 512,
                id: None,
                #[cfg(windows)]
                io_concurrency: NonZeroU32::new(1).unwrap(),
                multiple_workers: false,
                async_executor: None,
            }
        );
        let params = from_block_arg("/some/path.img,sparse=false").unwrap();
        assert_eq!(
            params,
            DiskOption {
                path: "/some/path.img".into(),
                read_only: false,
                root: false,
                sparse: false,
                direct: false,
                block_size: 512,
                id: None,
                #[cfg(windows)]
                io_concurrency: NonZeroU32::new(1).unwrap(),
                multiple_workers: false,
                async_executor: None,
            }
        );

        // direct
        let params = from_block_arg("/some/path.img,direct").unwrap();
        assert_eq!(
            params,
            DiskOption {
                path: "/some/path.img".into(),
                read_only: false,
                root: false,
                sparse: true,
                direct: true,
                block_size: 512,
                id: None,
                #[cfg(windows)]
                io_concurrency: NonZeroU32::new(1).unwrap(),
                multiple_workers: false,
                async_executor: None,
            }
        );

        // o_direct (deprecated, kept for backward compatibility)
        let params = from_block_arg("/some/path.img,o_direct").unwrap();
        assert_eq!(
            params,
            DiskOption {
                path: "/some/path.img".into(),
                read_only: false,
                root: false,
                sparse: true,
                direct: true,
                block_size: 512,
                id: None,
                #[cfg(windows)]
                io_concurrency: NonZeroU32::new(1).unwrap(),
                multiple_workers: false,
                async_executor: None,
            }
        );

        // block-size
        let params = from_block_arg("/some/path.img,block-size=128").unwrap();
        assert_eq!(
            params,
            DiskOption {
                path: "/some/path.img".into(),
                read_only: false,
                root: false,
                sparse: true,
                direct: false,
                block_size: 128,
                id: None,
                #[cfg(windows)]
                io_concurrency: NonZeroU32::new(1).unwrap(),
                multiple_workers: false,
                async_executor: None,
            }
        );

        // block_size (deprecated, kept for backward compatibility)
        let params = from_block_arg("/some/path.img,block_size=128").unwrap();
        assert_eq!(
            params,
            DiskOption {
                path: "/some/path.img".into(),
                read_only: false,
                root: false,
                sparse: true,
                direct: false,
                block_size: 128,
                id: None,
                async_executor: None,
                #[cfg(windows)]
                io_concurrency: NonZeroU32::new(1).unwrap(),
                multiple_workers: false,
            }
        );

        // io_concurrency
        #[cfg(windows)]
        {
            let params = from_block_arg("/some/path.img,io_concurrency=4").unwrap();
            assert_eq!(
                params,
                DiskOption {
                    path: "/some/path.img".into(),
                    read_only: false,
                    root: false,
                    sparse: true,
                    direct: false,
                    block_size: 512,
                    id: None,
                    io_concurrency: NonZeroU32::new(4).unwrap(),
                    multiple_workers: false,
                    async_executor: None,
                }
            );
        }

        // id
        let params = from_block_arg("/some/path.img,id=DISK").unwrap();
        assert_eq!(
            params,
            DiskOption {
                path: "/some/path.img".into(),
                read_only: false,
                root: false,
                sparse: true,
                direct: false,
                block_size: 512,
                id: Some(*b"DISK\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"),
                #[cfg(windows)]
                io_concurrency: NonZeroU32::new(1).unwrap(),
                multiple_workers: false,
                async_executor: None,
            }
        );
        let err = from_block_arg("/some/path.img,id=DISK_ID_IS_WAY_TOO_LONG").unwrap_err();
        assert_eq!(
            err,
            ParseError {
                kind: ErrorKind::SerdeError("disk id must be 20 or fewer characters".into()),
                pos: 0,
            }
        );

        // async-executor
        #[cfg(windows)]
        let (ex_kind, ex_kind_opt) = (ExecutorKind::Handle, "handle");
        #[cfg(unix)]
        let (ex_kind, ex_kind_opt) = (ExecutorKind::Fd, "epoll");
        let params =
            from_block_arg(&format!("/some/path.img,async-executor={ex_kind_opt}")).unwrap();
        assert_eq!(
            params,
            DiskOption {
                path: "/some/path.img".into(),
                read_only: false,
                root: false,
                sparse: true,
                direct: false,
                block_size: 512,
                id: None,
                #[cfg(windows)]
                io_concurrency: NonZeroU32::new(1).unwrap(),
                multiple_workers: false,
                async_executor: Some(ex_kind),
            }
        );

        // All together
        let params = from_block_arg(&format!(
            "/some/path.img,block_size=256,ro,root,sparse=false,id=DISK_LABEL\
            ,direct,async-executor={ex_kind_opt}"
        ))
        .unwrap();
        assert_eq!(
            params,
            DiskOption {
                path: "/some/path.img".into(),
                read_only: true,
                root: true,
                sparse: false,
                direct: true,
                block_size: 256,
                id: Some(*b"DISK_LABEL\0\0\0\0\0\0\0\0\0\0"),
                #[cfg(windows)]
                io_concurrency: NonZeroU32::new(1).unwrap(),
                multiple_workers: false,
                async_executor: Some(ex_kind),
            }
        );
    }

    #[test]
    fn diskoption_serialize_deserialize() {
        // With id == None
        let original = DiskOption {
            path: "./rootfs".into(),
            read_only: false,
            root: false,
            sparse: true,
            direct: false,
            block_size: 512,
            id: None,
            #[cfg(windows)]
            io_concurrency: NonZeroU32::new(1).unwrap(),
            multiple_workers: false,
            async_executor: None,
        };
        let json = serde_json::to_string(&original).unwrap();
        let deserialized = serde_json::from_str(&json).unwrap();
        assert_eq!(original, deserialized);

        // With id == Some
        let original = DiskOption {
            path: "./rootfs".into(),
            read_only: false,
            root: false,
            sparse: true,
            direct: false,
            block_size: 512,
            id: Some(*b"BLK\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"),
            #[cfg(windows)]
            io_concurrency: NonZeroU32::new(1).unwrap(),
            multiple_workers: false,
            async_executor: Some(ExecutorKind::default()),
        };
        let json = serde_json::to_string(&original).unwrap();
        let deserialized = serde_json::from_str(&json).unwrap();
        assert_eq!(original, deserialized);

        // With id taking all the available space.
        let original = DiskOption {
            path: "./rootfs".into(),
            read_only: false,
            root: false,
            sparse: true,
            direct: false,
            block_size: 512,
            id: Some(*b"QWERTYUIOPASDFGHJKL:"),
            #[cfg(windows)]
            io_concurrency: NonZeroU32::new(1).unwrap(),
            multiple_workers: false,
            async_executor: Some(ExecutorKind::default()),
        };
        let json = serde_json::to_string(&original).unwrap();
        let deserialized = serde_json::from_str(&json).unwrap();
        assert_eq!(original, deserialized);
    }
}
