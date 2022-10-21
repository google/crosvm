// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(windows)]
use std::num::NonZeroU32;
use std::path::PathBuf;

use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;

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

fn deserialize_disk_id<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<[u8; DISK_ID_LEN]>, D::Error> {
    let id = String::deserialize(deserializer)?;

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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, serde_keyvalue::FromKeyValues)]
#[serde(deny_unknown_fields)]
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
    #[serde(default)]
    pub o_direct: bool,
    #[serde(default = "block_option_block_size_default")]
    pub block_size: u32,
    #[serde(default, deserialize_with = "deserialize_disk_id")]
    pub id: Option<[u8; DISK_ID_LEN]>,
    #[cfg(windows)]
    #[serde(default = "block_option_io_concurrency_default")]
    pub io_concurrency: NonZeroU32,
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
                o_direct: false,
                block_size: 512,
                id: None,
                #[cfg(windows)]
                io_concurrency: NonZeroU32::new(1).unwrap(),
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
                o_direct: false,
                block_size: 512,
                id: None,
                #[cfg(windows)]
                io_concurrency: NonZeroU32::new(1).unwrap(),
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
                o_direct: false,
                block_size: 512,
                id: None,
                #[cfg(windows)]
                io_concurrency: NonZeroU32::new(1).unwrap(),
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
                o_direct: false,
                block_size: 512,
                id: None,
                #[cfg(windows)]
                io_concurrency: NonZeroU32::new(1).unwrap(),
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
                o_direct: false,
                block_size: 512,
                id: None,
                #[cfg(windows)]
                io_concurrency: NonZeroU32::new(1).unwrap(),
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
                o_direct: false,
                block_size: 512,
                id: None,
                #[cfg(windows)]
                io_concurrency: NonZeroU32::new(1).unwrap(),
            }
        );

        // o_direct
        let params = from_block_arg("/some/path.img,o_direct").unwrap();
        assert_eq!(
            params,
            DiskOption {
                path: "/some/path.img".into(),
                read_only: false,
                root: false,
                sparse: true,
                o_direct: true,
                block_size: 512,
                id: None,
                #[cfg(windows)]
                io_concurrency: NonZeroU32::new(1).unwrap(),
            }
        );

        // block_size
        let params = from_block_arg("/some/path.img,block_size=128").unwrap();
        assert_eq!(
            params,
            DiskOption {
                path: "/some/path.img".into(),
                read_only: false,
                root: false,
                sparse: true,
                o_direct: false,
                block_size: 128,
                id: None,
                #[cfg(windows)]
                io_concurrency: NonZeroU32::new(1).unwrap(),
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
                    o_direct: false,
                    block_size: 512,
                    id: None,
                    io_concurrency: NonZeroU32::new(4).unwrap(),
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
                o_direct: false,
                block_size: 512,
                id: Some(*b"DISK\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"),
                #[cfg(windows)]
                io_concurrency: NonZeroU32::new(1).unwrap(),
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

        // All together
        let params = from_block_arg(
            "/some/path.img,block_size=256,ro,root,sparse=false,id=DISK_LABEL,o_direct",
        )
        .unwrap();
        assert_eq!(
            params,
            DiskOption {
                path: "/some/path.img".into(),
                read_only: true,
                root: true,
                sparse: false,
                o_direct: true,
                block_size: 256,
                id: Some(*b"DISK_LABEL\0\0\0\0\0\0\0\0\0\0"),
                #[cfg(windows)]
                io_concurrency: NonZeroU32::new(1).unwrap(),
            }
        );
    }
}
