// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Provides utilites for extended attributes.

use std::ffi::c_char;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

use crate::inode::Inode;

fn listxattr(path: &CString) -> Result<Vec<Vec<u8>>> {
    // SAFETY: Passing valid pointers and values.
    let size = unsafe { libc::llistxattr(path.as_ptr(), std::ptr::null_mut(), 0) };
    if size < 0 {
        bail!(
            "failed to get xattr size: {}",
            std::io::Error::last_os_error()
        );
    }

    if size == 0 {
        // No extended attributes were set.
        return Ok(vec![]);
    }

    let mut buf = vec![0 as c_char; size as usize];

    // SAFETY: Passing valid pointers and values.
    let size = unsafe { libc::llistxattr(path.as_ptr(), buf.as_mut_ptr(), buf.len()) };
    if size < 0 {
        bail!(
            "failed to list of xattr: {}",
            std::io::Error::last_os_error()
        );
    }

    buf.pop(); // Remove null terminator

    // While `c_char` is `i8` on x86_64, it's `u8` on ARM. So, disable the clippy for the cast.
    #[cfg_attr(
        any(target_arch = "arm", target_arch = "aarch64"),
        allow(clippy::unnecessary_cast)
    )]
    let keys = buf
        .split(|c| *c == 0)
        .map(|v| v.iter().map(|c| *c as u8).collect::<Vec<_>>())
        .collect::<Vec<Vec<_>>>();

    Ok(keys)
}

fn lgetxattr(path: &CString, name: &CString) -> Result<Vec<u8>> {
    // SAFETY: passing valid pointers.
    let size = unsafe { libc::lgetxattr(path.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };
    if size < 0 {
        bail!(
            "failed to get xattr size for {:?}: {}",
            name,
            std::io::Error::last_os_error()
        );
    }
    let mut buf = vec![0; size as usize];
    // SAFETY: passing valid pointers and length.
    let size = unsafe {
        libc::lgetxattr(
            path.as_ptr(),
            name.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
        )
    };
    if size < 0 {
        bail!(
            "failed to get xattr for {:?}: {}",
            name,
            std::io::Error::last_os_error()
        );
    }

    Ok(buf)
}

/// Retrieves the list of pairs of a name and a value of the extended attribute of the given `path`.
/// If `path` is a symbolic link, it won't be followed and the value of the symlink itself is
/// returned.
/// The return values are byte arrays WITHOUT trailing NULL byte.
pub fn dump_xattrs(path: &Path) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut path_vec = path.as_os_str().as_bytes().to_vec();
    path_vec.push(0);
    let path_str = CString::from_vec_with_nul(path_vec)?;

    let keys = listxattr(&path_str).context("failed to listxattr")?;

    let mut kvs = vec![];
    for key in keys {
        let mut key_vec = key.to_vec();
        key_vec.push(0);
        let name = CString::from_vec_with_nul(key_vec)?;

        let buf = lgetxattr(&path_str, &name).context("failed to getxattr")?;
        kvs.push((key.to_vec(), buf));
    }

    Ok(kvs)
}

/// Sets the extended attribute of the given `path` with the given `key` and `value`.
pub fn set_xattr(path: &Path, key: &str, value: &str) -> Result<()> {
    let mut path_bytes = path
        .as_os_str()
        .as_bytes()
        .iter()
        .map(|i| *i as c_char)
        .collect::<Vec<_>>();
    path_bytes.push(0); // null terminator

    // While name must be a nul-terminated string, value is not, as it can be a binary data.
    let mut key_vec = key.bytes().collect::<Vec<_>>();
    key_vec.push(0);
    let name = CString::from_vec_with_nul(key_vec)?;
    let v = value.bytes().collect::<Vec<_>>();

    // SAFETY: `path_bytes` and `nam` are null-terminated byte arrays.
    // `v` is valid data.
    let size = unsafe {
        libc::lsetxattr(
            path_bytes.as_ptr(),
            name.as_ptr(),
            v.as_ptr() as *const libc::c_void,
            v.len(),
            0,
        )
    };
    if size != 0 {
        bail!(
            "failed to set xattr for {:?}: {}",
            path,
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

#[repr(C)]
#[derive(Default, Debug, Copy, Clone, FromZeroes, FromBytes, AsBytes)]
pub(crate) struct XattrEntry {
    name_len: u8,
    name_index: u8,
    value_offs: u16,
    value_inum: u32,
    value_size: u32,
    hash: u32,
    // name[name_len] follows
}

impl XattrEntry {
    /// Creates a new `XattrEntry` instance with the name as a byte sequence that follows.
    pub(crate) fn new_with_name<'a>(
        name: &'a [u8],
        value: &[u8],
        value_offs: u16,
    ) -> Result<(Self, &'a [u8])> {
        let (name_index, key_str) = Self::split_key_prefix(name);
        let name_len = key_str.len() as u8;
        let value_size = value.len() as u32;
        Ok((
            XattrEntry {
                name_len,
                name_index,
                value_offs,
                value_inum: 0,
                value_size,
                hash: 0,
            },
            key_str,
        ))
    }

    /// Split the given xatrr key string into it's prefix's name index and the remaining part.
    /// e.g. "user.foo" -> (1, "foo") because the key prefix "user." has index 1.
    fn split_key_prefix(name: &[u8]) -> (u8, &[u8]) {
        // ref. https://docs.kernel.org/filesystems/ext4/dynamic.html#attribute-name-indices
        for (name_index, key_prefix) in [
            (1, "user."),
            (2, "system.posix_acl_access"),
            (3, "system.posix_acl_default"),
            (4, "trusted."),
            // 5 is skipped
            (6, "security."),
            (7, "system."),
            (8, "system.richacl"),
        ] {
            let prefix_bytes = key_prefix.as_bytes();
            if name.starts_with(prefix_bytes) {
                return (name_index, &name[prefix_bytes.len()..]);
            }
        }
        (0, name)
    }
}

/// Xattr data written into Inode's inline xattr space.
#[derive(Default, Debug, PartialEq, Eq)]
pub struct InlineXattrs {
    pub entry_table: Vec<u8>,
    pub values: Vec<u8>,
}

fn align<T: Clone + Default>(mut v: Vec<T>, alignment: usize) -> Vec<T> {
    let aligned = v.len().next_multiple_of(alignment);
    v.extend(vec![T::default(); aligned - v.len()]);
    v
}

const XATTR_HEADER_MAGIC: u32 = 0xEA020000;

impl InlineXattrs {
    // Creates `InlineXattrs` for the given path.
    pub fn from_path(path: &Path) -> Result<Self> {
        let v = dump_xattrs(path).with_context(|| format!("failed to get xattr for {:?}", path))?;

        // Assume all the data are in inode record.
        let mut entry_table = vec![];
        let mut values = vec![];
        // Data layout of the inline Inode record is as follows.
        //
        // | Inode struct | header | extra region |
        //  <--------- Inode record  ------------>
        //
        // The value `val_offset` below is an offset from the beginning of the extra region and used
        // to indicate the place where the next xattr value will be written. While we place
        // attribute entries from the beginning of the extra region, we place values from the end of
        // the region. So the initial value of `val_offset` indicates the end of the extra
        // region.
        //
        // See Table 5.1. at https://www.nongnu.org/ext2-doc/ext2.html#extended-attribute-layout for the more details on data layout.
        // Although this table is for xattr in a separate block, data layout is same.
        let mut val_offset = Inode::INODE_RECORD_SIZE
            - std::mem::size_of::<Inode>()
            - std::mem::size_of_val(&XATTR_HEADER_MAGIC);

        entry_table.extend(XATTR_HEADER_MAGIC.to_le_bytes());
        for (name, value) in v {
            let aligned_val_len = value.len().next_multiple_of(4);

            if entry_table.len()
                + values.len()
                + std::mem::size_of::<XattrEntry>()
                + aligned_val_len
                > Inode::XATTR_AREA_SIZE
            {
                bail!("Xattr entry is too large");
            }

            val_offset -= aligned_val_len;
            let (entry, name) = XattrEntry::new_with_name(&name, &value, val_offset as u16)?;
            entry_table.extend(entry.as_bytes());
            entry_table.extend(name);
            entry_table = align(entry_table, 4);
            values.push(align(value, 4));
        }
        let values = values.iter().rev().flatten().copied().collect::<Vec<_>>();

        Ok(Self {
            entry_table,
            values,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::BTreeMap;
    use std::fs::File;

    use tempfile::tempdir;

    use super::*;

    fn to_char_array(s: &str) -> Vec<u8> {
        s.bytes().collect()
    }

    #[test]
    fn test_attr_name_index() {
        assert_eq!(
            XattrEntry::split_key_prefix(b"user.foo"),
            (1, "foo".as_bytes())
        );
        assert_eq!(
            XattrEntry::split_key_prefix(b"trusted.bar"),
            (4, "bar".as_bytes())
        );
        assert_eq!(
            XattrEntry::split_key_prefix(b"security.abcdefgh"),
            (6, "abcdefgh".as_bytes())
        );

        // "system."-prefix
        assert_eq!(
            XattrEntry::split_key_prefix(b"system.posix_acl_access"),
            (2, "".as_bytes())
        );
        assert_eq!(
            XattrEntry::split_key_prefix(b"system.posix_acl_default"),
            (3, "".as_bytes())
        );
        assert_eq!(
            XattrEntry::split_key_prefix(b"system.abcdefgh"),
            (7, "abcdefgh".as_bytes())
        );

        // unmatched prefix
        assert_eq!(
            XattrEntry::split_key_prefix(b"invalid.foo"),
            (0, "invalid.foo".as_bytes())
        );
    }

    #[test]
    fn test_get_xattr_empty() {
        let td = tempdir().unwrap();
        let test_path = td.path().join("test.txt");

        // Don't set any extended attributes.
        File::create(&test_path).unwrap();

        let kvs = dump_xattrs(&test_path).unwrap();
        assert_eq!(kvs.len(), 0);
    }

    #[test]
    fn test_inline_xattr_from_path() {
        let td = tempdir().unwrap();
        let test_path = td.path().join("test.txt");
        File::create(&test_path).unwrap();

        let key = "key";
        let xattr_key = &format!("user.{key}");
        let value = "value";

        set_xattr(&test_path, xattr_key, value).unwrap();

        let xattrs = InlineXattrs::from_path(&test_path).unwrap();
        let entry = XattrEntry {
            name_len: key.len() as u8,
            name_index: 1,
            value_offs: (Inode::INODE_RECORD_SIZE
                - std::mem::size_of::<Inode>()
                - std::mem::size_of_val(&XATTR_HEADER_MAGIC)
                - value.len().next_multiple_of(4)) as u16,
            value_size: value.len() as u32,
            value_inum: 0,
            ..Default::default()
        };
        assert_eq!(
            xattrs.entry_table,
            align(
                [
                    XATTR_HEADER_MAGIC.to_le_bytes().to_vec(),
                    entry.as_bytes().to_vec(),
                    key.as_bytes().to_vec(),
                ]
                .concat(),
                4
            ),
        );
        assert_eq!(xattrs.values, align(value.as_bytes().to_vec(), 4),);
    }

    #[test]
    fn test_too_many_values_for_inline_xattr() {
        let td = tempdir().unwrap();
        let test_path = td.path().join("test.txt");
        File::create(&test_path).unwrap();

        // Prepare 10 pairs of xattributes, which will not fit inline space.
        let mut xattr_pairs = vec![];
        for i in 0..10 {
            xattr_pairs.push((format!("user.foo{i}"), "bar"));
        }

        for (key, value) in &xattr_pairs {
            set_xattr(&test_path, key, value).unwrap();
        }

        // Must fail
        InlineXattrs::from_path(&test_path).unwrap_err();
    }

    #[test]
    fn test_get_xattr() {
        let td = tempdir().unwrap();
        let test_path = td.path().join("test.txt");
        File::create(&test_path).unwrap();

        let xattr_pairs = vec![
            ("user.foo", "bar"),
            ("user.hash", "09f7e02f1290be211da707a266f153b3"),
            ("user.empty", ""),
        ];

        for (key, value) in &xattr_pairs {
            set_xattr(&test_path, key, value).unwrap();
        }

        let kvs = dump_xattrs(&test_path).unwrap();
        assert_eq!(kvs.len(), xattr_pairs.len());

        let xattr_map: BTreeMap<Vec<u8>, Vec<u8>> = kvs.into_iter().collect();

        for (orig_k, orig_v) in xattr_pairs {
            let k = to_char_array(orig_k);
            let v = to_char_array(orig_v);
            let got = xattr_map.get(&k).unwrap();
            assert_eq!(&v, got);
        }
    }

    #[test]
    fn test_get_xattr_symlink() {
        let td = tempdir().unwrap();

        // Set xattr on test.txt.
        let test_path = td.path().join("test.txt");
        File::create(&test_path).unwrap();
        set_xattr(&test_path, "user.name", "user.test.txt").unwrap();

        // Create a symlink to test.txt.
        let symlink_path = td.path().join("symlink");
        std::os::unix::fs::symlink(&test_path, &symlink_path).unwrap();

        // dump_xattrs shouldn't follow a symlink.
        let kvs = dump_xattrs(&symlink_path).unwrap();
        assert_eq!(kvs, vec![]);
    }
}
