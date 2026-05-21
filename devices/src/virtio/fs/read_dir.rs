// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::CStr;
use std::io;
use std::mem::size_of;
use std::ops::Deref;
use std::ops::DerefMut;

use base::AsRawDescriptor;
use fuse::filesystem::DirEntry;
use fuse::filesystem::DirectoryIterator;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

use crate::virtio::fs::allowlist::PathAllowlist;

#[repr(C, packed)]
#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout)]
struct LinuxDirent64 {
    d_ino: libc::ino64_t,
    d_off: libc::off64_t,
    d_reclen: libc::c_ushort,
    d_ty: libc::c_uchar,
}

pub struct ReadDir<P> {
    buf: P,
    current: usize,
    end: usize,
    allowlist_context: Option<(String, PathAllowlist)>,
}

impl<P> ReadDir<P> {
    pub fn with_allowlist(mut self, parent_path: String, allowlist: PathAllowlist) -> Self {
        self.allowlist_context = Some((parent_path, allowlist));
        self
    }
}

impl<P: DerefMut<Target = [u8]>> ReadDir<P> {
    pub fn new<D: AsRawDescriptor>(dir: &D, offset: libc::off64_t, mut buf: P) -> io::Result<Self> {
        // SAFETY:
        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe { libc::lseek64(dir.as_raw_descriptor(), offset, libc::SEEK_SET) };
        if res < 0 {
            return Err(io::Error::last_os_error());
        }

        // SAFETY:
        // Safe because the kernel guarantees that it will only write to `buf` and we check the
        // return value.
        let res = unsafe {
            libc::syscall(
                libc::SYS_getdents64,
                dir.as_raw_descriptor(),
                buf.as_mut_ptr() as *mut LinuxDirent64,
                buf.len() as libc::c_int,
            )
        };
        if res < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(ReadDir {
            buf,
            current: 0,
            end: res as usize,
            allowlist_context: None,
        })
    }
}

impl<P> ReadDir<P> {
    /// Returns the number of bytes from the internal buffer that have not yet been consumed.
    pub fn remaining(&self) -> usize {
        self.end.saturating_sub(self.current)
    }
}

impl<P: Deref<Target = [u8]>> DirectoryIterator for ReadDir<P> {
    fn next(&mut self) -> Option<DirEntry> {
        loop {
            let rem = &self.buf[self.current..self.end];
            if rem.is_empty() {
                return None;
            }

            let (dirent64, back) = LinuxDirent64::read_from_prefix(rem)
                .expect("unable to get LinuxDirent64 from slice");

            let namelen = dirent64.d_reclen as usize - size_of::<LinuxDirent64>();
            debug_assert!(namelen <= back.len(), "back is smaller than `namelen`");

            let name = strip_padding(&back[..namelen]);
            let entry = DirEntry {
                ino: dirent64.d_ino,
                offset: dirent64.d_off as u64,
                type_: dirent64.d_ty as u32,
                name,
            };

            debug_assert!(
                rem.len() >= dirent64.d_reclen as usize,
                "rem is smaller than `d_reclen`"
            );
            self.current += dirent64.d_reclen as usize;

            // Apply dynamic path allowlist filtering.
            // If the resolved full path of an entry is not accessible according to the allowlist,
            // we skip the entry (hide it from directory listings).
            if let Some((parent_path, allowlist)) = &self.allowlist_context {
                let name_str = match entry.name.to_str() {
                    Ok(s) => s,
                    Err(_) => {
                        // Skip entries with invalid UTF-8 names since they cannot be
                        // validated against the string-based allowlist.
                        base::debug!("Skipping non-UTF-8 directory entry: {:?}", entry.name);
                        continue;
                    }
                };
                if name_str != "." && name_str != ".." {
                    let full_path = if parent_path == "/" {
                        format!("/{name_str}")
                    } else {
                        format!("{parent_path}/{name_str}")
                    };
                    if !allowlist.is_accessible(&full_path) {
                        // Skip this entry and check the next one (hide from guest)
                        continue;
                    }
                }
            }

            return Some(entry);
        }
    }
}

// Like `CStr::from_bytes_with_nul` but strips any bytes after the first '\0'-byte. Panics if `b`
// doesn't contain any '\0' bytes.
fn strip_padding(b: &[u8]) -> &CStr {
    // It would be nice if we could use memchr here but that's locked behind an unstable gate.
    let pos = b
        .iter()
        .position(|&c| c == 0)
        .expect("`b` doesn't contain any nul bytes");

    // SAFETY:
    // Safe because we are creating this string with the first nul-byte we found so we can
    // guarantee that it is nul-terminated and doesn't contain any interior nuls.
    unsafe { CStr::from_bytes_with_nul_unchecked(&b[..pos + 1]) }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn padded_cstrings() {
        assert_eq!(strip_padding(b".\0\0\0\0\0\0\0").to_bytes(), b".");
        assert_eq!(strip_padding(b"..\0\0\0\0\0\0").to_bytes(), b"..");
        assert_eq!(
            strip_padding(b"normal cstring\0").to_bytes(),
            b"normal cstring"
        );
        assert_eq!(strip_padding(b"\0\0\0\0").to_bytes(), b"");
        assert_eq!(
            strip_padding(b"interior\0nul bytes\0\0\0").to_bytes(),
            b"interior"
        );
    }

    #[test]
    #[should_panic(expected = "`b` doesn't contain any nul bytes")]
    fn no_nul_byte() {
        strip_padding(b"no nul bytes in string");
    }
}
