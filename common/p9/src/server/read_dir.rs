// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::CStr;
use std::io::Result;
use std::mem::size_of;
use std::os::unix::io::AsRawFd;

use crate::syscall;

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct LinuxDirent64 {
    d_ino: libc::ino64_t,
    d_off: libc::off64_t,
    d_reclen: libc::c_ushort,
    d_ty: libc::c_uchar,
}

impl LinuxDirent64 {
    // Note: Taken from data_model::DataInit
    fn from_slice(data: &[u8]) -> Option<&Self> {
        // Early out to avoid an unneeded `align_to` call.
        if data.len() != size_of::<Self>() {
            return None;
        }
        // The `align_to` method ensures that we don't have any unaligned references.
        // This aliases a pointer, but because the pointer is from a const slice reference,
        // there are no mutable aliases.
        // Finally, the reference returned can not outlive data because they have equal implicit
        // lifetime constraints.
        match unsafe { data.align_to::<Self>() } {
            ([], [mid], []) => Some(mid),
            _ => None,
        }
    }
}

pub struct DirEntry<'r> {
    pub ino: libc::ino64_t,
    pub offset: u64,
    pub type_: u8,
    pub name: &'r CStr,
}

pub struct ReadDir<'d, D> {
    buf: [u8; 256],
    dir: &'d mut D,
    current: usize,
    end: usize,
}

impl<'d, D: AsRawFd> ReadDir<'d, D> {
    /// Return the next directory entry. This is implemented as a separate method rather than via
    /// the `Iterator` trait because rust doesn't currently support generic associated types.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<Result<DirEntry>> {
        if self.current >= self.end {
            let res: Result<libc::c_long> = syscall!(unsafe {
                libc::syscall(
                    libc::SYS_getdents64,
                    self.dir.as_raw_fd(),
                    self.buf.as_mut_ptr() as *mut LinuxDirent64,
                    self.buf.len() as libc::c_int,
                )
            });
            match res {
                Ok(end) => {
                    self.current = 0;
                    self.end = end as usize;
                }
                Err(e) => return Some(Err(e)),
            }
        }

        let rem = &self.buf[self.current..self.end];
        if rem.is_empty() {
            return None;
        }

        // We only use debug asserts here because these values are coming from the kernel and we
        // trust them implicitly.
        debug_assert!(
            rem.len() >= size_of::<LinuxDirent64>(),
            "not enough space left in `rem`"
        );

        let (front, back) = rem.split_at(size_of::<LinuxDirent64>());

        let dirent64 =
            LinuxDirent64::from_slice(front).expect("unable to get LinuxDirent64 from slice");

        let namelen = dirent64.d_reclen as usize - size_of::<LinuxDirent64>();
        debug_assert!(namelen <= back.len(), "back is smaller than `namelen`");

        // The kernel will pad the name with additional nul bytes until it is 8-byte aligned so
        // we need to strip those off here.
        let name = strip_padding(&back[..namelen]);
        let entry = DirEntry {
            ino: dirent64.d_ino,
            offset: dirent64.d_off as u64,
            type_: dirent64.d_ty,
            name,
        };

        debug_assert!(
            rem.len() >= dirent64.d_reclen as usize,
            "rem is smaller than `d_reclen`"
        );
        self.current += dirent64.d_reclen as usize;
        Some(Ok(entry))
    }
}

pub fn read_dir<D: AsRawFd>(dir: &mut D, offset: libc::off64_t) -> Result<ReadDir<D>> {
    // Safe because this doesn't modify any memory and we check the return value.
    syscall!(unsafe { libc::lseek64(dir.as_raw_fd(), offset, libc::SEEK_SET) })?;

    Ok(ReadDir {
        buf: [0u8; 256],
        dir,
        current: 0,
        end: 0,
    })
}

// Like `CStr::from_bytes_with_nul` but strips any bytes after the first '\0'-byte. Panics if `b`
// doesn't contain any '\0' bytes.
fn strip_padding(b: &[u8]) -> &CStr {
    // It would be nice if we could use memchr here but that's locked behind an unstable gate.
    let pos = b
        .iter()
        .position(|&c| c == 0)
        .expect("`b` doesn't contain any nul bytes");

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
