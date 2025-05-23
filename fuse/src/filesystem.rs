// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Data structures and traits for the fuse filesystem.

#![deny(missing_docs)]

use std::convert::TryInto;
use std::ffi::CStr;
use std::fs::File;
use std::io;
use std::mem;
use std::mem::MaybeUninit;
use std::time::Duration;

use crate::server::Mapper;
use crate::sys;
pub use crate::sys::FsOptions;
pub use crate::sys::IoctlFlags;
pub use crate::sys::IoctlIovec;
pub use crate::sys::OpenOptions;
pub use crate::sys::RemoveMappingOne;
pub use crate::sys::SetattrValid;
pub use crate::sys::ROOT_ID;

const MAX_BUFFER_SIZE: u32 = 1 << 20;

/// Information about a path in the filesystem.
#[derive(Debug)]
pub struct Entry {
    /// An `Inode` that uniquely identifies this path. During `lookup`, setting this to `0` means a
    /// negative entry. Returning `ENOENT` also means a negative entry but setting this to `0`
    /// allows the kernel to cache the negative result for `entry_timeout`. The value should be
    /// produced by converting a `FileSystem::Inode` into a `u64`.
    pub inode: u64,

    /// The generation number for this `Entry`. Typically used for network file systems. An `inode`
    /// / `generation` pair must be unique over the lifetime of the file system (rather than just
    /// the lifetime of the mount). In other words, if a `FileSystem` implementation re-uses an
    /// `Inode` after it has been deleted then it must assign a new, previously unused generation
    /// number to the `Inode` at the same time.
    pub generation: u64,

    /// Inode attributes. Even if `attr_timeout` is zero, `attr` must be correct. For example, for
    /// `open()`, FUSE uses `attr.st_size` from `lookup()` to determine how many bytes to request.
    /// If this value is not correct, incorrect data will be returned.
    pub attr: libc::stat64,

    /// How long the values in `attr` should be considered valid. If the attributes of the `Entry`
    /// are only modified by the FUSE client, then this should be set to a very large value.
    pub attr_timeout: Duration,

    /// How long the name associated with this `Entry` should be considered valid. If directory
    /// entries are only changed or deleted by the FUSE client, then this should be set to a very
    /// large value.
    pub entry_timeout: Duration,
}

impl From<Entry> for sys::EntryOut {
    fn from(entry: Entry) -> sys::EntryOut {
        sys::EntryOut {
            nodeid: entry.inode,
            generation: entry.generation,
            entry_valid: entry.entry_timeout.as_secs(),
            attr_valid: entry.attr_timeout.as_secs(),
            entry_valid_nsec: entry.entry_timeout.subsec_nanos(),
            attr_valid_nsec: entry.attr_timeout.subsec_nanos(),
            attr: entry.attr.into(),
        }
    }
}

impl Entry {
    /// Creates a new negative cache entry. A negative d_entry has an inode number of 0, and is
    /// valid for the duration of `negative_timeout`.
    ///
    /// # Arguments
    ///
    /// * `negative_timeout` - The duration for which this negative d_entry should be considered
    ///   valid. After the timeout expires, the d_entry will be invalidated.
    ///
    /// # Returns
    ///
    /// A new negative entry with provided entry timeout and 0 attr timeout.
    pub fn new_negative(negative_timeout: Duration) -> Entry {
        let attr = MaybeUninit::<libc::stat64>::zeroed();
        Entry {
            inode: 0, // Using 0 for negative entry
            entry_timeout: negative_timeout,
            // Zero-fill other fields that won't be used.
            attr_timeout: Duration::from_secs(0),
            generation: 0,
            // SAFETY: zero-initialized `stat64` is a valid value.
            attr: unsafe { attr.assume_init() },
        }
    }
}

/// Represents information about an entry in a directory.
pub struct DirEntry<'a> {
    /// The inode number for this entry. This does NOT have to be the same as the `Inode` for this
    /// directory entry. However, it must be the same as the `attr.st_ino` field of the `Entry`
    /// that would be returned by a `lookup` request in the parent directory for `name`.
    pub ino: libc::ino64_t,

    /// Any non-zero value that the kernel can use to identify the current point in the directory
    /// entry stream. It does not need to be the actual physical position. A value of `0` is
    /// reserved to mean "from the beginning" and should never be used. The `offset` value of the
    /// first entry in a stream should point to the beginning of the second entry and so on.
    pub offset: u64,

    /// The type of this directory entry. Valid values are any of the `libc::DT_*` constants.
    pub type_: u32,

    /// The name of this directory entry. There are no requirements for the contents of this field
    /// and any sequence of bytes is considered valid.
    pub name: &'a CStr,
}

/// A reply to a `getxattr` method call.
#[derive(Debug)]
pub enum GetxattrReply {
    /// The value of the requested extended attribute. This can be arbitrary textual or binary data
    /// and does not need to be nul-terminated.
    Value(Vec<u8>),

    /// The size of the buffer needed to hold the value of the requested extended attribute. Should
    /// be returned when the `size` parameter is 0. Callers should note that it is still possible
    /// for the size of the value to change in between `getxattr` calls and should not assume that
    /// a subsequent call to `getxattr` with the returned count will always succeed.
    Count(u32),
}

/// A reply to a `listxattr` method call.
pub enum ListxattrReply {
    /// A buffer containing a nul-separated list of the names of all the extended attributes
    /// associated with this `Inode`. This list of names may be unordered and includes a namespace
    /// prefix. There may be several disjoint namespaces associated with a single `Inode`.
    Names(Vec<u8>),

    /// This size of the buffer needed to hold the full list of extended attribute names associated
    /// with this `Inode`. Should be returned when the `size` parameter is 0. Callers should note
    /// that it is still possible for the set of extended attributes to change between `listxattr`
    /// calls and so should not assume that a subsequent call to `listxattr` with the returned
    /// count will always succeed.
    Count(u32),
}

/// A reply to an `ioctl` method call.
#[derive(Debug)]
pub enum IoctlReply {
    /// Indicates that the ioctl should be retried. This is only a valid reply when the `flags`
    /// field of the ioctl request contains `IoctlFlags::UNRESTRICTED`. The kernel will read in
    /// data and prepare output buffers as specified in the `input` and `output` fields before
    /// re-sending the ioctl message.
    Retry {
        /// Data that should be read by the kernel module and sent to the server when the ioctl is
        /// retried.
        input: Vec<IoctlIovec>,

        /// Buffer space that should be prepared so that the server can send back the response to
        /// the ioctl.
        output: Vec<IoctlIovec>,
    },

    /// Indicates that the ioctl was processed.
    Done(io::Result<Vec<u8>>),
}

/// A trait for directly copying data from the fuse transport into a `File` without first storing it
/// in an intermediate buffer.
pub trait ZeroCopyReader {
    /// Copies at most `count` bytes from `self` directly into `f` at offset `off` without storing
    /// it in any intermediate buffers. If the return value is `Ok(n)` then it must be guaranteed
    /// that `0 <= n <= count`. If `n` is `0`, then it can indicate one of 3 possibilities:
    ///
    /// 1. There is no more data left in `self`.
    /// 2. There is no more space in `f`.
    /// 3. `count` was `0`.
    ///
    /// # Errors
    ///
    /// If any error is returned then the implementation must guarantee that no bytes were copied
    /// from `self`. If the underlying write to `f` returns `0` then the implementation must return
    /// an error of the kind `io::ErrorKind::WriteZero`.
    fn read_to(&mut self, f: &mut File, count: usize, off: u64) -> io::Result<usize>;

    /// Copies exactly `count` bytes of data from `self` into `f` at offset `off`. `off + count`
    /// must be less than `u64::MAX`.
    ///
    /// # Errors
    ///
    /// If an error is returned then the number of bytes copied from `self` is unspecified but it
    /// will never be more than `count`.
    fn read_exact_to(&mut self, f: &mut File, mut count: usize, mut off: u64) -> io::Result<()> {
        let c = count
            .try_into()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        if off.checked_add(c).is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "`off` + `count` must be less than u64::MAX",
            ));
        }

        while count > 0 {
            match self.read_to(f, count, off) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to fill whole buffer",
                    ))
                }
                Ok(n) => {
                    count -= n;
                    off += n as u64;
                }
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }

    /// Copies all remaining bytes from `self` into `f` at offset `off`. Equivalent to repeatedly
    /// calling `read_to` until it returns either `Ok(0)` or a non-`ErrorKind::Interrupted` error.
    ///
    /// # Errors
    ///
    /// If an error is returned then the number of bytes copied from `self` is unspecified.
    fn copy_to_end(&mut self, f: &mut File, mut off: u64) -> io::Result<usize> {
        let mut out = 0;
        loop {
            match self.read_to(f, usize::MAX, off) {
                Ok(0) => return Ok(out),
                Ok(n) => {
                    off = off.saturating_add(n as u64);
                    out += n;
                }
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }
}

impl<R: ZeroCopyReader> ZeroCopyReader for &mut R {
    fn read_to(&mut self, f: &mut File, count: usize, off: u64) -> io::Result<usize> {
        (**self).read_to(f, count, off)
    }
    fn read_exact_to(&mut self, f: &mut File, count: usize, off: u64) -> io::Result<()> {
        (**self).read_exact_to(f, count, off)
    }
    fn copy_to_end(&mut self, f: &mut File, off: u64) -> io::Result<usize> {
        (**self).copy_to_end(f, off)
    }
}

/// A trait for directly copying data from a `File` into the fuse transport without first storing
/// it in an intermediate buffer.
pub trait ZeroCopyWriter {
    /// Copies at most `count` bytes from `f` at offset `off` directly into `self` without storing
    /// it in any intermediate buffers. If the return value is `Ok(n)` then it must be guaranteed
    /// that `0 <= n <= count`. If `n` is `0`, then it can indicate one of 3 possibilities:
    ///
    /// 1. There is no more data left in `f`.
    /// 2. There is no more space in `self`.
    /// 3. `count` was `0`.
    ///
    /// # Errors
    ///
    /// If any error is returned then the implementation must guarantee that no bytes were copied
    /// from `f`. If the underlying read from `f` returns `0` then the implementation must return an
    /// error of the kind `io::ErrorKind::UnexpectedEof`.
    fn write_from(&mut self, f: &mut File, count: usize, off: u64) -> io::Result<usize>;

    /// Copies exactly `count` bytes of data from `f` at offset `off` into `self`. `off + count`
    /// must be less than `u64::MAX`.
    ///
    /// # Errors
    ///
    /// If an error is returned then the number of bytes copied from `self` is unspecified but it
    /// well never be more than `count`.
    fn write_all_from(&mut self, f: &mut File, mut count: usize, mut off: u64) -> io::Result<()> {
        let c = count
            .try_into()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        if off.checked_add(c).is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "`off` + `count` must be less than u64::MAX",
            ));
        }

        while count > 0 {
            match self.write_from(f, count, off) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "failed to write whole buffer",
                    ))
                }
                Ok(n) => {
                    // No need for checked math here because we verified that `off + count` will not
                    // overflow and `n` must be <= `count`.
                    count -= n;
                    off += n as u64;
                }
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }

    /// Copies all remaining bytes from `f` at offset `off` into `self`. Equivalent to repeatedly
    /// calling `write_from` until it returns either `Ok(0)` or a non-`ErrorKind::Interrupted`
    /// error.
    ///
    /// # Errors
    ///
    /// If an error is returned then the number of bytes copied from `f` is unspecified.
    fn copy_to_end(&mut self, f: &mut File, mut off: u64) -> io::Result<usize> {
        let mut out = 0;
        loop {
            match self.write_from(f, usize::MAX, off) {
                Ok(0) => return Ok(out),
                Ok(n) => {
                    off = off.saturating_add(n as u64);
                    out += n;
                }
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }
}

impl<W: ZeroCopyWriter> ZeroCopyWriter for &mut W {
    fn write_from(&mut self, f: &mut File, count: usize, off: u64) -> io::Result<usize> {
        (**self).write_from(f, count, off)
    }
    fn write_all_from(&mut self, f: &mut File, count: usize, off: u64) -> io::Result<()> {
        (**self).write_all_from(f, count, off)
    }
    fn copy_to_end(&mut self, f: &mut File, off: u64) -> io::Result<usize> {
        (**self).copy_to_end(f, off)
    }
}

/// Additional context associated with requests.
#[derive(Clone, Copy, Debug)]
pub struct Context {
    /// The user ID of the calling process.
    pub uid: libc::uid_t,

    /// The group ID of the calling process.
    pub gid: libc::gid_t,

    /// The thread group ID of the calling process.
    pub pid: libc::pid_t,
}

impl From<sys::InHeader> for Context {
    fn from(source: sys::InHeader) -> Self {
        Context {
            uid: source.uid,
            gid: source.gid,
            pid: source.pid as i32,
        }
    }
}

/// A trait for iterating over the contents of a directory. This trait is needed because rust
/// doesn't support generic associated types, which means that it's not possible to implement a
/// regular iterator that yields a `DirEntry` due to its generic lifetime parameter.
pub trait DirectoryIterator {
    /// Returns the next entry in the directory or `None` if there are no more.
    fn next(&mut self) -> Option<DirEntry>;
}

/// The main trait that connects a file system with a transport.
#[allow(unused_variables)]
pub trait FileSystem {
    /// Represents a location in the filesystem tree and can be used to perform operations that act
    /// on the metadata of a file/directory (e.g., `getattr` and `setattr`). Can also be used as the
    /// starting point for looking up paths in the filesystem tree. An `Inode` may support operating
    /// directly on the content of the path that to which it points. `FileSystem` implementations
    /// that support this should set the `FsOptions::ZERO_MESSAGE_OPEN` option in the return value
    /// of the `init` function. On linux based systems, an `Inode` is equivalent to opening a file
    /// or directory with the `libc::O_PATH` flag.
    ///
    /// # Lookup Count
    ///
    /// The `FileSystem` implementation is required to keep a "lookup count" for every `Inode`.
    /// Every time an `Entry` is returned by a `FileSystem` trait method, this lookup count should
    /// increase by 1. The lookup count for an `Inode` decreases when the kernel sends a `forget`
    /// request. `Inode`s with a non-zero lookup count may receive requests from the kernel even
    /// after calls to `unlink`, `rmdir` or (when overwriting an existing file) `rename`.
    /// `FileSystem` implementations must handle such requests properly and it is recommended to
    /// defer removal of the `Inode` until the lookup count reaches zero. Calls to `unlink`, `rmdir`
    /// or `rename` will be followed closely by `forget` unless the file or directory is open, in
    /// which case the kernel issues `forget` only after the `release` or `releasedir` calls.
    ///
    /// Note that if a file system will be exported over NFS the `Inode`'s lifetime must extend even
    /// beyond `forget`. See the `generation` field in `Entry`.
    type Inode: From<u64> + Into<u64>;

    /// Represents a file or directory that is open for reading/writing.
    type Handle: From<u64> + Into<u64>;

    /// An iterator over the entries of a directory. See the documentation for `readdir` for more
    /// details.
    type DirIter: DirectoryIterator;

    /// Maximum size of the buffer that the filesystem can generate data to, including the header.
    /// This corresponds to max_write in the initialization.
    fn max_buffer_size(&self) -> u32 {
        MAX_BUFFER_SIZE
    }

    /// Initialize the file system.
    ///
    /// This method is called when a connection to the FUSE kernel module is first established. The
    /// `capable` parameter indicates the features that are supported by the kernel module. The
    /// implementation should return the options that it supports. Any options set in the returned
    /// `FsOptions` that are not also set in `capable` are silently dropped.
    fn init(&self, capable: FsOptions) -> io::Result<FsOptions> {
        Ok(FsOptions::empty())
    }

    /// Clean up the file system.
    ///
    /// Called when the filesystem exits. All open `Handle`s should be closed and the lookup count
    /// for all open `Inode`s implicitly goes to zero. At this point the connection to the FUSE
    /// kernel module may already be gone so implementations should not rely on being able to
    /// communicate with the kernel.
    fn destroy(&self) {}

    /// Look up a directory entry by name and get its attributes.
    ///
    /// If this call is successful then the lookup count of the `Inode` associated with the returned
    /// `Entry` must be increased by 1.
    fn lookup(&self, ctx: Context, parent: Self::Inode, name: &CStr) -> io::Result<Entry> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Forget about an inode.
    ///
    /// Called when the kernel removes an inode from its internal caches. `count` indicates the
    /// amount by which the lookup count for the inode should be decreased. If reducing the lookup
    /// count by `count` causes it to go to zero, then the implementation may delete the `Inode`.
    fn forget(&self, ctx: Context, inode: Self::Inode, count: u64) {}

    /// Forget about multiple inodes.
    ///
    /// `requests` is a vector of `(inode, count)` pairs. See the documentation for `forget` for
    /// more information.
    fn batch_forget(&self, ctx: Context, requests: Vec<(Self::Inode, u64)>) {
        for (inode, count) in requests {
            self.forget(ctx, inode, count)
        }
    }

    /// Get attributes for a file / directory.
    ///
    /// If `handle` is not `None`, then it contains the handle previously returned by the
    /// implementation after a call to `open` or `opendir`. However, implementations should still
    /// take care to verify the handle if they do not trust the client (e.g., virtio-fs).
    ///
    /// If writeback caching is enabled (`FsOptions::WRITEBACK_CACHE`), then the kernel module
    /// likely has a better idea of the length of the file than the file system (for
    /// example, if there was a write that extended the size of the file but has not yet been
    /// flushed). In this case, the `st_size` field of the returned struct is ignored.
    ///
    /// The returned `Duration` indicates how long the returned attributes should be considered
    /// valid by the client. If the attributes are only changed via the FUSE kernel module (i.e.,
    /// the kernel module has exclusive access), then this should be a very large value.
    fn getattr(
        &self,
        ctx: Context,
        inode: Self::Inode,
        handle: Option<Self::Handle>,
    ) -> io::Result<(libc::stat64, Duration)> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Set attributes for a file / directory.
    ///
    /// If `handle` is not `None`, then it contains the handle previously returned by the
    /// implementation after a call to `open` or `opendir`. However, implementations should still
    /// take care to verify the handle if they do not trust the client (e.g., virtio-fs).
    ///
    /// The `valid` parameter indicates the fields of `attr` that may be considered valid and should
    /// be set by the file system. The content of all other fields in `attr` is undefined.
    ///
    /// If the `FsOptions::HANDLE_KILLPRIV` was set during `init`, then the implementation is
    /// expected to reset the setuid and setgid bits if the file size or owner is being changed.
    ///
    /// This method returns the new attributes after making the modifications requested by the
    /// client. The returned `Duration` indicates how long the returned attributes should be
    /// considered valid by the client. If the attributes are only changed via the FUSE kernel
    /// module (i.e., the kernel module has exclusive access), then this should be a very large
    /// value.
    fn setattr(
        &self,
        ctx: Context,
        inode: Self::Inode,
        attr: libc::stat64,
        handle: Option<Self::Handle>,
        valid: SetattrValid,
    ) -> io::Result<(libc::stat64, Duration)> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Read a symbolic link.
    fn readlink(&self, ctx: Context, inode: Self::Inode) -> io::Result<Vec<u8>> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Create a symbolic link.
    ///
    /// The file system must create a symbolic link named `name` in the directory represented by
    /// `parent`, which contains the string `linkname`. Returns an `Entry` for the newly created
    /// symlink.
    ///
    /// If this call is successful then the lookup count of the `Inode` associated with the returned
    /// `Entry` must be increased by 1.
    fn symlink(
        &self,
        ctx: Context,
        linkname: &CStr,
        parent: Self::Inode,
        name: &CStr,
        security_ctx: Option<&CStr>,
    ) -> io::Result<Entry> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Create a file node.
    ///
    /// Create a regular file, character device, block device, fifo, or socket node named `name` in
    /// the directory represented by `inode`. Valid values for `mode` and `rdev` are the same as
    /// those accepted by the `mknod(2)` system call. Returns an `Entry` for the newly created node.
    ///
    /// When the `FsOptions::DONT_MASK` feature is set, the file system is responsible for setting
    /// the permissions of the created node to `mode & !umask`.
    ///
    /// If this call is successful then the lookup count of the `Inode` associated with the returned
    /// `Entry` must be increased by 1.
    fn mknod(
        &self,
        ctx: Context,
        inode: Self::Inode,
        name: &CStr,
        mode: u32,
        rdev: u32,
        umask: u32,
        security_ctx: Option<&CStr>,
    ) -> io::Result<Entry> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Create a directory.
    ///
    /// When the `FsOptions::DONT_MASK` feature is set, the file system is responsible for setting
    /// the permissions of the created directory to `mode & !umask`. Returns an `Entry` for the
    /// newly created directory.
    ///
    /// If this call is successful then the lookup count of the `Inode` associated with the returned
    /// `Entry` must be increased by 1.
    fn mkdir(
        &self,
        ctx: Context,
        parent: Self::Inode,
        name: &CStr,
        mode: u32,
        umask: u32,
        security_ctx: Option<&CStr>,
    ) -> io::Result<Entry> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Create an unnamed temporary file.
    fn chromeos_tmpfile(
        &self,
        ctx: Context,
        parent: Self::Inode,
        mode: u32,
        umask: u32,
        security_ctx: Option<&CStr>,
    ) -> io::Result<Entry> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Remove a file.
    ///
    /// If the file's inode lookup count is non-zero, then the file system is expected to delay
    /// removal of the inode until the lookup count goes to zero. See the documentation of the
    /// `forget` function for more information.
    fn unlink(&self, ctx: Context, parent: Self::Inode, name: &CStr) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Remove a directory.
    ///
    /// If the directory's inode lookup count is non-zero, then the file system is expected to delay
    /// removal of the inode until the lookup count goes to zero. See the documentation of the
    /// `forget` function for more information.
    fn rmdir(&self, ctx: Context, parent: Self::Inode, name: &CStr) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Rename a file / directory.
    ///
    /// If the destination exists, it should be atomically replaced. If the destination's inode
    /// lookup count is non-zero, then the file system is expected to delay removal of the inode
    /// until the lookup count goes to zero. See the documentation of the `forget` function for more
    /// information.
    ///
    /// `flags` may be `libc::RENAME_EXCHANGE` or `libc::RENAME_NOREPLACE`. If
    /// `libc::RENAME_NOREPLACE` is specified, the implementation must not overwrite `newname` if it
    /// exists and must return an error instead. If `libc::RENAME_EXCHANGE` is specified, the
    /// implementation must atomically exchange the two files, i.e., both must exist and neither may
    /// be deleted.
    fn rename(
        &self,
        ctx: Context,
        olddir: Self::Inode,
        oldname: &CStr,
        newdir: Self::Inode,
        newname: &CStr,
        flags: u32,
    ) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Create a hard link.
    ///
    /// Create a hard link from `inode` to `newname` in the directory represented by `newparent`.
    ///
    /// If this call is successful then the lookup count of the `Inode` associated with the returned
    /// `Entry` must be increased by 1.
    fn link(
        &self,
        ctx: Context,
        inode: Self::Inode,
        newparent: Self::Inode,
        newname: &CStr,
    ) -> io::Result<Entry> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Open a file.
    ///
    /// Open the file associated with `inode` for reading / writing. All values accepted by the
    /// `open(2)` system call are valid values for `flags` and must be handled by the file system.
    /// However, there are some additional rules:
    ///
    /// * Creation flags (`libc::O_CREAT`, `libc::O_EXCL`, `libc::O_NOCTTY`) will be filtered out
    ///   and handled by the kernel.
    ///
    /// * The file system should check the access modes (`libc::O_RDONLY`, `libc::O_WRONLY`,
    ///   `libc::O_RDWR`) to determine if the operation is permitted. If the file system was mounted
    ///   with the `-o default_permissions` mount option, then this check will also be carried out
    ///   by the kernel before sending the open request.
    ///
    /// * When writeback caching is enabled (`FsOptions::WRITEBACK_CACHE`) the kernel may send read
    ///   requests even for files opened with `libc::O_WRONLY`. The file system should be prepared
    ///   to handle this.
    ///
    /// * When writeback caching is enabled, the kernel will handle the `libc::O_APPEND` flag.
    ///   However, this will not work reliably unless the kernel has exclusive access to the file.
    ///   In this case the file system may either ignore the `libc::O_APPEND` flag or return an
    ///   error to indicate that reliable `libc::O_APPEND` handling is not available.
    ///
    /// * When writeback caching is disabled, the file system is expected to properly handle
    ///   `libc::O_APPEND` and ensure that each write is appended to the end of the file.
    ///
    /// The file system may choose to return a `Handle` to refer to the newly opened file. The
    /// kernel will then use this `Handle` for all operations on the content of the file (`read`,
    /// `write`, `flush`, `release`, `fsync`). If the file system does not return a
    /// `Handle` then the kernel will use the `Inode` for the file to operate on its contents. In
    /// this case the file system may wish to enable the `FsOptions::ZERO_MESSAGE_OPEN` feature if
    /// it is supported by the kernel (see below).
    ///
    /// The returned `OpenOptions` allow the file system to change the way the opened file is
    /// handled by the kernel. See the documentation of `OpenOptions` for more information.
    ///
    /// If the `FsOptions::ZERO_MESSAGE_OPEN` feature is enabled by both the file system
    /// implementation and the kernel, then the file system may return an error of `ENOSYS`. This
    /// will be interpreted by the kernel as success and future calls to `open` and `release` will
    /// be handled by the kernel without being passed on to the file system.
    fn open(
        &self,
        ctx: Context,
        inode: Self::Inode,
        flags: u32,
    ) -> io::Result<(Option<Self::Handle>, OpenOptions)> {
        // Matches the behavior of libfuse.
        Ok((None, OpenOptions::empty()))
    }

    /// Create and open a file.
    ///
    /// If the file does not already exist, the file system should create it with the specified
    /// `mode`. When the `FsOptions::DONT_MASK` feature is set, the file system is responsible for
    /// setting the permissions of the created file to `mode & !umask`.
    ///
    /// If the file system returns an `ENOSYS` error, then the kernel will treat this method as
    /// unimplemented and all future calls to `create` will be handled by calling the `mknod` and
    /// `open` methods instead.
    ///
    /// See the documentation for the `open` method for more information about opening the file. In
    /// addition to the optional `Handle` and the `OpenOptions`, the file system must also return an
    /// `Entry` for the file. This increases the lookup count for the `Inode` associated with the
    /// file by 1.
    fn create(
        &self,
        ctx: Context,
        parent: Self::Inode,
        name: &CStr,
        mode: u32,
        flags: u32,
        umask: u32,
        security_ctx: Option<&CStr>,
    ) -> io::Result<(Entry, Option<Self::Handle>, OpenOptions)> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Read data from a file.
    ///
    /// Returns `size` bytes of data starting from offset `off` from the file associated with
    /// `inode` or `handle`.
    ///
    /// `flags` contains the flags used to open the file. Similarly, `handle` is the `Handle`
    /// returned by the file system from the `open` method, if any. If the file system
    /// implementation did not return a `Handle` from `open` then the contents of `handle` are
    /// undefined.
    ///
    /// This method should return exactly the number of bytes requested by the kernel, except in the
    /// case of error or EOF. Otherwise, the kernel will substitute the rest of the data with
    /// zeroes. An exception to this rule is if the file was opened with the "direct I/O" option
    /// (`libc::O_DIRECT`), in which case the kernel will forward the return code from this method
    /// to the userspace application that made the system call.
    fn read<W: io::Write + ZeroCopyWriter>(
        &self,
        ctx: Context,
        inode: Self::Inode,
        handle: Self::Handle,
        w: W,
        size: u32,
        offset: u64,
        lock_owner: Option<u64>,
        flags: u32,
    ) -> io::Result<usize> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Write data to a file.
    ///
    /// Writes `size` bytes of data starting from offset `off` to the file associated with `inode`
    /// or `handle`.
    ///
    /// `flags` contains the flags used to open the file. Similarly, `handle` is the `Handle`
    /// returned by the file system from the `open` method, if any. If the file system
    /// implementation did not return a `Handle` from `open` then the contents of `handle` are
    /// undefined.
    ///
    /// If the `FsOptions::HANDLE_KILLPRIV` feature is not enabled then then the file system is
    /// expected to clear the setuid and setgid bits.
    ///
    /// If `delayed_write` is true then it indicates that this is a write for buffered data.
    ///
    /// This method should return exactly the number of bytes requested by the kernel, except in the
    /// case of error. An exception to this rule is if the file was opened with the "direct I/O"
    /// option (`libc::O_DIRECT`), in which case the kernel will forward the return code from this
    /// method to the userspace application that made the system call.
    fn write<R: io::Read + ZeroCopyReader>(
        &self,
        ctx: Context,
        inode: Self::Inode,
        handle: Self::Handle,
        r: R,
        size: u32,
        offset: u64,
        lock_owner: Option<u64>,
        delayed_write: bool,
        flags: u32,
    ) -> io::Result<usize> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Flush the contents of a file.
    ///
    /// This method is called on every `close()` of a file descriptor. Since it is possible to
    /// duplicate file descriptors there may be many `flush` calls for one call to `open`.
    ///
    /// File systems should not make any assumptions about when `flush` will be
    /// called or even if it will be called at all.
    ///
    /// `handle` is the `Handle` returned by the file system from the `open` method, if any. If the
    /// file system did not return a `Handle` from `open` then the contents of `handle` are
    /// undefined.
    ///
    /// Unlike `fsync`, the file system is not required to flush pending writes. One reason to flush
    /// data is if the file system wants to return write errors during close. However, this is not
    /// portable because POSIX does not require `close` to wait for delayed I/O to complete.
    ///
    /// If the `FsOptions::POSIX_LOCKS` feature is enabled, then the file system must remove all
    /// locks belonging to `lock_owner`.
    ///
    /// If this method returns an `ENOSYS` error then the kernel will treat it as success and all
    /// subsequent calls to `flush` will be handled by the kernel without being forwarded to the
    /// file system.
    fn flush(
        &self,
        ctx: Context,
        inode: Self::Inode,
        handle: Self::Handle,
        lock_owner: u64,
    ) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Synchronize file contents.
    ///
    /// File systems must ensure that the file contents have been flushed to disk before returning
    /// from this method. If `datasync` is true then only the file data (but not the metadata) needs
    /// to be flushed.
    ///
    /// `handle` is the `Handle` returned by the file system from the `open` method, if any. If the
    /// file system did not return a `Handle` from `open` then the contents of
    /// `handle` are undefined.
    ///
    /// If this method returns an `ENOSYS` error then the kernel will treat it as success and all
    /// subsequent calls to `fsync` will be handled by the kernel without being forwarded to the
    /// file system.
    fn fsync(
        &self,
        ctx: Context,
        inode: Self::Inode,
        datasync: bool,
        handle: Self::Handle,
    ) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Allocate requested space for file data.
    ///
    /// If this function returns success, then the file sytem must guarantee that it is possible to
    /// write up to `length` bytes of data starting at `offset` without failing due to a lack of
    /// free space on the disk.
    ///
    /// `handle` is the `Handle` returned by the file system from the `open` method, if any. If the
    /// file system did not return a `Handle` from `open` then the contents of `handle` are
    /// undefined.
    ///
    /// If this method returns an `ENOSYS` error then the kernel will treat that as a permanent
    /// failure: all future calls to `fallocate` will fail with `EOPNOTSUPP` without being forwarded
    /// to the file system.
    fn fallocate(
        &self,
        ctx: Context,
        inode: Self::Inode,
        handle: Self::Handle,
        mode: u32,
        offset: u64,
        length: u64,
    ) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Release an open file.
    ///
    /// This method is called when there are no more references to an open file: all file
    /// descriptors are closed and all memory mappings are unmapped.
    ///
    /// For every `open` call there will be exactly one `release` call (unless the file system is
    /// force-unmounted).
    ///
    /// The file system may reply with an error, but error values are not returned to the `close()`
    /// or `munmap()` which triggered the release.
    ///
    /// `handle` is the `Handle` returned by the file system from the `open` method, if any. If the
    /// file system did not return a `Handle` from `open` then the contents of
    /// `handle` are undefined.
    ///
    /// If `flush` is `true` then the contents of the file should also be flushed to disk.
    fn release(
        &self,
        ctx: Context,
        inode: Self::Inode,
        flags: u32,
        handle: Self::Handle,
        flush: bool,
        flock_release: bool,
        lock_owner: Option<u64>,
    ) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Get information about the file system.
    fn statfs(&self, ctx: Context, inode: Self::Inode) -> io::Result<libc::statvfs64> {
        // SAFETY: zero-initializing a struct with only POD fields.
        let mut st: libc::statvfs64 = unsafe { mem::zeroed() };

        // This matches the behavior of libfuse as it returns these values if the
        // filesystem doesn't implement this method.
        st.f_namemax = 255;
        st.f_bsize = 512;

        Ok(st)
    }

    /// Set an extended attribute.
    ///
    /// If this method fails with an `ENOSYS` error, then the kernel will treat that as a permanent
    /// failure. The kernel will return `EOPNOTSUPP` for all future calls to `setxattr` without
    /// forwarding them to the file system.
    ///
    /// Valid values for flags are the same as those accepted by the `setxattr(2)` system call and
    /// have the same behavior.
    fn setxattr(
        &self,
        ctx: Context,
        inode: Self::Inode,
        name: &CStr,
        value: &[u8],
        flags: u32,
    ) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Get an extended attribute.
    ///
    /// If `size` is 0, then the file system should respond with `GetxattrReply::Count` and the
    /// number of bytes needed to hold the value. If `size` is large enough to hold the value, then
    /// the file system should reply with `GetxattrReply::Value` and the value of the extended
    /// attribute. If `size` is not 0 but is also not large enough to hold the value, then the file
    /// system should reply with an `ERANGE` error.
    ///
    /// If this method fails with an `ENOSYS` error, then the kernel will treat that as a permanent
    /// failure. The kernel will return `EOPNOTSUPP` for all future calls to `getxattr` without
    /// forwarding them to the file system.
    fn getxattr(
        &self,
        ctx: Context,
        inode: Self::Inode,
        name: &CStr,
        size: u32,
    ) -> io::Result<GetxattrReply> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// List extended attribute names.
    ///
    /// If `size` is 0, then the file system should respond with `ListxattrReply::Count` and the
    /// number of bytes needed to hold a `\0` byte separated list of the names of all the extended
    /// attributes. If `size` is large enough to hold the `\0` byte separated list of the attribute
    /// names, then the file system should reply with `ListxattrReply::Names` and the list. If
    /// `size` is not 0 but is also not large enough to hold the list, then the file system should
    /// reply with an `ERANGE` error.
    ///
    /// If this method fails with an `ENOSYS` error, then the kernel will treat that as a permanent
    /// failure. The kernel will return `EOPNOTSUPP` for all future calls to `listxattr` without
    /// forwarding them to the file system.
    fn listxattr(&self, ctx: Context, inode: Self::Inode, size: u32) -> io::Result<ListxattrReply> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Remove an extended attribute.
    ///
    /// If this method fails with an `ENOSYS` error, then the kernel will treat that as a permanent
    /// failure. The kernel will return `EOPNOTSUPP` for all future calls to `removexattr` without
    /// forwarding them to the file system.
    fn removexattr(&self, ctx: Context, inode: Self::Inode, name: &CStr) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Open a directory for reading.
    ///
    /// The file system may choose to return a `Handle` to refer to the newly opened directory. The
    /// kernel will then use this `Handle` for all operations on the content of the directory
    /// (`readdir`, `readdirplus`, `fsyncdir`, `releasedir`). If the file system does not return a
    /// `Handle` then the kernel will use the `Inode` for the directory to operate on its contents.
    /// In this case the file system may wish to enable the `FsOptions::ZERO_MESSAGE_OPENDIR`
    /// feature if it is supported by the kernel (see below).
    ///
    /// The returned `OpenOptions` allow the file system to change the way the opened directory is
    /// handled by the kernel. See the documentation of `OpenOptions` for more information.
    ///
    /// If the `FsOptions::ZERO_MESSAGE_OPENDIR` feature is enabled by both the file system
    /// implementation and the kernel, then the file system may return an error of `ENOSYS`. This
    /// will be interpreted by the kernel as success and future calls to `opendir` and `releasedir`
    /// will be handled by the kernel without being passed on to the file system.
    fn opendir(
        &self,
        ctx: Context,
        inode: Self::Inode,
        flags: u32,
    ) -> io::Result<(Option<Self::Handle>, OpenOptions)> {
        // Matches the behavior of libfuse.
        Ok((None, OpenOptions::empty()))
    }

    /// Read a directory.
    ///
    /// `handle` is the `Handle` returned by the file system from the `opendir` method, if any. If
    /// the file system did not return a `Handle` from `opendir` then the contents of `handle` are
    /// undefined.
    ///
    /// `size` indicates the maximum number of bytes that should be returned by this method.
    ///
    /// If `offset` is non-zero then it corresponds to one of the `offset` values from a `DirEntry`
    /// that was previously returned by a call to `readdir` for the same handle. In this case the
    /// file system should skip over the entries before the position defined by the `offset` value.
    /// If entries were added or removed while the `Handle` is open then the file system may still
    /// include removed entries or skip newly created entries. However, adding or removing entries
    /// should never cause the file system to skip over unrelated entries or include an entry more
    /// than once. This means that `offset` cannot be a simple index and must include sufficient
    /// information to uniquely determine the next entry in the list even when the set of entries is
    /// being changed.
    ///
    /// The file system may return entries for the current directory (".") and parent directory
    /// ("..") but is not required to do so. If the file system does not return these entries, then
    /// they are implicitly added by the kernel.
    ///
    /// The lookup count for `Inode`s associated with the returned directory entries is **NOT**
    /// affected by this method.
    fn readdir(
        &self,
        ctx: Context,
        inode: Self::Inode,
        handle: Self::Handle,
        size: u32,
        offset: u64,
    ) -> io::Result<Self::DirIter> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Synchronize the contents of a directory.
    ///
    /// File systems must ensure that the directory contents have been flushed to disk before
    /// returning from this method. If `datasync` is true then only the directory data (but not the
    /// metadata) needs to be flushed.
    ///
    /// `handle` is the `Handle` returned by the file system from the `opendir` method, if any. If
    /// the file system did not return a `Handle` from `opendir` then the contents of
    /// `handle` are undefined.
    ///
    /// If this method returns an `ENOSYS` error then the kernel will treat it as success and all
    /// subsequent calls to `fsyncdir` will be handled by the kernel without being forwarded to the
    /// file system.
    fn fsyncdir(
        &self,
        ctx: Context,
        inode: Self::Inode,
        datasync: bool,
        handle: Self::Handle,
    ) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Release an open directory.
    ///
    /// For every `opendir` call there will be exactly one `releasedir` call (unless the file system
    /// is force-unmounted).
    ///
    /// `handle` is the `Handle` returned by the file system from the `opendir` method, if any. If
    /// the file system did not return a `Handle` from `opendir` then the contents of `handle` are
    /// undefined.
    ///
    /// `flags` contains used the flags used to open the directory in `opendir`.
    fn releasedir(
        &self,
        ctx: Context,
        inode: Self::Inode,
        flags: u32,
        handle: Self::Handle,
    ) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Check file access permissions.
    ///
    /// This method is called when a userspace process in the client makes an `access()` or
    /// `chdir()` system call. If the file system was mounted with the `-o default_permissions`
    /// mount option, then the kernel will perform these checks itself and this method will not be
    /// called.
    ///
    /// If this method returns an `ENOSYS` error, then the kernel will treat it as a permanent
    /// success: all future calls to `access` will return success without being forwarded to the
    /// file system.
    fn access(&self, ctx: Context, inode: Self::Inode, mask: u32) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Perform an ioctl on a file or directory.
    ///
    /// `handle` is the `Handle` returned by the file system from the `open` or `opendir` methods,
    /// if any. If the file system did not return a `Handle` from then the contents of `handle` are
    /// undefined.
    ///
    /// If `flags` contains `IoctlFlags::UNRESTRICTED` then the file system may retry the ioctl
    /// after informing the kernel about the input and output areas. If `flags` does not contain
    /// `IoctlFlags::UNRESTRICTED` then the kernel will prepare the input and output areas according
    /// to the encoding in the ioctl command. In that case the ioctl cannot be retried.
    ///
    /// `cmd` is the ioctl request made by the calling process, truncated to 32 bits.
    ///
    /// `arg` is the argument provided by the calling process.
    ///
    /// `in_size` is the length of the additional data that accompanies the request. The file system
    /// may fetch this data from `reader`.
    ///
    /// `out_size` is the length of the output area prepared by the kernel to hold the response to
    /// the ioctl.
    fn ioctl<R: io::Read>(
        &self,
        ctx: Context,
        inode: Self::Inode,
        handle: Self::Handle,
        flags: IoctlFlags,
        cmd: u32,
        arg: u64,
        in_size: u32,
        out_size: u32,
        reader: R,
    ) -> io::Result<IoctlReply> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// TODO: support this
    fn getlk(&self) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// TODO: support this
    fn setlk(&self) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// TODO: support this
    fn setlkw(&self) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// TODO: support this
    fn bmap(&self) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// TODO: support this
    fn poll(&self) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// TODO: support this
    fn notify_reply(&self) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// TODO: support this
    fn lseek(&self) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Copy a range of data from one file to another
    ///
    /// Performs an optimized copy between two file descriptors without the additional cost of
    /// transferring data through the kernel module to user space (glibc) and then back into
    /// the file system again.
    ///
    /// In case this method is not implemented, glibc falls back to reading data from the source and
    /// writing to the destination.
    ///
    /// If this method fails with an `ENOSYS` error, then the kernel will treat that as a permanent
    /// failure. The kernel will return `EOPNOTSUPP` for all future calls to `copy_file_range`
    /// without forwarding them to the file system.
    ///
    /// All values accepted by the `copy_file_range(2)` system call are valid values for `flags` and
    /// must be handled by the file system.
    fn copy_file_range(
        &self,
        ctx: Context,
        inode_src: Self::Inode,
        handle_src: Self::Handle,
        offset_src: u64,
        inode_dst: Self::Inode,
        handle_dst: Self::Handle,
        offset_dst: u64,
        length: u64,
        flags: u64,
    ) -> io::Result<usize> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Set up memory mappings.
    ///
    /// Used to set up file mappings in DAX window.
    ///
    /// # Arguments
    ///
    /// * `file_offset` - Offset into the file to start the mapping.
    /// * `mem_offset` - Offset in Memory Window.
    /// * `size` - Length of mapping required.
    /// * `flags` - Bit field of `FUSE_SETUPMAPPING_FLAGS_*`.
    /// * `mapper` - Mapper object which performs the mapping.
    fn set_up_mapping<M: Mapper>(
        &self,
        ctx: Context,
        inode: Self::Inode,
        handle: Self::Handle,
        file_offset: u64,
        mem_offset: u64,
        size: usize,
        flags: u32,
        mapper: M,
    ) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Remove memory mappings.
    ///
    /// Used to tear down file mappings in DAX window. This method must be supported when
    /// `set_up_mapping` is supported.
    fn remove_mapping<M: Mapper>(&self, msgs: &[RemoveMappingOne], mapper: M) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Lookup and open/create the file
    ///
    /// In this call, program first do a lookup on the file. Then depending upon
    /// flags combination, either do create + open, open only or return error.
    /// In all successful cases, it will return the dentry. For return value's
    /// handle and open options atomic_open should apply same rules to handle
    /// flags and configuration in open/create system call.
    ///
    /// This function is called when the client supports FUSE_OPEN_ATOMIC.
    /// Implementing atomic_open is optional. When the it's not implemented,
    /// the client fall back to send lookup and open requests separately.
    ///
    ///  # Specification
    ///
    /// If file was indeed newly created (as a result of O_CREAT), then set
    /// `FOPEN_FILE_CREATED` bit in `struct OpenOptions open`. This bit is used by
    ///  crosvm to inform the fuse client to set `FILE_CREATED` bit in `struct
    /// fuse_file_info'.
    ///
    /// All flags applied to open/create should be handled samely in atomic open,
    /// only the following are exceptions:
    /// * The O_NOCTTY is filtered out by fuse client.
    /// * O_TRUNC is filtered out by VFS for O_CREAT, O_EXCL combination.
    ///
    /// # Implementation
    ///
    /// To implement this API, you need to handle the following cases:
    ///
    /// a) File does not exist
    ///  - O_CREAT:
    ///    - Create file with specified mode
    ///    - Set `FOPEN_FILE_CREATED` bit in `struct OpenOptions open`
    ///    - Open the file
    ///    - Return d_entry and file handler
    ///  - ~O_CREAT:
    ///    - ENOENT
    ///
    /// b) File exist already (exception is O_EXCL)
    ///    - O_CREAT:
    ///      - Open the file
    ///      - Return d_entry and file handler
    ///    - O_EXCL:
    ///      - EEXIST
    ///
    /// c) File is symbol link
    ///    - Return dentry and file handler
    fn atomic_open(
        &self,
        ctx: Context,
        parent: Self::Inode,
        name: &CStr,
        mode: u32,
        flags: u32,
        umask: u32,
        security_ctx: Option<&CStr>,
    ) -> io::Result<(Entry, Option<Self::Handle>, OpenOptions)> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }
}
