// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::btree_map;
use std::collections::BTreeMap;
use std::ffi::{c_void, CStr, CString};
use std::fs::File;
use std::io;
use std::mem::{self, size_of, MaybeUninit};
use std::os::raw::{c_int, c_long};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::ptr;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use base::{error, ioctl_ior_nr, ioctl_iow_nr, ioctl_with_mut_ptr, ioctl_with_ptr, warn};
use data_model::DataInit;
use rand_ish::SimpleRng;
use sync::Mutex;

use crate::virtio::fs::filesystem::{
    Context, DirectoryIterator, Entry, FileSystem, FsOptions, GetxattrReply, IoctlFlags,
    IoctlIovec, IoctlReply, ListxattrReply, OpenOptions, SetattrValid, ZeroCopyReader,
    ZeroCopyWriter,
};
use crate::virtio::fs::fuse;
use crate::virtio::fs::multikey::MultikeyBTreeMap;
use crate::virtio::fs::read_dir::ReadDir;

const EMPTY_CSTR: &[u8] = b"\0";
const ROOT_CSTR: &[u8] = b"/\0";
const PROC_CSTR: &[u8] = b"/proc\0";
const UNLABELED: &[u8] = b"unlabeled";

const USER_VIRTIOFS_XATTR: &[u8] = b"user.virtiofs.";
const SECURITY_XATTR: &[u8] = b"security.";
const SELINUX_XATTR: &[u8] = b"security.selinux";

const FSCRYPT_KEY_DESCRIPTOR_SIZE: usize = 8;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct fscrypt_policy_v1 {
    _version: u8,
    _contents_encryption_mode: u8,
    _filenames_encryption_mode: u8,
    _flags: u8,
    _master_key_descriptor: [u8; FSCRYPT_KEY_DESCRIPTOR_SIZE],
}
unsafe impl DataInit for fscrypt_policy_v1 {}

ioctl_ior_nr!(FS_IOC_SET_ENCRYPTION_POLICY, 0x66, 19, fscrypt_policy_v1);
ioctl_iow_nr!(FS_IOC_GET_ENCRYPTION_POLICY, 0x66, 21, fscrypt_policy_v1);

#[repr(C)]
#[derive(Clone, Copy)]
struct fsxattr {
    _fsx_xflags: u32,     /* xflags field value (get/set) */
    _fsx_extsize: u32,    /* extsize field value (get/set)*/
    _fsx_nextents: u32,   /* nextents field value (get)	*/
    _fsx_projid: u32,     /* project identifier (get/set) */
    _fsx_cowextsize: u32, /* CoW extsize field value (get/set)*/
    _fsx_pad: [u8; 8],
}
unsafe impl DataInit for fsxattr {}

ioctl_ior_nr!(FS_IOC_FSGETXATTR, 'X' as u32, 31, fsxattr);
ioctl_iow_nr!(FS_IOC_FSSETXATTR, 'X' as u32, 32, fsxattr);

ioctl_ior_nr!(FS_IOC_GETFLAGS, 'f' as u32, 1, c_long);
ioctl_iow_nr!(FS_IOC_SETFLAGS, 'f' as u32, 2, c_long);

ioctl_ior_nr!(FS_IOC32_GETFLAGS, 'f' as u32, 1, u32);
ioctl_iow_nr!(FS_IOC32_SETFLAGS, 'f' as u32, 2, u32);

ioctl_ior_nr!(FS_IOC64_GETFLAGS, 'f' as u32, 1, u64);
ioctl_iow_nr!(FS_IOC64_SETFLAGS, 'f' as u32, 2, u64);

type Inode = u64;
type Handle = u64;

#[derive(Clone, Copy, PartialOrd, Ord, PartialEq, Eq)]
struct InodeAltKey {
    ino: libc::ino64_t,
    dev: libc::dev_t,
}

struct InodeData {
    inode: Inode,
    // Most of these aren't actually files but ¯\_(ツ)_/¯.
    file: File,
    refcount: AtomicU64,
}

struct HandleData {
    inode: Inode,
    file: Mutex<File>,
}

macro_rules! scoped_cred {
    ($name:ident, $ty:ty, $syscall_nr:expr) => {
        #[derive(Debug)]
        struct $name {
            old: $ty,
        }

        impl $name {
            // Changes the effective uid/gid of the current thread to `val`. Changes the thread's
            // credentials back to `old` when the returned struct is dropped.
            fn new(val: $ty, old: $ty) -> io::Result<Option<$name>> {
                if val == old {
                    // Nothing to do since we already have the correct value.
                    return Ok(None);
                }

                // We want credential changes to be per-thread because otherwise
                // we might interfere with operations being carried out on other
                // threads with different uids/gids.  However, posix requires that
                // all threads in a process share the same credentials.  To do this
                // libc uses signals to ensure that when one thread changes its
                // credentials the other threads do the same thing.
                //
                // So instead we invoke the syscall directly in order to get around
                // this limitation.  Another option is to use the setfsuid and
                // setfsgid systems calls.   However since those calls have no way to
                // return an error, it's preferable to do this instead.

                // This call is safe because it doesn't modify any memory and we
                // check the return value.
                let res = unsafe { libc::syscall($syscall_nr, -1, val, -1) };
                if res == 0 {
                    Ok(Some($name { old }))
                } else {
                    Err(io::Error::last_os_error())
                }
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                let res = unsafe { libc::syscall($syscall_nr, -1, self.old, -1) };
                if res < 0 {
                    error!(
                        "failed to change credentials back to {}: {}",
                        self.old,
                        io::Error::last_os_error(),
                    );
                }
            }
        }
    };
}
#[cfg(not(target_arch = "arm"))]
scoped_cred!(ScopedUid, libc::uid_t, libc::SYS_setresuid);
#[cfg(target_arch = "arm")]
scoped_cred!(ScopedUid, libc::uid_t, libc::SYS_setresuid32);

#[cfg(not(target_arch = "arm"))]
scoped_cred!(ScopedGid, libc::gid_t, libc::SYS_setresgid);
#[cfg(target_arch = "arm")]
scoped_cred!(ScopedGid, libc::gid_t, libc::SYS_setresgid32);

#[cfg(not(target_arch = "arm"))]
const SYS_GETEUID: libc::c_long = libc::SYS_geteuid;
#[cfg(target_arch = "arm")]
const SYS_GETEUID: libc::c_long = libc::SYS_geteuid32;

#[cfg(not(target_arch = "arm"))]
const SYS_GETEGID: libc::c_long = libc::SYS_getegid;
#[cfg(target_arch = "arm")]
const SYS_GETEGID: libc::c_long = libc::SYS_getegid32;

thread_local! {
    // Both these calls are safe because they take no parameters, and only return an integer value.
    // The kernel also guarantees that they can never fail.
    static THREAD_EUID: libc::uid_t = unsafe { libc::syscall(SYS_GETEUID) as libc::uid_t };
    static THREAD_EGID: libc::gid_t = unsafe { libc::syscall(SYS_GETEGID) as libc::gid_t };
}

fn set_creds(
    uid: libc::uid_t,
    gid: libc::gid_t,
) -> io::Result<(Option<ScopedUid>, Option<ScopedGid>)> {
    let olduid = THREAD_EUID.with(|uid| *uid);
    let oldgid = THREAD_EGID.with(|gid| *gid);

    // We have to change the gid before we change the uid because if we change the uid first then we
    // lose the capability to change the gid.  However changing back can happen in any order.
    ScopedGid::new(gid, oldgid).and_then(|gid| Ok((ScopedUid::new(uid, olduid)?, gid)))
}

thread_local!(static THREAD_FSCREATE: RefCell<Option<File>> = RefCell::new(None));

// Opens and returns a write-only handle to /proc/thread-self/attr/fscreate. Panics if it fails to
// open the file.
fn open_fscreate(proc: &File) -> File {
    // Safe because this is a valid c-string.
    let fscreate = unsafe { CStr::from_bytes_with_nul_unchecked(b"thread-self/attr/fscreate\0") };

    // Safe because this doesn't modify any memory and we check the return value.
    let fd = unsafe {
        libc::openat(
            proc.as_raw_fd(),
            fscreate.as_ptr(),
            libc::O_CLOEXEC | libc::O_WRONLY,
        )
    };

    // We don't expect this to fail and we're not in a position to return an error here so just
    // panic.
    if fd < 0 {
        panic!(
            "Failed to open /proc/thread-self/attr/fscreate: {}",
            io::Error::last_os_error()
        );
    }

    // Safe because we just opened this fd.
    unsafe { File::from_raw_fd(fd) }
}

struct ScopedSecurityContext;

impl ScopedSecurityContext {
    fn new(proc: &File, ctx: &CStr) -> io::Result<ScopedSecurityContext> {
        THREAD_FSCREATE.with(|thread_fscreate| {
            let mut fscreate = thread_fscreate.borrow_mut();
            let file = fscreate.get_or_insert_with(|| open_fscreate(proc));
            // Safe because this doesn't modify any memory and we check the return value.
            let ret = unsafe {
                libc::write(
                    file.as_raw_fd(),
                    ctx.as_ptr() as *const libc::c_void,
                    ctx.to_bytes_with_nul().len(),
                )
            };
            if ret < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(ScopedSecurityContext)
            }
        })
    }
}

impl Drop for ScopedSecurityContext {
    fn drop(&mut self) {
        THREAD_FSCREATE.with(|thread_fscreate| {
            // expect is safe here because the thread local would have been initialized by the call
            // to `new` above.
            let fscreate = thread_fscreate.borrow();
            let file = fscreate
                .as_ref()
                .expect("Uninitialized thread-local when dropping ScopedSecurityContext");

            // Safe because this doesn't modify any memory and we check the return value.
            let ret = unsafe { libc::write(file.as_raw_fd(), ptr::null(), 0) };

            if ret < 0 {
                warn!(
                    "Failed to restore security context: {}",
                    io::Error::last_os_error()
                );
            }
        })
    }
}

fn ebadf() -> io::Error {
    io::Error::from_raw_os_error(libc::EBADF)
}

fn stat(f: &File) -> io::Result<libc::stat64> {
    let mut st = MaybeUninit::<libc::stat64>::zeroed();

    // Safe because this is a constant value and a valid C string.
    let pathname = unsafe { CStr::from_bytes_with_nul_unchecked(EMPTY_CSTR) };

    // Safe because the kernel will only write data in `st` and we check the return
    // value.
    let res = unsafe {
        libc::fstatat64(
            f.as_raw_fd(),
            pathname.as_ptr(),
            st.as_mut_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if res >= 0 {
        // Safe because the kernel guarantees that the struct is now fully initialized.
        Ok(unsafe { st.assume_init() })
    } else {
        Err(io::Error::last_os_error())
    }
}

/// The caching policy that the file system should report to the FUSE client. By default the FUSE
/// protocol uses close-to-open consistency. This means that any cached contents of the file are
/// invalidated the next time that file is opened.
#[derive(Debug, Clone)]
pub enum CachePolicy {
    /// The client should never cache file data and all I/O should be directly forwarded to the
    /// server. This policy must be selected when file contents may change without the knowledge of
    /// the FUSE client (i.e., the file system does not have exclusive access to the directory).
    Never,

    /// The client is free to choose when and how to cache file data. This is the default policy and
    /// uses close-to-open consistency as described in the enum documentation.
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

impl Default for CachePolicy {
    fn default() -> Self {
        CachePolicy::Auto
    }
}

/// Options that configure the behavior of the file system.
#[derive(Debug, Clone)]
pub struct Config {
    /// How long the FUSE client should consider directory entries to be valid. If the contents of a
    /// directory can only be modified by the FUSE client (i.e., the file system has exclusive
    /// access), then this should be a large value.
    ///
    /// The default value for this option is 5 seconds.
    pub entry_timeout: Duration,

    /// How long the FUSE client should consider file and directory attributes to be valid. If the
    /// attributes of a file or directory can only be modified by the FUSE client (i.e., the file
    /// system has exclusive access), then this should be set to a large value.
    ///
    /// The default value for this option is 5 seconds.
    pub attr_timeout: Duration,

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
}

impl Default for Config {
    fn default() -> Self {
        Config {
            entry_timeout: Duration::from_secs(5),
            attr_timeout: Duration::from_secs(5),
            cache_policy: Default::default(),
            writeback: false,
            rewrite_security_xattrs: false,
            ascii_casefold: false,
        }
    }
}

/// A file system that simply "passes through" all requests it receives to the underlying file
/// system. To keep the implementation simple it servers the contents of its root directory. Users
/// that wish to serve only a specific directory should set up the environment so that that
/// directory ends up as the root of the file system process. One way to accomplish this is via a
/// combination of mount namespaces and the pivot_root system call.
pub struct PassthroughFs {
    // File descriptors for various points in the file system tree. These fds are always opened with
    // the `O_PATH` option so they cannot be used for reading or writing any data. See the
    // documentation of the `O_PATH` flag in `open(2)` for more details on what one can and cannot
    // do with an fd opened with this flag.
    inodes: Mutex<MultikeyBTreeMap<Inode, InodeAltKey, Arc<InodeData>>>,
    next_inode: AtomicU64,

    // File descriptors for open files and directories. Unlike the fds in `inodes`, these _can_ be
    // used for reading and writing data.
    handles: Mutex<BTreeMap<Handle, Arc<HandleData>>>,
    next_handle: AtomicU64,

    // File descriptor pointing to the `/proc` directory. This is used to convert an fd from
    // `inodes` into one that can go into `handles`. This is accomplished by reading the
    // `self/fd/{}` symlink. We keep an open fd here in case the file system tree that we are meant
    // to be serving doesn't have access to `/proc`.
    proc: File,

    // Whether writeback caching is enabled for this directory. This will only be true when
    // `cfg.writeback` is true and `init` was called with `FsOptions::WRITEBACK_CACHE`.
    writeback: AtomicBool,

    cfg: Config,
}

impl PassthroughFs {
    pub fn new(cfg: Config) -> io::Result<PassthroughFs> {
        // Safe because this is a constant value and a valid C string.
        let proc_cstr = unsafe { CStr::from_bytes_with_nul_unchecked(PROC_CSTR) };

        // Safe because this doesn't modify any memory and we check the return value.
        let fd = unsafe {
            libc::openat(
                libc::AT_FDCWD,
                proc_cstr.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // Safe because we just opened this fd.
        let proc = unsafe { File::from_raw_fd(fd) };

        Ok(PassthroughFs {
            inodes: Mutex::new(MultikeyBTreeMap::new()),
            next_inode: AtomicU64::new(fuse::ROOT_ID + 1),

            handles: Mutex::new(BTreeMap::new()),
            next_handle: AtomicU64::new(0),

            proc,

            writeback: AtomicBool::new(false),
            cfg,
        })
    }

    pub fn keep_fds(&self) -> Vec<RawFd> {
        vec![self.proc.as_raw_fd()]
    }

    fn rewrite_xattr_name<'xattr>(&self, name: &'xattr CStr) -> Cow<'xattr, CStr> {
        if !self.cfg.rewrite_security_xattrs {
            return Cow::Borrowed(name);
        }

        // Does not include nul-terminator.
        let buf = name.to_bytes();
        if !buf.starts_with(SECURITY_XATTR) || buf == SELINUX_XATTR {
            return Cow::Borrowed(name);
        }

        let mut newname = USER_VIRTIOFS_XATTR.to_vec();
        newname.extend_from_slice(buf);

        // The unwrap is safe here because the prefix doesn't contain any interior nul-bytes and the
        // to_bytes() call above will not return a byte slice with any interior nul-bytes either.
        Cow::Owned(CString::new(newname).expect("Failed to re-write xattr name"))
    }

    fn get_path(&self, inode: Inode) -> io::Result<CString> {
        let data = self
            .inodes
            .lock()
            .get(&inode)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        let mut buf = Vec::with_capacity(libc::PATH_MAX as usize);
        buf.resize(libc::PATH_MAX as usize, 0);

        let path = CString::new(format!("self/fd/{}", data.file.as_raw_fd()))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // Safe because this will only modify the contents of `buf` and we check the return value.
        let res = unsafe {
            libc::readlinkat(
                self.proc.as_raw_fd(),
                path.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
            )
        };
        if res < 0 {
            return Err(io::Error::last_os_error());
        }

        buf.resize(res as usize, 0);
        CString::new(buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    fn open_inode(&self, inode: Inode, mut flags: i32) -> io::Result<File> {
        let data = self
            .inodes
            .lock()
            .get(&inode)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        let pathname = CString::new(format!("self/fd/{}", data.file.as_raw_fd()))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // When writeback caching is enabled, the kernel may send read requests even if the
        // userspace program opened the file write-only. So we need to ensure that we have opened
        // the file for reading as well as writing.
        let writeback = self.writeback.load(Ordering::Relaxed);
        if writeback && flags & libc::O_ACCMODE == libc::O_WRONLY {
            flags &= !libc::O_ACCMODE;
            flags |= libc::O_RDWR;
        }

        // When writeback caching is enabled the kernel is responsible for handling `O_APPEND`.
        // However, this breaks atomicity as the file may have changed on disk, invalidating the
        // cached copy of the data in the kernel and the offset that the kernel thinks is the end of
        // the file. Just allow this for now as it is the user's responsibility to enable writeback
        // caching only for directories that are not shared. It also means that we need to clear the
        // `O_APPEND` flag.
        if writeback && flags & libc::O_APPEND != 0 {
            flags &= !libc::O_APPEND;
        }

        // Safe because this doesn't modify any memory and we check the return value. We don't
        // really check `flags` because if the kernel can't handle poorly specified flags then we
        // have much bigger problems. Also, clear the `O_NOFOLLOW` flag if it is set since we need
        // to follow the `/proc/self/fd` symlink to get the file.
        let fd = unsafe {
            libc::openat(
                self.proc.as_raw_fd(),
                pathname.as_ptr(),
                (flags | libc::O_CLOEXEC) & !(libc::O_NOFOLLOW | libc::O_DIRECT),
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // Safe because we just opened this fd.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    // Performs an ascii case insensitive lookup and returns an O_PATH fd for the entry, if found.
    fn ascii_casefold_lookup(&self, dir: Inode, name: &[u8]) -> io::Result<RawFd> {
        let parent = self.open_inode(dir, libc::O_RDONLY | libc::O_DIRECTORY)?;
        let mut buf = [0u8; 1024];
        let mut offset = 0;
        loop {
            let mut read_dir = ReadDir::new(&parent, offset, &mut buf[..])?;
            if read_dir.remaining() == 0 {
                break;
            }

            while let Some(entry) = read_dir.next() {
                offset = entry.offset as libc::off64_t;
                if name.eq_ignore_ascii_case(entry.name.to_bytes()) {
                    return Ok(unsafe {
                        libc::openat(
                            parent.as_raw_fd(),
                            entry.name.as_ptr(),
                            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                        )
                    });
                }
            }
        }
        Err(io::Error::from_raw_os_error(libc::ENOENT))
    }

    fn do_lookup(&self, parent: Inode, name: &CStr) -> io::Result<Entry> {
        let p = self
            .inodes
            .lock()
            .get(&parent)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        let fd = {
            // Safe because this doesn't modify any memory and we check the return value.
            let fd = unsafe {
                libc::openat(
                    p.file.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };

            if fd < 0 && self.cfg.ascii_casefold {
                // Ignore any errors during casefold lookup.
                self.ascii_casefold_lookup(parent, name.to_bytes())
                    .unwrap_or(fd)
            } else {
                fd
            }
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // Safe because we just opened this fd.
        let f = unsafe { File::from_raw_fd(fd) };

        let st = stat(&f)?;

        let altkey = InodeAltKey {
            ino: st.st_ino,
            dev: st.st_dev,
        };
        let data = self.inodes.lock().get_alt(&altkey).map(Arc::clone);

        let inode = if let Some(data) = data {
            // Matches with the release store in `forget`.
            data.refcount.fetch_add(1, Ordering::Acquire);
            data.inode
        } else {
            // There is a possible race here where 2 threads end up adding the same file
            // into the inode list.  However, since each of those will get a unique Inode
            // value and unique file descriptors this shouldn't be that much of a problem.
            let inode = self.next_inode.fetch_add(1, Ordering::Relaxed);
            self.inodes.lock().insert(
                inode,
                InodeAltKey {
                    ino: st.st_ino,
                    dev: st.st_dev,
                },
                Arc::new(InodeData {
                    inode,
                    file: f,
                    refcount: AtomicU64::new(1),
                }),
            );

            inode
        };

        Ok(Entry {
            inode,
            generation: 0,
            attr: st,
            attr_timeout: self.cfg.attr_timeout.clone(),
            entry_timeout: self.cfg.entry_timeout.clone(),
        })
    }

    fn do_readdir(
        &self,
        inode: Inode,
        handle: Handle,
        size: u32,
        offset: u64,
    ) -> io::Result<ReadDir<Box<[u8]>>> {
        let data = self
            .handles
            .lock()
            .get(&handle)
            .filter(|hd| hd.inode == inode)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        let mut buf = Vec::with_capacity(size as usize);
        buf.resize(size as usize, 0);

        let dir = data.file.lock();

        ReadDir::new(&*dir, offset as libc::off64_t, buf.into_boxed_slice())
    }

    fn do_open(&self, inode: Inode, flags: u32) -> io::Result<(Option<Handle>, OpenOptions)> {
        let file = Mutex::new(self.open_inode(inode, flags as i32)?);

        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        let data = HandleData { inode, file };

        self.handles.lock().insert(handle, Arc::new(data));

        let mut opts = OpenOptions::empty();
        match self.cfg.cache_policy {
            // We only set the direct I/O option on files.
            CachePolicy::Never => opts.set(
                OpenOptions::DIRECT_IO,
                flags & (libc::O_DIRECTORY as u32) == 0,
            ),
            CachePolicy::Always => {
                opts |= if flags & (libc::O_DIRECTORY as u32) == 0 {
                    OpenOptions::KEEP_CACHE
                } else {
                    OpenOptions::CACHE_DIR
                }
            }
            _ => {}
        };

        Ok((Some(handle), opts))
    }

    fn do_release(&self, inode: Inode, handle: Handle) -> io::Result<()> {
        let mut handles = self.handles.lock();

        if let btree_map::Entry::Occupied(e) = handles.entry(handle) {
            if e.get().inode == inode {
                // We don't need to close the file here because that will happen automatically when
                // the last `Arc` is dropped.
                e.remove();
                return Ok(());
            }
        }

        Err(ebadf())
    }

    fn do_getattr(&self, inode: Inode) -> io::Result<(libc::stat64, Duration)> {
        let data = self
            .inodes
            .lock()
            .get(&inode)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        let st = stat(&data.file)?;

        Ok((st, self.cfg.attr_timeout.clone()))
    }

    fn do_unlink(&self, parent: Inode, name: &CStr, flags: libc::c_int) -> io::Result<()> {
        let data = self
            .inodes
            .lock()
            .get(&parent)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe { libc::unlinkat(data.file.as_raw_fd(), name.as_ptr(), flags) };
        if res == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn get_encryption_policy(&self, handle: Handle) -> io::Result<IoctlReply> {
        let data = self
            .handles
            .lock()
            .get(&handle)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        let mut buf = MaybeUninit::<fscrypt_policy_v1>::zeroed();
        let file = data.file.lock();

        // Safe because the kernel will only write to `buf` and we check the return value.
        let res =
            unsafe { ioctl_with_mut_ptr(&*file, FS_IOC_GET_ENCRYPTION_POLICY(), buf.as_mut_ptr()) };
        if res < 0 {
            Ok(IoctlReply::Done(Err(io::Error::last_os_error())))
        } else {
            // Safe because the kernel guarantees that the policy is now initialized.
            let policy = unsafe { buf.assume_init() };
            Ok(IoctlReply::Done(Ok(policy.as_slice().to_vec())))
        }
    }

    fn set_encryption_policy<R: io::Read>(&self, handle: Handle, r: R) -> io::Result<IoctlReply> {
        let data = self
            .handles
            .lock()
            .get(&handle)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        let policy = fscrypt_policy_v1::from_reader(r)?;
        let file = data.file.lock();
        // Safe because the kernel will only read from `policy` and we check the return value.
        let res = unsafe { ioctl_with_ptr(&*file, FS_IOC_SET_ENCRYPTION_POLICY(), &policy) };
        if res < 0 {
            Ok(IoctlReply::Done(Err(io::Error::last_os_error())))
        } else {
            Ok(IoctlReply::Done(Ok(Vec::new())))
        }
    }

    fn get_fsxattr(&self, handle: Handle) -> io::Result<IoctlReply> {
        let data = self
            .handles
            .lock()
            .get(&handle)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        let mut buf = MaybeUninit::<fsxattr>::zeroed();
        let file = data.file.lock();

        // Safe because the kernel will only write to `buf` and we check the return value.
        let res = unsafe { ioctl_with_mut_ptr(&*file, FS_IOC_FSGETXATTR(), buf.as_mut_ptr()) };
        if res < 0 {
            Ok(IoctlReply::Done(Err(io::Error::last_os_error())))
        } else {
            // Safe because the kernel guarantees that the policy is now initialized.
            let xattr = unsafe { buf.assume_init() };
            Ok(IoctlReply::Done(Ok(xattr.as_slice().to_vec())))
        }
    }

    fn set_fsxattr<R: io::Read>(&self, handle: Handle, r: R) -> io::Result<IoctlReply> {
        let data = self
            .handles
            .lock()
            .get(&handle)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        let attr = fsxattr::from_reader(r)?;
        let file = data.file.lock();

        //  Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe { ioctl_with_ptr(&*file, FS_IOC_FSSETXATTR(), &attr) };
        if res < 0 {
            Ok(IoctlReply::Done(Err(io::Error::last_os_error())))
        } else {
            Ok(IoctlReply::Done(Ok(Vec::new())))
        }
    }

    fn get_flags(&self, handle: Handle) -> io::Result<IoctlReply> {
        let data = self
            .handles
            .lock()
            .get(&handle)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        // The ioctl encoding is a long but the parameter is actually an int.
        let mut flags: c_int = 0;
        let file = data.file.lock();

        // Safe because the kernel will only write to `flags` and we check the return value.
        let res = unsafe { ioctl_with_mut_ptr(&*file, FS_IOC_GETFLAGS(), &mut flags) };
        if res < 0 {
            Ok(IoctlReply::Done(Err(io::Error::last_os_error())))
        } else {
            Ok(IoctlReply::Done(Ok(flags.to_ne_bytes().to_vec())))
        }
    }

    fn set_flags<R: io::Read>(&self, handle: Handle, r: R) -> io::Result<IoctlReply> {
        let data = self
            .handles
            .lock()
            .get(&handle)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        // The ioctl encoding is a long but the parameter is actually an int.
        let flags = c_int::from_reader(r)?;
        let file = data.file.lock();

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe { ioctl_with_ptr(&*file, FS_IOC_SETFLAGS(), &flags) };
        if res < 0 {
            Ok(IoctlReply::Done(Err(io::Error::last_os_error())))
        } else {
            Ok(IoctlReply::Done(Ok(Vec::new())))
        }
    }
}

fn forget_one(
    inodes: &mut MultikeyBTreeMap<Inode, InodeAltKey, Arc<InodeData>>,
    inode: Inode,
    count: u64,
) {
    if let Some(data) = inodes.get(&inode) {
        // Acquiring the write lock on the inode map prevents new lookups from incrementing the
        // refcount but there is the possibility that a previous lookup already acquired a
        // reference to the inode data and is in the process of updating the refcount so we need
        // to loop here until we can decrement successfully.
        loop {
            let refcount = data.refcount.load(Ordering::Relaxed);

            // Saturating sub because it doesn't make sense for a refcount to go below zero and
            // we don't want misbehaving clients to cause integer overflow.
            let new_count = refcount.saturating_sub(count);

            // Synchronizes with the acquire load in `do_lookup`.
            if data
                .refcount
                .compare_and_swap(refcount, new_count, Ordering::Release)
                == refcount
            {
                if new_count == 0 {
                    // We just removed the last refcount for this inode. There's no need for an
                    // acquire fence here because we hold a write lock on the inode map and any
                    // thread that is waiting to do a forget on the same inode will have to wait
                    // until we release the lock. So there's is no other release store for us to
                    // synchronize with before deleting the entry.
                    inodes.remove(&inode);
                }
                break;
            }
        }
    }
}

// Strips any `user.virtiofs.` prefix from `buf`. If buf contains one or more nul-bytes, each
// nul-byte-separated slice is treated as a C string and the prefix is stripped from each one.
fn strip_xattr_prefix(buf: &mut Vec<u8>) {
    fn next_cstr(b: &[u8], start: usize) -> Option<&[u8]> {
        if start >= b.len() {
            return None;
        }

        let end = b[start..]
            .iter()
            .position(|&c| c == b'\0')
            .map(|p| start + p + 1)
            .unwrap_or(b.len());

        Some(&b[start..end])
    }

    let mut pos = 0;
    while let Some(name) = next_cstr(&buf, pos) {
        if !name.starts_with(USER_VIRTIOFS_XATTR) {
            pos += name.len();
            continue;
        }

        let newlen = name.len() - USER_VIRTIOFS_XATTR.len();
        buf.drain(pos..pos + USER_VIRTIOFS_XATTR.len());
        pos += newlen;
    }
}

// Like mkdtemp but also takes a mode parameter rather than always using 0o700. This is needed
// because if the parent has a default posix acl set then the meaning of the mode parameter in the
// mkdir call completely changes: the actual mode is inherited from the default acls set in the
// parent and the mode is treated like a umask (the real umask is ignored in this case).
// Additionally, this only happens when the inode is first created and not on subsequent fchmod
// calls so we really need to use the requested mode from the very beginning and not the default
// 0o700 mode that mkdtemp uses.
fn create_temp_dir(parent: &File, mode: libc::mode_t) -> io::Result<CString> {
    const MAX_ATTEMPTS: usize = 64;
    let mut seed = 0u64.to_ne_bytes();
    // Safe because this will only modify `seed` and we check the return value.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_getrandom,
            seed.as_mut_ptr() as *mut c_void,
            seed.len(),
            0,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut rng = SimpleRng::new(u64::from_ne_bytes(seed));

    // Set an upper bound so that we don't end up spinning here forever.
    for _ in 0..MAX_ATTEMPTS {
        let mut name = String::from(".");
        name.push_str(&rng.str(6));
        let name = CString::new(name).expect("SimpleRng produced string with nul-bytes");

        // Safe because this doesn't modify any memory and we check the return value.
        let ret = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), mode) };
        if ret == 0 {
            return Ok(name);
        }

        let e = io::Error::last_os_error();
        if let Some(libc::EEXIST) = e.raw_os_error() {
            continue;
        } else {
            return Err(e);
        }
    }

    Err(io::Error::from_raw_os_error(libc::EAGAIN))
}

// A temporary directory that is automatically deleted when dropped unless `into_inner()` is called.
// This isn't a general-purpose temporary directory and is only intended to be used to ensure that
// there are no leaks when initializing a newly created directory with the correct metadata (see the
// implementation of `mkdir()` below). The directory is removed via a call to `unlinkat` so callers
// are not allowed to actually populate this temporary directory with any entries (or else deleting
// the directory will fail).
struct TempDir<'a> {
    parent: &'a File,
    name: CString,
    file: File,
}

impl<'a> TempDir<'a> {
    // Creates a new temporary directory in `parent` with a randomly generated name. `parent` must
    // be a directory.
    fn new(parent: &File, mode: libc::mode_t) -> io::Result<TempDir> {
        let name = create_temp_dir(parent, mode)?;

        // Safe because this doesn't modify any memory and we check the return value.
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(TempDir {
            parent,
            name,
            // Safe because we just opened this fd.
            file: unsafe { File::from_raw_fd(fd) },
        })
    }

    fn basename(&self) -> &CStr {
        &self.name
    }

    // Consumes the `TempDir`, returning the inner `File` without deleting the temporary
    // directory.
    fn into_inner(self) -> (CString, File) {
        // Safe because this is a valid pointer and we are going to call `mem::forget` on `self` so
        // we will not be aliasing memory.
        let _parent = unsafe { ptr::read(&self.parent) };
        let name = unsafe { ptr::read(&self.name) };
        let file = unsafe { ptr::read(&self.file) };
        mem::forget(self);

        (name, file)
    }
}

impl<'a> AsRawFd for TempDir<'a> {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

impl<'a> Drop for TempDir<'a> {
    fn drop(&mut self) {
        // Safe because this doesn't modify any memory and we check the return value.
        let ret = unsafe {
            libc::unlinkat(
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                libc::AT_REMOVEDIR,
            )
        };
        if ret < 0 {
            println!("Failed to remove tempdir: {}", io::Error::last_os_error());
            error!("Failed to remove tempdir: {}", io::Error::last_os_error());
        }
    }
}

// Checks whether `path` has a default posix acl xattr.
fn has_default_posix_acl(path: &CStr) -> io::Result<bool> {
    // Safe because this is a valid c string with no interior nul-bytes.
    let acl = unsafe { CStr::from_bytes_with_nul_unchecked(b"system.posix_acl_default\0") };

    // Safe because this doesn't modify any memory and we check the return value.
    let res = unsafe { libc::lgetxattr(path.as_ptr(), acl.as_ptr(), ptr::null_mut(), 0) };

    if res < 0 {
        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::ENODATA) | Some(libc::EOPNOTSUPP) => Ok(false),
            _ => Err(err),
        }
    } else {
        Ok(true)
    }
}

impl FileSystem for PassthroughFs {
    type Inode = Inode;
    type Handle = Handle;
    type DirIter = ReadDir<Box<[u8]>>;

    fn init(&self, capable: FsOptions) -> io::Result<FsOptions> {
        // Safe because this is a constant value and a valid C string.
        let root = unsafe { CStr::from_bytes_with_nul_unchecked(ROOT_CSTR) };

        // Safe because this doesn't modify any memory and we check the return value.
        // We use `O_PATH` because we just want this for traversing the directory tree
        // and not for actually reading the contents.
        let fd = unsafe {
            libc::openat(
                libc::AT_FDCWD,
                root.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // Safe because we just opened this fd above.
        let f = unsafe { File::from_raw_fd(fd) };

        let st = stat(&f)?;

        // Safe because this doesn't modify any memory and there is no need to check the return
        // value because this system call always succeeds. We need to clear the umask here because
        // we want the client to be able to set all the bits in the mode.
        unsafe { libc::umask(0o000) };

        let mut inodes = self.inodes.lock();

        // Not sure why the root inode gets a refcount of 2 but that's what libfuse does.
        inodes.insert(
            fuse::ROOT_ID,
            InodeAltKey {
                ino: st.st_ino,
                dev: st.st_dev,
            },
            Arc::new(InodeData {
                inode: fuse::ROOT_ID,
                file: f,
                refcount: AtomicU64::new(2),
            }),
        );

        let mut opts = FsOptions::DO_READDIRPLUS
            | FsOptions::READDIRPLUS_AUTO
            | FsOptions::EXPORT_SUPPORT
            | FsOptions::DONT_MASK
            | FsOptions::SECURITY_CONTEXT
            | FsOptions::POSIX_ACL;
        if self.cfg.writeback && capable.contains(FsOptions::WRITEBACK_CACHE) {
            opts |= FsOptions::WRITEBACK_CACHE;
            self.writeback.store(true, Ordering::Relaxed);
        }
        Ok(opts)
    }

    fn destroy(&self) {
        self.handles.lock().clear();
        self.inodes.lock().clear();
    }

    fn statfs(&self, _ctx: Context, inode: Inode) -> io::Result<libc::statvfs64> {
        let data = self
            .inodes
            .lock()
            .get(&inode)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        let mut out = MaybeUninit::<libc::statvfs64>::zeroed();

        // Safe because this will only modify `out` and we check the return value.
        let res = unsafe { libc::fstatvfs64(data.file.as_raw_fd(), out.as_mut_ptr()) };
        if res == 0 {
            // Safe because the kernel guarantees that `out` has been initialized.
            Ok(unsafe { out.assume_init() })
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn lookup(&self, _ctx: Context, parent: Inode, name: &CStr) -> io::Result<Entry> {
        self.do_lookup(parent, name)
    }

    fn forget(&self, _ctx: Context, inode: Inode, count: u64) {
        let mut inodes = self.inodes.lock();

        forget_one(&mut inodes, inode, count)
    }

    fn batch_forget(&self, _ctx: Context, requests: Vec<(Inode, u64)>) {
        let mut inodes = self.inodes.lock();

        for (inode, count) in requests {
            forget_one(&mut inodes, inode, count)
        }
    }

    fn opendir(
        &self,
        _ctx: Context,
        inode: Inode,
        flags: u32,
    ) -> io::Result<(Option<Handle>, OpenOptions)> {
        self.do_open(inode, flags | (libc::O_DIRECTORY as u32))
    }

    fn releasedir(
        &self,
        _ctx: Context,
        inode: Inode,
        _flags: u32,
        handle: Handle,
    ) -> io::Result<()> {
        self.do_release(inode, handle)
    }

    fn mkdir(
        &self,
        ctx: Context,
        parent: Inode,
        name: &CStr,
        mut mode: u32,
        umask: u32,
        security_ctx: Option<&CStr>,
    ) -> io::Result<Entry> {
        // This method has the same issues as `create()`: namely that the kernel may have allowed a
        // process to make a directory due to one of its supplementary groups but that information
        // is not forwarded to us. However, there is no `O_TMPDIR` equivalent for directories so
        // instead we create a "hidden" directory with a randomly generated name in the parent
        // directory, modify the uid/gid and mode to the proper values, and then rename it to the
        // requested name. This ensures that even in the case of a power loss the directory is not
        // visible in the filesystem with the requested name but incorrect metadata. The only thing
        // left would be a empty hidden directory with a random name.
        let data = self
            .inodes
            .lock()
            .get(&parent)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        let path = self.get_path(parent)?;

        let _ctx = security_ctx
            .filter(|ctx| ctx.to_bytes() != UNLABELED)
            .map(|ctx| ScopedSecurityContext::new(&self.proc, ctx))
            .transpose()?;

        // The presence of a default posix acl xattr in the parent directory completely changes the
        // meaning of the mode parameter so only apply the umask if it doesn't have one.
        if !has_default_posix_acl(&path)? {
            mode &= !umask;
        }

        let tmpdir = TempDir::new(&data.file, mode)?;

        // We need to respect the setgid bit in the parent directory if it is set.
        let st = stat(&data.file)?;
        let gid = if st.st_mode & libc::S_ISGID != 0 {
            st.st_gid
        } else {
            ctx.gid
        };

        // Set the uid and gid for the directory. Safe because this doesn't modify any memory and we
        // check the return value.
        let ret = unsafe { libc::fchown(tmpdir.as_raw_fd(), ctx.uid, gid) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        // Now rename it into place. Safe because this doesn't modify any memory and we check the
        // return value. TODO: Switch to libc::renameat2 once
        // https://github.com/rust-lang/libc/pull/1508 lands and we have glibc 2.28.
        let ret = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                data.file.as_raw_fd(),
                tmpdir.basename().as_ptr(),
                data.file.as_raw_fd(),
                name.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        // Now that we've moved the directory make sure we don't try to delete the now non-existent
        // `tmpdir`.
        tmpdir.into_inner();

        self.do_lookup(parent, name)
    }

    fn rmdir(&self, _ctx: Context, parent: Inode, name: &CStr) -> io::Result<()> {
        self.do_unlink(parent, name, libc::AT_REMOVEDIR)
    }

    fn readdir(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        size: u32,
        offset: u64,
    ) -> io::Result<Self::DirIter> {
        self.do_readdir(inode, handle, size, offset)
    }

    fn open(
        &self,
        _ctx: Context,
        inode: Inode,
        flags: u32,
    ) -> io::Result<(Option<Handle>, OpenOptions)> {
        self.do_open(inode, flags)
    }

    fn release(
        &self,
        _ctx: Context,
        inode: Inode,
        _flags: u32,
        handle: Handle,
        _flush: bool,
        _flock_release: bool,
        _lock_owner: Option<u64>,
    ) -> io::Result<()> {
        self.do_release(inode, handle)
    }

    fn create(
        &self,
        ctx: Context,
        parent: Inode,
        name: &CStr,
        mut mode: u32,
        flags: u32,
        umask: u32,
        security_ctx: Option<&CStr>,
    ) -> io::Result<(Entry, Option<Handle>, OpenOptions)> {
        // The `Context` may not contain all the information we need to create the file here. For
        // example, a process may be part of several groups, one of which gives it permission to
        // create a file in `parent`, but is not the gid of the process. This information is not
        // forwarded to the server so we don't know when this is happening. Instead, we just rely on
        // the access checks in the kernel driver: if we received this request then the kernel has
        // determined that the process is allowed to create the file and we shouldn't reject it now
        // based on acls.
        //
        // To ensure that the file is created atomically with the proper uid/gid we use `O_TMPFILE`
        // + `linkat` as described in the `open(2)` manpage.
        let data = self
            .inodes
            .lock()
            .get(&parent)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        let _ctx = security_ctx
            .filter(|ctx| ctx.to_bytes() != UNLABELED)
            .map(|ctx| ScopedSecurityContext::new(&self.proc, ctx))
            .transpose()?;

        // We don't want to use `O_EXCL` with `O_TMPFILE` as it has a different meaning when used in
        // that combination.
        let mut tmpflags = (flags as i32 | libc::O_TMPFILE | libc::O_CLOEXEC | libc::O_NOFOLLOW)
            & !(libc::O_EXCL | libc::O_CREAT);

        // O_TMPFILE requires that we use O_RDWR or O_WRONLY.
        if flags as i32 & libc::O_ACCMODE == libc::O_RDONLY {
            tmpflags &= !libc::O_ACCMODE;
            tmpflags |= libc::O_RDWR;
        }

        // The presence of a default posix acl xattr in the parent directory completely changes the
        // meaning of the mode parameter so only apply the umask if it doesn't have one.
        let path = self.get_path(parent)?;
        if !has_default_posix_acl(&path)? {
            mode &= !umask;
        }

        // Safe because this is a valid c string.
        let current_dir = unsafe { CStr::from_bytes_with_nul_unchecked(b".\0") };

        // Safe because this doesn't modify any memory and we check the return value.
        let fd =
            unsafe { libc::openat(data.file.as_raw_fd(), current_dir.as_ptr(), tmpflags, mode) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // Safe because we just opened this fd.
        let tmpfile = unsafe { File::from_raw_fd(fd) };

        // We need to respect the setgid bit in the parent directory if it is set.
        let st = stat(&data.file)?;
        let gid = if st.st_mode & libc::S_ISGID != 0 {
            st.st_gid
        } else {
            ctx.gid
        };

        // Now set the uid and gid for the file. Safe because this doesn't modify any memory and we
        // check the return value.
        let ret = unsafe { libc::fchown(tmpfile.as_raw_fd(), ctx.uid, gid) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        let proc_path = CString::new(format!("self/fd/{}", tmpfile.as_raw_fd()))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // Finally link it into the file system tree so that it's visible to other processes. Safe
        // because this doesn't modify any memory and we check the return value.
        let ret = unsafe {
            libc::linkat(
                self.proc.as_raw_fd(),
                proc_path.as_ptr(),
                data.file.as_raw_fd(),
                name.as_ptr(),
                libc::AT_SYMLINK_FOLLOW,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        // We no longer need the tmpfile.
        mem::drop(tmpfile);

        let entry = self.do_lookup(parent, name)?;
        let (handle, opts) = self
            .do_open(
                entry.inode,
                flags & !((libc::O_CREAT | libc::O_EXCL | libc::O_NOCTTY) as u32),
            )
            .map_err(|e| {
                // Don't leak the entry.
                self.forget(ctx, entry.inode, 1);
                e
            })?;

        Ok((entry, handle, opts))
    }

    fn unlink(&self, _ctx: Context, parent: Inode, name: &CStr) -> io::Result<()> {
        self.do_unlink(parent, name, 0)
    }

    fn read<W: io::Write + ZeroCopyWriter>(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        mut w: W,
        size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _flags: u32,
    ) -> io::Result<usize> {
        let data = self
            .handles
            .lock()
            .get(&handle)
            .filter(|hd| hd.inode == inode)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        let mut f = data.file.lock();
        w.write_from(&mut f, size as usize, offset)
    }

    fn write<R: io::Read + ZeroCopyReader>(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Handle,
        mut r: R,
        size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _delayed_write: bool,
        _flags: u32,
    ) -> io::Result<usize> {
        // We need to change credentials during a write so that the kernel will remove setuid or
        // setgid bits from the file if it was written to by someone other than the owner.
        let (_uid, _gid) = set_creds(ctx.uid, ctx.gid)?;
        let data = self
            .handles
            .lock()
            .get(&handle)
            .filter(|hd| hd.inode == inode)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        let mut f = data.file.lock();
        r.read_to(&mut f, size as usize, offset)
    }

    fn getattr(
        &self,
        _ctx: Context,
        inode: Inode,
        _handle: Option<Handle>,
    ) -> io::Result<(libc::stat64, Duration)> {
        self.do_getattr(inode)
    }

    fn setattr(
        &self,
        _ctx: Context,
        inode: Inode,
        attr: libc::stat64,
        handle: Option<Handle>,
        valid: SetattrValid,
    ) -> io::Result<(libc::stat64, Duration)> {
        let inode_data = self
            .inodes
            .lock()
            .get(&inode)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        enum Data {
            Handle(Arc<HandleData>, RawFd),
            ProcPath(CString),
        }

        // If we have a handle then use it otherwise get a new fd from the inode.
        let data = if let Some(handle) = handle {
            let hd = self
                .handles
                .lock()
                .get(&handle)
                .filter(|hd| hd.inode == inode)
                .map(Arc::clone)
                .ok_or_else(ebadf)?;

            let fd = hd.file.lock().as_raw_fd();
            Data::Handle(hd, fd)
        } else {
            let pathname = CString::new(format!("self/fd/{}", inode_data.file.as_raw_fd()))
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            Data::ProcPath(pathname)
        };

        if valid.contains(SetattrValid::MODE) {
            // Safe because this doesn't modify any memory and we check the return value.
            let res = unsafe {
                match data {
                    Data::Handle(_, fd) => libc::fchmod(fd, attr.st_mode),
                    Data::ProcPath(ref p) => {
                        libc::fchmodat(self.proc.as_raw_fd(), p.as_ptr(), attr.st_mode, 0)
                    }
                }
            };
            if res < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        if valid.intersects(SetattrValid::UID | SetattrValid::GID) {
            let uid = if valid.contains(SetattrValid::UID) {
                attr.st_uid
            } else {
                // Cannot use -1 here because these are unsigned values.
                ::std::u32::MAX
            };
            let gid = if valid.contains(SetattrValid::GID) {
                attr.st_gid
            } else {
                // Cannot use -1 here because these are unsigned values.
                ::std::u32::MAX
            };

            // Safe because this is a constant value and a valid C string.
            let empty = unsafe { CStr::from_bytes_with_nul_unchecked(EMPTY_CSTR) };

            // Safe because this doesn't modify any memory and we check the return value.
            let res = unsafe {
                libc::fchownat(
                    inode_data.file.as_raw_fd(),
                    empty.as_ptr(),
                    uid,
                    gid,
                    libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if res < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        if valid.contains(SetattrValid::SIZE) {
            // Safe because this doesn't modify any memory and we check the return value.
            let res = match data {
                Data::Handle(_, fd) => unsafe { libc::ftruncate64(fd, attr.st_size) },
                _ => {
                    // There is no `ftruncateat` so we need to get a new fd and truncate it.
                    let f = self.open_inode(inode, libc::O_NONBLOCK | libc::O_RDWR)?;
                    unsafe { libc::ftruncate64(f.as_raw_fd(), attr.st_size) }
                }
            };
            if res < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        if valid.intersects(SetattrValid::ATIME | SetattrValid::MTIME) {
            let mut tvs = [
                libc::timespec {
                    tv_sec: 0,
                    tv_nsec: libc::UTIME_OMIT,
                },
                libc::timespec {
                    tv_sec: 0,
                    tv_nsec: libc::UTIME_OMIT,
                },
            ];

            if valid.contains(SetattrValid::ATIME_NOW) {
                tvs[0].tv_nsec = libc::UTIME_NOW;
            } else if valid.contains(SetattrValid::ATIME) {
                tvs[0].tv_sec = attr.st_atime;
                tvs[0].tv_nsec = attr.st_atime_nsec;
            }

            if valid.contains(SetattrValid::MTIME_NOW) {
                tvs[1].tv_nsec = libc::UTIME_NOW;
            } else if valid.contains(SetattrValid::MTIME) {
                tvs[1].tv_sec = attr.st_mtime;
                tvs[1].tv_nsec = attr.st_mtime_nsec;
            }

            // Safe because this doesn't modify any memory and we check the return value.
            let res = match data {
                Data::Handle(_, fd) => unsafe { libc::futimens(fd, tvs.as_ptr()) },
                Data::ProcPath(ref p) => unsafe {
                    libc::utimensat(self.proc.as_raw_fd(), p.as_ptr(), tvs.as_ptr(), 0)
                },
            };
            if res < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        self.do_getattr(inode)
    }

    fn rename(
        &self,
        _ctx: Context,
        olddir: Inode,
        oldname: &CStr,
        newdir: Inode,
        newname: &CStr,
        flags: u32,
    ) -> io::Result<()> {
        let old_inode = self
            .inodes
            .lock()
            .get(&olddir)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;
        let new_inode = self
            .inodes
            .lock()
            .get(&newdir)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        // Safe because this doesn't modify any memory and we check the return value.
        // TODO: Switch to libc::renameat2 once https://github.com/rust-lang/libc/pull/1508 lands
        // and we have glibc 2.28.
        let res = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                old_inode.file.as_raw_fd(),
                oldname.as_ptr(),
                new_inode.file.as_raw_fd(),
                newname.as_ptr(),
                flags,
            )
        };
        if res == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn mknod(
        &self,
        ctx: Context,
        parent: Inode,
        name: &CStr,
        mut mode: u32,
        rdev: u32,
        umask: u32,
        security_ctx: Option<&CStr>,
    ) -> io::Result<Entry> {
        let (_uid, _gid) = set_creds(ctx.uid, ctx.gid)?;

        // The presence of a default posix acl xattr in the parent directory completely changes the
        // meaning of the mode parameter so only apply the umask if it doesn't have one.
        let path = self.get_path(parent)?;
        if !has_default_posix_acl(&path)? {
            mode &= !umask;
        }

        let data = self
            .inodes
            .lock()
            .get(&parent)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        let _ctx = security_ctx
            .filter(|ctx| ctx.to_bytes() != UNLABELED)
            .map(|ctx| ScopedSecurityContext::new(&self.proc, ctx))
            .transpose()?;

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe {
            libc::mknodat(
                data.file.as_raw_fd(),
                name.as_ptr(),
                mode as libc::mode_t,
                rdev as libc::dev_t,
            )
        };

        if res < 0 {
            Err(io::Error::last_os_error())
        } else {
            self.do_lookup(parent, name)
        }
    }

    fn link(
        &self,
        _ctx: Context,
        inode: Inode,
        newparent: Inode,
        newname: &CStr,
    ) -> io::Result<Entry> {
        let data = self
            .inodes
            .lock()
            .get(&inode)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;
        let new_inode = self
            .inodes
            .lock()
            .get(&newparent)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        let path = CString::new(format!("self/fd/{}", data.file.as_raw_fd()))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe {
            libc::linkat(
                self.proc.as_raw_fd(),
                path.as_ptr(),
                new_inode.file.as_raw_fd(),
                newname.as_ptr(),
                libc::AT_SYMLINK_FOLLOW,
            )
        };
        if res == 0 {
            self.do_lookup(newparent, newname)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn symlink(
        &self,
        ctx: Context,
        linkname: &CStr,
        parent: Inode,
        name: &CStr,
        security_ctx: Option<&CStr>,
    ) -> io::Result<Entry> {
        let data = self
            .inodes
            .lock()
            .get(&parent)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        let _ctx = security_ctx
            .filter(|ctx| ctx.to_bytes() != UNLABELED)
            .map(|ctx| ScopedSecurityContext::new(&self.proc, ctx))
            .transpose()?;

        let (_uid, _gid) = set_creds(ctx.uid, ctx.gid)?;

        // Safe because this doesn't modify any memory and we check the return value.
        let res =
            unsafe { libc::symlinkat(linkname.as_ptr(), data.file.as_raw_fd(), name.as_ptr()) };
        if res == 0 {
            self.do_lookup(parent, name)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn readlink(&self, _ctx: Context, inode: Inode) -> io::Result<Vec<u8>> {
        let data = self
            .inodes
            .lock()
            .get(&inode)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        let mut buf = Vec::with_capacity(libc::PATH_MAX as usize);
        buf.resize(libc::PATH_MAX as usize, 0);

        // Safe because this is a constant value and a valid C string.
        let empty = unsafe { CStr::from_bytes_with_nul_unchecked(EMPTY_CSTR) };

        // Safe because this will only modify the contents of `buf` and we check the return value.
        let res = unsafe {
            libc::readlinkat(
                data.file.as_raw_fd(),
                empty.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
            )
        };
        if res < 0 {
            return Err(io::Error::last_os_error());
        }

        buf.resize(res as usize, 0);
        Ok(buf)
    }

    fn flush(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        _lock_owner: u64,
    ) -> io::Result<()> {
        let data = self
            .handles
            .lock()
            .get(&handle)
            .filter(|hd| hd.inode == inode)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        // Since this method is called whenever an fd is closed in the client, we can emulate that
        // behavior by doing the same thing (dup-ing the fd and then immediately closing it). Safe
        // because this doesn't modify any memory and we check the return values.
        unsafe {
            let newfd = libc::dup(data.file.lock().as_raw_fd());
            if newfd < 0 {
                return Err(io::Error::last_os_error());
            }

            if libc::close(newfd) < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }

    fn fsync(&self, _ctx: Context, inode: Inode, datasync: bool, handle: Handle) -> io::Result<()> {
        let data = self
            .handles
            .lock()
            .get(&handle)
            .filter(|hd| hd.inode == inode)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        let fd = data.file.lock().as_raw_fd();

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe {
            if datasync {
                libc::fdatasync(fd)
            } else {
                libc::fsync(fd)
            }
        };

        if res == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn fsyncdir(
        &self,
        ctx: Context,
        inode: Inode,
        datasync: bool,
        handle: Handle,
    ) -> io::Result<()> {
        self.fsync(ctx, inode, datasync, handle)
    }

    fn access(&self, ctx: Context, inode: Inode, mask: u32) -> io::Result<()> {
        let data = self
            .inodes
            .lock()
            .get(&inode)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        let st = stat(&data.file)?;
        let mode = mask as i32 & (libc::R_OK | libc::W_OK | libc::X_OK);

        if mode == libc::F_OK {
            // The file exists since we were able to call `stat(2)` on it.
            return Ok(());
        }

        if (mode & libc::R_OK) != 0 {
            if ctx.uid != 0
                && (st.st_uid != ctx.uid || st.st_mode & 0o400 == 0)
                && (st.st_gid != ctx.gid || st.st_mode & 0o040 == 0)
                && st.st_mode & 0o004 == 0
            {
                return Err(io::Error::from_raw_os_error(libc::EACCES));
            }
        }

        if (mode & libc::W_OK) != 0 {
            if ctx.uid != 0
                && (st.st_uid != ctx.uid || st.st_mode & 0o200 == 0)
                && (st.st_gid != ctx.gid || st.st_mode & 0o020 == 0)
                && st.st_mode & 0o002 == 0
            {
                return Err(io::Error::from_raw_os_error(libc::EACCES));
            }
        }

        // root can only execute something if it is executable by one of the owner, the group, or
        // everyone.
        if (mode & libc::X_OK) != 0 {
            if (ctx.uid != 0 || st.st_mode & 0o111 == 0)
                && (st.st_uid != ctx.uid || st.st_mode & 0o100 == 0)
                && (st.st_gid != ctx.gid || st.st_mode & 0o010 == 0)
                && st.st_mode & 0o001 == 0
            {
                return Err(io::Error::from_raw_os_error(libc::EACCES));
            }
        }

        Ok(())
    }

    fn setxattr(
        &self,
        _ctx: Context,
        inode: Inode,
        name: &CStr,
        value: &[u8],
        flags: u32,
    ) -> io::Result<()> {
        // We can't allow the VM to set this xattr because an unprivileged process may use it to set
        // a privileged xattr.
        if self.cfg.rewrite_security_xattrs && name.to_bytes().starts_with(USER_VIRTIOFS_XATTR) {
            return Err(io::Error::from_raw_os_error(libc::EPERM));
        }

        let path = self.get_path(inode)?;

        let name = self.rewrite_xattr_name(name);

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe {
            libc::lsetxattr(
                path.as_ptr(),
                name.as_ptr(),
                value.as_ptr() as *const libc::c_void,
                value.len(),
                flags as libc::c_int,
            )
        };
        if res == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn getxattr(
        &self,
        _ctx: Context,
        inode: Inode,
        name: &CStr,
        size: u32,
    ) -> io::Result<GetxattrReply> {
        // We don't allow the VM to set this xattr so we also pretend there is no value associated
        // with it.
        if self.cfg.rewrite_security_xattrs && name.to_bytes().starts_with(USER_VIRTIOFS_XATTR) {
            return Err(io::Error::from_raw_os_error(libc::ENODATA));
        }

        let path = self.get_path(inode)?;

        let mut buf = Vec::with_capacity(size as usize);
        buf.resize(size as usize, 0);

        let name = self.rewrite_xattr_name(name);

        // Safe because this will only modify the contents of `buf`.
        let res = unsafe {
            libc::lgetxattr(
                path.as_ptr(),
                name.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_void,
                size as libc::size_t,
            )
        };
        if res < 0 {
            return Err(io::Error::last_os_error());
        }

        if size == 0 {
            Ok(GetxattrReply::Count(res as u32))
        } else {
            buf.resize(res as usize, 0);
            Ok(GetxattrReply::Value(buf))
        }
    }

    fn listxattr(&self, _ctx: Context, inode: Inode, size: u32) -> io::Result<ListxattrReply> {
        let path = self.get_path(inode)?;

        let mut buf = Vec::with_capacity(size as usize);
        buf.resize(size as usize, 0);

        // Safe because this will only modify the contents of `buf`.
        let res = unsafe {
            libc::llistxattr(
                path.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_char,
                size as libc::size_t,
            )
        };
        if res < 0 {
            return Err(io::Error::last_os_error());
        }

        if size == 0 {
            Ok(ListxattrReply::Count(res as u32))
        } else {
            buf.resize(res as usize, 0);

            if self.cfg.rewrite_security_xattrs {
                strip_xattr_prefix(&mut buf);
            }
            Ok(ListxattrReply::Names(buf))
        }
    }

    fn removexattr(&self, _ctx: Context, inode: Inode, name: &CStr) -> io::Result<()> {
        // We don't allow the VM to set this xattr so we also pretend there is no value associated
        // with it.
        if self.cfg.rewrite_security_xattrs && name.to_bytes().starts_with(USER_VIRTIOFS_XATTR) {
            return Err(io::Error::from_raw_os_error(libc::ENODATA));
        }

        let path = self.get_path(inode)?;

        let name = self.rewrite_xattr_name(name);

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe { libc::lremovexattr(path.as_ptr(), name.as_ptr()) };

        if res == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn fallocate(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        mode: u32,
        offset: u64,
        length: u64,
    ) -> io::Result<()> {
        let data = self
            .handles
            .lock()
            .get(&handle)
            .filter(|hd| hd.inode == inode)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        let fd = data.file.lock().as_raw_fd();
        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe {
            libc::fallocate64(
                fd,
                mode as libc::c_int,
                offset as libc::off64_t,
                length as libc::off64_t,
            )
        };
        if res == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn ioctl<R: io::Read>(
        &self,
        _ctx: Context,
        handle: Handle,
        _flags: IoctlFlags,
        cmd: u32,
        arg: u64,
        in_size: u32,
        out_size: u32,
        r: R,
    ) -> io::Result<IoctlReply> {
        const GET_ENCRYPTION_POLICY: u32 = FS_IOC_GET_ENCRYPTION_POLICY() as u32;
        const SET_ENCRYPTION_POLICY: u32 = FS_IOC_SET_ENCRYPTION_POLICY() as u32;
        const GET_FSXATTR: u32 = FS_IOC_FSGETXATTR() as u32;
        const SET_FSXATTR: u32 = FS_IOC_FSSETXATTR() as u32;
        const GET_FLAGS32: u32 = FS_IOC32_GETFLAGS() as u32;
        const SET_FLAGS32: u32 = FS_IOC32_SETFLAGS() as u32;
        const GET_FLAGS64: u32 = FS_IOC64_GETFLAGS() as u32;
        const SET_FLAGS64: u32 = FS_IOC64_SETFLAGS() as u32;

        // Normally, we wouldn't need to retry the FS_IOC_GET_ENCRYPTION_POLICY and
        // FS_IOC_SET_ENCRYPTION_POLICY ioctls. Unfortunately, the I/O directions for both of them
        // are encoded backwards so they can only be handled as unrestricted fuse ioctls.
        match cmd {
            GET_ENCRYPTION_POLICY => {
                if out_size < size_of::<fscrypt_policy_v1>() as u32 {
                    let input = Vec::new();
                    let output = vec![IoctlIovec {
                        base: arg,
                        len: size_of::<fscrypt_policy_v1>() as u64,
                    }];
                    Ok(IoctlReply::Retry { input, output })
                } else {
                    self.get_encryption_policy(handle)
                }
            }
            SET_ENCRYPTION_POLICY => {
                if in_size < size_of::<fscrypt_policy_v1>() as u32 {
                    let input = vec![IoctlIovec {
                        base: arg,
                        len: size_of::<fscrypt_policy_v1>() as u64,
                    }];
                    let output = Vec::new();
                    Ok(IoctlReply::Retry { input, output })
                } else {
                    self.set_encryption_policy(handle, r)
                }
            }
            GET_FSXATTR => {
                if out_size < size_of::<fsxattr>() as u32 {
                    Err(io::Error::from_raw_os_error(libc::ENOMEM))
                } else {
                    self.get_fsxattr(handle)
                }
            }
            SET_FSXATTR => {
                if in_size < size_of::<fsxattr>() as u32 {
                    Err(io::Error::from_raw_os_error(libc::EINVAL))
                } else {
                    self.set_fsxattr(handle, r)
                }
            }
            GET_FLAGS32 | GET_FLAGS64 => {
                if out_size < size_of::<c_int>() as u32 {
                    Err(io::Error::from_raw_os_error(libc::ENOMEM))
                } else {
                    self.get_flags(handle)
                }
            }
            SET_FLAGS32 | SET_FLAGS64 => {
                if in_size < size_of::<c_int>() as u32 {
                    Err(io::Error::from_raw_os_error(libc::ENOMEM))
                } else {
                    self.set_flags(handle, r)
                }
            }
            _ => Err(io::Error::from_raw_os_error(libc::ENOTTY)),
        }
    }

    fn copy_file_range(
        &self,
        ctx: Context,
        inode_src: Inode,
        handle_src: Handle,
        offset_src: u64,
        inode_dst: Inode,
        handle_dst: Handle,
        offset_dst: u64,
        length: u64,
        flags: u64,
    ) -> io::Result<usize> {
        // We need to change credentials during a write so that the kernel will remove setuid or
        // setgid bits from the file if it was written to by someone other than the owner.
        let (_uid, _gid) = set_creds(ctx.uid, ctx.gid)?;
        let src_data = self
            .handles
            .lock()
            .get(&handle_src)
            .filter(|hd| hd.inode == inode_src)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;
        let dst_data = self
            .handles
            .lock()
            .get(&handle_dst)
            .filter(|hd| hd.inode == inode_dst)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        let src = src_data.file.lock().as_raw_fd();
        let dst = dst_data.file.lock().as_raw_fd();

        let res = unsafe {
            libc::syscall(
                libc::SYS_copy_file_range,
                src,
                &offset_src,
                dst,
                &offset_dst,
                length,
                flags,
            )
        };

        if res >= 0 {
            Ok(res as usize)
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::env;
    use std::os::unix::ffi::OsStringExt;
    use std::path::PathBuf;

    #[test]
    fn create_temp_dir() {
        let testdir = CString::new(env::temp_dir().into_os_string().into_vec())
            .expect("env::temp_dir() is not a valid c-string");
        let fd = unsafe {
            libc::openat(
                libc::AT_FDCWD,
                testdir.as_ptr(),
                libc::O_PATH | libc::O_CLOEXEC,
            )
        };
        assert!(fd >= 0, "Failed to open env::temp_dir()");
        let parent = unsafe { File::from_raw_fd(fd) };
        let t = TempDir::new(&parent, 0o755).expect("Failed to create temporary directory");

        let basename = t.basename().to_string_lossy();
        let path = PathBuf::from(env::temp_dir()).join(&*basename);
        assert!(path.exists());
        assert!(path.is_dir());
    }

    #[test]
    fn remove_temp_dir() {
        let testdir = CString::new(env::temp_dir().into_os_string().into_vec())
            .expect("env::temp_dir() is not a valid c-string");
        let fd = unsafe {
            libc::openat(
                libc::AT_FDCWD,
                testdir.as_ptr(),
                libc::O_PATH | libc::O_CLOEXEC,
            )
        };
        assert!(fd >= 0, "Failed to open env::temp_dir()");
        let parent = unsafe { File::from_raw_fd(fd) };
        let t = TempDir::new(&parent, 0o755).expect("Failed to create temporary directory");

        let basename = t.basename().to_string_lossy();
        let path = PathBuf::from(env::temp_dir()).join(&*basename);
        mem::drop(t);
        assert!(!path.exists());
    }

    #[test]
    fn temp_dir_into_inner() {
        let testdir = CString::new(env::temp_dir().into_os_string().into_vec())
            .expect("env::temp_dir() is not a valid c-string");
        let fd = unsafe {
            libc::openat(
                libc::AT_FDCWD,
                testdir.as_ptr(),
                libc::O_PATH | libc::O_CLOEXEC,
            )
        };
        assert!(fd >= 0, "Failed to open env::temp_dir()");
        let parent = unsafe { File::from_raw_fd(fd) };
        let t = TempDir::new(&parent, 0o755).expect("Failed to create temporary directory");

        let (basename_cstr, _) = t.into_inner();
        let basename = basename_cstr.to_string_lossy();
        let path = PathBuf::from(env::temp_dir()).join(&*basename);
        assert!(path.exists());
    }

    #[test]
    fn rewrite_xattr_names() {
        let mut cfg = Config::default();
        cfg.rewrite_security_xattrs = true;

        let p = PassthroughFs::new(cfg).expect("Failed to create PassthroughFs");

        // Selinux shouldn't get overwritten.
        let selinux = unsafe { CStr::from_bytes_with_nul_unchecked(b"security.selinux\0") };
        assert_eq!(p.rewrite_xattr_name(selinux).to_bytes(), selinux.to_bytes());

        // user, trusted, and system should not be changed either.
        let user = unsafe { CStr::from_bytes_with_nul_unchecked(b"user.foobar\0") };
        assert_eq!(p.rewrite_xattr_name(user).to_bytes(), user.to_bytes());
        let trusted = unsafe { CStr::from_bytes_with_nul_unchecked(b"trusted.foobar\0") };
        assert_eq!(p.rewrite_xattr_name(trusted).to_bytes(), trusted.to_bytes());
        let system = unsafe { CStr::from_bytes_with_nul_unchecked(b"system.foobar\0") };
        assert_eq!(p.rewrite_xattr_name(system).to_bytes(), system.to_bytes());

        // sehash should be re-written.
        let sehash = unsafe { CStr::from_bytes_with_nul_unchecked(b"security.sehash\0") };
        assert_eq!(
            p.rewrite_xattr_name(sehash).to_bytes(),
            b"user.virtiofs.security.sehash"
        );
    }

    #[test]
    fn strip_xattr_names() {
        let only_nuls = b"\0\0\0\0\0";
        let mut actual = only_nuls.to_vec();
        strip_xattr_prefix(&mut actual);
        assert_eq!(&actual[..], &only_nuls[..]);

        let no_nuls = b"security.sehashuser.virtiofs";
        let mut actual = no_nuls.to_vec();
        strip_xattr_prefix(&mut actual);
        assert_eq!(&actual[..], &no_nuls[..]);

        let empty = b"";
        let mut actual = empty.to_vec();
        strip_xattr_prefix(&mut actual);
        assert_eq!(&actual[..], &empty[..]);

        let no_strippable_names = b"security.selinux\0user.foobar\0system.test\0";
        let mut actual = no_strippable_names.to_vec();
        strip_xattr_prefix(&mut actual);
        assert_eq!(&actual[..], &no_strippable_names[..]);

        let only_strippable_names = b"user.virtiofs.security.sehash\0user.virtiofs.security.wtf\0";
        let mut actual = only_strippable_names.to_vec();
        strip_xattr_prefix(&mut actual);
        assert_eq!(&actual[..], b"security.sehash\0security.wtf\0");

        let mixed_names = b"user.virtiofs.security.sehash\0security.selinux\0user.virtiofs.security.wtf\0user.foobar\0";
        let mut actual = mixed_names.to_vec();
        strip_xattr_prefix(&mut actual);
        let expected = b"security.sehash\0security.selinux\0security.wtf\0user.foobar\0";
        assert_eq!(&actual[..], &expected[..]);

        let no_nul_with_prefix = b"user.virtiofs.security.sehash";
        let mut actual = no_nul_with_prefix.to_vec();
        strip_xattr_prefix(&mut actual);
        assert_eq!(&actual[..], b"security.sehash");
    }
}
