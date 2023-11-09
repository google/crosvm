// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::borrow::Cow;
use std::cmp;
use std::collections::btree_map;
use std::collections::BTreeMap;
use std::ffi::CStr;
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::mem;
use std::mem::size_of;
use std::mem::MaybeUninit;
use std::os::raw::c_int;
use std::os::raw::c_long;
use std::ptr::addr_of;
use std::ptr::addr_of_mut;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::MutexGuard;
use std::time::Duration;

use base::error;
use base::ioctl_ior_nr;
use base::ioctl_iow_nr;
use base::ioctl_iowr_nr;
use base::ioctl_with_mut_ptr;
use base::ioctl_with_ptr;
use base::linux::FileFlags;
use base::syscall;
use base::AsRawDescriptor;
use base::FromRawDescriptor;
use base::Protection;
use base::RawDescriptor;
use data_model::zerocopy_from_reader;
use fuse::filesystem::Context;
use fuse::filesystem::DirectoryIterator;
use fuse::filesystem::Entry;
use fuse::filesystem::FileSystem;
use fuse::filesystem::FsOptions;
use fuse::filesystem::GetxattrReply;
use fuse::filesystem::IoctlFlags;
use fuse::filesystem::IoctlReply;
use fuse::filesystem::ListxattrReply;
use fuse::filesystem::OpenOptions;
use fuse::filesystem::RemoveMappingOne;
use fuse::filesystem::SetattrValid;
use fuse::filesystem::ZeroCopyReader;
use fuse::filesystem::ZeroCopyWriter;
use fuse::filesystem::ROOT_ID;
use fuse::sys::WRITE_KILL_PRIV;
use fuse::Mapper;
#[cfg(feature = "arc_quota")]
use protobuf::Message;
use sync::Mutex;
#[cfg(feature = "arc_quota")]
use system_api::client::OrgChromiumSpaced;
#[cfg(feature = "arc_quota")]
use system_api::spaced::SetProjectIdReply;
#[cfg(feature = "arc_quota")]
use system_api::spaced::SetProjectInheritanceFlagReply;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

use crate::virtio::fs::caps::Capability;
use crate::virtio::fs::caps::Caps;
use crate::virtio::fs::caps::Set as CapSet;
use crate::virtio::fs::caps::Value as CapValue;
use crate::virtio::fs::config::CachePolicy;
use crate::virtio::fs::config::Config;
use crate::virtio::fs::expiring_map::ExpiringMap;
use crate::virtio::fs::multikey::MultikeyBTreeMap;
use crate::virtio::fs::read_dir::ReadDir;

const EMPTY_CSTR: &[u8] = b"\0";
const ROOT_CSTR: &[u8] = b"/\0";
const PROC_CSTR: &[u8] = b"/proc\0";

const USER_VIRTIOFS_XATTR: &[u8] = b"user.virtiofs.";
const SECURITY_XATTR: &[u8] = b"security.";
const SELINUX_XATTR: &[u8] = b"security.selinux";

const FSCRYPT_KEY_DESCRIPTOR_SIZE: usize = 8;
const FSCRYPT_KEY_IDENTIFIER_SIZE: usize = 16;

#[cfg(feature = "arc_quota")]
const FS_PROJINHERIT_FL: c_int = 0x20000000;

// 25 seconds is the default timeout for dbus-send.
#[cfg(feature = "arc_quota")]
const DEFAULT_DBUS_TIMEOUT: Duration = Duration::from_secs(25);

/// Internal utility wrapper for `cros_tracing::trace_event!()` macro with VirtioFS calls.
macro_rules! fs_trace {
    ($tag:expr, $name:expr, $($arg:expr),+) => {
        cros_tracing::trace_event!(VirtioFs, $name, $tag, $($arg),*)
    };
}

#[repr(C)]
#[derive(Clone, Copy, AsBytes, FromZeroes, FromBytes)]
struct fscrypt_policy_v1 {
    _version: u8,
    _contents_encryption_mode: u8,
    _filenames_encryption_mode: u8,
    _flags: u8,
    _master_key_descriptor: [u8; FSCRYPT_KEY_DESCRIPTOR_SIZE],
}

#[repr(C)]
#[derive(Clone, Copy, AsBytes, FromZeroes, FromBytes)]
struct fscrypt_policy_v2 {
    _version: u8,
    _contents_encryption_mode: u8,
    _filenames_encryption_mode: u8,
    _flags: u8,
    __reserved: [u8; 4],
    master_key_identifier: [u8; FSCRYPT_KEY_IDENTIFIER_SIZE],
}

#[repr(C)]
#[derive(Copy, Clone, FromZeroes, FromBytes)]
union fscrypt_policy {
    _version: u8,
    _v1: fscrypt_policy_v1,
    _v2: fscrypt_policy_v2,
}

#[repr(C)]
#[derive(Copy, Clone, FromZeroes, FromBytes)]
struct fscrypt_get_policy_ex_arg {
    policy_size: u64,       /* input/output */
    policy: fscrypt_policy, /* output */
}

impl From<&fscrypt_get_policy_ex_arg> for &[u8] {
    fn from(value: &fscrypt_get_policy_ex_arg) -> Self {
        assert!(value.policy_size <= size_of::<fscrypt_policy>() as u64);
        let data_raw: *const fscrypt_get_policy_ex_arg = value;
        // Safe because the length of the output slice is asserted to be within the struct it points to
        unsafe {
            std::slice::from_raw_parts(
                data_raw.cast(),
                value.policy_size as usize + size_of::<u64>(),
            )
        }
    }
}

ioctl_iowr_nr!(FS_IOC_GET_ENCRYPTION_POLICY_EX, 'f' as u32, 22, [u8; 9]);

#[repr(C)]
#[derive(Clone, Copy, AsBytes, FromZeroes, FromBytes)]
struct fsxattr {
    fsx_xflags: u32,     /* xflags field value (get/set) */
    fsx_extsize: u32,    /* extsize field value (get/set)*/
    fsx_nextents: u32,   /* nextents field value (get)	*/
    fsx_projid: u32,     /* project identifier (get/set) */
    fsx_cowextsize: u32, /* CoW extsize field value (get/set)*/
    fsx_pad: [u8; 8],
}

ioctl_ior_nr!(FS_IOC_FSGETXATTR, 'X' as u32, 31, fsxattr);
ioctl_iow_nr!(FS_IOC_FSSETXATTR, 'X' as u32, 32, fsxattr);

ioctl_ior_nr!(FS_IOC_GETFLAGS, 'f' as u32, 1, c_long);
ioctl_iow_nr!(FS_IOC_SETFLAGS, 'f' as u32, 2, c_long);

ioctl_ior_nr!(FS_IOC32_GETFLAGS, 'f' as u32, 1, u32);
ioctl_iow_nr!(FS_IOC32_SETFLAGS, 'f' as u32, 2, u32);

ioctl_ior_nr!(FS_IOC64_GETFLAGS, 'f' as u32, 1, u64);
ioctl_iow_nr!(FS_IOC64_SETFLAGS, 'f' as u32, 2, u64);

#[repr(C)]
#[derive(Clone, Copy, AsBytes, FromZeroes, FromBytes)]
struct fsverity_enable_arg {
    _version: u32,
    _hash_algorithm: u32,
    _block_size: u32,
    salt_size: u32,
    salt_ptr: u64,
    sig_size: u32,
    __reserved1: u32,
    sig_ptr: u64,
    __reserved2: [u64; 11],
}

#[repr(C)]
#[derive(Clone, Copy, AsBytes, FromZeroes, FromBytes)]
struct fsverity_digest {
    _digest_algorithm: u16,
    digest_size: u16,
    // __u8 digest[];
}

ioctl_iow_nr!(FS_IOC_ENABLE_VERITY, 'f' as u32, 133, fsverity_enable_arg);
ioctl_iowr_nr!(FS_IOC_MEASURE_VERITY, 'f' as u32, 134, fsverity_digest);

pub type Inode = u64;
type Handle = u64;

#[derive(Clone, Copy, Debug, PartialOrd, Ord, PartialEq, Eq)]
struct InodeAltKey {
    ino: libc::ino64_t,
    dev: libc::dev_t,
}

#[derive(PartialEq, Eq, Debug)]
enum FileType {
    Regular,
    Directory,
    Other,
}

impl From<libc::mode_t> for FileType {
    fn from(mode: libc::mode_t) -> Self {
        match mode & libc::S_IFMT {
            libc::S_IFREG => FileType::Regular,
            libc::S_IFDIR => FileType::Directory,
            _ => FileType::Other,
        }
    }
}

#[derive(Debug)]
struct InodeData {
    inode: Inode,
    // (File, open_flags)
    file: Mutex<(File, libc::c_int)>,
    refcount: AtomicU64,
    filetype: FileType,
    path: String,
}

impl AsRawDescriptor for InodeData {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.file.lock().0.as_raw_descriptor()
    }
}

#[derive(Debug)]
struct HandleData {
    inode: Inode,
    file: Mutex<File>,
}

impl AsRawDescriptor for HandleData {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.file.lock().as_raw_descriptor()
    }
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

struct ScopedUmask {
    old: libc::mode_t,
    mask: libc::mode_t,
}

impl ScopedUmask {
    fn new(mask: libc::mode_t) -> ScopedUmask {
        ScopedUmask {
            // Safe because this doesn't modify any memory and always succeeds.
            old: unsafe { libc::umask(mask) },
            mask,
        }
    }
}

impl Drop for ScopedUmask {
    fn drop(&mut self) {
        // Safe because this doesn't modify any memory and always succeeds.
        let previous = unsafe { libc::umask(self.old) };
        debug_assert_eq!(
            previous, self.mask,
            "umask changed while holding ScopedUmask"
        );
    }
}

struct ScopedFsetid(Caps);
impl Drop for ScopedFsetid {
    fn drop(&mut self) {
        if let Err(e) = raise_cap_fsetid(&mut self.0) {
            error!(
                "Failed to restore CAP_FSETID: {}.  Some operations may be broken.",
                e
            )
        }
    }
}

fn raise_cap_fsetid(c: &mut Caps) -> io::Result<()> {
    c.update(&[Capability::Fsetid], CapSet::Effective, CapValue::Set)?;
    c.apply()
}

// Drops CAP_FSETID from the effective set for the current thread and returns an RAII guard that
// adds the capability back when it is dropped.
fn drop_cap_fsetid() -> io::Result<ScopedFsetid> {
    let mut caps = Caps::for_current_thread()?;
    caps.update(&[Capability::Fsetid], CapSet::Effective, CapValue::Clear)?;
    caps.apply()?;
    Ok(ScopedFsetid(caps))
}

fn ebadf() -> io::Error {
    io::Error::from_raw_os_error(libc::EBADF)
}

fn stat<F: AsRawDescriptor + ?Sized>(f: &F) -> io::Result<libc::stat64> {
    let mut st = MaybeUninit::<libc::stat64>::zeroed();

    // Safe because this is a constant value and a valid C string.
    let pathname = unsafe { CStr::from_bytes_with_nul_unchecked(EMPTY_CSTR) };

    // Safe because the kernel will only write data in `st` and we check the return
    // value.
    syscall!(unsafe {
        libc::fstatat64(
            f.as_raw_descriptor(),
            pathname.as_ptr(),
            st.as_mut_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
        )
    })?;

    // Safe because the kernel guarantees that the struct is now fully initialized.
    Ok(unsafe { st.assume_init() })
}

fn statat<D: AsRawDescriptor>(dir: &D, name: &CStr) -> io::Result<libc::stat64> {
    let mut st = MaybeUninit::<libc::stat64>::zeroed();

    // Safe because the kernel will only write data in `st` and we check the return
    // value.
    syscall!(unsafe {
        libc::fstatat64(
            dir.as_raw_descriptor(),
            name.as_ptr(),
            st.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    })?;

    // Safe because the kernel guarantees that the struct is now fully initialized.
    Ok(unsafe { st.assume_init() })
}

#[cfg(feature = "arc_quota")]
fn is_android_project_id(project_id: u32) -> bool {
    // The following constants defines the valid range of project ID used by
    // Android and are taken from android_filesystem_config.h in Android
    // codebase.
    //
    // Project IDs reserved for Android files on external storage. Total 100 IDs
    // from PROJECT_ID_EXT_DEFAULT (1000) are reserved.
    const PROJECT_ID_FOR_ANDROID_FILES: std::ops::RangeInclusive<u32> = 1000..=1099;
    // Project IDs reserved for Android apps.
    // The lower-limit of the range is PROJECT_ID_EXT_DATA_START.
    // The upper-limit of the range differs before and after T. Here we use that
    // of T (PROJECT_ID_APP_CACHE_END) as it is larger.
    const PROJECT_ID_FOR_ANDROID_APPS: std::ops::RangeInclusive<u32> = 20000..=69999;

    PROJECT_ID_FOR_ANDROID_FILES.contains(&project_id)
        || PROJECT_ID_FOR_ANDROID_APPS.contains(&project_id)
}

/// Per-directory cache for `PassthroughFs::ascii_casefold_lookup()`.
///
/// The key of the underlying `BTreeMap` is a lower-cased file name in the direcoty.
/// The value is the case-sensitive file name stored in the host file system.
/// We assume that if PassthroughFs has exclusive access to the filesystem, this cache exhaustively
///  covers all file names that exist within the directory.
/// So every `PassthroughFs`'s handler that adds or removes files in the directory is expected to
/// update this cache.
struct CasefoldCache(BTreeMap<Vec<u8>, CString>);

impl CasefoldCache {
    fn new(dir: &InodeData) -> io::Result<Self> {
        let mut mp = BTreeMap::new();

        let mut buf = [0u8; 1024];
        let mut offset = 0;
        loop {
            let mut read_dir = ReadDir::new(dir, offset, &mut buf[..])?;
            if read_dir.remaining() == 0 {
                break;
            }

            while let Some(entry) = read_dir.next() {
                offset = entry.offset as libc::off64_t;
                let entry_name = entry.name;
                mp.insert(
                    entry_name.to_bytes().to_ascii_lowercase(),
                    entry_name.to_owned(),
                );
            }
        }
        Ok(Self(mp))
    }

    fn insert(&mut self, name: &CStr) {
        let lower_case = name.to_bytes().to_ascii_lowercase();
        self.0.insert(lower_case, name.into());
    }

    fn lookup(&self, name: &[u8]) -> Option<CString> {
        let lower = name.to_ascii_lowercase();
        self.0.get(&lower).cloned()
    }

    fn remove(&mut self, name: &CStr) {
        let lower_case = name.to_bytes().to_ascii_lowercase();
        self.0.remove(&lower_case);
    }
}

/// Time expiring mapping from an inode of a directory to `CasefoldCache` for the directory.
/// Each entry will be expired after `timeout`.
/// When ascii_casefold is disabled, this struct does nothing.
struct ExpiringCasefoldLookupCaches {
    inner: ExpiringMap<Inode, CasefoldCache>,
}

impl ExpiringCasefoldLookupCaches {
    fn new(timeout: Duration) -> Self {
        Self {
            inner: ExpiringMap::new(timeout),
        }
    }

    fn insert(&mut self, parent: Inode, name: &CStr) {
        if let Some(dir_cache) = self.inner.get_mut(&parent) {
            dir_cache.insert(name);
        }
    }

    fn remove(&mut self, parent: Inode, name: &CStr) {
        if let Some(dir_cache) = self.inner.get_mut(&parent) {
            dir_cache.remove(name);
        }
    }

    fn forget(&mut self, parent: Inode) {
        self.inner.remove(&parent);
    }

    /// Get `CasefoldCache` for the given directory.
    /// If the cache doesn't exist, generate it by fetching directory information with
    /// `getdents64()`.
    fn get(&mut self, parent: &InodeData) -> io::Result<&CasefoldCache> {
        self.inner
            .get_or_insert_with(&parent.inode, || CasefoldCache::new(parent))
    }

    #[cfg(test)]
    fn exists_in_cache(&mut self, parent: Inode, name: &CStr) -> bool {
        if let Some(dir_cache) = self.inner.get(&parent) {
            dir_cache.lookup(name.to_bytes()).is_some()
        } else {
            false
        }
    }
}

/// A file system that simply "passes through" all requests it receives to the underlying file
/// system. To keep the implementation simple it servers the contents of its root directory. Users
/// that wish to serve only a specific directory should set up the environment so that that
/// directory ends up as the root of the file system process. One way to accomplish this is via a
/// combination of mount namespaces and the pivot_root system call.
pub struct PassthroughFs {
    // Mutex that must be acquired before executing a process-wide operation such as fchdir.
    process_lock: Mutex<()>,
    // virtio-fs tag that the guest uses when mounting. This is only used for debugging
    // when tracing is enabled.
    #[cfg_attr(not(feature = "trace_marker"), allow(dead_code))]
    tag: String,

    // File descriptors for various points in the file system tree.
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

    // Whether zero message opens are supported by the kernel driver.
    zero_message_open: AtomicBool,

    // Whether zero message opendir is supported by the kernel driver.
    zero_message_opendir: AtomicBool,

    // Used to communicate with other processes using D-Bus.
    #[cfg(feature = "arc_quota")]
    dbus_connection: Option<Mutex<dbus::blocking::Connection>>,
    #[cfg(feature = "arc_quota")]
    dbus_fd: Option<std::os::unix::io::RawFd>,

    // Time-expiring cache for `ascii_casefold_lookup()`.
    // The key is an inode of a directory, and the value is a cache for the directory.
    // Each value will be expired `cfg.timeout` after it's created.
    //
    // TODO(b/267748212): Instead of per-device Mutex, we might want to have per-directory Mutex
    // if we use PassthroughFs in multi-threaded environments.
    expiring_casefold_lookup_caches: Option<Mutex<ExpiringCasefoldLookupCaches>>,

    cfg: Config,
}

impl std::fmt::Debug for PassthroughFs {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("PassthroughFs")
            .field("tag", &self.tag)
            .field("next_inode", &self.next_inode)
            .field("next_handle", &self.next_handle)
            .field("proc", &self.proc)
            .field("writeback", &self.writeback)
            .field("zero_message_open", &self.zero_message_open)
            .field("zero_message_opendir", &self.zero_message_opendir)
            .field("cfg", &self.cfg)
            .finish()
    }
}

impl PassthroughFs {
    pub fn new(tag: &str, cfg: Config) -> io::Result<PassthroughFs> {
        // Safe because this is a constant value and a valid C string.
        let proc_cstr = unsafe { CStr::from_bytes_with_nul_unchecked(PROC_CSTR) };

        // Safe because this doesn't modify any memory and we check the return value.
        let raw_descriptor = syscall!(unsafe {
            libc::openat64(
                libc::AT_FDCWD,
                proc_cstr.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        })?;

        // Privileged UIDs can use D-Bus to perform some operations.
        #[cfg(feature = "arc_quota")]
        let (dbus_connection, dbus_fd) = if cfg.privileged_quota_uids.is_empty() {
            (None, None)
        } else {
            let mut channel = dbus::channel::Channel::get_private(dbus::channel::BusType::System)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            channel.set_watch_enabled(true);
            let dbus_fd = channel.watch().fd;
            channel.set_watch_enabled(false);
            (
                Some(Mutex::new(dbus::blocking::Connection::from(channel))),
                Some(dbus_fd),
            )
        };

        // Safe because we just opened this descriptor.
        let proc = unsafe { File::from_raw_descriptor(raw_descriptor) };

        let expiring_casefold_lookup_caches = if cfg.ascii_casefold {
            Some(Mutex::new(ExpiringCasefoldLookupCaches::new(cfg.timeout)))
        } else {
            None
        };

        let passthroughfs = PassthroughFs {
            process_lock: Mutex::new(()),
            tag: tag.to_string(),
            inodes: Mutex::new(MultikeyBTreeMap::new()),
            next_inode: AtomicU64::new(ROOT_ID + 1),

            handles: Mutex::new(BTreeMap::new()),
            next_handle: AtomicU64::new(1),

            proc,

            writeback: AtomicBool::new(false),
            zero_message_open: AtomicBool::new(false),
            zero_message_opendir: AtomicBool::new(false),

            #[cfg(feature = "arc_quota")]
            dbus_connection,
            #[cfg(feature = "arc_quota")]
            dbus_fd,
            expiring_casefold_lookup_caches,
            cfg,
        };

        cros_tracing::trace_simple_print!(
            VirtioFs,
            "New PassthroughFS initialized: {:?}",
            passthroughfs
        );
        Ok(passthroughfs)
    }

    pub fn cfg(&self) -> &Config {
        &self.cfg
    }

    pub fn keep_rds(&self) -> Vec<RawDescriptor> {
        #[cfg_attr(not(feature = "arc_quota"), allow(unused_mut))]
        let mut keep_rds = vec![self.proc.as_raw_descriptor()];
        #[cfg(feature = "arc_quota")]
        if let Some(fd) = self.dbus_fd {
            keep_rds.push(fd);
        }
        keep_rds
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

    fn find_inode(&self, inode: Inode) -> io::Result<Arc<InodeData>> {
        self.inodes
            .lock()
            .get(&inode)
            .map(Arc::clone)
            .ok_or_else(ebadf)
    }

    fn find_handle(&self, handle: Handle, inode: Inode) -> io::Result<Arc<HandleData>> {
        self.handles
            .lock()
            .get(&handle)
            .filter(|hd| hd.inode == inode)
            .map(Arc::clone)
            .ok_or_else(ebadf)
    }

    fn open_fd(&self, fd: RawDescriptor, flags: i32) -> io::Result<File> {
        let pathname = CString::new(format!("self/fd/{}", fd))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // Safe because this doesn't modify any memory and we check the return value. We don't
        // really check `flags` because if the kernel can't handle poorly specified flags then we
        // have much bigger problems. Also, clear the `O_NOFOLLOW` flag if it is set since we need
        // to follow the `/proc/self/fd` symlink to get the file.
        let raw_descriptor = syscall!(unsafe {
            libc::openat64(
                self.proc.as_raw_descriptor(),
                pathname.as_ptr(),
                (flags | libc::O_CLOEXEC) & !(libc::O_NOFOLLOW | libc::O_DIRECT),
            )
        })?;

        // Safe because we just opened this descriptor.
        Ok(unsafe { File::from_raw_descriptor(raw_descriptor) })
    }

    fn open_inode(&self, inode: &InodeData, mut flags: i32) -> io::Result<File> {
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

        self.open_fd(inode.as_raw_descriptor(), flags)
    }

    // Increases the inode refcount and returns the inode.
    fn increase_inode_refcount(&self, inode_data: &InodeData) -> Inode {
        // Matches with the release store in `forget`.
        inode_data.refcount.fetch_add(1, Ordering::Acquire);
        inode_data.inode
    }

    // Creates a new entry for `f` or increases the refcount of the existing entry for `f`.
    // The inodes mutex lock must not be already taken by the same thread otherwise this
    // will deadlock.
    fn add_entry(&self, f: File, st: libc::stat64, open_flags: libc::c_int, path: String) -> Entry {
        let mut inodes = self.inodes.lock();

        let altkey = InodeAltKey {
            ino: st.st_ino,
            dev: st.st_dev,
        };

        let inode = if let Some(data) = inodes.get_alt(&altkey) {
            self.increase_inode_refcount(data)
        } else {
            let inode = self.next_inode.fetch_add(1, Ordering::Relaxed);
            inodes.insert(
                inode,
                altkey,
                Arc::new(InodeData {
                    inode,
                    file: Mutex::new((f, open_flags)),
                    refcount: AtomicU64::new(1),
                    filetype: st.st_mode.into(),
                    path,
                }),
            );

            inode
        };

        Entry {
            inode,
            generation: 0,
            attr: st,
            // We use the same timeout for the attribute and the entry.
            attr_timeout: self.cfg.timeout,
            entry_timeout: self.cfg.timeout,
        }
    }

    /// Acquires lock of `expiring_casefold_lookup_caches` if `ascii_casefold` is enabled.
    fn lock_casefold_lookup_caches(&self) -> Option<MutexGuard<'_, ExpiringCasefoldLookupCaches>> {
        self.expiring_casefold_lookup_caches
            .as_ref()
            .map(|c| c.lock())
    }

    // Returns an actual case-sensitive file name that matches with the given `name`.
    // Returns `Ok(None)` if no file matches with the give `name`.
    // This function will panic if casefold is not enabled.
    fn lookup_case_unfolded_name(
        &self,
        parent: &InodeData,
        name: &[u8],
    ) -> io::Result<Option<CString>> {
        let mut caches = self
            .lock_casefold_lookup_caches()
            .expect("casefold must be enabled");
        let dir_cache = caches.get(parent)?;
        Ok(dir_cache.lookup(name))
    }

    // Performs an ascii case insensitive lookup.
    fn ascii_casefold_lookup(&self, parent: &InodeData, name: &[u8]) -> io::Result<Entry> {
        match self.lookup_case_unfolded_name(parent, name)? {
            None => Err(io::Error::from_raw_os_error(libc::ENOENT)),
            Some(actual_name) => self.do_lookup(parent, &actual_name),
        }
    }

    #[cfg(test)]
    fn exists_in_casefold_cache(&self, parent: Inode, name: &CStr) -> bool {
        let mut cache = self
            .lock_casefold_lookup_caches()
            .expect("casefold must be enabled");
        cache.exists_in_cache(parent, name)
    }

    fn do_lookup(&self, parent: &InodeData, name: &CStr) -> io::Result<Entry> {
        let st = statat(parent, name)?;

        let altkey = InodeAltKey {
            ino: st.st_ino,
            dev: st.st_dev,
        };

        // Check if we already have an entry before opening a new file.
        if let Some(data) = self.inodes.lock().get_alt(&altkey) {
            // Return the same inode with the reference counter increased.
            return Ok(Entry {
                inode: self.increase_inode_refcount(data),
                generation: 0,
                attr: st,
                // We use the same timeout for the attribute and the entry.
                attr_timeout: self.cfg.timeout,
                entry_timeout: self.cfg.timeout,
            });
        }

        // Open a regular file with O_RDONLY to store in `InodeData` so explicit open requests can
        // be skipped later if the ZERO_MESSAGE_{OPEN,OPENDIR} features are enabled.
        // If the crosvm process doesn't have a read permission, fall back to O_PATH below.
        let mut flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        match FileType::from(st.st_mode) {
            FileType::Regular => {}
            FileType::Directory => flags |= libc::O_DIRECTORY,
            FileType::Other => flags |= libc::O_PATH,
        };

        // Safe because this doesn't modify any memory and we check the return value.
        let fd = match unsafe {
            syscall!(libc::openat64(
                parent.as_raw_descriptor(),
                name.as_ptr(),
                flags
            ))
        } {
            Ok(fd) => fd,
            Err(e) if e.errno() == libc::EACCES => {
                // If O_RDONLY is unavailable, fall back to O_PATH to get an FD to store in
                // `InodeData`.
                // Note that some operations which should be allowed without read permissions
                // require syscalls that don't support O_PATH fds. For those syscalls, we will
                // need to fall back to their path-based equivalents with /self/fd/${FD}.
                // e.g. `fgetxattr()` for an O_PATH FD fails while `getxaattr()` for /self/fd/${FD}
                // works.
                flags |= libc::O_PATH;
                // Safe because this doesn't modify any memory and we check the return value.
                unsafe {
                    syscall!(libc::openat64(
                        parent.as_raw_descriptor(),
                        name.as_ptr(),
                        flags
                    ))
                }?
            }
            Err(e) => {
                return Err(e.into());
            }
        };

        // Safe because we own the fd.
        let f = unsafe { File::from_raw_descriptor(fd) };
        let path = format!(
            "{}/{}",
            parent.path.clone(),
            name.to_str().unwrap_or("<non UTF-8 str>")
        );
        // We made sure the lock acquired for `self.inodes` is released automatically when
        // the if block above is exited, so a call to `self.add_entry()` should not cause a deadlock
        // here. This would not be the case if this were executed in an else block instead.
        Ok(self.add_entry(f, st, flags, path))
    }

    fn do_open(&self, inode: Inode, flags: u32) -> io::Result<(Option<Handle>, OpenOptions)> {
        let inode_data = self.find_inode(inode)?;

        let file = Mutex::new(self.open_inode(&inode_data, flags as i32)?);

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

    fn do_getattr(&self, inode: &InodeData) -> io::Result<(libc::stat64, Duration)> {
        let st = stat(inode)?;

        Ok((st, self.cfg.timeout))
    }

    fn do_unlink(&self, parent: &InodeData, name: &CStr, flags: libc::c_int) -> io::Result<()> {
        // Safe because this doesn't modify any memory and we check the return value.
        syscall!(unsafe { libc::unlinkat(parent.as_raw_descriptor(), name.as_ptr(), flags) })?;
        Ok(())
    }

    fn do_fsync<F: AsRawDescriptor>(&self, file: &F, datasync: bool) -> io::Result<()> {
        // Safe because this doesn't modify any memory and we check the return value.
        syscall!(unsafe {
            if datasync {
                libc::fdatasync(file.as_raw_descriptor())
            } else {
                libc::fsync(file.as_raw_descriptor())
            }
        })?;

        Ok(())
    }

    // Changes the CWD to `self.proc`, runs `f`, and then changes the CWD back to the root
    // directory. This effectively emulates an *at syscall starting at /proc, which is useful when
    // there is no *at syscall available. Panics if any of the fchdir calls fail or if there is no
    // root inode.
    //
    // NOTE: this method acquires an `self`-wide lock. If any locks are acquired in `f`, care must
    // be taken to avoid the risk of deadlocks.
    fn with_proc_chdir<F, T>(&self, f: F) -> T
    where
        F: FnOnce() -> T,
    {
        let root = self.find_inode(ROOT_ID).expect("failed to find root inode");

        // Acquire a lock for `fchdir`.
        let _proc_lock = self.process_lock.lock();
        // Safe because this doesn't modify any memory and we check the return value. Since the
        // fchdir should never fail we just use debug_asserts.
        let proc_cwd = unsafe { libc::fchdir(self.proc.as_raw_descriptor()) };
        debug_assert_eq!(
            proc_cwd,
            0,
            "failed to fchdir to /proc: {}",
            io::Error::last_os_error()
        );

        let res = f();

        // Safe because this doesn't modify any memory and we check the return value. Since the
        // fchdir should never fail we just use debug_asserts.
        let root_cwd = unsafe { libc::fchdir(root.as_raw_descriptor()) };
        debug_assert_eq!(
            root_cwd,
            0,
            "failed to fchdir back to root directory: {}",
            io::Error::last_os_error()
        );

        res
    }

    fn do_getxattr(&self, inode: &InodeData, name: &CStr, value: &mut [u8]) -> io::Result<usize> {
        let file = inode.file.lock();
        let o_path_file = (file.1 & libc::O_PATH) != 0;
        let res = if o_path_file {
            // For FDs opened with `O_PATH`, we cannot call `fgetxattr` normally. Instead we
            // emulate an _at syscall by changing the CWD to /proc, running the path based syscall,
            //  and then setting the CWD back to the root directory.
            let path = CString::new(format!("self/fd/{}", file.0.as_raw_descriptor()))
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            // Safe because this will only modify `value` and we check the return value.
            self.with_proc_chdir(|| unsafe {
                libc::getxattr(
                    path.as_ptr(),
                    name.as_ptr(),
                    value.as_mut_ptr() as *mut libc::c_void,
                    value.len() as libc::size_t,
                )
            })
        } else {
            // For regular files and directories, we can just use fgetxattr. Safe because this will
            // only write to `value` and we check the return value.
            unsafe {
                libc::fgetxattr(
                    file.0.as_raw_descriptor(),
                    name.as_ptr(),
                    value.as_mut_ptr() as *mut libc::c_void,
                    value.len() as libc::size_t,
                )
            }
        };

        if res < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(res as usize)
        }
    }

    fn get_encryption_policy_ex<R: io::Read>(
        &self,
        inode: Inode,
        handle: Handle,
        mut r: R,
    ) -> io::Result<IoctlReply> {
        let data: Arc<dyn AsRawDescriptor> = if self.zero_message_open.load(Ordering::Relaxed) {
            self.find_inode(inode)?
        } else {
            self.find_handle(handle, inode)?
        };

        // Safe because this only has integer fields.
        let mut arg = unsafe { MaybeUninit::<fscrypt_get_policy_ex_arg>::zeroed().assume_init() };
        r.read_exact(arg.policy_size.as_bytes_mut())?;

        let policy_size = cmp::min(arg.policy_size, size_of::<fscrypt_policy>() as u64);
        arg.policy_size = policy_size;

        // Safe because the kernel will only write to `arg` and we check the return value.
        let res =
            unsafe { ioctl_with_mut_ptr(&*data, FS_IOC_GET_ENCRYPTION_POLICY_EX(), &mut arg) };
        if res < 0 {
            Ok(IoctlReply::Done(Err(io::Error::last_os_error())))
        } else {
            let len = size_of::<u64>() + arg.policy_size as usize;
            Ok(IoctlReply::Done(Ok(<&[u8]>::from(&arg)[..len].to_vec())))
        }
    }

    fn get_fsxattr(&self, inode: Inode, handle: Handle) -> io::Result<IoctlReply> {
        let data: Arc<dyn AsRawDescriptor> = if self.zero_message_open.load(Ordering::Relaxed) {
            self.find_inode(inode)?
        } else {
            self.find_handle(handle, inode)?
        };

        let mut buf = MaybeUninit::<fsxattr>::zeroed();

        // Safe because the kernel will only write to `buf` and we check the return value.
        let res = unsafe { ioctl_with_mut_ptr(&*data, FS_IOC_FSGETXATTR(), buf.as_mut_ptr()) };
        if res < 0 {
            Ok(IoctlReply::Done(Err(io::Error::last_os_error())))
        } else {
            // Safe because the kernel guarantees that the policy is now initialized.
            let xattr = unsafe { buf.assume_init() };
            Ok(IoctlReply::Done(Ok(xattr.as_bytes().to_vec())))
        }
    }

    fn set_fsxattr<R: io::Read>(
        &self,
        #[cfg_attr(not(feature = "arc_quota"), allow(unused_variables))] ctx: Context,
        inode: Inode,
        handle: Handle,
        r: R,
    ) -> io::Result<IoctlReply> {
        let data: Arc<dyn AsRawDescriptor> = if self.zero_message_open.load(Ordering::Relaxed) {
            self.find_inode(inode)?
        } else {
            self.find_handle(handle, inode)?
        };

        let in_attr: fsxattr = zerocopy_from_reader(r)?;

        #[cfg(feature = "arc_quota")]
        let st = stat(&*data)?;

        // Changing quota project ID requires CAP_FOWNER or being file owner.
        // Here we use privileged_quota_uids because we cannot perform a CAP_FOWNER check.
        #[cfg(feature = "arc_quota")]
        if ctx.uid == st.st_uid || self.cfg.privileged_quota_uids.contains(&ctx.uid) {
            // Get the current fsxattr.
            let mut buf = MaybeUninit::<fsxattr>::zeroed();
            // Safe because the kernel will only write to `buf` and we check the return value.
            let res = unsafe { ioctl_with_mut_ptr(&*data, FS_IOC_FSGETXATTR(), buf.as_mut_ptr()) };
            if res < 0 {
                return Ok(IoctlReply::Done(Err(io::Error::last_os_error())));
            }
            // Safe because the kernel guarantees that the policy is now initialized.
            let current_attr = unsafe { buf.assume_init() };

            // Project ID cannot be changed inside a user namespace.
            // Use Spaced to avoid this restriction.
            if current_attr.fsx_projid != in_attr.fsx_projid {
                let connection = self.dbus_connection.as_ref().unwrap().lock();
                let proxy = connection.with_proxy(
                    "org.chromium.Spaced",
                    "/org/chromium/Spaced",
                    DEFAULT_DBUS_TIMEOUT,
                );
                let project_id = in_attr.fsx_projid;
                if !is_android_project_id(project_id) {
                    return Err(io::Error::from_raw_os_error(libc::EINVAL));
                }
                // Safe because data is a valid file descriptor.
                let fd = unsafe { dbus::arg::OwnedFd::new(base::clone_descriptor(&*data)?) };
                match proxy.set_project_id(fd, project_id) {
                    Ok(r) => {
                        let r = SetProjectIdReply::parse_from_bytes(&r)
                            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                        if !r.success {
                            return Ok(IoctlReply::Done(Err(io::Error::from_raw_os_error(
                                r.error,
                            ))));
                        }
                    }
                    Err(e) => {
                        return Err(io::Error::new(io::ErrorKind::Other, e));
                    }
                };
            }
        }

        //  Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe { ioctl_with_ptr(&*data, FS_IOC_FSSETXATTR(), &in_attr) };
        if res < 0 {
            Ok(IoctlReply::Done(Err(io::Error::last_os_error())))
        } else {
            Ok(IoctlReply::Done(Ok(Vec::new())))
        }
    }

    fn get_flags(&self, inode: Inode, handle: Handle) -> io::Result<IoctlReply> {
        let data: Arc<dyn AsRawDescriptor> = if self.zero_message_open.load(Ordering::Relaxed) {
            self.find_inode(inode)?
        } else {
            self.find_handle(handle, inode)?
        };

        // The ioctl encoding is a long but the parameter is actually an int.
        let mut flags: c_int = 0;

        // Safe because the kernel will only write to `flags` and we check the return value.
        let res = unsafe { ioctl_with_mut_ptr(&*data, FS_IOC_GETFLAGS(), &mut flags) };
        if res < 0 {
            Ok(IoctlReply::Done(Err(io::Error::last_os_error())))
        } else {
            Ok(IoctlReply::Done(Ok(flags.to_ne_bytes().to_vec())))
        }
    }

    fn set_flags<R: io::Read>(
        &self,
        #[cfg_attr(not(feature = "arc_quota"), allow(unused_variables))] ctx: Context,
        inode: Inode,
        handle: Handle,
        r: R,
    ) -> io::Result<IoctlReply> {
        let data: Arc<dyn AsRawDescriptor> = if self.zero_message_open.load(Ordering::Relaxed) {
            self.find_inode(inode)?
        } else {
            self.find_handle(handle, inode)?
        };

        // The ioctl encoding is a long but the parameter is actually an int.
        let in_flags: c_int = zerocopy_from_reader(r)?;

        #[cfg(feature = "arc_quota")]
        let st = stat(&*data)?;

        // Only privleged uid can perform FS_IOC_SETFLAGS through cryptohome.
        #[cfg(feature = "arc_quota")]
        if ctx.uid == st.st_uid || self.cfg.privileged_quota_uids.contains(&ctx.uid) {
            // Get the current flag.
            let mut buf = MaybeUninit::<c_int>::zeroed();
            // Safe because the kernel will only write to `buf` and we check the return value.
            let res = unsafe { ioctl_with_mut_ptr(&*data, FS_IOC_GETFLAGS(), buf.as_mut_ptr()) };
            if res < 0 {
                return Ok(IoctlReply::Done(Err(io::Error::last_os_error())));
            }
            // Safe because the kernel guarantees that the policy is now initialized.
            let current_flags = unsafe { buf.assume_init() };

            // Project inheritance flag cannot be changed inside a user namespace.
            // Use Spaced to avoid this restriction.
            if (in_flags & FS_PROJINHERIT_FL) != (current_flags & FS_PROJINHERIT_FL) {
                let connection = self.dbus_connection.as_ref().unwrap().lock();
                let proxy = connection.with_proxy(
                    "org.chromium.Spaced",
                    "/org/chromium/Spaced",
                    DEFAULT_DBUS_TIMEOUT,
                );
                // If the input flags contain FS_PROJINHERIT_FL, then it is a set. Otherwise it is a
                // reset.
                let enable = (in_flags & FS_PROJINHERIT_FL) == FS_PROJINHERIT_FL;
                // Safe because data is a valid file descriptor.
                let fd = unsafe { dbus::arg::OwnedFd::new(base::clone_descriptor(&*data)?) };
                match proxy.set_project_inheritance_flag(fd, enable) {
                    Ok(r) => {
                        let r = SetProjectInheritanceFlagReply::parse_from_bytes(&r)
                            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                        if !r.success {
                            return Ok(IoctlReply::Done(Err(io::Error::from_raw_os_error(
                                r.error,
                            ))));
                        }
                    }
                    Err(e) => {
                        return Err(io::Error::new(io::ErrorKind::Other, e));
                    }
                };
            }
        }

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe { ioctl_with_ptr(&*data, FS_IOC_SETFLAGS(), &in_flags) };
        if res < 0 {
            Ok(IoctlReply::Done(Err(io::Error::last_os_error())))
        } else {
            Ok(IoctlReply::Done(Ok(Vec::new())))
        }
    }

    fn enable_verity<R: io::Read>(
        &self,
        inode: Inode,
        handle: Handle,
        mut r: R,
    ) -> io::Result<IoctlReply> {
        let inode_data = self.find_inode(inode)?;

        // These match the return codes from `fsverity_ioctl_enable` in the kernel.
        match inode_data.filetype {
            FileType::Regular => {}
            FileType::Directory => return Err(io::Error::from_raw_os_error(libc::EISDIR)),
            FileType::Other => return Err(io::Error::from_raw_os_error(libc::EINVAL)),
        }

        {
            // We cannot enable verity while holding a writable fd so get a new one, if necessary.
            let mut file = inode_data.file.lock();
            let mut flags = file.1;
            match flags & libc::O_ACCMODE {
                libc::O_WRONLY | libc::O_RDWR => {
                    flags &= !libc::O_ACCMODE;
                    flags |= libc::O_RDONLY;

                    // We need to get a read-only handle for this file.
                    let newfile = self.open_fd(file.0.as_raw_descriptor(), libc::O_RDONLY)?;
                    *file = (newfile, flags);
                }
                libc::O_RDONLY => {}
                _ => panic!("Unexpected flags: {:#x}", flags),
            }
        }

        let data: Arc<dyn AsRawDescriptor> = if self.zero_message_open.load(Ordering::Relaxed) {
            inode_data
        } else {
            let data = self.find_handle(handle, inode)?;

            {
                // We can't enable verity while holding a writable fd. We don't know whether the file
                // was opened for writing so check it here. We don't expect this to be a frequent
                // operation so the extra latency should be fine.
                let mut file = data.file.lock();
                let flags = FileFlags::from_file(&*file).map_err(io::Error::from)?;
                match flags {
                    FileFlags::ReadWrite | FileFlags::Write => {
                        // We need to get a read-only handle for this file.
                        *file = self.open_fd(file.as_raw_descriptor(), libc::O_RDONLY)?;
                    }
                    FileFlags::Read => {}
                }
            }

            data
        };

        let mut arg: fsverity_enable_arg = zerocopy_from_reader(&mut r)?;

        let mut salt;
        if arg.salt_size > 0 {
            if arg.salt_size > self.max_buffer_size() {
                return Ok(IoctlReply::Done(Err(io::Error::from_raw_os_error(
                    libc::ENOMEM,
                ))));
            }
            salt = vec![0; arg.salt_size as usize];
            r.read_exact(&mut salt)?;
            arg.salt_ptr = salt.as_ptr() as usize as u64;
        } else {
            arg.salt_ptr = 0;
        }

        let mut sig;
        if arg.sig_size > 0 {
            if arg.sig_size > self.max_buffer_size() {
                return Ok(IoctlReply::Done(Err(io::Error::from_raw_os_error(
                    libc::ENOMEM,
                ))));
            }
            sig = vec![0; arg.sig_size as usize];
            r.read_exact(&mut sig)?;
            arg.sig_ptr = sig.as_ptr() as usize as u64;
        } else {
            arg.sig_ptr = 0;
        }

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe { ioctl_with_ptr(&*data, FS_IOC_ENABLE_VERITY(), &arg) };
        if res < 0 {
            Ok(IoctlReply::Done(Err(io::Error::last_os_error())))
        } else {
            Ok(IoctlReply::Done(Ok(Vec::new())))
        }
    }

    fn measure_verity<R: io::Read>(
        &self,
        inode: Inode,
        handle: Handle,
        r: R,
        out_size: u32,
    ) -> io::Result<IoctlReply> {
        let data: Arc<dyn AsRawDescriptor> = if self.zero_message_open.load(Ordering::Relaxed) {
            self.find_inode(inode)?
        } else {
            self.find_handle(handle, inode)?
        };

        let digest: fsverity_digest = zerocopy_from_reader(r)?;

        // Taken from fs/verity/fsverity_private.h.
        const FS_VERITY_MAX_DIGEST_SIZE: u16 = 64;

        // This digest size is what the fsverity command line utility uses.
        const DIGEST_SIZE: u16 = FS_VERITY_MAX_DIGEST_SIZE * 2 + 1;
        const BUFLEN: usize = size_of::<fsverity_digest>() + DIGEST_SIZE as usize;
        const ROUNDED_LEN: usize =
            (BUFLEN + size_of::<fsverity_digest>() - 1) / size_of::<fsverity_digest>();

        // Make sure we get a properly aligned allocation.
        let mut buf = [MaybeUninit::<fsverity_digest>::uninit(); ROUNDED_LEN];

        // Safe because we are only writing data and not reading uninitialized memory.
        unsafe {
            // TODO: Replace with `MaybeUninit::slice_as_mut_ptr` once it is stabilized.
            addr_of_mut!((*(buf.as_mut_ptr() as *mut fsverity_digest)).digest_size)
                .write(DIGEST_SIZE)
        };

        // Safe because this will only modify `buf` and we check the return value.
        let res = unsafe { ioctl_with_mut_ptr(&*data, FS_IOC_MEASURE_VERITY(), buf.as_mut_ptr()) };
        if res < 0 {
            Ok(IoctlReply::Done(Err(io::Error::last_os_error())))
        } else {
            // Safe because this value was initialized by us already and then overwritten by the
            // kernel.
            // TODO: Replace with `MaybeUninit::slice_as_ptr` once it is stabilized.
            let digest_size =
                unsafe { addr_of!((*(buf.as_ptr() as *const fsverity_digest)).digest_size).read() };
            let outlen = size_of::<fsverity_digest>() as u32 + u32::from(digest_size);

            // The kernel guarantees this but it doesn't hurt to be paranoid.
            debug_assert!(outlen <= (ROUNDED_LEN * size_of::<fsverity_digest>()) as u32);
            if digest.digest_size < digest_size || out_size < outlen {
                return Ok(IoctlReply::Done(Err(io::Error::from_raw_os_error(
                    libc::EOVERFLOW,
                ))));
            }

            // Safe because any bit pattern is valid for `MaybeUninit<u8>` and `fsverity_digest`
            // doesn't contain any references.
            let buf: [MaybeUninit<u8>; ROUNDED_LEN * size_of::<fsverity_digest>()] =
                unsafe { mem::transmute(buf) };

            // Casting to `*const [u8]` is safe because the kernel guarantees that the first
            // `outlen` bytes of `buf` are initialized and `MaybeUninit<u8>` is guaranteed to have
            // the same layout as `u8`.
            // TODO: Replace with `MaybeUninit::slice_assume_init_ref` once it is stabilized.
            let buf =
                unsafe { &*(&buf[..outlen as usize] as *const [MaybeUninit<u8>] as *const [u8]) };
            Ok(IoctlReply::Done(Ok(buf.to_vec())))
        }
    }
}

/// Decrements the refcount of the inode.
/// Returns `true` if the refcount became 0.
fn forget_one(
    inodes: &mut MultikeyBTreeMap<Inode, InodeAltKey, Arc<InodeData>>,
    inode: Inode,
    count: u64,
) -> bool {
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
                .compare_exchange_weak(refcount, new_count, Ordering::Release, Ordering::Relaxed)
                .is_ok()
            {
                if new_count == 0 {
                    // We just removed the last refcount for this inode. There's no need for an
                    // acquire fence here because we hold a write lock on the inode map and any
                    // thread that is waiting to do a forget on the same inode will have to wait
                    // until we release the lock. So there's is no other release store for us to
                    // synchronize with before deleting the entry.
                    inodes.remove(&inode);
                    return true;
                }
                break;
            }
        }
    }
    false
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
    while let Some(name) = next_cstr(buf, pos) {
        if !name.starts_with(USER_VIRTIOFS_XATTR) {
            pos += name.len();
            continue;
        }

        let newlen = name.len() - USER_VIRTIOFS_XATTR.len();
        buf.drain(pos..pos + USER_VIRTIOFS_XATTR.len());
        pos += newlen;
    }
}

impl FileSystem for PassthroughFs {
    type Inode = Inode;
    type Handle = Handle;
    type DirIter = ReadDir<Box<[u8]>>;

    fn init(&self, capable: FsOptions) -> io::Result<FsOptions> {
        // Safe because this is a constant value and a valid C string.
        let root = unsafe { CStr::from_bytes_with_nul_unchecked(ROOT_CSTR) };

        let flags = libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        // Safe because this doesn't modify any memory and we check the return value.
        let raw_descriptor = unsafe { libc::openat64(libc::AT_FDCWD, root.as_ptr(), flags) };
        if raw_descriptor < 0 {
            return Err(io::Error::last_os_error());
        }

        // Safe because we just opened this descriptor above.
        let f = unsafe { File::from_raw_descriptor(raw_descriptor) };

        let st = stat(&f)?;

        // Safe because this doesn't modify any memory and there is no need to check the return
        // value because this system call always succeeds. We need to clear the umask here because
        // we want the client to be able to set all the bits in the mode.
        unsafe { libc::umask(0o000) };

        let mut inodes = self.inodes.lock();

        // Not sure why the root inode gets a refcount of 2 but that's what libfuse does.
        inodes.insert(
            ROOT_ID,
            InodeAltKey {
                ino: st.st_ino,
                dev: st.st_dev,
            },
            Arc::new(InodeData {
                inode: ROOT_ID,
                file: Mutex::new((f, flags)),
                refcount: AtomicU64::new(2),
                filetype: st.st_mode.into(),
                path: "".to_string(),
            }),
        );

        let mut opts = FsOptions::DO_READDIRPLUS
            | FsOptions::READDIRPLUS_AUTO
            | FsOptions::EXPORT_SUPPORT
            | FsOptions::DONT_MASK
            | FsOptions::CACHE_SYMLINKS;
        if self.cfg.posix_acl {
            opts |= FsOptions::POSIX_ACL;
        }
        if self.cfg.writeback && capable.contains(FsOptions::WRITEBACK_CACHE) {
            opts |= FsOptions::WRITEBACK_CACHE;
            self.writeback.store(true, Ordering::Relaxed);
        }
        if self.cfg.cache_policy == CachePolicy::Always {
            if capable.contains(FsOptions::ZERO_MESSAGE_OPEN) {
                opts |= FsOptions::ZERO_MESSAGE_OPEN;
                self.zero_message_open.store(true, Ordering::Relaxed);
            }
            if capable.contains(FsOptions::ZERO_MESSAGE_OPENDIR) {
                opts |= FsOptions::ZERO_MESSAGE_OPENDIR;
                self.zero_message_opendir.store(true, Ordering::Relaxed);
            }
        }
        Ok(opts)
    }

    fn destroy(&self) {
        cros_tracing::trace_simple_print!(VirtioFs, "{:?}: destroy", self);
        self.handles.lock().clear();
        self.inodes.lock().clear();
    }

    fn statfs(&self, _ctx: Context, inode: Inode) -> io::Result<libc::statvfs64> {
        let _trace = fs_trace!(self.tag, "statfs", inode);
        let data = self.find_inode(inode)?;

        let mut out = MaybeUninit::<libc::statvfs64>::zeroed();

        // Safe because this will only modify `out` and we check the return value.
        syscall!(unsafe { libc::fstatvfs64(data.as_raw_descriptor(), out.as_mut_ptr()) })?;

        // Safe because the kernel guarantees that `out` has been initialized.
        Ok(unsafe { out.assume_init() })
    }

    fn lookup(&self, _ctx: Context, parent: Inode, name: &CStr) -> io::Result<Entry> {
        let data = self.find_inode(parent)?;
        #[allow(unused_variables)]
        let path = format!(
            "{}/{}",
            data.path,
            name.to_str().unwrap_or("<non UTF-8 path>")
        );
        let _trace = fs_trace!(self.tag, "lookup", parent, path);

        let mut res = self.do_lookup(&data, name);
        // If `ascii_casefold` is enabled, fallback to `ascii_casefold_lookup()`.
        if res.is_err() && self.cfg.ascii_casefold {
            res = self.ascii_casefold_lookup(&data, name.to_bytes());
        }
        // FUSE takes a inode=0 as a request to do negative dentry cache.
        // So, if `negative_timeout` is set, return success with the timeout value and inode=0 as a
        // response.
        if let Err(e) = &res {
            if e.kind() == std::io::ErrorKind::NotFound && !self.cfg.negative_timeout.is_zero() {
                let attr = MaybeUninit::<libc::stat64>::zeroed();
                res = Ok(Entry {
                    inode: 0, // Using 0 for negative entry
                    entry_timeout: self.cfg.negative_timeout,
                    // Zero-fill other fields that won't be used.
                    attr_timeout: Duration::from_secs(0),
                    generation: 0,
                    // Safe because zero-initialized `stat64` is a valid value.
                    attr: unsafe { attr.assume_init() },
                });
            }
        }

        res
    }

    fn forget(&self, _ctx: Context, inode: Inode, count: u64) {
        let _trace = fs_trace!(self.tag, "forget", inode, count);
        let mut inodes = self.inodes.lock();
        let caches = self.lock_casefold_lookup_caches();
        if forget_one(&mut inodes, inode, count) {
            if let Some(mut c) = caches {
                c.forget(inode);
            }
        }
    }

    fn batch_forget(&self, _ctx: Context, requests: Vec<(Inode, u64)>) {
        let mut inodes = self.inodes.lock();
        let mut caches = self.lock_casefold_lookup_caches();
        for (inode, count) in requests {
            if forget_one(&mut inodes, inode, count) {
                if let Some(c) = caches.as_mut() {
                    c.forget(inode);
                }
            }
        }
    }

    fn opendir(
        &self,
        _ctx: Context,
        inode: Inode,
        flags: u32,
    ) -> io::Result<(Option<Handle>, OpenOptions)> {
        let _trace = fs_trace!(self.tag, "opendir", inode, flags);
        if self.zero_message_opendir.load(Ordering::Relaxed) {
            Err(io::Error::from_raw_os_error(libc::ENOSYS))
        } else {
            self.do_open(inode, flags | (libc::O_DIRECTORY as u32))
        }
    }

    fn releasedir(
        &self,
        _ctx: Context,
        inode: Inode,
        _flags: u32,
        handle: Handle,
    ) -> io::Result<()> {
        let _trace = fs_trace!(self.tag, "releasedir", inode, handle);
        if self.zero_message_opendir.load(Ordering::Relaxed) {
            Ok(())
        } else {
            self.do_release(inode, handle)
        }
    }

    fn mkdir(
        &self,
        ctx: Context,
        parent: Inode,
        name: &CStr,
        mode: u32,
        umask: u32,
    ) -> io::Result<Entry> {
        let _trace = fs_trace!(self.tag, "mkdir", parent, name, mode, umask);
        let data = self.find_inode(parent)?;

        let (_uid, _gid) = set_creds(ctx.uid, ctx.gid)?;
        {
            let casefold_cache = self.lock_casefold_lookup_caches();
            let _scoped_umask = ScopedUmask::new(umask);

            // Safe because this doesn't modify any memory and we check the return value.
            syscall!(unsafe { libc::mkdirat(data.as_raw_descriptor(), name.as_ptr(), mode) })?;
            if let Some(mut c) = casefold_cache {
                c.insert(data.inode, name);
            }
        }
        self.do_lookup(&data, name)
    }

    fn rmdir(&self, _ctx: Context, parent: Inode, name: &CStr) -> io::Result<()> {
        let _trace = fs_trace!(self.tag, "rmdir", parent, name);
        let data = self.find_inode(parent)?;
        let casefold_cache = self.lock_casefold_lookup_caches();
        // TODO(b/278691962): If ascii_casefold is enabled, we need to call
        // `lookup_case_unfolded_name()` to get the actual name to be unlinked.
        self.do_unlink(&data, name, libc::AT_REMOVEDIR)?;
        if let Some(mut c) = casefold_cache {
            c.remove(data.inode, name);
        }
        Ok(())
    }

    fn readdir(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        size: u32,
        offset: u64,
    ) -> io::Result<Self::DirIter> {
        let _trace = fs_trace!(self.tag, "readdir", inode, handle, size, offset);
        let buf = vec![0; size as usize].into_boxed_slice();

        if self.zero_message_opendir.load(Ordering::Relaxed) {
            let data = self.find_inode(inode)?;
            ReadDir::new(&*data, offset as libc::off64_t, buf)
        } else {
            let data = self.find_handle(handle, inode)?;

            let dir = data.file.lock();

            ReadDir::new(&*dir, offset as libc::off64_t, buf)
        }
    }

    fn open(
        &self,
        _ctx: Context,
        inode: Inode,
        flags: u32,
    ) -> io::Result<(Option<Handle>, OpenOptions)> {
        if self.zero_message_open.load(Ordering::Relaxed) {
            let _trace = fs_trace!(self.tag, "open (zero-message)", inode, flags);
            Err(io::Error::from_raw_os_error(libc::ENOSYS))
        } else {
            let _trace = fs_trace!(self.tag, "open", inode, flags);
            self.do_open(inode, flags)
        }
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
        if self.zero_message_open.load(Ordering::Relaxed) {
            let _trace = fs_trace!(self.tag, "release (zero-message)", inode, handle);
            Ok(())
        } else {
            let _trace = fs_trace!(self.tag, "release", inode, handle);
            self.do_release(inode, handle)
        }
    }

    fn chromeos_tmpfile(
        &self,
        ctx: Context,
        parent: Self::Inode,
        mode: u32,
        umask: u32,
    ) -> io::Result<Entry> {
        let _trace = fs_trace!(self.tag, "chromeos_tempfile", parent, mode, umask);
        let data = self.find_inode(parent)?;

        let (_uid, _gid) = set_creds(ctx.uid, ctx.gid)?;

        let tmpflags = libc::O_RDWR | libc::O_TMPFILE | libc::O_CLOEXEC | libc::O_NOFOLLOW;

        // Safe because this is a valid c string.
        let current_dir = unsafe { CStr::from_bytes_with_nul_unchecked(b".\0") };

        let fd = {
            let _scoped_umask = ScopedUmask::new(umask);

            // Safe because this doesn't modify any memory and we check the return value.
            syscall!(unsafe {
                libc::openat64(
                    data.as_raw_descriptor(),
                    current_dir.as_ptr(),
                    tmpflags,
                    mode,
                )
            })?
        };
        // No need to add casefold_cache becuase we created an anonymous file.

        // Safe because we just opened this fd.
        let tmpfile = unsafe { File::from_raw_descriptor(fd) };

        let st = stat(&tmpfile)?;
        let path = format!(
            "{}/{}",
            data.path.clone(),
            current_dir.to_str().unwrap_or("<non UTF-8 str>")
        );
        Ok(self.add_entry(tmpfile, st, tmpflags, path))
    }

    fn create(
        &self,
        ctx: Context,
        parent: Inode,
        name: &CStr,
        mode: u32,
        flags: u32,
        umask: u32,
    ) -> io::Result<(Entry, Option<Handle>, OpenOptions)> {
        let _trace = fs_trace!(self.tag, "create", parent, name, mode, flags, umask);
        let data = self.find_inode(parent)?;
        let (_uid, _gid) = set_creds(ctx.uid, ctx.gid)?;

        let create_flags =
            (flags as i32 | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW) & !libc::O_DIRECT;

        let fd = {
            let _scoped_umask = ScopedUmask::new(umask);
            let casefold_cache = self.lock_casefold_lookup_caches();

            // Safe because this doesn't modify any memory and we check the return value. We don't
            // really check `flags` because if the kernel can't handle poorly specified flags then
            // we have much bigger problems.
            // TODO(b/278691962): If ascii_casefold is enabled, we need to call
            // `lookup_case_unfolded_name()` to get the actual name to be created.
            let fd = syscall!(unsafe {
                libc::openat64(data.as_raw_descriptor(), name.as_ptr(), create_flags, mode)
            })?;
            if let Some(mut c) = casefold_cache {
                c.insert(parent, name);
            }
            fd
        };

        // Safe because we just opened this fd.
        let file = unsafe { File::from_raw_descriptor(fd) };

        let st = stat(&file)?;
        let path = format!(
            "{}/{}",
            data.path.clone(),
            name.to_str().unwrap_or("<non UTF-8 str>")
        );
        let entry = self.add_entry(file, st, create_flags, path);

        let (handle, opts) = if self.zero_message_open.load(Ordering::Relaxed) {
            (None, OpenOptions::KEEP_CACHE)
        } else {
            self.do_open(
                entry.inode,
                flags & !((libc::O_CREAT | libc::O_EXCL | libc::O_NOCTTY) as u32),
            )
            .map_err(|e| {
                // Don't leak the entry.
                self.forget(ctx, entry.inode, 1);
                e
            })?
        };
        Ok((entry, handle, opts))
    }

    fn unlink(&self, _ctx: Context, parent: Inode, name: &CStr) -> io::Result<()> {
        let _trace = fs_trace!(self.tag, "unlink", parent, name);
        let data = self.find_inode(parent)?;
        let casefold_cache = self.lock_casefold_lookup_caches();
        // TODO(b/278691962): If ascii_casefold is enabled, we need to call
        // `lookup_case_unfolded_name()` to get the actual name to be unlinked.
        self.do_unlink(&data, name, 0)?;
        if let Some(mut c) = casefold_cache {
            c.remove(data.inode, name);
        }
        Ok(())
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
        if self.zero_message_open.load(Ordering::Relaxed) {
            let _trace = fs_trace!(self.tag, "read (zero-message)", inode, handle, size, offset);
            let data = self.find_inode(inode)?;

            let mut file = data.file.lock();
            let mut flags = file.1;
            match flags & libc::O_ACCMODE {
                libc::O_WRONLY => {
                    flags &= !libc::O_WRONLY;
                    flags |= libc::O_RDWR;

                    // We need to get a readable handle for this file.
                    let newfile = self.open_fd(file.0.as_raw_descriptor(), libc::O_RDWR)?;
                    *file = (newfile, flags);
                }
                libc::O_RDONLY | libc::O_RDWR => {}
                _ => panic!("Unexpected flags: {:#x}", flags),
            }

            w.write_from(&mut file.0, size as usize, offset)
        } else {
            let _trace = fs_trace!(self.tag, "read", inode, handle, size, offset);
            let data = self.find_handle(handle, inode)?;

            let mut f = data.file.lock();
            w.write_from(&mut f, size as usize, offset)
        }
    }

    fn write<R: io::Read + ZeroCopyReader>(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        mut r: R,
        size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _delayed_write: bool,
        flags: u32,
    ) -> io::Result<usize> {
        // When the WRITE_KILL_PRIV flag is set, drop CAP_FSETID so that the kernel will
        // automatically clear the setuid and setgid bits for us.
        let _fsetid = if flags & WRITE_KILL_PRIV != 0 {
            Some(drop_cap_fsetid()?)
        } else {
            None
        };

        if self.zero_message_open.load(Ordering::Relaxed) {
            let _trace = fs_trace!(
                self.tag,
                "write (zero-message)",
                inode,
                handle,
                size,
                offset
            );

            let data = self.find_inode(inode)?;

            let mut file = data.file.lock();
            let mut flags = file.1;
            match flags & libc::O_ACCMODE {
                libc::O_RDONLY => {
                    flags &= !libc::O_RDONLY;
                    flags |= libc::O_RDWR;

                    // We need to get a writable handle for this file.
                    let newfile = self.open_fd(file.0.as_raw_descriptor(), libc::O_RDWR)?;
                    *file = (newfile, flags);
                }
                libc::O_WRONLY | libc::O_RDWR => {}
                _ => panic!("Unexpected flags: {:#x}", flags),
            }

            r.read_to(&mut file.0, size as usize, offset)
        } else {
            let _trace = fs_trace!(self.tag, "write", inode, handle, size, offset);

            let data = self.find_handle(handle, inode)?;

            let mut f = data.file.lock();
            r.read_to(&mut f, size as usize, offset)
        }
    }

    fn getattr(
        &self,
        _ctx: Context,
        inode: Inode,
        _handle: Option<Handle>,
    ) -> io::Result<(libc::stat64, Duration)> {
        let _trace = fs_trace!(self.tag, "getattr", inode, _handle);

        let data = self.find_inode(inode)?;
        self.do_getattr(&data)
    }

    fn setattr(
        &self,
        _ctx: Context,
        inode: Inode,
        attr: libc::stat64,
        handle: Option<Handle>,
        valid: SetattrValid,
    ) -> io::Result<(libc::stat64, Duration)> {
        let _trace = fs_trace!(self.tag, "setattr", inode, handle);
        let inode_data = self.find_inode(inode)?;

        enum Data {
            Handle(Arc<HandleData>, RawDescriptor),
            ProcPath(CString),
        }

        // If we have a handle then use it otherwise get a new fd from the inode.
        let data = if let Some(handle) = handle.filter(|&h| h != 0) {
            let hd = self.find_handle(handle, inode)?;

            let fd = hd.file.lock().as_raw_descriptor();
            Data::Handle(hd, fd)
        } else {
            let pathname = CString::new(format!("self/fd/{}", inode_data.as_raw_descriptor()))
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            Data::ProcPath(pathname)
        };

        if valid.contains(SetattrValid::MODE) {
            // Safe because this doesn't modify any memory and we check the return value.
            syscall!(unsafe {
                match data {
                    Data::Handle(_, fd) => libc::fchmod(fd, attr.st_mode),
                    Data::ProcPath(ref p) => {
                        libc::fchmodat(self.proc.as_raw_descriptor(), p.as_ptr(), attr.st_mode, 0)
                    }
                }
            })?;
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
            syscall!(unsafe {
                libc::fchownat(
                    inode_data.as_raw_descriptor(),
                    empty.as_ptr(),
                    uid,
                    gid,
                    libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                )
            })?;
        }

        if valid.contains(SetattrValid::SIZE) {
            // Safe because this doesn't modify any memory and we check the return value.
            syscall!(match data {
                Data::Handle(_, fd) => unsafe { libc::ftruncate64(fd, attr.st_size) },
                _ => {
                    // There is no `ftruncateat` so we need to get a new fd and truncate it.
                    let f = self.open_inode(&inode_data, libc::O_NONBLOCK | libc::O_RDWR)?;
                    unsafe { libc::ftruncate64(f.as_raw_descriptor(), attr.st_size) }
                }
            })?;
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
            syscall!(unsafe {
                match data {
                    Data::Handle(_, fd) => libc::futimens(fd, tvs.as_ptr()),
                    Data::ProcPath(ref p) => {
                        libc::utimensat(self.proc.as_raw_descriptor(), p.as_ptr(), tvs.as_ptr(), 0)
                    }
                }
            })?;
        }

        self.do_getattr(&inode_data)
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
        let _trace = fs_trace!(self.tag, "rename", olddir, oldname, newdir, newname, flags);

        let old_inode = self.find_inode(olddir)?;
        let new_inode = self.find_inode(newdir)?;
        {
            let casefold_cache = self.lock_casefold_lookup_caches();

            // Safe because this doesn't modify any memory and we check the return value.
            // TODO: Switch to libc::renameat2 once https://github.com/rust-lang/libc/pull/1508 lands
            // and we have glibc 2.28.
            syscall!(unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    old_inode.as_raw_descriptor(),
                    oldname.as_ptr(),
                    new_inode.as_raw_descriptor(),
                    newname.as_ptr(),
                    flags,
                )
            })?;
            if let Some(mut c) = casefold_cache {
                c.remove(olddir, oldname);
                c.insert(newdir, newname);
            }
        }

        Ok(())
    }

    fn mknod(
        &self,
        ctx: Context,
        parent: Inode,
        name: &CStr,
        mode: u32,
        rdev: u32,
        umask: u32,
    ) -> io::Result<Entry> {
        let _trace = fs_trace!(self.tag, "mknod", parent, name, mode, rdev, umask);
        let data = self.find_inode(parent)?;

        let (_uid, _gid) = set_creds(ctx.uid, ctx.gid)?;
        {
            let _scoped_umask = ScopedUmask::new(umask);
            let casefold_cache = self.lock_casefold_lookup_caches();

            // Safe because this doesn't modify any memory and we check the return value.
            syscall!(unsafe {
                libc::mknodat(
                    data.as_raw_descriptor(),
                    name.as_ptr(),
                    mode as libc::mode_t,
                    rdev as libc::dev_t,
                )
            })?;
            if let Some(mut c) = casefold_cache {
                c.insert(parent, name);
            }
        }

        self.do_lookup(&data, name)
    }

    fn link(
        &self,
        _ctx: Context,
        inode: Inode,
        newparent: Inode,
        newname: &CStr,
    ) -> io::Result<Entry> {
        let _trace = fs_trace!(self.tag, "link", inode, newparent, newname);
        let data = self.find_inode(inode)?;
        let new_inode = self.find_inode(newparent)?;

        let path = CString::new(format!("self/fd/{}", data.as_raw_descriptor()))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        {
            let casefold_cache = self.lock_casefold_lookup_caches();
            // Safe because this doesn't modify any memory and we check the return value.
            syscall!(unsafe {
                libc::linkat(
                    self.proc.as_raw_descriptor(),
                    path.as_ptr(),
                    new_inode.as_raw_descriptor(),
                    newname.as_ptr(),
                    libc::AT_SYMLINK_FOLLOW,
                )
            })?;
            if let Some(mut c) = casefold_cache {
                c.insert(newparent, newname);
            }
        }

        self.do_lookup(&new_inode, newname)
    }

    fn symlink(
        &self,
        ctx: Context,
        linkname: &CStr,
        parent: Inode,
        name: &CStr,
    ) -> io::Result<Entry> {
        let _trace = fs_trace!(self.tag, "symlink", parent, linkname, name);
        let data = self.find_inode(parent)?;

        let (_uid, _gid) = set_creds(ctx.uid, ctx.gid)?;
        {
            let casefold_cache = self.lock_casefold_lookup_caches();
            // Safe because this doesn't modify any memory and we check the return value.
            syscall!(unsafe {
                libc::symlinkat(linkname.as_ptr(), data.as_raw_descriptor(), name.as_ptr())
            })?;
            if let Some(mut c) = casefold_cache {
                c.insert(parent, name);
            }
        }

        self.do_lookup(&data, name)
    }

    fn readlink(&self, _ctx: Context, inode: Inode) -> io::Result<Vec<u8>> {
        let _trace = fs_trace!(self.tag, "readlink", inode);
        let data = self.find_inode(inode)?;

        let mut buf = vec![0; libc::PATH_MAX as usize];

        // Safe because this is a constant value and a valid C string.
        let empty = unsafe { CStr::from_bytes_with_nul_unchecked(EMPTY_CSTR) };

        // Safe because this will only modify the contents of `buf` and we check the return value.
        let res = syscall!(unsafe {
            libc::readlinkat(
                data.as_raw_descriptor(),
                empty.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
            )
        })?;

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
        let _trace = fs_trace!(self.tag, "flush", inode, handle);
        let data: Arc<dyn AsRawDescriptor> = if self.zero_message_open.load(Ordering::Relaxed) {
            self.find_inode(inode)?
        } else {
            self.find_handle(handle, inode)?
        };

        // Since this method is called whenever an fd is closed in the client, we can emulate that
        // behavior by doing the same thing (dup-ing the fd and then immediately closing it). Safe
        // because this doesn't modify any memory and we check the return values.
        unsafe {
            let newfd = syscall!(libc::fcntl(
                data.as_raw_descriptor(),
                libc::F_DUPFD_CLOEXEC,
                0
            ))?;

            syscall!(libc::close(newfd))?;
        }
        Ok(())
    }

    fn fsync(&self, _ctx: Context, inode: Inode, datasync: bool, handle: Handle) -> io::Result<()> {
        if self.zero_message_open.load(Ordering::Relaxed) {
            let _trace = fs_trace!(self.tag, "fsync (zero-message)", inode, datasync, handle);
            let data = self.find_inode(inode)?;
            self.do_fsync(&*data, datasync)
        } else {
            let _trace = fs_trace!(self.tag, "fsync", inode, datasync, handle);
            let data = self.find_handle(handle, inode)?;

            let file = data.file.lock();
            self.do_fsync(&*file, datasync)
        }
    }

    fn fsyncdir(
        &self,
        _ctx: Context,
        inode: Inode,
        datasync: bool,
        handle: Handle,
    ) -> io::Result<()> {
        if self.zero_message_opendir.load(Ordering::Relaxed) {
            let _trace = fs_trace!(self.tag, "fsyncdir (zero-message)", inode, datasync, handle);
            let data = self.find_inode(inode)?;
            self.do_fsync(&*data, datasync)
        } else {
            let _trace = fs_trace!(self.tag, "fsyncdir", inode, datasync, handle);
            let data = self.find_handle(handle, inode)?;

            let file = data.file.lock();
            self.do_fsync(&*file, datasync)
        }
    }

    fn access(&self, ctx: Context, inode: Inode, mask: u32) -> io::Result<()> {
        let _trace = fs_trace!(self.tag, "access", inode, mask);
        let data = self.find_inode(inode)?;

        let st = stat(&*data)?;
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
        let _trace = fs_trace!(self.tag, "setxattr", inode, name, flags);
        // We can't allow the VM to set this xattr because an unprivileged process may use it to set
        // a privileged xattr.
        if self.cfg.rewrite_security_xattrs && name.to_bytes().starts_with(USER_VIRTIOFS_XATTR) {
            return Err(io::Error::from_raw_os_error(libc::EPERM));
        }

        let data = self.find_inode(inode)?;
        let name = self.rewrite_xattr_name(name);
        let file = data.file.lock();
        let o_path_file = (file.1 & libc::O_PATH) != 0;
        if o_path_file {
            // For FDs opened with `O_PATH`, we cannot call `fsetxattr` normally. Instead we emulate
            // an _at syscall by changing the CWD to /proc, running the path based syscall, and then
            // setting the CWD back to the root directory.
            let path = CString::new(format!("self/fd/{}", file.0.as_raw_descriptor()))
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            // Safe because this doesn't modify any memory and we check the return value.
            syscall!(self.with_proc_chdir(|| {
                unsafe {
                    libc::setxattr(
                        path.as_ptr(),
                        name.as_ptr(),
                        value.as_ptr() as *const libc::c_void,
                        value.len() as libc::size_t,
                        flags as c_int,
                    )
                }
            }))?;
        } else {
            // For regular files and directories, we can just use fsetxattr. Safe because this
            // doesn't modify any memory and we check the return value.
            syscall!(unsafe {
                libc::fsetxattr(
                    file.0.as_raw_descriptor(),
                    name.as_ptr(),
                    value.as_ptr() as *const libc::c_void,
                    value.len() as libc::size_t,
                    flags as c_int,
                )
            })?;
        }

        Ok(())
    }

    fn getxattr(
        &self,
        _ctx: Context,
        inode: Inode,
        name: &CStr,
        size: u32,
    ) -> io::Result<GetxattrReply> {
        let _trace = fs_trace!(self.tag, "getxattr", inode, name, size);
        // We don't allow the VM to set this xattr so we also pretend there is no value associated
        // with it.
        if self.cfg.rewrite_security_xattrs && name.to_bytes().starts_with(USER_VIRTIOFS_XATTR) {
            return Err(io::Error::from_raw_os_error(libc::ENODATA));
        }

        let data = self.find_inode(inode)?;
        let name = self.rewrite_xattr_name(name);
        let mut buf = vec![0u8; size as usize];

        // Safe because this will only modify the contents of `buf`.
        let res = self.do_getxattr(&data, &name, &mut buf[..])?;
        if size == 0 {
            Ok(GetxattrReply::Count(res as u32))
        } else {
            buf.truncate(res);
            Ok(GetxattrReply::Value(buf))
        }
    }

    fn listxattr(&self, _ctx: Context, inode: Inode, size: u32) -> io::Result<ListxattrReply> {
        let _trace = fs_trace!(self.tag, "listxattr", inode, size);
        let data = self.find_inode(inode)?;

        let mut buf = vec![0u8; size as usize];

        let file = data.file.lock();
        let o_path_file = (file.1 & libc::O_PATH) != 0;
        let res = if o_path_file {
            // For FDs opened with `O_PATH`, we cannot call `flistxattr` normally. Instead we
            // emulate an _at syscall by changing the CWD to /proc, running the path based syscall,
            // and then setting the CWD back to the root directory.
            let path = CString::new(format!("self/fd/{}", file.0.as_raw_descriptor()))
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            // Safe because this will only modify `buf` and we check the return value.
            syscall!(self.with_proc_chdir(|| unsafe {
                libc::listxattr(
                    path.as_ptr(),
                    buf.as_mut_ptr() as *mut libc::c_char,
                    buf.len() as libc::size_t,
                )
            }))?
        } else {
            // For regular files and directories, we can just flistxattr. Safe because this will only
            // write to `buf` and we check the return value.
            syscall!(unsafe {
                libc::flistxattr(
                    file.0.as_raw_descriptor(),
                    buf.as_mut_ptr() as *mut libc::c_char,
                    buf.len() as libc::size_t,
                )
            })?
        };

        if size == 0 {
            Ok(ListxattrReply::Count(res as u32))
        } else {
            buf.truncate(res as usize);

            if self.cfg.rewrite_security_xattrs {
                strip_xattr_prefix(&mut buf);
            }
            Ok(ListxattrReply::Names(buf))
        }
    }

    fn removexattr(&self, _ctx: Context, inode: Inode, name: &CStr) -> io::Result<()> {
        let _trace = fs_trace!(self.tag, "removexattr", inode, name);
        // We don't allow the VM to set this xattr so we also pretend there is no value associated
        // with it.
        if self.cfg.rewrite_security_xattrs && name.to_bytes().starts_with(USER_VIRTIOFS_XATTR) {
            return Err(io::Error::from_raw_os_error(libc::ENODATA));
        }

        let data = self.find_inode(inode)?;
        let name = self.rewrite_xattr_name(name);

        let file = data.file.lock();
        let o_path_file = (file.1 & libc::O_PATH) != 0;
        if o_path_file {
            // For files opened with `O_PATH`, we cannot call `fremovexattr` normally. Instead we
            // emulate an _at syscall by changing the CWD to /proc, running the path based syscall,
            // and then setting the CWD back to the root directory.
            let path = CString::new(format!("self/fd/{}", file.0.as_raw_descriptor()))
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            // Safe because this doesn't modify any memory and we check the return value.
            syscall!(
                self.with_proc_chdir(|| unsafe { libc::removexattr(path.as_ptr(), name.as_ptr()) })
            )?;
        } else {
            // For regular files and directories, we can just use fremovexattr. Safe because this
            // doesn't modify any memory and we check the return value.
            syscall!(unsafe { libc::fremovexattr(file.0.as_raw_descriptor(), name.as_ptr()) })?;
        }

        Ok(())
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
        let _trace = fs_trace!(self.tag, "fallocate", inode, handle, mode, offset, length);

        let data: Arc<dyn AsRawDescriptor> = if self.zero_message_open.load(Ordering::Relaxed) {
            let data = self.find_inode(inode)?;

            {
                // fallocate needs a writable fd
                let mut file = data.file.lock();
                let mut flags = file.1;
                match flags & libc::O_ACCMODE {
                    libc::O_RDONLY => {
                        flags &= !libc::O_RDONLY;
                        flags |= libc::O_RDWR;

                        // We need to get a writable handle for this file.
                        let newfile = self.open_fd(file.0.as_raw_descriptor(), libc::O_RDWR)?;
                        *file = (newfile, flags);
                    }
                    libc::O_WRONLY | libc::O_RDWR => {}
                    _ => panic!("Unexpected flags: {:#x}", flags),
                }
            }

            data
        } else {
            self.find_handle(handle, inode)?
        };

        let fd = data.as_raw_descriptor();
        // Safe because this doesn't modify any memory and we check the return value.
        syscall!(unsafe {
            libc::fallocate64(
                fd,
                mode as libc::c_int,
                offset as libc::off64_t,
                length as libc::off64_t,
            )
        })?;

        Ok(())
    }

    #[allow(clippy::unnecessary_cast)]
    fn ioctl<R: io::Read>(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Handle,
        _flags: IoctlFlags,
        cmd: u32,
        _arg: u64,
        in_size: u32,
        out_size: u32,
        r: R,
    ) -> io::Result<IoctlReply> {
        let _trace = fs_trace!(self.tag, "ioctl", inode, handle, cmd, in_size, out_size);

        const GET_ENCRYPTION_POLICY_EX: u32 = FS_IOC_GET_ENCRYPTION_POLICY_EX() as u32;
        const GET_FSXATTR: u32 = FS_IOC_FSGETXATTR() as u32;
        const SET_FSXATTR: u32 = FS_IOC_FSSETXATTR() as u32;
        const GET_FLAGS32: u32 = FS_IOC32_GETFLAGS() as u32;
        const SET_FLAGS32: u32 = FS_IOC32_SETFLAGS() as u32;
        const GET_FLAGS64: u32 = FS_IOC64_GETFLAGS() as u32;
        const SET_FLAGS64: u32 = FS_IOC64_SETFLAGS() as u32;
        const ENABLE_VERITY: u32 = FS_IOC_ENABLE_VERITY() as u32;
        const MEASURE_VERITY: u32 = FS_IOC_MEASURE_VERITY() as u32;

        match cmd {
            GET_ENCRYPTION_POLICY_EX => self.get_encryption_policy_ex(inode, handle, r),
            GET_FSXATTR => {
                if out_size < size_of::<fsxattr>() as u32 {
                    Err(io::Error::from_raw_os_error(libc::ENOMEM))
                } else {
                    self.get_fsxattr(inode, handle)
                }
            }
            SET_FSXATTR => {
                if in_size < size_of::<fsxattr>() as u32 {
                    Err(io::Error::from_raw_os_error(libc::EINVAL))
                } else {
                    self.set_fsxattr(ctx, inode, handle, r)
                }
            }
            GET_FLAGS32 | GET_FLAGS64 => {
                if out_size < size_of::<c_int>() as u32 {
                    Err(io::Error::from_raw_os_error(libc::ENOMEM))
                } else {
                    self.get_flags(inode, handle)
                }
            }
            SET_FLAGS32 | SET_FLAGS64 => {
                if in_size < size_of::<c_int>() as u32 {
                    Err(io::Error::from_raw_os_error(libc::ENOMEM))
                } else {
                    self.set_flags(ctx, inode, handle, r)
                }
            }
            ENABLE_VERITY => {
                if in_size < size_of::<fsverity_enable_arg>() as u32 {
                    Err(io::Error::from_raw_os_error(libc::ENOMEM))
                } else {
                    self.enable_verity(inode, handle, r)
                }
            }
            MEASURE_VERITY => {
                if in_size < size_of::<fsverity_digest>() as u32
                    || out_size < size_of::<fsverity_digest>() as u32
                {
                    Err(io::Error::from_raw_os_error(libc::ENOMEM))
                } else {
                    self.measure_verity(inode, handle, r, out_size)
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
        let _trace = fs_trace!(
            self.tag,
            "copy_file_range",
            inode_src,
            handle_src,
            offset_src,
            inode_dst,
            handle_dst,
            offset_dst,
            length,
            flags
        );
        // We need to change credentials during a write so that the kernel will remove setuid or
        // setgid bits from the file if it was written to by someone other than the owner.
        let (_uid, _gid) = set_creds(ctx.uid, ctx.gid)?;
        let (src_data, dst_data): (Arc<dyn AsRawDescriptor>, Arc<dyn AsRawDescriptor>) =
            if self.zero_message_open.load(Ordering::Relaxed) {
                (self.find_inode(inode_src)?, self.find_inode(inode_dst)?)
            } else {
                (
                    self.find_handle(handle_src, inode_src)?,
                    self.find_handle(handle_dst, inode_dst)?,
                )
            };

        let src = src_data.as_raw_descriptor();
        let dst = dst_data.as_raw_descriptor();

        Ok(syscall!(unsafe {
            libc::syscall(
                libc::SYS_copy_file_range,
                src,
                &offset_src,
                dst,
                &offset_dst,
                length,
                flags,
            )
        })? as usize)
    }

    fn set_up_mapping<M: Mapper>(
        &self,
        _ctx: Context,
        inode: Self::Inode,
        _handle: Self::Handle,
        file_offset: u64,
        mem_offset: u64,
        size: usize,
        prot: u32,
        mapper: M,
    ) -> io::Result<()> {
        let _trace = fs_trace!(
            self.tag,
            "set_up_mapping",
            inode,
            file_offset,
            mem_offset,
            size,
            prot
        );
        if !self.cfg.use_dax {
            return Err(io::Error::from_raw_os_error(libc::ENOSYS));
        }

        let read = prot & libc::PROT_READ as u32 != 0;
        let write = prot & libc::PROT_WRITE as u32 != 0;
        let (mmap_flags, prot) = match (read, write) {
            (true, true) => (libc::O_RDWR, Protection::read_write()),
            (true, false) => (libc::O_RDONLY, Protection::read()),
            // Write-only is mapped to O_RDWR since mmap always requires an fd opened for reading.
            (false, true) => (libc::O_RDWR, Protection::write()),
            (false, false) => return Err(io::Error::from_raw_os_error(libc::EINVAL)),
        };

        let data = self.find_inode(inode)?;

        if self.zero_message_open.load(Ordering::Relaxed) {
            let mut file = data.file.lock();
            let mut open_flags = file.1;
            match (mmap_flags, open_flags & libc::O_ACCMODE) {
                (libc::O_RDONLY, libc::O_WRONLY)
                | (libc::O_RDWR, libc::O_RDONLY)
                | (libc::O_RDWR, libc::O_WRONLY) => {
                    // We have a read-only or write-only fd and we need to upgrade it.
                    open_flags &= !libc::O_ACCMODE;
                    open_flags |= libc::O_RDWR;

                    let newfile = self.open_fd(file.0.as_raw_descriptor(), libc::O_RDWR)?;
                    *file = (newfile, open_flags);
                }
                (libc::O_RDONLY, libc::O_RDONLY)
                | (libc::O_RDONLY, libc::O_RDWR)
                | (libc::O_RDWR, libc::O_RDWR) => {}
                (m, o) => panic!(
                    "Unexpected combination of access flags: ({:#x}, {:#x})",
                    m, o
                ),
            }
            mapper.map(mem_offset, size, &file.0, file_offset, prot)
        } else {
            let file = self.open_inode(&data, mmap_flags | libc::O_NONBLOCK)?;
            mapper.map(mem_offset, size, &file, file_offset, prot)
        }
    }

    fn remove_mapping<M: Mapper>(&self, msgs: &[RemoveMappingOne], mapper: M) -> io::Result<()> {
        let _trace = fs_trace!(self.tag, "remove_mapping", msgs);
        if !self.cfg.use_dax {
            return Err(io::Error::from_raw_os_error(libc::ENOSYS));
        }

        for RemoveMappingOne { moffset, len } in msgs {
            mapper.unmap(*moffset, *len)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use named_lock::NamedLock;
    use tempfile::TempDir;

    use super::*;

    const UNITTEST_LOCK_NAME: &str = "passthroughfs_unittest_lock";

    // Create an instance of `Context` with valid uid, gid, and pid.
    // The correct ids are necessary for test cases where new files are created.
    fn get_context() -> Context {
        // Both these calls are safe because they take no parameters, and only return an integer
        // value. The kernel also guarantees that they can never fail.
        let uid = unsafe { libc::syscall(SYS_GETEUID) as libc::uid_t };
        let gid = unsafe { libc::syscall(SYS_GETEGID) as libc::gid_t };
        let pid = std::process::id() as libc::pid_t;
        Context { uid, gid, pid }
    }

    /// Creates the given directories and files under `temp_dir`.
    fn create_test_data(temp_dir: &TempDir, dirs: &[&str], files: &[&str]) {
        let path = temp_dir.path();

        for d in dirs {
            std::fs::create_dir_all(path.join(d)).unwrap();
        }

        for f in files {
            File::create(path.join(f)).unwrap();
        }
    }

    /// Looks up the given `path` in `fs`.
    fn lookup(fs: &PassthroughFs, path: &Path) -> io::Result<Inode> {
        let mut inode = 1;
        let ctx = get_context();
        for name in path.iter() {
            let name = CString::new(name.to_str().unwrap()).unwrap();
            let ent = match fs.lookup(ctx, inode, &name) {
                Ok(ent) => ent,
                Err(e) => {
                    return Err(e);
                }
            };
            inode = ent.inode;
        }
        Ok(inode)
    }

    /// Creates a file at the given `path`.
    fn create(fs: &PassthroughFs, path: &Path) -> io::Result<Entry> {
        let parent = path.parent().unwrap();
        let filename = CString::new(path.file_name().unwrap().to_str().unwrap()).unwrap();
        let parent_inode = lookup(fs, parent)?;
        let ctx = get_context();
        fs.create(ctx, parent_inode, &filename, 0o666, libc::O_RDWR as u32, 0)
            .map(|(entry, _, _)| entry)
    }

    /// Removes a file at the given `path`.
    fn unlink(fs: &PassthroughFs, path: &Path) -> io::Result<()> {
        let parent = path.parent().unwrap();
        let filename = CString::new(path.file_name().unwrap().to_str().unwrap()).unwrap();
        let parent_inode = lookup(fs, parent)?;
        let ctx = get_context();
        fs.unlink(ctx, parent_inode, &filename)
    }

    /// Forgets cache.
    fn forget(fs: &PassthroughFs, path: &Path) -> io::Result<()> {
        let ctx = get_context();
        let inode = lookup(fs, path)?;
        // Pass `u64::MAX` to ensure that the refcount goes to 0 and we forget inode.
        fs.forget(ctx, inode, u64::MAX);
        Ok(())
    }

    #[test]
    fn rewrite_xattr_names() {
        // Since PassthroughFs may executes process-wide operations such as `fchdir`, acquire
        // `NamedLock` before starting each unit test creating a `PassthroughFs` instance.
        let lock = NamedLock::create(UNITTEST_LOCK_NAME).expect("create named lock");
        let _guard = lock.lock().expect("acquire named lock");

        let cfg = Config {
            rewrite_security_xattrs: true,
            ..Default::default()
        };

        let p = PassthroughFs::new("tag", cfg).expect("Failed to create PassthroughFs");

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

        let only_strippable_names = b"user.virtiofs.security.sehash\0user.virtiofs.security.wat\0";
        let mut actual = only_strippable_names.to_vec();
        strip_xattr_prefix(&mut actual);
        assert_eq!(&actual[..], b"security.sehash\0security.wat\0");

        let mixed_names = b"user.virtiofs.security.sehash\0security.selinux\0user.virtiofs.security.wat\0user.foobar\0";
        let mut actual = mixed_names.to_vec();
        strip_xattr_prefix(&mut actual);
        let expected = b"security.sehash\0security.selinux\0security.wat\0user.foobar\0";
        assert_eq!(&actual[..], &expected[..]);

        let no_nul_with_prefix = b"user.virtiofs.security.sehash";
        let mut actual = no_nul_with_prefix.to_vec();
        strip_xattr_prefix(&mut actual);
        assert_eq!(&actual[..], b"security.sehash");
    }

    #[test]
    fn lookup_files() {
        // Since PassthroughFs may executes process-wide operations such as `fchdir`, acquire
        // `NamedLock` before starting each unit test creating a `PassthroughFs` instance.
        let lock = NamedLock::create(UNITTEST_LOCK_NAME).expect("create named lock");
        let _guard = lock.lock().expect("acquire named lock");

        let temp_dir = TempDir::new().unwrap();
        create_test_data(&temp_dir, &["dir"], &["a.txt", "dir/b.txt"]);

        let cfg = Default::default();
        let fs = PassthroughFs::new("tag", cfg).unwrap();

        let capable = FsOptions::empty();
        fs.init(capable).unwrap();

        assert!(lookup(&fs, &temp_dir.path().join("a.txt")).is_ok());
        assert!(lookup(&fs, &temp_dir.path().join("dir")).is_ok());
        assert!(lookup(&fs, &temp_dir.path().join("dir/b.txt")).is_ok());

        assert_eq!(
            lookup(&fs, &temp_dir.path().join("nonexistent-file"))
                .expect_err("file must not exist")
                .kind(),
            io::ErrorKind::NotFound
        );
        // "A.txt" is different from "a.txt".
        assert_eq!(
            lookup(&fs, &temp_dir.path().join("A.txt"))
                .expect_err("file must not exist")
                .kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn lookup_files_ascii_casefold() {
        // Since PassthroughFs may executes process-wide operations such as `fchdir`, acquire
        // `NamedLock` before starting each unit test creating a `PassthroughFs` instance.
        let lock = NamedLock::create(UNITTEST_LOCK_NAME).expect("create named lock");
        let _guard = lock.lock().expect("acquire named lock");

        let temp_dir = TempDir::new().unwrap();
        create_test_data(&temp_dir, &["dir"], &["a.txt", "dir/b.txt"]);

        let cfg = Config {
            ascii_casefold: true,
            ..Default::default()
        };
        let fs = PassthroughFs::new("tag", cfg).unwrap();

        let capable = FsOptions::empty();
        fs.init(capable).unwrap();

        // Ensure that "A.txt" is equated with "a.txt".
        let a_inode = lookup(&fs, &temp_dir.path().join("a.txt")).expect("a.txt must be found");
        assert_eq!(
            lookup(&fs, &temp_dir.path().join("A.txt")).expect("A.txt must exist"),
            a_inode
        );

        let dir_inode = lookup(&fs, &temp_dir.path().join("dir")).expect("dir must be found");
        assert_eq!(
            lookup(&fs, &temp_dir.path().join("DiR")).expect("DiR must exist"),
            dir_inode
        );

        let b_inode =
            lookup(&fs, &temp_dir.path().join("dir/b.txt")).expect("dir/b.txt must be found");
        assert_eq!(
            lookup(&fs, &temp_dir.path().join("dIr/B.TxT")).expect("dIr/B.TxT must exist"),
            b_inode
        );

        assert_eq!(
            lookup(&fs, &temp_dir.path().join("nonexistent-file"))
                .expect_err("file must not exist")
                .kind(),
            io::ErrorKind::NotFound
        );
    }

    fn test_create_and_remove(ascii_casefold: bool) {
        // Since PassthroughFs may executes process-wide operations such as `fchdir`, acquire
        // `NamedLock` before starting each unit test creating a `PassthroughFs` instance.
        let lock = NamedLock::create(UNITTEST_LOCK_NAME).expect("create named lock");
        let _guard = lock.lock().expect("acquire named lock");

        let temp_dir = TempDir::new().unwrap();
        let timeout = Duration::from_millis(10);
        let cfg = Config {
            timeout,
            cache_policy: CachePolicy::Auto,
            ascii_casefold,
            ..Default::default()
        };
        let fs = PassthroughFs::new("tag", cfg).unwrap();

        let capable = FsOptions::empty();
        fs.init(capable).unwrap();

        // Create a.txt and b.txt.
        let a_path = temp_dir.path().join("a.txt");
        let b_path = temp_dir.path().join("b.txt");
        let a_entry = create(&fs, &a_path).expect("create a.txt");
        let b_entry = create(&fs, &b_path).expect("create b.txt");
        assert_eq!(
            a_entry.inode,
            lookup(&fs, &a_path).expect("lookup a.txt"),
            "Created file 'a.txt' must be looked up"
        );
        assert_eq!(
            b_entry.inode,
            lookup(&fs, &b_path).expect("lookup b.txt"),
            "Created file 'b.txt' must be looked up"
        );

        // Remove a.txt only
        unlink(&fs, &a_path).expect("Remove");
        assert_eq!(
            lookup(&fs, &a_path)
                .expect_err("file must not exist")
                .kind(),
            io::ErrorKind::NotFound,
            "a.txt must be removed"
        );
        // "A.TXT" must not be found regardless of whether casefold is enabled or not.
        let upper_a_path = temp_dir.path().join("A.TXT");
        assert_eq!(
            lookup(&fs, &upper_a_path)
                .expect_err("file must not exist")
                .kind(),
            io::ErrorKind::NotFound,
            "A.txt must be removed"
        );

        // Check if the host file system doesn't have a.txt but does b.txt.
        assert!(!a_path.exists(), "a.txt must be removed");
        assert!(b_path.exists(), "b.txt must exist");
    }

    #[test]
    fn create_and_remove() {
        test_create_and_remove(false /* casefold */);
    }

    #[test]
    fn create_and_remove_casefold() {
        test_create_and_remove(true /* casefold */);
    }

    fn test_create_and_forget(ascii_casefold: bool) {
        // Since PassthroughFs may executes process-wide operations such as `fchdir`, acquire
        // `NamedLock` before starting each unit test creating a `PassthroughFs` instance.
        let lock = NamedLock::create(UNITTEST_LOCK_NAME).expect("create named lock");
        let _guard = lock.lock().expect("acquire named lock");

        let temp_dir = TempDir::new().unwrap();
        let timeout = Duration::from_millis(10);
        let cfg = Config {
            timeout,
            cache_policy: CachePolicy::Auto,
            ascii_casefold,
            ..Default::default()
        };
        let fs = PassthroughFs::new("tag", cfg).unwrap();

        let capable = FsOptions::empty();
        fs.init(capable).unwrap();

        // Create a.txt.
        let a_path = temp_dir.path().join("a.txt");
        let a_entry = create(&fs, &a_path).expect("create a.txt");
        assert_eq!(
            a_entry.inode,
            lookup(&fs, &a_path).expect("lookup a.txt"),
            "Created file 'a.txt' must be looked up"
        );

        // Forget a.txt's inode from PassthroughFs's internal cache.
        forget(&fs, &a_path).expect("forget a.txt");

        if ascii_casefold {
            let upper_a_path = temp_dir.path().join("A.TXT");
            let new_a_inode = lookup(&fs, &upper_a_path).expect("lookup a.txt");
            assert_ne!(
                a_entry.inode, new_a_inode,
                "inode must be changed after forget()"
            );
            assert_eq!(
                new_a_inode,
                lookup(&fs, &a_path).expect("lookup a.txt"),
                "inode must be same for a.txt and A.TXT"
            );
        } else {
            assert_ne!(
                a_entry.inode,
                lookup(&fs, &a_path).expect("lookup a.txt"),
                "inode must be changed after forget()"
            );
        }
    }

    #[test]
    fn create_and_forget() {
        test_create_and_forget(false /* ascii_casefold */);
    }

    #[test]
    fn create_and_forget_casefold() {
        test_create_and_forget(true /* ascii_casefold */);
    }

    #[test]
    fn casefold_lookup_cache() {
        let temp_dir = TempDir::new().unwrap();
        // Prepare `a.txt` before starting the test.
        create_test_data(&temp_dir, &[], &["a.txt"]);

        let cfg = Config {
            ascii_casefold: true,
            ..Default::default()
        };
        let fs = PassthroughFs::new("tag", cfg).unwrap();

        let capable = FsOptions::empty();
        fs.init(capable).unwrap();

        let parent = lookup(&fs, temp_dir.path()).expect("lookup temp_dir");

        // Since `a.txt` exists, "A.TXT" must exist.
        let large_a_path = temp_dir.path().join("A.TXT");
        // Looking up "A.TXT" must create a CasefoldCache entry.
        lookup(&fs, &large_a_path).expect("A.TXT must exist");
        assert!(fs.exists_in_casefold_cache(parent, &CString::new("A.TXT").unwrap()));

        // Create b.txt.
        let b_path = temp_dir.path().join("b.txt");
        create(&fs, &b_path).expect("create b.txt");
        // Then, b.txt must exists in the cache.
        assert!(fs.exists_in_casefold_cache(parent, &CString::new("B.TXT").unwrap()));
        // When removing b.txt, it must be removed from the cache as well.
        unlink(&fs, &b_path).expect("remove b.txt");
        assert!(!fs.exists_in_casefold_cache(parent, &CString::new("B.TXT").unwrap()));
    }

    #[test]
    fn lookup_negative_cache() {
        let temp_dir = TempDir::new().unwrap();
        // Prepare `a.txt` before starting the test.
        create_test_data(&temp_dir, &[], &[]);

        let cfg = Config {
            negative_timeout: Duration::from_secs(5),
            ..Default::default()
        };
        let fs = PassthroughFs::new("tag", cfg).unwrap();

        let capable = FsOptions::empty();
        fs.init(capable).unwrap();

        let a_path = temp_dir.path().join("a.txt");
        // a.txt hasn't existed yet.
        // Since negative_timeout is enabled, success with inode=0 is expected.
        assert_eq!(
            0,
            lookup(&fs, &a_path).expect("lookup a.txt"),
            "Entry with inode=0 is expected for non-existing file 'a.txt'"
        );
        // Create a.txt
        let a_entry = create(&fs, &a_path).expect("create a.txt");
        assert_eq!(
            a_entry.inode,
            lookup(&fs, &a_path).expect("lookup a.txt"),
            "Created file 'a.txt' must be looked up"
        );
        // Remove a.txt
        unlink(&fs, &a_path).expect("Remove");
        assert_eq!(
            0,
            lookup(&fs, &a_path).expect("lookup a.txt"),
            "Entry with inode=0 is expected for the removed file 'a.txt'"
        );
    }
}
