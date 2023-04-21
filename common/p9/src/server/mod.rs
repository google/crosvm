// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod read_dir;

use std::cmp::min;
use std::collections::btree_map;
use std::collections::BTreeMap;
use std::ffi::CStr;
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::io::Cursor;
use std::io::Read;
use std::io::Write;
use std::mem;
use std::mem::MaybeUninit;
use std::ops::Deref;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::FromRawFd;
use std::os::unix::io::RawFd;
use std::path::Path;
use std::str::FromStr;

use read_dir::read_dir;
use serde::Deserialize;
use serde::Serialize;

use crate::protocol::*;
use crate::syscall;

// Tlopen and Tlcreate flags.  Taken from "include/net/9p/9p.h" in the linux tree.
const P9_RDONLY: u32 = 0o00000000;
const P9_WRONLY: u32 = 0o00000001;
const P9_RDWR: u32 = 0o00000002;
const P9_NOACCESS: u32 = 0o00000003;
const P9_CREATE: u32 = 0o00000100;
const P9_EXCL: u32 = 0o00000200;
const P9_NOCTTY: u32 = 0o00000400;
const P9_TRUNC: u32 = 0o00001000;
const P9_APPEND: u32 = 0o00002000;
const P9_NONBLOCK: u32 = 0o00004000;
const P9_DSYNC: u32 = 0o00010000;
const P9_FASYNC: u32 = 0o00020000;
const P9_DIRECT: u32 = 0o00040000;
const P9_LARGEFILE: u32 = 0o00100000;
const P9_DIRECTORY: u32 = 0o00200000;
const P9_NOFOLLOW: u32 = 0o00400000;
const P9_NOATIME: u32 = 0o01000000;
const _P9_CLOEXEC: u32 = 0o02000000;
const P9_SYNC: u32 = 0o04000000;

// Mapping from 9P flags to libc flags.
const MAPPED_FLAGS: [(u32, i32); 16] = [
    (P9_WRONLY, libc::O_WRONLY),
    (P9_RDWR, libc::O_RDWR),
    (P9_CREATE, libc::O_CREAT),
    (P9_EXCL, libc::O_EXCL),
    (P9_NOCTTY, libc::O_NOCTTY),
    (P9_TRUNC, libc::O_TRUNC),
    (P9_APPEND, libc::O_APPEND),
    (P9_NONBLOCK, libc::O_NONBLOCK),
    (P9_DSYNC, libc::O_DSYNC),
    (P9_FASYNC, 0), // Unsupported
    (P9_DIRECT, libc::O_DIRECT),
    (P9_LARGEFILE, libc::O_LARGEFILE),
    (P9_DIRECTORY, libc::O_DIRECTORY),
    (P9_NOFOLLOW, libc::O_NOFOLLOW),
    (P9_NOATIME, libc::O_NOATIME),
    (P9_SYNC, libc::O_SYNC),
];

// 9P Qid types.  Taken from "include/net/9p/9p.h" in the linux tree.
const P9_QTDIR: u8 = 0x80;
const _P9_QTAPPEND: u8 = 0x40;
const _P9_QTEXCL: u8 = 0x20;
const _P9_QTMOUNT: u8 = 0x10;
const _P9_QTAUTH: u8 = 0x08;
const _P9_QTTMP: u8 = 0x04;
const P9_QTSYMLINK: u8 = 0x02;
const _P9_QTLINK: u8 = 0x01;
const P9_QTFILE: u8 = 0x00;

// Bitmask values for the getattr request.
const _P9_GETATTR_MODE: u64 = 0x00000001;
const _P9_GETATTR_NLINK: u64 = 0x00000002;
const _P9_GETATTR_UID: u64 = 0x00000004;
const _P9_GETATTR_GID: u64 = 0x00000008;
const _P9_GETATTR_RDEV: u64 = 0x00000010;
const _P9_GETATTR_ATIME: u64 = 0x00000020;
const _P9_GETATTR_MTIME: u64 = 0x00000040;
const _P9_GETATTR_CTIME: u64 = 0x00000080;
const _P9_GETATTR_INO: u64 = 0x00000100;
const _P9_GETATTR_SIZE: u64 = 0x00000200;
const _P9_GETATTR_BLOCKS: u64 = 0x00000400;

const _P9_GETATTR_BTIME: u64 = 0x00000800;
const _P9_GETATTR_GEN: u64 = 0x00001000;
const _P9_GETATTR_DATA_VERSION: u64 = 0x00002000;

const P9_GETATTR_BASIC: u64 = 0x000007ff; /* Mask for fields up to BLOCKS */
const _P9_GETATTR_ALL: u64 = 0x00003fff; /* Mask for All fields above */

// Bitmask values for the setattr request.
const P9_SETATTR_MODE: u32 = 0x00000001;
const P9_SETATTR_UID: u32 = 0x00000002;
const P9_SETATTR_GID: u32 = 0x00000004;
const P9_SETATTR_SIZE: u32 = 0x00000008;
const P9_SETATTR_ATIME: u32 = 0x00000010;
const P9_SETATTR_MTIME: u32 = 0x00000020;
const P9_SETATTR_CTIME: u32 = 0x00000040;
const P9_SETATTR_ATIME_SET: u32 = 0x00000080;
const P9_SETATTR_MTIME_SET: u32 = 0x00000100;

// 9p lock constants. Taken from "include/net/9p/9p.h" in the linux kernel.
const _P9_LOCK_TYPE_RDLCK: u8 = 0;
const _P9_LOCK_TYPE_WRLCK: u8 = 1;
const P9_LOCK_TYPE_UNLCK: u8 = 2;
const _P9_LOCK_FLAGS_BLOCK: u8 = 1;
const _P9_LOCK_FLAGS_RECLAIM: u8 = 2;
const P9_LOCK_SUCCESS: u8 = 0;
const _P9_LOCK_BLOCKED: u8 = 1;
const _P9_LOCK_ERROR: u8 = 2;
const _P9_LOCK_GRACE: u8 = 3;

// Minimum and maximum message size that we'll expect from the client.
const MIN_MESSAGE_SIZE: u32 = 256;
const MAX_MESSAGE_SIZE: u32 = 64 * 1024 + 24; // 64 KiB of payload plus some extra for the header

#[derive(PartialEq, Eq)]
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

// Represents state that the server is holding on behalf of a client. Fids are somewhat like file
// descriptors but are not restricted to open files and directories. Fids are identified by a unique
// 32-bit number chosen by the client. Most messages sent by clients include a fid on which to
// operate. The fid in a Tattach message represents the root of the file system tree that the client
// is allowed to access. A client can create more fids by walking the directory tree from that fid.
struct Fid {
    path: File,
    file: Option<File>,
    filetype: FileType,
}

impl From<libc::stat64> for Qid {
    fn from(st: libc::stat64) -> Qid {
        let ty = match st.st_mode & libc::S_IFMT {
            libc::S_IFDIR => P9_QTDIR,
            libc::S_IFREG => P9_QTFILE,
            libc::S_IFLNK => P9_QTSYMLINK,
            _ => 0,
        };

        Qid {
            ty,
            // TODO: deal with the 2038 problem before 2038
            version: st.st_mtime as u32,
            path: st.st_ino,
        }
    }
}

fn statat(d: &File, name: &CStr, flags: libc::c_int) -> io::Result<libc::stat64> {
    let mut st = MaybeUninit::<libc::stat64>::zeroed();

    // Safe because the kernel will only write data in `st` and we check the return
    // value.
    let res = unsafe {
        libc::fstatat64(
            d.as_raw_fd(),
            name.as_ptr(),
            st.as_mut_ptr(),
            flags | libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if res >= 0 {
        // Safe because the kernel guarantees that the struct is now fully initialized.
        Ok(unsafe { st.assume_init() })
    } else {
        Err(io::Error::last_os_error())
    }
}

fn stat(f: &File) -> io::Result<libc::stat64> {
    // Safe because this is a constant value and a valid C string.
    let pathname = unsafe { CStr::from_bytes_with_nul_unchecked(b"\0") };

    statat(f, pathname, libc::AT_EMPTY_PATH)
}

fn string_to_cstring(s: String) -> io::Result<CString> {
    CString::new(s).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}

fn error_to_rmessage(err: io::Error) -> Rmessage {
    let errno = if let Some(errno) = err.raw_os_error() {
        errno
    } else {
        // Make a best-effort guess based on the kind.
        match err.kind() {
            io::ErrorKind::NotFound => libc::ENOENT,
            io::ErrorKind::PermissionDenied => libc::EPERM,
            io::ErrorKind::ConnectionRefused => libc::ECONNREFUSED,
            io::ErrorKind::ConnectionReset => libc::ECONNRESET,
            io::ErrorKind::ConnectionAborted => libc::ECONNABORTED,
            io::ErrorKind::NotConnected => libc::ENOTCONN,
            io::ErrorKind::AddrInUse => libc::EADDRINUSE,
            io::ErrorKind::AddrNotAvailable => libc::EADDRNOTAVAIL,
            io::ErrorKind::BrokenPipe => libc::EPIPE,
            io::ErrorKind::AlreadyExists => libc::EEXIST,
            io::ErrorKind::WouldBlock => libc::EWOULDBLOCK,
            io::ErrorKind::InvalidInput => libc::EINVAL,
            io::ErrorKind::InvalidData => libc::EINVAL,
            io::ErrorKind::TimedOut => libc::ETIMEDOUT,
            io::ErrorKind::WriteZero => libc::EIO,
            io::ErrorKind::Interrupted => libc::EINTR,
            io::ErrorKind::Other => libc::EIO,
            io::ErrorKind::UnexpectedEof => libc::EIO,
            _ => libc::EIO,
        }
    };

    Rmessage::Lerror(Rlerror {
        ecode: errno as u32,
    })
}

// Sigh.. Cow requires the underlying type to implement Clone.
enum MaybeOwned<'b, T> {
    Borrowed(&'b T),
    Owned(T),
}

impl<'a, T> Deref for MaybeOwned<'a, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        use MaybeOwned::*;
        match *self {
            Borrowed(borrowed) => borrowed,
            Owned(ref owned) => owned,
        }
    }
}

impl<'a, T> AsRef<T> for MaybeOwned<'a, T> {
    fn as_ref(&self) -> &T {
        use MaybeOwned::*;
        match self {
            Borrowed(borrowed) => borrowed,
            Owned(ref owned) => owned,
        }
    }
}

fn ebadf() -> io::Error {
    io::Error::from_raw_os_error(libc::EBADF)
}

pub type ServerIdMap<T> = BTreeMap<T, T>;
pub type ServerUidMap = ServerIdMap<libc::uid_t>;
pub type ServerGidMap = ServerIdMap<libc::gid_t>;

fn map_id_from_host<T: Clone + Ord>(map: &ServerIdMap<T>, id: T) -> T {
    map.get(&id).map_or(id.clone(), |v| v.clone())
}

// Performs an ascii case insensitive lookup and returns an O_PATH fd for the entry, if found.
fn ascii_casefold_lookup(proc: &File, parent: &File, name: &[u8]) -> io::Result<File> {
    let mut dir = open_fid(proc, parent, P9_DIRECTORY)?;
    let mut dirents = read_dir(&mut dir, 0)?;

    while let Some(entry) = dirents.next().transpose()? {
        if name.eq_ignore_ascii_case(entry.name.to_bytes()) {
            return lookup(parent, entry.name);
        }
    }

    Err(io::Error::from_raw_os_error(libc::ENOENT))
}

fn lookup(parent: &File, name: &CStr) -> io::Result<File> {
    // Safe because this doesn't modify any memory and we check the return value.
    let fd = syscall!(unsafe {
        libc::openat64(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    })?;

    // Safe because we just opened this fd.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn do_walk(
    proc: &File,
    wnames: Vec<String>,
    start: &File,
    ascii_casefold: bool,
    mds: &mut Vec<libc::stat64>,
) -> io::Result<File> {
    let mut current = MaybeOwned::Borrowed(start);

    for wname in wnames {
        let name = string_to_cstring(wname)?;
        current = MaybeOwned::Owned(lookup(current.as_ref(), &name).or_else(|e| {
            if ascii_casefold {
                if let Some(libc::ENOENT) = e.raw_os_error() {
                    return ascii_casefold_lookup(proc, current.as_ref(), name.to_bytes());
                }
            }

            Err(e)
        })?);
        mds.push(stat(&current)?);
    }

    match current {
        MaybeOwned::Owned(owned) => Ok(owned),
        MaybeOwned::Borrowed(borrowed) => borrowed.try_clone(),
    }
}

fn open_fid(proc: &File, path: &File, p9_flags: u32) -> io::Result<File> {
    let pathname = string_to_cstring(format!("self/fd/{}", path.as_raw_fd()))?;

    // We always open files with O_CLOEXEC.
    let mut flags: i32 = libc::O_CLOEXEC;
    for &(p9f, of) in &MAPPED_FLAGS {
        if (p9_flags & p9f) != 0 {
            flags |= of;
        }
    }

    if p9_flags & P9_NOACCESS == P9_RDONLY {
        flags |= libc::O_RDONLY;
    }

    // Safe because this doesn't modify any memory and we check the return value. We need to
    // clear the O_NOFOLLOW flag because we want to follow the proc symlink.
    let fd = syscall!(unsafe {
        libc::openat64(
            proc.as_raw_fd(),
            pathname.as_ptr(),
            flags & !libc::O_NOFOLLOW,
        )
    })?;

    // Safe because we just opened this fd and we know it is valid.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Config {
    pub root: Box<Path>,
    pub msize: u32,

    pub uid_map: ServerUidMap,
    pub gid_map: ServerGidMap,

    pub ascii_casefold: bool,
}

impl FromStr for Config {
    type Err = &'static str;

    fn from_str(params: &str) -> Result<Self, Self::Err> {
        let mut cfg = Self::default();
        if params.is_empty() {
            return Ok(cfg);
        }
        for opt in params.split(':') {
            let mut o = opt.splitn(2, '=');
            let kind = o.next().ok_or("`cfg` options mut not be empty")?;
            let value = o
                .next()
                .ok_or("`cfg` options must be of the form `kind=value`")?;
            match kind {
                "ascii_casefold" => {
                    let ascii_casefold = value
                        .parse()
                        .map_err(|_| "`ascii_casefold` must be a boolean")?;
                    cfg.ascii_casefold = ascii_casefold;
                }
                _ => return Err("unrecognized option for p9 config"),
            }
        }
        Ok(cfg)
    }
}

impl Default for Config {
    fn default() -> Config {
        Config {
            root: Path::new("/").into(),
            msize: MAX_MESSAGE_SIZE,
            uid_map: Default::default(),
            gid_map: Default::default(),
            ascii_casefold: false,
        }
    }
}
pub struct Server {
    fids: BTreeMap<u32, Fid>,
    proc: File,
    cfg: Config,
}

impl Server {
    pub fn new<P: Into<Box<Path>>>(
        root: P,
        uid_map: ServerUidMap,
        gid_map: ServerGidMap,
    ) -> io::Result<Server> {
        Server::with_config(Config {
            root: root.into(),
            msize: MAX_MESSAGE_SIZE,
            uid_map,
            gid_map,
            ascii_casefold: false,
        })
    }

    pub fn with_config(cfg: Config) -> io::Result<Server> {
        // Safe because this is a valid c-string.
        let proc_cstr = unsafe { CStr::from_bytes_with_nul_unchecked(b"/proc\0") };

        // Safe because this doesn't modify any memory and we check the return value.
        let fd = syscall!(unsafe {
            libc::openat64(
                libc::AT_FDCWD,
                proc_cstr.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        })?;

        // Safe because we just opened this fd and we know it is valid.
        let proc = unsafe { File::from_raw_fd(fd) };
        Ok(Server {
            fids: BTreeMap::new(),
            proc,
            cfg,
        })
    }

    pub fn keep_fds(&self) -> Vec<RawFd> {
        vec![self.proc.as_raw_fd()]
    }

    pub fn handle_message<R: Read, W: Write>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
    ) -> io::Result<()> {
        let Tframe { tag, msg } = WireFormat::decode(&mut reader.take(self.cfg.msize as u64))?;

        let rmsg = match msg {
            Ok(Tmessage::Version(ref version)) => self.version(version).map(Rmessage::Version),
            Ok(Tmessage::Flush(ref flush)) => self.flush(flush).and(Ok(Rmessage::Flush)),
            Ok(Tmessage::Walk(walk)) => self.walk(walk).map(Rmessage::Walk),
            Ok(Tmessage::Read(ref read)) => self.read(read).map(Rmessage::Read),
            Ok(Tmessage::Write(ref write)) => self.write(write).map(Rmessage::Write),
            Ok(Tmessage::Clunk(ref clunk)) => self.clunk(clunk).and(Ok(Rmessage::Clunk)),
            Ok(Tmessage::Remove(ref remove)) => self.remove(remove).and(Ok(Rmessage::Remove)),
            Ok(Tmessage::Attach(ref attach)) => self.attach(attach).map(Rmessage::Attach),
            Ok(Tmessage::Auth(ref auth)) => self.auth(auth).map(Rmessage::Auth),
            Ok(Tmessage::Statfs(ref statfs)) => self.statfs(statfs).map(Rmessage::Statfs),
            Ok(Tmessage::Lopen(ref lopen)) => self.lopen(lopen).map(Rmessage::Lopen),
            Ok(Tmessage::Lcreate(lcreate)) => self.lcreate(lcreate).map(Rmessage::Lcreate),
            Ok(Tmessage::Symlink(ref symlink)) => self.symlink(symlink).map(Rmessage::Symlink),
            Ok(Tmessage::Mknod(ref mknod)) => self.mknod(mknod).map(Rmessage::Mknod),
            Ok(Tmessage::Rename(ref rename)) => self.rename(rename).and(Ok(Rmessage::Rename)),
            Ok(Tmessage::Readlink(ref readlink)) => self.readlink(readlink).map(Rmessage::Readlink),
            Ok(Tmessage::GetAttr(ref get_attr)) => self.get_attr(get_attr).map(Rmessage::GetAttr),
            Ok(Tmessage::SetAttr(ref set_attr)) => {
                self.set_attr(set_attr).and(Ok(Rmessage::SetAttr))
            }
            Ok(Tmessage::XattrWalk(ref xattr_walk)) => {
                self.xattr_walk(xattr_walk).map(Rmessage::XattrWalk)
            }
            Ok(Tmessage::XattrCreate(ref xattr_create)) => self
                .xattr_create(xattr_create)
                .and(Ok(Rmessage::XattrCreate)),
            Ok(Tmessage::Readdir(ref readdir)) => self.readdir(readdir).map(Rmessage::Readdir),
            Ok(Tmessage::Fsync(ref fsync)) => self.fsync(fsync).and(Ok(Rmessage::Fsync)),
            Ok(Tmessage::Lock(ref lock)) => self.lock(lock).map(Rmessage::Lock),
            Ok(Tmessage::GetLock(ref get_lock)) => self.get_lock(get_lock).map(Rmessage::GetLock),
            Ok(Tmessage::Link(link)) => self.link(link).and(Ok(Rmessage::Link)),
            Ok(Tmessage::Mkdir(mkdir)) => self.mkdir(mkdir).map(Rmessage::Mkdir),
            Ok(Tmessage::RenameAt(rename_at)) => {
                self.rename_at(rename_at).and(Ok(Rmessage::RenameAt))
            }
            Ok(Tmessage::UnlinkAt(unlink_at)) => {
                self.unlink_at(unlink_at).and(Ok(Rmessage::UnlinkAt))
            }
            Err(e) => {
                // The header was successfully decoded, but the body failed to decode - send an
                // error response for this tag.
                let error = format!("Tframe message decode failed: {}", e);
                Err(io::Error::new(io::ErrorKind::InvalidData, error))
            }
        };

        // Errors while handling requests are never fatal.
        let response = Rframe {
            tag,
            msg: rmsg.unwrap_or_else(error_to_rmessage),
        };

        response.encode(writer)?;
        writer.flush()
    }

    fn auth(&mut self, _auth: &Tauth) -> io::Result<Rauth> {
        // Returning an error for the auth message means that the server does not require
        // authentication.
        Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
    }

    fn attach(&mut self, attach: &Tattach) -> io::Result<Rattach> {
        // TODO: Check attach parameters
        match self.fids.entry(attach.fid) {
            btree_map::Entry::Vacant(entry) => {
                let root = CString::new(self.cfg.root.as_os_str().as_bytes())
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

                // Safe because this doesn't modify any memory and we check the return value.
                let fd = syscall!(unsafe {
                    libc::openat64(
                        libc::AT_FDCWD,
                        root.as_ptr(),
                        libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                })?;

                let root_path = unsafe { File::from_raw_fd(fd) };
                let st = stat(&root_path)?;

                let fid = Fid {
                    // Safe because we just opened this fd.
                    path: root_path,
                    file: None,
                    filetype: st.st_mode.into(),
                };
                let response = Rattach { qid: st.into() };
                entry.insert(fid);
                Ok(response)
            }
            btree_map::Entry::Occupied(_) => Err(io::Error::from_raw_os_error(libc::EBADF)),
        }
    }

    fn version(&mut self, version: &Tversion) -> io::Result<Rversion> {
        if version.msize < MIN_MESSAGE_SIZE {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }

        // A Tversion request clunks all open fids and terminates any pending I/O.
        self.fids.clear();
        self.cfg.msize = min(self.cfg.msize, version.msize);

        Ok(Rversion {
            msize: self.cfg.msize,
            version: if version.version == "9P2000.L" {
                String::from("9P2000.L")
            } else {
                String::from("unknown")
            },
        })
    }

    #[allow(clippy::unnecessary_wraps)]
    fn flush(&mut self, _flush: &Tflush) -> io::Result<()> {
        // TODO: Since everything is synchronous we can't actually flush requests.
        Ok(())
    }

    fn walk(&mut self, walk: Twalk) -> io::Result<Rwalk> {
        // `newfid` must not currently be in use unless it is the same as `fid`.
        if walk.fid != walk.newfid && self.fids.contains_key(&walk.newfid) {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        }

        // We need to walk the tree.  First get the starting path.
        let start = &self.fids.get(&walk.fid).ok_or_else(ebadf)?.path;

        // Now walk the tree and break on the first error, if any.
        let expected_len = walk.wnames.len();
        let mut mds = Vec::with_capacity(expected_len);
        match do_walk(
            &self.proc,
            walk.wnames,
            start,
            self.cfg.ascii_casefold,
            &mut mds,
        ) {
            Ok(end) => {
                // Store the new fid if the full walk succeeded.
                if mds.len() == expected_len {
                    let st = mds.last().copied().map(Ok).unwrap_or_else(|| stat(&end))?;
                    self.fids.insert(
                        walk.newfid,
                        Fid {
                            path: end,
                            file: None,
                            filetype: st.st_mode.into(),
                        },
                    );
                }
            }
            Err(e) => {
                // Only return an error if it occurred on the first component.
                if mds.is_empty() {
                    return Err(e);
                }
            }
        }

        Ok(Rwalk {
            wqids: mds.into_iter().map(Qid::from).collect(),
        })
    }

    fn read(&mut self, read: &Tread) -> io::Result<Rread> {
        // Thankfully, `read` cannot be used to read directories in 9P2000.L.
        let file = self
            .fids
            .get_mut(&read.fid)
            .and_then(|fid| fid.file.as_mut())
            .ok_or_else(ebadf)?;

        // Use an empty Rread struct to figure out the overhead of the header.
        let header_size = Rframe {
            tag: 0,
            msg: Rmessage::Read(Rread {
                data: Data(Vec::new()),
            }),
        }
        .byte_size();

        let capacity = min(self.cfg.msize - header_size, read.count);
        let mut buf = Data(vec![0u8; capacity as usize]);

        let count = file.read_at(&mut buf, read.offset)?;
        buf.truncate(count);

        Ok(Rread { data: buf })
    }

    fn write(&mut self, write: &Twrite) -> io::Result<Rwrite> {
        let file = self
            .fids
            .get_mut(&write.fid)
            .and_then(|fid| fid.file.as_mut())
            .ok_or_else(ebadf)?;

        let count = file.write_at(&write.data, write.offset)?;
        Ok(Rwrite {
            count: count as u32,
        })
    }

    fn clunk(&mut self, clunk: &Tclunk) -> io::Result<()> {
        match self.fids.entry(clunk.fid) {
            btree_map::Entry::Vacant(_) => Err(io::Error::from_raw_os_error(libc::EBADF)),
            btree_map::Entry::Occupied(entry) => {
                entry.remove();
                Ok(())
            }
        }
    }

    fn remove(&mut self, _remove: &Tremove) -> io::Result<()> {
        // Since a file could be linked into multiple locations, there is no way to know exactly
        // which path we are supposed to unlink. Linux uses unlink_at anyway, so we can just return
        // an error here.
        Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
    }

    fn statfs(&mut self, statfs: &Tstatfs) -> io::Result<Rstatfs> {
        let fid = self.fids.get(&statfs.fid).ok_or_else(ebadf)?;
        let mut buf = MaybeUninit::zeroed();

        // Safe because this will only modify `out` and we check the return value.
        syscall!(unsafe { libc::fstatfs64(fid.path.as_raw_fd(), buf.as_mut_ptr()) })?;

        // Safe because this only has integer types and any value is valid.
        let out = unsafe { buf.assume_init() };
        Ok(Rstatfs {
            ty: out.f_type as u32,
            bsize: out.f_bsize as u32,
            blocks: out.f_blocks,
            bfree: out.f_bfree,
            bavail: out.f_bavail,
            files: out.f_files,
            ffree: out.f_ffree,
            // Safe because the fsid has only integer fields and the compiler will verify that is
            // the same width as the `fsid` field in Rstatfs.
            fsid: unsafe { mem::transmute(out.f_fsid) },
            namelen: out.f_namelen as u32,
        })
    }

    fn lopen(&mut self, lopen: &Tlopen) -> io::Result<Rlopen> {
        let fid = self.fids.get_mut(&lopen.fid).ok_or_else(ebadf)?;

        let file = open_fid(&self.proc, &fid.path, lopen.flags)?;
        let st = stat(&file)?;

        fid.file = Some(file);
        Ok(Rlopen {
            qid: st.into(),
            iounit: 0, // Allow the client to send requests up to the negotiated max message size.
        })
    }

    fn lcreate(&mut self, lcreate: Tlcreate) -> io::Result<Rlcreate> {
        let fid = self.fids.get_mut(&lcreate.fid).ok_or_else(ebadf)?;

        if fid.filetype != FileType::Directory {
            return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
        }

        let mut flags: i32 = libc::O_CLOEXEC | libc::O_CREAT | libc::O_EXCL;
        for &(p9f, of) in &MAPPED_FLAGS {
            if (lcreate.flags & p9f) != 0 {
                flags |= of;
            }
        }
        if lcreate.flags & P9_NOACCESS == P9_RDONLY {
            flags |= libc::O_RDONLY;
        }

        let name = string_to_cstring(lcreate.name)?;

        // Safe because this doesn't modify any memory and we check the return value.
        let fd = syscall!(unsafe {
            libc::openat64(fid.path.as_raw_fd(), name.as_ptr(), flags, lcreate.mode)
        })?;

        // Safe because we just opened this fd and we know it is valid.
        let file = unsafe { File::from_raw_fd(fd) };
        let st = stat(&file)?;

        fid.file = Some(file);
        fid.filetype = FileType::Regular;

        // This fid now refers to the newly created file so we need to update the O_PATH fd for it
        // as well.
        fid.path = lookup(&fid.path, &name)?;

        Ok(Rlcreate {
            qid: st.into(),
            iounit: 0, // Allow the client to send requests up to the negotiated max message size.
        })
    }

    fn symlink(&mut self, _symlink: &Tsymlink) -> io::Result<Rsymlink> {
        // symlinks are not allowed.
        Err(io::Error::from_raw_os_error(libc::EACCES))
    }

    fn mknod(&mut self, _mknod: &Tmknod) -> io::Result<Rmknod> {
        // No nodes either.
        Err(io::Error::from_raw_os_error(libc::EACCES))
    }

    fn rename(&mut self, _rename: &Trename) -> io::Result<()> {
        // We cannot support this as an inode may be linked into multiple directories but we don't
        // know which one the client wants us to rename. Linux uses rename_at anyway, so we don't
        // need to worry about this.
        Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
    }

    fn readlink(&mut self, readlink: &Treadlink) -> io::Result<Rreadlink> {
        let fid = self.fids.get(&readlink.fid).ok_or_else(ebadf)?;

        let mut link = vec![0; libc::PATH_MAX as usize];

        // Safe because this will only modify `link` and we check the return value.
        let len = syscall!(unsafe {
            libc::readlinkat(
                fid.path.as_raw_fd(),
                [0].as_ptr(),
                link.as_mut_ptr() as *mut libc::c_char,
                link.len(),
            )
        })? as usize;
        link.truncate(len);
        let target = String::from_utf8(link)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        Ok(Rreadlink { target })
    }

    #[allow(clippy::unnecessary_cast)] // nlink_t is u32 on 32-bit platforms
    fn get_attr(&mut self, get_attr: &Tgetattr) -> io::Result<Rgetattr> {
        let fid = self.fids.get_mut(&get_attr.fid).ok_or_else(ebadf)?;

        let st = stat(&fid.path)?;

        Ok(Rgetattr {
            valid: P9_GETATTR_BASIC,
            qid: st.into(),
            mode: st.st_mode,
            uid: map_id_from_host(&self.cfg.uid_map, st.st_uid),
            gid: map_id_from_host(&self.cfg.gid_map, st.st_gid),
            nlink: st.st_nlink as u64,
            rdev: st.st_rdev,
            size: st.st_size as u64,
            blksize: st.st_blksize as u64,
            blocks: st.st_blocks as u64,
            atime_sec: st.st_atime as u64,
            atime_nsec: st.st_atime_nsec as u64,
            mtime_sec: st.st_mtime as u64,
            mtime_nsec: st.st_mtime_nsec as u64,
            ctime_sec: st.st_ctime as u64,
            ctime_nsec: st.st_ctime_nsec as u64,
            btime_sec: 0,
            btime_nsec: 0,
            gen: 0,
            data_version: 0,
        })
    }

    fn set_attr(&mut self, set_attr: &Tsetattr) -> io::Result<()> {
        let fid = self.fids.get(&set_attr.fid).ok_or_else(ebadf)?;
        let path = string_to_cstring(format!("self/fd/{}", fid.path.as_raw_fd()))?;

        if set_attr.valid & P9_SETATTR_MODE != 0 {
            // Safe because this doesn't modify any memory and we check the return value.
            syscall!(unsafe {
                libc::fchmodat(self.proc.as_raw_fd(), path.as_ptr(), set_attr.mode, 0)
            })?;
        }

        if set_attr.valid & (P9_SETATTR_UID | P9_SETATTR_GID) != 0 {
            let uid = if set_attr.valid & P9_SETATTR_UID != 0 {
                set_attr.uid
            } else {
                -1i32 as u32
            };
            let gid = if set_attr.valid & P9_SETATTR_GID != 0 {
                set_attr.gid
            } else {
                -1i32 as u32
            };

            // Safe because this doesn't modify any memory and we check the return value.
            syscall!(unsafe { libc::fchownat(self.proc.as_raw_fd(), path.as_ptr(), uid, gid, 0) })?;
        }

        if set_attr.valid & P9_SETATTR_SIZE != 0 {
            let file = if fid.filetype == FileType::Directory {
                return Err(io::Error::from_raw_os_error(libc::EISDIR));
            } else if let Some(ref file) = fid.file {
                MaybeOwned::Borrowed(file)
            } else {
                MaybeOwned::Owned(open_fid(&self.proc, &fid.path, P9_NONBLOCK | P9_RDWR)?)
            };

            file.set_len(set_attr.size)?;
        }

        if set_attr.valid & (P9_SETATTR_ATIME | P9_SETATTR_MTIME) != 0 {
            let times = [
                libc::timespec {
                    tv_sec: set_attr.atime_sec as _,
                    tv_nsec: if set_attr.valid & P9_SETATTR_ATIME == 0 {
                        libc::UTIME_OMIT
                    } else if set_attr.valid & P9_SETATTR_ATIME_SET == 0 {
                        libc::UTIME_NOW
                    } else {
                        set_attr.atime_nsec as _
                    },
                },
                libc::timespec {
                    tv_sec: set_attr.mtime_sec as _,
                    tv_nsec: if set_attr.valid & P9_SETATTR_MTIME == 0 {
                        libc::UTIME_OMIT
                    } else if set_attr.valid & P9_SETATTR_MTIME_SET == 0 {
                        libc::UTIME_NOW
                    } else {
                        set_attr.mtime_nsec as _
                    },
                },
            ];

            // Safe because file is valid and we have initialized times fully.
            let ret = unsafe {
                libc::utimensat(
                    self.proc.as_raw_fd(),
                    path.as_ptr(),
                    &times as *const libc::timespec,
                    0,
                )
            };
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        // The ctime would have been updated by any of the above operations so we only
        // need to change it if it was the only option given.
        if set_attr.valid & P9_SETATTR_CTIME != 0 && set_attr.valid & (!P9_SETATTR_CTIME) == 0 {
            // Setting -1 as the uid and gid will not actually change anything but will
            // still update the ctime.
            let ret = unsafe {
                libc::fchownat(
                    self.proc.as_raw_fd(),
                    path.as_ptr(),
                    libc::uid_t::max_value(),
                    libc::gid_t::max_value(),
                    0,
                )
            };
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        Ok(())
    }

    fn xattr_walk(&mut self, _xattr_walk: &Txattrwalk) -> io::Result<Rxattrwalk> {
        Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
    }

    fn xattr_create(&mut self, _xattr_create: &Txattrcreate) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
    }

    fn readdir(&mut self, readdir: &Treaddir) -> io::Result<Rreaddir> {
        let fid = self.fids.get_mut(&readdir.fid).ok_or_else(ebadf)?;

        if fid.filetype != FileType::Directory {
            return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
        }

        // Use an empty Rreaddir struct to figure out the maximum number of bytes that
        // can be returned.
        let header_size = Rframe {
            tag: 0,
            msg: Rmessage::Readdir(Rreaddir {
                data: Data(Vec::new()),
            }),
        }
        .byte_size();
        let count = min(self.cfg.msize - header_size, readdir.count);
        let mut cursor = Cursor::new(Vec::with_capacity(count as usize));

        let dir = fid.file.as_mut().ok_or_else(ebadf)?;
        let mut dirents = read_dir(dir, readdir.offset as libc::off64_t)?;
        while let Some(dirent) = dirents.next().transpose()? {
            let st = statat(&fid.path, dirent.name, 0)?;

            let name = dirent
                .name
                .to_str()
                .map(String::from)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;

            let entry = Dirent {
                qid: st.into(),
                offset: dirent.offset,
                ty: dirent.type_,
                name,
            };

            let byte_size = entry.byte_size() as usize;

            if cursor.get_ref().capacity() - cursor.get_ref().len() < byte_size {
                // No more room in the buffer.
                break;
            }

            entry.encode(&mut cursor)?;
        }

        Ok(Rreaddir {
            data: Data(cursor.into_inner()),
        })
    }

    fn fsync(&mut self, fsync: &Tfsync) -> io::Result<()> {
        let file = self
            .fids
            .get(&fsync.fid)
            .and_then(|fid| fid.file.as_ref())
            .ok_or_else(ebadf)?;

        if fsync.datasync == 0 {
            file.sync_all()?;
        } else {
            file.sync_data()?;
        }
        Ok(())
    }

    /// Implement posix byte range locking code.
    /// Our implementation mirrors that of QEMU/9p - that is to say,
    /// we essentially punt on mirroring lock state between client/server
    /// and defer lock semantics to the VFS layer on the client side. Aside
    /// from fd existence check we always return success. QEMU reference:
    /// <https://github.com/qemu/qemu/blob/754f756cc4c6d9d14b7230c62b5bb20f9d655888/hw/9pfs/9p.c#L3669>
    ///
    /// NOTE: this means that files locked on the client may be interefered with
    /// from either the server's side, or from other clients (guests). This
    /// tracks with QEMU implementation, and will be obviated if crosvm decides
    /// to drop 9p in favor of virtio-fs. QEMU only allows for a single client,
    /// and we leave it to users of the crate to provide actual lock handling.
    fn lock(&mut self, lock: &Tlock) -> io::Result<Rlock> {
        // Ensure fd passed in TLOCK request exists and has a mapping.
        let fd = self
            .fids
            .get(&lock.fid)
            .and_then(|fid| fid.file.as_ref())
            .ok_or_else(ebadf)?
            .as_raw_fd();

        syscall!(unsafe {
            // Safe because zero-filled libc::stat is a valid value, fstat
            // populates the struct fields.
            let mut stbuf: libc::stat64 = std::mem::zeroed();
            // Safe because this doesn't modify memory and we check the return value.
            libc::fstat64(fd, &mut stbuf)
        })?;

        Ok(Rlock {
            status: P9_LOCK_SUCCESS,
        })
    }

    ///
    /// Much like lock(), defer locking semantics to VFS and return success.
    ///
    fn get_lock(&mut self, get_lock: &Tgetlock) -> io::Result<Rgetlock> {
        // Ensure fd passed in GETTLOCK request exists and has a mapping.
        let fd = self
            .fids
            .get(&get_lock.fid)
            .and_then(|fid| fid.file.as_ref())
            .ok_or_else(ebadf)?
            .as_raw_fd();

        // Safe because this doesn't modify memory and we check the return value.
        syscall!(unsafe {
            let mut stbuf: libc::stat64 = std::mem::zeroed();
            libc::fstat64(fd, &mut stbuf)
        })?;

        Ok(Rgetlock {
            type_: P9_LOCK_TYPE_UNLCK,
            start: get_lock.start,
            length: get_lock.length,
            proc_id: get_lock.proc_id,
            client_id: get_lock.client_id.clone(),
        })
    }

    fn link(&mut self, link: Tlink) -> io::Result<()> {
        let target = self.fids.get(&link.fid).ok_or_else(ebadf)?;
        let path = string_to_cstring(format!("self/fd/{}", target.path.as_raw_fd()))?;

        let dir = self.fids.get(&link.dfid).ok_or_else(ebadf)?;
        let name = string_to_cstring(link.name)?;

        // Safe because this doesn't modify any memory and we check the return value.
        syscall!(unsafe {
            libc::linkat(
                self.proc.as_raw_fd(),
                path.as_ptr(),
                dir.path.as_raw_fd(),
                name.as_ptr(),
                libc::AT_SYMLINK_FOLLOW,
            )
        })?;
        Ok(())
    }

    fn mkdir(&mut self, mkdir: Tmkdir) -> io::Result<Rmkdir> {
        let fid = self.fids.get(&mkdir.dfid).ok_or_else(ebadf)?;
        let name = string_to_cstring(mkdir.name)?;

        // Safe because this doesn't modify any memory and we check the return value.
        syscall!(unsafe { libc::mkdirat(fid.path.as_raw_fd(), name.as_ptr(), mkdir.mode) })?;
        Ok(Rmkdir {
            qid: statat(&fid.path, &name, 0).map(Qid::from)?,
        })
    }

    fn rename_at(&mut self, rename_at: Trenameat) -> io::Result<()> {
        let olddir = self.fids.get(&rename_at.olddirfid).ok_or_else(ebadf)?;
        let oldname = string_to_cstring(rename_at.oldname)?;

        let newdir = self.fids.get(&rename_at.newdirfid).ok_or_else(ebadf)?;
        let newname = string_to_cstring(rename_at.newname)?;

        // Safe because this doesn't modify any memory and we check the return value.
        syscall!(unsafe {
            libc::renameat(
                olddir.path.as_raw_fd(),
                oldname.as_ptr(),
                newdir.path.as_raw_fd(),
                newname.as_ptr(),
            )
        })?;

        Ok(())
    }

    fn unlink_at(&mut self, unlink_at: Tunlinkat) -> io::Result<()> {
        let dir = self.fids.get(&unlink_at.dirfd).ok_or_else(ebadf)?;
        let name = string_to_cstring(unlink_at.name)?;

        syscall!(unsafe {
            libc::unlinkat(
                dir.path.as_raw_fd(),
                name.as_ptr(),
                unlink_at.flags as libc::c_int,
            )
        })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests;
