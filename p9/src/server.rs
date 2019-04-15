// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use libc;

use std::cmp::min;
use std::collections::{btree_map, BTreeMap};
use std::ffi::CString;
use std::fs;
use std::io::{self, Cursor, Read, Write};
use std::mem;
use std::os::linux::fs::MetadataExt;
use std::os::unix::fs::{DirBuilderExt, FileExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Component, Path, PathBuf};

use crate::protocol::*;

// Tlopen and Tlcreate flags.  Taken from "include/net/9p/9p.h" in the linux tree.
const _P9_RDONLY: u32 = 0o00000000;
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
const MAPPED_FLAGS: [(u32, i32); 10] = [
    (P9_NOCTTY, libc::O_NOCTTY),
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
const _P9_QTSYMLINK: u8 = 0x02;
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

// Minimum and maximum message size that we'll expect from the client.
const MIN_MESSAGE_SIZE: u32 = 256;
const MAX_MESSAGE_SIZE: u32 = ::std::u16::MAX as u32;

// Represents state that the server is holding on behalf of a client. Fids are somewhat like file
// descriptors but are not restricted to open files and directories. Fids are identified by a unique
// 32-bit number chosen by the client. Most messages sent by clients include a fid on which to
// operate. The fid in a Tattach message represents the root of the file system tree that the client
// is allowed to access. A client can create more fids by walking the directory tree from that fid.
struct Fid {
    path: Box<Path>,
    metadata: fs::Metadata,
    file: Option<fs::File>,
    dirents: Option<Vec<Dirent>>,
}

fn metadata_to_qid(metadata: &fs::Metadata) -> Qid {
    let ty = if metadata.is_dir() {
        P9_QTDIR
    } else if metadata.is_file() {
        P9_QTFILE
    } else {
        // Unknown file type...
        0
    };

    Qid {
        ty,
        // TODO: deal with the 2038 problem before 2038
        version: metadata.st_mtime() as u32,
        path: metadata.st_ino(),
    }
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

// Joins `path` to `buf`.  If `path` is '..', removes the last component from `buf`
// only if `buf` != `root` but does nothing if `buf` == `root`.  Pushes `path` onto
// `buf` if it is a normal path component.
//
// Returns an error if `path` is absolute, has more than one component, or contains
// a '.' component.
fn join_path<P: AsRef<Path>, R: AsRef<Path>>(
    mut buf: PathBuf,
    path: P,
    root: R,
) -> io::Result<PathBuf> {
    let path = path.as_ref();
    let root = root.as_ref();
    debug_assert!(buf.starts_with(root));

    if path.components().count() > 1 {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }

    for component in path.components() {
        match component {
            // Prefix should only appear on windows systems.
            Component::Prefix(_) => return Err(io::Error::from_raw_os_error(libc::EINVAL)),
            // Absolute paths are not allowed.
            Component::RootDir => return Err(io::Error::from_raw_os_error(libc::EINVAL)),
            // '.' elements are not allowed.
            Component::CurDir => return Err(io::Error::from_raw_os_error(libc::EINVAL)),
            Component::ParentDir => {
                // We only remove the parent path if we are not already at the root of the
                // file system.
                if buf != root {
                    buf.pop();
                }
            }
            Component::Normal(element) => buf.push(element),
        }
    }

    Ok(buf)
}

pub struct Server {
    root: Box<Path>,
    msize: u32,
    fids: BTreeMap<u32, Fid>,
}

impl Server {
    pub fn new<P: AsRef<Path>>(root: P) -> Server {
        Server {
            root: root.as_ref().into(),
            msize: MAX_MESSAGE_SIZE,
            fids: BTreeMap::new(),
        }
    }

    pub fn handle_message<R: Read, W: Write>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
    ) -> io::Result<()> {
        let request: Tframe = WireFormat::decode(&mut reader.take(self.msize as u64))?;

        if cfg!(feature = "trace") {
            println!("{:?}", &request);
        }

        let rmsg = match &request.msg {
            Tmessage::Version(version) => self.version(version),
            Tmessage::Flush(flush) => self.flush(flush),
            Tmessage::Walk(walk) => self.walk(walk),
            Tmessage::Read(read) => self.read(read),
            Tmessage::Write(write) => self.write(write),
            Tmessage::Clunk(clunk) => self.clunk(clunk),
            Tmessage::Remove(remove) => self.remove(remove),
            Tmessage::Attach(attach) => self.attach(attach),
            Tmessage::Auth(auth) => self.auth(auth),
            Tmessage::Statfs(statfs) => self.statfs(statfs),
            Tmessage::Lopen(lopen) => self.lopen(lopen),
            Tmessage::Lcreate(lcreate) => self.lcreate(lcreate),
            Tmessage::Symlink(symlink) => self.symlink(symlink),
            Tmessage::Mknod(mknod) => self.mknod(mknod),
            Tmessage::Rename(rename) => self.rename(rename),
            Tmessage::Readlink(readlink) => self.readlink(readlink),
            Tmessage::GetAttr(get_attr) => self.get_attr(get_attr),
            Tmessage::SetAttr(set_attr) => self.set_attr(set_attr),
            Tmessage::XattrWalk(xattr_walk) => self.xattr_walk(xattr_walk),
            Tmessage::XattrCreate(xattr_create) => self.xattr_create(xattr_create),
            Tmessage::Readdir(readdir) => self.readdir(readdir),
            Tmessage::Fsync(fsync) => self.fsync(fsync),
            Tmessage::Lock(lock) => self.lock(lock),
            Tmessage::GetLock(get_lock) => self.get_lock(get_lock),
            Tmessage::Link(link) => self.link(link),
            Tmessage::Mkdir(mkdir) => self.mkdir(mkdir),
            Tmessage::RenameAt(rename_at) => self.rename_at(rename_at),
            Tmessage::UnlinkAt(unlink_at) => self.unlink_at(unlink_at),
        };

        // Errors while handling requests are never fatal.
        let response = Rframe {
            tag: request.tag,
            msg: rmsg.unwrap_or_else(error_to_rmessage),
        };

        if cfg!(feature = "trace") {
            println!("{:?}", &response);
        }

        response.encode(writer)?;
        writer.flush()
    }

    fn auth(&mut self, _auth: &Tauth) -> io::Result<Rmessage> {
        // Returning an error for the auth message means that the server does not require
        // authentication.
        Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
    }

    fn attach(&mut self, attach: &Tattach) -> io::Result<Rmessage> {
        // TODO: Check attach parameters
        match self.fids.entry(attach.fid) {
            btree_map::Entry::Vacant(entry) => {
                let fid = Fid {
                    path: self.root.to_path_buf().into_boxed_path(),
                    metadata: fs::metadata(&self.root)?,
                    file: None,
                    dirents: None,
                };
                let response = Rattach {
                    qid: metadata_to_qid(&fid.metadata),
                };
                entry.insert(fid);
                Ok(Rmessage::Attach(response))
            }
            btree_map::Entry::Occupied(_) => Err(io::Error::from_raw_os_error(libc::EBADF)),
        }
    }

    fn version(&mut self, version: &Tversion) -> io::Result<Rmessage> {
        if version.msize < MIN_MESSAGE_SIZE {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }

        // A Tversion request clunks all open fids and terminates any pending I/O.
        self.fids.clear();
        self.msize = min(MAX_MESSAGE_SIZE, version.msize);

        Ok(Rmessage::Version(Rversion {
            msize: self.msize,
            version: if version.version == "9P2000.L" {
                String::from("9P2000.L")
            } else {
                String::from("unknown")
            },
        }))
    }

    fn flush(&mut self, _flush: &Tflush) -> io::Result<Rmessage> {
        // TODO: Since everything is synchronous we can't actually flush requests.
        Ok(Rmessage::Flush)
    }

    fn do_walk(
        &self,
        wnames: &[String],
        mut buf: PathBuf,
        mds: &mut Vec<fs::Metadata>,
    ) -> io::Result<PathBuf> {
        for wname in wnames {
            let name = Path::new(wname);
            buf = join_path(buf, name, &*self.root)?;
            mds.push(fs::metadata(&buf)?);
        }

        Ok(buf)
    }

    fn walk(&mut self, walk: &Twalk) -> io::Result<Rmessage> {
        // `newfid` must not currently be in use unless it is the same as `fid`.
        if walk.fid != walk.newfid && self.fids.contains_key(&walk.newfid) {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        }

        // We need to walk the tree.  First get the starting path.
        let (buf, oldmd) = self
            .fids
            .get(&walk.fid)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF))
            .map(|fid| (fid.path.to_path_buf(), fid.metadata.clone()))?;

        // Now walk the tree and break on the first error, if any.
        let mut mds = Vec::with_capacity(walk.wnames.len());
        match self.do_walk(&walk.wnames, buf, &mut mds) {
            Ok(buf) => {
                // Store the new fid if the full walk succeeded.
                if mds.len() == walk.wnames.len() {
                    // This could just be a duplication operation.
                    let md = if let Some(md) = mds.last() {
                        md.clone()
                    } else {
                        oldmd
                    };

                    self.fids.insert(
                        walk.newfid,
                        Fid {
                            path: buf.into_boxed_path(),
                            metadata: md,
                            file: None,
                            dirents: None,
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

        Ok(Rmessage::Walk(Rwalk {
            wqids: mds.iter().map(metadata_to_qid).collect(),
        }))
    }

    fn read(&mut self, read: &Tread) -> io::Result<Rmessage> {
        // Thankfully, `read` cannot be used to read directories in 9P2000.L.
        let file = self
            .fids
            .get_mut(&read.fid)
            .and_then(|fid| fid.file.as_mut())
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF))?;

        // Use an empty Rread struct to figure out the overhead of the header.
        let header_size = Rframe {
            tag: 0,
            msg: Rmessage::Read(Rread {
                data: Data(Vec::new()),
            }),
        }
        .byte_size();

        let capacity = min(self.msize - header_size, read.count);
        let mut buf = Data(Vec::with_capacity(capacity as usize));
        buf.resize(capacity as usize, 0);

        let count = file.read_at(&mut buf, read.offset)?;
        buf.resize(count, 0);

        Ok(Rmessage::Read(Rread { data: buf }))
    }

    fn write(&mut self, write: &Twrite) -> io::Result<Rmessage> {
        let file = self
            .fids
            .get_mut(&write.fid)
            .and_then(|fid| fid.file.as_mut())
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF))?;

        let count = file.write_at(&write.data, write.offset)?;
        Ok(Rmessage::Write(Rwrite {
            count: count as u32,
        }))
    }

    fn clunk(&mut self, clunk: &Tclunk) -> io::Result<Rmessage> {
        match self.fids.entry(clunk.fid) {
            btree_map::Entry::Vacant(_) => Err(io::Error::from_raw_os_error(libc::EBADF)),
            btree_map::Entry::Occupied(entry) => {
                entry.remove();
                Ok(Rmessage::Clunk)
            }
        }
    }

    fn remove(&mut self, remove: &Tremove) -> io::Result<Rmessage> {
        match self.fids.entry(remove.fid) {
            btree_map::Entry::Vacant(_) => Err(io::Error::from_raw_os_error(libc::EBADF)),
            btree_map::Entry::Occupied(o) => {
                let (_, fid) = o.remove_entry();

                if fid.metadata.is_dir() {
                    fs::remove_dir(&fid.path)?;
                } else {
                    fs::remove_file(&fid.path)?;
                }

                Ok(Rmessage::Remove)
            }
        }
    }

    fn statfs(&mut self, statfs: &Tstatfs) -> io::Result<Rmessage> {
        let fid = self
            .fids
            .get(&statfs.fid)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF))?;
        let path = fid
            .path
            .to_str()
            .and_then(|path| CString::new(path).ok())
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;

        // Safe because we are zero-initializing a C struct with only primitive
        // data members.
        let mut out: libc::statfs64 = unsafe { mem::zeroed() };

        // Safe because we know that `path` is valid and we have already initialized `out`.
        let ret = unsafe { libc::statfs64(path.as_ptr(), &mut out) };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Rmessage::Statfs(Rstatfs {
            ty: out.f_type as u32,
            bsize: out.f_bsize as u32,
            blocks: out.f_blocks,
            bfree: out.f_bfree,
            bavail: out.f_bavail,
            files: out.f_files,
            ffree: out.f_ffree,
            fsid: 0, // No way to get the fields of a libc::fsid_t
            namelen: out.f_namelen as u32,
        }))
    }

    fn lopen(&mut self, lopen: &Tlopen) -> io::Result<Rmessage> {
        let fid = self
            .fids
            .get_mut(&lopen.fid)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF))?;
        // We always open files with O_CLOEXEC.
        let mut custom_flags: i32 = libc::O_CLOEXEC;
        for &(p9f, of) in &MAPPED_FLAGS {
            if (lopen.flags & p9f) != 0 {
                custom_flags |= of;
            }
        }

        let file = fs::OpenOptions::new()
            .read((lopen.flags & P9_NOACCESS) == 0 || (lopen.flags & P9_RDWR) != 0)
            .write((lopen.flags & P9_WRONLY) != 0 || (lopen.flags & P9_RDWR) != 0)
            .append((lopen.flags & P9_APPEND) != 0)
            .truncate((lopen.flags & P9_TRUNC) != 0)
            .create((lopen.flags & P9_CREATE) != 0)
            .create_new((lopen.flags & P9_CREATE) != 0 && (lopen.flags & P9_EXCL) != 0)
            .custom_flags(custom_flags)
            .open(&fid.path)?;

        fid.metadata = file.metadata()?;
        fid.file = Some(file);

        Ok(Rmessage::Lopen(Rlopen {
            qid: metadata_to_qid(&fid.metadata),
            iounit: 0,
        }))
    }

    fn lcreate(&mut self, lcreate: &Tlcreate) -> io::Result<Rmessage> {
        let fid = self
            .fids
            .get_mut(&lcreate.fid)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF))?;

        if !fid.metadata.is_dir() {
            return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
        }

        let name = Path::new(&lcreate.name);
        let path = join_path(fid.path.to_path_buf(), name, &*self.root)?;

        let mut custom_flags: i32 = libc::O_CLOEXEC;
        for &(p9f, of) in &MAPPED_FLAGS {
            if (lcreate.flags & p9f) != 0 {
                custom_flags |= of;
            }
        }

        let file = fs::OpenOptions::new()
            .read(false)
            .write(true)
            .truncate(true)
            .create(true)
            .append((lcreate.flags & P9_APPEND) != 0)
            .create_new((lcreate.flags & P9_EXCL) != 0)
            .custom_flags(custom_flags)
            .mode(lcreate.mode & 0o755)
            .open(&path)?;

        fid.metadata = file.metadata()?;
        fid.file = Some(file);
        fid.path = path.into_boxed_path();

        Ok(Rmessage::Lcreate(Rlcreate {
            qid: metadata_to_qid(&fid.metadata),
            iounit: 0,
        }))
    }

    fn symlink(&mut self, _symlink: &Tsymlink) -> io::Result<Rmessage> {
        // symlinks are not allowed.
        Err(io::Error::from_raw_os_error(libc::EACCES))
    }

    fn mknod(&mut self, _mknod: &Tmknod) -> io::Result<Rmessage> {
        // No nodes either.
        Err(io::Error::from_raw_os_error(libc::EACCES))
    }

    fn rename(&mut self, rename: &Trename) -> io::Result<Rmessage> {
        let newname = Path::new(&rename.name);
        let buf = self
            .fids
            .get(&rename.dfid)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF))
            .map(|dfid| dfid.path.to_path_buf())?;
        let newpath = join_path(buf, newname, &*self.root)?;

        let fid = self
            .fids
            .get_mut(&rename.fid)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;

        fs::rename(&fid.path, &newpath)?;

        // TODO: figure out if the client expects |fid.path| to point to
        // the renamed path.
        fid.path = newpath.into_boxed_path();
        Ok(Rmessage::Rename)
    }

    fn readlink(&mut self, _readlink: &Treadlink) -> io::Result<Rmessage> {
        // symlinks are not allowed
        Err(io::Error::from_raw_os_error(libc::EACCES))
    }

    fn get_attr(&mut self, get_attr: &Tgetattr) -> io::Result<Rmessage> {
        let fid = self
            .fids
            .get_mut(&get_attr.fid)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF))?;

        // Refresh the metadata since we were explicitly asked for it.
        fid.metadata = fs::metadata(&fid.path)?;

        Ok(Rmessage::GetAttr(Rgetattr {
            valid: P9_GETATTR_BASIC,
            qid: metadata_to_qid(&fid.metadata),
            mode: fid.metadata.st_mode(),
            uid: fid.metadata.st_uid(),
            gid: fid.metadata.st_gid(),
            nlink: fid.metadata.st_nlink(),
            rdev: fid.metadata.st_rdev(),
            size: fid.metadata.st_size(),
            blksize: fid.metadata.st_blksize(),
            blocks: fid.metadata.st_blocks(),
            atime_sec: fid.metadata.st_atime() as u64,
            atime_nsec: fid.metadata.st_atime_nsec() as u64,
            mtime_sec: fid.metadata.st_mtime() as u64,
            mtime_nsec: fid.metadata.st_mtime_nsec() as u64,
            ctime_sec: fid.metadata.st_ctime() as u64,
            ctime_nsec: fid.metadata.st_ctime_nsec() as u64,
            btime_sec: 0,
            btime_nsec: 0,
            gen: 0,
            data_version: 0,
        }))
    }

    fn set_attr(&mut self, set_attr: &Tsetattr) -> io::Result<Rmessage> {
        let blocked_ops = P9_SETATTR_MODE | P9_SETATTR_UID | P9_SETATTR_GID;
        if set_attr.valid & blocked_ops != 0 {
            return Err(io::Error::from_raw_os_error(libc::EPERM));
        }

        let fid = self
            .fids
            .get_mut(&set_attr.fid)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF))?;
        let file = fs::OpenOptions::new().write(true).open(&fid.path)?;

        if set_attr.valid & P9_SETATTR_SIZE != 0 {
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
            let ret = unsafe { libc::futimens(file.as_raw_fd(), &times as *const libc::timespec) };
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
                libc::fchown(
                    file.as_raw_fd(),
                    libc::uid_t::max_value(),
                    libc::gid_t::max_value(),
                )
            };
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        Ok(Rmessage::SetAttr)
    }

    fn xattr_walk(&mut self, _xattr_walk: &Txattrwalk) -> io::Result<Rmessage> {
        Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
    }

    fn xattr_create(&mut self, _xattr_create: &Txattrcreate) -> io::Result<Rmessage> {
        Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
    }

    fn readdir(&mut self, readdir: &Treaddir) -> io::Result<Rmessage> {
        let fid = self
            .fids
            .get_mut(&readdir.fid)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF))?;

        if !fid.metadata.is_dir() {
            return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
        }

        // The p9 client implementation in the kernel doesn't fully read all the contents
        // of the directory.  This means that if some application performs a getdents()
        // call, followed by removing some files, followed by another getdents() call,
        // the offset that we get from the kernel is completely meaningless.  Instead
        // we fully read the contents of the directory here and only re-read the directory
        // if the offset we get from the client is 0.  Any other offset is served from the
        // directory entries in memory.  This ensures consistency even if the directory
        // changes in between Treaddir messages.
        if readdir.offset == 0 {
            let mut offset = 0;
            let iter = fs::read_dir(&fid.path)?;
            let dirents = iter.map(|item| -> io::Result<Dirent> {
                let entry = item?;

                let md = entry.metadata()?;
                let qid = metadata_to_qid(&md);

                let ty = if md.is_dir() {
                    libc::DT_DIR
                } else if md.is_file() {
                    libc::DT_REG
                } else {
                    libc::DT_UNKNOWN
                };

                let name = entry
                    .file_name()
                    .into_string()
                    .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;

                let mut out = Dirent {
                    qid,
                    offset: 0, // set below
                    ty,
                    name,
                };

                offset += out.byte_size() as u64;
                out.offset = offset;

                Ok(out)
            });

            // This is taking advantage of the fact that we can turn a Iterator of Result<T, E>
            // into a Result<FromIterator<T>, E> since Result implements FromIterator<Result<T, E>>.
            fid.dirents = Some(dirents.collect::<io::Result<Vec<Dirent>>>()?);
        }

        let mut entries = fid
            .dirents
            .as_ref()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF))?
            .iter()
            .skip_while(|entry| entry.offset <= readdir.offset)
            .peekable();

        // Use an empty Rreaddir struct to figure out the maximum number of bytes that
        // can be returned.
        let header_size = Rframe {
            tag: 0,
            msg: Rmessage::Readdir(Rreaddir {
                data: Data(Vec::new()),
            }),
        }
        .byte_size();
        let count = min(self.msize - header_size, readdir.count);
        let mut cursor = Cursor::new(Vec::with_capacity(count as usize));

        while let Some(entry) = entries.peek() {
            let byte_size = entry.byte_size() as usize;

            if cursor.get_ref().capacity() - cursor.get_ref().len() < byte_size {
                // No more room in the buffer.
                break;
            }

            // Safe because we just checked that the iterator contains at least one more item.
            entries.next().unwrap().encode(&mut cursor)?;
        }

        Ok(Rmessage::Readdir(Rreaddir {
            data: Data(cursor.into_inner()),
        }))
    }

    fn fsync(&mut self, fsync: &Tfsync) -> io::Result<Rmessage> {
        let file = self
            .fids
            .get(&fsync.fid)
            .and_then(|fid| fid.file.as_ref())
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF))?;

        if fsync.datasync == 0 {
            file.sync_all()?;
        } else {
            file.sync_data()?;
        }
        Ok(Rmessage::Fsync)
    }

    fn lock(&mut self, _lock: &Tlock) -> io::Result<Rmessage> {
        // File locking is not supported.
        Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
    }
    fn get_lock(&mut self, _get_lock: &Tgetlock) -> io::Result<Rmessage> {
        // File locking is not supported.
        Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
    }

    fn link(&mut self, link: &Tlink) -> io::Result<Rmessage> {
        let newname = Path::new(&link.name);
        let buf = self
            .fids
            .get(&link.dfid)
            .map(|dfid| dfid.path.to_path_buf())
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF))?;
        let newpath = join_path(buf, newname, &*self.root)?;

        let path = self
            .fids
            .get(&link.fid)
            .map(|fid| &fid.path)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF))?;

        fs::hard_link(path, &newpath)?;
        Ok(Rmessage::Link)
    }

    fn mkdir(&mut self, mkdir: &Tmkdir) -> io::Result<Rmessage> {
        let fid = self
            .fids
            .get(&mkdir.dfid)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF))?;

        let name = Path::new(&mkdir.name);
        let newpath = join_path(fid.path.to_path_buf(), name, &*self.root)?;

        fs::DirBuilder::new()
            .recursive(false)
            .mode(mkdir.mode & 0o755)
            .create(&newpath)?;

        Ok(Rmessage::Mkdir(Rmkdir {
            qid: metadata_to_qid(&fs::metadata(&newpath)?),
        }))
    }

    fn rename_at(&mut self, rename_at: &Trenameat) -> io::Result<Rmessage> {
        let oldname = Path::new(&rename_at.oldname);
        let oldbuf = self
            .fids
            .get(&rename_at.olddirfid)
            .map(|dfid| dfid.path.to_path_buf())
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF))?;
        let oldpath = join_path(oldbuf, oldname, &*self.root)?;

        let newname = Path::new(&rename_at.newname);
        let newbuf = self
            .fids
            .get(&rename_at.newdirfid)
            .map(|dfid| dfid.path.to_path_buf())
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF))?;
        let newpath = join_path(newbuf, newname, &*self.root)?;

        fs::rename(&oldpath, &newpath)?;
        Ok(Rmessage::RenameAt)
    }

    fn unlink_at(&mut self, unlink_at: &Tunlinkat) -> io::Result<Rmessage> {
        let name = Path::new(&unlink_at.name);
        let buf = self
            .fids
            .get(&unlink_at.dirfd)
            .map(|fid| fid.path.to_path_buf())
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF))?;
        let path = join_path(buf, name, &*self.root)?;

        let md = fs::metadata(&path)?;
        if md.is_dir() && (unlink_at.flags & (libc::AT_REMOVEDIR as u32)) == 0 {
            return Err(io::Error::from_raw_os_error(libc::EISDIR));
        }

        if md.is_dir() {
            fs::remove_dir(&path)?;
        } else {
            fs::remove_file(&path)?;
        }

        Ok(Rmessage::UnlinkAt)
    }
}

#[cfg(test)]
mod tests {
    // Most of the server implementation is tested via integration tests.
    use super::*;

    #[test]
    fn path_joins() {
        let root = PathBuf::from("/a/b/c");
        let path = PathBuf::from("/a/b/c/d/e/f");

        assert_eq!(
            &join_path(path.clone(), "nested", &root).expect("normal"),
            Path::new("/a/b/c/d/e/f/nested")
        );

        let p1 = join_path(path.clone(), "..", &root).expect("parent 1");
        assert_eq!(&p1, Path::new("/a/b/c/d/e/"));

        let p2 = join_path(p1, "..", &root).expect("parent 2");
        assert_eq!(&p2, Path::new("/a/b/c/d/"));

        let p3 = join_path(p2, "..", &root).expect("parent 3");
        assert_eq!(&p3, Path::new("/a/b/c/"));

        let p4 = join_path(p3, "..", &root).expect("parent of root");
        assert_eq!(&p4, Path::new("/a/b/c/"));
    }

    #[test]
    fn invalid_joins() {
        let root = PathBuf::from("/a");
        let path = PathBuf::from("/a/b");

        join_path(path.clone(), ".", &root).expect_err("current directory");
        join_path(path.clone(), "c/d/e", &root).expect_err("too many components");
        join_path(path.clone(), "/c/d/e", &root).expect_err("absolute path");
    }
}
