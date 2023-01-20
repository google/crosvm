// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;
use std::io::ErrorKind;
use std::io::Read;
use std::io::Write;
use std::mem;
use std::string::String;
use std::vec::Vec;

use crate::protocol::wire_format::Data;
use crate::protocol::wire_format::WireFormat;

// Message type constants.  Taken from "include/net/9p/9p.h" in the linux kernel
// tree.  The protocol specifies each R* message to be the corresponding T*
// message plus one.
const TLERROR: u8 = 6;
const RLERROR: u8 = TLERROR + 1;
const TSTATFS: u8 = 8;
const RSTATFS: u8 = TSTATFS + 1;
const TLOPEN: u8 = 12;
const RLOPEN: u8 = TLOPEN + 1;
const TLCREATE: u8 = 14;
const RLCREATE: u8 = TLCREATE + 1;
const TSYMLINK: u8 = 16;
const RSYMLINK: u8 = TSYMLINK + 1;
const TMKNOD: u8 = 18;
const RMKNOD: u8 = TMKNOD + 1;
const TRENAME: u8 = 20;
const RRENAME: u8 = TRENAME + 1;
const TREADLINK: u8 = 22;
const RREADLINK: u8 = TREADLINK + 1;
const TGETATTR: u8 = 24;
const RGETATTR: u8 = TGETATTR + 1;
const TSETATTR: u8 = 26;
const RSETATTR: u8 = TSETATTR + 1;
const TXATTRWALK: u8 = 30;
const RXATTRWALK: u8 = TXATTRWALK + 1;
const TXATTRCREATE: u8 = 32;
const RXATTRCREATE: u8 = TXATTRCREATE + 1;
const TREADDIR: u8 = 40;
const RREADDIR: u8 = TREADDIR + 1;
const TFSYNC: u8 = 50;
const RFSYNC: u8 = TFSYNC + 1;
const TLOCK: u8 = 52;
const RLOCK: u8 = TLOCK + 1;
const TGETLOCK: u8 = 54;
const RGETLOCK: u8 = TGETLOCK + 1;
const TLINK: u8 = 70;
const RLINK: u8 = TLINK + 1;
const TMKDIR: u8 = 72;
const RMKDIR: u8 = TMKDIR + 1;
const TRENAMEAT: u8 = 74;
const RRENAMEAT: u8 = TRENAMEAT + 1;
const TUNLINKAT: u8 = 76;
const RUNLINKAT: u8 = TUNLINKAT + 1;
const TVERSION: u8 = 100;
const RVERSION: u8 = TVERSION + 1;
const TAUTH: u8 = 102;
const RAUTH: u8 = TAUTH + 1;
const TATTACH: u8 = 104;
const RATTACH: u8 = TATTACH + 1;
const _TERROR: u8 = 106;
const _RERROR: u8 = _TERROR + 1;
const TFLUSH: u8 = 108;
const RFLUSH: u8 = TFLUSH + 1;
const TWALK: u8 = 110;
const RWALK: u8 = TWALK + 1;
const _TOPEN: u8 = 112;
const _ROPEN: u8 = _TOPEN + 1;
const _TCREATE: u8 = 114;
const _RCREATE: u8 = _TCREATE + 1;
const TREAD: u8 = 116;
const RREAD: u8 = TREAD + 1;
const TWRITE: u8 = 118;
const RWRITE: u8 = TWRITE + 1;
const TCLUNK: u8 = 120;
const RCLUNK: u8 = TCLUNK + 1;
const TREMOVE: u8 = 122;
const RREMOVE: u8 = TREMOVE + 1;
const _TSTAT: u8 = 124;
const _RSTAT: u8 = _TSTAT + 1;
const _TWSTAT: u8 = 126;
const _RWSTAT: u8 = _TWSTAT + 1;

/// A message sent from a 9P client to a 9P server.
#[derive(Debug)]
pub enum Tmessage {
    Version(Tversion),
    Flush(Tflush),
    Walk(Twalk),
    Read(Tread),
    Write(Twrite),
    Clunk(Tclunk),
    Remove(Tremove),
    Attach(Tattach),
    Auth(Tauth),
    Statfs(Tstatfs),
    Lopen(Tlopen),
    Lcreate(Tlcreate),
    Symlink(Tsymlink),
    Mknod(Tmknod),
    Rename(Trename),
    Readlink(Treadlink),
    GetAttr(Tgetattr),
    SetAttr(Tsetattr),
    XattrWalk(Txattrwalk),
    XattrCreate(Txattrcreate),
    Readdir(Treaddir),
    Fsync(Tfsync),
    Lock(Tlock),
    GetLock(Tgetlock),
    Link(Tlink),
    Mkdir(Tmkdir),
    RenameAt(Trenameat),
    UnlinkAt(Tunlinkat),
}

#[derive(Debug)]
pub struct Tframe {
    pub tag: u16,
    pub msg: io::Result<Tmessage>,
}

impl WireFormat for Tframe {
    fn byte_size(&self) -> u32 {
        let msg = self
            .msg
            .as_ref()
            .expect("tried to encode Tframe with invalid msg");
        let msg_size = match msg {
            Tmessage::Version(ref version) => version.byte_size(),
            Tmessage::Flush(ref flush) => flush.byte_size(),
            Tmessage::Walk(ref walk) => walk.byte_size(),
            Tmessage::Read(ref read) => read.byte_size(),
            Tmessage::Write(ref write) => write.byte_size(),
            Tmessage::Clunk(ref clunk) => clunk.byte_size(),
            Tmessage::Remove(ref remove) => remove.byte_size(),
            Tmessage::Attach(ref attach) => attach.byte_size(),
            Tmessage::Auth(ref auth) => auth.byte_size(),
            Tmessage::Statfs(ref statfs) => statfs.byte_size(),
            Tmessage::Lopen(ref lopen) => lopen.byte_size(),
            Tmessage::Lcreate(ref lcreate) => lcreate.byte_size(),
            Tmessage::Symlink(ref symlink) => symlink.byte_size(),
            Tmessage::Mknod(ref mknod) => mknod.byte_size(),
            Tmessage::Rename(ref rename) => rename.byte_size(),
            Tmessage::Readlink(ref readlink) => readlink.byte_size(),
            Tmessage::GetAttr(ref getattr) => getattr.byte_size(),
            Tmessage::SetAttr(ref setattr) => setattr.byte_size(),
            Tmessage::XattrWalk(ref xattrwalk) => xattrwalk.byte_size(),
            Tmessage::XattrCreate(ref xattrcreate) => xattrcreate.byte_size(),
            Tmessage::Readdir(ref readdir) => readdir.byte_size(),
            Tmessage::Fsync(ref fsync) => fsync.byte_size(),
            Tmessage::Lock(ref lock) => lock.byte_size(),
            Tmessage::GetLock(ref getlock) => getlock.byte_size(),
            Tmessage::Link(ref link) => link.byte_size(),
            Tmessage::Mkdir(ref mkdir) => mkdir.byte_size(),
            Tmessage::RenameAt(ref renameat) => renameat.byte_size(),
            Tmessage::UnlinkAt(ref unlinkat) => unlinkat.byte_size(),
        };

        // size + type + tag + message size
        (mem::size_of::<u32>() + mem::size_of::<u8>() + mem::size_of::<u16>()) as u32 + msg_size
    }

    fn encode<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        let msg = match self.msg.as_ref() {
            Ok(msg) => msg,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "tried to encode Tframe with invalid msg",
                ))
            }
        };

        self.byte_size().encode(writer)?;

        let ty = match msg {
            Tmessage::Version(_) => TVERSION,
            Tmessage::Flush(_) => TFLUSH,
            Tmessage::Walk(_) => TWALK,
            Tmessage::Read(_) => TREAD,
            Tmessage::Write(_) => TWRITE,
            Tmessage::Clunk(_) => TCLUNK,
            Tmessage::Remove(_) => TREMOVE,
            Tmessage::Attach(_) => TATTACH,
            Tmessage::Auth(_) => TAUTH,
            Tmessage::Statfs(_) => TSTATFS,
            Tmessage::Lopen(_) => TLOPEN,
            Tmessage::Lcreate(_) => TLCREATE,
            Tmessage::Symlink(_) => TSYMLINK,
            Tmessage::Mknod(_) => TMKNOD,
            Tmessage::Rename(_) => TRENAME,
            Tmessage::Readlink(_) => TREADLINK,
            Tmessage::GetAttr(_) => TGETATTR,
            Tmessage::SetAttr(_) => TSETATTR,
            Tmessage::XattrWalk(_) => TXATTRWALK,
            Tmessage::XattrCreate(_) => TXATTRCREATE,
            Tmessage::Readdir(_) => TREADDIR,
            Tmessage::Fsync(_) => TFSYNC,
            Tmessage::Lock(_) => TLOCK,
            Tmessage::GetLock(_) => TGETLOCK,
            Tmessage::Link(_) => TLINK,
            Tmessage::Mkdir(_) => TMKDIR,
            Tmessage::RenameAt(_) => TRENAMEAT,
            Tmessage::UnlinkAt(_) => TUNLINKAT,
        };

        ty.encode(writer)?;
        self.tag.encode(writer)?;

        match msg {
            Tmessage::Version(ref version) => version.encode(writer),
            Tmessage::Flush(ref flush) => flush.encode(writer),
            Tmessage::Walk(ref walk) => walk.encode(writer),
            Tmessage::Read(ref read) => read.encode(writer),
            Tmessage::Write(ref write) => write.encode(writer),
            Tmessage::Clunk(ref clunk) => clunk.encode(writer),
            Tmessage::Remove(ref remove) => remove.encode(writer),
            Tmessage::Attach(ref attach) => attach.encode(writer),
            Tmessage::Auth(ref auth) => auth.encode(writer),
            Tmessage::Statfs(ref statfs) => statfs.encode(writer),
            Tmessage::Lopen(ref lopen) => lopen.encode(writer),
            Tmessage::Lcreate(ref lcreate) => lcreate.encode(writer),
            Tmessage::Symlink(ref symlink) => symlink.encode(writer),
            Tmessage::Mknod(ref mknod) => mknod.encode(writer),
            Tmessage::Rename(ref rename) => rename.encode(writer),
            Tmessage::Readlink(ref readlink) => readlink.encode(writer),
            Tmessage::GetAttr(ref getattr) => getattr.encode(writer),
            Tmessage::SetAttr(ref setattr) => setattr.encode(writer),
            Tmessage::XattrWalk(ref xattrwalk) => xattrwalk.encode(writer),
            Tmessage::XattrCreate(ref xattrcreate) => xattrcreate.encode(writer),
            Tmessage::Readdir(ref readdir) => readdir.encode(writer),
            Tmessage::Fsync(ref fsync) => fsync.encode(writer),
            Tmessage::Lock(ref lock) => lock.encode(writer),
            Tmessage::GetLock(ref getlock) => getlock.encode(writer),
            Tmessage::Link(ref link) => link.encode(writer),
            Tmessage::Mkdir(ref mkdir) => mkdir.encode(writer),
            Tmessage::RenameAt(ref renameat) => renameat.encode(writer),
            Tmessage::UnlinkAt(ref unlinkat) => unlinkat.encode(writer),
        }
    }

    fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let byte_size: u32 = WireFormat::decode(reader)?;

        // byte_size includes the size of byte_size so remove that from the
        // expected length of the message.  Also make sure that byte_size is at least
        // that long to begin with.
        if byte_size < mem::size_of::<u32>() as u32 {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!("byte_size(= {}) is less than 4 bytes", byte_size),
            ));
        }

        let reader = &mut reader.take((byte_size - mem::size_of::<u32>() as u32) as u64);

        let mut ty = [0u8];
        reader.read_exact(&mut ty)?;

        let tag: u16 = WireFormat::decode(reader)?;
        let msg = Self::decode_message(reader, ty[0]);

        Ok(Tframe { tag, msg })
    }
}

impl Tframe {
    fn decode_message<R: Read>(reader: &mut R, ty: u8) -> io::Result<Tmessage> {
        match ty {
            TVERSION => Ok(Tmessage::Version(WireFormat::decode(reader)?)),
            TFLUSH => Ok(Tmessage::Flush(WireFormat::decode(reader)?)),
            TWALK => Ok(Tmessage::Walk(WireFormat::decode(reader)?)),
            TREAD => Ok(Tmessage::Read(WireFormat::decode(reader)?)),
            TWRITE => Ok(Tmessage::Write(WireFormat::decode(reader)?)),
            TCLUNK => Ok(Tmessage::Clunk(WireFormat::decode(reader)?)),
            TREMOVE => Ok(Tmessage::Remove(WireFormat::decode(reader)?)),
            TATTACH => Ok(Tmessage::Attach(WireFormat::decode(reader)?)),
            TAUTH => Ok(Tmessage::Auth(WireFormat::decode(reader)?)),
            TSTATFS => Ok(Tmessage::Statfs(WireFormat::decode(reader)?)),
            TLOPEN => Ok(Tmessage::Lopen(WireFormat::decode(reader)?)),
            TLCREATE => Ok(Tmessage::Lcreate(WireFormat::decode(reader)?)),
            TSYMLINK => Ok(Tmessage::Symlink(WireFormat::decode(reader)?)),
            TMKNOD => Ok(Tmessage::Mknod(WireFormat::decode(reader)?)),
            TRENAME => Ok(Tmessage::Rename(WireFormat::decode(reader)?)),
            TREADLINK => Ok(Tmessage::Readlink(WireFormat::decode(reader)?)),
            TGETATTR => Ok(Tmessage::GetAttr(WireFormat::decode(reader)?)),
            TSETATTR => Ok(Tmessage::SetAttr(WireFormat::decode(reader)?)),
            TXATTRWALK => Ok(Tmessage::XattrWalk(WireFormat::decode(reader)?)),
            TXATTRCREATE => Ok(Tmessage::XattrCreate(WireFormat::decode(reader)?)),
            TREADDIR => Ok(Tmessage::Readdir(WireFormat::decode(reader)?)),
            TFSYNC => Ok(Tmessage::Fsync(WireFormat::decode(reader)?)),
            TLOCK => Ok(Tmessage::Lock(WireFormat::decode(reader)?)),
            TGETLOCK => Ok(Tmessage::GetLock(WireFormat::decode(reader)?)),
            TLINK => Ok(Tmessage::Link(WireFormat::decode(reader)?)),
            TMKDIR => Ok(Tmessage::Mkdir(WireFormat::decode(reader)?)),
            TRENAMEAT => Ok(Tmessage::RenameAt(WireFormat::decode(reader)?)),
            TUNLINKAT => Ok(Tmessage::UnlinkAt(WireFormat::decode(reader)?)),
            err => Err(io::Error::new(
                ErrorKind::InvalidData,
                format!("unknown message type {}", err),
            )),
        }
    }
}

#[derive(Debug, P9WireFormat)]
pub struct Tversion {
    pub msize: u32,
    pub version: String,
}

#[derive(Debug, P9WireFormat)]
pub struct Tflush {
    pub oldtag: u16,
}

#[derive(Debug, P9WireFormat)]
pub struct Twalk {
    pub fid: u32,
    pub newfid: u32,
    pub wnames: Vec<String>,
}

#[derive(Debug, P9WireFormat)]
pub struct Tread {
    pub fid: u32,
    pub offset: u64,
    pub count: u32,
}

#[derive(Debug, P9WireFormat)]
pub struct Twrite {
    pub fid: u32,
    pub offset: u64,
    pub data: Data,
}

#[derive(Debug, P9WireFormat)]
pub struct Tclunk {
    pub fid: u32,
}

#[derive(Debug, P9WireFormat)]
pub struct Tremove {
    pub fid: u32,
}

#[derive(Debug, P9WireFormat)]
pub struct Tauth {
    pub afid: u32,
    pub uname: String,
    pub aname: String,
    pub n_uname: u32,
}

#[derive(Debug, P9WireFormat)]
pub struct Tattach {
    pub fid: u32,
    pub afid: u32,
    pub uname: String,
    pub aname: String,
    pub n_uname: u32,
}

#[derive(Debug, P9WireFormat)]
pub struct Tstatfs {
    pub fid: u32,
}

#[derive(Debug, P9WireFormat)]
pub struct Tlopen {
    pub fid: u32,
    pub flags: u32,
}

#[derive(Debug, P9WireFormat)]
pub struct Tlcreate {
    pub fid: u32,
    pub name: String,
    pub flags: u32,
    pub mode: u32,
    pub gid: u32,
}

#[derive(Debug, P9WireFormat)]
pub struct Tsymlink {
    pub fid: u32,
    pub name: String,
    pub symtgt: String,
    pub gid: u32,
}

#[derive(Debug, P9WireFormat)]
pub struct Tmknod {
    pub dfid: u32,
    pub name: String,
    pub mode: u32,
    pub major: u32,
    pub minor: u32,
    pub gid: u32,
}

#[derive(Debug, P9WireFormat)]
pub struct Trename {
    pub fid: u32,
    pub dfid: u32,
    pub name: String,
}

#[derive(Debug, P9WireFormat)]
pub struct Treadlink {
    pub fid: u32,
}

#[derive(Debug, P9WireFormat)]
pub struct Tgetattr {
    pub fid: u32,
    pub request_mask: u64,
}

#[derive(Debug, P9WireFormat)]
pub struct Tsetattr {
    pub fid: u32,
    pub valid: u32,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub atime_sec: u64,
    pub atime_nsec: u64,
    pub mtime_sec: u64,
    pub mtime_nsec: u64,
}

#[derive(Debug, P9WireFormat)]
pub struct Txattrwalk {
    pub fid: u32,
    pub newfid: u32,
    pub name: String,
}

#[derive(Debug, P9WireFormat)]
pub struct Txattrcreate {
    pub fid: u32,
    pub name: String,
    pub attr_size: u64,
    pub flags: u32,
}

#[derive(Debug, P9WireFormat)]
pub struct Treaddir {
    pub fid: u32,
    pub offset: u64,
    pub count: u32,
}

#[derive(Debug, P9WireFormat)]
pub struct Tfsync {
    pub fid: u32,
    pub datasync: u32,
}

#[derive(Debug, P9WireFormat)]
pub struct Tlock {
    pub fid: u32,
    pub type_: u8,
    pub flags: u32,
    pub start: u64,
    pub length: u64,
    pub proc_id: u32,
    pub client_id: String,
}

#[derive(Debug, P9WireFormat)]
pub struct Tgetlock {
    pub fid: u32,
    pub type_: u8,
    pub start: u64,
    pub length: u64,
    pub proc_id: u32,
    pub client_id: String,
}

#[derive(Debug, P9WireFormat)]
pub struct Tlink {
    pub dfid: u32,
    pub fid: u32,
    pub name: String,
}

#[derive(Debug, P9WireFormat)]
pub struct Tmkdir {
    pub dfid: u32,
    pub name: String,
    pub mode: u32,
    pub gid: u32,
}

#[derive(Debug, P9WireFormat)]
pub struct Trenameat {
    pub olddirfid: u32,
    pub oldname: String,
    pub newdirfid: u32,
    pub newname: String,
}

#[derive(Debug, P9WireFormat)]
pub struct Tunlinkat {
    pub dirfd: u32,
    pub name: String,
    pub flags: u32,
}

/// A message sent from a 9P server to a 9P client in response to a request from
/// that client.  Encapsulates a full frame.
#[derive(Debug)]
pub enum Rmessage {
    Version(Rversion),
    Flush,
    Walk(Rwalk),
    Read(Rread),
    Write(Rwrite),
    Clunk,
    Remove,
    Attach(Rattach),
    Auth(Rauth),
    Statfs(Rstatfs),
    Lopen(Rlopen),
    Lcreate(Rlcreate),
    Symlink(Rsymlink),
    Mknod(Rmknod),
    Rename,
    Readlink(Rreadlink),
    GetAttr(Rgetattr),
    SetAttr,
    XattrWalk(Rxattrwalk),
    XattrCreate,
    Readdir(Rreaddir),
    Fsync,
    Lock(Rlock),
    GetLock(Rgetlock),
    Link,
    Mkdir(Rmkdir),
    RenameAt,
    UnlinkAt,
    Lerror(Rlerror),
}

#[derive(Debug)]
pub struct Rframe {
    pub tag: u16,
    pub msg: Rmessage,
}

impl WireFormat for Rframe {
    fn byte_size(&self) -> u32 {
        let msg_size = match self.msg {
            Rmessage::Version(ref version) => version.byte_size(),
            Rmessage::Flush => 0,
            Rmessage::Walk(ref walk) => walk.byte_size(),
            Rmessage::Read(ref read) => read.byte_size(),
            Rmessage::Write(ref write) => write.byte_size(),
            Rmessage::Clunk => 0,
            Rmessage::Remove => 0,
            Rmessage::Attach(ref attach) => attach.byte_size(),
            Rmessage::Auth(ref auth) => auth.byte_size(),
            Rmessage::Statfs(ref statfs) => statfs.byte_size(),
            Rmessage::Lopen(ref lopen) => lopen.byte_size(),
            Rmessage::Lcreate(ref lcreate) => lcreate.byte_size(),
            Rmessage::Symlink(ref symlink) => symlink.byte_size(),
            Rmessage::Mknod(ref mknod) => mknod.byte_size(),
            Rmessage::Rename => 0,
            Rmessage::Readlink(ref readlink) => readlink.byte_size(),
            Rmessage::GetAttr(ref getattr) => getattr.byte_size(),
            Rmessage::SetAttr => 0,
            Rmessage::XattrWalk(ref xattrwalk) => xattrwalk.byte_size(),
            Rmessage::XattrCreate => 0,
            Rmessage::Readdir(ref readdir) => readdir.byte_size(),
            Rmessage::Fsync => 0,
            Rmessage::Lock(ref lock) => lock.byte_size(),
            Rmessage::GetLock(ref getlock) => getlock.byte_size(),
            Rmessage::Link => 0,
            Rmessage::Mkdir(ref mkdir) => mkdir.byte_size(),
            Rmessage::RenameAt => 0,
            Rmessage::UnlinkAt => 0,
            Rmessage::Lerror(ref lerror) => lerror.byte_size(),
        };

        // size + type + tag + message size
        (mem::size_of::<u32>() + mem::size_of::<u8>() + mem::size_of::<u16>()) as u32 + msg_size
    }

    fn encode<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        self.byte_size().encode(writer)?;

        let ty = match self.msg {
            Rmessage::Version(_) => RVERSION,
            Rmessage::Flush => RFLUSH,
            Rmessage::Walk(_) => RWALK,
            Rmessage::Read(_) => RREAD,
            Rmessage::Write(_) => RWRITE,
            Rmessage::Clunk => RCLUNK,
            Rmessage::Remove => RREMOVE,
            Rmessage::Attach(_) => RATTACH,
            Rmessage::Auth(_) => RAUTH,
            Rmessage::Statfs(_) => RSTATFS,
            Rmessage::Lopen(_) => RLOPEN,
            Rmessage::Lcreate(_) => RLCREATE,
            Rmessage::Symlink(_) => RSYMLINK,
            Rmessage::Mknod(_) => RMKNOD,
            Rmessage::Rename => RRENAME,
            Rmessage::Readlink(_) => RREADLINK,
            Rmessage::GetAttr(_) => RGETATTR,
            Rmessage::SetAttr => RSETATTR,
            Rmessage::XattrWalk(_) => RXATTRWALK,
            Rmessage::XattrCreate => RXATTRCREATE,
            Rmessage::Readdir(_) => RREADDIR,
            Rmessage::Fsync => RFSYNC,
            Rmessage::Lock(_) => RLOCK,
            Rmessage::GetLock(_) => RGETLOCK,
            Rmessage::Link => RLINK,
            Rmessage::Mkdir(_) => RMKDIR,
            Rmessage::RenameAt => RRENAMEAT,
            Rmessage::UnlinkAt => RUNLINKAT,
            Rmessage::Lerror(_) => RLERROR,
        };

        ty.encode(writer)?;
        self.tag.encode(writer)?;

        match self.msg {
            Rmessage::Version(ref version) => version.encode(writer),
            Rmessage::Flush => Ok(()),
            Rmessage::Walk(ref walk) => walk.encode(writer),
            Rmessage::Read(ref read) => read.encode(writer),
            Rmessage::Write(ref write) => write.encode(writer),
            Rmessage::Clunk => Ok(()),
            Rmessage::Remove => Ok(()),
            Rmessage::Attach(ref attach) => attach.encode(writer),
            Rmessage::Auth(ref auth) => auth.encode(writer),
            Rmessage::Statfs(ref statfs) => statfs.encode(writer),
            Rmessage::Lopen(ref lopen) => lopen.encode(writer),
            Rmessage::Lcreate(ref lcreate) => lcreate.encode(writer),
            Rmessage::Symlink(ref symlink) => symlink.encode(writer),
            Rmessage::Mknod(ref mknod) => mknod.encode(writer),
            Rmessage::Rename => Ok(()),
            Rmessage::Readlink(ref readlink) => readlink.encode(writer),
            Rmessage::GetAttr(ref getattr) => getattr.encode(writer),
            Rmessage::SetAttr => Ok(()),
            Rmessage::XattrWalk(ref xattrwalk) => xattrwalk.encode(writer),
            Rmessage::XattrCreate => Ok(()),
            Rmessage::Readdir(ref readdir) => readdir.encode(writer),
            Rmessage::Fsync => Ok(()),
            Rmessage::Lock(ref lock) => lock.encode(writer),
            Rmessage::GetLock(ref getlock) => getlock.encode(writer),
            Rmessage::Link => Ok(()),
            Rmessage::Mkdir(ref mkdir) => mkdir.encode(writer),
            Rmessage::RenameAt => Ok(()),
            Rmessage::UnlinkAt => Ok(()),
            Rmessage::Lerror(ref lerror) => lerror.encode(writer),
        }
    }

    fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let byte_size: u32 = WireFormat::decode(reader)?;

        // byte_size includes the size of byte_size so remove that from the
        // expected length of the message.
        let reader = &mut reader.take((byte_size - mem::size_of::<u32>() as u32) as u64);

        let mut ty = [0u8];
        reader.read_exact(&mut ty)?;

        let tag: u16 = WireFormat::decode(reader)?;

        let msg = match ty[0] {
            RVERSION => Ok(Rmessage::Version(WireFormat::decode(reader)?)),
            RFLUSH => Ok(Rmessage::Flush),
            RWALK => Ok(Rmessage::Walk(WireFormat::decode(reader)?)),
            RREAD => Ok(Rmessage::Read(WireFormat::decode(reader)?)),
            RWRITE => Ok(Rmessage::Write(WireFormat::decode(reader)?)),
            RCLUNK => Ok(Rmessage::Clunk),
            RREMOVE => Ok(Rmessage::Remove),
            RATTACH => Ok(Rmessage::Attach(WireFormat::decode(reader)?)),
            RAUTH => Ok(Rmessage::Auth(WireFormat::decode(reader)?)),
            RSTATFS => Ok(Rmessage::Statfs(WireFormat::decode(reader)?)),
            RLOPEN => Ok(Rmessage::Lopen(WireFormat::decode(reader)?)),
            RLCREATE => Ok(Rmessage::Lcreate(WireFormat::decode(reader)?)),
            RSYMLINK => Ok(Rmessage::Symlink(WireFormat::decode(reader)?)),
            RMKNOD => Ok(Rmessage::Mknod(WireFormat::decode(reader)?)),
            RRENAME => Ok(Rmessage::Rename),
            RREADLINK => Ok(Rmessage::Readlink(WireFormat::decode(reader)?)),
            RGETATTR => Ok(Rmessage::GetAttr(WireFormat::decode(reader)?)),
            RSETATTR => Ok(Rmessage::SetAttr),
            RXATTRWALK => Ok(Rmessage::XattrWalk(WireFormat::decode(reader)?)),
            RXATTRCREATE => Ok(Rmessage::XattrCreate),
            RREADDIR => Ok(Rmessage::Readdir(WireFormat::decode(reader)?)),
            RFSYNC => Ok(Rmessage::Fsync),
            RLOCK => Ok(Rmessage::Lock(WireFormat::decode(reader)?)),
            RGETLOCK => Ok(Rmessage::GetLock(WireFormat::decode(reader)?)),
            RLINK => Ok(Rmessage::Link),
            RMKDIR => Ok(Rmessage::Mkdir(WireFormat::decode(reader)?)),
            RRENAMEAT => Ok(Rmessage::RenameAt),
            RUNLINKAT => Ok(Rmessage::UnlinkAt),
            RLERROR => Ok(Rmessage::Lerror(WireFormat::decode(reader)?)),
            err => Err(io::Error::new(
                ErrorKind::InvalidData,
                format!("unknown message type {}", err),
            )),
        }?;

        Ok(Rframe { tag, msg })
    }
}

#[derive(Debug, Copy, Clone, P9WireFormat)]
pub struct Qid {
    pub ty: u8,
    pub version: u32,
    pub path: u64,
}

#[derive(Debug, P9WireFormat)]
pub struct Dirent {
    pub qid: Qid,
    pub offset: u64,
    pub ty: u8,
    pub name: String,
}

#[derive(Debug, P9WireFormat)]
pub struct Rversion {
    pub msize: u32,
    pub version: String,
}

#[derive(Debug, P9WireFormat)]
pub struct Rwalk {
    pub wqids: Vec<Qid>,
}

#[derive(Debug, P9WireFormat)]
pub struct Rread {
    pub data: Data,
}

#[derive(Debug, P9WireFormat)]
pub struct Rwrite {
    pub count: u32,
}

#[derive(Debug, P9WireFormat)]
pub struct Rauth {
    pub aqid: Qid,
}

#[derive(Debug, P9WireFormat)]
pub struct Rattach {
    pub qid: Qid,
}

#[derive(Debug, P9WireFormat)]
pub struct Rlerror {
    pub ecode: u32,
}

#[derive(Debug, P9WireFormat)]
pub struct Rstatfs {
    pub ty: u32,
    pub bsize: u32,
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub fsid: u64,
    pub namelen: u32,
}

#[derive(Debug, P9WireFormat)]
pub struct Rlopen {
    pub qid: Qid,
    pub iounit: u32,
}

#[derive(Debug, P9WireFormat)]
pub struct Rlcreate {
    pub qid: Qid,
    pub iounit: u32,
}

#[derive(Debug, P9WireFormat)]
pub struct Rsymlink {
    pub qid: Qid,
}

#[derive(Debug, P9WireFormat)]
pub struct Rmknod {
    pub qid: Qid,
}

#[derive(Debug, P9WireFormat)]
pub struct Rreadlink {
    pub target: String,
}

#[derive(Debug, P9WireFormat)]
pub struct Rgetattr {
    pub valid: u64,
    pub qid: Qid,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u64,
    pub rdev: u64,
    pub size: u64,
    pub blksize: u64,
    pub blocks: u64,
    pub atime_sec: u64,
    pub atime_nsec: u64,
    pub mtime_sec: u64,
    pub mtime_nsec: u64,
    pub ctime_sec: u64,
    pub ctime_nsec: u64,
    pub btime_sec: u64,
    pub btime_nsec: u64,
    pub gen: u64,
    pub data_version: u64,
}

#[derive(Debug, P9WireFormat)]
pub struct Rxattrwalk {
    pub size: u64,
}

#[derive(Debug, P9WireFormat)]
pub struct Rreaddir {
    pub data: Data,
}

#[derive(Debug, P9WireFormat)]
pub struct Rlock {
    pub status: u8,
}

#[derive(Debug, P9WireFormat)]
pub struct Rgetlock {
    pub type_: u8,
    pub start: u64,
    pub length: u64,
    pub proc_id: u32,
    pub client_id: String,
}

#[derive(Debug, P9WireFormat)]
pub struct Rmkdir {
    pub qid: Qid,
}
