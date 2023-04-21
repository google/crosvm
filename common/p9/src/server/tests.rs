// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::borrow::Cow;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::env;
use std::ffi::CString;
use std::ffi::OsString;
use std::fs;
use std::fs::File;
use std::io;
use std::io::Cursor;
use std::mem;
use std::ops::Deref;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::symlink;
use std::os::unix::fs::MetadataExt;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;
use std::u32;

use super::*;

// Used to indicate that there is no fid associated with this message.
const P9_NOFID: u32 = u32::MAX;

// The fid associated with the root directory of the server.
const ROOT_FID: u32 = 1;

// The pid of the server process, cannot be 1 since that's the kernel init
const SERVER_PID: u32 = 5;

// How big we want the default buffer to be when running tests.
const DEFAULT_BUFFER_SIZE: u32 = 4096;

// How big we want to make randomly generated files
const LOCAL_FILE_LEN: u64 = 200;

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

// Automatically deletes the path it contains when it goes out of scope.
struct ScopedPath<P: AsRef<Path>>(P);

impl<P: AsRef<Path>> AsRef<Path> for ScopedPath<P> {
    fn as_ref(&self) -> &Path {
        self.0.as_ref()
    }
}

impl<P: AsRef<Path>> Deref for ScopedPath<P> {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl<P: AsRef<Path>> Drop for ScopedPath<P> {
    fn drop(&mut self) {
        if let Err(e) = fs::remove_dir_all(&**self) {
            println!("Failed to remove {}: {}", self.display(), e);
        }
    }
}

enum DirEntry<'a> {
    File {
        name: &'a str,
        content: &'a [u8],
    },
    Directory {
        name: &'a str,
        entries: &'a [DirEntry<'a>],
    },
    Symlink {
        name: &'a str,
        target: &'a str,
    },
}

impl<'a> DirEntry<'a> {
    // Creates `self` in the path given by `dir`.
    // TODO(b/228627457): clippy is warning about the `Cow` below, but it is necessary
    #[allow(clippy::ptr_arg)]
    fn create(&self, dir: &mut Cow<Path>) {
        match *self {
            DirEntry::File { name, content } => {
                let mut f = File::create(dir.join(name)).expect("failed to create file");
                f.write_all(content).expect("failed to write file content");
            }
            DirEntry::Directory { name, entries } => {
                dir.to_mut().push(name);

                fs::create_dir_all(&**dir).expect("failed to create directory");
                for e in entries {
                    e.create(dir);
                }

                assert!(dir.to_mut().pop());
            }
            DirEntry::Symlink { name, target } => {
                symlink(target, dir.join(name)).expect("failed to create symlink");
            }
        }
    }
}

// Creates a file with `name` in `dir` and fills it with random
// content.
fn create_local_file<P: AsRef<Path>>(dir: P, name: &str) -> Vec<u8> {
    let mut content = Vec::new();
    File::open("/dev/urandom")
        .and_then(|f| f.take(LOCAL_FILE_LEN).read_to_end(&mut content))
        .expect("failed to read from /dev/urandom");

    let f = DirEntry::File {
        name,
        content: &content,
    };
    f.create(&mut Cow::from(dir.as_ref()));

    content
}

// Create a symlink named `name` that links to `target`.
fn create_local_symlink<P: AsRef<Path>>(dir: P, name: &str, target: &str) {
    let f = DirEntry::Symlink { name, target };
    f.create(&mut Cow::from(dir.as_ref()));
}

fn check_qid(qid: &Qid, md: &fs::Metadata) {
    let ty = if md.is_dir() {
        P9_QTDIR
    } else if md.is_file() {
        P9_QTFILE
    } else if md.file_type().is_symlink() {
        P9_QTSYMLINK
    } else {
        panic!("unknown file type: {:?}", md.file_type());
    };
    assert_eq!(qid.ty, ty);
    assert_eq!(qid.version, md.mtime() as u32);
    assert_eq!(qid.path, md.ino());
}

fn check_attr(server: &mut Server, fid: u32, md: &fs::Metadata) {
    let tgetattr = Tgetattr {
        fid,
        request_mask: P9_GETATTR_BASIC,
    };

    let rgetattr = server.get_attr(&tgetattr).expect("failed to call get_attr");

    let ty = if md.is_dir() {
        P9_QTDIR
    } else if md.is_file() {
        P9_QTFILE
    } else if md.file_type().is_symlink() {
        P9_QTSYMLINK
    } else {
        panic!("unknown file type: {:?}", md.file_type());
    };
    assert_eq!(rgetattr.valid, P9_GETATTR_BASIC);
    assert_eq!(rgetattr.qid.ty, ty);
    assert_eq!(rgetattr.qid.version, md.mtime() as u32);
    assert_eq!(rgetattr.qid.path, md.ino());
    assert_eq!(rgetattr.mode, md.mode());
    assert_eq!(rgetattr.uid, md.uid());
    assert_eq!(rgetattr.gid, md.gid());
    assert_eq!(rgetattr.nlink, md.nlink());
    assert_eq!(rgetattr.rdev, md.rdev());
    assert_eq!(rgetattr.size, md.size());
    assert_eq!(rgetattr.atime_sec, md.atime() as u64);
    assert_eq!(rgetattr.atime_nsec, md.atime_nsec() as u64);
    assert_eq!(rgetattr.mtime_sec, md.mtime() as u64);
    assert_eq!(rgetattr.mtime_nsec, md.mtime_nsec() as u64);
    assert_eq!(rgetattr.ctime_sec, md.ctime() as u64);
    assert_eq!(rgetattr.ctime_nsec, md.ctime_nsec() as u64);
    assert_eq!(rgetattr.btime_sec, 0);
    assert_eq!(rgetattr.btime_nsec, 0);
    assert_eq!(rgetattr.gen, 0);
    assert_eq!(rgetattr.data_version, 0);
}

fn check_content(server: &mut Server, content: &[u8], fid: u32) {
    for offset in 0..content.len() {
        let tread = Tread {
            fid,
            offset: offset as u64,
            count: DEFAULT_BUFFER_SIZE,
        };

        let rread = server.read(&tread).expect("failed to read file");
        assert_eq!(content[offset..], rread.data[..]);
    }
}

fn walk<P: Into<PathBuf>>(
    server: &mut Server,
    start: P,
    fid: u32,
    newfid: u32,
    names: Vec<String>,
) {
    let mut mds = Vec::with_capacity(names.len());
    let mut buf = start.into();
    for name in &names {
        buf.push(name);
        mds.push(
            buf.symlink_metadata()
                .expect("failed to get metadata for path"),
        );
    }

    let twalk = Twalk {
        fid,
        newfid,
        wnames: names,
    };

    let rwalk = server.walk(twalk).expect("failed to walk directoy");
    assert_eq!(mds.len(), rwalk.wqids.len());
    for (md, qid) in mds.iter().zip(rwalk.wqids.iter()) {
        check_qid(qid, md);
    }
}

fn open<P: Into<PathBuf>>(
    server: &mut Server,
    dir: P,
    dir_fid: u32,
    name: &str,
    fid: u32,
    flags: u32,
) -> io::Result<Rlopen> {
    let wnames = if name.is_empty() {
        vec![]
    } else {
        vec![String::from(name)]
    };
    walk(server, dir, dir_fid, fid, wnames);

    let tlopen = Tlopen { fid, flags };

    server.lopen(&tlopen)
}

fn write<P: AsRef<Path>>(server: &mut Server, dir: P, name: &str, fid: u32, flags: u32) {
    let file_path = dir.as_ref().join(name);
    let file_len = if file_path.exists() {
        fs::symlink_metadata(&file_path)
            .expect("unable to get metadata for file")
            .len() as usize
    } else {
        0usize
    };
    let mut new_content = Vec::new();
    File::open("/dev/urandom")
        .and_then(|f| f.take(200).read_to_end(&mut new_content))
        .expect("failed to read from /dev/urandom");

    let twrite = Twrite {
        fid,
        offset: 0,
        data: Data(new_content),
    };

    let rwrite = server.write(&twrite).expect("failed to write file");
    assert_eq!(rwrite.count, twrite.data.len() as u32);

    let tfsync = Tfsync { fid, datasync: 0 };
    server.fsync(&tfsync).expect("failed to sync file contents");

    let actual_content = fs::read(file_path).expect("failed to read back content from file");

    // If the file was opened append-only, then the content should have been
    // written to the end even though the offset was 0.
    let idx = if flags & P9_APPEND == 0 { 0 } else { file_len };
    assert_eq!(actual_content[idx..], twrite.data[..]);
}

fn create<P: Into<PathBuf>>(
    server: &mut Server,
    dir: P,
    dir_fid: u32,
    fid: u32,
    name: &str,
    flags: u32,
    mode: u32,
) -> io::Result<Rlcreate> {
    // The `fid` in the lcreate call initially points to the directory
    // but is supposed to point to the newly created file after the call
    // completes.  Duplicate the fid so that we don't end up consuming the
    // directory fid.
    walk(server, dir, dir_fid, fid, Vec::new());

    let tlcreate = Tlcreate {
        fid,
        name: String::from(name),
        flags,
        mode,
        gid: 0,
    };

    server.lcreate(tlcreate)
}

struct Readdir<'a> {
    server: &'a mut Server,
    fid: u32,
    offset: u64,
    cursor: Cursor<Vec<u8>>,
}

impl<'a> Iterator for Readdir<'a> {
    type Item = Dirent;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor.position() >= self.cursor.get_ref().len() as u64 {
            let treaddir = Treaddir {
                fid: self.fid,
                offset: self.offset,
                count: DEFAULT_BUFFER_SIZE,
            };

            let Rreaddir { data } = self
                .server
                .readdir(&treaddir)
                .expect("failed to read directory");
            if data.is_empty() {
                // No more entries.
                return None;
            }

            mem::drop(mem::replace(&mut self.cursor, Cursor::new(data.0)));
        }

        let dirent: Dirent = WireFormat::decode(&mut self.cursor).expect("failed to decode dirent");
        self.offset = dirent.offset;

        Some(dirent)
    }
}

fn readdir(server: &mut Server, fid: u32) -> Readdir {
    Readdir {
        server,
        fid,
        offset: 0,
        cursor: Cursor::new(Vec::new()),
    }
}

// Sets up the server to start handling messages.  Creates a new temporary
// directory to act as the server root and sends an initial Tattach message.
// At the end of setup, fid 1 points to the root of the server.
fn setup<P: AsRef<Path>>(name: P) -> (ScopedPath<OsString>, Server) {
    let mut test_dir = env::var_os("T")
        .map(PathBuf::from)
        .unwrap_or_else(env::temp_dir);
    test_dir.push(name);

    let mut os_str = OsString::from(test_dir);
    os_str.push(".XXXXXX");

    // Create a c string and release ownership.  This seems like the only way
    // to get a *mut c_char.
    let buf = CString::new(os_str.into_vec())
        .expect("failed to create CString")
        .into_raw();

    // Safe because this will only modify the contents of `buf`.
    let ret = unsafe { libc::mkdtemp(buf) };

    // Take ownership of the buffer back before checking the result.  Safe because
    // this was created by a call to into_raw() above and mkdtemp will not overwrite
    // the trailing '\0'.
    let buf = unsafe { CString::from_raw(buf) };

    assert!(!ret.is_null());

    let test_dir = ScopedPath(OsString::from_vec(buf.into_bytes()));

    // Create a basic file system hierarchy.
    let entries = [
        DirEntry::Directory {
            name: "subdir",
            entries: &[
                DirEntry::File {
                    name: "b",
                    content: b"hello, world!",
                },
                DirEntry::Directory {
                    name: "nested",
                    entries: &[DirEntry::File {
                        name: "Огонь по готовности!",
                        content: &[
                            0xe9u8, 0xbeu8, 0x8du8, 0xe3u8, 0x81u8, 0x8cu8, 0xe6u8, 0x88u8, 0x91u8,
                            0xe3u8, 0x81u8, 0x8cu8, 0xe6u8, 0x95u8, 0xb5u8, 0xe3u8, 0x82u8, 0x92u8,
                            0xe5u8, 0x96u8, 0xb0u8, 0xe3u8, 0x82u8, 0x89u8, 0xe3u8, 0x81u8, 0x86u8,
                            0x21u8,
                        ],
                    }],
                },
            ],
        },
        DirEntry::File {
            name: "世界.txt",
            content: &[
                0xe3u8, 0x81u8, 0x93u8, 0xe3u8, 0x82u8, 0x93u8, 0xe3u8, 0x81u8, 0xabu8, 0xe3u8,
                0x81u8, 0xa1u8, 0xe3u8, 0x81u8, 0xafu8,
            ],
        },
    ];

    for e in &entries {
        e.create(&mut Cow::from(&*test_dir));
    }

    let md = test_dir
        .symlink_metadata()
        .expect("failed to get metadata for root dir");

    let mut server = Server::new(&*test_dir, Default::default(), Default::default())
        .expect("Failed to create server");

    let tversion = Tversion {
        msize: DEFAULT_BUFFER_SIZE,
        version: String::from("9P2000.L"),
    };

    let rversion = server
        .version(&tversion)
        .expect("failed to get version from server");
    assert_eq!(rversion.msize, DEFAULT_BUFFER_SIZE);
    assert_eq!(rversion.version, "9P2000.L");

    let tattach = Tattach {
        fid: ROOT_FID,
        afid: P9_NOFID,
        uname: String::from("unittest"),
        aname: String::from(""),
        n_uname: 1000,
    };

    let rattach = server.attach(&tattach).expect("failed to attach to server");
    check_qid(&rattach.qid, &md);

    (test_dir, server)
}

#[test]
fn path_joins() {
    let root = PathBuf::from("/a/b/c");
    let path = PathBuf::from("/a/b/c/d/e/f");

    assert_eq!(
        &join_path(path.clone(), "nested", &root).expect("normal"),
        Path::new("/a/b/c/d/e/f/nested")
    );

    let p1 = join_path(path, "..", &root).expect("parent 1");
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
    join_path(path, "/c/d/e", &root).expect_err("absolute path");
}

#[test]
fn clunk() {
    let (_test_dir, mut server) = setup("clunk");

    let tclunk = Tclunk { fid: ROOT_FID };
    server.clunk(&tclunk).expect("failed to clunk root fid");
}

#[test]
fn get_attr() {
    let (test_dir, mut server) = setup("get_attr");

    let md = test_dir
        .symlink_metadata()
        .expect("failed to get metadata for test dir");

    check_attr(&mut server, ROOT_FID, &md);
}

#[test]
fn tree_walk() {
    let (test_dir, mut server) = setup("readdir");

    let mut next_fid = ROOT_FID + 1;

    let mut dirs = VecDeque::new();
    dirs.push_back(test_dir.to_path_buf());

    while let Some(dir) = dirs.pop_front() {
        let dfid = next_fid;
        next_fid += 1;

        let wnames: Vec<String> = dir
            .strip_prefix(&test_dir)
            .expect("test directory is not prefix of subdir")
            .components()
            .map(|c| Path::new(&c).to_string_lossy().to_string())
            .collect();
        walk(&mut server, &*test_dir, ROOT_FID, dfid, wnames);

        let md = dir.symlink_metadata().expect("failed to get metadata");

        check_attr(&mut server, dfid, &md);

        let fid = next_fid;
        next_fid += 1;
        open(&mut server, &dir, dfid, "", fid, P9_DIRECTORY).expect("Failed to open directory");
        for dirent in readdir(&mut server, fid) {
            if dirent.name == "." || dirent.name == ".." {
                continue;
            }

            let entry_path = dir.join(&dirent.name);
            assert!(
                entry_path.exists(),
                "directory entry \"{}\" does not exist",
                entry_path.display()
            );
            let md = fs::symlink_metadata(&entry_path).expect("failed to get metadata for entry");

            let ty = if md.is_dir() {
                dirs.push_back(dir.join(dirent.name));
                libc::DT_DIR
            } else if md.is_file() {
                libc::DT_REG
            } else if md.file_type().is_symlink() {
                libc::DT_LNK
            } else {
                panic!("unknown file type: {:?}", md.file_type());
            };

            assert_eq!(dirent.ty, ty);
            check_qid(&dirent.qid, &md);
        }

        let tclunk = Tclunk { fid };
        server.clunk(&tclunk).expect("failed to clunk fid");
    }
}

#[test]
fn create_existing_file() {
    let (test_dir, mut server) = setup("create_existing");

    let name = "existing";
    create_local_file(&test_dir, name);

    let fid = ROOT_FID + 1;
    create(
        &mut server,
        &*test_dir,
        ROOT_FID,
        fid,
        name,
        P9_APPEND,
        0o644,
    )
    .expect_err("successfully created existing file");
}

enum SetAttrKind {
    File,
    Directory,
}

fn set_attr_test<F>(kind: SetAttrKind, set_fields: F) -> io::Result<fs::Metadata>
where
    F: FnOnce(&mut Tsetattr),
{
    let (test_dir, mut server) = setup("set_attr");

    let name = "existing";
    match kind {
        SetAttrKind::File => {
            create_local_file(&test_dir, name);
        }
        SetAttrKind::Directory => {
            let tmkdir = Tmkdir {
                dfid: ROOT_FID,
                name: String::from(name),
                mode: 0o755,
                gid: 0,
            };

            let rmkdir = server.mkdir(tmkdir).expect("failed to create directory");
            let md = fs::symlink_metadata(test_dir.join(name))
                .expect("failed to get metadata for directory");

            assert!(md.is_dir());
            check_qid(&rmkdir.qid, &md);
        }
    };

    let fid = ROOT_FID + 1;
    walk(
        &mut server,
        &*test_dir,
        ROOT_FID,
        fid,
        vec![String::from(name)],
    );

    let mut tsetattr = Tsetattr {
        fid,
        valid: 0,
        mode: 0,
        uid: 0,
        gid: 0,
        size: 0,
        atime_sec: 0,
        atime_nsec: 0,
        mtime_sec: 0,
        mtime_nsec: 0,
    };

    set_fields(&mut tsetattr);
    server.set_attr(&tsetattr)?;

    fs::symlink_metadata(test_dir.join(name))
}

#[test]
fn set_len() {
    let len = 661;
    let md = set_attr_test(SetAttrKind::File, |tsetattr| {
        tsetattr.valid = P9_SETATTR_SIZE;
        tsetattr.size = len;
    })
    .expect("failed to run set length of file");

    assert_eq!(md.size(), len);
}

#[test]
fn set_file_mode() {
    let mode = 0o640;
    let md = set_attr_test(SetAttrKind::File, |tsetattr| {
        tsetattr.valid = P9_SETATTR_MODE;
        tsetattr.mode = mode;
    })
    .expect("failed to set mode");

    assert_eq!(md.mode() & 0o777, mode);
}

#[test]
fn set_file_mtime() {
    let (secs, nanos) = (1245247825, 524617);
    let md = set_attr_test(SetAttrKind::File, |tsetattr| {
        tsetattr.valid = P9_SETATTR_MTIME | P9_SETATTR_MTIME_SET;
        tsetattr.mtime_sec = secs;
        tsetattr.mtime_nsec = nanos;
    })
    .expect("failed to set mtime");

    assert_eq!(md.mtime() as u64, secs);
    assert_eq!(md.mtime_nsec() as u64, nanos);
}

#[test]
fn set_file_atime() {
    let (secs, nanos) = (9247605, 4016);
    let md = set_attr_test(SetAttrKind::File, |tsetattr| {
        tsetattr.valid = P9_SETATTR_ATIME | P9_SETATTR_ATIME_SET;
        tsetattr.atime_sec = secs;
        tsetattr.atime_nsec = nanos;
    })
    .expect("failed to set atime");

    assert_eq!(md.atime() as u64, secs);
    assert_eq!(md.atime_nsec() as u64, nanos);
}

#[test]
fn set_dir_mode() {
    let mode = 0o640;
    let md = set_attr_test(SetAttrKind::Directory, |tsetattr| {
        tsetattr.valid = P9_SETATTR_MODE;
        tsetattr.mode = mode;
    })
    .expect("failed to set mode");

    assert_eq!(md.mode() & 0o777, mode);
}

#[test]
fn set_dir_mtime() {
    let (secs, nanos) = (1245247825, 524617);
    let md = set_attr_test(SetAttrKind::Directory, |tsetattr| {
        tsetattr.valid = P9_SETATTR_MTIME | P9_SETATTR_MTIME_SET;
        tsetattr.mtime_sec = secs;
        tsetattr.mtime_nsec = nanos;
    })
    .expect("failed to set mtime");

    assert_eq!(md.mtime() as u64, secs);
    assert_eq!(md.mtime_nsec() as u64, nanos);
}

#[test]
fn set_dir_atime() {
    let (secs, nanos) = (9247605, 4016);
    let md = set_attr_test(SetAttrKind::Directory, |tsetattr| {
        tsetattr.valid = P9_SETATTR_ATIME | P9_SETATTR_ATIME_SET;
        tsetattr.atime_sec = secs;
        tsetattr.atime_nsec = nanos;
    })
    .expect("failed to set atime");

    assert_eq!(md.atime() as u64, secs);
    assert_eq!(md.atime_nsec() as u64, nanos);
}

#[test]
fn huge_directory() {
    let (test_dir, mut server) = setup("huge_directory");

    let name = "newdir";
    let newdir = test_dir.join(name);
    fs::create_dir(&newdir).expect("failed to create directory");

    let dfid = ROOT_FID + 1;
    walk(
        &mut server,
        &*test_dir,
        ROOT_FID,
        dfid,
        vec![String::from(name)],
    );

    // Create ~4K files in the directory and then attempt to read them all.
    let mut filenames = HashSet::with_capacity(4096);
    for i in 0..4096 {
        let name = format!("file_{}", i);
        create_local_file(&newdir, &name);
        assert!(filenames.insert(name));
    }

    let fid = dfid + 1;
    open(&mut server, &newdir, dfid, "", fid, P9_DIRECTORY).expect("Failed to open directory");
    for f in readdir(&mut server, fid) {
        let path = newdir.join(&f.name);

        let md = fs::symlink_metadata(path).expect("failed to get metadata for path");
        check_qid(&f.qid, &md);

        if f.name == "." || f.name == ".." {
            assert_eq!(f.ty, libc::DT_DIR);
        } else {
            assert_eq!(f.ty, libc::DT_REG);
            assert!(filenames.remove(&f.name));
        }
    }

    assert!(filenames.is_empty());
}

#[test]
fn mkdir() {
    let (test_dir, mut server) = setup("mkdir");

    let name = "conan";
    let tmkdir = Tmkdir {
        dfid: ROOT_FID,
        name: String::from(name),
        mode: 0o755,
        gid: 0,
    };

    let rmkdir = server.mkdir(tmkdir).expect("failed to create directory");
    let md =
        fs::symlink_metadata(test_dir.join(name)).expect("failed to get metadata for directory");

    assert!(md.is_dir());
    check_qid(&rmkdir.qid, &md);
}

#[test]
fn unlink_all() {
    let (test_dir, mut server) = setup("readdir");

    let mut next_fid = ROOT_FID + 1;

    let mut dirs = VecDeque::new();
    dirs.push_back((ROOT_FID, test_dir.to_path_buf()));

    // First iterate over the whole directory.
    let mut unlinks = VecDeque::new();
    while let Some((dfid, dir)) = dirs.pop_front() {
        let mut names = VecDeque::new();
        for entry in fs::read_dir(dir).expect("failed to read directory") {
            let entry = entry.expect("unable to iterate over directory");
            let ft = entry
                .file_type()
                .expect("failed to get file type for entry");
            if ft.is_dir() {
                let fid = next_fid;
                next_fid += 1;

                let wnames: Vec<String> = entry
                    .path()
                    .strip_prefix(&test_dir)
                    .expect("test directory is not prefix of subdir")
                    .components()
                    .map(|c| Path::new(&c).to_string_lossy().to_string())
                    .collect();
                walk(&mut server, &*test_dir, ROOT_FID, fid, wnames);
                dirs.push_back((fid, entry.path()));
            }

            names.push_back((
                entry
                    .file_name()
                    .into_string()
                    .expect("failed to convert entry name to string"),
                if ft.is_dir() {
                    libc::AT_REMOVEDIR as u32
                } else {
                    0
                },
            ));
        }

        unlinks.push_back((dfid, names));
    }

    // Now remove everything in reverse order.
    while let Some((dfid, names)) = unlinks.pop_back() {
        for (name, flags) in names {
            let tunlinkat = Tunlinkat {
                dirfd: dfid,
                name,
                flags,
            };

            server.unlink_at(tunlinkat).expect("failed to unlink path");
        }
    }
}

#[test]
fn rename_at() {
    let (test_dir, mut server) = setup("rename");

    let name = "oldfile";
    let content = create_local_file(&test_dir, name);

    let newname = "newfile";
    let trename = Trenameat {
        olddirfid: ROOT_FID,
        oldname: String::from(name),
        newdirfid: ROOT_FID,
        newname: String::from(newname),
    };

    server.rename_at(trename).expect("failed to rename file");

    assert!(!test_dir.join(name).exists());

    let mut newcontent = Vec::with_capacity(content.len());
    let size = File::open(test_dir.join(newname))
        .expect("failed to open file")
        .read_to_end(&mut newcontent)
        .expect("failed to read new file content");
    assert_eq!(size, content.len());
    assert_eq!(newcontent, content);
}

fn setlk_tlock(fid: u32, len: u64, start: u64, type_: i32) -> Tlock {
    Tlock {
        fid,
        type_: type_ as u8,
        flags: 0,
        start,
        length: len,
        proc_id: SERVER_PID,
        client_id: String::from("test-server"),
    }
}

fn getlk_tgetlock(fid: u32, type_: i32) -> Tgetlock {
    Tgetlock {
        fid,
        type_: type_ as u8,
        start: 0,
        length: 0,
        proc_id: SERVER_PID,
        client_id: String::from("test-server"),
    }
}

fn setup_simple_lock_no_open() -> Server {
    let (test_dir, server) = setup("simple lock");

    let filename = "file";
    create_local_file(&test_dir, filename);

    server
}

fn setup_simple_lock(flags: u32) -> Server {
    let (test_dir, mut server) = setup("simple lock");

    let filename = "file";
    create_local_file(&test_dir, filename);

    open(
        &mut server,
        &*test_dir,
        ROOT_FID,
        filename,
        ROOT_FID + 1,
        flags,
    )
    .expect("failed to open file");

    server
}

#[test]
fn lock_rdlck_no_open_file() {
    let mut server = setup_simple_lock_no_open();

    let tlock = setlk_tlock(ROOT_FID + 1, 8, 0, libc::F_RDLCK);

    server.lock(&tlock).expect_err("Bad file descriptor");
}

#[test]
fn lock_rdlck() {
    let mut server = setup_simple_lock(P9_RDWR);

    let tlock = setlk_tlock(ROOT_FID + 1, 8, 0, libc::F_RDLCK);

    server.lock(&tlock).expect("failed to lock file");
}
#[test]
fn lock_wrlck_no_open_file() {
    let mut server = setup_simple_lock_no_open();

    let tlock = setlk_tlock(ROOT_FID + 1, 8, 0, libc::F_WRLCK);

    server.lock(&tlock).expect_err("Bad file descriptor");
}
#[test]
fn lock_wrlck() {
    let mut server = setup_simple_lock(P9_RDWR);

    let tlock = setlk_tlock(ROOT_FID + 1, 8, 0, libc::F_WRLCK);

    server.lock(&tlock).expect("failed to lock file");
}

#[test]
fn lock_unlck_no_lock() {
    let mut server = setup_simple_lock(P9_RDWR);

    let tlock = setlk_tlock(ROOT_FID + 1, 0, 0, libc::F_UNLCK);

    server.lock(&tlock).expect("failed to lock file");
}

#[test]
fn lock_unlck() {
    let mut server = setup_simple_lock(P9_RDWR);

    let tlock = setlk_tlock(ROOT_FID + 1, LOCAL_FILE_LEN / 2, 0, libc::F_RDLCK);

    server.lock(&tlock).expect("failed to lock file");

    let tlock = setlk_tlock(ROOT_FID + 1, 0, 0, libc::F_UNLCK);

    server.lock(&tlock).expect("failed to lock file");
}

#[test]
fn lock_unlck_relock() {
    let mut server = setup_simple_lock(P9_RDWR);

    let tlock = setlk_tlock(ROOT_FID + 1, LOCAL_FILE_LEN / 2, 0, libc::F_RDLCK);

    server.lock(&tlock).expect("failed to lock file");

    let tlock = setlk_tlock(ROOT_FID + 1, 0, 0, libc::F_UNLCK);

    server.lock(&tlock).expect("failed to lock file");

    let tlock = setlk_tlock(ROOT_FID + 1, LOCAL_FILE_LEN / 2, 0, libc::F_RDLCK);

    server.lock(&tlock).expect("failed to lock file");
}

#[test]
fn getlock_rdlck_nolock() {
    let mut server = setup_simple_lock(P9_RDWR);

    let tgetlock = getlk_tgetlock(ROOT_FID + 1, libc::F_RDLCK);

    server
        .get_lock(&tgetlock)
        .expect("failed to get lock on file");
}

#[test]
fn getlock_wrlck() {
    let mut server = setup_simple_lock(P9_RDWR);

    let tlock = setlk_tlock(ROOT_FID + 1, LOCAL_FILE_LEN / 2, 0, libc::F_WRLCK);

    server.lock(&tlock).expect("failed to lock file");

    let tgetlock = getlk_tgetlock(ROOT_FID + 1, libc::F_WRLCK);

    server
        .get_lock(&tgetlock)
        .expect("failed to get lock on file");
}

#[test]
fn getlock_rdlck() {
    let mut server = setup_simple_lock(P9_RDWR);

    let tlock = setlk_tlock(ROOT_FID + 1, LOCAL_FILE_LEN / 2, 0, libc::F_RDLCK);

    server.lock(&tlock).expect("failed to lock file");

    let tgetlock = getlk_tgetlock(ROOT_FID + 1, libc::F_RDLCK);

    server
        .get_lock(&tgetlock)
        .expect("failed to get lock on file");
}

macro_rules! open_test {
    ($name:ident, $flags:expr) => {
        #[test]
        fn $name() {
            let (test_dir, mut server) = setup("open");

            let fid = ROOT_FID + 1;
            let name = "test.txt";
            let content = create_local_file(&test_dir, name);

            let rlopen = open(&mut server, &*test_dir, ROOT_FID, name, fid, $flags as u32)
                .expect("failed to open file");

            let md =
                fs::symlink_metadata(test_dir.join(name)).expect("failed to get metadata for file");
            check_qid(&rlopen.qid, &md);
            assert_eq!(rlopen.iounit, 0);

            check_attr(&mut server, fid, &md);

            // Check that the file has the proper contents as long as we didn't
            // truncate it first.
            if $flags & P9_TRUNC == 0 && $flags & P9_WRONLY == 0 {
                check_content(&mut server, &content, fid);
            }

            // Check that we can write to the file.
            if $flags & P9_RDWR != 0 || $flags & P9_WRONLY != 0 {
                write(&mut server, &test_dir, name, fid, $flags);
            }

            let tclunk = Tclunk { fid };
            server.clunk(&tclunk).expect("Unable to clunk file");
        }
    };
    ($name:ident, $flags:expr, $expected_err:expr) => {
        #[test]
        fn $name() {
            let (test_dir, mut server) = setup("open_fail");

            let fid = ROOT_FID + 1;
            let name = "test.txt";
            create_local_file(&test_dir, name);

            let err = open(&mut server, &*test_dir, ROOT_FID, name, fid, $flags as u32)
                .expect_err("successfully opened file");
            assert_eq!(err.kind(), $expected_err);

            let tclunk = Tclunk { fid };
            server.clunk(&tclunk).expect("Unable to clunk file");
        }
    };
}

open_test!(read_only_file_open, P9_RDONLY);
open_test!(read_write_file_open, P9_RDWR);
open_test!(write_only_file_open, P9_WRONLY);

open_test!(create_read_only_file_open, P9_CREATE | P9_RDONLY);
open_test!(create_read_write_file_open, P9_CREATE | P9_RDWR);
open_test!(create_write_only_file_open, P9_CREATE | P9_WRONLY);

open_test!(append_read_only_file_open, P9_APPEND | P9_RDONLY);
open_test!(append_read_write_file_open, P9_APPEND | P9_RDWR);
open_test!(append_write_only_file_open, P9_APPEND | P9_WRONLY);

open_test!(trunc_read_only_file_open, P9_TRUNC | P9_RDONLY);
open_test!(trunc_read_write_file_open, P9_TRUNC | P9_RDWR);
open_test!(trunc_write_only_file_open, P9_TRUNC | P9_WRONLY);

open_test!(
    create_append_read_only_file_open,
    P9_CREATE | P9_APPEND | P9_RDONLY
);
open_test!(
    create_append_read_write_file_open,
    P9_CREATE | P9_APPEND | P9_RDWR
);
open_test!(
    create_append_wronly_file_open,
    P9_CREATE | P9_APPEND | P9_WRONLY
);

open_test!(
    create_trunc_read_only_file_open,
    P9_CREATE | P9_TRUNC | P9_RDONLY
);
open_test!(
    create_trunc_read_write_file_open,
    P9_CREATE | P9_TRUNC | P9_RDWR
);
open_test!(
    create_trunc_wronly_file_open,
    P9_CREATE | P9_TRUNC | P9_WRONLY
);

open_test!(
    append_trunc_read_only_file_open,
    P9_APPEND | P9_TRUNC | P9_RDONLY
);
open_test!(
    append_trunc_read_write_file_open,
    P9_APPEND | P9_TRUNC | P9_RDWR
);
open_test!(
    append_trunc_wronly_file_open,
    P9_APPEND | P9_TRUNC | P9_WRONLY
);

open_test!(
    create_append_trunc_read_only_file_open,
    P9_CREATE | P9_APPEND | P9_TRUNC | P9_RDONLY
);
open_test!(
    create_append_trunc_read_write_file_open,
    P9_CREATE | P9_APPEND | P9_TRUNC | P9_RDWR
);
open_test!(
    create_append_trunc_wronly_file_open,
    P9_CREATE | P9_APPEND | P9_TRUNC | P9_WRONLY
);

open_test!(
    create_excl_read_only_file_open,
    P9_CREATE | P9_EXCL | P9_RDONLY,
    io::ErrorKind::AlreadyExists
);
open_test!(
    create_excl_read_write_file_open,
    P9_CREATE | P9_EXCL | P9_RDWR,
    io::ErrorKind::AlreadyExists
);
open_test!(
    create_excl_wronly_file_open,
    P9_CREATE | P9_EXCL | P9_WRONLY,
    io::ErrorKind::AlreadyExists
);

macro_rules! create_test {
    ($name:ident, $flags:expr, $mode:expr) => {
        #[test]
        fn $name() {
            let (test_dir, mut server) = setup("create");

            let name = "foo.txt";
            let fid = ROOT_FID + 1;
            let rlcreate = create(&mut server, &*test_dir, ROOT_FID, fid, name, $flags, $mode)
                .expect("failed to create file");

            let md =
                fs::symlink_metadata(test_dir.join(name)).expect("failed to get metadata for file");
            assert_eq!(rlcreate.iounit, 0);
            check_qid(&rlcreate.qid, &md);
            check_attr(&mut server, fid, &md);

            // Check that we can write to the file.
            if $flags & P9_RDWR != 0 || $flags & P9_WRONLY != 0 {
                write(&mut server, &test_dir, name, fid, $flags);
            }

            let tclunk = Tclunk { fid };
            server.clunk(&tclunk).expect("Unable to clunk file");
        }
    };
    ($name:ident, $flags:expr, $mode:expr, $expected_err:expr) => {
        #[test]
        fn $name() {
            let (test_dir, mut server) = setup("create_fail");

            let name = "foo.txt";
            // The `fid` in the lcreate call initially points to the directory
            // but is supposed to point to the newly created file after the call
            // completes.  Duplicate the fid so that we don't end up consuming the
            // root fid.
            let fid = ROOT_FID + 1;
            let err = create(&mut server, &*test_dir, ROOT_FID, fid, name, $flags, $mode)
                .expect_err("successfully created file");
            assert_eq!(err.kind(), $expected_err);
        }
    };
}

create_test!(read_only_file_create, P9_RDONLY, 0o600u32);
create_test!(read_write_file_create, P9_RDWR, 0o600u32);
create_test!(write_only_file_create, P9_WRONLY, 0o600u32);

create_test!(
    append_read_only_file_create,
    P9_APPEND | P9_RDONLY,
    0o600u32
);
create_test!(append_read_write_file_create, P9_APPEND | P9_RDWR, 0o600u32);
create_test!(append_wronly_file_create, P9_APPEND | P9_WRONLY, 0o600u32);

#[test]
fn lcreate_set_len() {
    let (test_dir, mut server) = setup("lcreate_set_len");

    let name = "foo.txt";
    let fid = ROOT_FID + 1;
    create(
        &mut server,
        &*test_dir,
        ROOT_FID,
        fid,
        name,
        P9_RDWR,
        0o600u32,
    )
    .expect("failed to create file");

    let tsetattr = Tsetattr {
        fid,
        valid: 0x8, // P9_SETATTR_SIZE
        size: 100,
        // The other fields are not used because the relevant flags aren't set in `valid`.
        mode: 0,
        uid: 0,
        gid: 0,
        atime_sec: 0,
        atime_nsec: 0,
        mtime_sec: 0,
        mtime_nsec: 0,
    };
    server
        .set_attr(&tsetattr)
        .expect("failed to set file length after lcreate");

    let tclunk = Tclunk { fid };
    server.clunk(&tclunk).expect("Unable to clunk file");
}

#[test]
fn readlink() {
    let (test_dir, mut server) = setup("readlink");
    create_local_symlink(&test_dir, "symlink", "target/of/symlink");

    let fid = ROOT_FID + 1;
    walk(
        &mut server,
        &*test_dir,
        ROOT_FID,
        fid,
        vec!["symlink".into()],
    );

    let treadlink = Treadlink { fid };

    let rreadlink = server.readlink(&treadlink).expect("failed to readlink");

    assert_eq!(rreadlink.target, "target/of/symlink");
}
