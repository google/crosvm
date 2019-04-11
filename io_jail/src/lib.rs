// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[allow(dead_code)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
mod libminijail;

use libc::pid_t;
use std::ffi::CString;
use std::fmt::{self, Display};
use std::fs;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};

#[derive(Debug)]
pub enum Error {
    // minijail failed to accept bind mount.
    BindMount {
        errno: i32,
        src: PathBuf,
        dst: PathBuf,
    },
    // minijail failed to accept mount.
    Mount {
        errno: i32,
        src: PathBuf,
        dest: PathBuf,
        fstype: String,
        flags: usize,
        data: String,
    },
    /// Failure to count the number of threads in /proc/self/tasks.
    CheckingMultiThreaded(io::Error),
    /// minjail_new failed, this is an allocation failure.
    CreatingMinijail,
    /// minijail_fork failed with the given error code.
    ForkingMinijail(i32),
    /// Attempt to `fork` while already multithreaded.
    ForkingWhileMultiThreaded,
    /// The seccomp policy path doesn't exist.
    SeccompPath(PathBuf),
    /// The string passed in didn't parse to a valid CString.
    StrToCString(String),
    /// The path passed in didn't parse to a valid CString.
    PathToCString(PathBuf),
    /// Failed to call dup2 to set stdin, stdout, or stderr to /dev/null.
    DupDevNull(i32),
    /// Failed to set up /dev/null for FDs 0, 1, or 2.
    OpenDevNull(io::Error),
    /// Setting the specified alt-syscall table failed with errno. Is the table in the kernel?
    SetAltSyscallTable { errno: i32, name: String },
    /// chroot failed with the provided errno.
    SettingChrootDirectory(i32, PathBuf),
    /// pivot_root failed with the provided errno.
    SettingPivotRootDirectory(i32, PathBuf),
    /// There is an entry in /proc/self/fd that isn't a valid PID.
    ReadFdDirEntry(io::Error),
    /// /proc/self/fd failed to open.
    ReadFdDir(io::Error),
    /// An entry in /proc/self/fd is not an integer
    ProcFd(String),
    /// Minijail refused to preserve an FD in the inherit list of `fork()`.
    PreservingFd(i32),
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            BindMount { src, dst, errno } => write!(
                f,
                "failed to accept bind mount {} -> {}: {}",
                src.display(),
                dst.display(),
                io::Error::from_raw_os_error(*errno),
            ),
            Mount {
                errno,
                src,
                dest,
                fstype,
                flags,
                data,
            } => write!(
                f,
                "failed to accept mount {} -> {} of type {:?} with flags 0x{:x} \
                 and data {:?}: {}",
                src.display(),
                dest.display(),
                fstype,
                flags,
                data,
                io::Error::from_raw_os_error(*errno),
            ),
            CheckingMultiThreaded(e) => write!(
                f,
                "Failed to count the number of threads from /proc/self/tasks {}",
                e
            ),
            CreatingMinijail => write!(f, "minjail_new failed due to an allocation failure"),
            ForkingMinijail(e) => write!(f, "minijail_fork failed with error {}", e),
            ForkingWhileMultiThreaded => write!(f, "Attempt to call fork() while multithreaded"),
            SeccompPath(p) => write!(f, "missing seccomp policy path: {}", p.display()),
            StrToCString(s) => write!(f, "failed to convert string into CString: {}", s),
            PathToCString(s) => write!(f, "failed to convert path into CString: {}", s.display()),
            DupDevNull(errno) => write!(
                f,
                "failed to call dup2 to set stdin, stdout, or stderr to /dev/null: {}",
                io::Error::from_raw_os_error(*errno),
            ),
            OpenDevNull(e) => write!(
                f,
                "fail to open /dev/null for setting FDs 0, 1, or 2: {}",
                e,
            ),
            SetAltSyscallTable { name, errno } => write!(
                f,
                "failed to set alt-syscall table {}: {}",
                name,
                io::Error::from_raw_os_error(*errno),
            ),
            SettingChrootDirectory(errno, p) => write!(
                f,
                "failed to set chroot {}: {}",
                p.display(),
                io::Error::from_raw_os_error(*errno),
            ),
            SettingPivotRootDirectory(errno, p) => write!(
                f,
                "failed to set pivot root {}: {}",
                p.display(),
                io::Error::from_raw_os_error(*errno),
            ),
            ReadFdDirEntry(e) => write!(f, "failed to read an entry in /proc/self/fd: {}", e),
            ReadFdDir(e) => write!(f, "failed to open /proc/self/fd: {}", e),
            ProcFd(s) => write!(f, "an entry in /proc/self/fd is not an integer: {}", s),
            PreservingFd(e) => write!(f, "fork failed in minijail_preserve_fd with error {}", e),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// Configuration to jail a process based on wrapping libminijail.
///
/// Intentionally leave out everything related to `minijail_run`.  Forking is
/// hard to reason about w.r.t. memory and resource safety.  It is better to avoid
/// forking from rust code.  Leave forking to the library user, who can make
/// an informed decision about when to fork to minimize risk.
/// # Examples
/// * Load seccomp policy - like "minijail0 -n -S myfilter.policy"
///
/// ```
/// # use std::path::Path;
/// # use io_jail::Minijail;
/// # fn seccomp_filter_test() -> Result<(), ()> {
///       let mut j = Minijail::new().map_err(|_| ())?;
///       j.no_new_privs();
///       j.parse_seccomp_filters(Path::new("my_filter.policy")).map_err(|_| ())?;
///       j.use_seccomp_filter();
///       unsafe { // `fork` will close all the programs FDs.
///           j.fork(None).map_err(|_| ())?;
///       }
/// #     Ok(())
/// # }
/// ```
///
/// * Keep stdin, stdout, and stderr open after jailing.
///
/// ```
/// # use io_jail::Minijail;
/// # use std::os::unix::io::RawFd;
/// # fn seccomp_filter_test() -> Result<(), ()> {
///       let j = Minijail::new().map_err(|_| ())?;
///       let preserve_fds: Vec<RawFd> = vec![0, 1, 2];
///       unsafe { // `fork` will close all the programs FDs.
///           j.fork(Some(&preserve_fds)).map_err(|_| ())?;
///       }
/// #     Ok(())
/// # }
/// ```
/// # Errors
/// The `fork` function might not return an error if it fails after forking. A
/// partial jail is not recoverable and will instead result in killing the
/// process.
pub struct Minijail {
    jail: *mut libminijail::minijail,
}

impl Minijail {
    /// Creates a new jail configuration.
    pub fn new() -> Result<Minijail> {
        let j = unsafe {
            // libminijail actually owns the minijail structure. It will live until we call
            // minijail_destroy.
            libminijail::minijail_new()
        };
        if j.is_null() {
            return Err(Error::CreatingMinijail);
        }
        Ok(Minijail { jail: j })
    }

    // The following functions are safe because they only set values in the
    // struct already owned by minijail.  The struct's lifetime is tied to
    // `struct Minijail` so it is guaranteed to be valid

    pub fn change_uid(&mut self, uid: libc::uid_t) {
        unsafe {
            libminijail::minijail_change_uid(self.jail, uid);
        }
    }
    pub fn change_gid(&mut self, gid: libc::gid_t) {
        unsafe {
            libminijail::minijail_change_gid(self.jail, gid);
        }
    }
    pub fn set_supplementary_gids(&mut self, ids: &[libc::gid_t]) {
        unsafe {
            libminijail::minijail_set_supplementary_gids(self.jail, ids.len(), ids.as_ptr());
        }
    }
    pub fn keep_supplementary_gids(&mut self) {
        unsafe {
            libminijail::minijail_keep_supplementary_gids(self.jail);
        }
    }
    pub fn use_seccomp(&mut self) {
        unsafe {
            libminijail::minijail_use_seccomp(self.jail);
        }
    }
    pub fn no_new_privs(&mut self) {
        unsafe {
            libminijail::minijail_no_new_privs(self.jail);
        }
    }
    pub fn use_seccomp_filter(&mut self) {
        unsafe {
            libminijail::minijail_use_seccomp_filter(self.jail);
        }
    }
    pub fn set_seccomp_filter_tsync(&mut self) {
        unsafe {
            libminijail::minijail_set_seccomp_filter_tsync(self.jail);
        }
    }
    pub fn parse_seccomp_filters(&mut self, path: &Path) -> Result<()> {
        if !path.is_file() {
            return Err(Error::SeccompPath(path.to_owned()));
        }

        let pathstring = path
            .as_os_str()
            .to_str()
            .ok_or(Error::PathToCString(path.to_owned()))?;
        let filename =
            CString::new(pathstring).map_err(|_| Error::PathToCString(path.to_owned()))?;
        unsafe {
            libminijail::minijail_parse_seccomp_filters(self.jail, filename.as_ptr());
        }
        Ok(())
    }
    pub fn log_seccomp_filter_failures(&mut self) {
        unsafe {
            libminijail::minijail_log_seccomp_filter_failures(self.jail);
        }
    }
    pub fn use_caps(&mut self, capmask: u64) {
        unsafe {
            libminijail::minijail_use_caps(self.jail, capmask);
        }
    }
    pub fn capbset_drop(&mut self, capmask: u64) {
        unsafe {
            libminijail::minijail_capbset_drop(self.jail, capmask);
        }
    }
    pub fn set_ambient_caps(&mut self) {
        unsafe {
            libminijail::minijail_set_ambient_caps(self.jail);
        }
    }
    pub fn reset_signal_mask(&mut self) {
        unsafe {
            libminijail::minijail_reset_signal_mask(self.jail);
        }
    }
    pub fn run_as_init(&mut self) {
        unsafe {
            libminijail::minijail_run_as_init(self.jail);
        }
    }
    pub fn namespace_pids(&mut self) {
        unsafe {
            libminijail::minijail_namespace_pids(self.jail);
        }
    }
    pub fn namespace_user(&mut self) {
        unsafe {
            libminijail::minijail_namespace_user(self.jail);
        }
    }
    pub fn namespace_user_disable_setgroups(&mut self) {
        unsafe {
            libminijail::minijail_namespace_user_disable_setgroups(self.jail);
        }
    }
    pub fn namespace_vfs(&mut self) {
        unsafe {
            libminijail::minijail_namespace_vfs(self.jail);
        }
    }
    pub fn new_session_keyring(&mut self) {
        unsafe {
            libminijail::minijail_new_session_keyring(self.jail);
        }
    }
    pub fn skip_remount_private(&mut self) {
        unsafe {
            libminijail::minijail_skip_remount_private(self.jail);
        }
    }
    pub fn namespace_ipc(&mut self) {
        unsafe {
            libminijail::minijail_namespace_ipc(self.jail);
        }
    }
    pub fn namespace_net(&mut self) {
        unsafe {
            libminijail::minijail_namespace_net(self.jail);
        }
    }
    pub fn namespace_cgroups(&mut self) {
        unsafe {
            libminijail::minijail_namespace_cgroups(self.jail);
        }
    }
    pub fn remount_proc_readonly(&mut self) {
        unsafe {
            libminijail::minijail_remount_proc_readonly(self.jail);
        }
    }
    pub fn uidmap(&mut self, uid_map: &str) -> Result<()> {
        let map_cstring =
            CString::new(uid_map).map_err(|_| Error::StrToCString(uid_map.to_owned()))?;
        unsafe {
            libminijail::minijail_uidmap(self.jail, map_cstring.as_ptr());
        }
        Ok(())
    }
    pub fn gidmap(&mut self, gid_map: &str) -> Result<()> {
        let map_cstring =
            CString::new(gid_map).map_err(|_| Error::StrToCString(gid_map.to_owned()))?;
        unsafe {
            libminijail::minijail_gidmap(self.jail, map_cstring.as_ptr());
        }
        Ok(())
    }
    pub fn inherit_usergroups(&mut self) {
        unsafe {
            libminijail::minijail_inherit_usergroups(self.jail);
        }
    }
    pub fn use_alt_syscall(&mut self, table_name: &str) -> Result<()> {
        let table_name_string =
            CString::new(table_name).map_err(|_| Error::StrToCString(table_name.to_owned()))?;
        let ret =
            unsafe { libminijail::minijail_use_alt_syscall(self.jail, table_name_string.as_ptr()) };
        if ret < 0 {
            return Err(Error::SetAltSyscallTable {
                errno: ret,
                name: table_name.to_owned(),
            });
        }
        Ok(())
    }
    pub fn enter_chroot(&mut self, dir: &Path) -> Result<()> {
        let pathstring = dir
            .as_os_str()
            .to_str()
            .ok_or(Error::PathToCString(dir.to_owned()))?;
        let dirname = CString::new(pathstring).map_err(|_| Error::PathToCString(dir.to_owned()))?;
        let ret = unsafe { libminijail::minijail_enter_chroot(self.jail, dirname.as_ptr()) };
        if ret < 0 {
            return Err(Error::SettingChrootDirectory(ret, dir.to_owned()));
        }
        Ok(())
    }
    pub fn enter_pivot_root(&mut self, dir: &Path) -> Result<()> {
        let pathstring = dir
            .as_os_str()
            .to_str()
            .ok_or(Error::PathToCString(dir.to_owned()))?;
        let dirname = CString::new(pathstring).map_err(|_| Error::PathToCString(dir.to_owned()))?;
        let ret = unsafe { libminijail::minijail_enter_pivot_root(self.jail, dirname.as_ptr()) };
        if ret < 0 {
            return Err(Error::SettingPivotRootDirectory(ret, dir.to_owned()));
        }
        Ok(())
    }
    pub fn mount(&mut self, src: &Path, dest: &Path, fstype: &str, flags: usize) -> Result<()> {
        self.mount_with_data(src, dest, fstype, flags, "")
    }
    pub fn mount_with_data(
        &mut self,
        src: &Path,
        dest: &Path,
        fstype: &str,
        flags: usize,
        data: &str,
    ) -> Result<()> {
        let src_os = src
            .as_os_str()
            .to_str()
            .ok_or(Error::PathToCString(src.to_owned()))?;
        let src_path = CString::new(src_os).map_err(|_| Error::StrToCString(src_os.to_owned()))?;
        let dest_os = dest
            .as_os_str()
            .to_str()
            .ok_or(Error::PathToCString(dest.to_owned()))?;
        let dest_path =
            CString::new(dest_os).map_err(|_| Error::StrToCString(dest_os.to_owned()))?;
        let fstype_string =
            CString::new(fstype).map_err(|_| Error::StrToCString(fstype.to_owned()))?;
        let data_string = CString::new(data).map_err(|_| Error::StrToCString(data.to_owned()))?;
        let ret = unsafe {
            libminijail::minijail_mount_with_data(
                self.jail,
                src_path.as_ptr(),
                dest_path.as_ptr(),
                fstype_string.as_ptr(),
                flags as _,
                data_string.as_ptr(),
            )
        };
        if ret < 0 {
            return Err(Error::Mount {
                errno: ret,
                src: src.to_owned(),
                dest: dest.to_owned(),
                fstype: fstype.to_owned(),
                flags,
                data: data.to_owned(),
            });
        }
        Ok(())
    }
    pub fn mount_dev(&mut self) {
        unsafe {
            libminijail::minijail_mount_dev(self.jail);
        }
    }
    pub fn mount_tmp(&mut self) {
        unsafe {
            libminijail::minijail_mount_tmp(self.jail);
        }
    }
    pub fn mount_tmp_size(&mut self, size: usize) {
        unsafe {
            libminijail::minijail_mount_tmp_size(self.jail, size);
        }
    }
    pub fn mount_bind(&mut self, src: &Path, dest: &Path, writable: bool) -> Result<()> {
        let src_os = src
            .as_os_str()
            .to_str()
            .ok_or(Error::PathToCString(src.to_owned()))?;
        let src_path = CString::new(src_os).map_err(|_| Error::StrToCString(src_os.to_owned()))?;
        let dest_os = dest
            .as_os_str()
            .to_str()
            .ok_or(Error::PathToCString(dest.to_owned()))?;
        let dest_path =
            CString::new(dest_os).map_err(|_| Error::StrToCString(dest_os.to_owned()))?;
        let ret = unsafe {
            libminijail::minijail_bind(
                self.jail,
                src_path.as_ptr(),
                dest_path.as_ptr(),
                writable as _,
            )
        };
        if ret < 0 {
            return Err(Error::BindMount {
                errno: ret,
                src: src.to_owned(),
                dst: dest.to_owned(),
            });
        }
        Ok(())
    }

    /// Forks and execs a child and puts it in the previously configured minijail.
    /// FDs 0, 1, and 2 are overwritten with /dev/null FDs unless they are included in the
    /// inheritable_fds list. This function may abort in the child on error because a partially
    /// entered jail isn't recoverable.
    pub fn run(&self, cmd: &Path, inheritable_fds: &[RawFd], args: &[&str]) -> Result<pid_t> {
        let cmd_os = cmd.to_str().ok_or(Error::PathToCString(cmd.to_owned()))?;
        let cmd_cstr = CString::new(cmd_os).map_err(|_| Error::StrToCString(cmd_os.to_owned()))?;

        // Converts each incoming `args` string to a `CString`, and then puts each `CString` pointer
        // into a null terminated array, suitable for use as an argv parameter to `execve`.
        let mut args_cstr = Vec::with_capacity(args.len());
        let mut args_array = Vec::with_capacity(args.len());
        for &arg in args {
            let arg_cstr = CString::new(arg).map_err(|_| Error::StrToCString(arg.to_owned()))?;
            args_array.push(arg_cstr.as_ptr());
            args_cstr.push(arg_cstr);
        }
        args_array.push(null());

        for fd in inheritable_fds {
            let ret = unsafe { libminijail::minijail_preserve_fd(self.jail, *fd, *fd) };
            if ret < 0 {
                return Err(Error::PreservingFd(ret));
            }
        }

        let dev_null = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .map_err(Error::OpenDevNull)?;
        // Set stdin, stdout, and stderr to /dev/null unless they are in the inherit list.
        // These will only be closed when this process exits.
        for io_fd in &[libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
            if !inheritable_fds.contains(io_fd) {
                let ret = unsafe {
                    libminijail::minijail_preserve_fd(self.jail, dev_null.as_raw_fd(), *io_fd)
                };
                if ret < 0 {
                    return Err(Error::PreservingFd(ret));
                }
            }
        }

        unsafe {
            libminijail::minijail_close_open_fds(self.jail);
        }

        let mut pid = 0;
        let ret = unsafe {
            libminijail::minijail_run_pid_pipes(
                self.jail,
                cmd_cstr.as_ptr(),
                args_array.as_ptr(),
                &mut pid,
                null_mut(),
                null_mut(),
                null_mut(),
            )
        };
        if ret < 0 {
            return Err(Error::ForkingMinijail(ret));
        }
        Ok(pid)
    }

    /// Forks a child and puts it in the previously configured minijail.
    /// `fork` is unsafe because it closes all open FD for this process.  That
    /// could cause a lot of trouble if not handled carefully.  FDs 0, 1, and 2
    /// are overwritten with /dev/null FDs unless they are included in the
    /// inheritable_fds list.
    /// This Function may abort in the child on error because a partially
    /// entered jail isn't recoverable.
    pub unsafe fn fork(&self, inheritable_fds: Option<&[RawFd]>) -> Result<pid_t> {
        if !is_single_threaded().map_err(Error::CheckingMultiThreaded)? {
            // This test will fail during `cargo test` because the test harness always spawns a test
            // thread. We will make an exception for that case because the tests for this module
            // should always be run in a serial fashion using `--test-threads=1`.
            #[cfg(not(test))]
            return Err(Error::ForkingWhileMultiThreaded);
        }

        if let Some(keep_fds) = inheritable_fds {
            for fd in keep_fds {
                let ret = libminijail::minijail_preserve_fd(self.jail, *fd, *fd);
                if ret < 0 {
                    return Err(Error::PreservingFd(ret));
                }
            }
        }

        let dev_null = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .map_err(Error::OpenDevNull)?;
        // Set stdin, stdout, and stderr to /dev/null unless they are in the inherit list.
        // These will only be closed when this process exits.
        for io_fd in &[libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
            if inheritable_fds.is_none() || !inheritable_fds.unwrap().contains(io_fd) {
                let ret =
                    libminijail::minijail_preserve_fd(self.jail, dev_null.as_raw_fd(), *io_fd);
                if ret < 0 {
                    return Err(Error::PreservingFd(ret));
                }
            }
        }

        libminijail::minijail_close_open_fds(self.jail);

        let ret = libminijail::minijail_fork(self.jail);
        if ret < 0 {
            return Err(Error::ForkingMinijail(ret));
        }
        Ok(ret as pid_t)
    }
}

impl Drop for Minijail {
    /// Frees the Minijail created in Minijail::new.
    fn drop(&mut self) {
        unsafe {
            // Destroys the minijail's memory.  It is safe to do here because all references to
            // this object have been dropped.
            libminijail::minijail_destroy(self.jail);
        }
    }
}

// Count the number of files in the directory specified by `path`.
fn count_dir_entries<P: AsRef<Path>>(path: P) -> io::Result<usize> {
    Ok(fs::read_dir(path)?.count())
}

// Return true if the current thread is the only thread in the process.
fn is_single_threaded() -> io::Result<bool> {
    match count_dir_entries("/proc/self/task") {
        Ok(1) => Ok(true),
        Ok(_) => Ok(false),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_free() {
        unsafe {
            let j = libminijail::minijail_new();
            assert_ne!(std::ptr::null_mut(), j);
            libminijail::minijail_destroy(j);
        }

        let j = Minijail::new().unwrap();
        drop(j);
    }

    #[test]
    // Test that setting a seccomp filter with no-new-privs works as non-root.
    // This is equivalent to minijail0 -n -S <seccomp_policy>
    fn seccomp_no_new_privs() {
        let mut j = Minijail::new().unwrap();
        j.no_new_privs();
        j.parse_seccomp_filters(Path::new("src/test_filter.policy"))
            .unwrap();
        j.use_seccomp_filter();
        unsafe {
            j.fork(None).unwrap();
        }
    }

    #[test]
    // Test that open FDs get closed and that FDs in the inherit list are left open.
    fn close_fds() {
        unsafe {
            // Using libc to open/close FDs for testing.
            const FILE_PATH: &[u8] = b"/dev/null\0";
            let j = Minijail::new().unwrap();
            let first = libc::open(FILE_PATH.as_ptr() as *const i8, libc::O_RDONLY);
            assert!(first >= 0);
            let second = libc::open(FILE_PATH.as_ptr() as *const i8, libc::O_RDONLY);
            assert!(second >= 0);
            let fds: Vec<RawFd> = vec![0, 1, 2, first];
            if j.fork(Some(&fds)).unwrap() == 0 {
                assert!(libc::close(second) < 0); // Should fail as second should be closed already.
                assert_eq!(libc::close(first), 0); // Should succeed as first should be untouched.
            }
        }
    }

    #[test]
    #[ignore] // privileged operation.
    fn chroot() {
        let mut j = Minijail::new().unwrap();
        j.enter_chroot(Path::new(".")).unwrap();
        unsafe {
            j.fork(None).unwrap();
        }
    }

    #[test]
    #[ignore] // privileged operation.
    fn namespace_vfs() {
        let mut j = Minijail::new().unwrap();
        j.namespace_vfs();
        unsafe {
            j.fork(None).unwrap();
        }
    }

    #[test]
    fn run() {
        let j = Minijail::new().unwrap();
        j.run(Path::new("/bin/true"), &[], &[]).unwrap();
    }
}
