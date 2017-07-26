// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

extern crate libc;

#[allow(dead_code)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
mod libminijail;

use std::ffi::CString;
use std::fs;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;
use std::str::FromStr;

#[derive(Debug)]
pub enum Error {
    // minijail failed to accept bind mount.
    BindMount(i32),
    /// minjail_new failed, this is an allocation failure.
    CreatingMinijail,
    /// The path doesn't exist.
    InvalidPath,
    /// The path or name string passed in didn't parse to a valid CString.
    InvalidCString,
    /// Failed to call dup2 to set stdin, stdout, or stderr to /dev/null.
    DupDevNull(i32),
    /// Failed to set up /dev/null for FDs 0, 1, or 2.
    OpenDevNull(std::io::Error),
    /// Setting the specified alt-syscall table failed with errno. Is the table in the kernel?
    SetAltSyscallTable(i32),
    /// chroot failed with the provided errno.
    SettingChrootDirectory(i32),
    /// pivot_root failed with the provided errno.
    SettingPivotRootDirectory(i32),
    /// There is an entry in /proc/self/fd that isn't a valid PID.
    ReadFdDirEntry,
    /// /proc/self/fd failed to open.
    ReadFdDir,
}
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
///       unsafe { // Enter will close all the programs FDs.
///           j.enter(None).map_err(|_| ())?;
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
///       unsafe { // Enter will close all the programs FDs.
///           j.enter(Some(&preserve_fds)).map_err(|_| ())?;
///       }
/// #     Ok(())
/// # }
/// ```
/// # Errors
/// The `enter` function doesn't return an error. Instead, It kills the current
/// process on error.
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
        unsafe { libminijail::minijail_change_uid(self.jail, uid); }
    }
    pub fn change_gid(&mut self, gid: libc::gid_t) {
        unsafe { libminijail::minijail_change_gid(self.jail, gid); }
    }
    pub fn set_supplementary_gids(&mut self, ids: &[libc::gid_t]) {
        unsafe { libminijail::minijail_set_supplementary_gids(self.jail, ids.len(), ids.as_ptr()); }
    }
    pub fn keep_supplementary_gids(&mut self) {
        unsafe { libminijail::minijail_keep_supplementary_gids(self.jail); }
    }
    pub fn use_seccomp(&mut self) {
        unsafe { libminijail::minijail_use_seccomp(self.jail); }
    }
    pub fn no_new_privs(&mut self) {
        unsafe { libminijail::minijail_no_new_privs(self.jail); }
    }
    pub fn use_seccomp_filter(&mut self) {
        unsafe { libminijail::minijail_use_seccomp_filter(self.jail); }
    }
    pub fn set_seccomp_filter_tsync(&mut self) {
        unsafe { libminijail::minijail_set_seccomp_filter_tsync(self.jail); }
    }
    pub fn parse_seccomp_filters(&mut self, path: &Path) -> Result<()> {
        if !path.is_file() {
            return Err(Error::InvalidPath);
        }

        let pathstring = path.as_os_str().to_str().ok_or(Error::InvalidCString)?;
        let filename = CString::new(pathstring).map_err(|_| Error::InvalidCString)?;
        unsafe {
            libminijail::minijail_parse_seccomp_filters(self.jail, filename.as_ptr());
        }
        Ok(())
    }
    pub fn log_seccomp_filter_failures(&mut self) {
        unsafe { libminijail::minijail_log_seccomp_filter_failures(self.jail); }
    }
    pub fn use_caps(&mut self, capmask: u64) {
        unsafe { libminijail::minijail_use_caps(self.jail, capmask); }
    }
    pub fn capbset_drop(&mut self, capmask: u64) {
        unsafe { libminijail::minijail_capbset_drop(self.jail, capmask); }
    }
    pub fn set_ambient_caps(&mut self) {
        unsafe { libminijail::minijail_set_ambient_caps(self.jail); }
    }
    pub fn reset_signal_mask(&mut self) {
        unsafe { libminijail::minijail_reset_signal_mask(self.jail); }
    }
    pub fn namespace_vfs(&mut self) {
        unsafe { libminijail::minijail_namespace_vfs(self.jail); }
    }
    pub fn new_session_keyring(&mut self) {
        unsafe { libminijail::minijail_new_session_keyring(self.jail); }
    }
    pub fn skip_remount_private(&mut self) {
        unsafe { libminijail::minijail_skip_remount_private(self.jail); }
    }
    pub fn namespace_ipc(&mut self) {
        unsafe { libminijail::minijail_namespace_ipc(self.jail); }
    }
    pub fn namespace_net(&mut self) {
        unsafe { libminijail::minijail_namespace_net(self.jail); }
    }
    pub fn namespace_cgroups(&mut self) {
        unsafe { libminijail::minijail_namespace_cgroups(self.jail); }
    }
    pub fn remount_proc_readonly(&mut self) {
        unsafe { libminijail::minijail_remount_proc_readonly(self.jail); }
    }
    pub fn inherit_usergroups(&mut self) {
        unsafe { libminijail::minijail_inherit_usergroups(self.jail); }
    }
    pub fn use_alt_syscall(&mut self, table_name: &str) -> Result<()> {
        let table_name_string = CString::new(table_name)
                .map_err(|_| Error::InvalidCString)?;
        let ret = unsafe {
            libminijail::minijail_use_alt_syscall(self.jail, table_name_string.as_ptr())
        };
        if ret < 0 {
            return Err(Error::SetAltSyscallTable(ret));
        }
        Ok(())
    }
    pub fn enter_chroot(&mut self, dir: &Path) -> Result<()> {
        let pathstring = dir.as_os_str().to_str().ok_or(Error::InvalidCString)?;
        let dirname = CString::new(pathstring).map_err(|_| Error::InvalidCString)?;
        let ret = unsafe { libminijail::minijail_enter_chroot(self.jail, dirname.as_ptr()) };
        if ret < 0 {
            return Err(Error::SettingChrootDirectory(ret));
        }
        Ok(())
    }
    pub fn enter_pivot_root(&mut self, dir: &Path) -> Result<()> {
        let pathstring = dir.as_os_str().to_str().ok_or(Error::InvalidCString)?;
        let dirname = CString::new(pathstring).map_err(|_| Error::InvalidCString)?;
        let ret = unsafe { libminijail::minijail_enter_pivot_root(self.jail, dirname.as_ptr()) };
        if ret < 0 {
            return Err(Error::SettingPivotRootDirectory(ret));
        }
        Ok(())
    }
    pub fn mount_tmp(&mut self) {
        unsafe { libminijail::minijail_mount_tmp(self.jail); }
    }
    pub fn mount_tmp_size(&mut self, size: usize) {
        unsafe { libminijail::minijail_mount_tmp_size(self.jail, size); }
    }
    pub fn mount_bind(&mut self, src: &Path, dest: &Path, writable: bool) -> Result<()> {
        let src = src.as_os_str().to_str().ok_or(Error::InvalidCString)?;
        let src = CString::new(src).map_err(|_| Error::InvalidCString)?;
        let dest = dest.as_os_str().to_str().ok_or(Error::InvalidCString)?;
        let dest = CString::new(dest).map_err(|_| Error::InvalidCString)?;
        let ret = unsafe { libminijail::minijail_bind(self.jail, src.as_ptr(), dest.as_ptr(), writable as _) };
        if ret < 0 {
            return Err(Error::BindMount(ret));
        }
        Ok(())
    }

    /// Enters the previously configured minijail.
    /// `enter` is unsafe because it closes all open FD for this process.  That
    /// could cause a lot of trouble if not handled carefully.  FDs 0, 1, and 2
    /// are overwritten with /dev/null FDs unless they are included in the
    /// inheritable_fds list.
    /// This Function may abort on error because a partially entered jail isn't
    /// recoverable.
    pub unsafe fn enter(&self, inheritable_fds: Option<&[RawFd]>) -> Result<()> {
        if let Some(keep_fds) = inheritable_fds {
            self.close_open_fds(keep_fds)?;
        }
        libminijail::minijail_enter(self.jail);
        Ok(())
    }

    // Closing all open FDs could be unsafe if something is relying on an FD
    // that is closed unexpectedly.  It is safe as long as it is called
    // immediately after forking and all needed FDs are in `inheritable_fds`.
    unsafe fn close_open_fds(&self, inheritable_fds: &[RawFd]) -> Result<()> {
        const FD_PATH: &'static str = "/proc/self/fd";
        let mut fds_to_close: Vec<RawFd> = Vec::new();
        for entry in fs::read_dir(FD_PATH).map_err(|_| Error::ReadFdDir)? {
            let dir_entry = entry.map_err(|_| Error::ReadFdDirEntry)?;
            let name_path = dir_entry.path();
            let name = name_path.strip_prefix(FD_PATH)
                    .map_err(|_| Error::InvalidCString)?;
            let name_str = name.to_str().ok_or(Error::InvalidCString)?;
            let fd = <i32>::from_str(name_str).map_err(|_| Error::InvalidCString)?;
            if !inheritable_fds.contains(&fd) {
                fds_to_close.push(fd);
            }
        }
        for fd in fds_to_close {
            // Note that this will also close the DIR fd used to read the
            // directory, that FD was already closed.  Closing it again will
            // return an error but won't break anything.
            libc::close(fd);
        }
        // Set stdin, stdout, and stderr to /dev/null unless they are in the inherit list.
        // These will only be closed when this process exits.
        let dev_null = fs::File::open("/dev/null").map_err(Error::OpenDevNull)?;
        for io_fd in &[libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
            if !inheritable_fds.contains(io_fd) {
                let ret = libc::dup2(dev_null.as_raw_fd(), *io_fd);
                if ret < 0 {
                    return Err(Error::DupDevNull(*libc::__errno_location()));
                }
            }
        }
        Ok(())
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
        j.parse_seccomp_filters(Path::new("src/test_filter.policy")).unwrap();
        j.use_seccomp_filter();
        unsafe {
            j.enter(None).unwrap();
        }
    }

    #[test]
    // Test that open FDs get closed and that FDs in the inherit list are left open.
    fn close_fds() {
        unsafe { // Using libc to open/close FDs for testing.
            const FILE_PATH: &'static str = "/dev/null";
            let j = Minijail::new().unwrap();
            let first = libc::open(FILE_PATH.as_ptr() as *const i8, libc::O_RDONLY);
            assert!(first >= 0);
            let second = libc::open(FILE_PATH.as_ptr() as *const i8, libc::O_RDONLY);
            assert!(second >= 0);
            let fds: Vec<RawFd> = vec![0, 1, 2, first];
            j.enter(Some(&fds)).unwrap();
            assert!(libc::close(second) < 0); // Should fail as second should be closed already.
            assert_eq!(libc::close(first), 0); // Should succeed as first should be untouched.
        }
    }

    #[test]
    #[ignore] // privileged operation.
    fn chroot() {
        let mut j = Minijail::new().unwrap();
        j.enter_chroot(Path::new(".")).unwrap();
        unsafe {
            j.enter(None).unwrap();
        }
    }

    #[test]
    #[ignore] // privileged operation.
    fn namespace_vfs() {
        let mut j = Minijail::new().unwrap();
        j.namespace_vfs();
        unsafe {
            j.enter(None).unwrap();
        }
    }
}
