// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Small system utility modules for usage by other modules.

pub mod affinity;
mod alloc;
#[macro_use]
pub mod handle_eintr;
#[macro_use]
pub mod ioctl;
#[macro_use]
pub mod syslog;
mod capabilities;
mod clock;
mod errno;
mod eventfd;
mod file_flags;
mod file_traits;
mod fork;
mod guest_address;
pub mod guest_memory;
mod mmap;
pub mod net;
mod passwd;
mod poll;
mod priority;
mod raw_fd;
mod seek_hole;
mod shm;
pub mod signal;
mod signalfd;
mod sock_ctrl_msg;
mod struct_util;
mod tempdir;
mod terminal;
mod timerfd;
mod write_zeroes;

pub use crate::affinity::*;
pub use crate::alloc::LayoutAllocation;
pub use crate::capabilities::drop_capabilities;
pub use crate::clock::{Clock, FakeClock};
use crate::errno::errno_result;
pub use crate::errno::{Error, Result};
pub use crate::eventfd::*;
pub use crate::file_flags::*;
pub use crate::fork::*;
pub use crate::guest_address::*;
pub use crate::guest_memory::*;
pub use crate::ioctl::*;
pub use crate::mmap::*;
pub use crate::passwd::*;
pub use crate::poll::*;
pub use crate::priority::*;
pub use crate::raw_fd::*;
pub use crate::shm::*;
pub use crate::signal::*;
pub use crate::signalfd::*;
pub use crate::sock_ctrl_msg::*;
pub use crate::struct_util::*;
pub use crate::tempdir::*;
pub use crate::terminal::*;
pub use crate::timerfd::*;
pub use poll_token_derive::*;

pub use crate::file_traits::{FileReadWriteVolatile, FileSetLen, FileSync};
pub use crate::guest_memory::Error as GuestMemoryError;
pub use crate::mmap::Error as MmapError;
pub use crate::seek_hole::SeekHole;
pub use crate::signalfd::Error as SignalFdError;
pub use crate::write_zeroes::{PunchHole, WriteZeroes};

use std::ffi::CStr;
use std::fs::{remove_file, File};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixDatagram;
use std::ptr;

use libc::{
    c_long, gid_t, kill, pid_t, pipe2, syscall, sysconf, uid_t, waitpid, O_CLOEXEC, SIGKILL,
    WNOHANG, _SC_PAGESIZE,
};

use syscall_defines::linux::LinuxSyscall::SYS_getpid;

/// Safe wrapper for `sysconf(_SC_PAGESIZE)`.
#[inline(always)]
pub fn pagesize() -> usize {
    // Trivially safe
    unsafe { sysconf(_SC_PAGESIZE) as usize }
}

/// Uses the system's page size in bytes to round the given value up to the nearest page boundary.
#[inline(always)]
pub fn round_up_to_page_size(v: usize) -> usize {
    let page_mask = pagesize() - 1;
    (v + page_mask) & !page_mask
}

/// This bypasses `libc`'s caching `getpid(2)` wrapper which can be invalid if a raw clone was used
/// elsewhere.
#[inline(always)]
pub fn getpid() -> pid_t {
    // Safe because this syscall can never fail and we give it a valid syscall number.
    unsafe { syscall(SYS_getpid as c_long) as pid_t }
}

/// Safe wrapper for `geteuid(2)`.
#[inline(always)]
pub fn geteuid() -> uid_t {
    // trivially safe
    unsafe { libc::geteuid() }
}

/// Safe wrapper for `getegid(2)`.
#[inline(always)]
pub fn getegid() -> gid_t {
    // trivially safe
    unsafe { libc::getegid() }
}

/// Safe wrapper for chown(2).
#[inline(always)]
pub fn chown(path: &CStr, uid: uid_t, gid: gid_t) -> Result<()> {
    // Safe since we pass in a valid string pointer and check the return value.
    let ret = unsafe { libc::chown(path.as_ptr(), uid, gid) };

    if ret < 0 {
        errno_result()
    } else {
        Ok(())
    }
}

/// The operation to perform with `flock`.
pub enum FlockOperation {
    LockShared,
    LockExclusive,
    Unlock,
}

/// Safe wrapper for flock(2) with the operation `op` and optionally `nonblocking`. The lock will be
/// dropped automatically when `file` is dropped.
#[inline(always)]
pub fn flock(file: &dyn AsRawFd, op: FlockOperation, nonblocking: bool) -> Result<()> {
    let mut operation = match op {
        FlockOperation::LockShared => libc::LOCK_SH,
        FlockOperation::LockExclusive => libc::LOCK_EX,
        FlockOperation::Unlock => libc::LOCK_UN,
    };

    if nonblocking {
        operation |= libc::LOCK_NB;
    }

    // Safe since we pass in a valid fd and flock operation, and check the return value.
    let ret = unsafe { libc::flock(file.as_raw_fd(), operation) };

    if ret < 0 {
        errno_result()
    } else {
        Ok(())
    }
}

/// The operation to perform with `fallocate`.
pub enum FallocateMode {
    PunchHole,
    ZeroRange,
}

/// Safe wrapper for `fallocate()`.
pub fn fallocate(
    file: &dyn AsRawFd,
    mode: FallocateMode,
    keep_size: bool,
    offset: u64,
    len: u64,
) -> Result<()> {
    let offset = if offset > libc::off64_t::max_value() as u64 {
        return Err(Error::new(libc::EINVAL));
    } else {
        offset as libc::off64_t
    };

    let len = if len > libc::off64_t::max_value() as u64 {
        return Err(Error::new(libc::EINVAL));
    } else {
        len as libc::off64_t
    };

    let mut mode = match mode {
        FallocateMode::PunchHole => libc::FALLOC_FL_PUNCH_HOLE,
        FallocateMode::ZeroRange => libc::FALLOC_FL_ZERO_RANGE,
    };

    if keep_size {
        mode |= libc::FALLOC_FL_KEEP_SIZE;
    }

    // Safe since we pass in a valid fd and fallocate mode, validate offset and len,
    // and check the return value.
    let ret = unsafe { libc::fallocate64(file.as_raw_fd(), mode, offset, len) };
    if ret < 0 {
        errno_result()
    } else {
        Ok(())
    }
}

/// Reaps a child process that has terminated.
///
/// Returns `Ok(pid)` where `pid` is the process that was reaped or `Ok(0)` if none of the children
/// have terminated. An `Error` is with `errno == ECHILD` if there are no children left to reap.
///
/// # Examples
///
/// Reaps all child processes until there are no terminated children to reap.
///
/// ```
/// fn reap_children() {
///     loop {
///         match sys_util::reap_child() {
///             Ok(0) => println!("no children ready to reap"),
///             Ok(pid) => {
///                 println!("reaped {}", pid);
///                 continue
///             },
///             Err(e) if e.errno() == libc::ECHILD => println!("no children left"),
///             Err(e) => println!("error reaping children: {}", e),
///         }
///         break
///     }
/// }
/// ```
pub fn reap_child() -> Result<pid_t> {
    // Safe because we pass in no memory, prevent blocking with WNOHANG, and check for error.
    let ret = unsafe { waitpid(-1, ptr::null_mut(), WNOHANG) };
    if ret == -1 {
        errno_result()
    } else {
        Ok(ret)
    }
}

/// Kill all processes in the current process group.
///
/// On success, this kills all processes in the current process group, including the current
/// process, meaning this will not return. This is equivalent to a call to `kill(0, SIGKILL)`.
pub fn kill_process_group() -> Result<()> {
    let ret = unsafe { kill(0, SIGKILL) };
    if ret == -1 {
        errno_result()
    } else {
        // Kill succeeded, so this process never reaches here.
        unreachable!();
    }
}

/// Spawns a pipe pair where the first pipe is the read end and the second pipe is the write end.
///
/// If `close_on_exec` is true, the `O_CLOEXEC` flag will be set during pipe creation.
pub fn pipe(close_on_exec: bool) -> Result<(File, File)> {
    let flags = if close_on_exec { O_CLOEXEC } else { 0 };
    let mut pipe_fds = [-1; 2];
    // Safe because pipe2 will only write 2 element array of i32 to the given pointer, and we check
    // for error.
    let ret = unsafe { pipe2(&mut pipe_fds[0], flags) };
    if ret == -1 {
        errno_result()
    } else {
        // Safe because both fds must be valid for pipe2 to have returned sucessfully and we have
        // exclusive ownership of them.
        Ok(unsafe {
            (
                File::from_raw_fd(pipe_fds[0]),
                File::from_raw_fd(pipe_fds[1]),
            )
        })
    }
}

/// Used to attempt to clean up a named pipe after it is no longer used.
pub struct UnlinkUnixDatagram(pub UnixDatagram);
impl AsRef<UnixDatagram> for UnlinkUnixDatagram {
    fn as_ref(&self) -> &UnixDatagram {
        &self.0
    }
}
impl Drop for UnlinkUnixDatagram {
    fn drop(&mut self) {
        if let Ok(addr) = self.0.local_addr() {
            if let Some(path) = addr.as_pathname() {
                if let Err(e) = remove_file(path) {
                    warn!("failed to remove control socket file: {}", e);
                }
            }
        }
    }
}

/// Verifies that |raw_fd| is actually owned by this process and duplicates it to ensure that
/// we have a unique handle to it.
pub fn validate_raw_fd(raw_fd: RawFd) -> Result<RawFd> {
    // Checking that close-on-exec isn't set helps filter out FDs that were opened by
    // crosvm as all crosvm FDs are close on exec.
    // Safe because this doesn't modify any memory and we check the return value.
    let flags = unsafe { libc::fcntl(raw_fd, libc::F_GETFD) };
    if flags < 0 || (flags & libc::FD_CLOEXEC) != 0 {
        return Err(Error::new(libc::EBADF));
    }

    // Duplicate the fd to ensure that we don't accidentally close an fd previously
    // opened by another subsystem.  Safe because this doesn't modify any memory and
    // we check the return value.
    let dup_fd = unsafe { libc::fcntl(raw_fd, libc::F_DUPFD_CLOEXEC, 0) };
    if dup_fd < 0 {
        return Err(Error::last());
    }
    Ok(dup_fd as RawFd)
}
