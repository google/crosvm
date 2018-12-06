// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Small system utility modules for usage by other modules.

extern crate data_model;
extern crate libc;
extern crate syscall_defines;
#[allow(unused_imports)]
#[macro_use]
extern crate poll_token_derive;
extern crate sync;

#[macro_use]
pub mod handle_eintr;
#[macro_use]
pub mod ioctl;
#[macro_use]
pub mod syslog;
mod errno;
mod eventfd;
mod file_flags;
mod file_sync;
mod fork;
mod guest_address;
mod guest_memory;
mod mmap;
mod passwd;
mod poll;
mod priority;
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

use errno::errno_result;
pub use errno::{Error, Result};
pub use eventfd::*;
pub use file_flags::*;
pub use fork::*;
pub use guest_address::*;
pub use guest_memory::*;
pub use ioctl::*;
pub use mmap::*;
pub use passwd::*;
pub use poll::*;
pub use poll_token_derive::*;
pub use priority::*;
pub use shm::*;
pub use signal::*;
pub use signalfd::*;
pub use sock_ctrl_msg::*;
pub use struct_util::*;
pub use tempdir::*;
pub use terminal::*;
pub use timerfd::*;

pub use file_sync::FileSync;
pub use guest_memory::Error as GuestMemoryError;
pub use mmap::Error as MmapError;
pub use seek_hole::SeekHole;
pub use signalfd::Error as SignalFdError;
pub use write_zeroes::{PunchHole, WriteZeroes};

use std::ffi::CStr;
use std::fs::{remove_file, File};
use std::os::unix::io::{AsRawFd, FromRawFd};
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
pub fn flock(file: &AsRawFd, op: FlockOperation, nonblocking: bool) -> Result<()> {
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
    file: &AsRawFd,
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
/// # extern crate libc;
/// # extern crate sys_util;
/// fn reap_children() {
///     loop {
///         match sys_util::reap_child() {
///             Ok(0) => println!("no children ready to reap"),
///             Ok(pid) => {
///                 println!("reaped {}", pid);
///                 continue
///             },
///             Err(e) if e.errno() == libc::ECHILD => println!("no children left"),
///             Err(e) => println!("error reaping children: {:?}", e),
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
                    warn!("failed to remove control socket file: {:?}", e);
                }
            }
        }
    }
}
