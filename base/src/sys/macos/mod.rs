// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::CString;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::path::Path;

use crate::descriptor::AsRawDescriptor;
use crate::descriptor::FromRawDescriptor;
use crate::unix::set_descriptor_cloexec;
use crate::unix::Pid;

mod event;
pub mod ioctl;
pub(in crate::sys::macos) mod kqueue;
mod mmap;
mod net;
mod notifiers;
mod poll;
mod timer;
mod write_zeroes;

pub use mmap::*;
pub use poll::EventContext;
pub use write_zeroes::file_punch_hole;
pub use write_zeroes::file_write_zeroes_at;
pub(crate) use event::PlatformEvent;
pub(in crate::sys) use libc::sendmsg;
pub(in crate::sys) use net::sockaddr_un;
pub(in crate::sys) use net::sockaddrv4_to_lib_c;
pub(in crate::sys) use net::sockaddrv6_to_lib_c;

/// Sets the name of the current thread to the given name.
/// On macOS, pthread_setname_np only takes the name parameter (not a thread handle).
pub fn set_thread_name(name: &str) -> crate::errno::Result<()> {
    // macOS pthread_setname_np only takes a name, and sets it for the current thread
    let c_name = match CString::new(name) {
        Ok(n) => n,
        Err(_) => return Err(crate::errno::Error::new(libc::EINVAL)),
    };
    // SAFETY: pthread_setname_np is safe to call with a valid C string
    let ret = unsafe { libc::pthread_setname_np(c_name.as_ptr()) };
    if ret == 0 {
        Ok(())
    } else {
        Err(crate::errno::Error::new(ret))
    }
}

/// Gets the CPU affinity of the current thread.
/// macOS does not support CPU affinity in the same way as Linux.
/// We return an empty vector to indicate "any CPU".
pub fn get_cpu_affinity() -> crate::errno::Result<Vec<usize>> {
    // macOS doesn't support traditional CPU affinity like Linux.
    // Return an empty vector to indicate no specific affinity is set.
    Ok(Vec::new())
}

/// Gets the process ID of the current process.
pub fn getpid() -> Pid {
    // SAFETY: getpid is always safe to call
    unsafe { libc::getpid() }
}

/// Opens a file at the given path with the given options, or duplicates the file
/// descriptor if the path refers to /proc/self/fd/N.
pub fn open_file_or_duplicate<P: AsRef<Path>>(
    path: P,
    options: &OpenOptions,
) -> crate::Result<File> {
    // On macOS, we don't have /proc/self/fd, so just open the file normally
    options.open(path.as_ref()).map_err(crate::Error::from)
}

pub mod platform_timer_resolution {
    pub struct UnixSetTimerResolution {}
    impl crate::EnabledHighResTimer for UnixSetTimerResolution {}

    /// Enable high resolution timers. On macOS, this is effectively a no-op
    /// as macOS handles timer resolution automatically.
    pub fn enable_high_res_timers() -> crate::Result<Box<dyn crate::EnabledHighResTimer>> {
        Ok(Box::new(UnixSetTimerResolution {}))
    }
}

/// Sets the CPU affinity of the current thread.
/// macOS does not support CPU affinity in the same way as Linux.
/// This is a no-op that returns success.
pub fn set_cpu_affinity<I: IntoIterator<Item = usize>>(_cpus: I) -> crate::errno::Result<()> {
    // macOS doesn't support traditional CPU affinity like Linux.
    // The thread_policy_set API exists but has different semantics.
    // For now, we just return success as a no-op.
    Ok(())
}

pub mod syslog {
    /// PlatformSyslog for macOS.
    /// On macOS, we could use os_log, but for simplicity we'll just use stderr logging.
    pub struct PlatformSyslog {}

    impl crate::syslog::Syslog for PlatformSyslog {
        fn new(
            _proc_name: String,
            _facility: crate::syslog::Facility,
        ) -> Result<
            (
                Option<Box<dyn crate::syslog::Log + Send>>,
                Option<crate::RawDescriptor>,
            ),
            &'static crate::syslog::Error,
        > {
            // Return None to indicate no platform-specific logger
            // The logging system will fall back to the default logger
            Ok((None, None))
        }
    }
}

impl PartialEq for crate::SafeDescriptor {
    fn eq(&self, other: &Self) -> bool {
        // Compare file descriptors
        // Note: This compares the descriptor numbers, not whether they refer to the same file
        self.as_raw_descriptor() == other.as_raw_descriptor()
    }
}

impl crate::shm::PlatformSharedMemory for crate::SharedMemory {
    /// Creates a new shared memory object.
    /// On macOS, we use shm_open to create a POSIX shared memory object.
    fn new(debug_name: &std::ffi::CStr, size: u64) -> crate::Result<crate::SharedMemory> {
        use std::os::unix::io::FromRawFd;

        // Generate a unique name for the shared memory object.
        // macOS shm_open names are limited to 31 chars (PSHMNAMLEN),
        // so we use a compact format: /cvm-{pid}-{counter}
        use std::sync::atomic::{AtomicU32, Ordering};
        static SHM_COUNTER: AtomicU32 = AtomicU32::new(0);
        let name = format!(
            "/cvm-{}-{}",
            std::process::id(),
            SHM_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let c_name = CString::new(name.clone()).map_err(|_| crate::Error::new(libc::EINVAL))?;
        let _ = debug_name; // We use our own naming scheme

        // SAFETY: shm_open is safe with valid arguments
        let fd = unsafe {
            libc::shm_open(
                c_name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
                0o600,
            )
        };

        if fd < 0 {
            return Err(crate::Error::from(io::Error::last_os_error()));
        }

        // Immediately unlink so it will be cleaned up when all references are dropped
        // SAFETY: Safe with a valid name
        unsafe { libc::shm_unlink(c_name.as_ptr()) };

        // Set the size
        // SAFETY: fd is valid from shm_open
        let ret = unsafe { libc::ftruncate(fd, size as libc::off_t) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(crate::Error::from(err));
        }

        // Set close-on-exec
        // SAFETY: fd is valid
        let ret = unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(crate::Error::from(err));
        }

        // SAFETY: fd is valid and we own it
        let file = unsafe { File::from_raw_fd(fd) };
        let descriptor = crate::SafeDescriptor::from(file);

        Ok(crate::SharedMemory { descriptor, size })
    }

    /// Creates a SharedMemory from an existing descriptor.
    fn from_safe_descriptor(
        descriptor: crate::SafeDescriptor,
        size: u64,
    ) -> crate::Result<crate::SharedMemory> {
        Ok(crate::SharedMemory { descriptor, size })
    }
}

/// Returns the maximum frequency (in kHz) of a given logical core.
/// On macOS, we use sysctl to get the CPU max frequency.
pub fn logical_core_max_freq_khz(_cpu_id: usize) -> crate::errno::Result<u32> {
    // macOS doesn't expose per-core max frequency via sysctl in the same way.
    // Use hw.cpufrequency_max as an approximation (returns Hz, convert to kHz).
    let mut freq: u64 = 0;
    let mut size = std::mem::size_of::<u64>();
    let name = std::ffi::CString::new("hw.cpufrequency_max").unwrap();
    // SAFETY: sysctlbyname is safe with valid arguments
    let ret = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            &mut freq as *mut u64 as *mut libc::c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if ret < 0 {
        // Fallback: return a reasonable default
        Ok(2400000) // 2.4 GHz in kHz
    } else {
        Ok((freq / 1000) as u32)
    }
}

/// Returns a list of supported frequencies in kHz for a given logical core.
/// On macOS, we return just the max frequency since per-core frequency lists aren't available.
pub fn logical_core_frequencies_khz(cpu_id: usize) -> crate::errno::Result<Vec<u32>> {
    Ok(vec![logical_core_max_freq_khz(cpu_id)?])
}

/// Returns the capacity (measure of performance) of a given logical core.
/// On macOS, we return 1024 for all cores (full capacity).
pub fn logical_core_capacity(_cpu_id: usize) -> crate::errno::Result<u32> {
    Ok(1024)
}

/// Returns the cluster ID of a given logical core.
/// On macOS, we treat all cores as being in a single cluster.
pub fn logical_core_cluster_id(_cpu_id: usize) -> crate::errno::Result<u32> {
    Ok(0)
}

/// Returns whether the given CPU is online.
/// On macOS, all CPUs are always online (no hotplug).
pub fn is_cpu_online(_cpu_id: usize) -> crate::errno::Result<bool> {
    Ok(true)
}

pub(crate) use libc::off_t;
pub(crate) use libc::pread;
pub(crate) use libc::preadv;
pub(crate) use libc::pwrite;
pub(crate) use libc::pwritev;

/// This module provides the `lib` aliases used by file trait macros.
/// On macOS, off_t is already 64-bit so no `*64` variants are needed.
pub mod lib {
    pub use libc::off_t;
    pub use libc::pread;
    pub use libc::preadv;
    pub use libc::pwrite;
    pub use libc::pwritev;
}

use std::os::unix::io::AsRawFd;

use crate::FileAllocate;

impl FileAllocate for File {
    fn allocate(&self, offset: u64, len: u64) -> io::Result<()> {
        // On macOS, use fcntl with F_PREALLOCATE to allocate disk space.
        #[repr(C)]
        struct FStore {
            fst_flags: u32,
            fst_posmode: i32,
            fst_offset: libc::off_t,
            fst_length: libc::off_t,
            fst_bytesalloc: libc::off_t,
        }

        const F_PREALLOCATE: libc::c_int = 42;
        const F_ALLOCATECONTIG: u32 = 0x00000002;
        const F_ALLOCATEALL: u32 = 0x00000004;
        const F_PEOFPOSMODE: i32 = 3; // allocate from the physical end of file
        const F_VOLPOSMODE: i32 = 4; // allocate from the volume offset

        let _ = F_ALLOCATECONTIG;
        let _ = F_PEOFPOSMODE;

        let mut fstore = FStore {
            fst_flags: F_ALLOCATEALL,
            fst_posmode: F_VOLPOSMODE,
            fst_offset: offset as libc::off_t,
            fst_length: len as libc::off_t,
            fst_bytesalloc: 0,
        };

        // SAFETY: The file descriptor is valid and the fstore structure is properly initialized.
        let ret = unsafe {
            libc::fcntl(
                self.as_raw_fd(),
                F_PREALLOCATE,
                &mut fstore as *mut FStore,
            )
        };

        if ret < 0 {
            // F_PREALLOCATE can fail on some file systems; fall back to ftruncate
            // to extend the file if needed.
            let current_len = self.metadata()?.len();
            let required_len = offset + len;
            if required_len > current_len {
                // SAFETY: ftruncate is safe with a valid fd
                let ret =
                    unsafe { libc::ftruncate(self.as_raw_fd(), required_len as libc::off_t) };
                if ret < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            return Ok(());
        }

        // After F_PREALLOCATE, we also need to extend the file size if needed,
        // because F_PREALLOCATE only reserves space but doesn't change the file size.
        let current_len = self.metadata()?.len();
        let required_len = offset + len;
        if required_len > current_len {
            // SAFETY: ftruncate is safe with a valid fd
            let ret = unsafe { libc::ftruncate(self.as_raw_fd(), required_len as libc::off_t) };
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        Ok(())
    }
}

/// File locking operations.
#[derive(Copy, Clone, Debug)]
pub enum FlockOperation {
    /// Acquire a shared (read) lock.
    LockShared,
    /// Acquire an exclusive (write) lock.
    LockExclusive,
    /// Release the lock.
    Unlock,
}

/// Apply a file lock operation using flock(2).
/// macOS supports POSIX flock natively.
pub fn flock<F: crate::AsRawDescriptor>(
    file: &F,
    op: FlockOperation,
    nonblocking: bool,
) -> crate::errno::Result<()> {
    let mut operation = match op {
        FlockOperation::LockShared => libc::LOCK_SH,
        FlockOperation::LockExclusive => libc::LOCK_EX,
        FlockOperation::Unlock => libc::LOCK_UN,
    };

    if nonblocking {
        operation |= libc::LOCK_NB;
    }

    // SAFETY: The descriptor is valid and flock is safe to call.
    let ret = unsafe { libc::flock(file.as_raw_descriptor(), operation) };
    if ret < 0 {
        crate::errno::errno_result()
    } else {
        Ok(())
    }
}

/// Spawns a pipe pair where the first pipe is the read end and the second pipe is the write end.
///
/// The `O_CLOEXEC` flag will be applied after pipe creation.
pub fn pipe() -> crate::errno::Result<(File, File)> {
    let mut pipe_fds = [-1; 2];
    // SAFETY:
    // Safe because pipe will only write 2 element array of i32 to the given pointer, and we check
    // for error.
    let ret = unsafe { libc::pipe(pipe_fds.as_mut_ptr()) };
    if ret == -1 {
        return crate::errno::errno_result();
    }

    // SAFETY:
    // Safe because both fds must be valid for pipe to have returned sucessfully and we have
    // exclusive ownership of them.
    let pipes = unsafe {
        (
            File::from_raw_descriptor(pipe_fds[0]),
            File::from_raw_descriptor(pipe_fds[1]),
        )
    };

    set_descriptor_cloexec(&pipes.0)?;
    set_descriptor_cloexec(&pipes.1)?;

    Ok(pipes)
}
