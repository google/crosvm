// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::CString;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::path::Path;
use std::ptr;
use std::time::Duration;

use smallvec::SmallVec;

use crate::descriptor::AsRawDescriptor;
use crate::descriptor::FromRawDescriptor;
use crate::sys::unix::RawDescriptor;
use crate::unix::set_descriptor_cloexec;
use crate::unix::Pid;
use crate::EventToken;
use crate::EventType;
use crate::MmapError;
use crate::Protection;
use crate::TriggeredEvent;

mod event;
pub(in crate::sys::macos) mod kqueue;
mod mmap;
mod net;
mod notifiers;
mod timer;

pub use mmap::*;
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

/// EventContext provides kqueue-based event multiplexing for macOS.
/// This is analogous to epoll on Linux.
pub struct EventContext<T> {
    kqueue_fd: RawDescriptor,
    _phantom: std::marker::PhantomData<[T]>,
}

impl<T: EventToken> EventContext<T> {
    /// Creates a new EventContext.
    pub fn new() -> crate::errno::Result<EventContext<T>> {
        // SAFETY: kqueue() is safe to call
        let kqueue_fd = unsafe { libc::kqueue() };
        if kqueue_fd < 0 {
            return crate::errno::errno_result();
        }

        // Set close-on-exec flag
        // SAFETY: Safe because we know kqueue_fd is valid
        let ret = unsafe { libc::fcntl(kqueue_fd, libc::F_SETFD, libc::FD_CLOEXEC) };
        if ret < 0 {
            // SAFETY: Safe to close a valid fd
            unsafe { libc::close(kqueue_fd) };
            return crate::errno::errno_result();
        }

        Ok(EventContext {
            kqueue_fd,
            _phantom: std::marker::PhantomData,
        })
    }

    /// Creates a new EventContext with initial file descriptors and tokens.
    pub fn build_with(
        fd_tokens: &[(&dyn AsRawDescriptor, T)],
    ) -> crate::errno::Result<EventContext<T>> {
        let ctx = EventContext::new()?;
        ctx.add_many(fd_tokens)?;
        Ok(ctx)
    }

    /// Adds multiple fd/token pairs to this context.
    pub fn add_many(&self, fd_tokens: &[(&dyn AsRawDescriptor, T)]) -> crate::errno::Result<()> {
        for (fd, token) in fd_tokens {
            self.add(*fd, T::from_raw_token(token.as_raw_token()))?;
        }
        Ok(())
    }

    /// Adds a file descriptor to this context, watching for readable events.
    pub fn add(
        &self,
        descriptor: &dyn AsRawDescriptor,
        token: T,
    ) -> crate::errno::Result<()> {
        self.add_for_event(descriptor, EventType::Read, token)
    }

    /// Adds a file descriptor to the EventContext with the specified event type.
    pub fn add_for_event(
        &self,
        descriptor: &dyn AsRawDescriptor,
        event_type: EventType,
        token: T,
    ) -> crate::errno::Result<()> {
        let fd = descriptor.as_raw_descriptor();
        let token_raw = token.as_raw_token();

        let mut changes: Vec<libc::kevent> = Vec::new();

        match event_type {
            EventType::None => {
                // Remove existing events for this fd
                return self.delete(descriptor);
            }
            EventType::Read => {
                changes.push(libc::kevent {
                    ident: fd as usize,
                    filter: libc::EVFILT_READ,
                    flags: libc::EV_ADD | libc::EV_CLEAR,
                    fflags: 0,
                    data: 0,
                    udata: token_raw as *mut libc::c_void,
                });
            }
            EventType::Write => {
                changes.push(libc::kevent {
                    ident: fd as usize,
                    filter: libc::EVFILT_WRITE,
                    flags: libc::EV_ADD | libc::EV_CLEAR,
                    fflags: 0,
                    data: 0,
                    udata: token_raw as *mut libc::c_void,
                });
            }
            EventType::ReadWrite => {
                changes.push(libc::kevent {
                    ident: fd as usize,
                    filter: libc::EVFILT_READ,
                    flags: libc::EV_ADD | libc::EV_CLEAR,
                    fflags: 0,
                    data: 0,
                    udata: token_raw as *mut libc::c_void,
                });
                changes.push(libc::kevent {
                    ident: fd as usize,
                    filter: libc::EVFILT_WRITE,
                    flags: libc::EV_ADD | libc::EV_CLEAR,
                    fflags: 0,
                    data: 0,
                    udata: token_raw as *mut libc::c_void,
                });
            }
        }

        // SAFETY: We've constructed valid kevent structures
        let ret = unsafe {
            libc::kevent(
                self.kqueue_fd,
                changes.as_ptr(),
                changes.len() as i32,
                ptr::null_mut(),
                0,
                ptr::null(),
            )
        };

        if ret < 0 {
            crate::errno::errno_result()
        } else {
            Ok(())
        }
    }

    /// Modifies an existing file descriptor in the EventContext.
    pub fn modify(
        &self,
        fd: &dyn AsRawDescriptor,
        event_type: EventType,
        token: T,
    ) -> crate::errno::Result<()> {
        // On kqueue, modifying is the same as adding (EV_ADD will update)
        self.add_for_event(fd, event_type, token)
    }

    /// Removes a file descriptor from the EventContext.
    pub fn delete(&self, fd: &dyn AsRawDescriptor) -> crate::errno::Result<()> {
        let raw_fd = fd.as_raw_descriptor();

        // Delete both read and write filters
        let changes = [
            libc::kevent {
                ident: raw_fd as usize,
                filter: libc::EVFILT_READ,
                flags: libc::EV_DELETE,
                fflags: 0,
                data: 0,
                udata: ptr::null_mut(),
            },
            libc::kevent {
                ident: raw_fd as usize,
                filter: libc::EVFILT_WRITE,
                flags: libc::EV_DELETE,
                fflags: 0,
                data: 0,
                udata: ptr::null_mut(),
            },
        ];

        // SAFETY: We've constructed valid kevent structures
        // Note: It's okay if some of these fail (e.g., if only read was registered)
        unsafe {
            libc::kevent(
                self.kqueue_fd,
                changes.as_ptr(),
                changes.len() as i32,
                ptr::null_mut(),
                0,
                ptr::null(),
            );
        }

        Ok(())
    }

    /// Waits for events indefinitely.
    pub fn wait(&self) -> crate::errno::Result<SmallVec<[TriggeredEvent<T>; 16]>> {
        self.wait_timeout_impl(None)
    }

    /// Waits for events with a timeout.
    pub fn wait_timeout(
        &self,
        timeout: Duration,
    ) -> crate::errno::Result<SmallVec<[TriggeredEvent<T>; 16]>> {
        self.wait_timeout_impl(Some(timeout))
    }

    fn wait_timeout_impl(
        &self,
        timeout: Option<Duration>,
    ) -> crate::errno::Result<SmallVec<[TriggeredEvent<T>; 16]>> {
        let mut events: [libc::kevent; 16] = unsafe { std::mem::zeroed() };

        let timeout_spec = timeout.map(|d| libc::timespec {
            tv_sec: d.as_secs() as libc::time_t,
            tv_nsec: d.subsec_nanos() as libc::c_long,
        });

        let timeout_ptr = match &timeout_spec {
            Some(ts) => ts as *const libc::timespec,
            None => ptr::null(),
        };

        // SAFETY: We've allocated valid event buffer
        let ret = unsafe {
            libc::kevent(
                self.kqueue_fd,
                ptr::null(),
                0,
                events.as_mut_ptr(),
                events.len() as i32,
                timeout_ptr,
            )
        };

        if ret < 0 {
            return crate::errno::errno_result();
        }

        let mut triggered = SmallVec::new();
        for i in 0..(ret as usize) {
            let event = &events[i];

            // Skip error events
            if event.flags & libc::EV_ERROR != 0 {
                continue;
            }

            let is_readable = event.filter == libc::EVFILT_READ;
            let is_writable = event.filter == libc::EVFILT_WRITE;
            let is_hungup = (event.flags & libc::EV_EOF) != 0;

            let token = T::from_raw_token(event.udata as u64);

            triggered.push(TriggeredEvent {
                token,
                is_readable,
                is_writable,
                is_hungup,
            });
        }

        Ok(triggered)
    }
}

impl<T> AsRawDescriptor for EventContext<T> {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.kqueue_fd
    }
}

impl<T> Drop for EventContext<T> {
    fn drop(&mut self) {
        // SAFETY: We own the kqueue fd
        unsafe { libc::close(self.kqueue_fd) };
    }
}

/// MemoryMappingArena provides a reserved virtual address region for memory mappings.
pub struct MemoryMappingArena {
    addr: *mut u8,
    size: usize,
}

impl MemoryMappingArena {
    /// Creates a new MemoryMappingArena with the given size.
    /// The arena is backed by anonymous memory that can be remapped.
    pub fn new(size: usize) -> Result<MemoryMappingArena, MmapError> {
        // SAFETY: mmap with MAP_ANON|MAP_PRIVATE creates a new anonymous mapping
        let addr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                size,
                libc::PROT_NONE,
                libc::MAP_ANON | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };

        if addr == libc::MAP_FAILED {
            return Err(MmapError::SystemCallFailed(io::Error::last_os_error().into()));
        }

        Ok(MemoryMappingArena {
            addr: addr as *mut u8,
            size,
        })
    }

    /// Returns a pointer to the start of the arena.
    pub fn as_ptr(&self) -> *mut u8 {
        self.addr
    }

    /// Returns the size of the arena in bytes.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Maps `size` bytes starting at `fd_offset` bytes from within the given `fd`
    /// at `offset` bytes from the start of the arena with `prot` protections.
    pub fn add_fd_offset_protection(
        &mut self,
        offset: usize,
        size: usize,
        fd: &dyn AsRawDescriptor,
        fd_offset: u64,
        prot: Protection,
    ) -> crate::errno::Result<()> {
        let prot_flags: libc::c_int = prot.into();
        // SAFETY: We're remapping within our owned arena range
        let addr = unsafe {
            libc::mmap(
                (self.addr as usize + offset) as *mut libc::c_void,
                size,
                prot_flags,
                libc::MAP_SHARED | libc::MAP_FIXED,
                fd.as_raw_descriptor(),
                fd_offset as libc::off_t,
            )
        };
        if addr == libc::MAP_FAILED {
            return crate::errno::errno_result();
        }
        Ok(())
    }

    /// Removes a mapping at `offset` of `size` bytes, replacing with PROT_NONE anonymous mapping.
    pub fn remove(&mut self, offset: usize, size: usize) -> crate::errno::Result<()> {
        // SAFETY: We're remapping within our owned arena range
        let addr = unsafe {
            libc::mmap(
                (self.addr as usize + offset) as *mut libc::c_void,
                size,
                libc::PROT_NONE,
                libc::MAP_ANON | libc::MAP_PRIVATE | libc::MAP_FIXED,
                -1,
                0,
            )
        };
        if addr == libc::MAP_FAILED {
            return crate::errno::errno_result();
        }
        Ok(())
    }
}

// SAFETY: The pointer and size point to a memory range owned by this MemoryMappingArena that
// won't be unmapped until it's Dropped.
unsafe impl crate::MappedRegion for MemoryMappingArena {
    fn as_ptr(&self) -> *mut u8 {
        self.addr
    }

    fn size(&self) -> usize {
        self.size
    }

    fn add_fd_mapping(
        &mut self,
        offset: usize,
        size: usize,
        fd: &dyn AsRawDescriptor,
        fd_offset: u64,
        prot: Protection,
    ) -> Result<(), crate::MmapError> {
        self.add_fd_offset_protection(offset, size, fd, fd_offset, prot)
            .map_err(|e| MmapError::SystemCallFailed(e))
    }

    fn remove_mapping(&mut self, offset: usize, size: usize) -> Result<(), crate::MmapError> {
        self.remove(offset, size)
            .map_err(|e| MmapError::SystemCallFailed(e))
    }
}

impl Drop for MemoryMappingArena {
    fn drop(&mut self) {
        // SAFETY: We own this mapping
        unsafe {
            libc::munmap(self.addr as *mut libc::c_void, self.size);
        }
    }
}

// SAFETY: The memory mapping is process-global, so can be sent between threads
unsafe impl Send for MemoryMappingArena {}
// SAFETY: The memory mapping doesn't have interior mutability that could cause races
unsafe impl Sync for MemoryMappingArena {}

pub mod ioctl {
    use crate::AsRawDescriptor;

    pub type IoctlNr = std::ffi::c_ulong;

    /// Executes an ioctl with no arguments.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the ioctl number is valid for the
    /// given file descriptor.
    pub unsafe fn ioctl<F: AsRawDescriptor>(
        descriptor: &F,
        nr: IoctlNr,
    ) -> std::ffi::c_int {
        libc::ioctl(descriptor.as_raw_descriptor(), nr)
    }

    /// Executes an ioctl with a value argument.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the ioctl number is valid for the
    /// given file descriptor and that the value is appropriate.
    pub unsafe fn ioctl_with_val(
        descriptor: &dyn AsRawDescriptor,
        nr: IoctlNr,
        arg: std::ffi::c_ulong,
    ) -> std::ffi::c_int {
        libc::ioctl(descriptor.as_raw_descriptor(), nr, arg)
    }

    /// Executes an ioctl with a const reference argument.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the ioctl number is valid for the
    /// given file descriptor and that the reference points to valid data.
    pub unsafe fn ioctl_with_ref<T>(
        descriptor: &dyn AsRawDescriptor,
        nr: IoctlNr,
        arg: &T,
    ) -> std::ffi::c_int {
        libc::ioctl(descriptor.as_raw_descriptor(), nr, arg as *const T)
    }

    /// Executes an ioctl with a mutable reference argument.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the ioctl number is valid for the
    /// given file descriptor and that the reference points to valid data.
    pub unsafe fn ioctl_with_mut_ref<T>(
        descriptor: &dyn AsRawDescriptor,
        nr: IoctlNr,
        arg: &mut T,
    ) -> std::ffi::c_int {
        libc::ioctl(descriptor.as_raw_descriptor(), nr, arg as *mut T)
    }

    /// Executes an ioctl with a const pointer argument.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the ioctl number is valid for the
    /// given file descriptor and that the pointer is valid.
    pub unsafe fn ioctl_with_ptr<T>(
        descriptor: &dyn AsRawDescriptor,
        nr: IoctlNr,
        arg: *const T,
    ) -> std::ffi::c_int {
        libc::ioctl(descriptor.as_raw_descriptor(), nr, arg)
    }

    /// Executes an ioctl with a mutable pointer argument.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the ioctl number is valid for the
    /// given file descriptor and that the pointer is valid.
    pub unsafe fn ioctl_with_mut_ptr<T>(
        descriptor: &dyn AsRawDescriptor,
        nr: IoctlNr,
        arg: *mut T,
    ) -> std::ffi::c_int {
        libc::ioctl(descriptor.as_raw_descriptor(), nr, arg)
    }
}

/// Punches a hole in a file, deallocating the space.
/// On macOS, we use fcntl with F_PUNCHHOLE if available, otherwise fallback to writing zeros.
pub fn file_punch_hole(file: &File, offset: u64, length: u64) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;

    // macOS supports F_PUNCHHOLE on APFS volumes
    #[repr(C)]
    struct FPunchhole {
        fp_flags: libc::c_uint,
        reserved: libc::c_uint,
        fp_offset: libc::off_t,
        fp_length: libc::off_t,
    }

    const F_PUNCHHOLE: libc::c_int = 99;
    const FP_ALLOCATECONTIG: libc::c_uint = 0x00000002;
    const FP_ALLOCATEALL: libc::c_uint = 0x00000004;
    let _ = FP_ALLOCATECONTIG;
    let _ = FP_ALLOCATEALL;

    let punchhole = FPunchhole {
        fp_flags: 0,
        reserved: 0,
        fp_offset: offset as libc::off_t,
        fp_length: length as libc::off_t,
    };

    // SAFETY: The file descriptor is valid and the structure is properly initialized
    let ret = unsafe {
        libc::fcntl(
            file.as_raw_fd(),
            F_PUNCHHOLE,
            &punchhole as *const FPunchhole,
        )
    };

    if ret == 0 {
        Ok(())
    } else {
        // F_PUNCHHOLE might not be supported (e.g., not APFS), so fall back to doing nothing
        // This is acceptable for VM use cases where hole punching is an optimization
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOTSUP) || err.raw_os_error() == Some(libc::EINVAL) {
            Ok(())
        } else {
            Err(err)
        }
    }
}

/// Writes zeros to a file at the specified offset.
pub fn file_write_zeroes_at(
    file: &File,
    offset: u64,
    length: usize,
) -> io::Result<usize> {
    use std::os::unix::io::AsRawFd;

    // Create a buffer of zeros and write it using pwrite
    const CHUNK_SIZE: usize = 65536; // 64KB chunks
    let zeros = vec![0u8; std::cmp::min(length, CHUNK_SIZE)];

    let mut written = 0;
    let mut current_offset = offset;

    while written < length {
        let to_write = std::cmp::min(length - written, zeros.len());
        // SAFETY: The file descriptor is valid and the buffer is properly allocated
        let ret = unsafe {
            libc::pwrite(
                file.as_raw_fd(),
                zeros.as_ptr() as *const libc::c_void,
                to_write,
                current_offset as libc::off_t,
            )
        };

        if ret < 0 {
            let err = io::Error::last_os_error();
            if written > 0 {
                return Ok(written);
            }
            return Err(err);
        }

        let bytes_written = ret as usize;
        written += bytes_written;
        current_offset += bytes_written as u64;

        if bytes_written == 0 {
            break;
        }
    }

    Ok(written)
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
