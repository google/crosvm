// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! IO completion port wrapper.

use std::collections::VecDeque;
use std::io;
use std::ptr::null_mut;
use std::sync::Arc;
use std::sync::Condvar;
use std::time::Duration;

use base::error;
use base::info;
use base::AsRawDescriptor;
use base::Error as SysError;
use base::Event;
use base::EventWaitResult;
use base::FromRawDescriptor;
use base::RawDescriptor;
use base::SafeDescriptor;
use base::WorkerThread;
use smallvec::smallvec;
use smallvec::SmallVec;
use sync::Mutex;
use winapi::shared::minwindef::BOOL;
use winapi::shared::minwindef::DWORD;
use winapi::shared::minwindef::ULONG;
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::ioapiset::CreateIoCompletionPort;
use winapi::um::ioapiset::GetOverlappedResult;
use winapi::um::ioapiset::GetQueuedCompletionStatus;
use winapi::um::ioapiset::GetQueuedCompletionStatusEx;
use winapi::um::ioapiset::PostQueuedCompletionStatus;
use winapi::um::minwinbase::LPOVERLAPPED_ENTRY;
use winapi::um::minwinbase::OVERLAPPED;
use winapi::um::minwinbase::OVERLAPPED_ENTRY;
use winapi::um::winbase::INFINITE;

use super::handle_executor::Error;
use super::handle_executor::Result;

/// The number of IOCP packets we accept per poll operation.
/// Because this is only used for SmallVec sizes, clippy thinks it is unused.
#[allow(dead_code)]
const ENTRIES_PER_POLL: usize = 16;

/// A minimal version of completion packets from an IoCompletionPort.
pub(crate) struct CompletionPacket {
    pub completion_key: usize,
    pub overlapped_ptr: usize,
    pub result: std::result::Result<usize, SysError>,
}

struct Port {
    inner: RawDescriptor,
}

// SAFETY:
// Safe because the Port is dropped before IoCompletionPort goes out of scope
unsafe impl Send for Port {}

/// Wraps an IO Completion Port (iocp). These ports are very similar to an epoll
/// context on unix. Handles (equivalent to FDs) we want to wait on for
/// readiness are added to the port, and then the port can be waited on using a
/// syscall (GetQueuedCompletionStatus). IOCP is a little more flexible than
/// epoll because custom messages can be enqueued and received from the port
/// just like if a handle became ready (see [IoCompletionPort::post_status]).
///
/// Note that completion ports can only be subscribed to a handle, they
/// can never be unsubscribed. Handles are removed from the port automatically when they are closed.
///
/// Registered handles have their completion key set to their handle number.
pub(crate) struct IoCompletionPort {
    port: SafeDescriptor,
    threads: Vec<WorkerThread<Result<()>>>,
    completed: Arc<(Mutex<VecDeque<CompletionPacket>>, Condvar)>,
    concurrency: u32,
}

/// Gets a completion packet from the completion port. If the underlying IO operation
/// encountered an error, it will be contained inside the completion packet. If this method
/// encountered an error getting a completion packet, the error will be returned directly.
/// Safety: caller needs to ensure that the `handle` is valid and is for io completion port.
#[deny(unsafe_op_in_unsafe_fn)]
unsafe fn get_completion_status(
    handle: RawDescriptor,
    timeout: DWORD,
) -> io::Result<CompletionPacket> {
    let mut bytes_transferred = 0;
    let mut completion_key = 0;
    // SAFETY: trivially safe
    let mut overlapped: *mut OVERLAPPED = unsafe { std::mem::zeroed() };

    // SAFETY:
    // Safe because:
    //      1. Memory of pointers passed is stack allocated and lives as long as the syscall.
    //      2. We check the error so we don't use invalid output values (e.g. overlapped).
    let success = unsafe {
        GetQueuedCompletionStatus(
            handle,
            &mut bytes_transferred,
            &mut completion_key,
            &mut overlapped as *mut *mut OVERLAPPED,
            timeout,
        )
    } != 0;

    if success {
        return Ok(CompletionPacket {
            result: Ok(bytes_transferred as usize),
            completion_key,
            overlapped_ptr: overlapped as usize,
        });
    }

    // Did the IOCP operation fail, or did the overlapped operation fail?
    if overlapped.is_null() {
        // IOCP failed somehow.
        Err(io::Error::last_os_error())
    } else {
        // Overlapped operation failed.
        Ok(CompletionPacket {
            result: Err(SysError::last()),
            completion_key,
            overlapped_ptr: overlapped as usize,
        })
    }
}

/// Waits for completion events to arrive & returns the completion keys.
/// Safety: caller needs to ensure that the `handle` is valid and is for io completion port.
#[deny(unsafe_op_in_unsafe_fn)]
unsafe fn poll(port: RawDescriptor) -> Result<Vec<CompletionPacket>> {
    let mut completion_packets = vec![];
    completion_packets.push(
        // SAFETY: caller has ensured that the handle is valid and is for io completion port
        unsafe {
            get_completion_status(port, INFINITE)
                .map_err(|e| Error::IocpOperationFailed(SysError::from(e)))?
        },
    );

    // Drain any waiting completion packets.
    //
    // Wondering why we don't use GetQueuedCompletionStatusEx instead? Well, there's no way to
    // get detailed error information for each of the returned overlapped IO operations without
    // calling GetOverlappedResult. If we have to do that, then it's cheaper to just get each
    // completion packet individually.
    while completion_packets.len() < ENTRIES_PER_POLL {
        // SAFETY:
        // Safety: caller has ensured that the handle is valid and is for io completion port
        match unsafe { get_completion_status(port, 0) } {
            Ok(pkt) => {
                completion_packets.push(pkt);
            }
            Err(e) if e.kind() == io::ErrorKind::TimedOut => break,
            Err(e) => return Err(Error::IocpOperationFailed(SysError::from(e))),
        }
    }

    Ok(completion_packets)
}

/// Safety: caller needs to ensure that the `handle` is valid and is for io completion port.
fn iocp_waiter_thread(
    port: Arc<Mutex<Port>>,
    kill_evt: Event,
    completed: Arc<(Mutex<VecDeque<CompletionPacket>>, Condvar)>,
) -> Result<()> {
    let port = port.lock();
    loop {
        // SAFETY: caller has ensured that the handle is valid and is for io completion port
        let packets = unsafe { poll(port.inner)? };
        if !packets.is_empty() {
            {
                let mut c = completed.0.lock();
                for packet in packets {
                    c.push_back(packet);
                }
                completed.1.notify_one();
            }
        }
        if kill_evt
            .wait_timeout(Duration::from_nanos(0))
            .map_err(Error::IocpOperationFailed)?
            == EventWaitResult::Signaled
        {
            return Ok(());
        }
    }
}

impl Drop for IoCompletionPort {
    fn drop(&mut self) {
        if !self.threaded() {
            return;
        }

        let mut threads = std::mem::take(&mut self.threads);
        for thread in &mut threads {
            // let the thread know that it should exit
            if let Err(e) = thread.signal() {
                error!("faild to signal iocp thread: {}", e);
            }
        }

        // interrupt all poll/get status on ports.
        // Single thread can consume more ENTRIES_PER_POLL number of completion statuses.
        // We send enough post_status so that all threads have enough data to be woken up by the
        // completion ports.
        // This is slightly unpleasant way to interrupt all the threads.
        for _ in 0..(threads.len() * ENTRIES_PER_POLL) {
            if let Err(e) = self.wake() {
                error!("post_status failed during thread exit:{}", e);
            }
        }
    }
}

impl IoCompletionPort {
    pub fn new(concurrency: u32) -> Result<Self> {
        let completed = Arc::new((Mutex::new(VecDeque::new()), Condvar::new()));
        // Unwrap is safe because we're creating a new IOCP and will receive the owned handle
        // back.
        let port = create_iocp(None, None, 0, concurrency)?.unwrap();
        let mut threads = vec![];
        if concurrency > 1 {
            info!("creating iocp with concurrency: {}", concurrency);
            for i in 0..concurrency {
                let completed_clone = completed.clone();
                let port_desc = Arc::new(Mutex::new(Port {
                    inner: port.as_raw_descriptor(),
                }));
                threads.push(WorkerThread::start(
                    format!("overlapped_io_{}", i),
                    move |kill_evt| {
                        iocp_waiter_thread(port_desc, kill_evt, completed_clone).unwrap();
                        Ok(())
                    },
                ));
            }
        }
        Ok(Self {
            port,
            threads,
            completed,
            concurrency,
        })
    }

    fn threaded(&self) -> bool {
        self.concurrency > 1
    }

    /// Register the provided descriptor with this completion port. Registered descriptors cannot
    /// be deregistered. To deregister, close the descriptor.
    pub fn register_descriptor(&self, desc: &dyn AsRawDescriptor) -> Result<()> {
        create_iocp(
            Some(desc),
            Some(&self.port),
            desc.as_raw_descriptor() as usize,
            self.concurrency,
        )?;
        Ok(())
    }

    /// Posts a completion packet to the IO completion port.
    pub fn post_status(&self, bytes_transferred: u32, completion_key: usize) -> Result<()> {
        // SAFETY:
        // Safe because the IOCP handle is valid.
        let res = unsafe {
            PostQueuedCompletionStatus(
                self.port.as_raw_descriptor(),
                bytes_transferred,
                completion_key,
                null_mut(),
            )
        };
        if res == 0 {
            return Err(Error::IocpOperationFailed(SysError::last()));
        }
        Ok(())
    }

    /// Wake up thread waiting on this iocp.
    /// If there are more than one thread waiting, then you may need to call this function
    /// multiple times.
    pub fn wake(&self) -> Result<()> {
        self.post_status(0, INVALID_HANDLE_VALUE as usize)
    }

    /// Get up to ENTRIES_PER_POLL completion packets from the IOCP in one shot.
    #[allow(dead_code)]
    fn get_completion_status_ex(
        &self,
        timeout: DWORD,
    ) -> Result<SmallVec<[OVERLAPPED_ENTRY; ENTRIES_PER_POLL]>> {
        let mut overlapped_entries: SmallVec<[OVERLAPPED_ENTRY; ENTRIES_PER_POLL]> =
            smallvec!(OVERLAPPED_ENTRY::default(); ENTRIES_PER_POLL);

        let mut entries_removed: ULONG = 0;
        // SAFETY:
        // Safe because:
        //      1. IOCP is guaranteed to exist by self.
        //      2. Memory of pointers passed is stack allocated and lives as long as the syscall.
        //      3. We check the error so we don't use invalid output values (e.g. overlapped).
        let success = unsafe {
            GetQueuedCompletionStatusEx(
                self.port.as_raw_descriptor(),
                overlapped_entries.as_mut_ptr() as LPOVERLAPPED_ENTRY,
                ENTRIES_PER_POLL as ULONG,
                &mut entries_removed,
                timeout,
                // We are normally called from a polling loop. It's more efficient (loop latency
                // wise) to hold the thread instead of performing an alertable wait.
                /* fAlertable= */
                false as BOOL,
            )
        } != 0;

        if success {
            overlapped_entries.truncate(entries_removed as usize);
            return Ok(overlapped_entries);
        }

        // Overlapped operation failed.
        Err(Error::IocpOperationFailed(SysError::last()))
    }

    fn take_completed_packets(&self) -> SmallVec<[CompletionPacket; ENTRIES_PER_POLL]> {
        let mut completion_packets = SmallVec::with_capacity(ENTRIES_PER_POLL);
        let mut packets = self.completed.0.lock();
        let len = usize::min(ENTRIES_PER_POLL, packets.len());
        for p in packets.drain(..len) {
            completion_packets.push(p)
        }
        completion_packets
    }

    /// Waits for completion events to arrive & returns the completion keys.
    pub fn poll_threaded(&self) -> Result<SmallVec<[CompletionPacket; ENTRIES_PER_POLL]>> {
        let completion_packets = self.take_completed_packets();

        if !completion_packets.is_empty() {
            return Ok(completion_packets);
        }

        {
            let available = self.completed.0.lock();
            let _unused = self.completed.1.wait(available).unwrap();
        }
        let completion_packets = self.take_completed_packets();
        Ok(completion_packets)
    }

    /// Waits for completion events to arrive & returns the completion keys.
    pub fn poll_unthreaded(&self) -> Result<SmallVec<[CompletionPacket; ENTRIES_PER_POLL]>> {
        // SAFETY: safe because port is in scope for the duration of the call.
        let packets = unsafe { poll(self.port.as_raw_descriptor())? };
        let mut completion_packets = SmallVec::with_capacity(ENTRIES_PER_POLL);
        for pkt in packets {
            completion_packets.push(pkt);
        }
        Ok(completion_packets)
    }

    pub fn poll(&self) -> Result<SmallVec<[CompletionPacket; ENTRIES_PER_POLL]>> {
        if self.threaded() {
            self.poll_threaded()
        } else {
            self.poll_unthreaded()
        }
    }

    /// Waits for completion events to arrive & returns the completion keys. Internally uses
    /// GetCompletionStatusEx.
    ///
    /// WARNING: do NOT use completion keys that are not IO handles except for INVALID_HANDLE_VALUE
    /// or undefined behavior will result.
    #[allow(dead_code)]
    pub fn poll_ex(&self) -> Result<SmallVec<[CompletionPacket; ENTRIES_PER_POLL]>> {
        if self.threaded() {
            self.poll()
        } else {
            self.poll_ex_unthreaded()
        }
    }

    pub fn poll_ex_unthreaded(&self) -> Result<SmallVec<[CompletionPacket; ENTRIES_PER_POLL]>> {
        let mut completion_packets = SmallVec::with_capacity(ENTRIES_PER_POLL);
        let overlapped_entries = self.get_completion_status_ex(INFINITE)?;

        for entry in &overlapped_entries {
            if entry.lpCompletionKey as RawDescriptor == INVALID_HANDLE_VALUE {
                completion_packets.push(CompletionPacket {
                    result: Ok(0),
                    completion_key: entry.lpCompletionKey,
                    overlapped_ptr: entry.lpOverlapped as usize,
                });
                continue;
            }

            let mut bytes_transferred = 0;
            // SAFETY: trivially safe with return value checked
            let success = unsafe {
                GetOverlappedResult(
                    entry.lpCompletionKey as RawDescriptor,
                    entry.lpOverlapped,
                    &mut bytes_transferred,
                    // We don't need to wait because IOCP told us the IO is complete.
                    /* bWait= */
                    false as BOOL,
                )
            } != 0;
            if success {
                completion_packets.push(CompletionPacket {
                    result: Ok(bytes_transferred as usize),
                    completion_key: entry.lpCompletionKey,
                    overlapped_ptr: entry.lpOverlapped as usize,
                });
            } else {
                completion_packets.push(CompletionPacket {
                    result: Err(SysError::last()),
                    completion_key: entry.lpCompletionKey,
                    overlapped_ptr: entry.lpOverlapped as usize,
                });
            }
        }
        Ok(completion_packets)
    }
}

/// If existing_iocp is None, will return the created IOCP.
fn create_iocp(
    file: Option<&dyn AsRawDescriptor>,
    existing_iocp: Option<&dyn AsRawDescriptor>,
    completion_key: usize,
    concurrency: u32,
) -> Result<Option<SafeDescriptor>> {
    let raw_file = match file {
        Some(file) => file.as_raw_descriptor(),
        None => INVALID_HANDLE_VALUE,
    };
    let raw_existing_iocp = match existing_iocp {
        Some(iocp) => iocp.as_raw_descriptor(),
        None => null_mut(),
    };

    let port =
        // SAFETY:
        // Safe because:
        //      1. The file handle is open because we have a reference to it.
        //      2. The existing IOCP (if applicable) is valid.
        unsafe { CreateIoCompletionPort(raw_file, raw_existing_iocp, completion_key, concurrency) };

    if port.is_null() {
        return Err(Error::IocpOperationFailed(SysError::last()));
    }

    if existing_iocp.is_some() {
        Ok(None)
    } else {
        // SAFETY:
        // Safe because:
        // 1. We are creating a new IOCP.
        // 2. We exclusively own the handle.
        // 3. The handle is valid since CreateIoCompletionPort returned without errors.
        Ok(Some(unsafe { SafeDescriptor::from_raw_descriptor(port) }))
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::fs::OpenOptions;
    use std::os::windows::fs::OpenOptionsExt;
    use std::path::PathBuf;

    use tempfile::TempDir;
    use winapi::um::winbase::FILE_FLAG_OVERLAPPED;

    use super::*;

    static TEST_IO_CONCURRENCY: u32 = 4;

    fn tempfile_path() -> (PathBuf, TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let mut file_path = PathBuf::from(dir.path());
        file_path.push("test");
        (file_path, dir)
    }

    fn open_overlapped(path: &PathBuf) -> File {
        OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .custom_flags(FILE_FLAG_OVERLAPPED)
            .open(path)
            .unwrap()
    }

    fn basic_iocp_test_with(concurrency: u32) {
        let iocp = IoCompletionPort::new(concurrency).unwrap();
        let (file_path, _tmpdir) = tempfile_path();
        let mut overlapped = OVERLAPPED::default();
        let f = open_overlapped(&file_path);

        iocp.register_descriptor(&f).unwrap();
        let buf = [0u8; 16];
        // SAFETY: Safe given file is valid, buffers are allocated and initialized and return value
        // is checked.
        unsafe {
            base::windows::write_file(&f, buf.as_ptr(), buf.len(), Some(&mut overlapped)).unwrap()
        };
        assert_eq!(iocp.poll().unwrap().len(), 1);
    }

    #[test]
    fn basic_iocp_test_unthreaded() {
        basic_iocp_test_with(1)
    }

    #[test]
    fn basic_iocp_test_threaded() {
        basic_iocp_test_with(TEST_IO_CONCURRENCY)
    }

    fn basic_iocp_test_poll_ex(concurrency: u32) {
        let iocp = IoCompletionPort::new(concurrency).unwrap();
        let (file_path, _tmpdir) = tempfile_path();
        let mut overlapped = OVERLAPPED::default();
        let f = open_overlapped(&file_path);

        iocp.register_descriptor(&f).unwrap();
        let buf = [0u8; 16];
        // SAFETY: Safe given file is valid, buffers are allocated and initialized and return value
        // is checked.
        unsafe {
            base::windows::write_file(&f, buf.as_ptr(), buf.len(), Some(&mut overlapped)).unwrap()
        };
        assert_eq!(iocp.poll_ex().unwrap().len(), 1);
    }

    #[test]
    fn basic_iocp_test_poll_ex_unthreaded() {
        basic_iocp_test_poll_ex(1);
    }

    #[test]
    fn basic_iocp_test_poll_ex_threaded() {
        basic_iocp_test_poll_ex(TEST_IO_CONCURRENCY);
    }
}
