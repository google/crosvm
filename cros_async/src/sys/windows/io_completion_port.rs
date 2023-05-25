// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! IO completion port wrapper.

use std::io;
use std::ptr::null_mut;

use base::AsRawDescriptor;
use base::Error as SysError;
use base::FromRawDescriptor;
use base::RawDescriptor;
use base::SafeDescriptor;
use smallvec::smallvec;
use smallvec::SmallVec;
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
}

impl IoCompletionPort {
    pub fn new() -> Result<Self> {
        Ok(Self {
            // Unwrap is safe because we're creating a new IOCP and will receive the owned handle
            // back.
            port: create_iocp(None, None, 0)?.unwrap(),
        })
    }

    /// Register the provided descriptor with this completion port. Registered descriptors cannot
    /// be deregistered. To deregister, close the descriptor.
    pub fn register_descriptor(&self, desc: &dyn AsRawDescriptor) -> Result<()> {
        create_iocp(
            Some(desc),
            Some(&self.port),
            desc.as_raw_descriptor() as usize,
        )?;
        Ok(())
    }

    /// Posts a completion packet to the IO completion port.
    pub fn post_status(&self, bytes_transferred: u32, completion_key: usize) -> Result<()> {
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

    /// Gets a completion packet from the completion port. If the underlying IO operation
    /// encountered an error, it will be contained inside the completion packet. If this method
    /// encountered an error getting a completion packet, the error will be returned directly.
    fn get_completion_status(&self, timeout: DWORD) -> io::Result<CompletionPacket> {
        let mut bytes_transferred = 0;
        let mut completion_key = 0;
        let mut overlapped: *mut OVERLAPPED = unsafe { std::mem::zeroed() };

        // Safe because:
        //      1. IOCP is guaranteed to exist by self.
        //      2. Memory of pointers passed is stack allocated and lives as long as the syscall.
        //      3. We check the error so we don't use invalid output values (e.g. overlapped).
        let success = unsafe {
            GetQueuedCompletionStatus(
                self.port.as_raw_descriptor(),
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

    /// Get up to ENTRIES_PER_POLL completion packets from the IOCP in one shot.
    #[allow(dead_code)]
    fn get_completion_status_ex(
        &self,
        timeout: DWORD,
    ) -> Result<SmallVec<[OVERLAPPED_ENTRY; ENTRIES_PER_POLL]>> {
        let mut overlapped_entries: SmallVec<[OVERLAPPED_ENTRY; ENTRIES_PER_POLL]> =
            smallvec!(OVERLAPPED_ENTRY::default(); ENTRIES_PER_POLL);

        // Safe because:
        //      1. IOCP is guaranteed to exist by self.
        //      2. Memory of pointers passed is stack allocated and lives as long as the syscall.
        //      3. We check the error so we don't use invalid output values (e.g. overlapped).
        let mut entries_removed: ULONG = 0;
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

    /// Waits for completion events to arrive & returns the completion keys.
    pub fn poll(&self) -> Result<SmallVec<[CompletionPacket; ENTRIES_PER_POLL]>> {
        let mut completion_packets = SmallVec::with_capacity(ENTRIES_PER_POLL);
        completion_packets.push(
            self.get_completion_status(INFINITE)
                .map_err(|e| Error::IocpOperationFailed(SysError::from(e)))?,
        );

        // Drain any waiting completion packets.
        //
        // Wondering why we don't use GetQueuedCompletionStatusEx instead? Well, there's no way to
        // get detailed error information for each of the returned overlapped IO operations without
        // calling GetOverlappedResult. If we have to do that, then it's cheaper to just get each
        // completion packet individually.
        while completion_packets.len() < ENTRIES_PER_POLL {
            match self.get_completion_status(0) {
                Ok(pkt) => {
                    completion_packets.push(pkt);
                }
                Err(e) if e.kind() == io::ErrorKind::TimedOut => break,
                Err(e) => return Err(Error::IocpOperationFailed(SysError::from(e))),
            }
        }

        Ok(completion_packets)
    }

    /// Waits for completion events to arrive & returns the completion keys. Internally uses
    /// GetCompletionStatusEx.
    ///
    /// WARNING: do NOT use completion keys that are not IO handles except for INVALID_HANDLE_VALUE
    /// or undefined behavior will result.
    #[allow(dead_code)]
    pub fn poll_ex(&self) -> Result<SmallVec<[CompletionPacket; ENTRIES_PER_POLL]>> {
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
) -> Result<Option<SafeDescriptor>> {
    let raw_file = match file {
        Some(file) => file.as_raw_descriptor(),
        None => INVALID_HANDLE_VALUE,
    };
    let raw_existing_iocp = match existing_iocp {
        Some(iocp) => iocp.as_raw_descriptor(),
        None => null_mut(),
    };

    // Safe because:
    //      1. The file handle is open because we have a reference to it.
    //      2. The existing IOCP (if applicable) is valid.
    let port = unsafe {
        CreateIoCompletionPort(
            raw_file,
            raw_existing_iocp,
            completion_key,
            /* num_concurrent_threads= */ 0,
        )
    };

    if port.is_null() {
        return Err(Error::IocpOperationFailed(SysError::last()));
    }

    if existing_iocp.is_some() {
        Ok(None)
    } else {
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

    #[test]
    fn basic_iocp_test() {
        let iocp = IoCompletionPort::new().unwrap();
        let (file_path, _tmpdir) = tempfile_path();
        let mut overlapped = OVERLAPPED::default();
        let f = open_overlapped(&file_path);

        iocp.register_descriptor(&f).unwrap();
        let buf = [0u8; 16];
        unsafe {
            base::platform::write_file(&f, buf.as_ptr(), buf.len(), Some(&mut overlapped)).unwrap()
        };
        assert_eq!(iocp.poll().unwrap().len(), 1);
    }

    #[test]
    fn basic_iocp_test_poll_ex() {
        let iocp = IoCompletionPort::new().unwrap();
        let (file_path, _tmpdir) = tempfile_path();
        let mut overlapped = OVERLAPPED::default();
        let f = open_overlapped(&file_path);

        iocp.register_descriptor(&f).unwrap();
        let buf = [0u8; 16];
        unsafe {
            base::platform::write_file(&f, buf.as_ptr(), buf.len(), Some(&mut overlapped)).unwrap()
        };
        assert_eq!(iocp.poll_ex().unwrap().len(), 1);
    }
}
