// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::CString;
use std::fs::OpenOptions;
use std::io;
use std::io::Result;
use std::mem;
use std::os::windows::fs::OpenOptionsExt;
use std::process;
use std::ptr;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use rand::Rng;
use serde::Deserialize;
use serde::Serialize;
use win_util::fail_if_zero;
use win_util::SecurityAttributes;
use win_util::SelfRelativeSecurityDescriptor;
use winapi::shared::minwindef::DWORD;
use winapi::shared::minwindef::FALSE;
use winapi::shared::minwindef::TRUE;
use winapi::shared::winerror::ERROR_IO_INCOMPLETE;
use winapi::shared::winerror::ERROR_IO_PENDING;
use winapi::shared::winerror::ERROR_MORE_DATA;
use winapi::shared::winerror::ERROR_NO_DATA;
use winapi::shared::winerror::ERROR_PIPE_CONNECTED;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::fileapi::FlushFileBuffers;
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::ioapiset::CancelIoEx;
use winapi::um::ioapiset::GetOverlappedResult;
use winapi::um::minwinbase::OVERLAPPED;
use winapi::um::namedpipeapi::ConnectNamedPipe;
use winapi::um::namedpipeapi::DisconnectNamedPipe;
use winapi::um::namedpipeapi::GetNamedPipeInfo;
use winapi::um::namedpipeapi::PeekNamedPipe;
use winapi::um::namedpipeapi::SetNamedPipeHandleState;
use winapi::um::winbase::CreateNamedPipeA;
use winapi::um::winbase::FILE_FLAG_FIRST_PIPE_INSTANCE;
use winapi::um::winbase::FILE_FLAG_OVERLAPPED;
use winapi::um::winbase::PIPE_ACCESS_DUPLEX;
use winapi::um::winbase::PIPE_NOWAIT;
use winapi::um::winbase::PIPE_READMODE_BYTE;
use winapi::um::winbase::PIPE_READMODE_MESSAGE;
use winapi::um::winbase::PIPE_REJECT_REMOTE_CLIENTS;
use winapi::um::winbase::PIPE_TYPE_BYTE;
use winapi::um::winbase::PIPE_TYPE_MESSAGE;
use winapi::um::winbase::PIPE_WAIT;
use winapi::um::winbase::SECURITY_IDENTIFICATION;

use super::RawDescriptor;
use crate::descriptor::AsRawDescriptor;
use crate::descriptor::FromRawDescriptor;
use crate::descriptor::IntoRawDescriptor;
use crate::descriptor::SafeDescriptor;
use crate::Event;
use crate::EventToken;
use crate::WaitContext;

/// The default buffer size for all named pipes in the system. If this size is too small, writers
/// on named pipes that expect not to block *can* block until the reading side empties the buffer.
///
/// The general rule is this should be *at least* as big as the largest message, otherwise
/// unexpected blocking behavior can result; for example, if too small, this can interact badly with
/// crate::platform::StreamChannel, which expects to be able to make a complete write before releasing
/// a lock that the opposite side needs to complete a read. This means that if the buffer is too
/// small:
///     * The writer can't complete its write and release the lock because the buffer is too small.
///     * The reader can't start reading because the lock is held by the writer, so it can't
///       relieve buffer pressure. Note that for message pipes, the reader couldn't do anything
///       to help anyway, because a message mode pipe should NOT have a partial read (which is
///       what we would need to relieve pressure).
///     * Conditions for deadlock are met, and both the reader & writer enter circular waiting.
pub const DEFAULT_BUFFER_SIZE: usize = 50 * 1024;

static NEXT_PIPE_INDEX: AtomicUsize = AtomicUsize::new(1);

/// Represents one end of a named pipe
#[derive(Serialize, Deserialize, Debug)]
pub struct PipeConnection {
    handle: SafeDescriptor,
    framing_mode: FramingMode,
    blocking_mode: BlockingMode,
}

/// Wraps the OVERLAPPED structure. Also keeps track of whether OVERLAPPED is being used by a
/// Readfile or WriteFile operation and holds onto the event object so it doesn't get dropped.
pub struct OverlappedWrapper {
    // Allocated on the heap so that the OVERLAPPED struct doesn't move when performing I/O
    // operations.
    overlapped: Box<OVERLAPPED>,
    // This field prevents the event handle from being dropped too early and allows callers to
    // be notified when a read or write overlapped operation has completed.
    h_event: Option<Event>,
    in_use: bool,
}

impl OverlappedWrapper {
    pub fn get_h_event_ref(&self) -> Option<&Event> {
        self.h_event.as_ref()
    }

    /// Creates a valid `OVERLAPPED` struct used to pass into `ReadFile` and `WriteFile` in order
    /// to perform asynchronous I/O. When passing in the OVERLAPPED struct, the Event object
    /// returned must not be dropped.
    ///
    /// There is an option to create the event object and set it to the `hEvent` field. If hEvent
    /// is not set and the named pipe handle was created with `FILE_FLAG_OVERLAPPED`, then the file
    /// handle will be signaled when the operation is complete. In other words, you can use
    /// `WaitForSingleObject` on the file handle. Not setting an event is highly discouraged by
    /// Microsoft though.
    pub fn new(include_event: bool) -> Result<OverlappedWrapper> {
        let mut overlapped = OVERLAPPED::default();
        let h_event = if include_event {
            Some(Event::new()?)
        } else {
            None
        };

        overlapped.hEvent = if let Some(event) = h_event.as_ref() {
            event.as_raw_descriptor()
        } else {
            0 as RawDescriptor
        };

        Ok(OverlappedWrapper {
            overlapped: Box::new(overlapped),
            h_event,
            in_use: false,
        })
    }
}

// Safe because all of the contained fields may be safely sent to another thread.
unsafe impl Send for OverlappedWrapper {}

pub trait WriteOverlapped {
    /// Perform an overlapped write operation with the specified buffer and overlapped wrapper.
    /// If successful, the write operation will complete asynchronously, and
    /// `write_result()` should be called to get the result.
    ///
    /// # Safety
    /// `buf` and `overlapped_wrapper` will be in use for the duration of
    /// the overlapped operation. These must not be reused and must live until
    /// after `write_result()` has been called.
    unsafe fn write_overlapped(
        &mut self,
        buf: &mut [u8],
        overlapped_wrapper: &mut OverlappedWrapper,
    ) -> io::Result<()>;

    /// Gets the result of the overlapped write operation. Must only be called
    /// after issuing an overlapped write operation using `write_overlapped`. The
    /// same `overlapped_wrapper` must be provided.
    fn write_result(&mut self, overlapped_wrapper: &mut OverlappedWrapper) -> io::Result<usize>;

    /// Tries to get the result of the overlapped write operation. Must only be
    /// called once, and only after issuing an overlapped write operation using
    /// `write_overlapped`. The same `overlapped_wrapper` must be provided.
    ///
    /// An error indicates that the operation hasn't completed yet and
    /// `write_result` or `try_write_result` should be called again.
    fn try_write_result(&mut self, overlapped_wrapper: &mut OverlappedWrapper)
        -> io::Result<usize>;
}

pub trait ReadOverlapped {
    /// Perform an overlapped read operation with the specified buffer and overlapped wrapper.
    /// If successful, the read operation will complete asynchronously, and
    /// `read_result()` should be called to get the result.
    ///
    /// # Safety
    /// `buf` and `overlapped_wrapper` will be in use for the duration of
    /// the overlapped operation. These must not be reused and must live until
    /// after `read_result()` has been called.
    unsafe fn read_overlapped(
        &mut self,
        buf: &mut [u8],
        overlapped_wrapper: &mut OverlappedWrapper,
    ) -> io::Result<()>;

    /// Gets the result of the overlapped read operation. Must only be called
    /// once, and only after issuing an overlapped read operation using
    /// `read_overlapped`. The same `overlapped_wrapper` must be provided.
    fn read_result(&mut self, overlapped_wrapper: &mut OverlappedWrapper) -> io::Result<usize>;

    /// Tries to get the result of the overlapped read operation. Must only be called
    /// after issuing an overlapped read operation using `read_overlapped`. The
    /// same `overlapped_wrapper` must be provided.
    ///
    /// An error indicates that the operation hasn't completed yet and
    /// `read_result` or `try_read_result` should be called again.
    fn try_read_result(&mut self, overlapped_wrapper: &mut OverlappedWrapper) -> io::Result<usize>;
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug, PartialEq, Eq)]
pub enum FramingMode {
    Byte,
    Message,
}

impl FramingMode {
    fn to_readmode(self) -> DWORD {
        match self {
            FramingMode::Message => PIPE_READMODE_MESSAGE,
            FramingMode::Byte => PIPE_READMODE_BYTE,
        }
    }

    fn to_pipetype(self) -> DWORD {
        match self {
            FramingMode::Message => PIPE_TYPE_MESSAGE,
            FramingMode::Byte => PIPE_TYPE_BYTE,
        }
    }
}

#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Debug, Eq)]
pub enum BlockingMode {
    /// Calls to read() block until data is received
    Wait,
    /// Calls to read() return immediately even if there is nothing read with error code 232
    /// (Rust maps this to BrokenPipe but it's actually ERROR_NO_DATA)
    ///
    /// NOTE: This mode is discouraged by the Windows API documentation.
    NoWait,
}

impl From<&BlockingMode> for DWORD {
    fn from(blocking_mode: &BlockingMode) -> DWORD {
        match blocking_mode {
            BlockingMode::Wait => PIPE_WAIT,
            BlockingMode::NoWait => PIPE_NOWAIT,
        }
    }
}

/// Sets the handle state for a named pipe in a rust friendly way.
/// This is safe if the pipe handle is open.
unsafe fn set_named_pipe_handle_state(
    pipe_handle: RawDescriptor,
    client_mode: &mut DWORD,
) -> Result<()> {
    // Safe when the pipe handle is open. Safety also requires checking the return value, which we
    // do below.
    let success_flag = SetNamedPipeHandleState(
        /* hNamedPipe= */ pipe_handle,
        /* lpMode= */ client_mode,
        /* lpMaxCollectionCount= */ ptr::null_mut(),
        /* lpCollectDataTimeout= */ ptr::null_mut(),
    );
    if success_flag == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn pair(
    framing_mode: &FramingMode,
    blocking_mode: &BlockingMode,
    timeout: u64,
) -> Result<(PipeConnection, PipeConnection)> {
    pair_with_buffer_size(
        framing_mode,
        blocking_mode,
        timeout,
        DEFAULT_BUFFER_SIZE,
        false,
    )
}

/// Creates a pair of handles connected to either end of a duplex named pipe.
///
/// The pipe created will have a semi-random name and a default set of security options that
/// help prevent common named-pipe based vulnerabilities. Specifically the pipe is set to reject
/// remote clients, allow only a single server instance, and prevent impersonation by the server
/// end of the pipe.
///
/// # Arguments
///
/// * `framing_mode`  - Whether the system should provide a simple byte stream (Byte) or an
///                     automatically framed sequence of messages (Message). In message mode it's an
///                     error to read fewer bytes than were sent in a message from the other end of
///                     the pipe.
/// * `blocking_mode` - Whether the system should wait on read() until data is available (Wait) or
///                     return immediately if there is nothing available (NoWait).
/// * `timeout`       - A timeout to apply for socket operations, in milliseconds.
///                     Setting this to zero will create sockets with the system
///                     default timeout.
/// * `buffer_size`   - The default buffer size for the named pipe. The system should expand the
///                     buffer automatically as needed, except in the case of NOWAIT pipes, where
///                     it will just fail writes that don't fit in the buffer.
/// # Return value
///
/// Returns a pair of pipes, of the form (server, client). Note that for some winapis, such as
/// FlushFileBuffers, the server & client ends WILL BEHAVE DIFFERENTLY.
pub fn pair_with_buffer_size(
    framing_mode: &FramingMode,
    blocking_mode: &BlockingMode,
    timeout: u64,
    buffer_size: usize,
    overlapped: bool,
) -> Result<(PipeConnection, PipeConnection)> {
    // Give the pipe a unique name to avoid accidental collisions
    let pipe_name = format!(
        r"\\.\pipe\crosvm_ipc.pid{}.{}.rand{}",
        process::id(),
        NEXT_PIPE_INDEX.fetch_add(1, Ordering::SeqCst),
        rand::thread_rng().gen::<u32>(),
    );

    let server_end = create_server_pipe(
        &pipe_name,
        framing_mode,
        blocking_mode,
        timeout,
        buffer_size,
        overlapped,
    )?;

    // Open the named pipe we just created as the client
    let client_end = create_client_pipe(&pipe_name, framing_mode, blocking_mode, overlapped)?;

    // Accept the client's connection
    // Not sure if this is strictly needed but I'm doing it just in case.
    // We expect at this point that the client will already be connected,
    // so we'll get a return code of 0 and an ERROR_PIPE_CONNECTED.
    // It's also OK if we get a return code of success.
    server_end.wait_for_client_connection()?;

    Ok((server_end, client_end))
}

/// Creates a PipeConnection for the server end of a named pipe with the given path and pipe
/// settings.
///
/// The pipe will be set to reject remote clients and allow only a single connection at a time.
///
/// # Arguments
///
/// * `pipe_name`     - The path of the named pipe to create. Should be in the form
///                     `\\.\pipe\<some-name>`.
/// * `framing_mode`  - Whether the system should provide a simple byte stream (Byte) or an
///                     automatically framed sequence of messages (Message). In message mode it's an
///                     error to read fewer bytes than were sent in a message from the other end of
///                     the pipe.
/// * `blocking_mode` - Whether the system should wait on read() until data is available (Wait) or
///                     return immediately if there is nothing available (NoWait).
/// * `timeout`       - A timeout to apply for socket operations, in milliseconds.
///                     Setting this to zero will create sockets with the system
///                     default timeout.
/// * `buffer_size`   - The default buffer size for the named pipe. The system should expand the
///                     buffer automatically as needed, except in the case of NOWAIT pipes, where
///                     it will just fail writes that don't fit in the buffer.
/// * `overlapped`    - Sets whether overlapped mode is set on the pipe.
pub fn create_server_pipe(
    pipe_name: &str,
    framing_mode: &FramingMode,
    blocking_mode: &BlockingMode,
    timeout: u64,
    buffer_size: usize,
    overlapped: bool,
) -> Result<PipeConnection> {
    let c_pipe_name = CString::new(pipe_name).unwrap();

    let mut open_mode_flags = PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE;
    if overlapped {
        open_mode_flags |= FILE_FLAG_OVERLAPPED
    }

    // This sets flags so there will be an error if >1 instance (server end)
    // of this pipe name is opened because we expect exactly one.
    let server_handle = unsafe {
        // Safe because security attributes are valid, pipe_name is valid C string,
        // and we're checking the return code
        CreateNamedPipeA(
            c_pipe_name.as_ptr(),
            /* dwOpenMode= */
            open_mode_flags,
            /* dwPipeMode= */
            framing_mode.to_pipetype()
                | framing_mode.to_readmode()
                | DWORD::from(blocking_mode)
                | PIPE_REJECT_REMOTE_CLIENTS,
            /* nMaxInstances= */ 1,
            /* nOutBufferSize= */ buffer_size as DWORD,
            /* nInBufferSize= */ buffer_size as DWORD,
            /* nDefaultTimeOut= */ timeout as DWORD, // Default is 50ms
            /* lpSecurityAttributes= */
            SecurityAttributes::new_with_security_descriptor(
                SelfRelativeSecurityDescriptor::get_singleton(),
                /* inherit= */ true,
            )
            .as_mut(),
        )
    };

    if server_handle == INVALID_HANDLE_VALUE {
        Err(io::Error::last_os_error())
    } else {
        unsafe {
            Ok(PipeConnection {
                handle: SafeDescriptor::from_raw_descriptor(server_handle),
                framing_mode: *framing_mode,
                blocking_mode: *blocking_mode,
            })
        }
    }
}

/// Creates a PipeConnection for the client end of a named pipe with the given path and pipe
/// settings.
///
/// The pipe will be set to prevent impersonation of the client by the server process.
///
/// # Arguments
///
/// * `pipe_name`     - The path of the named pipe to create. Should be in the form
///                     `\\.\pipe\<some-name>`.
/// * `framing_mode`  - Whether the system should provide a simple byte stream (Byte) or an
///                     automatically framed sequence of messages (Message). In message mode it's an
///                     error to read fewer bytes than were sent in a message from the other end of
///                     the pipe.
/// * `blocking_mode` - Whether the system should wait on read() until data is available (Wait) or
///                     return immediately if there is nothing available (NoWait).
/// * `overlapped`    - Sets whether the pipe is opened in overlapped mode.
pub fn create_client_pipe(
    pipe_name: &str,
    framing_mode: &FramingMode,
    blocking_mode: &BlockingMode,
    overlapped: bool,
) -> Result<PipeConnection> {
    let client_handle = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .security_qos_flags(SECURITY_IDENTIFICATION)
        .custom_flags(if overlapped { FILE_FLAG_OVERLAPPED } else { 0 })
        .open(pipe_name)?
        .into_raw_descriptor();

    let mut client_mode = framing_mode.to_readmode() | DWORD::from(blocking_mode);

    // Safe because client_handle's open() call did not return an error.
    unsafe {
        set_named_pipe_handle_state(client_handle, &mut client_mode)?;
    }

    Ok(PipeConnection {
        // Safe because client_handle is valid
        handle: unsafe { SafeDescriptor::from_raw_descriptor(client_handle) },
        framing_mode: *framing_mode,
        blocking_mode: *blocking_mode,
    })
}

// This is used to mark types which can be appropriately sent through the
// generic helper functions write_to_pipe and read_from_pipe.
pub trait PipeSendable {
    // Default values used to fill in new empty indexes when resizing a buffer to
    // a larger size.
    fn default() -> Self;
}
impl PipeSendable for u8 {
    fn default() -> Self {
        0
    }
}
impl PipeSendable for RawDescriptor {
    fn default() -> Self {
        ptr::null_mut()
    }
}

impl PipeConnection {
    pub fn try_clone(&self) -> Result<PipeConnection> {
        let copy_handle = self.handle.try_clone()?;
        Ok(PipeConnection {
            handle: copy_handle,
            framing_mode: self.framing_mode,
            blocking_mode: self.blocking_mode,
        })
    }

    /// Creates a PipeConnection from an existing RawDescriptor, and the underlying the framing &
    /// blocking modes.
    ///
    /// # Safety
    /// 1. rd is valid and ownership is transferred to this function when it is called.
    ///
    /// To avoid undefined behavior, framing_mode & blocking_modes must match those of the
    /// underlying pipe.
    pub unsafe fn from_raw_descriptor(
        rd: RawDescriptor,
        framing_mode: FramingMode,
        blocking_mode: BlockingMode,
    ) -> PipeConnection {
        PipeConnection {
            handle: SafeDescriptor::from_raw_descriptor(rd),
            framing_mode,
            blocking_mode,
        }
    }

    /// Reads bytes from the pipe into the provided buffer, up to the capacity of the buffer.
    /// Returns the number of bytes (not values) read.
    ///
    /// # Safety
    ///
    /// This is safe only when the following conditions hold:
    ///     1. The data on the other end of the pipe is a valid binary representation of data for
    ///     type T, and
    ///     2. The number of bytes read is a multiple of the size of T; this must be checked by
    ///     the caller.
    /// If buf's type is file descriptors, this is only safe when those file descriptors are valid
    /// for the process where this function was called.
    pub unsafe fn read<T: PipeSendable>(&self, buf: &mut [T]) -> Result<usize> {
        PipeConnection::read_internal(&self.handle, self.blocking_mode, buf, None)
    }

    /// Similar to `PipeConnection::read` except it also allows:
    ///     1. The same end of the named pipe to read and write at the same time in different
    ///        threads.
    ///     2. Asynchronous read and write (read and write won't block).
    ///
    /// When reading, it will not block, but instead an `OVERLAPPED` struct that contains an event
    /// (can be created with `OverlappedWrapper::new`) will be passed into
    /// `ReadFile`. That event will be triggered when the read operation is complete.
    ///
    /// In order to get how many bytes were read, call `get_overlapped_result`. That function will
    /// also help with waiting until the read operation is complete.
    ///
    /// # Safety
    ///
    /// Same as `PipeConnection::read` safety comments. In addition, the pipe MUST be opened in
    /// overlapped mode otherwise there may be unexpected behavior.
    pub unsafe fn read_overlapped<T: PipeSendable>(
        &mut self,
        buf: &mut [T],
        overlapped_wrapper: &mut OverlappedWrapper,
    ) -> Result<()> {
        if overlapped_wrapper.in_use {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Overlapped struct already in use",
            ));
        }
        overlapped_wrapper.in_use = true;

        PipeConnection::read_internal(
            &self.handle,
            self.blocking_mode,
            buf,
            Some(&mut overlapped_wrapper.overlapped),
        )?;
        Ok(())
    }

    /// Helper for `read_overlapped` and `read`
    ///
    /// # Safety
    /// Comments `read_overlapped` or `read`, depending on which is used.
    unsafe fn read_internal<T: PipeSendable>(
        handle: &SafeDescriptor,
        blocking_mode: BlockingMode,
        buf: &mut [T],
        overlapped: Option<&mut OVERLAPPED>,
    ) -> Result<usize> {
        let res = crate::platform::read_file(
            handle,
            buf.as_mut_ptr() as *mut u8,
            mem::size_of_val(buf),
            overlapped,
        );
        match res {
            Ok(bytes_read) => Ok(bytes_read),
            Err(e)
                if blocking_mode == BlockingMode::NoWait
                    && e.raw_os_error() == Some(ERROR_NO_DATA as i32) =>
            {
                // A NOWAIT pipe will return ERROR_NO_DATA when no data is available; however,
                // this code is interpreted as a std::io::ErrorKind::BrokenPipe, which is not
                // correct. For further details see:
                // https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-
                // https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipe-type-read-and-wait-modes
                Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, e))
            }
            Err(e) => Err(e),
        }
    }

    /// Blockingly reads a `buf` bytes from the pipe. The blocking read can be interrupted
    /// by an event on `exit_event`.
    pub fn read_overlapped_blocking<T: PipeSendable>(
        &mut self,
        buf: &mut [T],
        overlapped_wrapper: &mut OverlappedWrapper,
        exit_event: &Event,
    ) -> Result<()> {
        // Safe because we are providing a valid buffer slice and also providing a valid
        // overlapped struct.
        match unsafe { self.read_overlapped(buf, overlapped_wrapper) } {
            // More data isn't necessarily an error as long as we've filled the provided buffer,
            // as is checked later in this function.
            Err(e) if e.raw_os_error().expect("must be an OS error") == ERROR_MORE_DATA as i32 => {
                Ok(())
            }
            Err(e) => Err(e),
            Ok(()) => Ok(()),
        }?;

        #[derive(EventToken)]
        enum Token {
            ReadOverlapped,
            Exit,
        }

        let wait_ctx = WaitContext::build_with(&[
            (
                overlapped_wrapper.get_h_event_ref().unwrap(),
                Token::ReadOverlapped,
            ),
            (exit_event, Token::Exit),
        ])?;

        let events = wait_ctx.wait()?;
        for event in events {
            match event.token {
                Token::ReadOverlapped => {
                    let size_read_in_bytes =
                        self.get_overlapped_result(overlapped_wrapper)? as usize;

                    // If this error shows, most likely the overlapped named pipe was set up
                    // incorrectly.
                    if size_read_in_bytes != buf.len() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "Short read",
                        ));
                    }
                }
                Token::Exit => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "IO canceled on exit request",
                    ));
                }
            }
        }

        Ok(())
    }

    /// Reads a variable size message and returns the message on success.
    /// The size of the message is expected to proceed the message in
    /// the form of `header_size` message.
    ///
    /// `parse_message_size` lets caller parse the header to extract
    /// message size.
    ///
    /// Event on `exit_event` is used to interrupt the blocked read.
    pub fn read_overlapped_blocking_message<F: FnOnce(&[u8]) -> usize>(
        &mut self,
        header_size: usize,
        parse_message_size: F,
        overlapped_wrapper: &mut OverlappedWrapper,
        exit_event: &Event,
    ) -> Result<Vec<u8>> {
        let mut header = vec![0; header_size];
        header.resize_with(header_size, Default::default);
        self.read_overlapped_blocking(&mut header, overlapped_wrapper, exit_event)?;
        let message_size = parse_message_size(&header);
        if message_size == 0 {
            return Ok(vec![]);
        }
        let mut buf = vec![];
        buf.resize_with(message_size, Default::default);
        self.read_overlapped_blocking(&mut buf, overlapped_wrapper, exit_event)?;
        Ok(buf)
    }

    /// Gets the size in bytes of data in the pipe.
    ///
    /// Note that PeekNamedPipes (the underlying win32 API) will return zero if the packets have
    /// not finished writing on the producer side.
    pub fn get_available_byte_count(&self) -> io::Result<u32> {
        let mut total_bytes_avail: DWORD = 0;

        // Safe because the underlying pipe handle is guaranteed to be open, and the output values
        // live at valid memory locations.
        fail_if_zero!(unsafe {
            PeekNamedPipe(
                self.as_raw_descriptor(),
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                &mut total_bytes_avail,
                ptr::null_mut(),
            )
        });

        Ok(total_bytes_avail)
    }

    /// Writes the bytes from a slice into the pipe. Returns the number of bytes written, which
    /// callers should check to ensure that it was the number expected.
    pub fn write<T: PipeSendable>(&self, buf: &[T]) -> Result<usize> {
        // SAFETY: overlapped is None so this is safe.
        unsafe { PipeConnection::write_internal(&self.handle, buf, None) }
    }

    /// Sends, blockingly,`buf` over the pipe in its entirety. Partial write is considered
    /// as a failure.
    pub fn write_overlapped_blocking_message<T: PipeSendable>(
        &mut self,
        buf: &[T],
        overlapped_wrapper: &mut OverlappedWrapper,
    ) -> Result<()> {
        // SAFETY: buf & overlapped_wrapper live until the overlapped operation is
        // complete, so this is safe.
        unsafe { self.write_overlapped(buf, overlapped_wrapper)? };

        let size_written_in_bytes = self.get_overlapped_result(overlapped_wrapper)?;

        if size_written_in_bytes as usize != buf.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!(
                    "Short write expected:{} found:{}",
                    size_written_in_bytes,
                    buf.len(),
                ),
            ));
        }
        Ok(())
    }

    /// Similar to `PipeConnection::write` except it also allows:
    ///     1. The same end of the named pipe to read and write at the same time in different
    ///        threads.
    ///     2. Asynchronous read and write (read and write won't block).
    ///
    /// When writing, it will not block, but instead an `OVERLAPPED` struct that contains an event
    /// (can be created with `OverlappedWrapper::new`) will be passed into
    /// `WriteFile`. That event will be triggered when the write operation is complete.
    ///
    /// In order to get how many bytes were written, call `get_overlapped_result`. That function will
    /// also help with waiting until the write operation is complete. The pipe must be opened in
    /// overlapped otherwise there may be unexpected behavior.
    ///
    /// # Safety
    /// * buf & overlapped_wrapper MUST live until the overlapped operation is complete.
    pub unsafe fn write_overlapped<T: PipeSendable>(
        &mut self,
        buf: &[T],
        overlapped_wrapper: &mut OverlappedWrapper,
    ) -> Result<()> {
        if overlapped_wrapper.in_use {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Overlapped struct already in use",
            ));
        }
        overlapped_wrapper.in_use = true;

        PipeConnection::write_internal(
            &self.handle,
            buf,
            Some(&mut overlapped_wrapper.overlapped),
        )?;
        Ok(())
    }

    /// Helper for `write_overlapped` and `write`.
    ///
    /// # Safety
    /// * Safe if overlapped is None.
    /// * Safe if overlapped is Some and:
    ///   + buf lives until the overlapped operation is complete.
    ///   + overlapped lives until the overlapped operation is complete.
    unsafe fn write_internal<T: PipeSendable>(
        handle: &SafeDescriptor,
        buf: &[T],
        overlapped: Option<&mut OVERLAPPED>,
    ) -> Result<usize> {
        // Safe because buf points to memory valid until the write completes and we pass a valid
        // length for that memory.
        unsafe {
            crate::platform::write_file(
                handle,
                buf.as_ptr() as *const u8,
                mem::size_of_val(buf),
                overlapped,
            )
        }
    }

    /// Sets the blocking mode on the pipe.
    pub fn set_blocking(&mut self, blocking_mode: &BlockingMode) -> io::Result<()> {
        let mut client_mode = DWORD::from(blocking_mode) | self.framing_mode.to_readmode();
        self.blocking_mode = *blocking_mode;

        // Safe because the pipe has not been closed (it is managed by this object).
        unsafe { set_named_pipe_handle_state(self.handle.as_raw_descriptor(), &mut client_mode) }
    }

    /// For a server named pipe, waits for a client to connect (blocking).
    pub fn wait_for_client_connection(&self) -> Result<()> {
        let mut overlapped_wrapper = OverlappedWrapper::new(/* include_event = */ true)?;
        self.wait_for_client_connection_internal(
            &mut overlapped_wrapper,
            /* should_block = */ true,
        )
    }

    /// Interruptable blocking wait for a client to connect.
    pub fn wait_for_client_connection_overlapped_blocking(
        &mut self,
        exit_event: &Event,
    ) -> Result<()> {
        let mut overlapped_wrapper = OverlappedWrapper::new(/* include_event = */ true)?;
        self.wait_for_client_connection_internal(
            &mut overlapped_wrapper,
            /* should_block = */ false,
        )?;

        #[derive(EventToken)]
        enum Token {
            Connected,
            Exit,
        }

        let wait_ctx = WaitContext::build_with(&[
            (
                overlapped_wrapper.get_h_event_ref().unwrap(),
                Token::Connected,
            ),
            (exit_event, Token::Exit),
        ])?;

        let events = wait_ctx.wait()?;
        if let Some(event) = events.into_iter().next() {
            return match event.token {
                Token::Connected => Ok(()),
                Token::Exit => {
                    // We must cancel IO here because it is unsafe to free the overlapped wrapper
                    // while the IO operation is active.
                    self.cancel_io()?;

                    Err(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "IO canceled on exit request",
                    ))
                }
            };
        }
        unreachable!("wait cannot return Ok with zero events");
    }

    /// For a server named pipe, waits for a client to connect using the given overlapped wrapper
    /// to signal connection.
    pub fn wait_for_client_connection_overlapped(
        &self,
        overlapped_wrapper: &mut OverlappedWrapper,
    ) -> Result<()> {
        self.wait_for_client_connection_internal(
            overlapped_wrapper,
            /* should_block = */ false,
        )
    }

    fn wait_for_client_connection_internal(
        &self,
        overlapped_wrapper: &mut OverlappedWrapper,
        should_block: bool,
    ) -> Result<()> {
        // Safe because the handle is valid and we're checking the return
        // code according to the documentation
        //
        // TODO(b/279669296) this safety statement is incomplete, and as such incorrect in one case:
        //      overlapped_wrapper must live until the overlapped operation is complete; however,
        //      if should_block is false, nothing guarantees that lifetime and so overlapped_wrapper
        //      could be freed while the operation is still running.
        unsafe {
            let success_flag = ConnectNamedPipe(
                self.as_raw_descriptor(),
                // Note: The overlapped structure is only used if the pipe was opened in
                // OVERLAPPED mode, but is necessary in that case.
                &mut *overlapped_wrapper.overlapped,
            );
            if success_flag == 0 {
                return match GetLastError() {
                    ERROR_PIPE_CONNECTED => {
                        if !should_block {
                            // If async, make sure the event is signalled to indicate the client
                            // is ready.
                            overlapped_wrapper.get_h_event_ref().unwrap().signal()?;
                        }

                        Ok(())
                    }
                    ERROR_IO_PENDING => {
                        if should_block {
                            overlapped_wrapper.get_h_event_ref().unwrap().wait()?;
                        }
                        Ok(())
                    }
                    err => Err(io::Error::from_raw_os_error(err as i32)),
                };
            }
        }
        Ok(())
    }

    /// Used for overlapped read and write operations.
    ///
    /// This will block until the ReadFile or WriteFile operation that also took in
    /// `overlapped_wrapper` is complete, assuming `overlapped_wrapper` was created from
    /// `OverlappedWrapper::new` or that `OVERLAPPED.hEvent` is set. This will also get
    /// the number of bytes that were read or written.
    pub fn get_overlapped_result(
        &mut self,
        overlapped_wrapper: &mut OverlappedWrapper,
    ) -> io::Result<u32> {
        let res = self.get_overlapped_result_internal(overlapped_wrapper, /* wait= */ true);
        overlapped_wrapper.in_use = false;
        res
    }

    /// Used for overlapped read and write operations.
    ///
    /// This will return immediately, regardless of the completion status of the
    /// ReadFile or WriteFile operation that took in `overlapped_wrapper`,
    /// assuming `overlapped_wrapper` was created from `OverlappedWrapper::new`
    /// or that `OVERLAPPED.hEvent` is set. This will also get the number of bytes
    /// that were read or written, if completed.  If the operation hasn't
    /// completed, an error of kind `io::ErrorKind::WouldBlock` will be
    /// returned.
    pub fn try_get_overlapped_result(
        &mut self,
        overlapped_wrapper: &mut OverlappedWrapper,
    ) -> io::Result<u32> {
        let res = self.get_overlapped_result_internal(overlapped_wrapper, /* wait= */ false);
        match res {
            Err(err) if err.raw_os_error().unwrap() as u32 == ERROR_IO_INCOMPLETE => {
                Err(io::Error::new(io::ErrorKind::WouldBlock, err))
            }
            _ => {
                overlapped_wrapper.in_use = false;
                res
            }
        }
    }

    fn get_overlapped_result_internal(
        &mut self,
        overlapped_wrapper: &mut OverlappedWrapper,
        wait: bool,
    ) -> io::Result<u32> {
        if !overlapped_wrapper.in_use {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Overlapped struct is not in use",
            ));
        }
        let mut size_transferred = 0;
        // Safe as long as `overlapped_struct` isn't copied and also contains a valid event.
        // Also the named pipe handle must created with `FILE_FLAG_OVERLAPPED`.
        fail_if_zero!(unsafe {
            GetOverlappedResult(
                self.handle.as_raw_descriptor(),
                &mut *overlapped_wrapper.overlapped,
                &mut size_transferred,
                if wait { TRUE } else { FALSE },
            )
        });

        Ok(size_transferred)
    }

    /// Cancels I/O Operations in the current process. Since `lpOverlapped` is null, this will
    /// cancel all I/O requests for the file handle passed in.
    pub fn cancel_io(&mut self) -> Result<()> {
        fail_if_zero!(unsafe {
            CancelIoEx(
                self.handle.as_raw_descriptor(),
                /* lpOverlapped= */ std::ptr::null_mut(),
            )
        });

        Ok(())
    }

    /// Get the framing mode of the pipe.
    pub fn get_framing_mode(&self) -> FramingMode {
        self.framing_mode
    }

    /// Returns metadata about the connected NamedPipe.
    pub fn get_info(&self) -> Result<NamedPipeInfo> {
        let mut flags: u32 = 0;
        let mut incoming_buffer_size: u32 = 0;
        let mut outgoing_buffer_size: u32 = 0;
        let mut max_instances: u32 = 0;
        // SAFETY: all pointers are valid
        fail_if_zero!(unsafe {
            GetNamedPipeInfo(
                self.as_raw_descriptor(),
                &mut flags,
                &mut outgoing_buffer_size,
                &mut incoming_buffer_size,
                &mut max_instances,
            )
        });

        Ok(NamedPipeInfo {
            outgoing_buffer_size,
            incoming_buffer_size,
            max_instances,
            flags,
        })
    }

    /// For a server pipe, flush the pipe contents. This will
    /// block until the pipe is cleared by the client. Only
    /// call this if you are sure the client is reading the
    /// data!
    pub fn flush_data_blocking(&self) -> Result<()> {
        // Safe because the only buffers interacted with are
        // outside of Rust memory
        fail_if_zero!(unsafe { FlushFileBuffers(self.as_raw_descriptor()) });
        Ok(())
    }

    /// For a server pipe, disconnect all clients, discarding any buffered data.
    pub fn disconnect_clients(&self) -> Result<()> {
        // Safe because we own the handle passed in and know it will remain valid for the duration
        // of the call. Discarded buffers are not managed by rust.
        fail_if_zero!(unsafe { DisconnectNamedPipe(self.as_raw_descriptor()) });
        Ok(())
    }
}

impl AsRawDescriptor for PipeConnection {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.handle.as_raw_descriptor()
    }
}

impl IntoRawDescriptor for PipeConnection {
    fn into_raw_descriptor(self) -> RawDescriptor {
        self.handle.into_raw_descriptor()
    }
}

unsafe impl Send for PipeConnection {}
unsafe impl Sync for PipeConnection {}

impl io::Read for PipeConnection {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // This is safe because PipeConnection::read is always safe for u8
        unsafe { PipeConnection::read(self, buf) }
    }
}

impl io::Write for PipeConnection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        PipeConnection::write(self, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A simple data struct representing
/// metadata about a NamedPipe.
#[derive(Debug, PartialEq, Eq)]
pub struct NamedPipeInfo {
    pub outgoing_buffer_size: u32,
    pub incoming_buffer_size: u32,
    pub max_instances: u32,
    pub flags: u32,
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;
    use std::time::Duration;

    use super::*;

    #[test]
    fn duplex_pipe_stream() {
        let (p1, p2) = pair(&FramingMode::Byte, &BlockingMode::Wait, 0).unwrap();

        // Test both forward and reverse direction since the underlying APIs are a bit asymmetrical
        unsafe {
            for (dir, sender, receiver) in [("1 -> 2", &p1, &p2), ("2 -> 1", &p2, &p1)].iter() {
                println!("{}", dir);

                sender.write(&[75, 77, 54, 82, 76, 65]).unwrap();

                // Smaller than what we sent so we get multiple chunks
                let mut recv_buffer: [u8; 4] = [0; 4];

                let mut size = receiver.read(&mut recv_buffer).unwrap();
                assert_eq!(size, 4);
                assert_eq!(recv_buffer, [75, 77, 54, 82]);

                size = receiver.read(&mut recv_buffer).unwrap();
                assert_eq!(size, 2);
                assert_eq!(recv_buffer[0..2], [76, 65]);
            }
        }
    }

    #[test]
    fn available_byte_count_byte_mode() {
        let (p1, p2) = pair(&FramingMode::Byte, &BlockingMode::Wait, 0).unwrap();
        p1.write(&[1, 23, 45]).unwrap();
        assert_eq!(p2.get_available_byte_count().unwrap(), 3);

        // PeekNamedPipe should NOT touch the data in the pipe. So if we call it again, it should
        // yield the same value.
        assert_eq!(p2.get_available_byte_count().unwrap(), 3);
    }

    #[test]
    fn available_byte_count_message_mode() {
        let (p1, p2) = pair(&FramingMode::Message, &BlockingMode::Wait, 0).unwrap();
        p1.write(&[1, 23, 45]).unwrap();
        assert_eq!(p2.get_available_byte_count().unwrap(), 3);

        // PeekNamedPipe should NOT touch the data in the pipe. So if we call it again, it should
        // yield the same value.
        assert_eq!(p2.get_available_byte_count().unwrap(), 3);
    }

    #[test]
    fn available_byte_count_message_mode_multiple_messages() {
        let (p1, p2) = pair(&FramingMode::Message, &BlockingMode::Wait, 0).unwrap();
        p1.write(&[1, 2, 3]).unwrap();
        p1.write(&[4, 5]).unwrap();
        assert_eq!(p2.get_available_byte_count().unwrap(), 5);
    }

    #[test]
    fn duplex_pipe_message() {
        let (p1, p2) = pair(&FramingMode::Message, &BlockingMode::Wait, 0).unwrap();

        // Test both forward and reverse direction since the underlying APIs are a bit asymmetrical
        unsafe {
            for (dir, sender, receiver) in [("1 -> 2", &p1, &p2), ("2 -> 1", &p2, &p1)].iter() {
                println!("{}", dir);

                // Send 2 messages so that we can check that message framing works
                sender.write(&[1, 23, 45]).unwrap();
                sender.write(&[67, 89, 10]).unwrap();

                let mut recv_buffer: [u8; 5] = [0; 5]; // Larger than required for messages

                let mut size = receiver.read(&mut recv_buffer).unwrap();
                assert_eq!(size, 3);
                assert_eq!(recv_buffer[0..3], [1, 23, 45]);

                size = receiver.read(&mut recv_buffer).unwrap();
                assert_eq!(size, 3);
                assert_eq!(recv_buffer[0..3], [67, 89, 10]);
            }
        }
    }

    #[cfg(test)]
    fn duplex_nowait_helper(p1: &PipeConnection, p2: &PipeConnection) {
        let mut recv_buffer: [u8; 1] = [0; 1];

        // Test both forward and reverse direction since the underlying APIs are a bit asymmetrical
        unsafe {
            for (dir, sender, receiver) in [("1 -> 2", &p1, &p2), ("2 -> 1", &p2, &p1)].iter() {
                println!("{}", dir);
                sender.write(&[1]).unwrap();
                assert_eq!(receiver.read(&mut recv_buffer).unwrap(), 1); // Should succeed!
                assert_eq!(
                    receiver.read(&mut recv_buffer).unwrap_err().kind(),
                    std::io::ErrorKind::WouldBlock
                );
            }
        }
    }

    #[test]
    fn duplex_nowait() {
        let (p1, p2) = pair(&FramingMode::Byte, &BlockingMode::NoWait, 0).unwrap();
        duplex_nowait_helper(&p1, &p2);
    }

    #[test]
    fn duplex_nowait_set_after_creation() {
        // Tests non blocking setting after pipe creation
        let (mut p1, mut p2) = pair(&FramingMode::Byte, &BlockingMode::Wait, 0).unwrap();
        p1.set_blocking(&BlockingMode::NoWait)
            .expect("Failed to set blocking mode on pipe p1");
        p2.set_blocking(&BlockingMode::NoWait)
            .expect("Failed to set blocking mode on pipe p2");
        duplex_nowait_helper(&p1, &p2);
    }

    #[test]
    fn duplex_overlapped() {
        let pipe_name = generate_pipe_name();

        let mut p1 = create_server_pipe(
            &pipe_name,
            &FramingMode::Message,
            &BlockingMode::Wait,
            /* timeout= */ 0,
            /* buffer_size= */ 1000,
            /* overlapped= */ true,
        )
        .unwrap();

        let mut p2 = create_client_pipe(
            &pipe_name,
            &FramingMode::Message,
            &BlockingMode::Wait,
            /* overlapped= */ true,
        )
        .unwrap();

        // Safe because `read_overlapped` can be called since overlapped struct is created.
        unsafe {
            let mut p1_overlapped_wrapper =
                OverlappedWrapper::new(/* include_event= */ true).unwrap();
            p1.write_overlapped(&[75, 77, 54, 82, 76, 65], &mut p1_overlapped_wrapper)
                .unwrap();
            let size = p1
                .get_overlapped_result(&mut p1_overlapped_wrapper)
                .unwrap();
            assert_eq!(size, 6);

            let mut recv_buffer: [u8; 6] = [0; 6];

            let mut p2_overlapped_wrapper =
                OverlappedWrapper::new(/* include_event= */ true).unwrap();
            p2.read_overlapped(&mut recv_buffer, &mut p2_overlapped_wrapper)
                .unwrap();
            let size = p2
                .get_overlapped_result(&mut p2_overlapped_wrapper)
                .unwrap();
            assert_eq!(size, 6);
            assert_eq!(recv_buffer, [75, 77, 54, 82, 76, 65]);
        }
    }

    #[test]
    fn duplex_overlapped_test_in_use() {
        let pipe_name = generate_pipe_name();

        let mut p1 = create_server_pipe(
            &pipe_name,
            &FramingMode::Message,
            &BlockingMode::Wait,
            /* timeout= */ 0,
            /* buffer_size= */ 1000,
            /* overlapped= */ true,
        )
        .unwrap();

        let mut p2 = create_client_pipe(
            &pipe_name,
            &FramingMode::Message,
            &BlockingMode::Wait,
            /* overlapped= */ true,
        )
        .unwrap();
        let mut overlapped_wrapper = OverlappedWrapper::new(/* include_event= */ true).unwrap();

        let res = p1.get_overlapped_result(&mut overlapped_wrapper);
        assert!(res.is_err());

        let data = vec![75, 77, 54, 82, 76, 65];
        // SAFETY: safe because: data & overlapped wrapper live until the
        // operation is verified completed below.
        let res = unsafe { p1.write_overlapped(&data, &mut overlapped_wrapper) };
        assert!(res.is_ok());

        // SAFETY: safe because we know the unsafe re-use of overlapped wrapper
        // will error out.
        let res =
            unsafe { p2.write_overlapped(&[75, 77, 54, 82, 76, 65], &mut overlapped_wrapper) };
        assert!(res.is_err());

        let mut recv_buffer: [u8; 6] = [0; 6];
        // SAFETY: safe because we know the unsafe re-use of overlapped wrapper
        // will error out.
        let res = unsafe { p2.read_overlapped(&mut recv_buffer, &mut overlapped_wrapper) };
        assert!(res.is_err());

        let res = p1.get_overlapped_result(&mut overlapped_wrapper);
        assert!(res.is_ok());

        let mut recv_buffer: [u8; 6] = [0; 6];
        // SAFETY: safe because recv_buffer & overlapped_wrapper live until the
        // operation is verified completed below.
        let res = unsafe { p2.read_overlapped(&mut recv_buffer, &mut overlapped_wrapper) };
        assert!(res.is_ok());
        let res = p2.get_overlapped_result(&mut overlapped_wrapper);
        assert!(res.is_ok());
    }

    fn generate_pipe_name() -> String {
        format!(
            r"\\.\pipe\test-ipc-pipe-name.rand{}",
            rand::thread_rng().gen::<u64>(),
        )
    }

    #[test]
    fn read_write_overlapped_message() {
        let pipe_name = generate_pipe_name();

        let mut p1 = create_server_pipe(
            &pipe_name,
            &FramingMode::Message,
            &BlockingMode::Wait,
            /* timeout= */ 0,
            /* buffer_size= */ 1000,
            /* overlapped= */ true,
        )
        .unwrap();

        let mut p2 = create_client_pipe(
            &pipe_name,
            &FramingMode::Message,
            &BlockingMode::Wait,
            /* overlapped= */ true,
        )
        .unwrap();

        // Safe because `read_overlapped` can be called since overlapped struct is created.
        let mut p1_overlapped_wrapper = OverlappedWrapper::new(/* include_event= */ true).unwrap();
        const MSG: [u8; 6] = [75, 77, 54, 82, 76, 65];
        p1.write_overlapped_blocking_message(&MSG.len().to_be_bytes(), &mut p1_overlapped_wrapper)
            .unwrap();
        p1.write_overlapped_blocking_message(&MSG, &mut p1_overlapped_wrapper)
            .unwrap();

        let mut p2_overlapped_wrapper = OverlappedWrapper::new(/* include_event= */ true).unwrap();
        let exit_event = Event::new().unwrap();
        let recv_buffer = p2
            .read_overlapped_blocking_message(
                size_of::<usize>(),
                |buf| usize::from_be_bytes(buf.try_into().expect("failed to get array from slice")),
                &mut p2_overlapped_wrapper,
                &exit_event,
            )
            .unwrap();
        assert_eq!(recv_buffer, MSG);
    }

    #[test]
    fn test_wait_for_connection_blocking() {
        let pipe_name = generate_pipe_name();

        let mut server_pipe = create_server_pipe(
            &pipe_name,
            &FramingMode::Message,
            &BlockingMode::Wait,
            /* timeout= */ 0,
            /* buffer_size= */ 1000,
            /* overlapped= */ true,
        )
        .unwrap();

        let server = crate::thread::spawn_with_timeout(move || {
            let exit_event = Event::new().unwrap();
            server_pipe
                .wait_for_client_connection_overlapped_blocking(&exit_event)
                .unwrap();
        });

        let _client = create_client_pipe(
            &pipe_name,
            &FramingMode::Message,
            &BlockingMode::Wait,
            /* overlapped= */ true,
        )
        .unwrap();
        server.try_join(Duration::from_secs(10)).unwrap();
    }

    #[test]
    fn test_wait_for_connection_blocking_exit_triggered() {
        let pipe_name = generate_pipe_name();

        let mut server_pipe = create_server_pipe(
            &pipe_name,
            &FramingMode::Message,
            &BlockingMode::Wait,
            /* timeout= */ 0,
            /* buffer_size= */ 1000,
            /* overlapped= */ true,
        )
        .unwrap();

        let exit_event = Event::new().unwrap();
        let exit_event_for_server = exit_event.try_clone().unwrap();
        let server = crate::thread::spawn_with_timeout(move || {
            assert!(server_pipe
                .wait_for_client_connection_overlapped_blocking(&exit_event_for_server)
                .is_err());
        });
        exit_event.signal().unwrap();
        server.try_join(Duration::from_secs(10)).unwrap();
    }
}
