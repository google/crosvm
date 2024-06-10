// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::os::fd::AsRawFd;

use tokio::io::unix::AsyncFd;

/// An async version of `base::Event`.
pub struct EventTokio(AsyncFd<base::SafeDescriptor>);

impl EventTokio {
    /// WARNING: Sets O_NONBLOCK internally, which will also affect all clones of the `Event`.
    pub fn new(event: base::Event) -> anyhow::Result<Self> {
        let fd: base::SafeDescriptor = event.into();
        base::add_fd_flags(fd.as_raw_fd(), libc::O_NONBLOCK)?;
        Ok(Self(AsyncFd::new(fd)?))
    }

    /// Blocks until the event is signaled and clears the signal.
    ///
    /// It is undefined behavior to wait on an event from multiple threads or processes
    /// simultaneously.
    pub async fn wait(&self) -> std::io::Result<()> {
        loop {
            let mut guard = self.0.readable().await?;
            let io_result = guard.try_io(|inner| {
                let mut buf: u64 = 0;
                // SAFETY: This is safe because we made this fd and the pointer we pass can not
                // overflow because we give the syscall's size parameter properly.
                let ret = unsafe {
                    libc::read(
                        inner.as_raw_fd(),
                        &mut buf as *mut u64 as *mut libc::c_void,
                        std::mem::size_of::<u64>(),
                    )
                };
                if ret < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if ret as usize != std::mem::size_of::<u64>() {
                    return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
                }
                Ok(())
            });

            match io_result {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }
}
