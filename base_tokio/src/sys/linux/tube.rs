// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::os::fd::AsRawFd;

use tokio::io::unix::AsyncFd;

/// An async version of `base::Tube`.
pub struct TubeTokio(AsyncFd<base::Tube>);

impl TubeTokio {
    pub fn new(tube: base::Tube) -> anyhow::Result<Self> {
        base::add_fd_flags(tube.as_raw_fd(), libc::O_NONBLOCK)?;
        Ok(Self(AsyncFd::new(tube)?))
    }

    pub async fn into_inner(self) -> base::Tube {
        let tube = self.0.into_inner();
        base::clear_fd_flags(tube.as_raw_fd(), libc::O_NONBLOCK)
            .expect("failed to clear O_NONBLOCK");
        tube
    }

    pub async fn send<T: serde::Serialize + Send + 'static>(
        &mut self,
        msg: T,
    ) -> base::TubeResult<()> {
        loop {
            let mut guard = self.0.writable().await.map_err(base::TubeError::Send)?;
            match guard.try_io(|inner| {
                // Re-using the non-async send is potentially hazardous since it isn't explicitly
                // written with O_NONBLOCK support. However, since it uses SOCK_SEQPACKET and a
                // single write syscall, it should be OK.
                let r = inner.get_ref().send(&msg);
                // Transpose the `std::io::Error` errors outside so that `try_io` can check them
                // for `WouldBlock`.
                match r {
                    Ok(x) => Ok(Ok(x)),
                    Err(base::TubeError::Send(e)) => Err(e),
                    Err(e) => Ok(Err(e)),
                }
            }) {
                Ok(result) => {
                    return match result {
                        Ok(Ok(x)) => Ok(x),
                        Ok(Err(e)) => Err(e),
                        Err(e) => Err(base::TubeError::Send(e)),
                    }
                }
                Err(_would_block) => continue,
            }
        }
    }

    pub async fn recv<T: serde::de::DeserializeOwned + Send + 'static>(
        &mut self,
    ) -> base::TubeResult<T> {
        loop {
            let mut guard = self.0.readable().await.map_err(base::TubeError::Recv)?;
            match guard.try_io(|inner| {
                // Re-using the non-async recv is potentially hazardous since it isn't explicitly
                // written with O_NONBLOCK support. However, since it uses SOCK_SEQPACKET and a
                // single read syscall, it should be OK.
                let r = inner.get_ref().recv();
                // Transpose the `std::io::Error` errors outside so that `try_io` can check them
                // for `WouldBlock`.
                match r {
                    Ok(x) => Ok(Ok(x)),
                    Err(base::TubeError::Recv(e)) => Err(e),
                    Err(e) => Ok(Err(e)),
                }
            }) {
                Ok(result) => {
                    return match result {
                        Ok(Ok(x)) => Ok(x),
                        Ok(Err(e)) => Err(e),
                        Err(e) => Err(base::TubeError::Recv(e)),
                    }
                }
                Err(_would_block) => continue,
            }
        }
    }
}
