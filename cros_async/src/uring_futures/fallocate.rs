// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::io_source::IoSource;
use crate::uring_executor::Result;

use super::uring_fut::UringFutState;

/// Future for the `fallocate` function.
#[derive(Debug)]
#[must_use = "futures do nothing unless you `.await` or poll them"]
pub struct Fallocate<'a, R: IoSource + ?Sized> {
    reader: &'a R,
    state: UringFutState<(u64, u64, u32), ()>,
}

impl<'a, R: IoSource + ?Sized + Unpin> Fallocate<'a, R> {
    pub(crate) fn new(reader: &'a R, file_offset: u64, len: u64, mode: u32) -> Self {
        Fallocate {
            reader,
            state: UringFutState::new((file_offset, len, mode)),
        }
    }
}

impl<R: IoSource + ?Sized + Unpin> Future for Fallocate<'_, R> {
    type Output = Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let state = std::mem::replace(&mut self.state, UringFutState::Processing);
        let (new_state, ret) = match state.advance(
            |(file_offset, len, mode)| {
                Ok((
                    Pin::new(&self.reader).fallocate(file_offset, len, mode)?,
                    (),
                ))
            },
            |op| Pin::new(&self.reader).poll_complete(cx, op),
        ) {
            Ok(d) => d,
            Err(e) => return Poll::Ready(Err(e)),
        };

        self.state = new_state;

        match ret {
            Poll::Pending => Poll::Pending,
            Poll::Ready((r, ())) => match r {
                Ok(_) => Poll::Ready(Ok(())),
                Err(e) => Poll::Ready(Err(e)),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::path::PathBuf;

    use futures::pin_mut;

    use crate::io_ext::IoSourceExt;
    use crate::UringSource;

    #[test]
    fn fallocate() {
        async fn go() {
            let dir = tempfile::TempDir::new().unwrap();
            let mut file_path = PathBuf::from(dir.path());
            file_path.push("test");

            let f = OpenOptions::new()
                .create(true)
                .write(true)
                .open(&file_path)
                .unwrap();
            let source = UringSource::new(f).unwrap();
            if let Err(e) = source.fallocate(0, 4096, 0).await {
                match e {
                    crate::uring_executor::Error::Io(io_err) => {
                        if io_err.kind() == std::io::ErrorKind::InvalidInput {
                            // Skip the test on kernels before fallocate support.
                            return;
                        }
                    }
                    _ => panic!("Unexpected uring error on fallocate: {}", e),
                }
            }

            let meta_data = std::fs::metadata(&file_path).unwrap();
            assert_eq!(meta_data.len(), 4096);
        }

        let fut = go();
        pin_mut!(fut);
        crate::run_one_uring(fut).unwrap();
    }
}
