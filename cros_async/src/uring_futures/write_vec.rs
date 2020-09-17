// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use crate::io_source::IoSource;
//TODO - move memvec to uring_mem
use crate::uring_executor::Result;
use crate::uring_mem::{MemRegion, VecIoWrapper};

use super::uring_fut::UringFutState;

/// Future for the `write_to_vec` function.
#[must_use = "futures do nothing unless you `.await` or poll them"]
pub struct WriteVec<'a, W: IoSource + ?Sized> {
    writer: &'a W,
    state: UringFutState<(u64, Rc<VecIoWrapper>), Rc<VecIoWrapper>>,
}

impl<'a, W: IoSource + ?Sized> WriteVec<'a, W> {
    pub(crate) fn new(writer: &'a W, file_offset: u64, vec: Vec<u8>) -> Self {
        WriteVec {
            writer,
            state: UringFutState::new((file_offset, Rc::new(VecIoWrapper::from(vec)))),
        }
    }
}

impl<W: IoSource + ?Sized> Future for WriteVec<'_, W> {
    type Output = Result<(u32, Vec<u8>)>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let state = std::mem::replace(&mut self.state, UringFutState::Processing);
        let (new_state, ret) = match state.advance(
            |(file_offset, wrapped_vec)| {
                Ok((
                    self.writer.write_from_mem(
                        file_offset,
                        Rc::<VecIoWrapper>::clone(&wrapped_vec),
                        &[MemRegion {
                            offset: 0,
                            len: wrapped_vec.len(),
                        }],
                    )?,
                    wrapped_vec,
                ))
            },
            |op| self.writer.poll_complete(cx, op),
        ) {
            Ok(d) => d,
            Err(e) => return Poll::Ready(Err(e)),
        };

        self.state = new_state;

        match ret {
            Poll::Pending => Poll::Pending,
            Poll::Ready((r, wrapped_vec)) => {
                let ret_vec = match Rc::try_unwrap(wrapped_vec) {
                    Ok(v) => v.into(),
                    Err(_) => {
                        panic!("too many refs on vec");
                    }
                };
                match r {
                    Ok(r) => Poll::Ready(Ok((r, ret_vec))),
                    Err(e) => Poll::Ready(Err(e)),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use futures::pin_mut;
    use std::fs::OpenOptions;

    use crate::io_ext::WriteAsync;
    use crate::UringSource;

    #[test]
    fn writevec() {
        async fn go() {
            let f = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open("/tmp/write_from_vec")
                .unwrap();
            let source = UringSource::new(f).unwrap();
            let v = vec![0x55u8; 32];
            let v_ptr = v.as_ptr();
            let (ret, ret_v) = source.write_from_vec(0, v).await.unwrap();
            assert_eq!(32, ret);
            assert_eq!(v_ptr, ret_v.as_ptr());
        }

        let fut = go();
        pin_mut!(fut);
        crate::run_one_uring(fut).unwrap();
    }

    #[test]
    fn readmulti() {
        async fn go() {
            let f = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open("/tmp/write_from_vec")
                .unwrap();
            let source = UringSource::new(f).unwrap();
            let v = vec![0x55u8; 32];
            let v2 = vec![0x55u8; 32];
            let (r, r2) =
                futures::future::join(source.write_from_vec(0, v), source.write_from_vec(32, v2))
                    .await;
            assert_eq!(32, r.unwrap().0);
            assert_eq!(32, r2.unwrap().0);
        }

        let fut = go();
        pin_mut!(fut);
        crate::run_one_uring(fut).unwrap();
    }
}
