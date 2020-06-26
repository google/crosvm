// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use crate::io_source::IoSource;
use crate::uring_executor::Result;
use crate::uring_mem::{BackingMemory, MemRegion};

use super::uring_fut::UringFutState;

/// Future for the `write_from_mem` function.
#[must_use = "futures do nothing unless you `.await` or poll them"]
pub struct WriteMem<'a, 'b, W: IoSource + ?Sized> {
    writer: &'a W,
    state: UringFutState<(u64, Rc<dyn BackingMemory>, &'b [MemRegion]), Rc<dyn BackingMemory>>,
}

impl<'a, 'b, R: IoSource + ?Sized + Unpin> WriteMem<'a, 'b, R> {
    pub(crate) fn new(
        writer: &'a R,
        file_offset: u64,
        mem: Rc<dyn BackingMemory>,
        mem_offsets: &'b [MemRegion],
    ) -> Self {
        WriteMem {
            writer,
            state: UringFutState::new((file_offset, mem, mem_offsets)),
        }
    }
}

impl<R: IoSource + ?Sized + Unpin> Future for WriteMem<'_, '_, R> {
    type Output = Result<u32>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Special case writing zero bytes, no need to bother the kernel with an empty operation.
        if let UringFutState::Init((_, _, regions)) = &self.state {
            if regions.iter().all(|region| region.len == 0) {
                return Poll::Ready(Ok(0));
            }
        }

        let state = std::mem::replace(&mut self.state, UringFutState::Processing);
        let (new_state, ret) = match state.advance(
            |(file_offset, mem, mem_offsets)| {
                Ok((
                    Pin::new(&self.writer).write_from_mem(
                        file_offset,
                        Rc::clone(&mem),
                        mem_offsets,
                    )?,
                    mem,
                ))
            },
            |op| Pin::new(&self.writer).poll_complete(cx, op),
        ) {
            Ok(d) => d,
            Err(e) => return Poll::Ready(Err(e)),
        };

        self.state = new_state;

        match ret {
            Poll::Pending => Poll::Pending,
            Poll::Ready((r, _)) => Poll::Ready(r),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::rc::Rc;

    use futures::pin_mut;

    use crate::io_ext::IoSourceExt;
    use crate::uring_mem::MemRegion;
    use crate::UringSource;

    #[test]
    fn writemem() {
        async fn go() {
            let f = OpenOptions::new()
                .create(true)
                .write(true)
                .open("/tmp/write_from_vec")
                .unwrap();
            let source = UringSource::new(f).unwrap();
            let v = vec![0x55u8; 64];
            let vw = Rc::new(crate::uring_mem::VecIoWrapper::from(v));
            let ret = source
                .write_from_mem(0, vw, &[MemRegion { offset: 0, len: 32 }])
                .await
                .unwrap();
            assert_eq!(32, ret);
        }

        let fut = go();
        pin_mut!(fut);
        crate::run_one_uring(fut).unwrap();
    }
}
