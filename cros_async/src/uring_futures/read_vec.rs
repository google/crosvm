// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use crate::io_source::IoSource;
use crate::uring_executor::Result;
use crate::uring_mem::{MemRegion, VecIoWrapper};

use super::uring_fut::UringFutState;

/// Future for the `read_to_vec` function.
#[must_use = "futures do nothing unless you `.await` or poll them"]
pub struct ReadVec<'a, R: IoSource + ?Sized> {
    reader: &'a R,
    state: UringFutState<(u64, Rc<VecIoWrapper>), Rc<VecIoWrapper>>,
}

impl<'a, R: IoSource + ?Sized> ReadVec<'a, R> {
    pub(crate) fn new(reader: &'a R, file_offset: u64, vec: Vec<u8>) -> Self {
        ReadVec {
            reader,
            state: UringFutState::new((file_offset, Rc::new(VecIoWrapper::from(vec)))),
        }
    }
}

impl<R: IoSource + ?Sized> Future for ReadVec<'_, R> {
    type Output = Result<(u32, Vec<u8>)>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let state = std::mem::replace(&mut self.state, UringFutState::Processing);
        let (new_state, ret) = match state.advance(
            |(file_offset, wrapped_vec)| {
                Ok((
                    self.reader.read_to_mem(
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
            |op| self.reader.poll_complete(cx, op),
        ) {
            Ok(d) => d,
            Err(e) => return Poll::Ready(Err(e)),
        };

        self.state = new_state;

        match ret {
            Poll::Pending => Poll::Pending,
            Poll::Ready((r, wrapped_vec)) => match r {
                Ok(r) => Poll::Ready(Ok((
                    r,
                    match Rc::try_unwrap(wrapped_vec) {
                        Ok(v) => v.into(),
                        Err(_) => {
                            panic!("too many refs on vec");
                        }
                    },
                ))),
                Err(e) => Poll::Ready(Err(e)),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::os::unix::io::AsRawFd;

    use futures::pin_mut;

    use crate::io_ext::ReadAsync;
    use crate::UringSource;

    #[test]
    fn readvec() {
        async fn go() {
            let f = File::open("/dev/zero").unwrap();
            let source = UringSource::new(f).unwrap();
            let v = vec![0x55u8; 32];
            let v_ptr = v.as_ptr();
            let ret = source.read_to_vec(0, v).await.unwrap();
            assert_eq!(ret.0, 32);
            let ret_v = ret.1;
            assert_eq!(v_ptr, ret_v.as_ptr());
            assert!(ret_v.iter().all(|&b| b == 0));
        }

        let fut = go();
        pin_mut!(fut);
        crate::run_one_uring(fut).unwrap();
    }

    #[test]
    fn readmulti() {
        async fn go() {
            let f = File::open("/dev/zero").unwrap();
            let source = UringSource::new(f).unwrap();
            let v = vec![0x55u8; 32];
            let v2 = vec![0x55u8; 32];
            let (ret, ret2) =
                futures::future::join(source.read_to_vec(0, v), source.read_to_vec(32, v2)).await;

            assert!(ret.unwrap().1.iter().all(|&b| b == 0));
            assert!(ret2.unwrap().1.iter().all(|&b| b == 0));
        }

        let fut = go();
        pin_mut!(fut);
        crate::run_one_uring(fut).unwrap();
    }

    async fn read_u64<T: AsRawFd + Unpin>(source: &UringSource<T>) -> u64 {
        // Init a vec that translates to u64::max;
        let u64_mem = vec![0xffu8; std::mem::size_of::<u64>()];
        let (ret, u64_mem) = source.read_to_vec(0, u64_mem).await.unwrap();
        assert_eq!(ret as usize, std::mem::size_of::<u64>());
        let mut val = 0u64.to_ne_bytes();
        val.copy_from_slice(&u64_mem);
        u64::from_ne_bytes(val)
    }

    #[test]
    fn u64_from_file() {
        let f = File::open("/dev/zero").unwrap();
        let source = UringSource::new(f).unwrap();
        let read_val = read_u64(&source);
        pin_mut!(read_val);
        let res = crate::run_one_uring(read_val).unwrap();
        assert_eq!(0u64, res);
    }

    #[test]
    fn event() {
        use sys_util::EventFd;

        async fn write_event(ev: EventFd, wait: EventFd) {
            let wait = UringSource::new(wait).unwrap();
            ev.write(55).unwrap();
            read_u64(&wait).await;
            ev.write(66).unwrap();
            read_u64(&wait).await;
            ev.write(77).unwrap();
            read_u64(&wait).await;
        }

        async fn read_events(ev: EventFd, signal: EventFd) {
            let source = UringSource::new(ev).unwrap();
            assert_eq!(read_u64(&source).await, 55);
            signal.write(1).unwrap();
            assert_eq!(read_u64(&source).await, 66);
            signal.write(1).unwrap();
            assert_eq!(read_u64(&source).await, 77);
            signal.write(1).unwrap();
        }

        let event = EventFd::new().unwrap();
        let signal_wait = EventFd::new().unwrap();
        let write_task = write_event(event.try_clone().unwrap(), signal_wait.try_clone().unwrap());
        let read_task = read_events(event, signal_wait);
        let joined = futures::future::join(read_task, write_task);
        pin_mut!(joined);
        crate::run_one_uring(joined).unwrap();
    }

    #[test]
    fn pend_on_pipe() {
        use futures::future::Either;

        async fn do_test() {
            let (read_source, _w) = sys_util::pipe(true).unwrap();
            let source = UringSource::new(read_source).unwrap();
            let done = async { 5usize };
            let pending = read_u64(&source);
            pin_mut!(done);
            pin_mut!(pending);
            match futures::future::select(pending, done).await {
                Either::Right((5, pending)) => std::mem::drop(pending),
                _ => panic!("unexpected select result"),
            }
        }

        let fut = do_test();

        crate::run_one_uring(Box::pin(fut)).unwrap();
    }
}
