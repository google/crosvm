// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::OnceLock;

use base::AsRawDescriptors;
use base::RawDescriptor;
use tokio::runtime::Runtime;
use tokio::task::LocalSet;

use crate::sys::platform::tokio_source::TokioSource;
use crate::AsyncError;
use crate::AsyncResult;
use crate::ExecutorTrait;
use crate::IntoAsync;
use crate::IoSource;
use crate::TaskHandle;

mod send_wrapper {
    use std::thread;

    #[derive(Clone)]
    pub(super) struct SendWrapper<T> {
        instance: T,
        thread_id: thread::ThreadId,
    }

    impl<T> SendWrapper<T> {
        pub(super) fn new(instance: T) -> SendWrapper<T> {
            SendWrapper {
                instance,
                thread_id: thread::current().id(),
            }
        }
    }

    // SAFETY: panics when the value is accessed on the wrong thread.
    unsafe impl<T> Send for SendWrapper<T> {}
    // SAFETY: panics when the value is accessed on the wrong thread.
    unsafe impl<T> Sync for SendWrapper<T> {}

    impl<T> Drop for SendWrapper<T> {
        fn drop(&mut self) {
            if self.thread_id != thread::current().id() {
                panic!("SendWrapper value was dropped on the wrong thread");
            }
        }
    }

    impl<T> std::ops::Deref for SendWrapper<T> {
        type Target = T;

        fn deref(&self) -> &T {
            if self.thread_id != thread::current().id() {
                panic!("SendWrapper value was accessed on the wrong thread");
            }
            &self.instance
        }
    }
}

#[derive(Clone)]
pub struct TokioExecutor {
    runtime: Arc<Runtime>,
    local_set: Arc<OnceLock<send_wrapper::SendWrapper<LocalSet>>>,
}

impl TokioExecutor {
    pub fn new() -> AsyncResult<Self> {
        Ok(TokioExecutor {
            runtime: Arc::new(Runtime::new().map_err(AsyncError::Io)?),
            local_set: Arc::new(OnceLock::new()),
        })
    }
}

impl ExecutorTrait for TokioExecutor {
    fn async_from<'a, F: IntoAsync + 'a>(&self, f: F) -> AsyncResult<IoSource<F>> {
        Ok(IoSource::Tokio(TokioSource::new(
            f,
            self.runtime.handle().clone(),
        )?))
    }

    fn run_until<F: Future>(&self, f: F) -> AsyncResult<F::Output> {
        let local_set = self
            .local_set
            .get_or_init(|| send_wrapper::SendWrapper::new(LocalSet::new()));
        Ok(self
            .runtime
            .block_on(async { local_set.run_until(f).await }))
    }

    fn spawn<F>(&self, f: F) -> TaskHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        TaskHandle::Tokio(TokioTaskHandle {
            join_handle: Some(self.runtime.spawn(f)),
        })
    }

    fn spawn_blocking<F, R>(&self, f: F) -> TaskHandle<R>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        TaskHandle::Tokio(TokioTaskHandle {
            join_handle: Some(self.runtime.spawn_blocking(f)),
        })
    }

    fn spawn_local<F>(&self, f: F) -> TaskHandle<F::Output>
    where
        F: Future + 'static,
        F::Output: 'static,
    {
        let local_set = self
            .local_set
            .get_or_init(|| send_wrapper::SendWrapper::new(LocalSet::new()));
        TaskHandle::Tokio(TokioTaskHandle {
            join_handle: Some(local_set.spawn_local(f)),
        })
    }
}

impl AsRawDescriptors for TokioExecutor {
    fn as_raw_descriptors(&self) -> Vec<RawDescriptor> {
        todo!();
    }
}

pub struct TokioTaskHandle<T> {
    join_handle: Option<tokio::task::JoinHandle<T>>,
}
impl<R> TokioTaskHandle<R> {
    pub async fn cancel(mut self) -> Option<R> {
        match self.join_handle.take() {
            Some(handle) => {
                handle.abort();
                handle.await.ok()
            }
            None => None,
        }
    }
    pub fn detach(mut self) {
        self.join_handle.take();
    }
}
impl<R: 'static> Future for TokioTaskHandle<R> {
    type Output = R;
    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context) -> std::task::Poll<Self::Output> {
        let self_mut = self.get_mut();
        Pin::new(self_mut.join_handle.as_mut().unwrap())
            .poll(cx)
            .map(|v| v.unwrap())
    }
}
impl<T> std::ops::Drop for TokioTaskHandle<T> {
    fn drop(&mut self) {
        if let Some(handle) = self.join_handle.take() {
            handle.abort()
        }
    }
}
