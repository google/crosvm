// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

#[cfg(any(target_os = "android", target_os = "linux"))]
use base::warn;
#[cfg(any(target_os = "android", target_os = "linux"))]
use base::AsRawDescriptors;
#[cfg(any(target_os = "android", target_os = "linux"))]
use base::RawDescriptor;
use once_cell::sync::OnceCell;
use serde::Deserialize;
use serde_keyvalue::argh::FromArgValue;
use serde_keyvalue::ErrorKind;
use serde_keyvalue::KeyValueDeserializer;

use crate::common_executor;
use crate::common_executor::RawExecutor;
#[cfg(any(target_os = "android", target_os = "linux"))]
use crate::sys::linux;
#[cfg(windows)]
use crate::sys::windows;
use crate::sys::ExecutorKindSys;
use crate::AsyncResult;
use crate::IntoAsync;
use crate::IoSource;

cfg_if::cfg_if! {
    if #[cfg(feature = "tokio")] {
        use crate::tokio_executor::TokioExecutor;
        use crate::tokio_executor::TokioTaskHandle;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutorKind {
    SysVariants(ExecutorKindSys),
    #[cfg(feature = "tokio")]
    Tokio,
}

impl From<ExecutorKindSys> for ExecutorKind {
    fn from(e: ExecutorKindSys) -> ExecutorKind {
        ExecutorKind::SysVariants(e)
    }
}

/// If set, [`ExecutorKind::default()`] returns the value of `DEFAULT_EXECUTOR_KIND`.
/// If not set, [`ExecutorKind::default()`] returns a statically-chosen default value, and
/// [`ExecutorKind::default()`] initializes `DEFAULT_EXECUTOR_KIND` with that value.
static DEFAULT_EXECUTOR_KIND: OnceCell<ExecutorKind> = OnceCell::new();

impl Default for ExecutorKind {
    fn default() -> Self {
        #[cfg(any(target_os = "android", target_os = "linux"))]
        let default_fn = || ExecutorKindSys::Fd.into();
        #[cfg(windows)]
        let default_fn = || ExecutorKindSys::Handle.into();
        *DEFAULT_EXECUTOR_KIND.get_or_init(default_fn)
    }
}

/// The error type for [`Executor::set_default_executor_kind()`].
#[derive(thiserror::Error, Debug)]
pub enum SetDefaultExecutorKindError {
    /// The default executor kind is set more than once.
    #[error("The default executor kind is already set to {0:?}")]
    SetMoreThanOnce(ExecutorKind),

    #[cfg(any(target_os = "android", target_os = "linux"))]
    /// io_uring is unavailable. The reason might be the lack of the kernel support,
    /// but is not limited to that.
    #[error("io_uring is unavailable: {0}")]
    UringUnavailable(linux::uring_executor::Error),
}

impl FromArgValue for ExecutorKind {
    fn from_arg_value(value: &str) -> std::result::Result<ExecutorKind, String> {
        // `from_arg_value` returns a `String` as error, but our deserializer API defines its own
        // error type. Perform parsing from a closure so we can easily map returned errors.
        let builder = move || {
            let mut des = KeyValueDeserializer::from(value);

            let kind: ExecutorKind = match (des.parse_identifier()?, des.next_char()) {
                #[cfg(any(target_os = "android", target_os = "linux"))]
                ("epoll", None) => ExecutorKindSys::Fd.into(),
                #[cfg(any(target_os = "android", target_os = "linux"))]
                ("uring", None) => ExecutorKindSys::Uring.into(),
                #[cfg(windows)]
                ("handle", None) => ExecutorKindSys::Handle.into(),
                #[cfg(windows)]
                ("overlapped", None) => ExecutorKindSys::Overlapped { concurrency: None }.into(),
                #[cfg(windows)]
                ("overlapped", Some(',')) => {
                    if des.parse_identifier()? != "concurrency" {
                        let kind = ErrorKind::SerdeError("expected `concurrency`".to_string());
                        return Err(des.error_here(kind));
                    }
                    if des.next_char() != Some('=') {
                        return Err(des.error_here(ErrorKind::ExpectedEqual));
                    }
                    let concurrency = des.parse_number()?;
                    ExecutorKindSys::Overlapped {
                        concurrency: Some(concurrency),
                    }
                    .into()
                }
                #[cfg(feature = "tokio")]
                ("tokio", None) => ExecutorKind::Tokio,
                (_identifier, _next) => {
                    let kind = ErrorKind::SerdeError("unexpected kind".to_string());
                    return Err(des.error_here(kind));
                }
            };
            des.finish()?;
            Ok(kind)
        };

        builder().map_err(|e| e.to_string())
    }
}

impl serde::Serialize for ExecutorKind {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            ExecutorKind::SysVariants(sv) => sv.serialize(serializer),
            #[cfg(feature = "tokio")]
            ExecutorKind::Tokio => "tokio".serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for ExecutorKind {
    fn deserialize<D>(deserializer: D) -> Result<ExecutorKind, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        base::error!("ExecutorKind::deserialize");
        let string = String::deserialize(deserializer)?;
        ExecutorKind::from_arg_value(&string).map_err(serde::de::Error::custom)
    }
}

/// Reference to a task managed by the executor.
///
/// Dropping a `TaskHandle` attempts to cancel the associated task. Call `detach` to allow it to
/// continue running the background.
///
/// `await`ing the `TaskHandle` waits for the task to finish and yields its result.
pub enum TaskHandle<R> {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    Fd(common_executor::RawTaskHandle<linux::EpollReactor, R>),
    #[cfg(any(target_os = "android", target_os = "linux"))]
    Uring(common_executor::RawTaskHandle<linux::UringReactor, R>),
    #[cfg(windows)]
    Handle(common_executor::RawTaskHandle<windows::HandleReactor, R>),
    #[cfg(feature = "tokio")]
    Tokio(TokioTaskHandle<R>),
}

impl<R: Send + 'static> TaskHandle<R> {
    pub fn detach(self) {
        match self {
            #[cfg(any(target_os = "android", target_os = "linux"))]
            TaskHandle::Fd(f) => f.detach(),
            #[cfg(any(target_os = "android", target_os = "linux"))]
            TaskHandle::Uring(u) => u.detach(),
            #[cfg(windows)]
            TaskHandle::Handle(h) => h.detach(),
            #[cfg(feature = "tokio")]
            TaskHandle::Tokio(t) => t.detach(),
        }
    }

    // Cancel the task and wait for it to stop. Returns the result of the task if it was already
    // finished.
    pub async fn cancel(self) -> Option<R> {
        match self {
            #[cfg(any(target_os = "android", target_os = "linux"))]
            TaskHandle::Fd(f) => f.cancel().await,
            #[cfg(any(target_os = "android", target_os = "linux"))]
            TaskHandle::Uring(u) => u.cancel().await,
            #[cfg(windows)]
            TaskHandle::Handle(h) => h.cancel().await,
            #[cfg(feature = "tokio")]
            TaskHandle::Tokio(t) => t.cancel().await,
        }
    }
}

impl<R: 'static> Future for TaskHandle<R> {
    type Output = R;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context) -> std::task::Poll<Self::Output> {
        match self.get_mut() {
            #[cfg(any(target_os = "android", target_os = "linux"))]
            TaskHandle::Fd(f) => Pin::new(f).poll(cx),
            #[cfg(any(target_os = "android", target_os = "linux"))]
            TaskHandle::Uring(u) => Pin::new(u).poll(cx),
            #[cfg(windows)]
            TaskHandle::Handle(h) => Pin::new(h).poll(cx),
            #[cfg(feature = "tokio")]
            TaskHandle::Tokio(t) => Pin::new(t).poll(cx),
        }
    }
}

pub(crate) trait ExecutorTrait {
    fn async_from<'a, F: IntoAsync + 'a>(&self, f: F) -> AsyncResult<IoSource<F>>;

    fn spawn<F>(&self, f: F) -> TaskHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static;

    fn spawn_blocking<F, R>(&self, f: F) -> TaskHandle<R>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static;

    fn spawn_local<F>(&self, f: F) -> TaskHandle<F::Output>
    where
        F: Future + 'static,
        F::Output: 'static;

    fn run_until<F: Future>(&self, f: F) -> AsyncResult<F::Output>;
}

/// An executor for scheduling tasks that poll futures to completion.
///
/// All asynchronous operations must run within an executor, which is capable of spawning futures as
/// tasks. This executor also provides a mechanism for performing asynchronous I/O operations.
///
/// The returned type is a cheap, clonable handle to the underlying executor. Cloning it will only
/// create a new reference, not a new executor.
///
/// Note that language limitations (trait objects can have <=1 non auto trait) require this to be
/// represented on the POSIX side as an enum, rather than a trait. This leads to some code &
/// interface duplication, but as far as we understand that is unavoidable.
///
/// See <https://chromium-review.googlesource.com/c/chromiumos/platform/crosvm/+/2571401/2..6/cros_async/src/executor.rs#b75>
/// for further details.
///
/// # Examples
///
/// Concurrently wait for multiple files to become readable/writable and then read/write the data.
///
/// ```
/// use std::cmp::min;
/// use std::error::Error;
/// use std::fs::{File, OpenOptions};
///
/// use cros_async::{AsyncResult, Executor, IoSource, complete3};
/// const CHUNK_SIZE: usize = 32;
///
/// // Write all bytes from `data` to `f`.
/// async fn write_file(f: &IoSource<File>, mut data: Vec<u8>) -> AsyncResult<()> {
///     while data.len() > 0 {
///         let (count, mut buf) = f.write_from_vec(None, data).await?;
///
///         data = buf.split_off(count);
///     }
///
///     Ok(())
/// }
///
/// // Transfer `len` bytes of data from `from` to `to`.
/// async fn transfer_data(
///     from: IoSource<File>,
///     to: IoSource<File>,
///     len: usize,
/// ) -> AsyncResult<usize> {
///     let mut rem = len;
///
///     while rem > 0 {
///         let buf = vec![0u8; min(rem, CHUNK_SIZE)];
///         let (count, mut data) = from.read_to_vec(None, buf).await?;
///
///         if count == 0 {
///             // End of file. Return the number of bytes transferred.
///             return Ok(len - rem);
///         }
///
///         data.truncate(count);
///         write_file(&to, data).await?;
///
///         rem = rem.saturating_sub(count);
///     }
///
///     Ok(len)
/// }
///
/// #[cfg(any(target_os = "android", target_os = "linux"))]
/// # fn do_it() -> Result<(), Box<dyn Error>> {
///     let ex = Executor::new()?;
///
///     let (rx, tx) = base::linux::pipe()?;
///     let zero = File::open("/dev/zero")?;
///     let zero_bytes = CHUNK_SIZE * 7;
///     let zero_to_pipe = transfer_data(
///         ex.async_from(zero)?,
///         ex.async_from(tx.try_clone()?)?,
///         zero_bytes,
///     );
///
///     let rand = File::open("/dev/urandom")?;
///     let rand_bytes = CHUNK_SIZE * 19;
///     let rand_to_pipe = transfer_data(ex.async_from(rand)?, ex.async_from(tx)?, rand_bytes);
///
///     let null = OpenOptions::new().write(true).open("/dev/null")?;
///     let null_bytes = zero_bytes + rand_bytes;
///     let pipe_to_null = transfer_data(ex.async_from(rx)?, ex.async_from(null)?, null_bytes);
///
///     ex.run_until(complete3(
///         async { assert_eq!(pipe_to_null.await.unwrap(), null_bytes) },
///         async { assert_eq!(zero_to_pipe.await.unwrap(), zero_bytes) },
///         async { assert_eq!(rand_to_pipe.await.unwrap(), rand_bytes) },
///     ))?;
///
/// #     Ok(())
/// # }
/// #[cfg(any(target_os = "android", target_os = "linux"))]
/// # do_it().unwrap();
/// ```
#[derive(Clone)]
pub enum Executor {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    Fd(Arc<RawExecutor<linux::EpollReactor>>),
    #[cfg(any(target_os = "android", target_os = "linux"))]
    Uring(Arc<RawExecutor<linux::UringReactor>>),
    #[cfg(windows)]
    Handle(Arc<RawExecutor<windows::HandleReactor>>),
    #[cfg(windows)]
    Overlapped(Arc<RawExecutor<windows::HandleReactor>>),
    #[cfg(feature = "tokio")]
    Tokio(TokioExecutor),
}

impl Executor {
    /// Create a new `Executor`.
    pub fn new() -> AsyncResult<Self> {
        Executor::with_executor_kind(ExecutorKind::default())
    }

    /// Create a new `Executor` of the given `ExecutorKind`.
    pub fn with_executor_kind(kind: ExecutorKind) -> AsyncResult<Self> {
        Ok(match kind {
            #[cfg(any(target_os = "android", target_os = "linux"))]
            ExecutorKind::SysVariants(ExecutorKindSys::Fd) => Executor::Fd(RawExecutor::new()?),
            #[cfg(any(target_os = "android", target_os = "linux"))]
            ExecutorKind::SysVariants(ExecutorKindSys::Uring) => {
                Executor::Uring(RawExecutor::new()?)
            }
            #[cfg(windows)]
            ExecutorKind::SysVariants(ExecutorKindSys::Handle) => {
                Executor::Handle(RawExecutor::new()?)
            }
            #[cfg(windows)]
            ExecutorKind::SysVariants(ExecutorKindSys::Overlapped { concurrency }) => {
                let reactor = match concurrency {
                    Some(concurrency) => windows::HandleReactor::new_with(concurrency)?,
                    None => windows::HandleReactor::new()?,
                };
                Executor::Overlapped(RawExecutor::new_with(reactor)?)
            }
            #[cfg(feature = "tokio")]
            ExecutorKind::Tokio => Executor::Tokio(TokioExecutor::new()?),
        })
    }

    /// Set the default ExecutorKind for [`Self::new()`]. This call is effective only once.
    pub fn set_default_executor_kind(
        executor_kind: ExecutorKind,
    ) -> Result<(), SetDefaultExecutorKindError> {
        #[cfg(any(target_os = "android", target_os = "linux"))]
        if executor_kind == ExecutorKind::SysVariants(ExecutorKindSys::Uring) {
            linux::uring_executor::check_uring_availability()
                .map_err(SetDefaultExecutorKindError::UringUnavailable)?;
            if !crate::is_uring_stable() {
                warn!(
                    "Enabling io_uring executor on the kernel version where io_uring is unstable"
                );
            }
        }
        DEFAULT_EXECUTOR_KIND.set(executor_kind).map_err(|_|
            // `expect` succeeds since this closure runs only when DEFAULT_EXECUTOR_KIND is set.
            SetDefaultExecutorKindError::SetMoreThanOnce(
                *DEFAULT_EXECUTOR_KIND
                    .get()
                    .expect("Failed to get DEFAULT_EXECUTOR_KIND"),
            ))
    }

    /// Create a new `IoSource<F>` associated with `self`. Callers may then use the returned
    /// `IoSource` to directly start async operations without needing a separate reference to the
    /// executor.
    pub fn async_from<'a, F: IntoAsync + 'a>(&self, f: F) -> AsyncResult<IoSource<F>> {
        match self {
            #[cfg(any(target_os = "android", target_os = "linux"))]
            Executor::Fd(ex) => ex.async_from(f),
            #[cfg(any(target_os = "android", target_os = "linux"))]
            Executor::Uring(ex) => ex.async_from(f),
            #[cfg(windows)]
            Executor::Handle(ex) => ex.async_from(f),
            #[cfg(windows)]
            Executor::Overlapped(ex) => ex.async_from(f),
            #[cfg(feature = "tokio")]
            Executor::Tokio(ex) => ex.async_from(f),
        }
    }

    /// Create a new overlapped `IoSource<F>` associated with `self`. Callers may then use the
    /// If the executor is not overlapped, then Handle source is returned.
    /// returned `IoSource` to directly start async operations without needing a separate reference
    /// to the executor.
    #[cfg(windows)]
    pub fn async_overlapped_from<'a, F: IntoAsync + 'a>(&self, f: F) -> AsyncResult<IoSource<F>> {
        match self {
            Executor::Overlapped(ex) => Ok(IoSource::Overlapped(windows::OverlappedSource::new(
                f, ex, false,
            )?)),
            _ => self.async_from(f),
        }
    }

    /// Spawn a new future for this executor to run to completion. Callers may use the returned
    /// `TaskHandle` to await on the result of `f`. Dropping the returned `TaskHandle` will cancel
    /// `f`, preventing it from being polled again. To drop a `TaskHandle` without canceling the
    /// future associated with it use `TaskHandle::detach`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use cros_async::AsyncResult;
    /// # fn example_spawn() -> AsyncResult<()> {
    /// #      use std::thread;
    ///
    /// #      use cros_async::Executor;
    ///        use futures::executor::block_on;
    ///
    /// #      let ex = Executor::new()?;
    ///
    /// #      // Spawn a thread that runs the executor.
    /// #      let ex2 = ex.clone();
    /// #      thread::spawn(move || ex2.run());
    ///
    ///       let task = ex.spawn(async { 7 + 13 });
    ///
    ///       let result = block_on(task);
    ///       assert_eq!(result, 20);
    /// #     Ok(())
    /// # }
    ///
    /// # example_spawn().unwrap();
    /// ```
    pub fn spawn<F>(&self, f: F) -> TaskHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        match self {
            #[cfg(any(target_os = "android", target_os = "linux"))]
            Executor::Fd(ex) => ex.spawn(f),
            #[cfg(any(target_os = "android", target_os = "linux"))]
            Executor::Uring(ex) => ex.spawn(f),
            #[cfg(windows)]
            Executor::Handle(ex) => ex.spawn(f),
            #[cfg(windows)]
            Executor::Overlapped(ex) => ex.spawn(f),
            #[cfg(feature = "tokio")]
            Executor::Tokio(ex) => ex.spawn(f),
        }
    }

    /// Spawn a thread-local task for this executor to drive to completion. Like `spawn` but without
    /// requiring `Send` on `F` or `F::Output`. This method should only be called from the same
    /// thread where `run()` or `run_until()` is called.
    ///
    /// # Panics
    ///
    /// `Executor::run` and `Executor::run_util` will panic if they try to poll a future that was
    /// added by calling `spawn_local` from a different thread.
    ///
    /// # Examples
    ///
    /// ```
    /// # use cros_async::AsyncResult;
    /// # fn example_spawn_local() -> AsyncResult<()> {
    /// #      use cros_async::Executor;
    ///
    /// #      let ex = Executor::new()?;
    ///
    ///        let task = ex.spawn_local(async { 7 + 13 });
    ///
    ///        let result = ex.run_until(task)?;
    ///        assert_eq!(result, 20);
    ///        Ok(())
    /// # }
    ///
    /// # example_spawn_local().unwrap();
    /// ```
    pub fn spawn_local<F>(&self, f: F) -> TaskHandle<F::Output>
    where
        F: Future + 'static,
        F::Output: 'static,
    {
        match self {
            #[cfg(any(target_os = "android", target_os = "linux"))]
            Executor::Fd(ex) => ex.spawn_local(f),
            #[cfg(any(target_os = "android", target_os = "linux"))]
            Executor::Uring(ex) => ex.spawn_local(f),
            #[cfg(windows)]
            Executor::Handle(ex) => ex.spawn_local(f),
            #[cfg(windows)]
            Executor::Overlapped(ex) => ex.spawn_local(f),
            #[cfg(feature = "tokio")]
            Executor::Tokio(ex) => ex.spawn_local(f),
        }
    }

    /// Run the provided closure on a dedicated thread where blocking is allowed.
    ///
    /// Callers may `await` on the returned `TaskHandle` to wait for the result of `f`. Dropping
    /// the returned `TaskHandle` may not cancel the operation if it was already started on a
    /// worker thread.
    ///
    /// # Panics
    ///
    /// `await`ing the `TaskHandle` after the `Executor` is dropped will panic if the work was not
    /// already completed.
    ///
    /// # Examples
    ///
    /// ```edition2018
    /// # use cros_async::Executor;
    ///
    /// # async fn do_it(ex: &Executor) {
    ///     let res = ex.spawn_blocking(move || {
    ///         // Do some CPU-intensive or blocking work here.
    ///
    ///         42
    ///     }).await;
    ///
    ///     assert_eq!(res, 42);
    /// # }
    ///
    /// # let ex = Executor::new().unwrap();
    /// # ex.run_until(do_it(&ex)).unwrap();
    /// ```
    pub fn spawn_blocking<F, R>(&self, f: F) -> TaskHandle<R>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        match self {
            #[cfg(any(target_os = "android", target_os = "linux"))]
            Executor::Fd(ex) => ex.spawn_blocking(f),
            #[cfg(any(target_os = "android", target_os = "linux"))]
            Executor::Uring(ex) => ex.spawn_blocking(f),
            #[cfg(windows)]
            Executor::Handle(ex) => ex.spawn_blocking(f),
            #[cfg(windows)]
            Executor::Overlapped(ex) => ex.spawn_blocking(f),
            #[cfg(feature = "tokio")]
            Executor::Tokio(ex) => ex.spawn_blocking(f),
        }
    }

    /// Run the executor indefinitely, driving all spawned futures to completion. This method will
    /// block the current thread and only return in the case of an error.
    ///
    /// # Panics
    ///
    /// Once this method has been called on a thread, it may only be called on that thread from that
    /// point on. Attempting to call it from another thread will panic.
    ///
    /// # Examples
    ///
    /// ```
    /// # use cros_async::AsyncResult;
    /// # fn example_run() -> AsyncResult<()> {
    ///       use std::thread;
    ///
    ///       use cros_async::Executor;
    ///       use futures::executor::block_on;
    ///
    ///       let ex = Executor::new()?;
    ///
    ///       // Spawn a thread that runs the executor.
    ///       let ex2 = ex.clone();
    ///       thread::spawn(move || ex2.run());
    ///
    ///       let task = ex.spawn(async { 7 + 13 });
    ///
    ///       let result = block_on(task);
    ///       assert_eq!(result, 20);
    /// #     Ok(())
    /// # }
    ///
    /// # example_run().unwrap();
    /// ```
    pub fn run(&self) -> AsyncResult<()> {
        self.run_until(std::future::pending())
    }

    /// Drive all futures spawned in this executor until `f` completes. This method will block the
    /// current thread only until `f` is complete and there may still be unfinished futures in the
    /// executor.
    ///
    /// # Panics
    ///
    /// Once this method has been called on a thread, from then onwards it may only be called on
    /// that thread. Attempting to call it from another thread will panic.
    ///
    /// # Examples
    ///
    /// ```
    /// # use cros_async::AsyncResult;
    /// # fn example_run_until() -> AsyncResult<()> {
    ///       use cros_async::Executor;
    ///
    ///       let ex = Executor::new()?;
    ///
    ///       let task = ex.spawn_local(async { 7 + 13 });
    ///
    ///       let result = ex.run_until(task)?;
    ///       assert_eq!(result, 20);
    /// #     Ok(())
    /// # }
    ///
    /// # example_run_until().unwrap();
    /// ```
    pub fn run_until<F: Future>(&self, f: F) -> AsyncResult<F::Output> {
        match self {
            #[cfg(any(target_os = "android", target_os = "linux"))]
            Executor::Fd(ex) => ex.run_until(f),
            #[cfg(any(target_os = "android", target_os = "linux"))]
            Executor::Uring(ex) => ex.run_until(f),
            #[cfg(windows)]
            Executor::Handle(ex) => ex.run_until(f),
            #[cfg(windows)]
            Executor::Overlapped(ex) => ex.run_until(f),
            #[cfg(feature = "tokio")]
            Executor::Tokio(ex) => ex.run_until(f),
        }
    }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
impl AsRawDescriptors for Executor {
    fn as_raw_descriptors(&self) -> Vec<RawDescriptor> {
        match self {
            Executor::Fd(ex) => ex.as_raw_descriptors(),
            Executor::Uring(ex) => ex.as_raw_descriptors(),
            #[cfg(feature = "tokio")]
            Executor::Tokio(ex) => ex.as_raw_descriptors(),
        }
    }
}
