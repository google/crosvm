// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::future::Future;
use std::pin::Pin;

use crate::common_executor;
#[cfg(any(target_os = "android", target_os = "linux"))]
use crate::sys::linux;
#[cfg(windows)]
use crate::sys::windows;
use crate::sys::ExecutorKindSys;

#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    serde_keyvalue::FromKeyValues,
)]
#[serde(deny_unknown_fields, rename_all = "kebab-case", untagged)]
pub enum ExecutorKind {
    SysVariants(ExecutorKindSys),
}

impl Default for ExecutorKind {
    fn default() -> ExecutorKind {
        ExecutorKind::SysVariants(ExecutorKindSys::default())
    }
}

impl From<ExecutorKindSys> for ExecutorKind {
    fn from(e: ExecutorKindSys) -> ExecutorKind {
        ExecutorKind::SysVariants(e)
    }
}

// TODO: schuffelen - Remove after adding a platform-independent Executor
impl From<ExecutorKind> for ExecutorKindSys {
    fn from(e: ExecutorKind) -> ExecutorKindSys {
        match e {
            ExecutorKind::SysVariants(inner) => inner,
        }
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
    Fd(common_executor::TaskHandle<linux::EpollReactor, R>),
    #[cfg(any(target_os = "android", target_os = "linux"))]
    Uring(common_executor::TaskHandle<linux::UringReactor, R>),
    #[cfg(windows)]
    Handle(common_executor::TaskHandle<windows::HandleReactor, R>),
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
        }
    }
}
