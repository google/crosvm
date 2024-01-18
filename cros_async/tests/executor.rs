// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use cros_async::sys::ExecutorKindSys;
use cros_async::Executor;
use cros_async::ExecutorKind;

#[cfg(any(target_os = "android", target_os = "linux"))]
fn all_kinds() -> Vec<ExecutorKind> {
    let mut kinds = vec![ExecutorKindSys::Fd.into()];
    if cros_async::is_uring_stable() {
        kinds.push(ExecutorKindSys::Uring.into());
    }
    kinds
}
#[cfg(windows)]
fn all_kinds() -> Vec<ExecutorKind> {
    vec![ExecutorKindSys::Handle.into()]
}

#[test]
fn cancel_pending_task() {
    for kind in all_kinds() {
        let ex = Executor::with_executor_kind(kind).unwrap();
        let task = ex.spawn(std::future::pending::<()>());
        assert_eq!(ex.run_until(task.cancel()).unwrap(), None);
    }
}

// Testing a completed task without relying on implementation details is tricky. We create a future
// that signals a channel when it is polled so that we can delay the `task.cancel()` call until we
// know the task has been executed.
#[test]
fn cancel_ready_task() {
    for kind in all_kinds() {
        let ex = Executor::with_executor_kind(kind).unwrap();
        let (s, r) = futures::channel::oneshot::channel();
        let mut s = Some(s);
        let task = ex.spawn(futures::future::poll_fn(move |_| {
            s.take().unwrap().send(()).unwrap();
            std::task::Poll::Ready(5)
        }));
        assert_eq!(
            ex.run_until(async {
                r.await.unwrap();
                task.cancel().await
            })
            .unwrap(),
            Some(5)
        );
    }
}
