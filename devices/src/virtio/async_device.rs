// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Provides helpers that make it easier to process virtio queues on an async executor.

#![cfg_attr(windows, allow(dead_code))]

use anyhow::bail;
use anyhow::Context;
use base::warn;
use cros_async::AsyncResult;
use cros_async::Executor;
use cros_async::TaskHandle;
use futures::future::AbortHandle;
use futures::future::Abortable;
use futures::future::Pending;
use futures::Future;

/// A queue for which processing can be started on an async executor.
///
/// `T` is the resource type of the queue, i.e. the device-specific data it needs in order to run.
/// For instance, a block device will likely need a file to provide its data.
pub enum AsyncQueueState<T: 'static> {
    /// Queue is currently stopped.
    Stopped(T),
    /// Queue is being processed as a `Task` on an `Executor`, and can be stopped by aborting the
    /// `AbortHandle`.
    Running((TaskHandle<T>, Executor, AbortHandle)),
    /// Something terrible happened and this queue is in a non-recoverable state.
    Broken,
}

impl<T: 'static> AsyncQueueState<T> {
    /// Start processing of the queue on `ex`, or stop and restart it with the new parameters if
    /// it was already running.
    ///
    /// `fut_provider` is a closure that is passed the resource of the queue, as well as a
    /// `Abortable` future. It must return a `Future` that takes ownership of the device's resource
    /// and processes the queue for as long as possible, but immediately quits and returns the
    /// device resource when the `Abortable` is signaled.
    ///
    /// If `fut_provider` or the `Future` it returns end with an error, the queue is considered
    /// broken and cannot be used anymore.
    ///
    /// The task is only scheduled and no processing actually starts in this method. The task is
    /// scheduled locally, which implies that `ex` must be run on the current thread.
    pub fn start<
        U: Future<Output = T> + 'static,
        F: FnOnce(T, Abortable<Pending<()>>) -> anyhow::Result<U>,
    >(
        &mut self,
        ex: &Executor,
        fut_provider: F,
    ) -> anyhow::Result<()> {
        if matches!(self, AsyncQueueState::Running(_)) {
            warn!("queue is already running, stopping it first");
            self.stop().context("while trying to restart queue")?;
        }

        let resource = match std::mem::replace(self, AsyncQueueState::Broken) {
            AsyncQueueState::Stopped(resource) => resource,
            _ => bail!("queue is in a bad state and cannot be started"),
        };

        let (wait_fut, abort_handle) = futures::future::abortable(futures::future::pending::<()>());
        let queue_future = fut_provider(resource, wait_fut)?;
        let task = ex.spawn_local(queue_future);

        *self = AsyncQueueState::Running((task, ex.clone(), abort_handle));
        Ok(())
    }

    /// Stops a previously started queue.
    ///
    /// The executor on which the task has been started will be run if needed in order to retrieve
    /// the queue's resource.
    ///
    /// Returns `true` if the queue was running, `false` if it wasn't.
    pub fn stop(&mut self) -> AsyncResult<bool> {
        match std::mem::replace(self, AsyncQueueState::Broken) {
            AsyncQueueState::Running((task, ex, handle)) => {
                // Abort the task and run it to completion to retrieve the queue's resource.
                handle.abort();
                let resource = ex.run_until(task)?;
                *self = AsyncQueueState::Stopped(resource);
                Ok(true)
            }
            state => {
                *self = state;
                Ok(false)
            }
        }
    }
}
