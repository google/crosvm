// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Multi-thread worker.

#![deny(missing_docs)]

use std::collections::VecDeque;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use anyhow::Context;
use base::error;
use base::Event;
use base::EventWaitResult;
use sync::Condvar;
use sync::Mutex;

/// Task to run on the worker threads.
pub trait Task {
    /// Executes the task.
    fn execute(self);
}

/// Multi thread based worker executing a single type [Task].
///
/// See the doc of [Channel] as well for the behaviors of it.
pub struct Worker<T> {
    /// Shared [Channel] with the worker threads.
    pub channel: Arc<Channel<T>>,
    handles: Vec<thread::JoinHandle<()>>,
}

impl<T: Task + Send + 'static> Worker<T> {
    /// Spawns the numbers of worker threads.
    pub fn new(len_channel: usize, n_workers: usize) -> Self {
        let channel = Arc::new(Channel::<T>::new(len_channel, n_workers));
        let mut handles = Vec::with_capacity(n_workers);
        for _ in 0..n_workers {
            let context = channel.clone();
            let handle = thread::spawn(move || {
                Self::worker_thread(context);
            });
            handles.push(handle);
        }
        Self { channel, handles }
    }

    fn worker_thread(context: Arc<Channel<T>>) {
        while let Some(task) = context.pop() {
            task.execute();
        }
    }

    /// Closes the channel and wait for worker threads shutdown.
    ///
    /// This also waits for all the tasks in the channel to be executed.
    pub fn close(self) {
        self.channel.close();
        for handle in self.handles {
            match handle.join() {
                Ok(()) => {}
                Err(e) => {
                    error!("failed to wait for worker thread: {:?}", e);
                }
            }
        }
    }
}

/// MPMC (Multi Producers Multi Consumers) queue integrated with [Worker].
///
/// [Channel] offers [Channel::wait_complete()] to guarantee all the tasks are executed.
///
/// This only exposes methods for producers.
pub struct Channel<T> {
    state: Mutex<ChannelState<T>>,
    consumer_wait: Condvar,
    producer_wait: Condvar,
    n_consumers: usize,
}

impl<T> Channel<T> {
    fn new(len: usize, n_consumers: usize) -> Self {
        Self {
            state: Mutex::new(ChannelState::new(len)),
            consumer_wait: Condvar::new(),
            producer_wait: Condvar::new(),
            n_consumers,
        }
    }

    fn close(&self) {
        let mut state = self.state.lock();
        state.is_closed = true;
        self.consumer_wait.notify_all();
        self.producer_wait.notify_all();
    }

    /// Pops a task from the channel.
    ///
    /// If the queue is closed and also **empty**, this returns [None]. This returns all the tasks
    /// in the queue even while this is closed.
    #[inline]
    fn pop(&self) -> Option<T> {
        let mut state = self.state.lock();
        loop {
            let was_full = state.queue.len() == state.capacity;
            if let Some(item) = state.queue.pop_front() {
                if was_full {
                    // notification for a producer waiting for `push()`.
                    self.producer_wait.notify_one();
                }
                return Some(item);
            } else {
                if state.is_closed {
                    return None;
                }
                state.n_waiting += 1;
                if state.n_waiting == self.n_consumers {
                    // notification for producers waiting for `wait_complete()`.
                    self.producer_wait.notify_all();
                }
                state = self.consumer_wait.wait(state);
                state.n_waiting -= 1;
            }
        }
    }

    /// Push a task.
    ///
    /// This blocks if the channel is full.
    ///
    /// If the channel is closed, this returns `false`.
    pub fn push(&self, item: T) -> bool {
        let mut state = self.state.lock();
        // Wait until the queue has room to push a task.
        while state.queue.len() == state.capacity {
            if state.is_closed {
                return false;
            }
            state = self.producer_wait.wait(state);
        }
        if state.is_closed {
            return false;
        }
        state.queue.push_back(item);
        self.consumer_wait.notify_one();
        true
    }

    /// Wait until all the tasks have been executed.
    ///
    /// This guarantees that all the tasks in this channel are not only consumed but also executed.
    pub fn wait_complete(&self) {
        let mut state = self.state.lock();
        while !(state.queue.is_empty() && state.n_waiting == self.n_consumers) {
            state = self.producer_wait.wait(state);
        }
    }
}

struct ChannelState<T> {
    queue: VecDeque<T>,
    capacity: usize,
    n_waiting: usize,
    is_closed: bool,
}

impl<T> ChannelState<T> {
    fn new(capacity: usize) -> Self {
        Self {
            queue: VecDeque::with_capacity(capacity),
            capacity,
            n_waiting: 0,
            is_closed: false,
        }
    }
}

/// The event channel for background jobs.
///
/// This sends an abort request from the main thread to the job thread via atomic boolean flag.
///
/// This notifies the main thread that the job thread is completed via [Event].
pub struct BackgroundJobControl {
    event: Event,
    abort_flag: AtomicBool,
}

impl BackgroundJobControl {
    /// Creates [BackgroundJobControl].
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            event: Event::new()?,
            abort_flag: AtomicBool::new(false),
        })
    }

    /// Creates [BackgroundJob].
    pub fn new_job(&self) -> BackgroundJob<'_> {
        BackgroundJob {
            event: &self.event,
            abort_flag: &self.abort_flag,
        }
    }

    /// Abort the background job.
    pub fn abort(&self) {
        self.abort_flag.store(true, Ordering::Release);
    }

    /// Reset the internal state for a next job.
    ///
    /// Returns false, if the event is already reset and no event exists.
    pub fn reset(&self) -> anyhow::Result<bool> {
        self.abort_flag.store(false, Ordering::Release);
        Ok(matches!(
            self.event
                .wait_timeout(Duration::ZERO)
                .context("failed to get job complete event")?,
            EventWaitResult::Signaled
        ))
    }

    /// Returns the event to notify the completion of background job.
    pub fn get_completion_event(&self) -> &Event {
        &self.event
    }
}

/// Background job context.
///
/// When dropped, this sends an event to the main thread via [Event].
pub struct BackgroundJob<'a> {
    event: &'a Event,
    abort_flag: &'a AtomicBool,
}

impl BackgroundJob<'_> {
    /// Returns whether the background job is aborted or not.
    pub fn is_aborted(&self) -> bool {
        self.abort_flag.load(Ordering::Acquire)
    }
}

impl Drop for BackgroundJob<'_> {
    fn drop(&mut self) {
        self.event.signal().expect("send job complete event");
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[derive(Clone, Copy)]
    struct Context {
        n_consume: usize,
        n_executed: usize,
    }

    struct FakeTask {
        context: Mutex<Context>,
        waker: Condvar,
    }

    impl FakeTask {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                context: Mutex::new(Context {
                    n_consume: 0,
                    n_executed: 0,
                }),
                waker: Condvar::new(),
            })
        }

        fn consume(&self, count: usize) {
            let mut context = self.context.lock();
            context.n_consume += count;
            self.waker.notify_all();
        }

        fn n_executed(&self) -> usize {
            self.context.lock().n_executed
        }
    }

    impl Task for Arc<FakeTask> {
        fn execute(self) {
            let mut context = self.context.lock();
            while context.n_consume == 0 {
                context = self.waker.wait(context);
            }
            context.n_consume -= 1;
            context.n_executed += 1;
        }
    }

    fn wait_thread_with_timeout<T>(join_handle: thread::JoinHandle<T>, timeout_millis: u64) -> T {
        for _ in 0..timeout_millis {
            if join_handle.is_finished() {
                return join_handle.join().unwrap();
            }
            thread::sleep(Duration::from_millis(1));
        }
        panic!("thread join timeout");
    }

    fn poll_until_with_timeout<F>(f: F, timeout_millis: u64)
    where
        F: Fn() -> bool,
    {
        for _ in 0..timeout_millis {
            if f() {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn test_worker() {
        let worker = Worker::new(2, 4);
        let task = FakeTask::new();
        let channel = worker.channel.clone();

        for _ in 0..4 {
            assert!(channel.push(task.clone()));
        }

        assert_eq!(task.n_executed(), 0);
        task.consume(4);
        worker.channel.wait_complete();
        assert_eq!(task.n_executed(), 4);
        worker.close();
    }

    #[test]
    fn test_worker_push_after_close() {
        let worker = Worker::new(2, 4);
        let task = FakeTask::new();
        let channel = worker.channel.clone();

        worker.close();

        assert!(!channel.push(task));
    }

    #[test]
    fn test_worker_push_block() {
        let worker = Worker::new(2, 4);
        let task = FakeTask::new();
        let channel = worker.channel.clone();

        let task_cloned = task.clone();
        // push tasks on another thread to avoid blocking forever
        wait_thread_with_timeout(
            thread::spawn(move || {
                for _ in 0..6 {
                    assert!(channel.push(task_cloned.clone()));
                }
            }),
            100,
        );
        let channel = worker.channel.clone();
        let task_cloned = task.clone();
        let push_thread = thread::spawn(move || {
            assert!(channel.push(task_cloned));
        });
        thread::sleep(Duration::from_millis(10));
        assert!(!push_thread.is_finished());

        task.consume(1);
        wait_thread_with_timeout(push_thread, 100);

        task.consume(6);
        let task_clone = task.clone();
        poll_until_with_timeout(|| task_clone.n_executed() == 7, 100);
        assert_eq!(task.n_executed(), 7);
        worker.close();
    }

    #[test]
    fn test_worker_close_on_push_blocked() {
        let worker = Worker::new(2, 4);
        let task = FakeTask::new();
        let channel = worker.channel.clone();

        let task_cloned = task.clone();
        // push tasks on another thread to avoid blocking forever
        wait_thread_with_timeout(
            thread::spawn(move || {
                for _ in 0..6 {
                    assert!(channel.push(task_cloned.clone()));
                }
            }),
            100,
        );
        let channel = worker.channel.clone();
        let task_cloned = task.clone();
        let push_thread = thread::spawn(move || channel.push(task_cloned));
        // sleep to run push_thread.
        thread::sleep(Duration::from_millis(10));
        // close blocks until all the task are executed.
        let close_thread = thread::spawn(move || {
            worker.close();
        });
        let push_result = wait_thread_with_timeout(push_thread, 100);
        // push fails.
        assert!(!push_result);

        // cleanup
        task.consume(6);
        wait_thread_with_timeout(close_thread, 100);
    }

    #[test]
    fn new_background_job_event() {
        assert!(BackgroundJobControl::new().is_ok());
    }

    #[test]
    fn background_job_is_not_aborted_default() {
        let event = BackgroundJobControl::new().unwrap();

        let job = event.new_job();

        assert!(!job.is_aborted());
    }

    #[test]
    fn abort_background_job() {
        let event = BackgroundJobControl::new().unwrap();

        let job = event.new_job();
        event.abort();

        assert!(job.is_aborted());
    }

    #[test]
    fn reset_background_job() {
        let event = BackgroundJobControl::new().unwrap();

        event.abort();
        event.reset().unwrap();
        let job = event.new_job();

        assert!(!job.is_aborted());
    }

    #[test]
    fn reset_background_job_event() {
        let event = BackgroundJobControl::new().unwrap();

        let job = event.new_job();
        drop(job);

        assert!(event.reset().unwrap());
    }

    #[test]
    fn reset_background_job_event_twice() {
        let event = BackgroundJobControl::new().unwrap();

        let job = event.new_job();
        drop(job);

        event.reset().unwrap();
        assert!(!event.reset().unwrap());
    }

    #[test]
    fn reset_background_job_event_no_jobs() {
        let event = BackgroundJobControl::new().unwrap();

        assert!(!event.reset().unwrap());
    }
}
