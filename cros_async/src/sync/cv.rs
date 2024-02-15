// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::UnsafeCell;
use std::hint;
use std::mem;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use super::super::sync::mu::RawRwLock;
use super::super::sync::mu::RwLockReadGuard;
use super::super::sync::mu::RwLockWriteGuard;
use super::super::sync::waiter::Kind as WaiterKind;
use super::super::sync::waiter::Waiter;
use super::super::sync::waiter::WaiterAdapter;
use super::super::sync::waiter::WaiterList;
use super::super::sync::waiter::WaitingFor;

const SPINLOCK: usize = 1 << 0;
const HAS_WAITERS: usize = 1 << 1;

/// A primitive to wait for an event to occur without consuming CPU time.
///
/// Condition variables are used in combination with a `RwLock` when a thread wants to wait for some
/// condition to become true. The condition must always be verified while holding the `RwLock` lock.
/// It is an error to use a `Condvar` with more than one `RwLock` while there are threads waiting on
/// the `Condvar`.
///
/// # Examples
///
/// ```edition2018
/// use std::sync::Arc;
/// use std::thread;
/// use std::sync::mpsc::channel;
///
/// use cros_async::{
///     block_on,
///     sync::{Condvar, RwLock},
/// };
///
/// const N: usize = 13;
///
/// // Spawn a few threads to increment a shared variable (non-atomically), and
/// // let all threads waiting on the Condvar know once the increments are done.
/// let data = Arc::new(RwLock::new(0));
/// let cv = Arc::new(Condvar::new());
///
/// for _ in 0..N {
///     let (data, cv) = (data.clone(), cv.clone());
///     thread::spawn(move || {
///         let mut data = block_on(data.lock());
///         *data += 1;
///         if *data == N {
///             cv.notify_all();
///         }
///     });
/// }
///
/// let mut val = block_on(data.lock());
/// while *val != N {
///     val = block_on(cv.wait(val));
/// }
/// ```
#[repr(align(128))]
pub struct Condvar {
    state: AtomicUsize,
    waiters: UnsafeCell<WaiterList>,
    mu: UnsafeCell<usize>,
}

impl Condvar {
    /// Creates a new condition variable ready to be waited on and notified.
    pub fn new() -> Condvar {
        Condvar {
            state: AtomicUsize::new(0),
            waiters: UnsafeCell::new(WaiterList::new(WaiterAdapter::new())),
            mu: UnsafeCell::new(0),
        }
    }

    /// Block the current thread until this `Condvar` is notified by another thread.
    ///
    /// This method will atomically unlock the `RwLock` held by `guard` and then block the current
    /// thread. Any call to `notify_one` or `notify_all` after the `RwLock` is unlocked may wake up
    /// the thread.
    ///
    /// To allow for more efficient scheduling, this call may return even when the programmer
    /// doesn't expect the thread to be woken. Therefore, calls to `wait()` should be used inside a
    /// loop that checks the predicate before continuing.
    ///
    /// Callers that are not in an async context may wish to use the `block_on` method to block the
    /// thread until the `Condvar` is notified.
    ///
    /// # Panics
    ///
    /// This method will panic if used with more than one `RwLock` at the same time.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::sync::Arc;
    /// # use std::thread;
    ///
    /// # use cros_async::{
    /// #     block_on,
    /// #     sync::{Condvar, RwLock},
    /// # };
    ///
    /// # let mu = Arc::new(RwLock::new(false));
    /// # let cv = Arc::new(Condvar::new());
    /// # let (mu2, cv2) = (mu.clone(), cv.clone());
    ///
    /// # let t = thread::spawn(move || {
    /// #     *block_on(mu2.lock()) = true;
    /// #     cv2.notify_all();
    /// # });
    ///
    /// let mut ready = block_on(mu.lock());
    /// while !*ready {
    ///     ready = block_on(cv.wait(ready));
    /// }
    ///
    /// # t.join().expect("failed to join thread");
    /// ```
    // Clippy doesn't like the lifetime parameters here but doing what it suggests leads to code
    // that doesn't compile.
    #[allow(clippy::needless_lifetimes)]
    pub async fn wait<'g, T>(&self, guard: RwLockWriteGuard<'g, T>) -> RwLockWriteGuard<'g, T> {
        let waiter = Arc::new(Waiter::new(
            WaiterKind::Exclusive,
            cancel_waiter,
            self as *const Condvar as usize,
            WaitingFor::Condvar,
        ));

        self.add_waiter(waiter.clone(), guard.as_raw_rwlock());

        // Get a reference to the rwlock and then drop the lock.
        let mu = guard.into_inner();

        // Wait to be woken up.
        waiter.wait().await;

        // Now re-acquire the lock.
        mu.lock_from_cv().await
    }

    /// Like `wait()` but takes and returns a `RwLockReadGuard` instead.
    // Clippy doesn't like the lifetime parameters here but doing what it suggests leads to code
    // that doesn't compile.
    #[allow(clippy::needless_lifetimes)]
    pub async fn wait_read<'g, T>(&self, guard: RwLockReadGuard<'g, T>) -> RwLockReadGuard<'g, T> {
        let waiter = Arc::new(Waiter::new(
            WaiterKind::Shared,
            cancel_waiter,
            self as *const Condvar as usize,
            WaitingFor::Condvar,
        ));

        self.add_waiter(waiter.clone(), guard.as_raw_rwlock());

        // Get a reference to the rwlock and then drop the lock.
        let mu = guard.into_inner();

        // Wait to be woken up.
        waiter.wait().await;

        // Now re-acquire the lock.
        mu.read_lock_from_cv().await
    }

    fn add_waiter(&self, waiter: Arc<Waiter>, raw_rwlock: &RawRwLock) {
        // Acquire the spin lock.
        let mut oldstate = self.state.load(Ordering::Relaxed);
        while (oldstate & SPINLOCK) != 0
            || self
                .state
                .compare_exchange_weak(
                    oldstate,
                    oldstate | SPINLOCK | HAS_WAITERS,
                    Ordering::Acquire,
                    Ordering::Relaxed,
                )
                .is_err()
        {
            hint::spin_loop();
            oldstate = self.state.load(Ordering::Relaxed);
        }

        // SAFETY:
        // Safe because the spin lock guarantees exclusive access and the reference does not escape
        // this function.
        let mu = unsafe { &mut *self.mu.get() };
        let muptr = raw_rwlock as *const RawRwLock as usize;

        match *mu {
            0 => *mu = muptr,
            p if p == muptr => {}
            _ => panic!("Attempting to use Condvar with more than one RwLock at the same time"),
        }

        // SAFETY:
        // Safe because the spin lock guarantees exclusive access.
        unsafe { (*self.waiters.get()).push_back(waiter) };

        // Release the spin lock. Use a direct store here because no other thread can modify
        // `self.state` while we hold the spin lock. Keep the `HAS_WAITERS` bit that we set earlier
        // because we just added a waiter.
        self.state.store(HAS_WAITERS, Ordering::Release);
    }

    /// Notify at most one thread currently waiting on the `Condvar`.
    ///
    /// If there is a thread currently waiting on the `Condvar` it will be woken up from its call to
    /// `wait`.
    ///
    /// Unlike more traditional condition variable interfaces, this method requires a reference to
    /// the `RwLock` associated with this `Condvar`. This is because it is inherently racy to call
    /// `notify_one` or `notify_all` without first acquiring the `RwLock` lock. Additionally, taking
    /// a reference to the `RwLock` here allows us to make some optimizations that can improve
    /// performance by reducing unnecessary wakeups.
    pub fn notify_one(&self) {
        let mut oldstate = self.state.load(Ordering::Relaxed);
        if (oldstate & HAS_WAITERS) == 0 {
            // No waiters.
            return;
        }

        while (oldstate & SPINLOCK) != 0
            || self
                .state
                .compare_exchange_weak(
                    oldstate,
                    oldstate | SPINLOCK,
                    Ordering::Acquire,
                    Ordering::Relaxed,
                )
                .is_err()
        {
            hint::spin_loop();
            oldstate = self.state.load(Ordering::Relaxed);
        }

        // SAFETY:
        // Safe because the spin lock guarantees exclusive access and the reference does not escape
        // this function.
        let waiters = unsafe { &mut *self.waiters.get() };
        let wake_list = get_wake_list(waiters);

        let newstate = if waiters.is_empty() {
            // SAFETY:
            // Also clear the rwlock associated with this Condvar since there are no longer any
            // waiters.  Safe because the spin lock guarantees exclusive access.
            unsafe { *self.mu.get() = 0 };

            // We are releasing the spin lock and there are no more waiters so we can clear all bits
            // in `self.state`.
            0
        } else {
            // There are still waiters so we need to keep the HAS_WAITERS bit in the state.
            HAS_WAITERS
        };

        // Release the spin lock.
        self.state.store(newstate, Ordering::Release);

        // Now wake any waiters in the wake list.
        for w in wake_list {
            w.wake();
        }
    }

    /// Notify all threads currently waiting on the `Condvar`.
    ///
    /// All threads currently waiting on the `Condvar` will be woken up from their call to `wait`.
    ///
    /// Unlike more traditional condition variable interfaces, this method requires a reference to
    /// the `RwLock` associated with this `Condvar`. This is because it is inherently racy to call
    /// `notify_one` or `notify_all` without first acquiring the `RwLock` lock. Additionally, taking
    /// a reference to the `RwLock` here allows us to make some optimizations that can improve
    /// performance by reducing unnecessary wakeups.
    pub fn notify_all(&self) {
        let mut oldstate = self.state.load(Ordering::Relaxed);
        if (oldstate & HAS_WAITERS) == 0 {
            // No waiters.
            return;
        }

        while (oldstate & SPINLOCK) != 0
            || self
                .state
                .compare_exchange_weak(
                    oldstate,
                    oldstate | SPINLOCK,
                    Ordering::Acquire,
                    Ordering::Relaxed,
                )
                .is_err()
        {
            hint::spin_loop();
            oldstate = self.state.load(Ordering::Relaxed);
        }

        // SAFETY:
        // Safe because the spin lock guarantees exclusive access to `self.waiters`.
        let wake_list = unsafe { (*self.waiters.get()).take() };

        // SAFETY:
        // Clear the rwlock associated with this Condvar since there are no longer any waiters. Safe
        // because we the spin lock guarantees exclusive access.
        unsafe { *self.mu.get() = 0 };

        // Mark any waiters left as no longer waiting for the Condvar.
        for w in &wake_list {
            w.set_waiting_for(WaitingFor::None);
        }

        // Release the spin lock.  We can clear all bits in the state since we took all the waiters.
        self.state.store(0, Ordering::Release);

        // Now wake any waiters in the wake list.
        for w in wake_list {
            w.wake();
        }
    }

    fn cancel_waiter(&self, waiter: &Waiter, wake_next: bool) {
        let mut oldstate = self.state.load(Ordering::Relaxed);
        while oldstate & SPINLOCK != 0
            || self
                .state
                .compare_exchange_weak(
                    oldstate,
                    oldstate | SPINLOCK,
                    Ordering::Acquire,
                    Ordering::Relaxed,
                )
                .is_err()
        {
            hint::spin_loop();
            oldstate = self.state.load(Ordering::Relaxed);
        }

        // SAFETY:
        // Safe because the spin lock provides exclusive access and the reference does not escape
        // this function.
        let waiters = unsafe { &mut *self.waiters.get() };

        let waiting_for = waiter.is_waiting_for();
        // Don't drop the old waiter now as we're still holding the spin lock.
        let old_waiter = if waiter.is_linked() && waiting_for == WaitingFor::Condvar {
            // SAFETY:
            // Safe because we know that the waiter is still linked and is waiting for the Condvar,
            // which guarantees that it is still in `self.waiters`.
            let mut cursor = unsafe { waiters.cursor_mut_from_ptr(waiter as *const Waiter) };
            cursor.remove()
        } else {
            None
        };

        let wake_list = if wake_next || waiting_for == WaitingFor::None {
            // Either the waiter was already woken or it's been removed from the condvar's waiter
            // list and is going to be woken. Either way, we need to wake up another thread.
            get_wake_list(waiters)
        } else {
            WaiterList::new(WaiterAdapter::new())
        };

        let set_on_release = if waiters.is_empty() {
            // SAFETY:
            // Clear the rwlock associated with this Condvar since there are no longer any waiters.
            // Safe because we the spin lock guarantees exclusive access.
            unsafe { *self.mu.get() = 0 };

            0
        } else {
            HAS_WAITERS
        };

        self.state.store(set_on_release, Ordering::Release);

        // Now wake any waiters still left in the wake list.
        for w in wake_list {
            w.wake();
        }

        mem::drop(old_waiter);
    }
}

// TODO(b/315998194): Add safety comment
#[allow(clippy::undocumented_unsafe_blocks)]
unsafe impl Send for Condvar {}
// TODO(b/315998194): Add safety comment
#[allow(clippy::undocumented_unsafe_blocks)]
unsafe impl Sync for Condvar {}

impl Default for Condvar {
    fn default() -> Self {
        Self::new()
    }
}

// Scan `waiters` and return all waiters that should be woken up.
//
// If the first waiter is trying to acquire a shared lock, then all waiters in the list that are
// waiting for a shared lock are also woken up. In addition one writer is woken up, if possible.
//
// If the first waiter is trying to acquire an exclusive lock, then only that waiter is returned and
// the rest of the list is not scanned.
fn get_wake_list(waiters: &mut WaiterList) -> WaiterList {
    let mut to_wake = WaiterList::new(WaiterAdapter::new());
    let mut cursor = waiters.front_mut();

    let mut waking_readers = false;
    let mut all_readers = true;
    while let Some(w) = cursor.get() {
        match w.kind() {
            WaiterKind::Exclusive if !waking_readers => {
                // This is the first waiter and it's a writer. No need to check the other waiters.
                // Also mark the waiter as having been removed from the Condvar's waiter list.
                let waiter = cursor.remove().unwrap();
                waiter.set_waiting_for(WaitingFor::None);
                to_wake.push_back(waiter);
                break;
            }

            WaiterKind::Shared => {
                // This is a reader and the first waiter in the list was not a writer so wake up all
                // the readers in the wait list.
                let waiter = cursor.remove().unwrap();
                waiter.set_waiting_for(WaitingFor::None);
                to_wake.push_back(waiter);
                waking_readers = true;
            }

            WaiterKind::Exclusive => {
                debug_assert!(waking_readers);
                if all_readers {
                    // We are waking readers but we need to ensure that at least one writer is woken
                    // up. Since we haven't yet woken up a writer, wake up this one.
                    let waiter = cursor.remove().unwrap();
                    waiter.set_waiting_for(WaitingFor::None);
                    to_wake.push_back(waiter);
                    all_readers = false;
                } else {
                    // We are waking readers and have already woken one writer. Skip this one.
                    cursor.move_next();
                }
            }
        }
    }

    to_wake
}

fn cancel_waiter(cv: usize, waiter: &Waiter, wake_next: bool) {
    let condvar = cv as *const Condvar;

    // SAFETY:
    // Safe because the thread that owns the waiter being canceled must also own a reference to the
    // Condvar, which guarantees that this pointer is valid.
    unsafe { (*condvar).cancel_waiter(waiter, wake_next) }
}

// TODO(b/194338842): Fix tests for windows
#[cfg(any(target_os = "android", target_os = "linux"))]
#[cfg(test)]
mod test {
    use std::future::Future;
    use std::mem;
    use std::ptr;
    use std::rc::Rc;
    use std::sync::mpsc::channel;
    use std::sync::mpsc::Sender;
    use std::sync::Arc;
    use std::task::Context;
    use std::task::Poll;
    use std::thread;
    use std::thread::JoinHandle;
    use std::time::Duration;

    use futures::channel::oneshot;
    use futures::select;
    use futures::task::waker_ref;
    use futures::task::ArcWake;
    use futures::FutureExt;
    use futures_executor::LocalPool;
    use futures_executor::LocalSpawner;
    use futures_executor::ThreadPool;
    use futures_util::task::LocalSpawnExt;

    use super::super::super::block_on;
    use super::super::super::sync::RwLock;
    use super::*;

    // Dummy waker used when we want to manually drive futures.
    struct TestWaker;
    impl ArcWake for TestWaker {
        fn wake_by_ref(_arc_self: &Arc<Self>) {}
    }

    #[test]
    fn smoke() {
        let cv = Condvar::new();
        cv.notify_one();
        cv.notify_all();
    }

    #[test]
    fn notify_one() {
        let mu = Arc::new(RwLock::new(()));
        let cv = Arc::new(Condvar::new());

        let mu2 = mu.clone();
        let cv2 = cv.clone();

        let guard = block_on(mu.lock());
        thread::spawn(move || {
            let _g = block_on(mu2.lock());
            cv2.notify_one();
        });

        let guard = block_on(cv.wait(guard));
        mem::drop(guard);
    }

    #[test]
    fn multi_rwlock() {
        const NUM_THREADS: usize = 5;

        let mu = Arc::new(RwLock::new(false));
        let cv = Arc::new(Condvar::new());

        let mut threads = Vec::with_capacity(NUM_THREADS);
        for _ in 0..NUM_THREADS {
            let mu = mu.clone();
            let cv = cv.clone();

            threads.push(thread::spawn(move || {
                let mut ready = block_on(mu.lock());
                while !*ready {
                    ready = block_on(cv.wait(ready));
                }
            }));
        }

        let mut g = block_on(mu.lock());
        *g = true;
        mem::drop(g);
        cv.notify_all();

        threads
            .into_iter()
            .try_for_each(JoinHandle::join)
            .expect("Failed to join threads");

        // Now use the Condvar with a different rwlock.
        let alt_mu = Arc::new(RwLock::new(None));
        let alt_mu2 = alt_mu.clone();
        let cv2 = cv.clone();
        let handle = thread::spawn(move || {
            let mut g = block_on(alt_mu2.lock());
            while g.is_none() {
                g = block_on(cv2.wait(g));
            }
        });

        let mut alt_g = block_on(alt_mu.lock());
        *alt_g = Some(());
        mem::drop(alt_g);
        cv.notify_all();

        handle
            .join()
            .expect("Failed to join thread alternate rwlock");
    }

    #[test]
    fn notify_one_single_thread_async() {
        async fn notify(mu: Rc<RwLock<()>>, cv: Rc<Condvar>) {
            let _g = mu.lock().await;
            cv.notify_one();
        }

        async fn wait(mu: Rc<RwLock<()>>, cv: Rc<Condvar>, spawner: LocalSpawner) {
            let mu2 = Rc::clone(&mu);
            let cv2 = Rc::clone(&cv);

            let g = mu.lock().await;
            // Has to be spawned _after_ acquiring the lock to prevent a race
            // where the notify happens before the waiter has acquired the lock.
            spawner
                .spawn_local(notify(mu2, cv2))
                .expect("Failed to spawn `notify` task");
            let _g = cv.wait(g).await;
        }

        let mut ex = LocalPool::new();
        let spawner = ex.spawner();

        let mu = Rc::new(RwLock::new(()));
        let cv = Rc::new(Condvar::new());

        spawner
            .spawn_local(wait(mu, cv, spawner.clone()))
            .expect("Failed to spawn `wait` task");

        ex.run();
    }

    #[test]
    fn notify_one_multi_thread_async() {
        async fn notify(mu: Arc<RwLock<()>>, cv: Arc<Condvar>) {
            let _g = mu.lock().await;
            cv.notify_one();
        }

        async fn wait(mu: Arc<RwLock<()>>, cv: Arc<Condvar>, tx: Sender<()>, pool: ThreadPool) {
            let mu2 = Arc::clone(&mu);
            let cv2 = Arc::clone(&cv);

            let g = mu.lock().await;
            // Has to be spawned _after_ acquiring the lock to prevent a race
            // where the notify happens before the waiter has acquired the lock.
            pool.spawn_ok(notify(mu2, cv2));
            let _g = cv.wait(g).await;

            tx.send(()).expect("Failed to send completion notification");
        }

        let ex = ThreadPool::new().expect("Failed to create ThreadPool");

        let mu = Arc::new(RwLock::new(()));
        let cv = Arc::new(Condvar::new());

        let (tx, rx) = channel();
        ex.spawn_ok(wait(mu, cv, tx, ex.clone()));

        rx.recv_timeout(Duration::from_secs(5))
            .expect("Failed to receive completion notification");
    }

    #[test]
    fn notify_one_with_cancel() {
        const TASKS: usize = 17;
        const OBSERVERS: usize = 7;
        const ITERATIONS: usize = 103;

        async fn observe(mu: &Arc<RwLock<usize>>, cv: &Arc<Condvar>) {
            let mut count = mu.read_lock().await;
            while *count == 0 {
                count = cv.wait_read(count).await;
            }
            // SAFETY: Safe because count is valid and is byte aligned.
            let _ = unsafe { ptr::read_volatile(&*count as *const usize) };
        }

        async fn decrement(mu: &Arc<RwLock<usize>>, cv: &Arc<Condvar>) {
            let mut count = mu.lock().await;
            while *count == 0 {
                count = cv.wait(count).await;
            }
            *count -= 1;
        }

        async fn increment(mu: Arc<RwLock<usize>>, cv: Arc<Condvar>, done: Sender<()>) {
            for _ in 0..TASKS * OBSERVERS * ITERATIONS {
                *mu.lock().await += 1;
                cv.notify_one();
            }

            done.send(()).expect("Failed to send completion message");
        }

        async fn observe_either(
            mu: Arc<RwLock<usize>>,
            cv: Arc<Condvar>,
            alt_mu: Arc<RwLock<usize>>,
            alt_cv: Arc<Condvar>,
            done: Sender<()>,
        ) {
            for _ in 0..ITERATIONS {
                select! {
                    () = observe(&mu, &cv).fuse() => {},
                    () = observe(&alt_mu, &alt_cv).fuse() => {},
                }
            }

            done.send(()).expect("Failed to send completion message");
        }

        async fn decrement_either(
            mu: Arc<RwLock<usize>>,
            cv: Arc<Condvar>,
            alt_mu: Arc<RwLock<usize>>,
            alt_cv: Arc<Condvar>,
            done: Sender<()>,
        ) {
            for _ in 0..ITERATIONS {
                select! {
                    () = decrement(&mu, &cv).fuse() => {},
                    () = decrement(&alt_mu, &alt_cv).fuse() => {},
                }
            }

            done.send(()).expect("Failed to send completion message");
        }

        let ex = ThreadPool::new().expect("Failed to create ThreadPool");

        let mu = Arc::new(RwLock::new(0usize));
        let alt_mu = Arc::new(RwLock::new(0usize));

        let cv = Arc::new(Condvar::new());
        let alt_cv = Arc::new(Condvar::new());

        let (tx, rx) = channel();
        for _ in 0..TASKS {
            ex.spawn_ok(decrement_either(
                Arc::clone(&mu),
                Arc::clone(&cv),
                Arc::clone(&alt_mu),
                Arc::clone(&alt_cv),
                tx.clone(),
            ));
        }

        for _ in 0..OBSERVERS {
            ex.spawn_ok(observe_either(
                Arc::clone(&mu),
                Arc::clone(&cv),
                Arc::clone(&alt_mu),
                Arc::clone(&alt_cv),
                tx.clone(),
            ));
        }

        ex.spawn_ok(increment(Arc::clone(&mu), Arc::clone(&cv), tx.clone()));
        ex.spawn_ok(increment(Arc::clone(&alt_mu), Arc::clone(&alt_cv), tx));

        for _ in 0..TASKS + OBSERVERS + 2 {
            if let Err(e) = rx.recv_timeout(Duration::from_secs(20)) {
                panic!("Error while waiting for threads to complete: {}", e);
            }
        }

        assert_eq!(
            *block_on(mu.read_lock()) + *block_on(alt_mu.read_lock()),
            (TASKS * OBSERVERS * ITERATIONS * 2) - (TASKS * ITERATIONS)
        );
        assert_eq!(cv.state.load(Ordering::Relaxed), 0);
        assert_eq!(alt_cv.state.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn notify_all_with_cancel() {
        const TASKS: usize = 17;
        const ITERATIONS: usize = 103;

        async fn decrement(mu: &Arc<RwLock<usize>>, cv: &Arc<Condvar>) {
            let mut count = mu.lock().await;
            while *count == 0 {
                count = cv.wait(count).await;
            }
            *count -= 1;
        }

        async fn increment(mu: Arc<RwLock<usize>>, cv: Arc<Condvar>, done: Sender<()>) {
            for _ in 0..TASKS * ITERATIONS {
                *mu.lock().await += 1;
                cv.notify_all();
            }

            done.send(()).expect("Failed to send completion message");
        }

        async fn decrement_either(
            mu: Arc<RwLock<usize>>,
            cv: Arc<Condvar>,
            alt_mu: Arc<RwLock<usize>>,
            alt_cv: Arc<Condvar>,
            done: Sender<()>,
        ) {
            for _ in 0..ITERATIONS {
                select! {
                    () = decrement(&mu, &cv).fuse() => {},
                    () = decrement(&alt_mu, &alt_cv).fuse() => {},
                }
            }

            done.send(()).expect("Failed to send completion message");
        }

        let ex = ThreadPool::new().expect("Failed to create ThreadPool");

        let mu = Arc::new(RwLock::new(0usize));
        let alt_mu = Arc::new(RwLock::new(0usize));

        let cv = Arc::new(Condvar::new());
        let alt_cv = Arc::new(Condvar::new());

        let (tx, rx) = channel();
        for _ in 0..TASKS {
            ex.spawn_ok(decrement_either(
                Arc::clone(&mu),
                Arc::clone(&cv),
                Arc::clone(&alt_mu),
                Arc::clone(&alt_cv),
                tx.clone(),
            ));
        }

        ex.spawn_ok(increment(Arc::clone(&mu), Arc::clone(&cv), tx.clone()));
        ex.spawn_ok(increment(Arc::clone(&alt_mu), Arc::clone(&alt_cv), tx));

        for _ in 0..TASKS + 2 {
            if let Err(e) = rx.recv_timeout(Duration::from_secs(10)) {
                panic!("Error while waiting for threads to complete: {}", e);
            }
        }

        assert_eq!(
            *block_on(mu.read_lock()) + *block_on(alt_mu.read_lock()),
            TASKS * ITERATIONS
        );
        assert_eq!(cv.state.load(Ordering::Relaxed), 0);
        assert_eq!(alt_cv.state.load(Ordering::Relaxed), 0);
    }
    #[test]
    fn notify_all() {
        const THREADS: usize = 13;

        let mu = Arc::new(RwLock::new(0));
        let cv = Arc::new(Condvar::new());
        let (tx, rx) = channel();

        let mut threads = Vec::with_capacity(THREADS);
        for _ in 0..THREADS {
            let mu2 = mu.clone();
            let cv2 = cv.clone();
            let tx2 = tx.clone();

            threads.push(thread::spawn(move || {
                let mut count = block_on(mu2.lock());
                *count += 1;
                if *count == THREADS {
                    tx2.send(()).unwrap();
                }

                while *count != 0 {
                    count = block_on(cv2.wait(count));
                }
            }));
        }

        mem::drop(tx);

        // Wait till all threads have started.
        rx.recv_timeout(Duration::from_secs(5)).unwrap();

        let mut count = block_on(mu.lock());
        *count = 0;
        mem::drop(count);
        cv.notify_all();

        for t in threads {
            t.join().unwrap();
        }
    }

    #[test]
    fn notify_all_single_thread_async() {
        const TASKS: usize = 13;

        async fn reset(mu: Rc<RwLock<usize>>, cv: Rc<Condvar>) {
            let mut count = mu.lock().await;
            *count = 0;
            cv.notify_all();
        }

        async fn watcher(mu: Rc<RwLock<usize>>, cv: Rc<Condvar>, spawner: LocalSpawner) {
            let mut count = mu.lock().await;
            *count += 1;
            if *count == TASKS {
                spawner
                    .spawn_local(reset(mu.clone(), cv.clone()))
                    .expect("Failed to spawn reset task");
            }

            while *count != 0 {
                count = cv.wait(count).await;
            }
        }

        let mut ex = LocalPool::new();
        let spawner = ex.spawner();

        let mu = Rc::new(RwLock::new(0));
        let cv = Rc::new(Condvar::new());

        for _ in 0..TASKS {
            spawner
                .spawn_local(watcher(mu.clone(), cv.clone(), spawner.clone()))
                .expect("Failed to spawn watcher task");
        }

        ex.run();
    }

    #[test]
    fn notify_all_multi_thread_async() {
        const TASKS: usize = 13;

        async fn reset(mu: Arc<RwLock<usize>>, cv: Arc<Condvar>) {
            let mut count = mu.lock().await;
            *count = 0;
            cv.notify_all();
        }

        async fn watcher(
            mu: Arc<RwLock<usize>>,
            cv: Arc<Condvar>,
            pool: ThreadPool,
            tx: Sender<()>,
        ) {
            let mut count = mu.lock().await;
            *count += 1;
            if *count == TASKS {
                pool.spawn_ok(reset(mu.clone(), cv.clone()));
            }

            while *count != 0 {
                count = cv.wait(count).await;
            }

            tx.send(()).expect("Failed to send completion notification");
        }

        let pool = ThreadPool::new().expect("Failed to create ThreadPool");

        let mu = Arc::new(RwLock::new(0));
        let cv = Arc::new(Condvar::new());

        let (tx, rx) = channel();
        for _ in 0..TASKS {
            pool.spawn_ok(watcher(mu.clone(), cv.clone(), pool.clone(), tx.clone()));
        }

        for _ in 0..TASKS {
            rx.recv_timeout(Duration::from_secs(5))
                .expect("Failed to receive completion notification");
        }
    }

    #[test]
    fn wake_all_readers() {
        async fn read(mu: Arc<RwLock<bool>>, cv: Arc<Condvar>) {
            let mut ready = mu.read_lock().await;
            while !*ready {
                ready = cv.wait_read(ready).await;
            }
        }

        let mu = Arc::new(RwLock::new(false));
        let cv = Arc::new(Condvar::new());
        let mut readers = [
            Box::pin(read(mu.clone(), cv.clone())),
            Box::pin(read(mu.clone(), cv.clone())),
            Box::pin(read(mu.clone(), cv.clone())),
            Box::pin(read(mu.clone(), cv.clone())),
        ];

        let arc_waker = Arc::new(TestWaker);
        let waker = waker_ref(&arc_waker);
        let mut cx = Context::from_waker(&waker);

        // First have all the readers wait on the Condvar.
        for r in &mut readers {
            if let Poll::Ready(()) = r.as_mut().poll(&mut cx) {
                panic!("reader unexpectedly ready");
            }
        }

        assert_eq!(cv.state.load(Ordering::Relaxed) & HAS_WAITERS, HAS_WAITERS);

        // Now make the condition true and notify the condvar. Even though we will call notify_one,
        // all the readers should be woken up.
        *block_on(mu.lock()) = true;
        cv.notify_one();

        assert_eq!(cv.state.load(Ordering::Relaxed), 0);

        // All readers should now be able to complete.
        for r in &mut readers {
            if r.as_mut().poll(&mut cx).is_pending() {
                panic!("reader unable to complete");
            }
        }
    }

    #[test]
    fn cancel_before_notify() {
        async fn dec(mu: Arc<RwLock<usize>>, cv: Arc<Condvar>) {
            let mut count = mu.lock().await;

            while *count == 0 {
                count = cv.wait(count).await;
            }

            *count -= 1;
        }

        let mu = Arc::new(RwLock::new(0));
        let cv = Arc::new(Condvar::new());

        let arc_waker = Arc::new(TestWaker);
        let waker = waker_ref(&arc_waker);
        let mut cx = Context::from_waker(&waker);

        let mut fut1 = Box::pin(dec(mu.clone(), cv.clone()));
        let mut fut2 = Box::pin(dec(mu.clone(), cv.clone()));

        if let Poll::Ready(()) = fut1.as_mut().poll(&mut cx) {
            panic!("future unexpectedly ready");
        }
        if let Poll::Ready(()) = fut2.as_mut().poll(&mut cx) {
            panic!("future unexpectedly ready");
        }
        assert_eq!(cv.state.load(Ordering::Relaxed) & HAS_WAITERS, HAS_WAITERS);

        *block_on(mu.lock()) = 2;
        // Drop fut1 before notifying the cv.
        mem::drop(fut1);
        cv.notify_one();

        // fut2 should now be ready to complete.
        assert_eq!(cv.state.load(Ordering::Relaxed), 0);

        if fut2.as_mut().poll(&mut cx).is_pending() {
            panic!("future unable to complete");
        }

        assert_eq!(*block_on(mu.lock()), 1);
    }

    #[test]
    fn cancel_after_notify_one() {
        async fn dec(mu: Arc<RwLock<usize>>, cv: Arc<Condvar>) {
            let mut count = mu.lock().await;

            while *count == 0 {
                count = cv.wait(count).await;
            }

            *count -= 1;
        }

        let mu = Arc::new(RwLock::new(0));
        let cv = Arc::new(Condvar::new());

        let arc_waker = Arc::new(TestWaker);
        let waker = waker_ref(&arc_waker);
        let mut cx = Context::from_waker(&waker);

        let mut fut1 = Box::pin(dec(mu.clone(), cv.clone()));
        let mut fut2 = Box::pin(dec(mu.clone(), cv.clone()));

        if let Poll::Ready(()) = fut1.as_mut().poll(&mut cx) {
            panic!("future unexpectedly ready");
        }
        if let Poll::Ready(()) = fut2.as_mut().poll(&mut cx) {
            panic!("future unexpectedly ready");
        }
        assert_eq!(cv.state.load(Ordering::Relaxed) & HAS_WAITERS, HAS_WAITERS);

        *block_on(mu.lock()) = 2;
        cv.notify_one();

        // fut1 should now be ready to complete. Drop it before polling. This should wake up fut2.
        mem::drop(fut1);
        assert_eq!(cv.state.load(Ordering::Relaxed), 0);

        if fut2.as_mut().poll(&mut cx).is_pending() {
            panic!("future unable to complete");
        }

        assert_eq!(*block_on(mu.lock()), 1);
    }

    #[test]
    fn cancel_after_notify_all() {
        async fn dec(mu: Arc<RwLock<usize>>, cv: Arc<Condvar>) {
            let mut count = mu.lock().await;

            while *count == 0 {
                count = cv.wait(count).await;
            }

            *count -= 1;
        }

        let mu = Arc::new(RwLock::new(0));
        let cv = Arc::new(Condvar::new());

        let arc_waker = Arc::new(TestWaker);
        let waker = waker_ref(&arc_waker);
        let mut cx = Context::from_waker(&waker);

        let mut fut1 = Box::pin(dec(mu.clone(), cv.clone()));
        let mut fut2 = Box::pin(dec(mu.clone(), cv.clone()));

        if let Poll::Ready(()) = fut1.as_mut().poll(&mut cx) {
            panic!("future unexpectedly ready");
        }
        if let Poll::Ready(()) = fut2.as_mut().poll(&mut cx) {
            panic!("future unexpectedly ready");
        }
        assert_eq!(cv.state.load(Ordering::Relaxed) & HAS_WAITERS, HAS_WAITERS);

        let mut count = block_on(mu.lock());
        *count = 2;

        // Notify the cv while holding the lock. This should wake up both waiters.
        cv.notify_all();
        assert_eq!(cv.state.load(Ordering::Relaxed), 0);

        mem::drop(count);

        mem::drop(fut1);

        if fut2.as_mut().poll(&mut cx).is_pending() {
            panic!("future unable to complete");
        }

        assert_eq!(*block_on(mu.lock()), 1);
    }

    #[test]
    fn timed_wait() {
        async fn wait_deadline(
            mu: Arc<RwLock<usize>>,
            cv: Arc<Condvar>,
            timeout: oneshot::Receiver<()>,
        ) {
            let mut count = mu.lock().await;

            if *count == 0 {
                let mut rx = timeout.fuse();

                while *count == 0 {
                    select! {
                        res = rx => {
                            if let Err(e) = res {
                                panic!("Error while receiving timeout notification: {}", e);
                            }

                            return;
                        },
                        c = cv.wait(count).fuse() => count = c,
                    }
                }
            }

            *count += 1;
        }

        let mu = Arc::new(RwLock::new(0));
        let cv = Arc::new(Condvar::new());

        let arc_waker = Arc::new(TestWaker);
        let waker = waker_ref(&arc_waker);
        let mut cx = Context::from_waker(&waker);

        let (tx, rx) = oneshot::channel();
        let mut wait = Box::pin(wait_deadline(mu.clone(), cv.clone(), rx));

        if let Poll::Ready(()) = wait.as_mut().poll(&mut cx) {
            panic!("wait_deadline unexpectedly ready");
        }

        assert_eq!(cv.state.load(Ordering::Relaxed), HAS_WAITERS);

        // Signal the channel, which should cancel the wait.
        tx.send(()).expect("Failed to send wakeup");

        // Wait for the timer to run out.
        if wait.as_mut().poll(&mut cx).is_pending() {
            panic!("wait_deadline unable to complete in time");
        }

        assert_eq!(cv.state.load(Ordering::Relaxed), 0);
        assert_eq!(*block_on(mu.lock()), 0);
    }
}
