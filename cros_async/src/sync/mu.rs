// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::UnsafeCell;
use std::hint;
use std::mem;
use std::ops::Deref;
use std::ops::DerefMut;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread::yield_now;

use super::super::sync::waiter::Kind as WaiterKind;
use super::super::sync::waiter::Waiter;
use super::super::sync::waiter::WaiterAdapter;
use super::super::sync::waiter::WaiterList;
use super::super::sync::waiter::WaitingFor;

// Set when the rwlock is exclusively locked.
const LOCKED: usize = 1 << 0;
// Set when there are one or more threads waiting to acquire the lock.
const HAS_WAITERS: usize = 1 << 1;
// Set when a thread has been woken up from the wait queue. Cleared when that thread either acquires
// the lock or adds itself back into the wait queue. Used to prevent unnecessary wake ups when a
// thread has been removed from the wait queue but has not gotten CPU time yet.
const DESIGNATED_WAKER: usize = 1 << 2;
// Used to provide exclusive access to the `waiters` field in `RwLock`. Should only be held while
// modifying the waiter list.
const SPINLOCK: usize = 1 << 3;
// Set when a thread that wants an exclusive lock adds itself to the wait queue. New threads
// attempting to acquire a shared lock will be preventing from getting it when this bit is set.
// However, this bit is ignored once a thread has gone through the wait queue at least once.
const WRITER_WAITING: usize = 1 << 4;
// Set when a thread has gone through the wait queue many times but has failed to acquire the lock
// every time it is woken up. When this bit is set, all other threads are prevented from acquiring
// the lock until the thread that set the `LONG_WAIT` bit has acquired the lock.
const LONG_WAIT: usize = 1 << 5;
// The bit that is added to the rwlock state in order to acquire a shared lock. Since more than one
// thread can acquire a shared lock, we cannot use a single bit. Instead we use all the remaining
// bits in the state to track the number of threads that have acquired a shared lock.
const READ_LOCK: usize = 1 << 8;
// Mask used for checking if any threads currently hold a shared lock.
const READ_MASK: usize = !0xff;

// The number of times the thread should just spin and attempt to re-acquire the lock.
const SPIN_THRESHOLD: usize = 7;

// The number of times the thread needs to go through the wait queue before it sets the `LONG_WAIT`
// bit and forces all other threads to wait for it to acquire the lock. This value is set relatively
// high so that we don't lose the benefit of having running threads unless it is absolutely
// necessary.
const LONG_WAIT_THRESHOLD: usize = 19;

// Common methods between shared and exclusive locks.
trait Kind {
    // The bits that must be zero for the thread to acquire this kind of lock. If any of these bits
    // are not zero then the thread will first spin and retry a few times before adding itself to
    // the wait queue.
    fn zero_to_acquire() -> usize;

    // The bit that must be added in order to acquire this kind of lock. This should either be
    // `LOCKED` or `READ_LOCK`.
    fn add_to_acquire() -> usize;

    // The bits that should be set when a thread adds itself to the wait queue while waiting to
    // acquire this kind of lock.
    fn set_when_waiting() -> usize;

    // The bits that should be cleared when a thread acquires this kind of lock.
    fn clear_on_acquire() -> usize;

    // The waiter that a thread should use when waiting to acquire this kind of lock.
    fn new_waiter(raw: &RawRwLock) -> Arc<Waiter>;
}

// A lock type for shared read-only access to the data. More than one thread may hold this kind of
// lock simultaneously.
struct Shared;

impl Kind for Shared {
    fn zero_to_acquire() -> usize {
        LOCKED | WRITER_WAITING | LONG_WAIT
    }

    fn add_to_acquire() -> usize {
        READ_LOCK
    }

    fn set_when_waiting() -> usize {
        0
    }

    fn clear_on_acquire() -> usize {
        0
    }

    fn new_waiter(raw: &RawRwLock) -> Arc<Waiter> {
        Arc::new(Waiter::new(
            WaiterKind::Shared,
            cancel_waiter,
            raw as *const RawRwLock as usize,
            WaitingFor::Mutex,
        ))
    }
}

// A lock type for mutually exclusive read-write access to the data. Only one thread can hold this
// kind of lock at a time.
struct Exclusive;

impl Kind for Exclusive {
    fn zero_to_acquire() -> usize {
        LOCKED | READ_MASK | LONG_WAIT
    }

    fn add_to_acquire() -> usize {
        LOCKED
    }

    fn set_when_waiting() -> usize {
        WRITER_WAITING
    }

    fn clear_on_acquire() -> usize {
        WRITER_WAITING
    }

    fn new_waiter(raw: &RawRwLock) -> Arc<Waiter> {
        Arc::new(Waiter::new(
            WaiterKind::Exclusive,
            cancel_waiter,
            raw as *const RawRwLock as usize,
            WaitingFor::Mutex,
        ))
    }
}

// Scan `waiters` and return the ones that should be woken up. Also returns any bits that should be
// set in the rwlock state when the current thread releases the spin lock protecting the waiter
// list.
//
// If the first waiter is trying to acquire a shared lock, then all waiters in the list that are
// waiting for a shared lock are also woken up. If any waiters waiting for an exclusive lock are
// found when iterating through the list, then the returned `usize` contains the `WRITER_WAITING`
// bit, which should be set when the thread releases the spin lock.
//
// If the first waiter is trying to acquire an exclusive lock, then only that waiter is returned and
// no bits are set in the returned `usize`.
fn get_wake_list(waiters: &mut WaiterList) -> (WaiterList, usize) {
    let mut to_wake = WaiterList::new(WaiterAdapter::new());
    let mut set_on_release = 0;
    let mut cursor = waiters.front_mut();

    let mut waking_readers = false;
    while let Some(w) = cursor.get() {
        match w.kind() {
            WaiterKind::Exclusive if !waking_readers => {
                // This is the first waiter and it's a writer. No need to check the other waiters.
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
                // We found a writer while looking for more readers to wake up. Set the
                // `WRITER_WAITING` bit to prevent any new readers from acquiring the lock. All
                // readers currently in the wait list will ignore this bit since they already waited
                // once.
                set_on_release |= WRITER_WAITING;
                cursor.move_next();
            }
        }
    }

    (to_wake, set_on_release)
}

#[inline]
fn cpu_relax(iterations: usize) {
    for _ in 0..iterations {
        hint::spin_loop();
    }
}

pub(crate) struct RawRwLock {
    state: AtomicUsize,
    waiters: UnsafeCell<WaiterList>,
}

impl RawRwLock {
    pub fn new() -> RawRwLock {
        RawRwLock {
            state: AtomicUsize::new(0),
            waiters: UnsafeCell::new(WaiterList::new(WaiterAdapter::new())),
        }
    }

    #[inline]
    pub async fn lock(&self) {
        match self
            .state
            .compare_exchange_weak(0, LOCKED, Ordering::Acquire, Ordering::Relaxed)
        {
            Ok(_) => {}
            Err(oldstate) => {
                // If any bits that should be zero are not zero or if we fail to acquire the lock
                // with a single compare_exchange then go through the slow path.
                if (oldstate & Exclusive::zero_to_acquire()) != 0
                    || self
                        .state
                        .compare_exchange_weak(
                            oldstate,
                            (oldstate + Exclusive::add_to_acquire())
                                & !Exclusive::clear_on_acquire(),
                            Ordering::Acquire,
                            Ordering::Relaxed,
                        )
                        .is_err()
                {
                    self.lock_slow::<Exclusive>(0, 0).await;
                }
            }
        }
    }

    #[inline]
    pub async fn read_lock(&self) {
        match self
            .state
            .compare_exchange_weak(0, READ_LOCK, Ordering::Acquire, Ordering::Relaxed)
        {
            Ok(_) => {}
            Err(oldstate) => {
                if (oldstate & Shared::zero_to_acquire()) != 0
                    || self
                        .state
                        .compare_exchange_weak(
                            oldstate,
                            (oldstate + Shared::add_to_acquire()) & !Shared::clear_on_acquire(),
                            Ordering::Acquire,
                            Ordering::Relaxed,
                        )
                        .is_err()
                {
                    self.lock_slow::<Shared>(0, 0).await;
                }
            }
        }
    }

    // Slow path for acquiring the lock. `clear` should contain any bits that need to be cleared
    // when the lock is acquired. Any bits set in `zero_mask` are cleared from the bits returned by
    // `K::zero_to_acquire()`.
    #[cold]
    async fn lock_slow<K: Kind>(&self, mut clear: usize, zero_mask: usize) {
        let mut zero_to_acquire = K::zero_to_acquire() & !zero_mask;

        let mut spin_count = 0;
        let mut wait_count = 0;
        let mut waiter = None;
        loop {
            let oldstate = self.state.load(Ordering::Relaxed);
            //  If all the bits in `zero_to_acquire` are actually zero then try to acquire the lock
            //  directly.
            if (oldstate & zero_to_acquire) == 0 {
                if self
                    .state
                    .compare_exchange_weak(
                        oldstate,
                        (oldstate + K::add_to_acquire()) & !(clear | K::clear_on_acquire()),
                        Ordering::Acquire,
                        Ordering::Relaxed,
                    )
                    .is_ok()
                {
                    return;
                }
            } else if (oldstate & SPINLOCK) == 0 {
                // The rwlock is locked and the spin lock is available.  Try to add this thread to
                // the waiter queue.
                let w = waiter.get_or_insert_with(|| K::new_waiter(self));
                w.reset(WaitingFor::Mutex);

                if self
                    .state
                    .compare_exchange_weak(
                        oldstate,
                        (oldstate | SPINLOCK | HAS_WAITERS | K::set_when_waiting()) & !clear,
                        Ordering::Acquire,
                        Ordering::Relaxed,
                    )
                    .is_ok()
                {
                    let mut set_on_release = 0;

                    // Safe because we have acquired the spin lock and it provides exclusive
                    // access to the waiter queue.
                    if wait_count < LONG_WAIT_THRESHOLD {
                        // Add the waiter to the back of the queue.
                        unsafe { (*self.waiters.get()).push_back(w.clone()) };
                    } else {
                        // This waiter has gone through the queue too many times. Put it in the
                        // front of the queue and block all other threads from acquiring the lock
                        // until this one has acquired it at least once.
                        unsafe { (*self.waiters.get()).push_front(w.clone()) };

                        // Set the LONG_WAIT bit to prevent all other threads from acquiring the
                        // lock.
                        set_on_release |= LONG_WAIT;

                        // Make sure we clear the LONG_WAIT bit when we do finally get the lock.
                        clear |= LONG_WAIT;

                        // Since we set the LONG_WAIT bit we shouldn't allow that bit to prevent us
                        // from acquiring the lock.
                        zero_to_acquire &= !LONG_WAIT;
                    }

                    // Release the spin lock.
                    let mut state = oldstate;
                    loop {
                        match self.state.compare_exchange_weak(
                            state,
                            (state | set_on_release) & !SPINLOCK,
                            Ordering::Release,
                            Ordering::Relaxed,
                        ) {
                            Ok(_) => break,
                            Err(w) => state = w,
                        }
                    }

                    // Now wait until we are woken.
                    w.wait().await;

                    // The `DESIGNATED_WAKER` bit gets set when this thread is woken up by the
                    // thread that originally held the lock. While this bit is set, no other waiters
                    // will be woken up so it's important to clear it the next time we try to
                    // acquire the main lock or the spin lock.
                    clear |= DESIGNATED_WAKER;

                    // Now that the thread has waited once, we no longer care if there is a writer
                    // waiting. Only the limits of mutual exclusion can prevent us from acquiring
                    // the lock.
                    zero_to_acquire &= !WRITER_WAITING;

                    // Reset the spin count since we just went through the wait queue.
                    spin_count = 0;

                    // Increment the wait count since we went through the wait queue.
                    wait_count += 1;

                    // Skip the `cpu_relax` below.
                    continue;
                }
            }

            // Both the lock and the spin lock are held by one or more other threads. First, we'll
            // spin a few times in case we can acquire the lock or the spin lock. If that fails then
            // we yield because we might be preventing the threads that do hold the 2 locks from
            // getting cpu time.
            if spin_count < SPIN_THRESHOLD {
                cpu_relax(1 << spin_count);
                spin_count += 1;
            } else {
                yield_now();
            }
        }
    }

    #[inline]
    pub fn unlock(&self) {
        // Fast path, if possible. We can directly clear the locked bit since we have exclusive
        // access to the rwlock.
        let oldstate = self.state.fetch_sub(LOCKED, Ordering::Release);

        // Panic if we just tried to unlock a rwlock that wasn't held by this thread. This shouldn't
        // really be possible since `unlock` is not a public method.
        debug_assert_eq!(
            oldstate & READ_MASK,
            0,
            "`unlock` called on rwlock held in read-mode"
        );
        debug_assert_ne!(
            oldstate & LOCKED,
            0,
            "`unlock` called on rwlock not held in write-mode"
        );

        if (oldstate & HAS_WAITERS) != 0 && (oldstate & DESIGNATED_WAKER) == 0 {
            // The oldstate has waiters but no designated waker has been chosen yet.
            self.unlock_slow();
        }
    }

    #[inline]
    pub fn read_unlock(&self) {
        // Fast path, if possible. We can directly subtract the READ_LOCK bit since we had
        // previously added it.
        let oldstate = self.state.fetch_sub(READ_LOCK, Ordering::Release);

        debug_assert_eq!(
            oldstate & LOCKED,
            0,
            "`read_unlock` called on rwlock held in write-mode"
        );
        debug_assert_ne!(
            oldstate & READ_MASK,
            0,
            "`read_unlock` called on rwlock not held in read-mode"
        );

        if (oldstate & HAS_WAITERS) != 0
            && (oldstate & DESIGNATED_WAKER) == 0
            && (oldstate & READ_MASK) == READ_LOCK
        {
            // There are waiters, no designated waker has been chosen yet, and the last reader is
            // unlocking so we have to take the slow path.
            self.unlock_slow();
        }
    }

    #[cold]
    fn unlock_slow(&self) {
        let mut spin_count = 0;

        loop {
            let oldstate = self.state.load(Ordering::Relaxed);
            if (oldstate & HAS_WAITERS) == 0 || (oldstate & DESIGNATED_WAKER) != 0 {
                // No more waiters or a designated waker has been chosen. Nothing left for us to do.
                return;
            } else if (oldstate & SPINLOCK) == 0 {
                // The spin lock is not held by another thread. Try to acquire it. Also set the
                // `DESIGNATED_WAKER` bit since we are likely going to wake up one or more threads.
                if self
                    .state
                    .compare_exchange_weak(
                        oldstate,
                        oldstate | SPINLOCK | DESIGNATED_WAKER,
                        Ordering::Acquire,
                        Ordering::Relaxed,
                    )
                    .is_ok()
                {
                    // Acquired the spinlock. Try to wake a waiter. We may also end up wanting to
                    // clear the HAS_WAITER and DESIGNATED_WAKER bits so start collecting the bits
                    // to be cleared.
                    let mut clear = SPINLOCK;

                    // Safe because the spinlock guarantees exclusive access to the waiter list and
                    // the reference does not escape this function.
                    let waiters = unsafe { &mut *self.waiters.get() };
                    let (wake_list, set_on_release) = get_wake_list(waiters);

                    // If the waiter list is now empty, clear the HAS_WAITERS bit.
                    if waiters.is_empty() {
                        clear |= HAS_WAITERS;
                    }

                    if wake_list.is_empty() {
                        // Since we are not going to wake any waiters clear the DESIGNATED_WAKER bit
                        // that we set when we acquired the spin lock.
                        clear |= DESIGNATED_WAKER;
                    }

                    // Release the spin lock and clear any other bits as necessary. Also, set any
                    // bits returned by `get_wake_list`. For now, this is just the `WRITER_WAITING`
                    // bit, which needs to be set when we are waking up a bunch of readers and there
                    // are still writers in the wait queue. This will prevent any readers that
                    // aren't in `wake_list` from acquiring the read lock.
                    let mut state = oldstate;
                    loop {
                        match self.state.compare_exchange_weak(
                            state,
                            (state | set_on_release) & !clear,
                            Ordering::Release,
                            Ordering::Relaxed,
                        ) {
                            Ok(_) => break,
                            Err(w) => state = w,
                        }
                    }

                    // Now wake the waiters, if any.
                    for w in wake_list {
                        w.wake();
                    }

                    // We're done.
                    return;
                }
            }

            // Spin and try again.  It's ok to block here as we have already released the lock.
            if spin_count < SPIN_THRESHOLD {
                cpu_relax(1 << spin_count);
                spin_count += 1;
            } else {
                yield_now();
            }
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

        // Safe because the spin lock provides exclusive access and the reference does not escape
        // this function.
        let waiters = unsafe { &mut *self.waiters.get() };

        let mut clear = SPINLOCK;

        // If we are about to remove the first waiter in the wait list, then clear the LONG_WAIT
        // bit. Also clear the bit if we are going to be waking some other waiters. In this case the
        // waiter that set the bit may have already been removed from the waiter list (and could be
        // the one that is currently being dropped). If it is still in the waiter list then clearing
        // this bit may starve it for one more iteration through the lock_slow() loop, whereas not
        // clearing this bit could cause a deadlock if the waiter that set it is the one that is
        // being dropped.
        if wake_next
            || waiters
                .front()
                .get()
                .map(|front| std::ptr::eq(front, waiter))
                .unwrap_or(false)
        {
            clear |= LONG_WAIT;
        }

        let waiting_for = waiter.is_waiting_for();

        // Don't drop the old waiter while holding the spin lock.
        let old_waiter = if waiter.is_linked() && waiting_for == WaitingFor::Mutex {
            // We know that the waiter is still linked and is waiting for the rwlock, which
            // guarantees that it is still linked into `self.waiters`.
            let mut cursor = unsafe { waiters.cursor_mut_from_ptr(waiter as *const Waiter) };
            cursor.remove()
        } else {
            None
        };

        let (wake_list, set_on_release) = if wake_next || waiting_for == WaitingFor::None {
            // Either the waiter was already woken or it's been removed from the rwlock's waiter
            // list and is going to be woken. Either way, we need to wake up another thread.
            get_wake_list(waiters)
        } else {
            (WaiterList::new(WaiterAdapter::new()), 0)
        };

        if waiters.is_empty() {
            clear |= HAS_WAITERS;
        }

        if wake_list.is_empty() {
            // We're not waking any other threads so clear the DESIGNATED_WAKER bit. In the worst
            // case this leads to an additional thread being woken up but we risk a deadlock if we
            // don't clear it.
            clear |= DESIGNATED_WAKER;
        }

        if let WaiterKind::Exclusive = waiter.kind() {
            // The waiter being dropped is a writer so clear the writer waiting bit for now. If we
            // found more writers in the list while fetching waiters to wake up then this bit will
            // be set again via `set_on_release`.
            clear |= WRITER_WAITING;
        }

        while self
            .state
            .compare_exchange_weak(
                oldstate,
                (oldstate & !clear) | set_on_release,
                Ordering::Release,
                Ordering::Relaxed,
            )
            .is_err()
        {
            hint::spin_loop();
            oldstate = self.state.load(Ordering::Relaxed);
        }

        for w in wake_list {
            w.wake();
        }

        mem::drop(old_waiter);
    }
}

unsafe impl Send for RawRwLock {}
unsafe impl Sync for RawRwLock {}

fn cancel_waiter(raw: usize, waiter: &Waiter, wake_next: bool) {
    let raw_rwlock = raw as *const RawRwLock;

    // Safe because the thread that owns the waiter that is being canceled must also own a reference
    // to the rwlock, which ensures that this pointer is valid.
    unsafe { (*raw_rwlock).cancel_waiter(waiter, wake_next) }
}

/// A high-level primitive that provides safe, mutable access to a shared resource.
///
/// `RwLock` safely provides both shared, immutable access (via `read_lock()`) as well as exclusive,
/// mutable access (via `lock()`) to an underlying resource asynchronously while ensuring fairness
/// with no loss of performance. If you don't need `read_lock()` nor fairness, try upstream
/// `futures::lock::Mutex` instead.
///
/// # Poisoning
///
/// `RwLock` does not support lock poisoning so if a thread panics while holding the lock, the
/// poisoned data will be accessible by other threads in your program. If you need to guarantee that
/// other threads cannot access poisoned data then you may wish to wrap this `RwLock` inside another
/// type that provides the poisoning feature. See the implementation of `std::sync::Mutex` for an
/// example of this. Note `futures::lock::Mutex` does not support poisoning either.
///
///
/// # Fairness
///
/// This `RwLock` implementation does not guarantee that threads will acquire the lock in the same
/// order that they call `lock()` or `read_lock()`. However it will attempt to prevent long-term
/// starvation: if a thread repeatedly fails to acquire the lock beyond a threshold then all other
/// threads will fail to acquire the lock until the starved thread has acquired it. Note, on the
/// other hand, `futures::lock::Mutex` does not guarantee fairness.
///
/// Similarly, this `RwLock` will attempt to balance reader and writer threads: once there is a
/// writer thread waiting to acquire the lock no new reader threads will be allowed to acquire it.
/// However, any reader threads that were already waiting will still be allowed to acquire it.
///
/// # Examples
///
/// ```edition2018
/// use std::sync::Arc;
/// use std::thread;
/// use std::sync::mpsc::channel;
///
/// use cros_async::{block_on, sync::RwLock};
///
/// const N: usize = 10;
///
/// // Spawn a few threads to increment a shared variable (non-atomically), and
/// // let the main thread know once all increments are done.
/// //
/// // Here we're using an Arc to share memory among threads, and the data inside
/// // the Arc is protected with a rwlock.
/// let data = Arc::new(RwLock::new(0));
///
/// let (tx, rx) = channel();
/// for _ in 0..N {
///     let (data, tx) = (Arc::clone(&data), tx.clone());
///     thread::spawn(move || {
///         // The shared state can only be accessed once the lock is held.
///         // Our non-atomic increment is safe because we're the only thread
///         // which can access the shared state when the lock is held.
///         let mut data = block_on(data.lock());
///         *data += 1;
///         if *data == N {
///             tx.send(()).unwrap();
///         }
///         // the lock is unlocked here when `data` goes out of scope.
///     });
/// }
///
/// rx.recv().unwrap();
/// ```
#[repr(align(128))]
pub struct RwLock<T: ?Sized> {
    raw: RawRwLock,
    value: UnsafeCell<T>,
}

impl<T> RwLock<T> {
    /// Create a new, unlocked `RwLock` ready for use.
    pub fn new(v: T) -> RwLock<T> {
        RwLock {
            raw: RawRwLock::new(),
            value: UnsafeCell::new(v),
        }
    }

    /// Consume the `RwLock` and return the contained value. This method does not perform any
    /// locking as the compiler will guarantee that there are no other references to `self` and the
    /// caller owns the `RwLock`.
    pub fn into_inner(self) -> T {
        // Don't need to acquire the lock because the compiler guarantees that there are
        // no references to `self`.
        self.value.into_inner()
    }
}

impl<T: ?Sized> RwLock<T> {
    /// Acquires exclusive, mutable access to the resource protected by the `RwLock`, blocking the
    /// current thread until it is able to do so. Upon returning, the current thread will be the
    /// only thread with access to the resource. The `RwLock` will be released when the returned
    /// `RwLockWriteGuard` is dropped.
    ///
    /// Calling `lock()` while holding a `RwLockWriteGuard` or a `RwLockReadGuard` will cause a
    /// deadlock.
    ///
    /// Callers that are not in an async context may wish to use the `block_on` method to block the
    /// thread until the `RwLock` is acquired.
    #[inline]
    pub async fn lock(&self) -> RwLockWriteGuard<'_, T> {
        self.raw.lock().await;

        // Safe because we have exclusive access to `self.value`.
        RwLockWriteGuard {
            mu: self,
            value: unsafe { &mut *self.value.get() },
        }
    }

    /// Acquires shared, immutable access to the resource protected by the `RwLock`, blocking the
    /// current thread until it is able to do so. Upon returning there may be other threads that
    /// also have immutable access to the resource but there will not be any threads that have
    /// mutable access to the resource. When the returned `RwLockReadGuard` is dropped the thread
    /// releases its access to the resource.
    ///
    /// Calling `read_lock()` while holding a `RwLockReadGuard` may deadlock. Calling `read_lock()`
    /// while holding a `RwLockWriteGuard` will deadlock.
    ///
    /// Callers that are not in an async context may wish to use the `block_on` method to block the
    /// thread until the `RwLock` is acquired.
    #[inline]
    pub async fn read_lock(&self) -> RwLockReadGuard<'_, T> {
        self.raw.read_lock().await;

        // Safe because we have shared read-only access to `self.value`.
        RwLockReadGuard {
            mu: self,
            value: unsafe { &*self.value.get() },
        }
    }

    // Called from `Condvar::wait` when the thread wants to reacquire the lock.
    #[inline]
    pub(crate) async fn lock_from_cv(&self) -> RwLockWriteGuard<'_, T> {
        self.raw.lock_slow::<Exclusive>(DESIGNATED_WAKER, 0).await;

        // Safe because we have exclusive access to `self.value`.
        RwLockWriteGuard {
            mu: self,
            value: unsafe { &mut *self.value.get() },
        }
    }

    // Like `lock_from_cv` but for acquiring a shared lock.
    #[inline]
    pub(crate) async fn read_lock_from_cv(&self) -> RwLockReadGuard<'_, T> {
        // Threads that have waited in the Condvar's waiter list don't have to care if there is a
        // writer waiting since they have already waited once.
        self.raw
            .lock_slow::<Shared>(DESIGNATED_WAKER, WRITER_WAITING)
            .await;

        // Safe because we have exclusive access to `self.value`.
        RwLockReadGuard {
            mu: self,
            value: unsafe { &*self.value.get() },
        }
    }

    #[inline]
    fn unlock(&self) {
        self.raw.unlock();
    }

    #[inline]
    fn read_unlock(&self) {
        self.raw.read_unlock();
    }

    pub fn get_mut(&mut self) -> &mut T {
        // Safe because the compiler statically guarantees that are no other references to `self`.
        // This is also why we don't need to acquire the lock first.
        unsafe { &mut *self.value.get() }
    }
}

unsafe impl<T: ?Sized + Send> Send for RwLock<T> {}
unsafe impl<T: ?Sized + Send> Sync for RwLock<T> {}

impl<T: ?Sized + Default> Default for RwLock<T> {
    fn default() -> Self {
        Self::new(Default::default())
    }
}

impl<T> From<T> for RwLock<T> {
    fn from(source: T) -> Self {
        Self::new(source)
    }
}

/// An RAII implementation of a "scoped exclusive lock" for a `RwLock`. When this structure is
/// dropped, the lock will be released. The resource protected by the `RwLock` can be accessed via
/// the `Deref` and `DerefMut` implementations of this structure.
pub struct RwLockWriteGuard<'a, T: ?Sized + 'a> {
    mu: &'a RwLock<T>,
    value: &'a mut T,
}

impl<'a, T: ?Sized> RwLockWriteGuard<'a, T> {
    pub(crate) fn into_inner(self) -> &'a RwLock<T> {
        self.mu
    }

    pub(crate) fn as_raw_rwlock(&self) -> &RawRwLock {
        &self.mu.raw
    }
}

impl<'a, T: ?Sized> Deref for RwLockWriteGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.value
    }
}

impl<'a, T: ?Sized> DerefMut for RwLockWriteGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.value
    }
}

impl<'a, T: ?Sized> Drop for RwLockWriteGuard<'a, T> {
    fn drop(&mut self) {
        self.mu.unlock()
    }
}

/// An RAII implementation of a "scoped shared lock" for a `RwLock`. When this structure is dropped,
/// the lock will be released. The resource protected by the `RwLock` can be accessed via the
/// `Deref` implementation of this structure.
pub struct RwLockReadGuard<'a, T: ?Sized + 'a> {
    mu: &'a RwLock<T>,
    value: &'a T,
}

impl<'a, T: ?Sized> RwLockReadGuard<'a, T> {
    pub(crate) fn into_inner(self) -> &'a RwLock<T> {
        self.mu
    }

    pub(crate) fn as_raw_rwlock(&self) -> &RawRwLock {
        &self.mu.raw
    }
}

impl<'a, T: ?Sized> Deref for RwLockReadGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.value
    }
}

impl<'a, T: ?Sized> Drop for RwLockReadGuard<'a, T> {
    fn drop(&mut self) {
        self.mu.read_unlock()
    }
}

// TODO(b/194338842): Fix tests for windows
#[cfg(any(target_os = "android", target_os = "linux"))]
#[cfg(test)]
mod test {
    use std::future::Future;
    use std::mem;
    use std::pin::Pin;
    use std::rc::Rc;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::sync::mpsc::channel;
    use std::sync::mpsc::Sender;
    use std::sync::Arc;
    use std::task::Context;
    use std::task::Poll;
    use std::task::Waker;
    use std::thread;
    use std::time::Duration;

    use futures::channel::oneshot;
    use futures::pending;
    use futures::select;
    use futures::task::waker_ref;
    use futures::task::ArcWake;
    use futures::FutureExt;
    use futures_executor::LocalPool;
    use futures_executor::ThreadPool;
    use futures_util::task::LocalSpawnExt;

    use super::super::super::block_on;
    use super::super::super::sync::Condvar;
    use super::super::super::sync::SpinLock;
    use super::*;

    #[derive(Debug, Eq, PartialEq)]
    struct NonCopy(u32);

    // Dummy waker used when we want to manually drive futures.
    struct TestWaker;
    impl ArcWake for TestWaker {
        fn wake_by_ref(_arc_self: &Arc<Self>) {}
    }

    #[test]
    fn it_works() {
        let mu = RwLock::new(NonCopy(13));

        assert_eq!(*block_on(mu.lock()), NonCopy(13));
    }

    #[test]
    fn smoke() {
        let mu = RwLock::new(NonCopy(7));

        mem::drop(block_on(mu.lock()));
        mem::drop(block_on(mu.lock()));
    }

    #[test]
    fn rw_smoke() {
        let mu = RwLock::new(NonCopy(7));

        mem::drop(block_on(mu.lock()));
        mem::drop(block_on(mu.read_lock()));
        mem::drop((block_on(mu.read_lock()), block_on(mu.read_lock())));
        mem::drop(block_on(mu.lock()));
    }

    #[test]
    fn async_smoke() {
        async fn lock(mu: Rc<RwLock<NonCopy>>) {
            mu.lock().await;
        }

        async fn read_lock(mu: Rc<RwLock<NonCopy>>) {
            mu.read_lock().await;
        }

        async fn double_read_lock(mu: Rc<RwLock<NonCopy>>) {
            let first = mu.read_lock().await;
            mu.read_lock().await;

            // Make sure first lives past the second read lock.
            first.as_raw_rwlock();
        }

        let mu = Rc::new(RwLock::new(NonCopy(7)));

        let mut ex = LocalPool::new();
        let spawner = ex.spawner();

        spawner
            .spawn_local(lock(Rc::clone(&mu)))
            .expect("Failed to spawn future");
        spawner
            .spawn_local(read_lock(Rc::clone(&mu)))
            .expect("Failed to spawn future");
        spawner
            .spawn_local(double_read_lock(Rc::clone(&mu)))
            .expect("Failed to spawn future");
        spawner
            .spawn_local(lock(Rc::clone(&mu)))
            .expect("Failed to spawn future");

        ex.run();
    }

    #[test]
    fn send() {
        let mu = RwLock::new(NonCopy(19));

        thread::spawn(move || {
            let value = block_on(mu.lock());
            assert_eq!(*value, NonCopy(19));
        })
        .join()
        .unwrap();
    }

    #[test]
    fn arc_nested() {
        // Tests nested rwlocks and access to underlying data.
        let mu = RwLock::new(1);
        let arc = Arc::new(RwLock::new(mu));
        thread::spawn(move || {
            let nested = block_on(arc.lock());
            let lock2 = block_on(nested.lock());
            assert_eq!(*lock2, 1);
        })
        .join()
        .unwrap();
    }

    #[test]
    fn arc_access_in_unwind() {
        let arc = Arc::new(RwLock::new(1));
        let arc2 = arc.clone();
        thread::spawn(move || {
            struct Unwinder {
                i: Arc<RwLock<i32>>,
            }
            impl Drop for Unwinder {
                fn drop(&mut self) {
                    *block_on(self.i.lock()) += 1;
                }
            }
            let _u = Unwinder { i: arc2 };
            panic!();
        })
        .join()
        .expect_err("thread did not panic");
        let lock = block_on(arc.lock());
        assert_eq!(*lock, 2);
    }

    #[test]
    fn unsized_value() {
        let rwlock: &RwLock<[i32]> = &RwLock::new([1, 2, 3]);
        {
            let b = &mut *block_on(rwlock.lock());
            b[0] = 4;
            b[2] = 5;
        }
        let expected: &[i32] = &[4, 2, 5];
        assert_eq!(&*block_on(rwlock.lock()), expected);
    }
    #[test]
    fn high_contention() {
        const THREADS: usize = 17;
        const ITERATIONS: usize = 103;

        let mut threads = Vec::with_capacity(THREADS);

        let mu = Arc::new(RwLock::new(0usize));
        for _ in 0..THREADS {
            let mu2 = mu.clone();
            threads.push(thread::spawn(move || {
                for _ in 0..ITERATIONS {
                    *block_on(mu2.lock()) += 1;
                }
            }));
        }

        for t in threads.into_iter() {
            t.join().unwrap();
        }

        assert_eq!(*block_on(mu.read_lock()), THREADS * ITERATIONS);
        assert_eq!(mu.raw.state.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn high_contention_with_cancel() {
        const TASKS: usize = 17;
        const ITERATIONS: usize = 103;

        async fn increment(mu: Arc<RwLock<usize>>, alt_mu: Arc<RwLock<usize>>, tx: Sender<()>) {
            for _ in 0..ITERATIONS {
                select! {
                    mut count = mu.lock().fuse() => *count += 1,
                    mut count = alt_mu.lock().fuse() => *count += 1,
                }
            }
            tx.send(()).expect("Failed to send completion signal");
        }

        let ex = ThreadPool::new().expect("Failed to create ThreadPool");

        let mu = Arc::new(RwLock::new(0usize));
        let alt_mu = Arc::new(RwLock::new(0usize));

        let (tx, rx) = channel();
        for _ in 0..TASKS {
            ex.spawn_ok(increment(Arc::clone(&mu), Arc::clone(&alt_mu), tx.clone()));
        }

        for _ in 0..TASKS {
            if let Err(e) = rx.recv_timeout(Duration::from_secs(10)) {
                panic!("Error while waiting for threads to complete: {}", e);
            }
        }

        assert_eq!(
            *block_on(mu.read_lock()) + *block_on(alt_mu.read_lock()),
            TASKS * ITERATIONS
        );
        assert_eq!(mu.raw.state.load(Ordering::Relaxed), 0);
        assert_eq!(alt_mu.raw.state.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn single_thread_async() {
        const TASKS: usize = 17;
        const ITERATIONS: usize = 103;

        // Async closures are unstable.
        async fn increment(mu: Rc<RwLock<usize>>) {
            for _ in 0..ITERATIONS {
                *mu.lock().await += 1;
            }
        }

        let mut ex = LocalPool::new();
        let spawner = ex.spawner();

        let mu = Rc::new(RwLock::new(0usize));
        for _ in 0..TASKS {
            spawner
                .spawn_local(increment(Rc::clone(&mu)))
                .expect("Failed to spawn task");
        }

        ex.run();

        assert_eq!(*block_on(mu.read_lock()), TASKS * ITERATIONS);
        assert_eq!(mu.raw.state.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn multi_thread_async() {
        const TASKS: usize = 17;
        const ITERATIONS: usize = 103;

        // Async closures are unstable.
        async fn increment(mu: Arc<RwLock<usize>>, tx: Sender<()>) {
            for _ in 0..ITERATIONS {
                *mu.lock().await += 1;
            }
            tx.send(()).expect("Failed to send completion signal");
        }

        let ex = ThreadPool::new().expect("Failed to create ThreadPool");

        let mu = Arc::new(RwLock::new(0usize));
        let (tx, rx) = channel();
        for _ in 0..TASKS {
            ex.spawn_ok(increment(Arc::clone(&mu), tx.clone()));
        }

        for _ in 0..TASKS {
            rx.recv_timeout(Duration::from_secs(5))
                .expect("Failed to receive completion signal");
        }
        assert_eq!(*block_on(mu.read_lock()), TASKS * ITERATIONS);
        assert_eq!(mu.raw.state.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn get_mut() {
        let mut mu = RwLock::new(NonCopy(13));
        *mu.get_mut() = NonCopy(17);

        assert_eq!(mu.into_inner(), NonCopy(17));
    }

    #[test]
    fn into_inner() {
        let mu = RwLock::new(NonCopy(29));
        assert_eq!(mu.into_inner(), NonCopy(29));
    }

    #[test]
    fn into_inner_drop() {
        struct NeedsDrop(Arc<AtomicUsize>);
        impl Drop for NeedsDrop {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::AcqRel);
            }
        }

        let value = Arc::new(AtomicUsize::new(0));
        let needs_drop = RwLock::new(NeedsDrop(value.clone()));
        assert_eq!(value.load(Ordering::Acquire), 0);

        {
            let inner = needs_drop.into_inner();
            assert_eq!(inner.0.load(Ordering::Acquire), 0);
        }

        assert_eq!(value.load(Ordering::Acquire), 1);
    }

    #[test]
    fn rw_arc() {
        const THREADS: isize = 7;
        const ITERATIONS: isize = 13;

        let mu = Arc::new(RwLock::new(0isize));
        let mu2 = mu.clone();

        let (tx, rx) = channel();
        thread::spawn(move || {
            let mut guard = block_on(mu2.lock());
            for _ in 0..ITERATIONS {
                let tmp = *guard;
                *guard = -1;
                thread::yield_now();
                *guard = tmp + 1;
            }
            tx.send(()).unwrap();
        });

        let mut readers = Vec::with_capacity(10);
        for _ in 0..THREADS {
            let mu3 = mu.clone();
            let handle = thread::spawn(move || {
                let guard = block_on(mu3.read_lock());
                assert!(*guard >= 0);
            });

            readers.push(handle);
        }

        // Wait for the readers to finish their checks.
        for r in readers {
            r.join().expect("One or more readers saw a negative value");
        }

        // Wait for the writer to finish.
        rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(*block_on(mu.read_lock()), ITERATIONS);
        assert_eq!(mu.raw.state.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn rw_single_thread_async() {
        // A Future that returns `Poll::pending` the first time it is polled and `Poll::Ready` every
        // time after that.
        struct TestFuture {
            polled: bool,
            waker: Arc<SpinLock<Option<Waker>>>,
        }

        impl Future for TestFuture {
            type Output = ();

            fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
                if self.polled {
                    Poll::Ready(())
                } else {
                    self.polled = true;
                    *self.waker.lock() = Some(cx.waker().clone());
                    Poll::Pending
                }
            }
        }

        fn wake_future(waker: Arc<SpinLock<Option<Waker>>>) {
            loop {
                if let Some(w) = waker.lock().take() {
                    w.wake();
                    return;
                }

                // This sleep cannot be moved into an else branch because we would end up holding
                // the lock while sleeping due to rust's drop ordering rules.
                thread::sleep(Duration::from_millis(10));
            }
        }

        async fn writer(mu: Rc<RwLock<isize>>) {
            let mut guard = mu.lock().await;
            for _ in 0..ITERATIONS {
                let tmp = *guard;
                *guard = -1;
                let waker = Arc::new(SpinLock::new(None));
                let waker2 = Arc::clone(&waker);
                thread::spawn(move || wake_future(waker2));
                let fut = TestFuture {
                    polled: false,
                    waker,
                };
                fut.await;
                *guard = tmp + 1;
            }
        }

        async fn reader(mu: Rc<RwLock<isize>>) {
            let guard = mu.read_lock().await;
            assert!(*guard >= 0);
        }

        const TASKS: isize = 7;
        const ITERATIONS: isize = 13;

        let mu = Rc::new(RwLock::new(0isize));
        let mut ex = LocalPool::new();
        let spawner = ex.spawner();

        spawner
            .spawn_local(writer(Rc::clone(&mu)))
            .expect("Failed to spawn writer");

        for _ in 0..TASKS {
            spawner
                .spawn_local(reader(Rc::clone(&mu)))
                .expect("Failed to spawn reader");
        }

        ex.run();

        assert_eq!(*block_on(mu.read_lock()), ITERATIONS);
        assert_eq!(mu.raw.state.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn rw_multi_thread_async() {
        async fn writer(mu: Arc<RwLock<isize>>, tx: Sender<()>) {
            let mut guard = mu.lock().await;
            for _ in 0..ITERATIONS {
                let tmp = *guard;
                *guard = -1;
                thread::yield_now();
                *guard = tmp + 1;
            }

            mem::drop(guard);
            tx.send(()).unwrap();
        }

        async fn reader(mu: Arc<RwLock<isize>>, tx: Sender<()>) {
            let guard = mu.read_lock().await;
            assert!(*guard >= 0);

            mem::drop(guard);
            tx.send(()).expect("Failed to send completion message");
        }

        const TASKS: isize = 7;
        const ITERATIONS: isize = 13;

        let mu = Arc::new(RwLock::new(0isize));
        let ex = ThreadPool::new().expect("Failed to create ThreadPool");

        let (txw, rxw) = channel();
        ex.spawn_ok(writer(Arc::clone(&mu), txw));

        let (txr, rxr) = channel();
        for _ in 0..TASKS {
            ex.spawn_ok(reader(Arc::clone(&mu), txr.clone()));
        }

        // Wait for the readers to finish their checks.
        for _ in 0..TASKS {
            rxr.recv_timeout(Duration::from_secs(5))
                .expect("Failed to receive completion message from reader");
        }

        // Wait for the writer to finish.
        rxw.recv_timeout(Duration::from_secs(5))
            .expect("Failed to receive completion message from writer");

        assert_eq!(*block_on(mu.read_lock()), ITERATIONS);
        assert_eq!(mu.raw.state.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn wake_all_readers() {
        async fn read(mu: Arc<RwLock<()>>) {
            let g = mu.read_lock().await;
            pending!();
            mem::drop(g);
        }

        async fn write(mu: Arc<RwLock<()>>) {
            mu.lock().await;
        }

        let mu = Arc::new(RwLock::new(()));
        let mut futures: [Pin<Box<dyn Future<Output = ()>>>; 5] = [
            Box::pin(read(mu.clone())),
            Box::pin(read(mu.clone())),
            Box::pin(read(mu.clone())),
            Box::pin(write(mu.clone())),
            Box::pin(read(mu.clone())),
        ];
        const NUM_READERS: usize = 4;

        let arc_waker = Arc::new(TestWaker);
        let waker = waker_ref(&arc_waker);
        let mut cx = Context::from_waker(&waker);

        // Acquire the lock so that the futures cannot get it.
        let g = block_on(mu.lock());

        for r in &mut futures {
            if let Poll::Ready(()) = r.as_mut().poll(&mut cx) {
                panic!("future unexpectedly ready");
            }
        }

        assert_eq!(
            mu.raw.state.load(Ordering::Relaxed) & HAS_WAITERS,
            HAS_WAITERS
        );

        assert_eq!(
            mu.raw.state.load(Ordering::Relaxed) & WRITER_WAITING,
            WRITER_WAITING
        );

        // Drop the lock. This should allow all readers to make progress. Since they already waited
        // once they should ignore the WRITER_WAITING bit that is currently set.
        mem::drop(g);
        for r in &mut futures {
            if let Poll::Ready(()) = r.as_mut().poll(&mut cx) {
                panic!("future unexpectedly ready");
            }
        }

        // Check that all readers were able to acquire the lock.
        assert_eq!(
            mu.raw.state.load(Ordering::Relaxed) & READ_MASK,
            READ_LOCK * NUM_READERS
        );
        assert_eq!(
            mu.raw.state.load(Ordering::Relaxed) & WRITER_WAITING,
            WRITER_WAITING
        );

        let mut needs_poll = None;

        // All the readers can now finish but the writer needs to be polled again.
        for (i, r) in futures.iter_mut().enumerate() {
            match r.as_mut().poll(&mut cx) {
                Poll::Ready(()) => {}
                Poll::Pending => {
                    if needs_poll.is_some() {
                        panic!("More than one future unable to complete");
                    }
                    needs_poll = Some(i);
                }
            }
        }

        if futures[needs_poll.expect("Writer unexpectedly able to complete")]
            .as_mut()
            .poll(&mut cx)
            .is_pending()
        {
            panic!("Writer unable to complete");
        }

        assert_eq!(mu.raw.state.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn long_wait() {
        async fn tight_loop(mu: Arc<RwLock<bool>>) {
            loop {
                let ready = mu.lock().await;
                if *ready {
                    break;
                }
                pending!();
            }
        }

        async fn mark_ready(mu: Arc<RwLock<bool>>) {
            *mu.lock().await = true;
        }

        let mu = Arc::new(RwLock::new(false));
        let mut tl = Box::pin(tight_loop(mu.clone()));
        let mut mark = Box::pin(mark_ready(mu.clone()));

        let arc_waker = Arc::new(TestWaker);
        let waker = waker_ref(&arc_waker);
        let mut cx = Context::from_waker(&waker);

        for _ in 0..=LONG_WAIT_THRESHOLD {
            if let Poll::Ready(()) = tl.as_mut().poll(&mut cx) {
                panic!("tight_loop unexpectedly ready");
            }

            if let Poll::Ready(()) = mark.as_mut().poll(&mut cx) {
                panic!("mark_ready unexpectedly ready");
            }
        }

        assert_eq!(
            mu.raw.state.load(Ordering::Relaxed),
            LOCKED | HAS_WAITERS | WRITER_WAITING | LONG_WAIT
        );

        // This time the tight loop will fail to acquire the lock.
        if let Poll::Ready(()) = tl.as_mut().poll(&mut cx) {
            panic!("tight_loop unexpectedly ready");
        }

        // Which will finally allow the mark_ready function to make progress.
        if mark.as_mut().poll(&mut cx).is_pending() {
            panic!("mark_ready not able to make progress");
        }

        // Now the tight loop will finish.
        if tl.as_mut().poll(&mut cx).is_pending() {
            panic!("tight_loop not able to finish");
        }

        assert!(*block_on(mu.lock()));
        assert_eq!(mu.raw.state.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn cancel_long_wait_before_wake() {
        async fn tight_loop(mu: Arc<RwLock<bool>>) {
            loop {
                let ready = mu.lock().await;
                if *ready {
                    break;
                }
                pending!();
            }
        }

        async fn mark_ready(mu: Arc<RwLock<bool>>) {
            *mu.lock().await = true;
        }

        let mu = Arc::new(RwLock::new(false));
        let mut tl = Box::pin(tight_loop(mu.clone()));
        let mut mark = Box::pin(mark_ready(mu.clone()));

        let arc_waker = Arc::new(TestWaker);
        let waker = waker_ref(&arc_waker);
        let mut cx = Context::from_waker(&waker);

        for _ in 0..=LONG_WAIT_THRESHOLD {
            if let Poll::Ready(()) = tl.as_mut().poll(&mut cx) {
                panic!("tight_loop unexpectedly ready");
            }

            if let Poll::Ready(()) = mark.as_mut().poll(&mut cx) {
                panic!("mark_ready unexpectedly ready");
            }
        }

        assert_eq!(
            mu.raw.state.load(Ordering::Relaxed),
            LOCKED | HAS_WAITERS | WRITER_WAITING | LONG_WAIT
        );

        // Now drop the mark_ready future, which should clear the LONG_WAIT bit.
        mem::drop(mark);
        assert_eq!(mu.raw.state.load(Ordering::Relaxed), LOCKED);

        mem::drop(tl);
        assert_eq!(mu.raw.state.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn cancel_long_wait_after_wake() {
        async fn tight_loop(mu: Arc<RwLock<bool>>) {
            loop {
                let ready = mu.lock().await;
                if *ready {
                    break;
                }
                pending!();
            }
        }

        async fn mark_ready(mu: Arc<RwLock<bool>>) {
            *mu.lock().await = true;
        }

        let mu = Arc::new(RwLock::new(false));
        let mut tl = Box::pin(tight_loop(mu.clone()));
        let mut mark = Box::pin(mark_ready(mu.clone()));

        let arc_waker = Arc::new(TestWaker);
        let waker = waker_ref(&arc_waker);
        let mut cx = Context::from_waker(&waker);

        for _ in 0..=LONG_WAIT_THRESHOLD {
            if let Poll::Ready(()) = tl.as_mut().poll(&mut cx) {
                panic!("tight_loop unexpectedly ready");
            }

            if let Poll::Ready(()) = mark.as_mut().poll(&mut cx) {
                panic!("mark_ready unexpectedly ready");
            }
        }

        assert_eq!(
            mu.raw.state.load(Ordering::Relaxed),
            LOCKED | HAS_WAITERS | WRITER_WAITING | LONG_WAIT
        );

        // This time the tight loop will fail to acquire the lock.
        if let Poll::Ready(()) = tl.as_mut().poll(&mut cx) {
            panic!("tight_loop unexpectedly ready");
        }

        // Now drop the mark_ready future, which should clear the LONG_WAIT bit.
        mem::drop(mark);
        assert_eq!(mu.raw.state.load(Ordering::Relaxed) & LONG_WAIT, 0);

        // Since the lock is not held, we should be able to spawn a future to set the ready flag.
        block_on(mark_ready(mu.clone()));

        // Now the tight loop will finish.
        if tl.as_mut().poll(&mut cx).is_pending() {
            panic!("tight_loop not able to finish");
        }

        assert_eq!(mu.raw.state.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn designated_waker() {
        async fn inc(mu: Arc<RwLock<usize>>) {
            *mu.lock().await += 1;
        }

        let mu = Arc::new(RwLock::new(0));

        let mut futures = [
            Box::pin(inc(mu.clone())),
            Box::pin(inc(mu.clone())),
            Box::pin(inc(mu.clone())),
        ];

        let arc_waker = Arc::new(TestWaker);
        let waker = waker_ref(&arc_waker);
        let mut cx = Context::from_waker(&waker);

        let count = block_on(mu.lock());

        // Poll 2 futures. Since neither will be able to acquire the lock, they should get added to
        // the waiter list.
        if let Poll::Ready(()) = futures[0].as_mut().poll(&mut cx) {
            panic!("future unexpectedly ready");
        }
        if let Poll::Ready(()) = futures[1].as_mut().poll(&mut cx) {
            panic!("future unexpectedly ready");
        }

        assert_eq!(
            mu.raw.state.load(Ordering::Relaxed),
            LOCKED | HAS_WAITERS | WRITER_WAITING,
        );

        // Now drop the lock. This should set the DESIGNATED_WAKER bit and wake up the first future
        // in the wait list.
        mem::drop(count);

        assert_eq!(
            mu.raw.state.load(Ordering::Relaxed),
            DESIGNATED_WAKER | HAS_WAITERS | WRITER_WAITING,
        );

        // Now poll the third future.  It should be able to acquire the lock immediately.
        if futures[2].as_mut().poll(&mut cx).is_pending() {
            panic!("future unable to complete");
        }
        assert_eq!(*block_on(mu.lock()), 1);

        // There should still be a waiter in the wait list and the DESIGNATED_WAKER bit should still
        // be set.
        assert_eq!(
            mu.raw.state.load(Ordering::Relaxed) & DESIGNATED_WAKER,
            DESIGNATED_WAKER
        );
        assert_eq!(
            mu.raw.state.load(Ordering::Relaxed) & HAS_WAITERS,
            HAS_WAITERS
        );

        // Now let the future that was woken up run.
        if futures[0].as_mut().poll(&mut cx).is_pending() {
            panic!("future unable to complete");
        }
        assert_eq!(*block_on(mu.lock()), 2);

        if futures[1].as_mut().poll(&mut cx).is_pending() {
            panic!("future unable to complete");
        }
        assert_eq!(*block_on(mu.lock()), 3);

        assert_eq!(mu.raw.state.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn cancel_designated_waker() {
        async fn inc(mu: Arc<RwLock<usize>>) {
            *mu.lock().await += 1;
        }

        let mu = Arc::new(RwLock::new(0));

        let mut fut = Box::pin(inc(mu.clone()));

        let arc_waker = Arc::new(TestWaker);
        let waker = waker_ref(&arc_waker);
        let mut cx = Context::from_waker(&waker);

        let count = block_on(mu.lock());

        if let Poll::Ready(()) = fut.as_mut().poll(&mut cx) {
            panic!("Future unexpectedly ready when lock is held");
        }

        // Drop the lock.  This will wake up the future.
        mem::drop(count);

        // Now drop the future without polling. This should clear all the state in the rwlock.
        mem::drop(fut);

        assert_eq!(mu.raw.state.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn cancel_before_wake() {
        async fn inc(mu: Arc<RwLock<usize>>) {
            *mu.lock().await += 1;
        }

        let mu = Arc::new(RwLock::new(0));

        let mut fut1 = Box::pin(inc(mu.clone()));

        let mut fut2 = Box::pin(inc(mu.clone()));

        let arc_waker = Arc::new(TestWaker);
        let waker = waker_ref(&arc_waker);
        let mut cx = Context::from_waker(&waker);

        // First acquire the lock.
        let count = block_on(mu.lock());

        // Now poll the futures. Since the lock is acquired they will both get queued in the waiter
        // list.
        match fut1.as_mut().poll(&mut cx) {
            Poll::Pending => {}
            Poll::Ready(()) => panic!("Future is unexpectedly ready"),
        }

        match fut2.as_mut().poll(&mut cx) {
            Poll::Pending => {}
            Poll::Ready(()) => panic!("Future is unexpectedly ready"),
        }

        assert_eq!(
            mu.raw.state.load(Ordering::Relaxed) & WRITER_WAITING,
            WRITER_WAITING
        );

        // Drop fut1.  This should remove it from the waiter list but shouldn't wake fut2.
        mem::drop(fut1);

        // There should be no designated waker.
        assert_eq!(mu.raw.state.load(Ordering::Relaxed) & DESIGNATED_WAKER, 0);

        // Since the waiter was a writer, we should clear the WRITER_WAITING bit.
        assert_eq!(mu.raw.state.load(Ordering::Relaxed) & WRITER_WAITING, 0);

        match fut2.as_mut().poll(&mut cx) {
            Poll::Pending => {}
            Poll::Ready(()) => panic!("Future is unexpectedly ready"),
        }

        // Now drop the lock.  This should mark fut2 as ready to make progress.
        mem::drop(count);

        match fut2.as_mut().poll(&mut cx) {
            Poll::Pending => panic!("Future is not ready to make progress"),
            Poll::Ready(()) => {}
        }

        // Verify that we only incremented the count once.
        assert_eq!(*block_on(mu.lock()), 1);
        assert_eq!(mu.raw.state.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn cancel_after_wake() {
        async fn inc(mu: Arc<RwLock<usize>>) {
            *mu.lock().await += 1;
        }

        let mu = Arc::new(RwLock::new(0));

        let mut fut1 = Box::pin(inc(mu.clone()));

        let mut fut2 = Box::pin(inc(mu.clone()));

        let arc_waker = Arc::new(TestWaker);
        let waker = waker_ref(&arc_waker);
        let mut cx = Context::from_waker(&waker);

        // First acquire the lock.
        let count = block_on(mu.lock());

        // Now poll the futures. Since the lock is acquired they will both get queued in the waiter
        // list.
        match fut1.as_mut().poll(&mut cx) {
            Poll::Pending => {}
            Poll::Ready(()) => panic!("Future is unexpectedly ready"),
        }

        match fut2.as_mut().poll(&mut cx) {
            Poll::Pending => {}
            Poll::Ready(()) => panic!("Future is unexpectedly ready"),
        }

        assert_eq!(
            mu.raw.state.load(Ordering::Relaxed) & WRITER_WAITING,
            WRITER_WAITING
        );

        // Drop the lock.  This should mark fut1 as ready to make progress.
        mem::drop(count);

        // Now drop fut1.  This should make fut2 ready to make progress.
        mem::drop(fut1);

        // Since there was still another waiter in the list we shouldn't have cleared the
        // DESIGNATED_WAKER bit.
        assert_eq!(
            mu.raw.state.load(Ordering::Relaxed) & DESIGNATED_WAKER,
            DESIGNATED_WAKER
        );

        // Since the waiter was a writer, we should clear the WRITER_WAITING bit.
        assert_eq!(mu.raw.state.load(Ordering::Relaxed) & WRITER_WAITING, 0);

        match fut2.as_mut().poll(&mut cx) {
            Poll::Pending => panic!("Future is not ready to make progress"),
            Poll::Ready(()) => {}
        }

        // Verify that we only incremented the count once.
        assert_eq!(*block_on(mu.lock()), 1);
        assert_eq!(mu.raw.state.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn timeout() {
        async fn timed_lock(timer: oneshot::Receiver<()>, mu: Arc<RwLock<()>>) {
            select! {
                res = timer.fuse() => {
                    match res {
                        Ok(()) => {},
                        Err(e) => panic!("Timer unexpectedly canceled: {}", e),
                    }
                }
                _ = mu.lock().fuse() => panic!("Successfuly acquired lock"),
            }
        }

        let mu = Arc::new(RwLock::new(()));
        let (tx, rx) = oneshot::channel();

        let mut timeout = Box::pin(timed_lock(rx, mu.clone()));

        let arc_waker = Arc::new(TestWaker);
        let waker = waker_ref(&arc_waker);
        let mut cx = Context::from_waker(&waker);

        // Acquire the lock.
        let g = block_on(mu.lock());

        // Poll the future.
        if let Poll::Ready(()) = timeout.as_mut().poll(&mut cx) {
            panic!("timed_lock unexpectedly ready");
        }

        assert_eq!(
            mu.raw.state.load(Ordering::Relaxed) & HAS_WAITERS,
            HAS_WAITERS
        );

        // Signal the channel, which should cancel the lock.
        tx.send(()).expect("Failed to send wakeup");

        // Now the future should have completed without acquiring the lock.
        if timeout.as_mut().poll(&mut cx).is_pending() {
            panic!("timed_lock not ready after timeout");
        }

        // The rwlock state should not show any waiters.
        assert_eq!(mu.raw.state.load(Ordering::Relaxed) & HAS_WAITERS, 0);

        mem::drop(g);

        assert_eq!(mu.raw.state.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn writer_waiting() {
        async fn read_zero(mu: Arc<RwLock<usize>>) {
            let val = mu.read_lock().await;
            pending!();

            assert_eq!(*val, 0);
        }

        async fn inc(mu: Arc<RwLock<usize>>) {
            *mu.lock().await += 1;
        }

        async fn read_one(mu: Arc<RwLock<usize>>) {
            let val = mu.read_lock().await;

            assert_eq!(*val, 1);
        }

        let mu = Arc::new(RwLock::new(0));

        let mut r1 = Box::pin(read_zero(mu.clone()));
        let mut r2 = Box::pin(read_zero(mu.clone()));

        let mut w = Box::pin(inc(mu.clone()));
        let mut r3 = Box::pin(read_one(mu.clone()));

        let arc_waker = Arc::new(TestWaker);
        let waker = waker_ref(&arc_waker);
        let mut cx = Context::from_waker(&waker);

        if let Poll::Ready(()) = r1.as_mut().poll(&mut cx) {
            panic!("read_zero unexpectedly ready");
        }
        if let Poll::Ready(()) = r2.as_mut().poll(&mut cx) {
            panic!("read_zero unexpectedly ready");
        }
        assert_eq!(
            mu.raw.state.load(Ordering::Relaxed) & READ_MASK,
            2 * READ_LOCK
        );

        if let Poll::Ready(()) = w.as_mut().poll(&mut cx) {
            panic!("inc unexpectedly ready");
        }
        assert_eq!(
            mu.raw.state.load(Ordering::Relaxed) & WRITER_WAITING,
            WRITER_WAITING
        );

        // The WRITER_WAITING bit should prevent the next reader from acquiring the lock.
        if let Poll::Ready(()) = r3.as_mut().poll(&mut cx) {
            panic!("read_one unexpectedly ready");
        }
        assert_eq!(
            mu.raw.state.load(Ordering::Relaxed) & READ_MASK,
            2 * READ_LOCK
        );

        if r1.as_mut().poll(&mut cx).is_pending() {
            panic!("read_zero unable to complete");
        }
        if r2.as_mut().poll(&mut cx).is_pending() {
            panic!("read_zero unable to complete");
        }
        if w.as_mut().poll(&mut cx).is_pending() {
            panic!("inc unable to complete");
        }
        if r3.as_mut().poll(&mut cx).is_pending() {
            panic!("read_one unable to complete");
        }

        assert_eq!(mu.raw.state.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn notify_one() {
        async fn read(mu: Arc<RwLock<usize>>, cv: Arc<Condvar>) {
            let mut count = mu.read_lock().await;
            while *count == 0 {
                count = cv.wait_read(count).await;
            }
        }

        async fn write(mu: Arc<RwLock<usize>>, cv: Arc<Condvar>) {
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

        let mut readers = [
            Box::pin(read(mu.clone(), cv.clone())),
            Box::pin(read(mu.clone(), cv.clone())),
            Box::pin(read(mu.clone(), cv.clone())),
            Box::pin(read(mu.clone(), cv.clone())),
        ];
        let mut writer = Box::pin(write(mu.clone(), cv.clone()));

        for r in &mut readers {
            if let Poll::Ready(()) = r.as_mut().poll(&mut cx) {
                panic!("reader unexpectedly ready");
            }
        }
        if let Poll::Ready(()) = writer.as_mut().poll(&mut cx) {
            panic!("writer unexpectedly ready");
        }

        let mut count = block_on(mu.lock());
        *count = 1;

        // This should wake all readers + one writer.
        cv.notify_one();

        // Poll the readers and the writer so they add themselves to the rwlock's waiter list.
        for r in &mut readers {
            if r.as_mut().poll(&mut cx).is_ready() {
                panic!("reader unexpectedly ready");
            }
        }

        if writer.as_mut().poll(&mut cx).is_ready() {
            panic!("writer unexpectedly ready");
        }

        assert_eq!(
            mu.raw.state.load(Ordering::Relaxed) & HAS_WAITERS,
            HAS_WAITERS
        );
        assert_eq!(
            mu.raw.state.load(Ordering::Relaxed) & WRITER_WAITING,
            WRITER_WAITING
        );

        mem::drop(count);

        assert_eq!(
            mu.raw.state.load(Ordering::Relaxed) & (HAS_WAITERS | WRITER_WAITING),
            HAS_WAITERS | WRITER_WAITING
        );

        for r in &mut readers {
            if r.as_mut().poll(&mut cx).is_pending() {
                panic!("reader unable to complete");
            }
        }

        if writer.as_mut().poll(&mut cx).is_pending() {
            panic!("writer unable to complete");
        }

        assert_eq!(*block_on(mu.read_lock()), 0);
    }

    #[test]
    fn notify_when_unlocked() {
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

        let mut futures = [
            Box::pin(dec(mu.clone(), cv.clone())),
            Box::pin(dec(mu.clone(), cv.clone())),
            Box::pin(dec(mu.clone(), cv.clone())),
            Box::pin(dec(mu.clone(), cv.clone())),
        ];

        for f in &mut futures {
            if let Poll::Ready(()) = f.as_mut().poll(&mut cx) {
                panic!("future unexpectedly ready");
            }
        }

        *block_on(mu.lock()) = futures.len();
        cv.notify_all();

        // Since we haven't polled `futures` yet, the rwlock should not have any waiters.
        assert_eq!(mu.raw.state.load(Ordering::Relaxed) & HAS_WAITERS, 0);

        for f in &mut futures {
            if f.as_mut().poll(&mut cx).is_pending() {
                panic!("future unexpectedly ready");
            }
        }
        assert_eq!(mu.raw.state.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn notify_reader_writer() {
        async fn read(mu: Arc<RwLock<usize>>, cv: Arc<Condvar>) {
            let mut count = mu.read_lock().await;
            while *count == 0 {
                count = cv.wait_read(count).await;
            }

            // Yield once while holding the read lock, which should prevent the writer from waking
            // up.
            pending!();
        }

        async fn write(mu: Arc<RwLock<usize>>, cv: Arc<Condvar>) {
            let mut count = mu.lock().await;
            while *count == 0 {
                count = cv.wait(count).await;
            }

            *count -= 1;
        }

        async fn lock(mu: Arc<RwLock<usize>>) {
            mem::drop(mu.lock().await);
        }

        let mu = Arc::new(RwLock::new(0));
        let cv = Arc::new(Condvar::new());

        let arc_waker = Arc::new(TestWaker);
        let waker = waker_ref(&arc_waker);
        let mut cx = Context::from_waker(&waker);

        let mut futures: [Pin<Box<dyn Future<Output = ()>>>; 5] = [
            Box::pin(read(mu.clone(), cv.clone())),
            Box::pin(read(mu.clone(), cv.clone())),
            Box::pin(read(mu.clone(), cv.clone())),
            Box::pin(write(mu.clone(), cv.clone())),
            Box::pin(read(mu.clone(), cv.clone())),
        ];
        const NUM_READERS: usize = 4;

        let mut l = Box::pin(lock(mu.clone()));

        for f in &mut futures {
            if let Poll::Ready(()) = f.as_mut().poll(&mut cx) {
                panic!("future unexpectedly ready");
            }
        }

        assert_eq!(mu.raw.state.load(Ordering::Relaxed), 0);

        let mut count = block_on(mu.lock());
        *count = 1;

        // Now poll the lock function. Since the lock is held by us, it will get queued on the
        // waiter list.
        if let Poll::Ready(()) = l.as_mut().poll(&mut cx) {
            panic!("lock() unexpectedly ready");
        }

        assert_eq!(
            mu.raw.state.load(Ordering::Relaxed) & (HAS_WAITERS | WRITER_WAITING),
            HAS_WAITERS | WRITER_WAITING
        );

        // Wake up waiters while holding the lock.
        cv.notify_all();

        // Drop the lock.  This should wake up the lock function.
        mem::drop(count);

        if l.as_mut().poll(&mut cx).is_pending() {
            panic!("lock() unable to complete");
        }

        // Since we haven't polled `futures` yet, the rwlock state should now be empty.
        assert_eq!(mu.raw.state.load(Ordering::Relaxed), 0);

        // Poll everything again. The readers should be able to make progress (but not complete) but
        // the writer should be blocked.
        for f in &mut futures {
            if let Poll::Ready(()) = f.as_mut().poll(&mut cx) {
                panic!("future unexpectedly ready");
            }
        }

        assert_eq!(
            mu.raw.state.load(Ordering::Relaxed) & READ_MASK,
            READ_LOCK * NUM_READERS
        );

        // All the readers can now finish but the writer needs to be polled again.
        let mut needs_poll = None;
        for (i, r) in futures.iter_mut().enumerate() {
            match r.as_mut().poll(&mut cx) {
                Poll::Ready(()) => {}
                Poll::Pending => {
                    if needs_poll.is_some() {
                        panic!("More than one future unable to complete");
                    }
                    needs_poll = Some(i);
                }
            }
        }

        if futures[needs_poll.expect("Writer unexpectedly able to complete")]
            .as_mut()
            .poll(&mut cx)
            .is_pending()
        {
            panic!("Writer unable to complete");
        }

        assert_eq!(*block_on(mu.lock()), 0);
        assert_eq!(mu.raw.state.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn notify_readers_with_read_lock() {
        async fn read(mu: Arc<RwLock<usize>>, cv: Arc<Condvar>) {
            let mut count = mu.read_lock().await;
            while *count == 0 {
                count = cv.wait_read(count).await;
            }

            // Yield once while holding the read lock.
            pending!();
        }

        let mu = Arc::new(RwLock::new(0));
        let cv = Arc::new(Condvar::new());

        let arc_waker = Arc::new(TestWaker);
        let waker = waker_ref(&arc_waker);
        let mut cx = Context::from_waker(&waker);

        let mut futures = [
            Box::pin(read(mu.clone(), cv.clone())),
            Box::pin(read(mu.clone(), cv.clone())),
            Box::pin(read(mu.clone(), cv.clone())),
            Box::pin(read(mu.clone(), cv.clone())),
        ];

        for f in &mut futures {
            if let Poll::Ready(()) = f.as_mut().poll(&mut cx) {
                panic!("future unexpectedly ready");
            }
        }

        // Increment the count and then grab a read lock.
        *block_on(mu.lock()) = 1;

        let g = block_on(mu.read_lock());

        // Notify the condvar while holding the read lock. This should wake up all the waiters.
        cv.notify_all();

        // Since the lock is held in shared mode, all the readers should immediately be able to
        // acquire the read lock.
        for f in &mut futures {
            if let Poll::Ready(()) = f.as_mut().poll(&mut cx) {
                panic!("future unexpectedly ready");
            }
        }
        assert_eq!(mu.raw.state.load(Ordering::Relaxed) & HAS_WAITERS, 0);
        assert_eq!(
            mu.raw.state.load(Ordering::Relaxed) & READ_MASK,
            READ_LOCK * (futures.len() + 1)
        );

        mem::drop(g);

        for f in &mut futures {
            if f.as_mut().poll(&mut cx).is_pending() {
                panic!("future unable to complete");
            }
        }

        assert_eq!(mu.raw.state.load(Ordering::Relaxed), 0);
    }
}
