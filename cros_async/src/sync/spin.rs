// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::UnsafeCell;
use std::hint;
use std::ops::Deref;
use std::ops::DerefMut;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

const UNLOCKED: bool = false;
const LOCKED: bool = true;

/// A primitive that provides safe, mutable access to a shared resource.
///
/// Unlike `Mutex`, a `SpinLock` will not voluntarily yield its CPU time until the resource is
/// available and will instead keep spinning until the resource is acquired. For the vast majority
/// of cases, `Mutex` is a better choice than `SpinLock`. If a `SpinLock` must be used then users
/// should try to do as little work as possible while holding the `SpinLock` and avoid any sort of
/// blocking at all costs as it can severely penalize performance.
///
/// # Poisoning
///
/// This `SpinLock` does not implement lock poisoning so it is possible for threads to access
/// poisoned data if a thread panics while holding the lock. If lock poisoning is needed, it can be
/// implemented by wrapping the `SpinLock` in a new type that implements poisoning. See the
/// implementation of `std::sync::Mutex` for an example of how to do this.
#[repr(align(128))]
pub struct SpinLock<T: ?Sized> {
    lock: AtomicBool,
    value: UnsafeCell<T>,
}

impl<T> SpinLock<T> {
    /// Creates a new, unlocked `SpinLock` that's ready for use.
    pub fn new(value: T) -> SpinLock<T> {
        SpinLock {
            lock: AtomicBool::new(UNLOCKED),
            value: UnsafeCell::new(value),
        }
    }

    /// Consumes the `SpinLock` and returns the value guarded by it. This method doesn't perform any
    /// locking as the compiler guarantees that there are no references to `self`.
    pub fn into_inner(self) -> T {
        // No need to take the lock because the compiler can statically guarantee
        // that there are no references to the SpinLock.
        self.value.into_inner()
    }
}

impl<T: ?Sized> SpinLock<T> {
    /// Acquires exclusive, mutable access to the resource protected by the `SpinLock`, blocking the
    /// current thread until it is able to do so. Upon returning, the current thread will be the
    /// only thread with access to the resource. The `SpinLock` will be released when the returned
    /// `SpinLockGuard` is dropped. Attempting to call `lock` while already holding the `SpinLock`
    /// will cause a deadlock.
    pub fn lock(&self) -> SpinLockGuard<T> {
        loop {
            let state = self.lock.load(Ordering::Relaxed);
            if state == UNLOCKED
                && self
                    .lock
                    .compare_exchange_weak(UNLOCKED, LOCKED, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
            {
                break;
            }
            hint::spin_loop();
        }

        // TODO(b/315998194): Add safety comment
        #[allow(clippy::undocumented_unsafe_blocks)]
        SpinLockGuard {
            lock: self,
            value: unsafe { &mut *self.value.get() },
        }
    }

    fn unlock(&self) {
        // Don't need to compare and swap because we exclusively hold the lock.
        self.lock.store(UNLOCKED, Ordering::Release);
    }

    /// Returns a mutable reference to the contained value. This method doesn't perform any locking
    /// as the compiler will statically guarantee that there are no other references to `self`.
    pub fn get_mut(&mut self) -> &mut T {
        // SAFETY:
        // Safe because the compiler can statically guarantee that there are no other references to
        // `self`. This is also why we don't need to acquire the lock.
        unsafe { &mut *self.value.get() }
    }
}

// TODO(b/315998194): Add safety comment
#[allow(clippy::undocumented_unsafe_blocks)]
unsafe impl<T: ?Sized + Send> Send for SpinLock<T> {}
// TODO(b/315998194): Add safety comment
#[allow(clippy::undocumented_unsafe_blocks)]
unsafe impl<T: ?Sized + Send> Sync for SpinLock<T> {}

impl<T: ?Sized + Default> Default for SpinLock<T> {
    fn default() -> Self {
        Self::new(Default::default())
    }
}

impl<T> From<T> for SpinLock<T> {
    fn from(source: T) -> Self {
        Self::new(source)
    }
}

/// An RAII implementation of a "scoped lock" for a `SpinLock`. When this structure is dropped, the
/// lock will be released. The resource protected by the `SpinLock` can be accessed via the `Deref`
/// and `DerefMut` implementations of this structure.
pub struct SpinLockGuard<'a, T: 'a + ?Sized> {
    lock: &'a SpinLock<T>,
    value: &'a mut T,
}

impl<'a, T: ?Sized> Deref for SpinLockGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.value
    }
}

impl<'a, T: ?Sized> DerefMut for SpinLockGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.value
    }
}

impl<'a, T: ?Sized> Drop for SpinLockGuard<'a, T> {
    fn drop(&mut self) {
        self.lock.unlock();
    }
}

#[cfg(test)]
mod test {
    use std::mem;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::thread;

    use super::*;

    #[derive(PartialEq, Eq, Debug)]
    struct NonCopy(u32);

    #[test]
    fn it_works() {
        let sl = SpinLock::new(NonCopy(13));

        assert_eq!(*sl.lock(), NonCopy(13));
    }

    #[test]
    fn smoke() {
        let sl = SpinLock::new(NonCopy(7));

        mem::drop(sl.lock());
        mem::drop(sl.lock());
    }

    #[test]
    fn send() {
        let sl = SpinLock::new(NonCopy(19));

        thread::spawn(move || {
            let value = sl.lock();
            assert_eq!(*value, NonCopy(19));
        })
        .join()
        .unwrap();
    }

    #[test]
    fn high_contention() {
        const THREADS: usize = 23;
        const ITERATIONS: usize = 101;

        let mut threads = Vec::with_capacity(THREADS);

        let sl = Arc::new(SpinLock::new(0usize));
        for _ in 0..THREADS {
            let sl2 = sl.clone();
            threads.push(thread::spawn(move || {
                for _ in 0..ITERATIONS {
                    *sl2.lock() += 1;
                }
            }));
        }

        for t in threads.into_iter() {
            t.join().unwrap();
        }

        assert_eq!(*sl.lock(), THREADS * ITERATIONS);
    }

    #[test]
    fn get_mut() {
        let mut sl = SpinLock::new(NonCopy(13));
        *sl.get_mut() = NonCopy(17);

        assert_eq!(sl.into_inner(), NonCopy(17));
    }

    #[test]
    fn into_inner() {
        let sl = SpinLock::new(NonCopy(29));
        assert_eq!(sl.into_inner(), NonCopy(29));
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
        let needs_drop = SpinLock::new(NeedsDrop(value.clone()));
        assert_eq!(value.load(Ordering::Acquire), 0);

        {
            let inner = needs_drop.into_inner();
            assert_eq!(inner.0.load(Ordering::Acquire), 0);
        }

        assert_eq!(value.load(Ordering::Acquire), 1);
    }

    #[test]
    fn arc_nested() {
        // Tests nested sltexes and access to underlying data.
        let sl = SpinLock::new(1);
        let arc = Arc::new(SpinLock::new(sl));
        thread::spawn(move || {
            let nested = arc.lock();
            let lock2 = nested.lock();
            assert_eq!(*lock2, 1);
        })
        .join()
        .unwrap();
    }

    #[test]
    fn arc_access_in_unwind() {
        let arc = Arc::new(SpinLock::new(1));
        let arc2 = arc.clone();
        thread::spawn(move || {
            struct Unwinder {
                i: Arc<SpinLock<i32>>,
            }
            impl Drop for Unwinder {
                fn drop(&mut self) {
                    *self.i.lock() += 1;
                }
            }
            let _u = Unwinder { i: arc2 };
            panic!();
        })
        .join()
        .expect_err("thread did not panic");
        let lock = arc.lock();
        assert_eq!(*lock, 2);
    }

    #[test]
    fn unsized_value() {
        let sltex: &SpinLock<[i32]> = &SpinLock::new([1, 2, 3]);
        {
            let b = &mut *sltex.lock();
            b[0] = 4;
            b[2] = 5;
        }
        let expected: &[i32] = &[4, 2, 5];
        assert_eq!(&*sltex.lock(), expected);
    }
}
