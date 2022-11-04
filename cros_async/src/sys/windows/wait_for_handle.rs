// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::c_void;
use std::future::Future;
use std::marker::PhantomData;
use std::marker::PhantomPinned;
use std::pin::Pin;
use std::ptr::null_mut;
use std::sync::MutexGuard;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;

use base::error;
use base::warn;
use base::AsRawDescriptor;
use base::Descriptor;
use sync::Mutex;
use winapi::shared::ntdef::FALSE;
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::threadpoollegacyapiset::UnregisterWaitEx;
use winapi::um::winbase::RegisterWaitForSingleObject;
use winapi::um::winbase::INFINITE;
use winapi::um::winnt::BOOLEAN;
use winapi::um::winnt::PVOID;
use winapi::um::winnt::WT_EXECUTEONLYONCE;

use crate::sys::windows::handle_source::Error;
use crate::sys::windows::handle_source::Result;

/// Inner state shared between the future struct & the kernel invoked waiter callback.
struct WaitForHandleInner {
    wait_state: WaitState,
    wait_object: Descriptor,
    waker: Option<Waker>,
}
impl WaitForHandleInner {
    fn new() -> WaitForHandleInner {
        WaitForHandleInner {
            wait_state: WaitState::New,
            wait_object: Descriptor(null_mut::<c_void>()),
            waker: None,
        }
    }
}

/// Future's state.
#[derive(Clone, Copy, PartialEq, Eq)]
enum WaitState {
    New,
    Sleeping,
    Woken,
    Aborted,
    Finished,
    Failed,
}

/// Waits for an object with a handle to be readable.
pub struct WaitForHandle<'a, T: AsRawDescriptor> {
    handle: Descriptor,
    inner: Mutex<WaitForHandleInner>,
    _marker: PhantomData<&'a T>,
    _pinned_marker: PhantomPinned,
}

impl<'a, T> WaitForHandle<'a, T>
where
    T: AsRawDescriptor,
{
    pub fn new(source: &'a T) -> WaitForHandle<'a, T> {
        WaitForHandle {
            handle: Descriptor(source.as_raw_descriptor()),
            inner: Mutex::new(WaitForHandleInner::new()),
            _marker: PhantomData,
            _pinned_marker: PhantomPinned,
        }
    }
}

impl<'a, T> Future for WaitForHandle<'a, T>
where
    T: AsRawDescriptor,
{
    type Output = Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let inner_for_callback = &self.inner as *const _ as *mut Mutex<WaitForHandleInner>;
        let mut inner = self.inner.lock();
        match inner.wait_state {
            WaitState::New => {
                // Safe because:
                //      a) the callback only runs when WaitForHandle is alive (we cancel it on
                //         drop).
                //      b) inner & its children are owned by WaitForHandle.
                let err = unsafe {
                    RegisterWaitForSingleObject(
                        &mut inner.wait_object as *mut _ as *mut *mut c_void,
                        self.handle.0,
                        Some(wait_for_handle_waker),
                        inner_for_callback as *mut c_void,
                        INFINITE,
                        WT_EXECUTEONLYONCE,
                    )
                };
                if err == 0 {
                    return Poll::Ready(Err(Error::HandleWaitFailed(base::Error::last())));
                }

                inner.wait_state = WaitState::Sleeping;
                inner.waker = Some(cx.waker().clone());
                Poll::Pending
            }
            WaitState::Sleeping => {
                // In case we are polled with a different waker which won't be woken by the existing
                // waker, we'll have to update to the new waker.
                if inner
                    .waker
                    .as_ref()
                    .map(|w| !w.will_wake(cx.waker()))
                    .unwrap_or(true)
                {
                    inner.waker = Some(cx.waker().clone());
                }
                Poll::Pending
            }
            WaitState::Woken => {
                inner.wait_state = WaitState::Finished;

                // Safe because:
                // a) we know a wait was registered and hasn't been unregistered yet.
                // b) the callback is not queued because we set WT_EXECUTEONLYONCE, and we know
                //    it has already completed.
                unsafe { unregister_wait(inner.wait_object) }

                Poll::Ready(Ok(()))
            }
            WaitState::Aborted => Poll::Ready(Err(Error::OperationAborted)),
            WaitState::Finished => panic!("polled an already completed WaitForHandle future."),
            WaitState::Failed => {
                panic!("WaitForHandle future's waiter callback hit unexpected behavior.")
            }
        }
    }
}

impl<'a, T> Drop for WaitForHandle<'a, T>
where
    T: AsRawDescriptor,
{
    fn drop(&mut self) {
        // We cannot hold the lock over the call to unregister_wait, otherwise we could deadlock
        // with the callback trying to access the same data. It is sufficient to just verify
        // (without mutual exclusion beyond the data access itself) that we have exited the New
        // state before attempting to unregister. This works because once we have exited New, we
        // cannot ever re-enter that state, and we know for sure that inner.wait_object is a valid
        // wait object.
        let (current_state, wait_object) = {
            let inner = self.inner.lock();
            (inner.wait_state, inner.wait_object)
        };

        // Safe because self.descriptor is valid in any state except New or Finished.
        //
        // Note: this method call is critical for supplying the safety guarantee relied upon by
        // wait_for_handle_waker. Upon return, it ensures that wait_for_handle_waker is not running
        // and won't be scheduled again, which makes it safe to drop self.inner_for_callback
        // (wait_for_handle_waker has a non owning pointer to self.inner_for_callback).
        if current_state != WaitState::New && current_state != WaitState::Finished {
            unsafe { unregister_wait(wait_object) }
        }
    }
}

/// Safe portion of the RegisterWaitForSingleObject callback.
fn process_wait_state_change(
    mut state: MutexGuard<WaitForHandleInner>,
    wait_fired: bool,
) -> Option<Waker> {
    let mut waker = None;
    state.wait_state = match state.wait_state {
        WaitState::Sleeping => {
            let new_state = if wait_fired {
                WaitState::Woken
            } else {
                // This should never happen.
                error!("wait_for_handle_waker did not wake due to wait firing.");
                WaitState::Aborted
            };

            match state.waker.take() {
                Some(w) => {
                    waker = Some(w);
                    new_state
                }
                None => {
                    error!("wait_for_handler_waker called, but no waker available.");
                    WaitState::Failed
                }
            }
        }
        _ => {
            error!("wait_for_handle_waker called with state != sleeping.");
            WaitState::Failed
        }
    };
    waker
}

/// # Safety
/// a) inner_ptr is valid whenever this function can be called. This is guaranteed by WaitForHandle,
///    which cannot be dropped until this function has finished running & is no longer queued for
///    execution because the Drop impl calls UnregisterWaitEx, which blocks on that condition.
unsafe extern "system" fn wait_for_handle_waker(inner_ptr: PVOID, timer_or_wait_fired: BOOLEAN) {
    let inner = inner_ptr as *const Mutex<WaitForHandleInner>;
    let inner_locked = (*inner).lock();
    let waker = process_wait_state_change(
        inner_locked,
        /* wait_fired= */ timer_or_wait_fired == FALSE,
    );

    // We wake *after* releasing the lock to avoid waking up a thread that then will go back to
    // sleep because the lock it needs is currently held.
    if let Some(w) = waker {
        w.wake()
    }
}

/// # Safety
/// a) desc must be a valid wait handle from RegisterWaitForSingleObject.
unsafe fn unregister_wait(desc: Descriptor) {
    if UnregisterWaitEx(desc.0, INVALID_HANDLE_VALUE) == 0 {
        warn!(
            "WaitForHandle: failed to clean up RegisterWaitForSingleObject wait handle: {}",
            base::Error::last()
        )
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::Weak;
    use std::time::Duration;

    use base::thread::spawn_with_timeout;
    use base::Event;
    use futures::pin_mut;

    use super::*;
    use crate::waker::new_waker;
    use crate::waker::WeakWake;
    use crate::EventAsync;
    use crate::Executor;

    struct FakeWaker {}
    impl WeakWake for FakeWaker {
        fn wake_by_ref(_weak_self: &Weak<Self>) {
            // Do nothing.
        }
    }

    #[test]
    fn test_unsignaled_event() {
        async fn wait_on_unsignaled_event(evt: EventAsync) {
            evt.next_val().await.unwrap();
            panic!("await should never terminate");
        }

        let fake_waker = Arc::new(FakeWaker {});
        let waker = new_waker(Arc::downgrade(&fake_waker));
        let mut cx = Context::from_waker(&waker);

        let ex = Executor::new().unwrap();
        let evt = Event::new().unwrap();
        let async_evt = EventAsync::new(evt, &ex).unwrap();

        let fut = wait_on_unsignaled_event(async_evt);
        pin_mut!(fut);

        // Assert we make it to the pending state. This means we've registered a wait.
        assert_eq!(fut.poll(&mut cx), Poll::Pending);

        // If this test doesn't crash trying to drop the future, it is considered successful.
    }

    #[test]
    fn test_signaled_event() {
        let join_handle = spawn_with_timeout(|| {
            async fn wait_on_signaled_event(evt: EventAsync) {
                evt.next_val().await.unwrap();
            }

            let ex = Executor::new().unwrap();
            let evt = Event::new().unwrap();
            evt.signal().unwrap();
            let async_evt = EventAsync::new(evt, &ex).unwrap();

            let fut = wait_on_signaled_event(async_evt);
            pin_mut!(fut);

            ex.run_until(fut).unwrap();
        });
        join_handle
            .try_join(Duration::from_secs(5))
            .expect("async wait never returned from signaled event.");
    }
}
