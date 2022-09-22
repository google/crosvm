// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::marker::PhantomData;
use std::mem;
use std::ptr::null_mut;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread::Builder as ThreadBuilder;
use std::thread::JoinHandle;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use base::error;
use base::info;
use base::warn;
use base::Event;
use base::Tube;
use euclid::size2;
use sync::Mutex;
#[cfg(feature = "kiwi")]
use vm_control::ServiceSendToGpu;
use win_util::win32_string;
use winapi::shared::minwindef::LPARAM;
use winapi::shared::minwindef::LRESULT;
use winapi::shared::minwindef::UINT;
use winapi::shared::minwindef::WPARAM;
use winapi::shared::windef::HWND;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::processthreadsapi::GetCurrentThreadId;
use winapi::um::winuser::*;

#[cfg(feature = "kiwi")]
use super::message_relay_thread::MessageRelayThread;
use super::message_relay_thread::MessageRelayThreadTrait;
use super::thread_message_util;
use super::window::MessagePacket;
use super::window::Window;
use super::window_message_dispatcher::WindowMessageDispatcher;
use super::window_message_dispatcher::DISPATCHER_PROPERTY_NAME;
use super::window_message_processor::*;

// The default app icon id, which is defined in crosvm-manifest.rc.
const APP_ICON_ID: u16 = 1;

// 0 is not a valid thread ID: https://devblogs.microsoft.com/oldnewthing/20040223-00/?p=40503
const INVALID_THREAD_ID: u32 = 0;

#[derive(Debug)]
enum MessageLoopState {
    /// The initial state.
    NotStarted = 0,
    /// The loop is running normally.
    Running,
    /// The loop has ended normally.
    ExitedNormally,
    /// The loop never started because errors occurred.
    EarlyTerminatedWithError,
    /// The loop has ended because errors occurred.
    ExitedWithError,
}

/// This class runs the WndProc thread, and provides helper functions for other threads to
/// communicate with it.
pub struct WindowProcedureThread<T: HandleWindowMessage> {
    thread: Option<JoinHandle<()>>,
    thread_id: u32,
    message_loop_state: Option<Arc<AtomicI32>>,
    thread_terminated_event: Event,
    _marker: PhantomData<T>,
}

impl<T: HandleWindowMessage> WindowProcedureThread<T> {
    pub fn start_thread(vm_tube: Option<Arc<Mutex<Tube>>>) -> Result<Self> {
        let thread_id = Arc::new(AtomicU32::new(INVALID_THREAD_ID));
        let message_loop_state = Arc::new(AtomicI32::new(MessageLoopState::NotStarted as i32));
        let thread_terminated_event = Event::new().unwrap();

        let thread_id_clone = Arc::clone(&thread_id);
        let message_loop_state_clone = Arc::clone(&message_loop_state);
        let thread_terminated_event_clone = thread_terminated_event
            .try_clone()
            .map_err(|e| anyhow!("Failed to clone thread_terminated_event: {}", e))?;

        match ThreadBuilder::new()
            .name("gpu_display_wndproc".into())
            .spawn(move || {
                // Safe because GetCurrentThreadId has no failure mode.
                let thread_id = unsafe { GetCurrentThreadId() };

                // Must be called before any other threads post messages to the WndProc thread.
                thread_message_util::force_create_message_queue();
                thread_id_clone.store(thread_id, Ordering::SeqCst);
                drop(thread_id_clone);

                // Safe because the message queue has been created, and the returned thread will go
                // out of scope and get dropped before the WndProc thread exits.
                let _message_relay_thread = unsafe {
                    vm_tube.and_then(|tube| Self::start_message_relay_thread(tube, thread_id))
                };

                Self::run_message_loop(message_loop_state_clone);

                if let Err(e) = thread_terminated_event_clone.write(1) {
                    error!("Failed to write to thread terminated event: {}", e);
                }
            }) {
            Ok(thread) => {
                // TODO(b/243184256): Use `Condvar` to avoid busy-waiting on the atomic variable.
                while message_loop_state.load(Ordering::SeqCst)
                    == MessageLoopState::NotStarted as i32
                {}

                let thread_id = Arc::try_unwrap(thread_id).unwrap().into_inner();
                if thread_id == INVALID_THREAD_ID {
                    bail!("Failed to retrieve thread ID when spawning WndProc thread!");
                }
                Ok(Self {
                    thread: Some(thread),
                    thread_id,
                    message_loop_state: Some(message_loop_state),
                    thread_terminated_event,
                    _marker: PhantomData,
                })
            }
            Err(e) => bail!("Failed to spawn WndProc thread: {:?}", e),
        }
    }

    pub fn try_clone_thread_terminated_event(&self) -> Result<Event> {
        self.thread_terminated_event
            .try_clone()
            .map_err(|e| anyhow!("Failed to clone thread_terminated_event: {}", e))
    }

    pub fn post_display_command(&self, message: DisplaySendToWndProc<T>) -> Result<()> {
        if !self.is_message_loop_running() {
            bail!("Host window has been destroyed!");
        }

        // Safe because the WndProc thread is still running the message loop.
        unsafe {
            thread_message_util::post_message_carrying_object(
                self.thread_id,
                WM_USER_HANDLE_DISPLAY_MESSAGE_INTERNAL,
                message,
            )
            .context("When posting DisplaySendToWndProc message")
        }
    }

    fn run_message_loop(message_loop_state: Arc<AtomicI32>) {
        // Safe because the dispatcher will take care of the lifetime of the `Window` object.
        let mut dispatcher = match unsafe {
            Self::create_window().and_then(|window| WindowMessageDispatcher::<T>::create(window))
        } {
            Ok(dispatcher) => dispatcher,
            Err(e) => {
                error!("WndProc thread didn't enter message loop: {:?}", e);
                message_loop_state.store(
                    MessageLoopState::EarlyTerminatedWithError as i32,
                    Ordering::SeqCst,
                );
                return;
            }
        };

        info!("WndProc thread entering message loop");
        message_loop_state.store(MessageLoopState::Running as i32, Ordering::SeqCst);
        loop {
            let mut message = mem::MaybeUninit::uninit();
            // Safe because we know the lifetime of `message`.
            match unsafe { GetMessageW(message.as_mut_ptr(), null_mut(), 0, 0) } {
                0 => {
                    info!("WndProc thread exiting message loop since WM_QUIT is received");
                    message_loop_state
                        .store(MessageLoopState::ExitedNormally as i32, Ordering::SeqCst);
                    break;
                }
                -1 => {
                    error!(
                        "WndProc thread exiting message loop because GetMessageW() failed with \
                        error code {}",
                        unsafe { GetLastError() }
                    );
                    message_loop_state
                        .store(MessageLoopState::ExitedWithError as i32, Ordering::SeqCst);
                    break;
                }
                _ => (),
            }

            // Safe because `GetMessageW()` will block until `message` is populated.
            let new_message = unsafe { message.assume_init() };
            if new_message.hwnd.is_null() {
                // Thread messages don't target a specific window and `DispatchMessageA()` won't
                // send them to `wnd_proc()` function, hence we need to handle it as a special case.
                dispatcher
                    .as_mut()
                    .process_thread_message(&new_message.into());
            } else {
                // Safe because `GetMessageW()` will block until `message` is populated.
                unsafe {
                    TranslateMessage(&new_message);
                    DispatchMessageW(&new_message);
                }
            }
        }
    }

    fn is_message_loop_running(&self) -> bool {
        self.message_loop_state.as_ref().map_or(false, |state| {
            state.load(Ordering::SeqCst) == MessageLoopState::Running as i32
        })
    }

    /// In the normal case, when all windows are closed by the user, the WndProc thread exits the
    /// message loop and terminates naturally. If we have to shutdown the VM before all windows are
    /// closed because of errors, this function will post a message to let the WndProc thread kill
    /// all windows and terminate.
    fn signal_exit_message_loop_if_needed(&self) {
        if !self.is_message_loop_running() {
            return;
        }

        info!("WndProc thread is still in message loop before dropping. Signaling killing windows");
        // Safe because the WndProc thread is still running the message loop.
        if let Err(e) = unsafe {
            thread_message_util::post_message(
                self.thread_id,
                WM_USER_WNDPROC_THREAD_DROP_KILL_WINDOW_INTERNAL,
                /* w_param */ 0,
                /* l_param */ 0,
            )
        } {
            error!("Failed to signal WndProc thread to kill windows: {:?}", e);
        }
    }

    /// Checks if the message loop has exited normally. This should be called after joining with the
    /// WndProc thread.
    fn check_message_loop_final_state(&mut self) {
        match Arc::try_unwrap(self.message_loop_state.take().unwrap()) {
            Ok(state) => {
                let state = state.into_inner();
                if state == MessageLoopState::ExitedNormally as i32 {
                    info!("WndProc thread exited gracefully");
                } else {
                    warn!("WndProc thread exited with message loop state: {:?}", state);
                }
            }
            Err(e) => error!(
                "WndProc thread exited but message loop state retrieval failed: {:?}",
                e
            ),
        }
    }

    /// # Safety
    /// The owner of the returned `Window` object is responsible for dropping it before we finish
    /// processing `WM_NCDESTROY`, because the window handle will become invalid afterwards.
    unsafe fn create_window() -> Result<Window> {
        // Gfxstream window is a child window of CrosVM window. Without WS_CLIPCHILDREN, the parent
        // window may use the background brush to clear the gfxstream window client area when
        // drawing occurs. This caused the screen flickering issue during resizing.
        // See b/197786842 for details.
        let dw_style = WS_POPUP | WS_CLIPCHILDREN;
        Window::new(
            Some(Self::wnd_proc),
            /* class_name */ "CROSVM",
            /* title */ "crosvm",
            APP_ICON_ID,
            dw_style,
            // The window size and style can be adjusted later when `Surface` is created.
            &size2(1, 1),
        )
    }

    /// # Safety
    /// The message queue must have been created on the WndProc thread before calling this, and the
    /// returned thread must not outlive the WndProc thread.
    unsafe fn start_message_relay_thread(
        #[allow(unused_variables)] vm_tube: Arc<Mutex<Tube>>,
        #[allow(unused_variables)] wndproc_thread_id: u32,
    ) -> Option<Box<dyn MessageRelayThreadTrait>> {
        #[cfg(feature = "kiwi")]
        match MessageRelayThread::<ServiceSendToGpu>::start_thread(
            vm_tube,
            wndproc_thread_id,
            WM_USER_HANDLE_SERVICE_MESSAGE_INTERNAL,
        ) {
            Ok(thread) => Some(thread),
            // We won't get messages from the service if we failed to spawn this thread. It may not
            // worth terminating the WndProc thread and crashing the emulator in that case, so we
            // just log the error.
            Err(e) => {
                error!("{:?}", e);
                None
            }
        }

        #[cfg(not(feature = "kiwi"))]
        None
    }

    unsafe extern "system" fn wnd_proc(
        hwnd: HWND,
        msg: UINT,
        w_param: WPARAM,
        l_param: LPARAM,
    ) -> LRESULT {
        let dispatcher_ptr = GetPropA(hwnd, win32_string(DISPATCHER_PROPERTY_NAME).as_ptr())
            as *mut WindowMessageDispatcher<T>;
        if let Some(dispatcher) = dispatcher_ptr.as_mut() {
            if let Some(ret) =
                dispatcher.dispatch_window_message(hwnd, &MessagePacket::new(msg, w_param, l_param))
            {
                return ret;
            }
        }
        DefWindowProcA(hwnd, msg, w_param, l_param)
    }
}

impl<T: HandleWindowMessage> Drop for WindowProcedureThread<T> {
    fn drop(&mut self) {
        self.signal_exit_message_loop_if_needed();
        match self.thread.take().unwrap().join() {
            Ok(_) => self.check_message_loop_final_state(),
            Err(e) => error!("Failed to join with WndProc thread: {:?}", e),
        }
    }
}

// `Send` may not be automatically inherited because of the `PhantomData`.
// Since `WindowProcedureThread` does not hold anything that cannot be transferred between threads,
// we can implement `Send` for it.
unsafe impl<T: HandleWindowMessage> Send for WindowProcedureThread<T> {}
