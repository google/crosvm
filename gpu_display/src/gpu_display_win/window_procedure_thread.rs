// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::HashMap;
use std::marker::PhantomData;
use std::mem;
use std::os::windows::io::RawHandle;
use std::pin::Pin;
use std::ptr::null_mut;
use std::rc::Rc;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::Ordering;
use std::sync::mpsc::channel;
use std::sync::mpsc::Sender;
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
use base::AsRawDescriptor;
use base::Event;
use base::ReadNotifier;
use base::Tube;
use euclid::size2;
#[cfg(feature = "kiwi")]
use vm_control::ServiceSendToGpu;
use win_util::syscall_bail;
use win_util::win32_wide_string;
use winapi::shared::minwindef::DWORD;
use winapi::shared::minwindef::FALSE;
use winapi::shared::minwindef::LPARAM;
use winapi::shared::minwindef::LRESULT;
use winapi::shared::minwindef::UINT;
use winapi::shared::minwindef::WPARAM;
use winapi::shared::windef::HWND;
use winapi::um::winbase::INFINITE;
use winapi::um::winbase::WAIT_OBJECT_0;
use winapi::um::winnt::MAXIMUM_WAIT_OBJECTS;
use winapi::um::winuser::*;

use super::window::GuiWindow;
use super::window::MessageOnlyWindow;
use super::window::MessagePacket;
use super::window_message_dispatcher::WindowMessageDispatcher;
use super::window_message_dispatcher::DISPATCHER_PROPERTY_NAME;
use super::window_message_processor::*;

// The default app icon id, which is defined in crosvm-manifest.rc.
const APP_ICON_ID: u16 = 1;

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

#[derive(Copy, Clone, PartialEq)]
enum Token {
    MessagePump,
    ServiceMessage,
}

/// A context that can wait on both the thread-specific message queue and the given handles.
struct MsgWaitContext {
    triggers: HashMap<RawHandle, Token>,
    raw_handles: Vec<RawHandle>,
}

impl MsgWaitContext {
    pub fn new() -> Self {
        Self {
            triggers: HashMap::new(),
            raw_handles: Vec::new(),
        }
    }

    /// Note that since there is no handle associated with `Token::MessagePump`, this token will be
    /// used internally by `MsgWaitContext` and the caller should never use it.
    pub fn add(&mut self, handle: &dyn AsRawDescriptor, token: Token) -> Result<()> {
        if token == Token::MessagePump {
            bail!("Token::MessagePump is reserved!");
        }
        if self.raw_handles.len() == MAXIMUM_WAIT_OBJECTS as usize {
            bail!("Number of raw handles exceeding MAXIMUM_WAIT_OBJECTS!");
        }

        let raw_descriptor = handle.as_raw_descriptor();
        if self.triggers.contains_key(&raw_descriptor) {
            bail!("The handle has already been registered in MsgWaitContext!")
        }

        self.triggers.insert(raw_descriptor, token);
        self.raw_handles.push(raw_descriptor);
        Ok(())
    }

    /// Blocks the thread until there is any new message available on the message queue, or if any
    /// of the given handles is signaled, and returns the associated token.
    ///
    /// If multiple handles are signaled, this will return the token associated with the one that
    /// was first added to this context.
    ///
    /// # Safety
    ///
    /// Caller is responsible for ensuring that the handles are still valid.
    pub unsafe fn wait(&self) -> Result<Token> {
        let num_handles = self.raw_handles.len();
        // Safe because the caller is required to guarantee that the handles are valid, and failures
        // are handled below.
        let result = MsgWaitForMultipleObjects(
            num_handles as DWORD,
            self.raw_handles.as_ptr(),
            /* fWaitAll= */ FALSE,
            INFINITE,
            QS_ALLINPUT,
        );
        match (result - WAIT_OBJECT_0) as usize {
            // At least one of the handles has been signaled.
            index if index < num_handles => Ok(self.triggers[&self.raw_handles[index]]),
            // At least one message is available at the message queue.
            index if index == num_handles => Ok(Token::MessagePump),
            // Invalid cases. This is most likely a `WAIT_FAILED`, but anything not matched by the
            // above is an error case.
            _ => syscall_bail!(format!(
                "MsgWaitForMultipleObjects() unexpectedly returned {}",
                result
            )),
        }
    }
}

/// This class runs the WndProc thread, and provides helper functions for other threads to
/// communicate with it.
pub struct WindowProcedureThread<T: HandleWindowMessage> {
    thread: Option<JoinHandle<()>>,
    message_router_handle: HWND,
    message_loop_state: Option<Arc<AtomicI32>>,
    thread_terminated_event: Event,
    _marker: PhantomData<T>,
}

impl<T: HandleWindowMessage> WindowProcedureThread<T> {
    pub fn start_thread(
        #[cfg(feature = "kiwi")] gpu_main_display_tube: Option<Tube>,
    ) -> Result<Self> {
        let (message_router_handle_sender, message_router_handle_receiver) = channel();
        let message_loop_state = Arc::new(AtomicI32::new(MessageLoopState::NotStarted as i32));
        let thread_terminated_event = Event::new().unwrap();

        let message_loop_state_clone = Arc::clone(&message_loop_state);
        let thread_terminated_event_clone = thread_terminated_event
            .try_clone()
            .map_err(|e| anyhow!("Failed to clone thread_terminated_event: {}", e))?;

        #[cfg(not(feature = "kiwi"))]
        let gpu_main_display_tube = None;
        let thread = match ThreadBuilder::new()
            .name("gpu_display_wndproc".into())
            .spawn(move || {
                Self::run_message_loop(
                    message_router_handle_sender,
                    message_loop_state_clone,
                    gpu_main_display_tube,
                );

                if let Err(e) = thread_terminated_event_clone.signal() {
                    error!("Failed to signal thread terminated event: {}", e);
                }
            }) {
            Ok(thread) => thread,
            Err(e) => bail!("Failed to spawn WndProc thread: {}", e),
        };

        match message_router_handle_receiver.recv() {
            Ok(message_router_handle_res) => match message_router_handle_res {
                Ok(message_router_handle) => Ok(Self {
                    thread: Some(thread),
                    message_router_handle: message_router_handle as HWND,
                    message_loop_state: Some(message_loop_state),
                    thread_terminated_event,
                    _marker: PhantomData,
                }),
                Err(e) => bail!("WndProc internal failure: {:?}", e),
            },
            Err(e) => bail!("Failed to receive WndProc thread ID: {}", e),
        }
    }

    pub fn try_clone_thread_terminated_event(&self) -> Result<Event> {
        self.thread_terminated_event
            .try_clone()
            .map_err(|e| anyhow!("Failed to clone thread_terminated_event: {}", e))
    }

    pub fn post_display_command(&self, message: DisplaySendToWndProc<T>) -> Result<()> {
        self.post_message_to_thread_carrying_object(
            WM_USER_HANDLE_DISPLAY_MESSAGE_INTERNAL,
            message,
        )
        .context("When posting DisplaySendToWndProc message")
    }

    /// Calls `PostMessageW()` internally.
    fn post_message_to_thread(&self, msg: UINT, w_param: WPARAM, l_param: LPARAM) -> Result<()> {
        if !self.is_message_loop_running() {
            bail!("Cannot post message to WndProc thread because message loop is not running!");
        }
        // Safe because the message loop is still running.
        if unsafe { PostMessageW(self.message_router_handle, msg, w_param, l_param) } == 0 {
            syscall_bail!("Failed to call PostMessageW()");
        }
        Ok(())
    }

    /// Calls `PostMessageW()` internally. This is a common pattern, where we send a pointer to
    /// the given object as the lParam. The receiver is responsible for destructing the object.
    fn post_message_to_thread_carrying_object<U>(&self, msg: UINT, object: U) -> Result<()> {
        let mut boxed_object = Box::new(object);
        self.post_message_to_thread(
            msg,
            /* w_param= */ 0,
            &mut *boxed_object as *mut U as LPARAM,
        )
        .map(|_| {
            // If successful, the receiver will be responsible for destructing the object.
            std::mem::forget(boxed_object);
        })
    }

    fn run_message_loop(
        message_router_handle_sender: Sender<Result<u32>>,
        message_loop_state: Arc<AtomicI32>,
        gpu_main_display_tube: Option<Tube>,
    ) {
        let gpu_main_display_tube = gpu_main_display_tube.map(Rc::new);
        // Safe because the dispatcher will take care of the lifetime of the `MessageOnlyWindow` and
        // `GuiWindow` objects.
        match unsafe { Self::create_windows() }.and_then(|(message_router_window, gui_window)| {
            WindowMessageDispatcher::<T>::create(
                message_router_window,
                gui_window,
                gpu_main_display_tube.clone(),
            )
        }) {
            Ok(dispatcher) => {
                info!("WndProc thread entering message loop");
                message_loop_state.store(MessageLoopState::Running as i32, Ordering::SeqCst);

                // Safe because we won't use the handle unless the message loop is still running.
                let message_router_handle =
                    unsafe { dispatcher.message_router_handle().unwrap_or(null_mut()) };
                // HWND cannot be sent cross threads, so we cast it to u32 first.
                if let Err(e) = message_router_handle_sender.send(Ok(message_router_handle as u32))
                {
                    error!("Failed to send message router handle: {}", e);
                }

                let exit_state = Self::run_message_loop_body(dispatcher, gpu_main_display_tube);
                message_loop_state.store(exit_state as i32, Ordering::SeqCst);
            }
            Err(e) => {
                error!("WndProc thread didn't enter message loop: {:?}", e);
                message_loop_state.store(
                    MessageLoopState::EarlyTerminatedWithError as i32,
                    Ordering::SeqCst,
                );
                if let Err(e) = message_router_handle_sender.send(Err(e)) {
                    error!("Failed to report message loop early termination: {}", e)
                }
            }
        }
    }

    fn run_message_loop_body(
        #[cfg_attr(not(feature = "kiwi"), allow(unused_variables, unused_mut))]
        mut message_dispatcher: Pin<Box<WindowMessageDispatcher<T>>>,
        gpu_main_display_tube: Option<Rc<Tube>>,
    ) -> MessageLoopState {
        #[cfg_attr(not(feature = "kiwi"), allow(unused_mut))]
        let mut msg_wait_ctx = MsgWaitContext::new();
        if let Some(tube) = &gpu_main_display_tube {
            if let Err(e) = msg_wait_ctx.add(tube.get_read_notifier(), Token::ServiceMessage) {
                error!(
                    "Failed to add service message read notifier to MsgWaitContext: {:?}",
                    e
                );
                return MessageLoopState::EarlyTerminatedWithError;
            }
        }

        loop {
            // Safe because the lifetime of handles are at least as long as the function call.
            match unsafe { msg_wait_ctx.wait() } {
                Ok(token) => match token {
                    Token::MessagePump => {
                        if !Self::retrieve_and_dispatch_messages() {
                            info!("WndProc thread exiting message loop normally");
                            return MessageLoopState::ExitedNormally;
                        }
                    }
                    Token::ServiceMessage => Self::read_and_dispatch_service_message(
                        &mut message_dispatcher,
                        // We never use this token if `gpu_main_display_tube` is None, so `expect()`
                        // should always succeed.
                        gpu_main_display_tube
                            .as_ref()
                            .expect("Service message tube is None"),
                    ),
                },
                Err(e) => {
                    error!(
                        "WndProc thread exiting message loop because of error: {:?}",
                        e
                    );
                    return MessageLoopState::ExitedWithError;
                }
            }
        }
    }

    /// Retrieves and dispatches all messages in the queue, and returns whether the message loop
    /// should continue running.
    fn retrieve_and_dispatch_messages() -> bool {
        // Since `MsgWaitForMultipleObjects()` returns only when there is a new event in the queue,
        // if we call `MsgWaitForMultipleObjects()` again without draining the queue, it will ignore
        // existing events and will not return immediately. Hence, we need to keep calling
        // `PeekMessageW()` with `PM_REMOVE` until the queue is drained before returning.
        // https://devblogs.microsoft.com/oldnewthing/20050217-00/?p=36423
        // Alternatively we could use `MsgWaitForMultipleObjectsEx()` with the `MWMO_INPUTAVAILABLE`
        // flag, which will always return if there is any message in the queue, no matter that is a
        // new message or not. However, we found that it may also return when there is no message at
        // all, so we slightly prefer `MsgWaitForMultipleObjects()`.
        loop {
            // Safe because if `message` is initialized, we will call `assume_init()` to extract the
            // value, which will get dropped eventually.
            let mut message = mem::MaybeUninit::uninit();
            // Safe because `message` lives at least as long as the function call.
            if unsafe {
                PeekMessageW(
                    message.as_mut_ptr(),
                    /* hWnd= */ null_mut(),
                    /* wMsgFilterMin= */ 0,
                    /* wMsgFilterMax= */ 0,
                    PM_REMOVE,
                ) == 0
            } {
                // No more message in the queue.
                return true;
            }

            // Safe because `PeekMessageW()` has populated `message`.
            unsafe {
                let new_message = message.assume_init();
                if new_message.message == WM_QUIT {
                    return false;
                }
                TranslateMessage(&new_message);
                DispatchMessageW(&new_message);
            }
        }
    }

    #[cfg(feature = "kiwi")]
    fn read_and_dispatch_service_message(
        message_dispatcher: &mut Pin<Box<WindowMessageDispatcher<T>>>,
        gpu_main_display_tube: &Tube,
    ) {
        match gpu_main_display_tube.recv::<ServiceSendToGpu>() {
            Ok(message) => message_dispatcher
                .as_mut()
                .process_service_message(&message),
            Err(e) => {
                error!("Failed to receive service message through the tube: {}", e)
            }
        }
    }

    #[cfg(not(feature = "kiwi"))]
    fn read_and_dispatch_service_message(
        _: &mut Pin<Box<WindowMessageDispatcher<T>>>,
        _gpu_main_display_tube: &Tube,
    ) {
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
        if let Err(e) = self.post_message_to_thread(
            WM_USER_WNDPROC_THREAD_DROP_KILL_WINDOW_INTERNAL,
            /* w_param */ 0,
            /* l_param */ 0,
        ) {
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
    /// The owner of the returned window objects is responsible for dropping them before we finish
    /// processing `WM_NCDESTROY`, because the window handle will become invalid afterwards.
    unsafe fn create_windows() -> Result<(MessageOnlyWindow, GuiWindow)> {
        let message_router_window = MessageOnlyWindow::new(
            Some(Self::wnd_proc),
            /* class_name */ "THREAD_MESSAGE_ROUTER",
            /* title */ "ThreadMessageRouter",
        )?;
        // Gfxstream window is a child window of crosvm window. Without WS_CLIPCHILDREN, the parent
        // window may use the background brush to clear the gfxstream window client area when
        // drawing occurs. This caused the screen flickering issue during resizing.
        // See b/197786842 for details.
        let gui_window = GuiWindow::new(
            Some(Self::wnd_proc),
            /* class_name */ "CROSVM",
            /* title */ "crosvm",
            APP_ICON_ID,
            WS_POPUP | WS_CLIPCHILDREN,
            // The window size and style can be adjusted later when `Surface` is created.
            &size2(1, 1),
        )?;
        Ok((message_router_window, gui_window))
    }

    unsafe extern "system" fn wnd_proc(
        hwnd: HWND,
        msg: UINT,
        w_param: WPARAM,
        l_param: LPARAM,
    ) -> LRESULT {
        let dispatcher_ptr = GetPropW(hwnd, win32_wide_string(DISPATCHER_PROPERTY_NAME).as_ptr())
            as *mut WindowMessageDispatcher<T>;
        if let Some(dispatcher) = dispatcher_ptr.as_mut() {
            if let Some(ret) =
                dispatcher.dispatch_window_message(hwnd, &MessagePacket::new(msg, w_param, l_param))
            {
                return ret;
            }
        }
        DefWindowProcW(hwnd, msg, w_param, l_param)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_on_adding_reserved_token_to_context() {
        let mut ctx = MsgWaitContext::new();
        let event = Event::new().unwrap();
        assert!(ctx.add(&event, Token::MessagePump).is_err());
    }

    #[test]
    fn error_on_adding_duplicated_handle_to_context() {
        let mut ctx = MsgWaitContext::new();
        let event = Event::new().unwrap();
        assert!(ctx.add(&event, Token::ServiceMessage).is_ok());
        assert!(ctx.add(&event, Token::ServiceMessage).is_err());
    }
}
