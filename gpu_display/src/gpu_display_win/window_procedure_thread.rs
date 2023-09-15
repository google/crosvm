// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::any::type_name;
use std::any::TypeId;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
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
use once_cell::sync::OnceCell;
use serde::Deserialize;
use serde::Serialize;
use sync::Mutex;
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

use super::window::get_current_module_handle;
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

trait RegisterWindowClass: 'static {
    // Only for debug purpose. Not required to be unique across different implementors.
    const CLASS_NAME_PREFIX: &'static str = "";
    fn register_window_class(class_name: &str, wnd_proc: WNDPROC) -> Result<()>;
}

impl RegisterWindowClass for GuiWindow {
    const CLASS_NAME_PREFIX: &'static str = "CROSVM";

    fn register_window_class(class_name: &str, wnd_proc: WNDPROC) -> Result<()> {
        let hinstance = get_current_module_handle();
        // If we fail to load any UI element below, use NULL to let the system use the default UI
        // rather than crash.
        let hicon = Self::load_custom_icon(hinstance, APP_ICON_ID).unwrap_or(null_mut());
        let hcursor = Self::load_system_cursor(IDC_ARROW).unwrap_or(null_mut());
        let hbrush_background = Self::create_opaque_black_brush().unwrap_or(null_mut());
        let class_name = win32_wide_string(class_name);
        let window_class = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: CS_OWNDC | CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: wnd_proc,
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: hinstance,
            hIcon: hicon,
            hCursor: hcursor,
            hbrBackground: hbrush_background,
            lpszMenuName: null_mut(),
            lpszClassName: class_name.as_ptr(),
            hIconSm: hicon,
        };

        // Safe because we know the lifetime of `window_class`, and we handle failures below.
        if unsafe { RegisterClassExW(&window_class) } == 0 {
            syscall_bail!("Failed to call RegisterClassExW()");
        }
        Ok(())
    }
}

impl RegisterWindowClass for MessageOnlyWindow {
    const CLASS_NAME_PREFIX: &'static str = "THREAD_MESSAGE_ROUTER";

    fn register_window_class(class_name: &str, wnd_proc: WNDPROC) -> Result<()> {
        let hinstance = get_current_module_handle();
        let class_name = win32_wide_string(class_name);
        let window_class = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: 0,
            lpfnWndProc: wnd_proc,
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: hinstance,
            hIcon: null_mut(),
            hCursor: null_mut(),
            hbrBackground: null_mut(),
            lpszMenuName: null_mut(),
            lpszClassName: class_name.as_ptr(),
            hIconSm: null_mut(),
        };

        // Safe because we know the lifetime of `window_class`, and we handle failures below.
        if unsafe { RegisterClassExW(&window_class) } == 0 {
            syscall_bail!("Failed to call RegisterClassExW()");
        }
        Ok(())
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
    pub fn builder() -> WindowProcedureThreadBuilder<T> {
        // We don't implement Default for WindowProcedureThreadBuilder so that the builder function
        // is the only way to create WindowProcedureThreadBuilder.
        WindowProcedureThreadBuilder::<T> {
            display_tube: None,
            #[cfg(feature = "kiwi")]
            ime_tube: None,
            _marker: Default::default(),
        }
    }

    fn start_thread(gpu_main_display_tube: Option<Tube>) -> Result<Self> {
        let (message_router_handle_sender, message_router_handle_receiver) = channel();
        let message_loop_state = Arc::new(AtomicI32::new(MessageLoopState::NotStarted as i32));
        let thread_terminated_event = Event::new().unwrap();

        let message_loop_state_clone = Arc::clone(&message_loop_state);
        let thread_terminated_event_clone = thread_terminated_event
            .try_clone()
            .map_err(|e| anyhow!("Failed to clone thread_terminated_event: {}", e))?;

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
            /* class_name */
            Self::get_window_class_name::<MessageOnlyWindow>()
                .with_context(|| {
                    format!(
                        "retrieve the window class name for MessageOnlyWindow of {}.",
                        type_name::<Self>()
                    )
                })?
                .as_str(),
            /* title */ "ThreadMessageRouter",
        )?;
        // Gfxstream window is a child window of crosvm window. Without WS_CLIPCHILDREN, the parent
        // window may use the background brush to clear the gfxstream window client area when
        // drawing occurs. This caused the screen flickering issue during resizing.
        // See b/197786842 for details.
        let gui_window = GuiWindow::new(
            /* class_name */
            Self::get_window_class_name::<GuiWindow>()
                .with_context(|| {
                    format!(
                        "retrieve the window class name for GuiWindow of {}",
                        type_name::<Self>()
                    )
                })?
                .as_str(),
            /* title */ Self::get_window_title().as_str(),
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

    /// U + T decides one window class. For the same combination of U + T, the same window class
    /// name will be returned. This function also registers the Window class if it is not registered
    /// through this function yet.
    fn get_window_class_name<U: RegisterWindowClass>() -> Result<String> {
        static WINDOW_CLASS_NAMES: OnceCell<Mutex<BTreeMap<(TypeId, TypeId), String>>> =
            OnceCell::new();
        let mut window_class_names = WINDOW_CLASS_NAMES.get_or_init(Default::default).lock();
        let id = window_class_names.len();
        let entry = window_class_names.entry((TypeId::of::<U>(), TypeId::of::<T>()));
        let entry = match entry {
            Entry::Occupied(entry) => return Ok(entry.get().clone()),
            Entry::Vacant(entry) => entry,
        };
        // We are generating a different class name everytime we reach this line, so the name
        // shouldn't collide with any window classes registered through this function. The
        // underscore here is important. If we just use `"{}{}"`, we may collide for prefix = "" and
        // prefix = "1".
        let window_class_name = format!("{}_{}", U::CLASS_NAME_PREFIX, id);
        U::register_window_class(&window_class_name, Some(Self::wnd_proc)).with_context(|| {
            format!(
                "Failed to register the window class for ({} - {}, {}), with name {}.",
                type_name::<Self>(),
                type_name::<T>(),
                type_name::<U>(),
                window_class_name
            )
        })?;
        entry.insert(window_class_name.clone());
        Ok(window_class_name)
    }

    fn get_window_title() -> String {
        "crosvm".to_string()
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

#[derive(Deserialize, Serialize)]
pub struct WindowProcedureThreadBuilder<T: HandleWindowMessage> {
    display_tube: Option<Tube>,
    #[cfg(feature = "kiwi")]
    ime_tube: Option<Tube>,
    // We use fn(T) -> T here so that this struct is still Send + Sync regardless of whether T is
    // Send + Sync. See details of this pattern at
    // https://doc.rust-lang.org/nomicon/phantom-data.html#table-of-phantomdata-patterns.
    _marker: PhantomData<fn(T) -> T>,
}

impl<T: HandleWindowMessage> WindowProcedureThreadBuilder<T> {
    pub fn set_display_tube(&mut self, display_tube: Option<Tube>) -> &mut Self {
        self.display_tube = display_tube;
        self
    }

    #[cfg(feature = "kiwi")]
    pub fn set_ime_tube(&mut self, ime_tube: Option<Tube>) -> &mut Self {
        self.ime_tube = ime_tube;
        self
    }

    /// This function creates the window procedure thread and windows.
    ///
    /// We have seen third-party DLLs hooking into window creation. They may have deep call stack,
    /// and they may not be well tested against late window creation, which may lead to stack
    /// overflow. Hence, this should be called as early as possible when the VM is booting.
    pub fn start_thread(self) -> Result<WindowProcedureThread<T>> {
        cfg_if::cfg_if! {
            if #[cfg(feature = "kiwi")] {
                let ime_tube = self.ime_tube.ok_or_else(|| anyhow!("The ime tube is not set."))?;
                WindowProcedureThread::<T>::start_thread(self.display_tube, ime_tube)
            } else {
                WindowProcedureThread::<T>::start_thread(None)
            }
        }
    }
}

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

    #[test]
    fn window_procedure_window_class_name_should_include_class_name_prefix() {
        const PREFIX: &str = "test-window-class-prefix";
        struct TestHandle;
        impl HandleWindowMessage for TestHandle {}
        struct TestWindow;
        impl RegisterWindowClass for TestWindow {
            const CLASS_NAME_PREFIX: &'static str = PREFIX;
            fn register_window_class(_class_name: &str, _wnd_proc: WNDPROC) -> Result<()> {
                Ok(())
            }
        }

        let name =
            WindowProcedureThread::<TestHandle>::get_window_class_name::<TestWindow>().unwrap();
        assert!(
            name.starts_with(PREFIX),
            "The class name {} should start with {}.",
            name,
            PREFIX
        );
    }

    #[test]
    fn window_procedure_with_same_types_should_return_same_name() {
        struct TestHandle;
        impl HandleWindowMessage for TestHandle {}
        struct TestWindow;
        impl RegisterWindowClass for TestWindow {
            fn register_window_class(_class_name: &str, _wnd_proc: WNDPROC) -> Result<()> {
                Ok(())
            }
        }

        let name1 =
            WindowProcedureThread::<TestHandle>::get_window_class_name::<TestWindow>().unwrap();
        let name2 =
            WindowProcedureThread::<TestHandle>::get_window_class_name::<TestWindow>().unwrap();
        assert_eq!(name1, name2);
    }

    #[test]
    fn window_procedure_with_different_types_should_return_different_names() {
        struct TestHandle1;
        impl HandleWindowMessage for TestHandle1 {}
        struct TestHandle2;
        impl HandleWindowMessage for TestHandle2 {}
        struct TestWindow1;
        impl RegisterWindowClass for TestWindow1 {
            fn register_window_class(_class_name: &str, _wnd_proc: WNDPROC) -> Result<()> {
                Ok(())
            }
        }
        struct TestWindow2;
        impl RegisterWindowClass for TestWindow2 {
            fn register_window_class(_class_name: &str, _wnd_proc: WNDPROC) -> Result<()> {
                Ok(())
            }
        }

        let name1 =
            WindowProcedureThread::<TestHandle1>::get_window_class_name::<TestWindow1>().unwrap();
        let name2 =
            WindowProcedureThread::<TestHandle1>::get_window_class_name::<TestWindow2>().unwrap();
        assert_ne!(name1, name2);

        let name1 =
            WindowProcedureThread::<TestHandle1>::get_window_class_name::<TestWindow1>().unwrap();
        let name2 =
            WindowProcedureThread::<TestHandle2>::get_window_class_name::<TestWindow1>().unwrap();
        assert_ne!(name1, name2);
    }

    #[test]
    fn window_procedure_with_different_types_should_not_collide() {
        struct TestHandle1;
        impl HandleWindowMessage for TestHandle1 {}
        struct TestHandle2;
        impl HandleWindowMessage for TestHandle2 {}
        struct TestHandle3;
        impl HandleWindowMessage for TestHandle3 {}
        struct TestHandle4;
        impl HandleWindowMessage for TestHandle4 {}
        struct TestHandle5;
        impl HandleWindowMessage for TestHandle5 {}
        struct TestHandle6;
        impl HandleWindowMessage for TestHandle6 {}
        struct TestHandle7;
        impl HandleWindowMessage for TestHandle7 {}
        struct TestHandle8;
        impl HandleWindowMessage for TestHandle8 {}
        struct TestHandle9;
        impl HandleWindowMessage for TestHandle9 {}
        struct TestHandle10;
        impl HandleWindowMessage for TestHandle10 {}
        struct TestHandle11;
        impl HandleWindowMessage for TestHandle11 {}

        struct TestWindow1;
        impl RegisterWindowClass for TestWindow1 {
            fn register_window_class(_class_name: &str, _wnd_proc: WNDPROC) -> Result<()> {
                Ok(())
            }
        }
        struct TestWindow2;
        impl RegisterWindowClass for TestWindow2 {
            const CLASS_NAME_PREFIX: &'static str = "1";
            fn register_window_class(_class_name: &str, _wnd_proc: WNDPROC) -> Result<()> {
                Ok(())
            }
        }

        let names = &[
            WindowProcedureThread::<TestHandle1>::get_window_class_name::<TestWindow2>().unwrap(),
            WindowProcedureThread::<TestHandle1>::get_window_class_name::<TestWindow1>().unwrap(),
            WindowProcedureThread::<TestHandle2>::get_window_class_name::<TestWindow1>().unwrap(),
            WindowProcedureThread::<TestHandle3>::get_window_class_name::<TestWindow1>().unwrap(),
            WindowProcedureThread::<TestHandle4>::get_window_class_name::<TestWindow1>().unwrap(),
            WindowProcedureThread::<TestHandle5>::get_window_class_name::<TestWindow1>().unwrap(),
            WindowProcedureThread::<TestHandle6>::get_window_class_name::<TestWindow1>().unwrap(),
            WindowProcedureThread::<TestHandle7>::get_window_class_name::<TestWindow1>().unwrap(),
            WindowProcedureThread::<TestHandle8>::get_window_class_name::<TestWindow1>().unwrap(),
            WindowProcedureThread::<TestHandle9>::get_window_class_name::<TestWindow1>().unwrap(),
            WindowProcedureThread::<TestHandle10>::get_window_class_name::<TestWindow1>().unwrap(),
            WindowProcedureThread::<TestHandle11>::get_window_class_name::<TestWindow1>().unwrap(),
        ];
        for name in names {
            let count = names
                .iter()
                .filter(|current_name| current_name == &name)
                .count();
            assert_eq!(count, 1, "{} should only appear once.", name);
        }
    }
}
