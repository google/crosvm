// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::mem::MaybeUninit;
use std::ptr::null;
use std::ptr::null_mut;
use std::sync::mpsc::channel;
use std::sync::mpsc::sync_channel;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::RecvTimeoutError;
use std::sync::mpsc::SyncSender;
use std::sync::mpsc::TryRecvError;
use std::sync::Arc;
use std::thread::ThreadId;
use std::thread::{self};
use std::time::Duration;

use anyhow::bail;
use anyhow::format_err;
use anyhow::Context;
use anyhow::Result;
use ash::vk;
use base::error;
use base::info;
use base::warn;
use base::AsRawDescriptor;
use euclid::size2;
use euclid::Box2D;
use euclid::Size2D;
use euclid::UnknownUnit;
use lazy_static::lazy_static;
use sync::Mutex;
use vulkano::device::Device;
use vulkano::instance::Instance;
use vulkano::memory::ExternalMemoryHandleType;
use vulkano::memory::ExternalMemoryHandleTypes;
use vulkano::memory::MemoryImportInfo;
use vulkano::VulkanObject;
use win_util::syscall_bail;
use win_util::win32_wide_string;
use winapi::shared::minwindef::HMODULE;
use winapi::shared::minwindef::LPARAM;
use winapi::shared::minwindef::LPVOID;
use winapi::shared::minwindef::LRESULT;
use winapi::shared::minwindef::TRUE;
use winapi::shared::minwindef::UINT;
use winapi::shared::minwindef::WPARAM;
use winapi::shared::windef::HWND;
use winapi::shared::windef::RECT;
use winapi::shared::winerror::ERROR_CLASS_DOES_NOT_EXIST;
use winapi::shared::winerror::ERROR_INVALID_WINDOW_HANDLE;
use winapi::shared::winerror::ERROR_SUCCESS;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::errhandlingapi::SetLastError;
use winapi::um::libloaderapi::GetModuleHandleW;
use winapi::um::winuser::CreateWindowExW;
use winapi::um::winuser::DefWindowProcW;
use winapi::um::winuser::DestroyWindow;
use winapi::um::winuser::DispatchMessageW;
use winapi::um::winuser::GetClassInfoExW;
use winapi::um::winuser::GetClientRect;
use winapi::um::winuser::GetMessageW;
use winapi::um::winuser::GetWindowLongPtrW;
use winapi::um::winuser::MoveWindow;
use winapi::um::winuser::PostMessageW;
use winapi::um::winuser::PostQuitMessage;
use winapi::um::winuser::RegisterClassExW;
use winapi::um::winuser::SetWindowLongPtrW;
use winapi::um::winuser::CREATESTRUCTW;
use winapi::um::winuser::CS_HREDRAW;
use winapi::um::winuser::CS_OWNDC;
use winapi::um::winuser::CS_VREDRAW;
use winapi::um::winuser::GWLP_USERDATA;
use winapi::um::winuser::WM_CLOSE;
use winapi::um::winuser::WM_DESTROY;
use winapi::um::winuser::WM_NCCREATE;
use winapi::um::winuser::WM_SIZE;
use winapi::um::winuser::WM_USER;
use winapi::um::winuser::WNDCLASSEXW;
use winapi::um::winuser::WS_CHILD;
use winapi::um::winuser::WS_DISABLED;
use winapi::um::winuser::WS_EX_NOPARENTNOTIFY;
use winapi::um::winuser::WS_VISIBLE;

use super::ApplicationState;
use super::ApplicationStateBuilder;
use super::Surface;
use super::Window as WindowT;
use super::WindowEvent;
use super::WindowEventLoop;

pub type NativeWindowType = HWND;

#[derive(Copy, Clone, Debug)]
struct MessagePacket {
    msg: UINT,
    w_param: WPARAM,
    l_param: LPARAM,
}

pub(crate) struct Window {
    hwnd: isize,
    hmodule: isize,
    owner_thread_id: ThreadId,
}

impl Window {
    /// # Safety
    /// `hwnd` must be a valid `HWND` handle. The ownership of the hwnd is transferred to this
    /// struct, so that the hwnd shouldn't be destroyed outside this struct.
    #[deny(unsafe_op_in_unsafe_fn)]
    unsafe fn new(hwnd: HWND, hmodule: HMODULE) -> Self {
        Self {
            hwnd: hwnd as isize,
            hmodule: hmodule as isize,
            owner_thread_id: thread::current().id(),
        }
    }
}

impl WindowT for Window {
    fn get_inner_size(&self) -> Result<Size2D<u32, euclid::UnknownUnit>> {
        let mut rect: RECT = Default::default();
        // SAFETY: Safe because self.hwnd and rect outlive this function call.
        if unsafe { GetClientRect(self.hwnd as HWND, &mut rect) } == 0 {
            syscall_bail!("Failed when calling GetClientRect.");
        }
        Ok(size2(rect.right - rect.left, rect.bottom - rect.top)
            .try_cast()
            .unwrap_or_else(|| {
                panic!(
                    "Size out of range for the client rect \
                       {{ left: {} right: {} bottom: {} top: {} }}",
                    rect.left, rect.right, rect.bottom, rect.top
                )
            }))
    }

    fn create_vulkan_surface(self: Arc<Self>, instance: Arc<Instance>) -> Result<Arc<Surface>> {
        // SAFETY: Safe because we checked hmodule when we got it, and we created hwnd and checked
        // it was valid when it was created and we know that self will oulive this Surface
        // because we pass a clone of the Arc<Self> as the win parameter, which is kept as a
        // field of the surface.
        unsafe {
            Surface::from_win32(
                instance,
                self.hmodule as HMODULE,
                self.hwnd as HWND,
                Arc::clone(&self) as _,
            )
        }
        .map_err(|e| e.into())
    }
}

impl Drop for Window {
    fn drop(&mut self) {
        // A thread cannot use DestroyWindow to destroy a window created by a different thread.
        assert!(thread::current().id() == self.owner_thread_id);
        // SAFETY: Safe because the safety requirement of new function guarantees that hwnd is a
        // valid window handle, and we handle the error here.
        if unsafe { DestroyWindow(self.hwnd as HWND) } == 0 {
            error!(
                "Failed to call DestroyWindow with {}. Error code: {}",
                self.hwnd as usize,
                // SAFETY: trivially safe
                unsafe { GetLastError() }
            );
        }
    }
}

// Used to notify the event loop thread that the user event queue has at least one user event
// available.
const WM_USER_USER_EVENT_AVAILABLE: UINT = WM_USER;

struct WindowState<AppState: ApplicationState> {
    app_state: AppState,
    user_event_rx: Receiver<AppState::UserEvent>,
    window: Arc<Window>,
}

#[deny(unsafe_op_in_unsafe_fn)]
/// # Safety
/// Must only be called inside an associated WNDPROC callback.
unsafe fn handle_window_message<AppState: ApplicationState>(
    window_state: &RefCell<Option<WindowState<AppState>>>,
    hwnd: HWND,
    message: MessagePacket,
) -> Result<LRESULT> {
    if let Some(window_state) = window_state.borrow().as_ref() {
        assert_eq!(
            window_state.window.owner_thread_id,
            std::thread::current().id()
        );
    }
    match message.msg {
        WM_DESTROY => {
            info!("Window {:#x} is being destroyed.", hwnd as usize);
            let window = window_state
                .borrow_mut()
                .take()
                .map(|WindowState { window, .. }| window);
            if let Some(window) = window {
                // This could happen if the window is destroyed without receiving WM_CLOSE.
                match Arc::try_unwrap(window) {
                    // The window is being destroyed. No need to call DestroyWindow again.
                    Ok(window) => std::mem::forget(window),
                    Err(window) => {
                        error!(concat!(
                            "Not the sole reference to the window. There is a possible resource ",
                            "leak."
                        ));
                        // Prevent other reference from calling DestroyWindow on the window.
                        std::mem::forget(window);
                    }
                }
            }
            // SAFETY: Safe because it will always succeed.
            unsafe { PostQuitMessage(0) };
            return Ok(0);
        }
        WM_CLOSE => {
            info!("Window {:#x} is about to be destroyed.", hwnd as usize);
            let window_state = window_state.borrow_mut().take();
            drop(window_state);
            return Ok(0);
        }
        WM_SIZE => {
            let window_state = window_state.borrow();
            if let Some(window_state) = window_state.as_ref() {
                window_state.app_state.process_event(WindowEvent::Resized);
            } else {
                warn!(
                    concat!(
                        "The window state is not initialized or has already been destroyed when ",
                        "handling WM_SIZE. lParam = {:#x}, wParam = {:#x}, HWND = {:#x}."
                    ),
                    message.l_param, message.w_param, hwnd as usize
                );
            }
            return Ok(0);
        }
        WM_USER_USER_EVENT_AVAILABLE => {
            let window_state = window_state.borrow();
            let window_state = window_state.as_ref().ok_or_else(|| {
                format_err!("The window state is not initialized or has already been destroyed.")
            })?;
            let user_event = {
                // It is unlikely that the message arrives early than the channel receiver is ready.
                // However, the message can arrives after the user event is read from the receiver.
                // We may even end up with many notification messages in the queue after all the
                // user events are handled. In which case, even a short timeout can hurt the
                // performance badly. Hence a very small timeout is used.
                const TIMEOUT: Duration = Duration::from_nanos(500);
                match window_state.user_event_rx.recv_timeout(TIMEOUT) {
                    Ok(event) => event,
                    Err(RecvTimeoutError::Timeout) => {
                        bail!(
                            "Didn't receive any user events for {:?} after recieved the user \
                               event available notification. Skip.",
                            TIMEOUT
                        );
                    }
                    Err(e) => bail!("Failed to receive user event from the channel: {:?}", e),
                }
            };
            let mut user_event = Some(user_event);
            loop {
                match user_event.take() {
                    Some(user_event) => window_state
                        .app_state
                        .process_event(WindowEvent::User(user_event)),
                    None => break,
                }
                match window_state.user_event_rx.try_recv() {
                    Ok(next_user_event) => user_event = Some(next_user_event),
                    Err(TryRecvError::Empty) => break,
                    Err(e) => bail!("Fail to receive more post commands: {:?}.", e),
                }
            }
        }
        _ => {}
    }
    // SAFETY: Safe because we are processing a message targeting this thread, which is guaranteed
    // by the safety requirement of this function.
    Ok(unsafe { DefWindowProcW(hwnd, message.msg, message.w_param, message.l_param) })
}

#[deny(unsafe_op_in_unsafe_fn)]
unsafe extern "system" fn wnd_proc<AppState: ApplicationState>(
    hwnd: HWND,
    msg: UINT,
    w_param: WPARAM,
    l_param: LPARAM,
) -> LRESULT {
    let userdata_ptr = if msg == WM_NCCREATE {
        // SAFETY: Safe because the lparam for this message is a CREATESTRUCTW.
        let create_struct = unsafe { (l_param as *const CREATESTRUCTW).as_ref() }
            .expect("Unexpected null lParam for the WM_NCCREATE message");
        // SAFETY: Safe because we handle the error cases.
        unsafe { SetLastError(ERROR_SUCCESS) };
        // SAFETY: Safe because the GWLP_USERDATA pointer is only used by us, and we check if it's
        // null each time before we use it. We also know that if the pointer is not null it always
        // points to a valid RefCell<Option<WindowState>>. This is guaranteed by the safety notes of
        // create_window.
        if unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, create_struct.lpCreateParams as isize) }
            == 0
        {
            // SAFETY: trivially safe
            let error = unsafe { GetLastError() };
            assert_eq!(
                error, ERROR_SUCCESS,
                "Failed to set GWLP_USERDATA when initializing the window (Error code {}).",
                error
            );
        }
        create_struct.lpCreateParams
    } else {
        // SAFETY: trivially safe
        unsafe { SetLastError(ERROR_SUCCESS) };
        // SAFETY: Safe because we handle the error cases.
        let userdata_ptr = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) };
        if userdata_ptr == 0 {
            // SAFETY: trivially safe
            let error = unsafe { GetLastError() };
            assert_eq!(
                error, ERROR_SUCCESS,
                "Failed to get GWLP_USERDATA when handling the message {} (Error code {}).",
                msg, error
            );
        }
        userdata_ptr as *mut _
    };

    let window_state =
    // SAFETY: Safe because if the pointer is not null, it always points to a valid
    // RefCell<Option<WindowState>>. This is guaranteed by the safety notes of create_window.
        unsafe { (userdata_ptr as *const RefCell<Option<WindowState<AppState>>>).as_ref() };
    let window_state = if let Some(window_state) = window_state {
        window_state
    } else {
        // SAFETY: Safe because we are processing a message targeting this thread.
        return unsafe { DefWindowProcW(hwnd, msg, w_param, l_param) };
    };

    let message = MessagePacket {
        msg,
        w_param,
        l_param,
    };
    // SAFETY: Safe because we are processing a message targeting this thread.
    let result = unsafe { handle_window_message(window_state, hwnd, message) }
        .with_context(|| format_err!("handle the window message: {:?}", message));

    match result {
        Ok(result) => result,
        Err(err) => {
            error!("{:?}", err);
            // SAFETY: Safe because we are processing a message targeting this thread.
            unsafe { DefWindowProcW(hwnd, msg, w_param, l_param) }
        }
    }
}

lazy_static! {
    static ref WND_CLASS_REGISTRATION_SUCCESS: Mutex<bool> = Mutex::new(false);
}

/// # Safety
///  - The passed in `worker` must not be destroyed before the created window is destroyed if the
/// window creation succeeds.
///  - The WNDPROC must be called within the same thread that calls create_window.
/// # Arguments
/// * `worker` - we use the runtime borrow checker to make sure there is no unwanted borrowing to
///   the underlying worker.
#[deny(unsafe_op_in_unsafe_fn)]
unsafe fn create_window<AppState, AppStateBuilder>(
    parent: HWND,
    initial_window_size: &Size2D<i32, UnknownUnit>,
    app_state_builder: AppStateBuilder,
    window_state: &RefCell<Option<WindowState<AppState>>>,
    user_event_rx: Receiver<AppState::UserEvent>,
) -> Result<HWND>
where
    AppState: ApplicationState,
    AppStateBuilder: ApplicationStateBuilder<Target = AppState>,
{
    // SAFETY: Safe because we pass a null pointer for the module which tells this function to
    // return the current executable name.
    let hmodule = unsafe { GetModuleHandleW(null_mut()) };
    if hmodule.is_null() {
        syscall_bail!("Failed to call GetModuleHandleW() for the current module.");
    }

    let class_name = "vulkan-subWin";
    let class_name_win32_str = win32_wide_string(class_name);
    let window_class = WNDCLASSEXW {
        cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
        style: CS_OWNDC | CS_HREDRAW | CS_VREDRAW,
        lpfnWndProc: Some(wnd_proc::<AppState>),
        cbClsExtra: 0,
        cbWndExtra: 0,
        hInstance: hmodule,
        hIcon: null_mut(),
        hCursor: null_mut(),
        hbrBackground: null_mut(),
        lpszMenuName: null_mut(),
        lpszClassName: class_name_win32_str.as_ptr(),
        hIconSm: null_mut(),
    };

    {
        let mut wnd_class_registration_success = WND_CLASS_REGISTRATION_SUCCESS.lock();
        if !*wnd_class_registration_success {
            // Check if a window class with the same name already exists. This is unexpected.
            {
                let mut window_class_info = MaybeUninit::uninit();
                // SAFETY: Safe because we pass valid pointers.
                if unsafe {
                    GetClassInfoExW(
                        window_class.hInstance,
                        window_class.lpszClassName,
                        window_class_info.as_mut_ptr(),
                    )
                } != 0
                {
                    bail!(
                        "A window class with the same name {} has already been registered.",
                        class_name
                    );
                } else {
                    // SAFETY: trivially safe
                    let sys_error = unsafe { GetLastError() };
                    if sys_error != ERROR_CLASS_DOES_NOT_EXIST {
                        bail!("Failed to call GetClassInfoExW: {}", sys_error);
                    }
                }
            }
            // SAFETY: Safe because we know the lifetime of `window_class`, and we handle failures
            // below.
            if unsafe { RegisterClassExW(&window_class) } == 0 {
                syscall_bail!("Failed to call RegisterClassExW()");
            }
            *wnd_class_registration_success = true;
        }
    }

    let window_name = win32_wide_string("sub");
    let mut style = WS_DISABLED | WS_VISIBLE;
    // In normal practice parent will not be NULL, but it is convenient for this function to also
    // support a NULL parent for unit tests.
    if !parent.is_null() {
        style |= WS_CHILD;
    }
    // SAFETY: Safe because we handle failures below.
    let hwnd = unsafe {
        CreateWindowExW(
            WS_EX_NOPARENTNOTIFY,
            class_name_win32_str.as_ptr(),
            window_name.as_ptr(),
            style,
            0,
            0,
            initial_window_size.width,
            initial_window_size.height,
            parent,
            null_mut(),
            hmodule,
            window_state as *const _ as LPVOID,
        )
    };
    if hwnd.is_null() {
        syscall_bail!("Failed to call CreateWindowExW()");
    }
    info!("Child window created. HWND = {:#x}", hwnd as usize);

    // SAFETY: Safe because hwnd is a valid HWND handle, and we won't destroy the window outside
    // this struct.
    let window = Arc::new(unsafe { Window::new(hwnd, hmodule) });
    let app_state = app_state_builder
        .build(Arc::clone(&window))
        .context("create the application state")?;
    *window_state.borrow_mut() = Some(WindowState {
        app_state,
        user_event_rx,
        window,
    });

    Ok(hwnd)
}

pub(crate) struct WindowsWindowEventLoop<AppState: ApplicationState> {
    hwnd: HWND,
    user_event_tx: SyncSender<AppState::UserEvent>,
    event_loop_thread: Option<thread::JoinHandle<()>>,
}

impl<AppState: ApplicationState> WindowEventLoop<AppState> for WindowsWindowEventLoop<AppState> {
    type WindowType = Window;

    /// # Safety
    /// The parent window must outlive the lifetime of this object.
    #[deny(unsafe_op_in_unsafe_fn)]
    unsafe fn create<Builder>(
        parent: NativeWindowType,
        initial_window_size: &Size2D<i32, UnknownUnit>,
        application_state_builder: Builder,
    ) -> Result<Self>
    where
        Builder: ApplicationStateBuilder<Target = AppState>,
    {
        let parent = parent as isize;
        let initial_window_size = *initial_window_size;
        let (tx, rx) = channel();
        // The only user events we have are Post and GetVulkanDevice. There's no point in queueing
        // more Post commands than there are swapchain images (usually 3), and GetVulkanDevice is
        // only used at initialization. Thus, a reasonable channel size is 5, and if any more
        // events are queued then it will block the caller.
        let (user_event_tx, user_event_rx) = sync_channel(5);
        let event_loop_thread = thread::Builder::new()
            .name("subwin event loop thread".to_owned())
            .spawn(move || {
                let window_state = RefCell::new(None);
                // SAFETY: Safe because worker will be destroyed at the end of the thread, and the
                // message pump would have already stopped then. And we are
                // processing the message in the same thread.
                let create_window_result = unsafe {
                    create_window(
                        parent as HWND,
                        &initial_window_size,
                        application_state_builder,
                        &window_state,
                        user_event_rx,
                    )
                }
                .context("Failed to create the window.");
                let hwnd = match create_window_result {
                    Ok(hwnd) => hwnd,
                    Err(err) => {
                        tx.send(Err(err)).expect(
                            "Failed to send the create window message back to the caller thread",
                        );
                        return;
                    }
                };

                tx.send(Ok(hwnd as isize))
                    .expect("send the HWND back to the caller thread");
                loop {
                    let mut message = MaybeUninit::uninit();
                    // SAFETY: Safe because we handle the error case.
                    match unsafe { GetMessageW(message.as_mut_ptr(), null_mut(), 0, 0) } {
                        // Receive WM_QUIT
                        0 => break,
                        -1 => {
                            // SAFETY: trivially safe
                            error!("GetMessage fails with error code {}", unsafe {
                                GetLastError()
                            });
                        }
                        _ => {
                            // SAFETY: Safe because GetMessage returns with success, and GetMessage
                            // should fill message on success.
                            let message = unsafe { message.assume_init() };
                            // SAFETY: Safe because we are calling this function on the thread where
                            // the window is created.
                            unsafe { DispatchMessageW(&message) };
                        }
                    }
                }
            })
            .context("create the worker thread")?;
        let hwnd = rx
            .recv()
            .context("receive the HWND from the worker thread")??;
        Ok(Self {
            hwnd: hwnd as HWND,
            user_event_tx,
            event_loop_thread: Some(event_loop_thread),
        })
    }

    fn move_window(&self, pos: &Box2D<i32, UnknownUnit>) -> Result<()> {
        // SAFETY: Safe because we handle the error.
        if unsafe {
            MoveWindow(
                self.hwnd,
                pos.min.x,
                pos.min.y,
                pos.width(),
                pos.height(),
                TRUE,
            )
        } == 0
        {
            syscall_bail!("Failed to call MoveWindow");
        }
        Ok(())
    }

    fn send_event(&self, event: AppState::UserEvent) -> Result<()> {
        self.user_event_tx.send(event).map_err(|e| {
            format_err!("Failed to send post command to the worker thread: {:?}", e)
        })?;
        // SAFETY: Safe because arguments outlive function call and contain no pointers.
        if unsafe { PostMessageW(self.hwnd, WM_USER_USER_EVENT_AVAILABLE, 0, 0) } == 0 {
            syscall_bail!(
                "Failed to call PostMessage to send the notification to the worker thread"
            );
        }
        Ok(())
    }
}

impl<AppState: ApplicationState> Drop for WindowsWindowEventLoop<AppState> {
    fn drop(&mut self) {
        // SAFETY: Safe because we handle the error.
        if unsafe { PostMessageW(self.hwnd, WM_CLOSE, 0, 0) } == 0 {
            // SAFETY: trivially safe
            let error = unsafe { GetLastError() };
            if error != ERROR_INVALID_WINDOW_HANDLE {
                error!(
                    "Failed to post the WM_CLOSE message the window. (Error code {})",
                    error
                );
            } else {
                info!(concat!(
                    "Failed to post the WM_CLOSE message the window with ",
                    "ERROR_INVALID_WINDOW_HANDLE. This is benign if the window is already closed ",
                    "through other mechanisms."
                ));
            }
        }
        if let Some(worker_thread) = self.event_loop_thread.take() {
            // It's Ok to panic on join failure, because it only happens if the worker thread
            // panics, on which case the whole process should have abort because crosvm sets abort
            // on panic.
            worker_thread
                .join()
                .expect("The worker thread panic unexpectedly");
        }
    }
}

pub(crate) fn create_post_image_external_memory_handle_types() -> ExternalMemoryHandleTypes {
    ExternalMemoryHandleTypes {
        opaque_win32: true,
        ..ExternalMemoryHandleTypes::empty()
    }
}

// The ownership of the descriptor is transferred to the returned MemoryImportInfo.
pub(crate) fn create_post_image_memory_import_info(
    memory_descriptor: &dyn AsRawDescriptor,
) -> MemoryImportInfo {
    MemoryImportInfo::Win32 {
        handle_type: ExternalMemoryHandleType::OpaqueWin32,
        handle: memory_descriptor.as_raw_descriptor(),
    }
}

pub(crate) fn import_semaphore_from_descriptor(
    device: &Arc<Device>,
    semaphore: vk::Semaphore,
    descriptor: &dyn AsRawDescriptor,
) -> vk::Result {
    let import_handle_info = vk::ImportSemaphoreWin32HandleInfoKHR::builder()
        .semaphore(semaphore)
        .flags(vk::SemaphoreImportFlags::empty())
        .handle_type(vk::ExternalSemaphoreHandleTypeFlags::OPAQUE_WIN32)
        .handle(descriptor.as_raw_descriptor())
        .name(null())
        .build();
    // SAFETY: Safe because `import_handle_info` outlives call to import_semaphore_win32_handle_khr
    // and because we know `import_semaphore_win32_handle_khr` will be non-null on windows.
    unsafe {
        (device
            .fns()
            .khr_external_semaphore_win32
            .import_semaphore_win32_handle_khr)(
            device.internal_object(), &import_handle_info
        )
    }
}

#[cfg(test)]
mod tests {
    use std::any::Any;
    use std::io;
    use std::sync::atomic::AtomicBool;

    use winapi::um::winuser::SetWindowTextW;

    use super::*;

    #[test]
    fn user_event_handler_can_call_into_wndproc() {
        static PROCESS_EVENT_CALLED: AtomicBool = AtomicBool::new(false);

        struct UserEvent;
        struct State {
            hwnd: HWND,
        }
        impl ApplicationState for State {
            type UserEvent = UserEvent;

            fn process_event(&self, _: WindowEvent<Self::UserEvent>) {
                // SAFETY: Safe because "test" string literal is static.
                let res = unsafe { SetWindowTextW(self.hwnd, win32_wide_string("test").as_ptr()) };
                assert!(
                    res != 0,
                    "SetWindowTextW failed: {:?}",
                    io::Error::last_os_error()
                );
                PROCESS_EVENT_CALLED.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        struct StateBuilder;
        impl ApplicationStateBuilder for StateBuilder {
            type Target = State;

            fn build<T: WindowT>(self, window: Arc<T>) -> Result<Self::Target> {
                let window =
                    Arc::downcast::<Window>(window as Arc<dyn Any + Sync + Send + 'static>)
                        .expect("Failed to downcast the window type");
                Ok(State {
                    hwnd: window.hwnd as HWND,
                })
            }
        }
        let event_loop =
            // SAFETY: safe because 0 for parent hwnd means this is a toplevel window so there is
            // no parent window that needs to outlive this object.
            unsafe { WindowsWindowEventLoop::create(0 as HWND, &size2(640, 480), StateBuilder) }
                .unwrap_or_else(|e| panic!("Failed to create the window event loop: {:?}", e));
        event_loop
            .send_event(UserEvent)
            .unwrap_or_else(|e| panic!("Failed to send the user event: {:?}", e));

        let max_timeout = Duration::from_secs(5);
        let poll_interval = Duration::from_millis(100);
        let loop_start = std::time::Instant::now();

        while !PROCESS_EVENT_CALLED.load(std::sync::atomic::Ordering::SeqCst) {
            if loop_start.elapsed() > max_timeout {
                panic!("Timeout reached waiting for process_event_to be called");
            }
            std::thread::sleep(poll_interval);
        }
    }
}
