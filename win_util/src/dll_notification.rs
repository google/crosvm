// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::OsString;
use std::ptr;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread::JoinHandle;

use anyhow::Context;
use winapi::shared::minwindef::ULONG;
use winapi::um::winnt::PVOID;

use super::unicode_string_to_os_string;

// Required for Windows API FFI bindings, as the names of the FFI structs and
// functions get called out by the linter.
#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(dead_code)]
mod dll_notification_sys {
    use std::io;

    use winapi::shared::minwindef::ULONG;
    use winapi::shared::ntdef::NTSTATUS;
    use winapi::shared::ntdef::PCUNICODE_STRING;
    use winapi::shared::ntstatus::STATUS_SUCCESS;
    use winapi::um::libloaderapi::GetModuleHandleA;
    use winapi::um::libloaderapi::GetProcAddress;
    use winapi::um::winnt::CHAR;
    use winapi::um::winnt::PVOID;

    #[repr(C)]
    pub union _LDR_DLL_NOTIFICATION_DATA {
        pub Loaded: LDR_DLL_LOADED_NOTIFICATION_DATA,
        pub Unloaded: LDR_DLL_UNLOADED_NOTIFICATION_DATA,
    }
    pub type LDR_DLL_NOTIFICATION_DATA = _LDR_DLL_NOTIFICATION_DATA;
    pub type PLDR_DLL_NOTIFICATION_DATA = *mut LDR_DLL_NOTIFICATION_DATA;

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct _LDR_DLL_LOADED_NOTIFICATION_DATA {
        pub Flags: ULONG,                  // Reserved.
        pub FullDllName: PCUNICODE_STRING, // The full path name of the DLL module.
        pub BaseDllName: PCUNICODE_STRING, // The base file name of the DLL module.
        pub DllBase: PVOID,                // A pointer to the base address for the DLL in memory.
        pub SizeOfImage: ULONG,            // The size of the DLL image, in bytes.
    }
    pub type LDR_DLL_LOADED_NOTIFICATION_DATA = _LDR_DLL_LOADED_NOTIFICATION_DATA;
    pub type PLDR_DLL_LOADED_NOTIFICATION_DATA = *mut LDR_DLL_LOADED_NOTIFICATION_DATA;

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct _LDR_DLL_UNLOADED_NOTIFICATION_DATA {
        pub Flags: ULONG,                  // Reserved.
        pub FullDllName: PCUNICODE_STRING, // The full path name of the DLL module.
        pub BaseDllName: PCUNICODE_STRING, // The base file name of the DLL module.
        pub DllBase: PVOID,                // A pointer to the base address for the DLL in memory.
        pub SizeOfImage: ULONG,            // The size of the DLL image, in bytes.
    }
    pub type LDR_DLL_UNLOADED_NOTIFICATION_DATA = _LDR_DLL_UNLOADED_NOTIFICATION_DATA;
    pub type PLDR_DLL_UNLOADED_NOTIFICATION_DATA = *mut LDR_DLL_UNLOADED_NOTIFICATION_DATA;

    pub const LDR_DLL_NOTIFICATION_REASON_LOADED: ULONG = 1;
    pub const LDR_DLL_NOTIFICATION_REASON_UNLOADED: ULONG = 2;

    const NTDLL: &[u8] = b"ntdll\0";
    const LDR_REGISTER_DLL_NOTIFICATION: &[u8] = b"LdrRegisterDllNotification\0";
    const LDR_UNREGISTER_DLL_NOTIFICATION: &[u8] = b"LdrUnregisterDllNotification\0";

    pub type LdrDllNotification = unsafe extern "system" fn(
        NotificationReason: ULONG,
        NotificationData: PLDR_DLL_NOTIFICATION_DATA,
        Context: PVOID,
    );

    pub type FnLdrRegisterDllNotification =
        unsafe extern "C" fn(ULONG, LdrDllNotification, PVOID, *mut PVOID) -> NTSTATUS;
    pub type FnLdrUnregisterDllNotification = unsafe extern "C" fn(PVOID) -> NTSTATUS;

    extern "C" {
        pub fn RtlNtStatusToDosError(Status: NTSTATUS) -> ULONG;
    }

    /// Wrapper for the NTDLL `LdrRegisterDllNotification` function. Dynamically
    /// gets the address of the function and invokes the function with the given
    /// arguments.
    ///
    /// # Safety
    /// Unsafe as this function does not verify its arguments; the caller is
    /// expected to verify the safety as if invoking the underlying C function.
    pub unsafe fn LdrRegisterDllNotification(
        Flags: ULONG,
        NotificationFunction: LdrDllNotification,
        Context: PVOID,
        Cookie: *mut PVOID,
    ) -> io::Result<()> {
        let proc_addr = GetProcAddress(
            /* hModule= */
            GetModuleHandleA(/* lpModuleName= */ NTDLL.as_ptr() as *const CHAR),
            /* lpProcName= */
            LDR_REGISTER_DLL_NOTIFICATION.as_ptr() as *const CHAR,
        );
        if proc_addr.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        let ldr_register_dll_notification: FnLdrRegisterDllNotification =
            std::mem::transmute(proc_addr);
        let ret = ldr_register_dll_notification(Flags, NotificationFunction, Context, Cookie);
        if ret != STATUS_SUCCESS {
            return Err(io::Error::from_raw_os_error(
                RtlNtStatusToDosError(/* Status= */ ret) as i32,
            ));
        };
        Ok(())
    }

    /// Wrapper for the NTDLL `LdrUnregisterDllNotification` function. Dynamically
    /// gets the address of the function and invokes the function with the given
    /// arguments.
    ///
    /// # Safety
    /// Unsafe as this function does not verify its arguments; the caller is
    /// expected to verify the safety as if invoking the underlying C function.
    pub unsafe fn LdrUnregisterDllNotification(Cookie: PVOID) -> io::Result<()> {
        let proc_addr = GetProcAddress(
            /* hModule= */
            GetModuleHandleA(/* lpModuleName= */ NTDLL.as_ptr() as *const CHAR),
            /* lpProcName= */
            LDR_UNREGISTER_DLL_NOTIFICATION.as_ptr() as *const CHAR,
        );
        if proc_addr.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        let ldr_unregister_dll_notification: FnLdrUnregisterDllNotification =
            std::mem::transmute(proc_addr);
        let ret = ldr_unregister_dll_notification(Cookie);
        if ret != STATUS_SUCCESS {
            return Err(io::Error::from_raw_os_error(
                RtlNtStatusToDosError(/* Status= */ ret) as i32,
            ));
        };
        Ok(())
    }
}

use dll_notification_sys::*;

#[derive(Debug, Clone)]
pub struct DllNotificationData {
    pub full_dll_name: OsString,
    pub base_dll_name: OsString,
}

#[derive(Clone, Debug)]
enum DllWatcherMessage {
    DllLoaded(DllNotificationData),
    DllUnloaded(DllNotificationData),
    Exit,
}

struct DllWatcherWorker<F1, F2>
where
    F1: FnMut(DllNotificationData),
    F2: FnMut(DllNotificationData),
{
    // We store tx here to ensure that the underlying sender is always alive when the notification
    // callback is called.
    #[allow(dead_code)]
    tx: Arc<Sender<DllWatcherMessage>>,
    rx: Receiver<DllWatcherMessage>,
    loaded_callback: F1,
    unloaded_callback: F2,
    cookie: Option<PVOID>,
}

impl<F1, F2> DllWatcherWorker<F1, F2>
where
    F1: FnMut(DllNotificationData),
    F2: FnMut(DllNotificationData),
{
    fn new(
        tx: Arc<Sender<DllWatcherMessage>>,
        rx: Receiver<DllWatcherMessage>,
        loaded_callback: F1,
        unloaded_callback: F2,
    ) -> anyhow::Result<Self> {
        extern "system" fn notification_function(
            notification_reason: ULONG,
            notification_data: PLDR_DLL_NOTIFICATION_DATA,
            context: PVOID,
        ) {
            let context = context as *const Sender<DllWatcherMessage>;
            // SAFETY: The DLLWatcherWorker guarantees that the channel sender is not null and we
            // don't have mutable reference to it.
            let sender = unsafe { context.as_ref() }.expect("context was null");

            assert!(!notification_data.is_null());

            let message = match notification_reason {
                LDR_DLL_NOTIFICATION_REASON_LOADED => {
                    // SAFETY: We know that the LDR_DLL_NOTIFICATION_DATA union contains the
                    // LDR_DLL_LOADED_NOTIFICATION_DATA because we got
                    // LDR_DLL_NOTIFICATION_REASON_LOADED as the notification reason.
                    let loaded = unsafe { &mut (*notification_data).Loaded };

                    assert!(!loaded.BaseDllName.is_null());

                    // SAFETY: We assert that the pointer is not null and expect that the OS has
                    // provided a valid UNICODE_STRING struct.
                    let base_dll_name =
                        unsafe { unicode_string_to_os_string(&*loaded.BaseDllName) };

                    assert!(!loaded.FullDllName.is_null());

                    // SAFETY: We assert that the pointer is not null and expect that the OS has
                    // provided a valid UNICODE_STRING struct.
                    let full_dll_name =
                        unsafe { unicode_string_to_os_string(&*loaded.FullDllName) };

                    DllWatcherMessage::DllLoaded(DllNotificationData {
                        base_dll_name,
                        full_dll_name,
                    })
                }
                LDR_DLL_NOTIFICATION_REASON_UNLOADED => {
                    // SAFETY: We know that the LDR_DLL_NOTIFICATION_DATA union contains the
                    // LDR_DLL_UNLOADED_NOTIFICATION_DATA because we got
                    // LDR_DLL_NOTIFICATION_REASON_UNLOADED as the notification reason.
                    let unloaded = unsafe { &mut (*notification_data).Unloaded };

                    assert!(!unloaded.BaseDllName.is_null());

                    // SAFETY: We assert that the pointer is not null and expect that the OS has
                    // provided a valid UNICODE_STRING struct.
                    let base_dll_name =
                        unsafe { unicode_string_to_os_string(&*unloaded.BaseDllName) };

                    assert!(!unloaded.FullDllName.is_null());

                    // SAFETY: We assert that the pointer is not null and expect that the OS has
                    // provided a valid UNICODE_STRING struct.
                    let full_dll_name =
                        unsafe { unicode_string_to_os_string(&*unloaded.FullDllName) };

                    DllWatcherMessage::DllUnloaded(DllNotificationData {
                        base_dll_name,
                        full_dll_name,
                    })
                }
                n => panic!("invalid value \"{n}\" for dll notification reason"),
            };
            if let Err(e) = sender.send(message) {
                log::warn!("failed to send the DLL watcher message: {:?}", e);
            }
        }

        let mut cookie: PVOID = ptr::null_mut();
        // SAFETY: We guarantee that tx is always alive when the notification function is called.
        unsafe {
            LdrRegisterDllNotification(
                /* Flags= */ 0,
                /* NotificationFunction= */ notification_function,
                /* Context= */ tx.as_ref() as *const _ as PVOID,
                /* Cookie= */ &mut cookie,
            )
        }
        .context("failed to register DLL notification")?;
        Ok(Self {
            tx,
            rx,
            loaded_callback,
            unloaded_callback,
            cookie: Some(cookie),
        })
    }

    fn run(&mut self) -> anyhow::Result<()> {
        loop {
            match self
                .rx
                .recv()
                .expect("the sender side should never disconnect at this point")
            {
                DllWatcherMessage::DllLoaded(data) => (self.loaded_callback)(data),
                DllWatcherMessage::DllUnloaded(data) => (self.unloaded_callback)(data),
                DllWatcherMessage::Exit => break,
            }
        }
        Ok(())
    }
}

impl<F1, F2> Drop for DllWatcherWorker<F1, F2>
where
    F1: FnMut(DllNotificationData),
    F2: FnMut(DllNotificationData),
{
    fn drop(&mut self) {
        if let Some(c) = self.cookie.take() {
            // SAFETY: We guarantee that `Cookie` was previously initialized.
            unsafe {
                LdrUnregisterDllNotification(/* Cookie= */ c)
            }
            .expect("error unregistering dll notification");
        }
    }
}

/// DLL watcher for monitoring DLL loads/unloads.
///
/// Provides a method to invoke a function-like type any time a DLL
/// is loaded or unloaded in the current process.
pub struct DllWatcher {
    tx: Arc<Sender<DllWatcherMessage>>,
    worker_thread: Option<JoinHandle<()>>,

    // For test only.
    #[cfg(test)]
    worker_initialization_complete_rx: Receiver<()>,
}

impl DllWatcher {
    /// Create a new `DllWatcher` with the two callback functions. Takes two
    /// callbacks, a `loaded_callback` which is called when a DLL is loaded,
    /// and `unloaded_callback` which is called when a DLL is unloaded.
    pub fn new<F1, F2>(loaded_callback: F1, unloaded_callback: F2) -> anyhow::Result<Self>
    where
        F1: FnMut(DllNotificationData) + Send + 'static,
        F2: FnMut(DllNotificationData) + Send + 'static,
    {
        let (tx, rx) = std::sync::mpsc::channel();
        #[cfg(test)]
        let (worker_initialization_complete_tx, worker_initialization_complete_rx) =
            std::sync::mpsc::channel();
        let tx = Arc::new(tx);
        let worker_thread = std::thread::Builder::new()
            .name("Dll watcher worker".to_string())
            .spawn({
                let tx = Arc::clone(&tx);
                let main = move || -> anyhow::Result<()> {
                    let mut worker =
                        DllWatcherWorker::new(tx, rx, loaded_callback, unloaded_callback)
                            .context("failed to create DllWatcherWorker")?;
                    #[cfg(test)]
                    if worker_initialization_complete_tx.send(()).is_err() {
                        // We don't treat this as an actual failure, because
                        // worker_initialization_complete_tx are only used in tests.
                        log::error!(
                            "failed to send the worker initialization complete notification"
                        );
                    }
                    worker.run().context("DllWatcherWorker run fails")?;
                    Ok(())
                };
                move || {
                    if let Err(e) = main() {
                        log::error!("DllWatcherWorker fails: {:?}", e);
                    }
                }
            })
            .context("failed to spawn the DLL watcher worker thread")?;
        Ok(Self {
            tx,
            worker_thread: Some(worker_thread),
            #[cfg(test)]
            worker_initialization_complete_rx,
        })
    }

    // Only for testing
    #[cfg(test)]
    fn wait_for_initialization(&self, timeout: std::time::Duration) {
        // If the message is received, we know the initialization completes. If the channel is
        // disconnected, the worker thread exits before the initialization completes, which we don't
        // care.
        if let Err(std::sync::mpsc::RecvTimeoutError::Timeout) =
            self.worker_initialization_complete_rx.recv_timeout(timeout)
        {
            panic!("timeout reached before the initialization completes");
        }
    }
}

impl Drop for DllWatcher {
    fn drop(&mut self) {
        if self.tx.send(DllWatcherMessage::Exit).is_err() {
            log::warn!("the worker thread exited prematurely, likely due to a failure");
        }
        if let Some(handle) = self.worker_thread.take() {
            if let Err(e) = handle.join() {
                log::warn!("failed to join the worker thread: {:?}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::ffi::CString;
    use std::io;
    use std::sync::Mutex;

    use winapi::um::libloaderapi::FreeLibrary;
    use winapi::um::libloaderapi::LoadLibraryA;

    use super::*;

    // Arbitrarily chosen DLLs for load/unload test. Chosen because they're
    // hopefully esoteric enough that they're probably not already loaded in
    // the process so we can test load/unload notifications.
    //
    // Using a single DLL can lead to flakiness; since the tests are run in the
    // same process, it can be hard to rely on the OS to clean up the DLL loaded
    // by one test before the other test runs. Using a different DLL makes the
    // tests more independent.
    const TEST_DLL_NAME_1: &str = "Imagehlp.dll";
    const TEST_DLL_NAME_2: &str = "dbghelp.dll";

    #[test]
    fn load_dll() {
        let test_dll_name = CString::new(TEST_DLL_NAME_1).expect("failed to create CString");
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let loaded_dlls: Arc<Mutex<HashSet<OsString>>> = Arc::default();
        let h_module = {
            let watcher = DllWatcher::new(
                {
                    let loaded_dlls = Arc::clone(&loaded_dlls);
                    move |data| {
                        loaded_dlls
                            .lock()
                            .expect("the mutex should not be poisoned")
                            .insert(data.base_dll_name);
                        tx.send(()).expect("channel send should succeed");
                    }
                },
                |_data| (),
            )
            .expect("failed to create DllWatcher");
            watcher.wait_for_initialization(std::time::Duration::from_secs(5));
            // SAFETY: We pass a valid C string in to the function.
            let h_module = unsafe { LoadLibraryA(test_dll_name.as_ptr()) };
            rx.recv_timeout(std::time::Duration::from_secs(5))
                .expect("we should receive the DLL unload event");
            h_module
        };
        assert!(
            !h_module.is_null(),
            "failed to load {}: {}",
            TEST_DLL_NAME_1,
            io::Error::last_os_error()
        );
        let loaded_dlls = loaded_dlls
            .lock()
            .expect("the mutex should not be poisoned");
        assert!(
            !loaded_dlls.is_empty(),
            "no DLL loads recorded by DLL watcher"
        );
        assert!(
            loaded_dlls.contains::<OsString>(&(TEST_DLL_NAME_1.to_owned().into())),
            "{} load wasn't recorded by DLL watcher",
            TEST_DLL_NAME_1
        );
        // SAFETY: We initialized h_module with a LoadLibraryA call.
        let success = unsafe { FreeLibrary(h_module) } > 0;
        assert!(
            success,
            "failed to free {}: {}",
            TEST_DLL_NAME_1,
            io::Error::last_os_error(),
        )
    }

    #[test]
    fn unload_dll() {
        let unloaded_dlls: Arc<Mutex<HashSet<OsString>>> = Arc::default();
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        {
            let test_dll_name = CString::new(TEST_DLL_NAME_2).expect("failed to create CString");
            let watcher = DllWatcher::new(|_data| (), {
                let unloaded_dlls = unloaded_dlls.clone();
                move |data| {
                    unloaded_dlls
                        .lock()
                        .expect("the lock shouldn't be poisoned")
                        .insert(data.base_dll_name);
                    tx.send(()).expect("channel send should success")
                }
            })
            .expect("failed to create DllWatcher");
            watcher.wait_for_initialization(std::time::Duration::from_secs(5));
            // SAFETY: We pass a valid C string in to the function.
            let h_module = unsafe { LoadLibraryA(test_dll_name.as_ptr()) };
            assert!(
                !h_module.is_null(),
                "failed to load {}: {}",
                TEST_DLL_NAME_2,
                io::Error::last_os_error()
            );
            // SAFETY: We initialized h_module with a LoadLibraryA call.
            let success = unsafe { FreeLibrary(h_module) } > 0;
            assert!(
                success,
                "failed to free {}: {}",
                TEST_DLL_NAME_2,
                io::Error::last_os_error(),
            )
        };
        rx.recv_timeout(std::time::Duration::from_secs(5))
            .expect("we should receive the DLL unload event");
        let unloaded_dlls = unloaded_dlls
            .lock()
            .expect("the lock shouldn't be poisoned");
        assert!(
            !unloaded_dlls.is_empty(),
            "no DLL unloads recorded by DLL watcher"
        );
        assert!(
            unloaded_dlls.contains::<OsString>(&(TEST_DLL_NAME_2.to_owned().into())),
            "{} unload wasn't recorded by DLL watcher",
            TEST_DLL_NAME_2
        );
    }
}
