// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::c_void;
use std::ffi::OsString;
use std::io;
use std::ptr;

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

    pub type LdrDllNotification = unsafe extern "C" fn(
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

#[derive(Debug)]
pub struct DllNotificationData {
    pub full_dll_name: OsString,
    pub base_dll_name: OsString,
}

/// Callback context wrapper for DLL load notification functions.
///
/// This struct provides a wrapper for invoking a function-like type any time a
/// DLL is loaded in the current process. This is done in a type-safe way,
/// provided that users of this struct observe some safety invariants.
///
/// # Safety
/// The struct instance must not be used once it has been registered as a
/// notification target. The callback function assumes that it has a mutable
/// reference to the struct instance. Only once the callback is unregistered is
/// it safe to re-use the struct instance.
struct CallbackContext<F1, F2>
where
    F1: FnMut(DllNotificationData),
    F2: FnMut(DllNotificationData),
{
    loaded_callback: F1,
    unloaded_callback: F2,
}

impl<F1, F2> CallbackContext<F1, F2>
where
    F1: FnMut(DllNotificationData),
    F2: FnMut(DllNotificationData),
{
    /// Create a new `CallbackContext` with the two callback functions. Takes
    /// two callbacks, a `loaded_callback` which is called when a DLL is
    /// loaded, and `unloaded_callback` which is called when a DLL is unloaded.
    pub fn new(loaded_callback: F1, unloaded_callback: F2) -> Self {
        CallbackContext {
            loaded_callback,
            unloaded_callback,
        }
    }

    /// Provides a notification function that can be passed to the
    /// `LdrRegisterDllNotification` function.
    pub fn get_notification_function(&self) -> LdrDllNotification {
        Self::notification_function
    }

    /// A notification function with C linkage. This function assumes that it
    /// has exclusive access to the instance of the struct passed through the
    /// `context` parameter.
    extern "C" fn notification_function(
        notification_reason: ULONG,
        notification_data: PLDR_DLL_NOTIFICATION_DATA,
        context: PVOID,
    ) {
        let callback_context =
            // SAFETY: The DLLWatcher guarantees that the CallbackContext instance is not null and
            // that we have exclusive access to it.
            unsafe { (context as *mut Self).as_mut() }.expect("context was null");

        assert!(!notification_data.is_null());

        match notification_reason {
            LDR_DLL_NOTIFICATION_REASON_LOADED => {
                // SAFETY: We know that the LDR_DLL_NOTIFICATION_DATA union contains the
                // LDR_DLL_LOADED_NOTIFICATION_DATA because we got
                // LDR_DLL_NOTIFICATION_REASON_LOADED as the notification reason.
                let loaded = unsafe { &mut (*notification_data).Loaded };

                assert!(!loaded.BaseDllName.is_null());

                // SAFETY: We assert that the pointer is not null and expect that the OS has
                // provided a valid UNICODE_STRING struct.
                let base_dll_name = unsafe { unicode_string_to_os_string(&*loaded.BaseDllName) };

                assert!(!loaded.FullDllName.is_null());

                // SAFETY: We assert that the pointer is not null and expect that the OS has
                // provided a valid UNICODE_STRING struct.
                let full_dll_name = unsafe { unicode_string_to_os_string(&*loaded.FullDllName) };

                (callback_context.loaded_callback)(DllNotificationData {
                    base_dll_name,
                    full_dll_name,
                });
            }
            LDR_DLL_NOTIFICATION_REASON_UNLOADED => {
                // SAFETY: We know that the LDR_DLL_NOTIFICATION_DATA union contains the
                // LDR_DLL_UNLOADED_NOTIFICATION_DATA because we got
                // LDR_DLL_NOTIFICATION_REASON_UNLOADED as the notification reason.
                let unloaded = unsafe { &mut (*notification_data).Unloaded };

                assert!(!unloaded.BaseDllName.is_null());

                // SAFETY: We assert that the pointer is not null and expect that the OS has
                // provided a valid UNICODE_STRING struct.
                let base_dll_name = unsafe { unicode_string_to_os_string(&*unloaded.BaseDllName) };

                assert!(!unloaded.FullDllName.is_null());

                // SAFETY: We assert that the pointer is not null and expect that the OS has
                // provided a valid UNICODE_STRING struct.
                let full_dll_name = unsafe { unicode_string_to_os_string(&*unloaded.FullDllName) };

                (callback_context.unloaded_callback)(DllNotificationData {
                    base_dll_name,
                    full_dll_name,
                })
            }
            n => panic!("invalid value \"{}\" for dll notification reason", n),
        }
    }
}

/// DLL watcher for monitoring DLL loads/unloads.
///
/// Provides a method to invoke a function-like type any time a DLL
/// is loaded or unloaded in the current process.
pub struct DllWatcher<F1, F2>
where
    F1: FnMut(DllNotificationData),
    F2: FnMut(DllNotificationData),
{
    context: Box<CallbackContext<F1, F2>>,
    cookie: Option<ptr::NonNull<c_void>>,
}

impl<F1, F2> DllWatcher<F1, F2>
where
    F1: FnMut(DllNotificationData),
    F2: FnMut(DllNotificationData),
{
    /// Create a new `DllWatcher` with the two callback functions. Takes two
    /// callbacks, a `loaded_callback` which is called when a DLL is loaded,
    /// and `unloaded_callback` which is called when a DLL is unloaded.
    pub fn new(loaded_callback: F1, unloaded_callback: F2) -> io::Result<Self> {
        let mut watcher = Self {
            context: Box::new(CallbackContext::new(loaded_callback, unloaded_callback)),
            cookie: None,
        };
        let mut cookie: PVOID = ptr::null_mut();
        // SAFETY: We guarantee that the notification function that we register will have exclusive
        // access to the context.
        unsafe {
            LdrRegisterDllNotification(
                /* Flags= */ 0,
                /* NotificationFunction= */ watcher.context.get_notification_function(),
                /* Context= */
                &mut *watcher.context as *mut CallbackContext<F1, F2> as PVOID,
                /* Cookie= */ &mut cookie as *mut PVOID,
            )?
        };
        watcher.cookie = ptr::NonNull::new(cookie);
        Ok(watcher)
    }

    fn unregister_dll_notification(&mut self) -> io::Result<()> {
        if let Some(c) = self.cookie.take() {
            // SAFETY: We guarantee that `Cookie` was previously initialized.
            unsafe {
                LdrUnregisterDllNotification(/* Cookie= */ c.as_ptr() as PVOID)?
            }
        }

        Ok(())
    }
}

impl<F1, F2> Drop for DllWatcher<F1, F2>
where
    F1: FnMut(DllNotificationData),
    F2: FnMut(DllNotificationData),
{
    fn drop(&mut self) {
        self.unregister_dll_notification()
            .expect("error unregistering dll notification");
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::ffi::CString;
    use std::io;

    use winapi::shared::minwindef::FALSE;
    use winapi::shared::minwindef::TRUE;
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::libloaderapi::FreeLibrary;
    use winapi::um::libloaderapi::LoadLibraryA;
    use winapi::um::synchapi::CreateEventA;
    use winapi::um::synchapi::SetEvent;
    use winapi::um::synchapi::WaitForSingleObject;
    use winapi::um::winbase::WAIT_OBJECT_0;

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
        let mut loaded_dlls: HashSet<OsString> = HashSet::new();
        let h_module = {
            let _watcher = DllWatcher::new(
                |data| {
                    loaded_dlls.insert(data.base_dll_name);
                },
                |_data| (),
            )
            .expect("failed to create DllWatcher");
            // SAFETY: We pass a valid C string in to the function.
            unsafe { LoadLibraryA(test_dll_name.as_ptr()) }
        };
        assert!(
            !h_module.is_null(),
            "failed to load {}: {}",
            TEST_DLL_NAME_1,
            io::Error::last_os_error()
        );
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
        let mut unloaded_dlls: HashSet<OsString> = HashSet::new();
        let event =
            // SAFETY: No pointers are passed. The handle may leak if the test fails.
            unsafe { CreateEventA(std::ptr::null_mut(), TRUE, FALSE, std::ptr::null_mut()) };
        assert!(
            !event.is_null(),
            "failed to create event; event was NULL: {}",
            io::Error::last_os_error()
        );
        {
            let test_dll_name = CString::new(TEST_DLL_NAME_2).expect("failed to create CString");
            let _watcher = DllWatcher::new(
                |_data| (),
                |data| {
                    unloaded_dlls.insert(data.base_dll_name);
                    // SAFETY: We assert that the event is valid above.
                    unsafe { SetEvent(event) };
                },
            )
            .expect("failed to create DllWatcher");
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
        // SAFETY: We assert that the event is valid above.
        assert_eq!(unsafe { WaitForSingleObject(event, 5000) }, WAIT_OBJECT_0);
        assert!(
            !unloaded_dlls.is_empty(),
            "no DLL unloads recorded by DLL watcher"
        );
        assert!(
            unloaded_dlls.contains::<OsString>(&(TEST_DLL_NAME_2.to_owned().into())),
            "{} unload wasn't recorded by DLL watcher",
            TEST_DLL_NAME_2
        );
        // SAFETY: We assert that the event is valid above.
        unsafe { CloseHandle(event) };
    }
}
