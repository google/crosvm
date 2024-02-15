// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering::SeqCst;

use base::info;
use base::Event;
use libc::c_void;
use winapi::shared::guiddef::IsEqualGUID;
use winapi::shared::guiddef::REFIID;
use winapi::shared::minwindef::ULONG;
use winapi::shared::winerror::E_INVALIDARG;
use winapi::shared::winerror::E_NOINTERFACE;
use winapi::shared::winerror::NOERROR;
use winapi::shared::winerror::S_OK;
use winapi::um::mmdeviceapi::*;
use winapi::um::objidlbase::IAgileObject;
use winapi::um::unknwnbase::IUnknown;
use winapi::um::unknwnbase::IUnknownVtbl;
use winapi::um::winnt::HRESULT;
use winapi::Interface;
use wio::com::ComPtr;

/// This struct is used to create the completion handler `IActivateAudioInterfaceCompletionHandler`
/// that is passed into `ActivateAudioInterfaceAsync`. In other words, the first field in the struct
/// must be `IActivateAudioInterfaceCompletionHandlerVtbl`.
///
/// This struct matches the `IActivateAudioInterfaceCompletionHandler` struct with the addition of
/// the `ref_count` below `lp_vtbl` which is used to keep a reference count to the completion
/// handler.
#[repr(C)]
pub struct WinAudioActivateAudioInterfaceCompletionHandler {
    pub lp_vtbl: &'static IActivateAudioInterfaceCompletionHandlerVtbl,
    ref_count: AtomicU32,
    activate_audio_interface_complete_event: Event,
}

impl WinAudioActivateAudioInterfaceCompletionHandler {
    /// The ComPtr is a `WinAudioActivateAudioInterfaceCompletionHandler` casted as an
    /// `IActivateAudioInterfaceCompletionHandler`.
    pub fn create_com_ptr(
        activate_audio_interface_complete_event: Event,
    ) -> ComPtr<IActivateAudioInterfaceCompletionHandler> {
        let win_completion_handler = Box::new(WinAudioActivateAudioInterfaceCompletionHandler {
            lp_vtbl: IWIN_AUDIO_COMPLETION_HANDLER_VTBL,
            ref_count: AtomicU32::new(1),
            activate_audio_interface_complete_event,
        });

        // This is safe if the value passed into `from_raw` is structured in a way where it can
        // match `IActivateAudioInterfaceCompletionHandler`.
        // Since `win_completion_handler.cast_to_com_ptr()` does, this is safe.
        // Safe because we are passing in a valid COM object that implements `IUnknown` into
        // `from_raw`.
        unsafe {
            ComPtr::from_raw(Box::into_raw(win_completion_handler)
                as *mut IActivateAudioInterfaceCompletionHandler)
        }
    }

    /// Unsafe if `thing` cannot because casted to
    /// `WinAudioActivateAudioInterfaceCompletionHandler`. This is safe because `thing` is
    /// originally a `WinAudioActivateAudioInterfaceCompletionHandler.
    unsafe fn increment_counter(&self) -> ULONG {
        self.ref_count.fetch_add(1, SeqCst) + 1
    }

    fn decrement_counter(&mut self) -> ULONG {
        let old_val = self.ref_count.fetch_sub(1, SeqCst);
        if old_val == 0 {
            panic!("Attempted to decrement WinAudioActivateInterfaceCompletionHandler ref count when it is already 0.");
        }
        old_val - 1
    }

    fn activate_completed(&self) {
        info!("Activate Completed handler called from ActiviateAudioInterfaceAsync.");
        self.activate_audio_interface_complete_event
            .signal()
            .expect("Failed to notify audioclientevent");
    }
}

impl Drop for WinAudioActivateAudioInterfaceCompletionHandler {
    fn drop(&mut self) {
        info!("IActivateAudioInterfaceCompletionHandler is dropped.");
    }
}

/// This is the callback when `ActivateAudioInterfaceAsync` is completed. When this is callback is
/// triggered, the IAudioClient will be available.
/// More info: https://docs.microsoft.com/en-us/windows/win32/api/mmdeviceapi/nf-mmdeviceapi-iactivateaudiointerfacecompletionhandler-activatecompleted
///
/// Safe because we are certain that `completion_handler` can be casted to
/// `WinAudioActivateAudioInterfaceHandler`, since that is its original type during construction.
unsafe extern "system" fn activate_completed(
    completion_handler: *mut IActivateAudioInterfaceCompletionHandler,
    _activate_operation: *mut IActivateAudioInterfaceAsyncOperation,
) -> HRESULT {
    let win_audio_activate_interface =
        completion_handler as *mut WinAudioActivateAudioInterfaceCompletionHandler;
    (*win_audio_activate_interface).activate_completed();

    S_OK
}

const IWIN_AUDIO_COMPLETION_HANDLER_VTBL: &IActivateAudioInterfaceCompletionHandlerVtbl =
    // Implementation based on
    // https://docs.microsoft.com/en-us/office/client-developer/outlook/mapi/implementing-iunknown-in-c-plus-plus
    &IActivateAudioInterfaceCompletionHandlerVtbl {
            parent: IUnknownVtbl {
                QueryInterface: {
                    /// Safe because if `this` is not implemented (fails the RIID check) this
                    /// function will just return. If it valid, it should be
                    /// able to safely increment the ref counter and set the
                    /// pointer `ppv_object`.
                    unsafe extern "system" fn query_interface(
                        this: *mut IUnknown,
                        riid: REFIID,
                        ppv_object: *mut *mut c_void,
                    ) -> HRESULT {
                        if ppv_object.is_null() {
                            return E_INVALIDARG;
                        }

                        *ppv_object = std::ptr::null_mut();

                        // Check for valid RIID's
                        if IsEqualGUID(&*riid, &IUnknown::uuidof())
                            || IsEqualGUID(
                                &*riid,
                                &IActivateAudioInterfaceCompletionHandler::uuidof(),
                            )
                            || IsEqualGUID(&*riid, &IAgileObject::uuidof())
                        {
                            *ppv_object = this as *mut c_void;
                            (*this).AddRef();
                            return NOERROR;
                        }
                        E_NOINTERFACE
                    }
                    query_interface
                },
                AddRef: {
                    /// Unsafe if `this` cannot because casted to
                    /// `WinAudioActivateAudioInterfaceCompletionHandler`.
                    ///
                    /// This is safe because `this` is
                    /// originally a `WinAudioActivateAudioInterfaceCompletionHandler.
                    unsafe extern "system" fn add_ref(this: *mut IUnknown) -> ULONG {
                        info!("Adding ref in IActivateAudioInterfaceCompletionHandler.");
                        let win_audio_completion_handler =
                            this as *mut WinAudioActivateAudioInterfaceCompletionHandler;
                        (*win_audio_completion_handler).increment_counter()
                    }
                    add_ref
                },
                Release: {
                    /// Unsafe if `this` cannot because casted to
                    /// `WinAudioActivateAudioInterfaceCompletionHandler`. Also would be unsafe
                    /// if `release` is called more than `add_ref`.
                    ///
                    /// This is safe because `this` is
                    /// originally a `WinAudioActivateAudioInterfaceCompletionHandler and isn't
                    /// called more than `add_ref`.
                    unsafe extern "system" fn release(this: *mut IUnknown) -> ULONG {
                        info!("Releasing ref in IActivateAudioInterfaceCompletionHandler.");
                        // Decrementing will free the `this` pointer if it's ref_count becomes 0.
                        let win_audio_completion_handler =
                            this as *mut WinAudioActivateAudioInterfaceCompletionHandler;
                        let ref_count = (*win_audio_completion_handler).decrement_counter();
                        if ref_count == 0 {
                            // Delete the pointer
                            drop(Box::from_raw(
                                this as *mut WinAudioActivateAudioInterfaceCompletionHandler,
                            ));
                        }
                        ref_count
                    }
                    release
                },
            },
            ActivateCompleted: activate_completed,
        };

/// `ActivateAudioInterfaceAsync` requires that `IActivateAudioCompletionHandler` to implement
/// `IAgileObject`, which means it is free threaded and can be called from any apartment. These
/// traits should allow it to do that.
unsafe impl Send for WinAudioActivateAudioInterfaceCompletionHandler {}
unsafe impl Sync for WinAudioActivateAudioInterfaceCompletionHandler {}

#[cfg(test)]
mod test {
    use base::EventExt;

    use super::*;

    #[test]
    fn test_query_interface_valid() {
        let completion_handler = WinAudioActivateAudioInterfaceCompletionHandler::create_com_ptr(
            Event::new_auto_reset().unwrap(),
        );
        let invalid_ref_iid = IUnknown::uuidof();
        let mut null_value = std::ptr::null_mut();
        let ppv_object: *mut *mut c_void = &mut null_value;

        // Calling `QueryInterface`
        let res = unsafe {
            ((*completion_handler.lpVtbl).parent.QueryInterface)(
                completion_handler.as_raw() as *mut IUnknown,
                &invalid_ref_iid,
                ppv_object,
            )
        };
        assert_eq!(res, NOERROR);

        // Release the reference from `QueryInteface` by calling `Release`
        release(&completion_handler);

        let invalid_ref_iid = IActivateAudioInterfaceCompletionHandler::uuidof();
        let res = unsafe {
            ((*completion_handler.lpVtbl).parent.QueryInterface)(
                completion_handler.as_raw() as *mut IUnknown,
                &invalid_ref_iid,
                ppv_object,
            )
        };
        assert_eq!(res, NOERROR);

        release(&completion_handler);

        let invalid_ref_iid = IAgileObject::uuidof();
        let res = unsafe {
            ((*completion_handler.lpVtbl).parent.QueryInterface)(
                completion_handler.as_raw() as *mut IUnknown,
                &invalid_ref_iid,
                ppv_object,
            )
        };
        release(&completion_handler);
        assert_eq!(res, NOERROR);
    }

    #[test]
    fn test_query_interface_invalid() {
        let completion_handler = WinAudioActivateAudioInterfaceCompletionHandler::create_com_ptr(
            Event::new_auto_reset().unwrap(),
        );
        let invalid_ref_iid = IMMDeviceCollection::uuidof();
        let mut null_value = std::ptr::null_mut();
        let ppv_object: *mut *mut c_void = &mut null_value;

        // Call `QueryInterface`
        let res = unsafe {
            ((*completion_handler.lpVtbl).parent.QueryInterface)(
                completion_handler.as_raw() as *mut IUnknown,
                &invalid_ref_iid,
                ppv_object,
            )
        };
        assert_eq!(res, E_NOINTERFACE)
    }

    #[test]
    fn test_add_ref() {
        // ref_count = 1
        let completion_handler = WinAudioActivateAudioInterfaceCompletionHandler::create_com_ptr(
            Event::new_auto_reset().unwrap(),
        );
        // ref_count = 2
        let ref_count = add_ref(&completion_handler);
        assert_eq!(ref_count, 2);
        // ref_count = 1
        release(&completion_handler);
        // ref_count = 0 since ComPtr drops
    }

    #[test]
    fn test_release() {
        // ref_count = 1
        let completion_handler = WinAudioActivateAudioInterfaceCompletionHandler::create_com_ptr(
            Event::new_auto_reset().unwrap(),
        );
        // ref_count = 2
        let ref_count = add_ref(&completion_handler);
        assert_eq!(ref_count, 2);
        // ref_count = 1
        let ref_count = release(&completion_handler);
        assert_eq!(ref_count, 1);
        // ref_count = 0 since ComPtr drops
    }

    fn release(completion_handler: &ComPtr<IActivateAudioInterfaceCompletionHandler>) -> ULONG {
        unsafe {
            ((*completion_handler.lpVtbl).parent.Release)(
                completion_handler.as_raw() as *mut IUnknown
            )
        }
    }

    fn add_ref(completion_handler: &ComPtr<IActivateAudioInterfaceCompletionHandler>) -> ULONG {
        unsafe {
            ((*completion_handler.lpVtbl).parent.AddRef)(
                completion_handler.as_raw() as *mut IUnknown
            )
        }
    }
}
