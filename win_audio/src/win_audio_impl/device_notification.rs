// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering::SeqCst;
use std::sync::Arc;

use base::info;
use libc::c_void;
use winapi::shared::guiddef::IsEqualGUID;
use winapi::shared::guiddef::REFIID;
use winapi::shared::minwindef::DWORD;
use winapi::shared::minwindef::ULONG;
use winapi::shared::winerror::E_INVALIDARG;
use winapi::shared::winerror::E_NOINTERFACE;
use winapi::shared::winerror::NOERROR;
use winapi::shared::wtypes::PROPERTYKEY;
use winapi::um::mmdeviceapi::EDataFlow;
use winapi::um::mmdeviceapi::ERole;
use winapi::um::mmdeviceapi::IMMNotificationClient;
use winapi::um::mmdeviceapi::IMMNotificationClientVtbl;
use winapi::um::objidlbase::IAgileObject;
use winapi::um::unknwnbase::IUnknown;
use winapi::um::unknwnbase::IUnknownVtbl;
use winapi::um::winnt::HRESULT;
use winapi::um::winnt::LPCWSTR;
use winapi::Interface;
use wio::com::ComPtr;

/// This device notification client will be used to notify win_audio when a new audio device is
/// available. This notification client will only be registered when there are
/// no audio devices detected.
#[repr(C)]
pub(crate) struct WinIMMNotificationClient {
    pub lp_vtbl: &'static IMMNotificationClientVtbl,
    ref_count: AtomicU32,
    // Shared with `WinAudioRenderer`. This will used in `next_playback_buffer` only when
    // `NoopStream` is being used. When this is set the `true`, `WinAudioRenderer` will attempt
    // to create a new `DeviceRenderer`.
    device_available: Arc<AtomicBool>,
    data_flow: EDataFlow,
}

impl WinIMMNotificationClient {
    /// The ComPtr is a `WinIMMNotificationClient` casted as an `IMMNotificationClient`.
    pub(crate) fn create_com_ptr(
        device_available: Arc<AtomicBool>,
        data_flow: EDataFlow,
    ) -> ComPtr<IMMNotificationClient> {
        let win_imm_notification_client = Box::new(WinIMMNotificationClient {
            lp_vtbl: IMM_NOTIFICATION_CLIENT_VTBL,
            ref_count: AtomicU32::new(1),
            device_available,
            data_flow,
        });

        // This is safe if the value passed into `from_raw` is structured in a way where it can
        // match `IMMNotificationClient`. Since `win_imm_notification_client.cast_to_com_ptr()`
        // does, this is safe.
        //
        // Safe because we are passing in a valid COM object that implements `IUnknown` into
        // `from_raw`.
        unsafe {
            ComPtr::from_raw(
                Box::into_raw(win_imm_notification_client) as *mut IMMNotificationClient
            )
        }
    }

    fn increment_counter(&self) -> ULONG {
        self.ref_count.fetch_add(1, SeqCst) + 1
    }

    fn decrement_counter(&mut self) -> ULONG {
        let old_val = self.ref_count.fetch_sub(1, SeqCst);
        assert_ne!(
            old_val, 0,
            "Attempted to decrement WinIMMNotificationClient ref count when it \
        is already 0."
        );
        old_val - 1
    }
}

impl Drop for WinIMMNotificationClient {
    fn drop(&mut self) {
        info!("IMMNotificationClient is dropped.");
    }
}

// TODO(b/274146821): Factor out common IUnknown code between here and `completion_handler.rs`.
const IMM_NOTIFICATION_CLIENT_VTBL: &IMMNotificationClientVtbl = {
    &IMMNotificationClientVtbl {
        parent: IUnknownVtbl {
            QueryInterface: {
                /// Safe because if `this` is not implemented (fails the RIID check) this function
                /// will just return. If it valid, it should be able to safely increment the ref
                /// counter and set the pointer `ppv_object`.
                unsafe extern "system" fn query_interface(
                    this: *mut IUnknown,
                    riid: REFIID,
                    ppv_object: *mut *mut c_void,
                ) -> HRESULT {
                    info!("querying ref in IMMNotificationClient.");
                    if ppv_object.is_null() {
                        return E_INVALIDARG;
                    }

                    *ppv_object = std::ptr::null_mut();

                    // Check for valid RIID's
                    if IsEqualGUID(&*riid, &IUnknown::uuidof())
                        || IsEqualGUID(&*riid, &IMMNotificationClient::uuidof())
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
                /// Unsafe if `this` cannot be casted to `WinIMMNotificationClient`.
                ///
                /// This is safe because `this` is originally a `WinIMMNotificationClient`.
                unsafe extern "system" fn add_ref(this: *mut IUnknown) -> ULONG {
                    info!("Adding ref in IMMNotificationClient.");
                    let win_imm_notification_client = this as *mut WinIMMNotificationClient;
                    (*win_imm_notification_client).increment_counter()
                }
                add_ref
            },
            Release: {
                /// Unsafe if `this` cannot because casted to `WinIMMNotificationClient`. Also
                /// would be unsafe if `release` is called more than `add_ref`.
                ///
                /// This is safe because `this` is
                /// originally a `WinIMMNotificationClient` and isn't called
                /// more than `add_ref`.
                unsafe extern "system" fn release(this: *mut IUnknown) -> ULONG {
                    info!("Releasing ref in IMMNotificationClient.");
                    // Decrementing will free the `this` pointer if it's ref_count becomes 0.
                    let win_imm_notification_client = this as *mut WinIMMNotificationClient;
                    let ref_count = (*win_imm_notification_client).decrement_counter();
                    if ref_count == 0 {
                        // Delete the pointer
                        drop(Box::from_raw(this as *mut WinIMMNotificationClient));
                    }
                    ref_count
                }
                release
            },
        },
        OnDeviceStateChanged: on_device_state_change,
        OnDeviceAdded: on_device_added,
        OnDeviceRemoved: on_device_removed,
        OnDefaultDeviceChanged: on_default_device_changed,
        OnPropertyValueChanged: on_property_value_changed,
    }
};

unsafe extern "system" fn on_device_state_change(
    _this: *mut IMMNotificationClient,
    _pwstr_device_id: LPCWSTR,
    _dw_new_state: DWORD,
) -> HRESULT {
    info!("IMMNotificationClient: on_device_state_change called");
    0
}

/// Indicates that an audio enpoint device has been added. In practice, I have not seen this get
/// triggered, even if I add an audio device.
///
/// # Safety
/// This is safe because this callback does nothing except for logging.
unsafe extern "system" fn on_device_added(
    _this: *mut IMMNotificationClient,
    _pwstr_device_id: LPCWSTR,
) -> HRESULT {
    info!("IMMNotificationClient: on_device_added called");
    0
}

/// Indicates that an audio enpoint device has been removed. In practice, I have not seen this get
/// triggered, even if I unplug an audio device.
///
/// # Safety
/// This is safe because this callback does nothing except for logging.
unsafe extern "system" fn on_device_removed(
    _this: *mut IMMNotificationClient,
    _pwstr_device_id: LPCWSTR,
) -> HRESULT {
    info!("IMMNotificationClient: on_device_removed called");
    0
}

/// Indicates that the default device has changed. In practice, this callback seemed reliable to
/// tell us when a new audio device has been added when no devices were previously present.
///
/// # Safety
/// Safe because we know `IMMNotificationClient` was originally a `WinIMMNotificationClient`,
/// so we can cast safely.
unsafe extern "system" fn on_default_device_changed(
    this: *mut IMMNotificationClient,
    flow: EDataFlow,
    _role: ERole,
    _pwstr_default_device_id: LPCWSTR,
) -> HRESULT {
    info!("IMMNotificationClient: on_default_device_changed called");
    let win = &*(this as *mut WinIMMNotificationClient);
    if flow == win.data_flow {
        base::info!("New device found");
        win.device_available.store(true, SeqCst);
    }
    0
}

/// Indicates that a property in an audio endpoint device has changed. In practice, this callback
/// gets spammed a lot and the information provided isn't useful.
///
/// # Safety
/// This is safe because this callback does nothing.
unsafe extern "system" fn on_property_value_changed(
    _this: *mut IMMNotificationClient,
    _pwstr_device_id: LPCWSTR,
    _key: PROPERTYKEY,
) -> HRESULT {
    0
}

/// The following tests the correctness of the COM object implementation. It won't test for
/// notifications of new devices.
#[cfg(test)]
mod test {
    use winapi::um::mmdeviceapi::eCapture;
    use winapi::um::mmdeviceapi::eRender;
    use winapi::um::mmdeviceapi::IMMDeviceCollection;

    use super::*;

    #[test]
    fn test_query_interface_valid() {
        let notification_client =
            WinIMMNotificationClient::create_com_ptr(Arc::new(AtomicBool::new(false)), eRender);
        let valid_ref_iid = IUnknown::uuidof();
        let mut ppv_object: *mut c_void = std::ptr::null_mut();

        // Calling `QueryInterface`
        let res = unsafe {
            ((*notification_client.lpVtbl).parent.QueryInterface)(
                notification_client.as_raw() as *mut IUnknown,
                &valid_ref_iid,
                &mut ppv_object,
            )
        };
        assert_eq!(res, NOERROR);

        // Release the reference from `QueryInteface` by calling `Release`
        release(&notification_client);

        let valid_ref_iid = IMMNotificationClient::uuidof();
        let res = unsafe {
            ((*notification_client.lpVtbl).parent.QueryInterface)(
                notification_client.as_raw() as *mut IUnknown,
                &valid_ref_iid,
                &mut ppv_object,
            )
        };
        assert_eq!(res, NOERROR);

        release(&notification_client);

        let valid_ref_iid = IAgileObject::uuidof();
        let res = unsafe {
            ((*notification_client.lpVtbl).parent.QueryInterface)(
                notification_client.as_raw() as *mut IUnknown,
                &valid_ref_iid,
                &mut ppv_object,
            )
        };
        release(&notification_client);
        assert_eq!(res, NOERROR);
    }

    #[test]
    fn test_query_interface_invalid() {
        let notification_client =
            WinIMMNotificationClient::create_com_ptr(Arc::new(AtomicBool::new(false)), eRender);
        let invalid_ref_iid = IMMDeviceCollection::uuidof();
        let mut ppv_object: *mut c_void = std::ptr::null_mut();

        // Call `QueryInterface`
        let res = unsafe {
            ((*notification_client.lpVtbl).parent.QueryInterface)(
                notification_client.as_raw() as *mut IUnknown,
                &invalid_ref_iid,
                &mut ppv_object,
            )
        };
        assert_eq!(res, E_NOINTERFACE)
    }

    #[test]
    fn test_release() {
        // ref_count = 1
        let notification_client =
            WinIMMNotificationClient::create_com_ptr(Arc::new(AtomicBool::new(false)), eCapture);
        // ref_count = 2
        let ref_count = add_ref(&notification_client);
        assert_eq!(ref_count, 2);
        // ref_count = 1
        let ref_count = release(&notification_client);
        assert_eq!(ref_count, 1);
        // ref_count = 0 since ComPtr drops
    }

    fn release(notification_client: &ComPtr<IMMNotificationClient>) -> ULONG {
        unsafe {
            ((*notification_client.lpVtbl).parent.Release)(
                notification_client.as_raw() as *mut IUnknown
            )
        }
    }

    fn add_ref(notification_client: &ComPtr<IMMNotificationClient>) -> ULONG {
        unsafe {
            ((*notification_client.lpVtbl).parent.AddRef)(
                notification_client.as_raw() as *mut IUnknown
            )
        }
    }
}
