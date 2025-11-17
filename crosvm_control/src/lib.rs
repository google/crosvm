// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Provides parts of crosvm as a library to communicate with running crosvm instances.
//!
//! This crate is a programmatic alternative to invoking crosvm with subcommands that produce the
//! result on stdout.
//!
//! Downstream projects rely on this library maintaining a stable API surface.
//! Do not make changes to this library without consulting the crosvm externalization team.
//! Email: <crosvm-dev@chromium.org>
//!
//! The API of this library should remain the same regardless of which crosvm features are enabled.
//! Any missing functionality should be handled by returning an error at runtime, not conditional
//! compilation, so that users can rely on the the same set of functions with the same prototypes
//! regardless of how crosvm is configured.
//!
//! For more information see:
//! <https://crosvm.dev/book/running_crosvm/programmatic_interaction.html#usage>

use std::convert::TryFrom;
use std::convert::TryInto;
use std::ffi::CStr;
use std::panic::catch_unwind;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use balloon_control::BalloonStats;
use balloon_control::BalloonWS;
use balloon_control::WSBucket;
use base::descriptor::IntoRawDescriptor;
use base::FromRawDescriptor;
use base::SafeDescriptor;
use libc::c_char;
use libc::c_int;
use libc::c_void;
use libc::ssize_t;
pub use swap::SwapStatus;
use vm_control::client::do_modify_battery;
use vm_control::client::do_net_add;
use vm_control::client::do_net_remove;
use vm_control::client::do_security_key_attach;
use vm_control::client::do_snd_mute_all;
use vm_control::client::do_usb_attach;
use vm_control::client::do_usb_detach;
use vm_control::client::do_usb_list;
use vm_control::client::handle_request;
use vm_control::client::handle_request_with_timeout;
use vm_control::client::vms_request;
use vm_control::BalloonControlCommand;
use vm_control::BatProperty;
use vm_control::DiskControlCommand;
use vm_control::HypervisorKind;
use vm_control::RegisteredEvent;
use vm_control::SwapCommand;
use vm_control::UsbControlAttachedDevice;
use vm_control::UsbControlResult;
use vm_control::VmRequest;
use vm_control::VmResponse;
use vm_control::USB_CONTROL_MAX_PORTS;

pub const VIRTIO_BALLOON_WS_MAX_NUM_BINS: usize = 16;
pub const VIRTIO_BALLOON_WS_MAX_NUM_INTERVALS: usize = 15;

/// # Safety
///
/// This function is safe when the caller ensures the socket_path raw pointer can be safely passed
/// to `CStr::from_ptr()`.
unsafe fn validate_socket_path(socket_path: *const c_char) -> Option<PathBuf> {
    if !socket_path.is_null() {
        let socket_path = CStr::from_ptr(socket_path);
        Some(PathBuf::from(socket_path.to_str().ok()?))
    } else {
        None
    }
}

/// Stops the crosvm instance whose control socket is listening on `socket_path`.
///
/// The function returns true on success or false if an error occurred.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - `socket_path` should be a non-null pointer to a
/// C string that is valid and not modified for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn crosvm_client_stop_vm(socket_path: *const c_char) -> bool {
    catch_unwind(|| {
        if let Some(socket_path) = validate_socket_path(socket_path) {
            vms_request(&VmRequest::Exit, socket_path).is_ok()
        } else {
            false
        }
    })
    .unwrap_or(false)
}

/// Suspends the crosvm instance whose control socket is listening on `socket_path`.
///
/// The function returns true on success or false if an error occurred.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - `socket_path` should be a non-null pointer to a
/// C string that is valid and not modified for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn crosvm_client_suspend_vm(socket_path: *const c_char) -> bool {
    catch_unwind(|| {
        if let Some(socket_path) = validate_socket_path(socket_path) {
            vms_request(&VmRequest::SuspendVcpus, socket_path).is_ok()
        } else {
            false
        }
    })
    .unwrap_or(false)
}

/// Resumes the crosvm instance whose control socket is listening on `socket_path`.
///
/// Note: this function just resumes vcpus of the vm. If you need to perform a full resume, call
/// crosvm_client_resume_vm_full.
///
/// The function returns true on success or false if an error occurred.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - `socket_path` should be a non-null pointer to a
/// C string that is valid for reads and not modified for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn crosvm_client_resume_vm(socket_path: *const c_char) -> bool {
    catch_unwind(|| {
        if let Some(socket_path) = validate_socket_path(socket_path) {
            vms_request(&VmRequest::ResumeVcpus, socket_path).is_ok()
        } else {
            false
        }
    })
    .unwrap_or(false)
}

/// Resumes the crosvm instance whose control socket is listening on `socket_path`.
///
/// Note: unlike crosvm_client_resume_vm, this function resumes both vcpus and devices.
///
/// The function returns true on success or false if an error occurred.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - `socket_path` should be a non-null pointer to a
/// C string that is valid for reads and not modified for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn crosvm_client_resume_vm_full(socket_path: *const c_char) -> bool {
    catch_unwind(|| {
        if let Some(socket_path) = validate_socket_path(socket_path) {
            vms_request(&VmRequest::ResumeVm, socket_path).is_ok()
        } else {
            false
        }
    })
    .unwrap_or(false)
}

/// Creates an RT vCPU for the crosvm instance whose control socket is listening on `socket_path`.
///
/// The function returns true on success or false if an error occurred.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - `socket_path` should be a non-null pointer to a
/// C string that is valid for reads and not modified for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn crosvm_client_make_rt_vm(socket_path: *const c_char) -> bool {
    catch_unwind(|| {
        if let Some(socket_path) = validate_socket_path(socket_path) {
            vms_request(&VmRequest::MakeRT, socket_path).is_ok()
        } else {
            false
        }
    })
    .unwrap_or(false)
}

/// Adjusts the balloon size of the crosvm instance whose control socket is
/// listening on `socket_path`.
///
/// The function returns true on success or false if an error occurred.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - `socket_path` should be a non-null pointer to a
/// C string that is valid for reads and not modified for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn crosvm_client_balloon_vms(
    socket_path: *const c_char,
    num_bytes: u64,
) -> bool {
    catch_unwind(|| {
        if let Some(socket_path) = validate_socket_path(socket_path) {
            let command = BalloonControlCommand::Adjust {
                num_bytes,
                wait_for_success: false,
            };
            vms_request(&VmRequest::BalloonCommand(command), socket_path).is_ok()
        } else {
            false
        }
    })
    .unwrap_or(false)
}

/// See crosvm_client_balloon_vms.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - `socket_path` should be a non-null pointer to a
/// C string that is valid for reads and not modified for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn crosvm_client_balloon_vms_wait_with_timeout(
    socket_path: *const c_char,
    num_bytes: u64,
    timeout_ms: u64,
) -> bool {
    catch_unwind(|| {
        if let Some(socket_path) = validate_socket_path(socket_path) {
            let command = BalloonControlCommand::Adjust {
                num_bytes,
                wait_for_success: true,
            };
            let resp = handle_request_with_timeout(
                &VmRequest::BalloonCommand(command),
                socket_path,
                Some(Duration::from_millis(timeout_ms)),
            );
            if matches!(resp, Ok(VmResponse::Ok)) {
                return true;
            }
            println!("adjust failure: {resp:?}");
        }
        false
    })
    .unwrap_or(false)
}

/// Mute or unmute all snd devices of the crosvm instance whose control socket is
/// listening on `socket_path`.
///
/// The function returns true on success or false if an error occurred.
///
/// # Safety
///
/// The caller will ensure the raw pointers in arguments passed in can be safely used by
/// `CStr::from_ptr()`
#[no_mangle]
pub unsafe extern "C" fn crosvm_client_snd_mute_all(
    socket_path: *const c_char,
    muted: bool,
) -> bool {
    catch_unwind(|| {
        if let Some(socket_path) = validate_socket_path(socket_path) {
            do_snd_mute_all(socket_path, muted).is_ok()
        } else {
            false
        }
    })
    .unwrap_or(false)
}

/// Enable vmm swap for crosvm instance whose control socket is listening on `socket_path`.
///
/// The function returns true on success or false if an error occurred.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - `socket_path` should be a non-null pointer to a
/// C string that is valid for reads and not modified for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn crosvm_client_swap_enable_vm(socket_path: *const c_char) -> bool {
    catch_unwind(|| {
        if let Some(socket_path) = validate_socket_path(socket_path) {
            vms_request(&VmRequest::Swap(SwapCommand::Enable), socket_path).is_ok()
        } else {
            false
        }
    })
    .unwrap_or(false)
}

/// Swap out staging memory for crosvm instance whose control socket is listening
/// on `socket_path`.
///
/// The function returns true on success or false if an error occurred.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - `socket_path` should be a non-null pointer to a
/// C string that is valid for reads and not modified for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn crosvm_client_swap_swapout_vm(socket_path: *const c_char) -> bool {
    catch_unwind(|| {
        if let Some(socket_path) = validate_socket_path(socket_path) {
            vms_request(&VmRequest::Swap(SwapCommand::SwapOut), socket_path).is_ok()
        } else {
            false
        }
    })
    .unwrap_or(false)
}

/// Arguments structure for crosvm_client_swap_disable_vm2.
#[repr(C)]
pub struct SwapDisableArgs {
    /// The path of the control socket to target.
    pub socket_path: *const c_char,
    /// Whether or not the swap file should be cleaned up in the background.
    pub slow_file_cleanup: bool,
}

/// Disable vmm swap according to `args`.
///
/// The function returns true on success or false if an error occurred.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - `socket_path` should be a non-null pointer to a
/// `SwapDisableArgs` instance valid for writes that is not externally modified for the duration of
/// this call.
#[no_mangle]
pub unsafe extern "C" fn crosvm_client_swap_disable_vm(args: *mut SwapDisableArgs) -> bool {
    catch_unwind(|| {
        if args.is_null() {
            return false;
        }
        let Some(socket_path) = validate_socket_path((*args).socket_path) else {
            return false;
        };
        vms_request(
            &VmRequest::Swap(SwapCommand::Disable {
                slow_file_cleanup: (*args).slow_file_cleanup,
            }),
            socket_path,
        )
        .is_ok()
    })
    .unwrap_or(false)
}

/// Trim staging memory for vmm swap for crosvm instance whose control socket is listening on
/// `socket_path`.
///
/// The function returns true on success or false if an error occurred.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - `socket_path` should be a non-null pointer to a
/// C string that is valid for reads and not modified for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn crosvm_client_swap_trim(socket_path: *const c_char) -> bool {
    catch_unwind(|| {
        if let Some(socket_path) = validate_socket_path(socket_path) {
            vms_request(&VmRequest::Swap(SwapCommand::Trim), socket_path).is_ok()
        } else {
            false
        }
    })
    .unwrap_or(false)
}

/// Returns vmm-swap status of the crosvm instance whose control socket is listening on
/// `socket_path`.
///
/// The parameters `status` is optional and will only be written to if they are non-null.
///
/// The function returns true on success or false if an error occurred.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - `socket_path` should be a non-null pointer to a C
/// string that is valid for reads and not modified for the duration of the call, and that `status`
/// is a non-null pointer to a `SwapStatus` valid for writes that is not externally modified for
/// the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn crosvm_client_swap_status(
    socket_path: *const c_char,
    status: *mut SwapStatus,
) -> bool {
    catch_unwind(|| {
        if let Some(socket_path) = validate_socket_path(socket_path) {
            let request = &VmRequest::Swap(SwapCommand::Status);
            if let Ok(VmResponse::SwapStatus(response)) = handle_request(request, socket_path) {
                if !status.is_null() {
                    // SAFETY: just checked that `status` is not null.
                    unsafe {
                        *status = response;
                    }
                }
                true
            } else {
                false
            }
        } else {
            false
        }
    })
    .unwrap_or(false)
}

/// Represents an individual attached USB device.
#[repr(C)]
pub struct UsbDeviceEntry {
    /// Internal port index used for identifying this individual device.
    pub port: u8,
    /// USB vendor ID
    pub vendor_id: u16,
    /// USB product ID
    pub product_id: u16,
}

impl From<&UsbControlAttachedDevice> for UsbDeviceEntry {
    fn from(other: &UsbControlAttachedDevice) -> Self {
        Self {
            port: other.port,
            vendor_id: other.vendor_id,
            product_id: other.product_id,
        }
    }
}

/// Simply returns the maximum possible number of USB devices
#[no_mangle]
pub extern "C" fn crosvm_client_max_usb_devices() -> usize {
    USB_CONTROL_MAX_PORTS
}

/// Returns all USB devices passed through the crosvm instance whose control socket is listening on
/// `socket_path`.
///
/// The function returns the amount of entries written.
/// # Arguments
///
/// * `socket_path` - Path to the crosvm control socket
/// * `entries` - Pointer to an array of `UsbDeviceEntry` where the details about the attached
///   devices will be written to
/// * `entries_length` - Amount of entries in the array specified by `entries`
///
/// Use the value returned by [`crosvm_client_max_usb_devices()`] to determine the size of the input
/// array to this function.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - `socket_path` should be a non-null pointer to a C
/// string that is valid and for reads and not modified for the duration of the call. `entries`
/// should be a valid pointer to an array of `UsbDeviceEntry` valid for writes that contains at
/// least `entries_length` elements and is not externally modified for the duration of this call.
#[no_mangle]
pub unsafe extern "C" fn crosvm_client_usb_list(
    socket_path: *const c_char,
    entries: *mut UsbDeviceEntry,
    entries_length: ssize_t,
) -> ssize_t {
    catch_unwind(|| {
        if let Some(socket_path) = validate_socket_path(socket_path) {
            if entries.is_null() {
                return -1;
            }
            if let Ok(UsbControlResult::Devices(res)) = do_usb_list(socket_path) {
                let mut i = 0;
                for entry in res.iter().filter(|x| x.valid()) {
                    if i >= entries_length {
                        break;
                    }
                    // SAFETY: checked that `entries` is not null.
                    unsafe {
                        *entries.offset(i) = entry.into();
                        i += 1;
                    }
                }
                i
            } else {
                -1
            }
        } else {
            -1
        }
    })
    .unwrap_or(-1)
}

/// Attaches an USB device to crosvm instance whose control socket is listening on `socket_path`.
///
/// The function returns the amount of entries written.
/// # Arguments
///
/// * `socket_path` - Path to the crosvm control socket
/// * `bus` - USB device bus ID (unused)
/// * `addr` - USB device address (unused)
/// * `vid` - USB device vendor ID (unused)
/// * `pid` - USB device product ID (unused)
/// * `dev_path` - Path to the USB device (Most likely `/dev/bus/usb/<bus>/<addr>`).
/// * `out_port` - (optional) internal port will be written here if provided.
///
/// The function returns true on success or false if an error occurred.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage.
/// Trivial !raw_pointer.is_null() checks prevent some unsafe behavior, but the caller should
/// ensure no null pointers are passed into the function.
///
/// The safety requirements for `socket_path` and `dev_path` are the same as the ones from
/// `CStr::from_ptr()`. `out_port` should be a non-null pointer that points to a writable 1byte
/// region.
#[no_mangle]
pub unsafe extern "C" fn crosvm_client_usb_attach(
    socket_path: *const c_char,
    _bus: u8,
    _addr: u8,
    _vid: u16,
    _pid: u16,
    dev_path: *const c_char,
    out_port: *mut u8,
) -> bool {
    catch_unwind(|| {
        if let Some(socket_path) = validate_socket_path(socket_path) {
            if dev_path.is_null() {
                return false;
            }
            // SAFETY: just checked that `dev_path` is not null.
            let dev_path = Path::new(unsafe { CStr::from_ptr(dev_path) }.to_str().unwrap_or(""));

            if let Ok(UsbControlResult::Ok { port }) = do_usb_attach(socket_path, dev_path) {
                if !out_port.is_null() {
                    // SAFETY: trivially safe
                    unsafe { *out_port = port };
                }
                true
            } else {
                false
            }
        } else {
            false
        }
    })
    .unwrap_or(false)
}

/// Attaches a u2f security key to crosvm instance whose control socket is listening on
/// `socket_path`.
///
/// The function returns the amount of entries written.
/// # Arguments
///
/// * `socket_path` - Path to the crosvm control socket
/// * `hidraw_path` - Path to the hidraw device of the security key (like `/dev/hidraw0`)
/// * `out_port` - (optional) internal port will be written here if provided.
///
/// The function returns true on success or false if an error occurred.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage.
/// Trivial !raw_pointer.is_null() checks prevent some unsafe behavior, but the caller should
/// ensure no null pointers are passed into the function.
///
/// The safety requirements for `socket_path` and `hidraw_path` are the same as the ones from
/// `CStr::from_ptr()`. `out_port` should be a non-null pointer that points to a writable 1byte
/// region.
#[no_mangle]
pub unsafe extern "C" fn crosvm_client_security_key_attach(
    socket_path: *const c_char,
    hidraw_path: *const c_char,
    out_port: *mut u8,
) -> bool {
    catch_unwind(|| {
        if let Some(socket_path) = validate_socket_path(socket_path) {
            if hidraw_path.is_null() {
                return false;
            }
            let hidraw_path = Path::new(
                // SAFETY: just checked that `hidraw_path` is not null.
                unsafe { CStr::from_ptr(hidraw_path) }
                    .to_str()
                    .unwrap_or(""),
            );

            if let Ok(UsbControlResult::Ok { port }) =
                do_security_key_attach(socket_path, hidraw_path)
            {
                if !out_port.is_null() {
                    // SAFETY: trivially safe
                    unsafe { *out_port = port };
                }
                true
            } else {
                false
            }
        } else {
            false
        }
    })
    .unwrap_or(false)
}

/// Detaches an USB device from crosvm instance whose control socket is listening on `socket_path`.
/// `port` determines device to be detached.
///
/// The function returns true on success or false if an error occurred.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - `socket_path` should be a non-null pointer to a
/// C string that is valid for reads and not modified for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn crosvm_client_usb_detach(socket_path: *const c_char, port: u8) -> bool {
    catch_unwind(|| {
        if let Some(socket_path) = validate_socket_path(socket_path) {
            do_usb_detach(socket_path, port).is_ok()
        } else {
            false
        }
    })
    .unwrap_or(false)
}

/// Attaches a net tap device to the crosvm instance with control socket at `socket_path`.
///
/// # Arguments
///
/// * `socket_path` - Path to the crosvm control socket
/// * `tap_name` - Name of the tap device
/// * `out_bus_num` - guest bus number will be written here
///
/// The function returns true on success, false on failure.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - socket_path and tap_name are assumed to point to a
/// null-terminated CStr. Function checks that the pointers are not null, but caller need to check
/// the validity of the pointer. out_bus_num is assumed to point to a u8 integer.
#[no_mangle]
pub unsafe extern "C" fn crosvm_client_net_tap_attach(
    socket_path: *const c_char,
    tap_name: *const c_char,
    out_bus_num: *mut u8,
) -> bool {
    catch_unwind(|| {
        if let Some(socket_path) = validate_socket_path(socket_path) {
            if tap_name.is_null() || out_bus_num.is_null() {
                return false;
            }
            // SAFETY: just checked that `tap_name` is not null. Function caller guarantees it
            // points to a valid CStr.
            let tap_name = unsafe { CStr::from_ptr(tap_name) }.to_str().unwrap_or("");

            match do_net_add(tap_name, socket_path) {
                Ok(bus_num) => {
                    // SAFETY: checked out_bus_num is not null. Function caller guarantees
                    // validity of pointer.
                    unsafe { *out_bus_num = bus_num };
                    true
                }
                Err(_e) => false,
            }
        } else {
            false
        }
    })
    .unwrap_or(false)
}

/// Detaches a hotplugged tap device from the crosvm instance with control socket at `socket_path`.
///
/// # Arguments
///
/// * `socket_path` - Path to the crosvm control socket
/// * `bus_num` - Bus number of the tap device to be removed.
///
/// The function returns true on success, and false on failure.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - socket_path is assumed to point to a
/// null-terminated Cstr. Function checks that the pointers are not null, but caller need to check
/// the validity of the pointer.
#[no_mangle]
pub unsafe extern "C" fn crosvm_client_net_tap_detach(
    socket_path: *const c_char,
    bus_num: u8,
) -> bool {
    catch_unwind(|| {
        if let Some(socket_path) = validate_socket_path(socket_path) {
            match do_net_remove(bus_num, socket_path) {
                Ok(()) => true,
                Err(_e) => false,
            }
        } else {
            false
        }
    })
    .unwrap_or(false)
}

/// Modifies the battery status of crosvm instance whose control socket is listening on
/// `socket_path`.
///
/// The function returns true on success or false if an error occurred.
///
/// # Safety
///
/// The caller will ensure the raw pointers in arguments passed in can be safely used by
/// `CStr::from_ptr()`
#[no_mangle]
pub unsafe extern "C" fn crosvm_client_modify_battery(
    socket_path: *const c_char,
    battery_type: *const c_char,
    property: *const c_char,
    target: *const c_char,
) -> bool {
    catch_unwind(|| {
        if let Some(socket_path) = validate_socket_path(socket_path) {
            if battery_type.is_null() || property.is_null() || target.is_null() {
                return false;
            }
            // SAFETY: trivially safe
            let battery_type = unsafe { CStr::from_ptr(battery_type) };
            // SAFETY: trivially safe
            let property = unsafe { CStr::from_ptr(property) };
            // SAFETY: trivially safe
            let target = unsafe { CStr::from_ptr(target) };

            do_modify_battery(
                socket_path,
                battery_type.to_str().unwrap(),
                property.to_str().unwrap(),
                target.to_str().unwrap(),
            )
            .is_ok()
        } else {
            false
        }
    })
    .unwrap_or(false)
}

/// Fakes the battery status of crosvm instance. The power status will always be on
/// battery, and the maximum battery capacity could be read by guest is set to the
/// `max_battery_capacity`.
///
/// The function returns true on success or false if an error occurred.
///
/// # Arguments
///
/// * `socket_path` - Path to the crosvm control socket
/// * `battery_type` - Type of battery emulation corresponding to vm_tools::BatteryType
/// * `max_battery_capacity` - maximum battery capacity could be read by guest
///
/// # Safety
///
/// The caller will ensure the raw pointers in arguments passed in can be safely used by
/// `CStr::from_ptr()`
#[no_mangle]
pub unsafe extern "C" fn crosvm_client_fake_power(
    socket_path: *const c_char,
    battery_type: *const c_char,
    max_battery_capacity: u32,
) -> bool {
    catch_unwind(|| {
        if let Some(socket_path) = validate_socket_path(socket_path) {
            if battery_type.is_null() || max_battery_capacity > 100 {
                return false;
            }

            let battery_type = CStr::from_ptr(battery_type);
            let fake_max_capacity_target: String = max_battery_capacity.to_string();

            do_modify_battery(
                socket_path.clone(),
                battery_type.to_str().unwrap(),
                &BatProperty::SetFakeBatConfig.to_string(),
                fake_max_capacity_target.as_str(),
            )
            .is_ok()
        } else {
            false
        }
    })
    .unwrap_or(false)
}

/// Resume the battery status of crosvm instance from fake status
///
/// The function returns true on success or false if an error occurred.
///
/// # Arguments
///
/// * `socket_path` - Path to the crosvm control socket
/// * `battery_type` - Type of battery emulation corresponding to vm_tools::BatteryType
///
/// # Safety
///
/// The caller will ensure the raw pointers in arguments passed in can be safely used by
/// `CStr::from_ptr()`.
#[no_mangle]
pub unsafe extern "C" fn crosvm_client_cancel_fake_power(
    socket_path: *const c_char,
    battery_type: *const c_char,
) -> bool {
    catch_unwind(|| {
        if let Some(socket_path) = validate_socket_path(socket_path) {
            if battery_type.is_null() {
                return false;
            }

            // SAFETY: the caller has a responsibility of giving a valid char* pointer
            let battery_type = CStr::from_ptr(battery_type);

            do_modify_battery(
                socket_path,
                battery_type.to_str().unwrap(),
                &BatProperty::CancelFakeBatConfig.to_string(),
                "",
            )
            .is_ok()
        } else {
            false
        }
    })
    .unwrap_or(false)
}

/// Resizes the disk of the crosvm instance whose control socket is listening on `socket_path`.
///
/// The function returns true on success or false if an error occurred.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - `socket_path` should be a non-null pointer to a
/// C string that is valid for reads and not modified for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn crosvm_client_resize_disk(
    socket_path: *const c_char,
    disk_index: u64,
    new_size: u64,
) -> bool {
    catch_unwind(|| {
        if let Some(socket_path) = validate_socket_path(socket_path) {
            if let Ok(disk_index) = usize::try_from(disk_index) {
                let request = VmRequest::DiskCommand {
                    disk_index,
                    command: DiskControlCommand::Resize { new_size },
                };
                vms_request(&request, socket_path).is_ok()
            } else {
                false
            }
        } else {
            false
        }
    })
    .unwrap_or(false)
}

/// Similar to internally used `BalloonStats` but using `i64` instead of
/// `Option<u64>`. `None` (or values bigger than `i64::max`) will be encoded as -1.
#[repr(C)]
pub struct BalloonStatsFfi {
    pub swap_in: i64,
    pub swap_out: i64,
    pub major_faults: i64,
    pub minor_faults: i64,
    pub free_memory: i64,
    pub total_memory: i64,
    pub available_memory: i64,
    pub disk_caches: i64,
    pub hugetlb_allocations: i64,
    pub hugetlb_failures: i64,
    pub shared_memory: i64,
    pub unevictable_memory: i64,
}

impl From<&BalloonStats> for BalloonStatsFfi {
    fn from(other: &BalloonStats) -> Self {
        let convert = |x: Option<u64>| -> i64 { x.and_then(|y| y.try_into().ok()).unwrap_or(-1) };
        Self {
            swap_in: convert(other.swap_in),
            swap_out: convert(other.swap_out),
            major_faults: convert(other.major_faults),
            minor_faults: convert(other.minor_faults),
            free_memory: convert(other.free_memory),
            total_memory: convert(other.total_memory),
            available_memory: convert(other.available_memory),
            disk_caches: convert(other.disk_caches),
            hugetlb_allocations: convert(other.hugetlb_allocations),
            hugetlb_failures: convert(other.hugetlb_failures),
            shared_memory: convert(other.shared_memory),
            unevictable_memory: convert(other.unevictable_memory),
        }
    }
}

/// Returns balloon stats of the crosvm instance whose control socket is listening on `socket_path`.
///
/// The parameters `stats` and `actual` are optional and will only be written to if they are
/// non-null.
///
/// The function returns true on success or false if an error occurred.
///
/// # Note
///
/// Entries in `BalloonStatsFfi` that are not available will be set to `-1`.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - `socket_path` should be a non-null pointer to a C
/// string that is valid for reads and not modified for the duration of the call. `stats` should be
/// a pointer to a `BalloonStatsFfi` valid for writes that is not modified for the duration of this
/// call, and `actual` should be a pointer to a `u64` valid for writes that is not modified for the
/// duration of this call.
#[no_mangle]
pub unsafe extern "C" fn crosvm_client_balloon_stats(
    socket_path: *const c_char,
    stats: *mut BalloonStatsFfi,
    actual: *mut u64,
) -> bool {
    crosvm_client_balloon_stats_impl(socket_path, None, stats, actual)
}

/// See crosvm_client_balloon_stats.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - `socket_path` should be a non-null pointer to a C
/// string that is valid for reads and not modified for the duration of the call. `stats` should be
/// a pointer to a `BalloonStatsFfi` valid for writes is not modified for the duration of this
/// call, and `actual` should be a pointer to a `u64` valid for writes that is not modified for the
/// duration of this call.
#[no_mangle]
pub unsafe extern "C" fn crosvm_client_balloon_stats_with_timeout(
    socket_path: *const c_char,
    timeout_ms: u64,
    stats: *mut BalloonStatsFfi,
    actual: *mut u64,
) -> bool {
    crosvm_client_balloon_stats_impl(
        socket_path,
        Some(Duration::from_millis(timeout_ms)),
        stats,
        actual,
    )
}

/// # Safety
///
/// This function is safe when the caller ensures the socket_path raw pointer can be safely passed
/// to `CStr::from_ptr()`. `stats` should be a pointer to a `BalloonStatsFfi` valid for writes that
/// is not modified for the duration of this call, and `actual` should be a pointer to a `u64`
/// valid for writes that is not modified for the duration of this call.
unsafe fn crosvm_client_balloon_stats_impl(
    socket_path: *const c_char,
    timeout_ms: Option<Duration>,
    stats: *mut BalloonStatsFfi,
    actual: *mut u64,
) -> bool {
    catch_unwind(|| {
        if let Some(socket_path) = validate_socket_path(socket_path) {
            let request = &VmRequest::BalloonCommand(BalloonControlCommand::Stats {});
            let resp = handle_request_with_timeout(request, socket_path, timeout_ms);
            if let Ok(VmResponse::BalloonStats {
                stats: ref balloon_stats,
                balloon_actual,
            }) = resp
            {
                if !stats.is_null() {
                    // SAFETY: just checked that `stats` is not null.
                    unsafe {
                        *stats = balloon_stats.into();
                    }
                }

                if !actual.is_null() {
                    // SAFETY: just checked that `actual` is not null.
                    unsafe {
                        *actual = balloon_actual;
                    }
                }
                true
            } else {
                false
            }
        } else {
            false
        }
    })
    .unwrap_or(false)
}

/// Externally exposed variant of BalloonWS/WSBucket, used for FFI.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct WorkingSetBucketFfi {
    pub age: u64,
    pub bytes: [u64; 2],
}

impl WorkingSetBucketFfi {
    fn new() -> Self {
        Self {
            age: 0,
            bytes: [0, 0],
        }
    }
}

impl From<WSBucket> for WorkingSetBucketFfi {
    fn from(other: WSBucket) -> Self {
        Self {
            age: other.age,
            bytes: other.bytes,
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct BalloonWSFfi {
    pub ws: [WorkingSetBucketFfi; VIRTIO_BALLOON_WS_MAX_NUM_BINS],
    pub num_bins: u8,
    pub _reserved: [u8; 7],
}

impl TryFrom<&BalloonWS> for BalloonWSFfi {
    type Error = &'static str;

    fn try_from(value: &BalloonWS) -> Result<Self, Self::Error> {
        if value.ws.len() > VIRTIO_BALLOON_WS_MAX_NUM_BINS {
            return Err("too many WS buckets in source object.");
        }

        let mut ffi = Self {
            ws: [WorkingSetBucketFfi::new(); VIRTIO_BALLOON_WS_MAX_NUM_BINS],
            num_bins: value.ws.len() as u8,
            ..Default::default()
        };
        for (ffi_ws, other_ws) in ffi.ws.iter_mut().zip(value.ws.iter()) {
            *ffi_ws = (*other_ws).into();
        }
        Ok(ffi)
    }
}

impl BalloonWSFfi {
    pub fn new() -> Self {
        Self {
            ws: [WorkingSetBucketFfi::new(); VIRTIO_BALLOON_WS_MAX_NUM_BINS],
            num_bins: 0,
            _reserved: [0; 7],
        }
    }
}

impl Default for BalloonWSFfi {
    fn default() -> Self {
        Self::new()
    }
}

#[repr(C)]
pub struct BalloonWSRConfigFfi {
    pub intervals: [u64; VIRTIO_BALLOON_WS_MAX_NUM_INTERVALS],
    pub num_intervals: u8,
    pub _reserved: [u8; 7],
    pub refresh_threshold: u64,
    pub report_threshold: u64,
}

/// Returns balloon working set of the crosvm instance whose control socket is listening on
/// socket_path.
///
/// The function returns true on success or false if an error occurred.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - `socket_path` should be a non-null pointer to a C
/// string that is valid for reads and not modified for the duration of the call. `ws` and `actual`
/// should be pointers to a `BalloonStatsFfi` and `u64` respectively that are valid for writes and
/// not modified for the duration of this call.
#[no_mangle]
pub unsafe extern "C" fn crosvm_client_balloon_working_set(
    socket_path: *const c_char,
    ws: *mut BalloonWSFfi,
    actual: *mut u64,
) -> bool {
    catch_unwind(|| {
        if let Some(socket_path) = validate_socket_path(socket_path) {
            let request = &VmRequest::BalloonCommand(BalloonControlCommand::WorkingSet);
            if let Ok(VmResponse::BalloonWS {
                ws: ref balloon_ws,
                balloon_actual,
            }) = handle_request(request, socket_path)
            {
                if !ws.is_null() {
                    // SAFETY: just checked that `ws` is not null.
                    unsafe {
                        *ws = match balloon_ws.try_into() {
                            Ok(result) => result,
                            Err(_) => return false,
                        };
                    }
                }

                if !actual.is_null() {
                    // SAFETY: just checked that `actual` is not null.
                    unsafe {
                        *actual = balloon_actual;
                    }
                }
                true
            } else {
                false
            }
        } else {
            false
        }
    })
    .unwrap_or(false)
}

/// Publically exposed version of RegisteredEvent enum, implemented as an
/// integral newtype for FFI safety.
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct RegisteredEventFfi(u32);

pub const REGISTERED_EVENT_VIRTIO_BALLOON_WS_REPORT: RegisteredEventFfi = RegisteredEventFfi(0);
pub const REGISTERED_EVENT_VIRTIO_BALLOON_RESIZE: RegisteredEventFfi = RegisteredEventFfi(1);
pub const REGISTERED_EVENT_VIRTIO_BALLOON_OOM_DEFLATION: RegisteredEventFfi = RegisteredEventFfi(2);

impl TryFrom<RegisteredEventFfi> for RegisteredEvent {
    type Error = &'static str;

    fn try_from(value: RegisteredEventFfi) -> Result<Self, Self::Error> {
        match value.0 {
            0 => Ok(RegisteredEvent::VirtioBalloonWsReport),
            1 => Ok(RegisteredEvent::VirtioBalloonResize),
            2 => Ok(RegisteredEvent::VirtioBalloonOOMDeflation),
            _ => Err("RegisteredEventFFi outside of known RegisteredEvent enum range"),
        }
    }
}

/// Registers the connected process as a listener for `event`.
///
/// The function returns true on success or false if an error occurred.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - `socket_path` and `listening_socket_path` should
/// be a non-null pointers to C strings that are valid for reads and not modified for the duration
/// of the call.
#[no_mangle]
pub unsafe extern "C" fn crosvm_client_register_events_listener(
    socket_path: *const c_char,
    listening_socket_path: *const c_char,
    event: RegisteredEventFfi,
) -> bool {
    catch_unwind(|| {
        if let Some(socket_path) = validate_socket_path(socket_path) {
            if let Some(listening_socket_path) = validate_socket_path(listening_socket_path) {
                if let Ok(event) = event.try_into() {
                    let request = VmRequest::RegisterListener {
                        event,
                        socket_addr: listening_socket_path.to_str().unwrap().to_string(),
                    };
                    vms_request(&request, socket_path).is_ok()
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        }
    })
    .unwrap_or(false)
}

/// Unegisters the connected process as a listener for `event`.
///
/// The function returns true on success or false if an error occurred.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - `socket_path` and `listening_socket_path` should
/// be a non-null pointers to C strings that are valid for reads and not modified for the duration
/// of the call.
#[no_mangle]
pub unsafe extern "C" fn crosvm_client_unregister_events_listener(
    socket_path: *const c_char,
    listening_socket_path: *const c_char,
    event: RegisteredEventFfi,
) -> bool {
    catch_unwind(|| {
        if let Some(socket_path) = validate_socket_path(socket_path) {
            if let Some(listening_socket_path) = validate_socket_path(listening_socket_path) {
                if let Ok(event) = event.try_into() {
                    let request = VmRequest::UnregisterListener {
                        event,
                        socket_addr: listening_socket_path.to_str().unwrap().to_string(),
                    };
                    vms_request(&request, socket_path).is_ok()
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        }
    })
    .unwrap_or(false)
}

/// Unegisters the connected process as a listener for all events.
///
/// The function returns true on success or false if an error occurred.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - `socket_path` and `listening_socket_path` should
/// be a non-null pointers to C strings that are valid for reads and not modified for the duration
/// of the call.
#[no_mangle]
pub unsafe extern "C" fn crosvm_client_unregister_listener(
    socket_path: *const c_char,
    listening_socket_path: *const c_char,
) -> bool {
    catch_unwind(|| {
        if let Some(socket_path) = validate_socket_path(socket_path) {
            if let Some(listening_socket_path) = validate_socket_path(listening_socket_path) {
                let request = VmRequest::Unregister {
                    socket_addr: listening_socket_path.to_str().unwrap().to_string(),
                };
                vms_request(&request, socket_path).is_ok()
            } else {
                false
            }
        } else {
            false
        }
    })
    .unwrap_or(false)
}

/// Set Working Set Reporting config in guest.
///
/// The function returns true on success or false if an error occurred.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - `socket_path` should be a non-null pointer to a C
/// string that is valid for reads and not modified for the duration of the call. `config` should
/// be a pointer to a `BalloonWSRConfigFfi` valid for reads that is not modified for the duration
/// of this call.
#[no_mangle]
pub unsafe extern "C" fn crosvm_client_balloon_wsr_config(
    socket_path: *const c_char,
    config: *const BalloonWSRConfigFfi,
) -> bool {
    catch_unwind(|| {
        if let Some(socket_path) = validate_socket_path(socket_path) {
            if !config.is_null() {
                // SAFETY: just checked that `config` is not null.
                unsafe {
                    if (*config).num_intervals > VIRTIO_BALLOON_WS_MAX_NUM_INTERVALS as u8 {
                        return false;
                    }
                    let mut actual_bins = vec![];
                    for idx in 0..(*config).num_intervals {
                        actual_bins.push((*config).intervals[idx as usize]);
                    }
                    let refresh_threshold = match u32::try_from((*config).refresh_threshold) {
                        Ok(r_t) => r_t,
                        Err(_) => return false,
                    };
                    let report_threshold = match u32::try_from((*config).report_threshold) {
                        Ok(r_p) => r_p,
                        Err(_) => return false,
                    };
                    let request =
                        VmRequest::BalloonCommand(BalloonControlCommand::WorkingSetConfig {
                            bins: actual_bins
                                .iter()
                                .map(|&b| u32::try_from(b).unwrap())
                                .collect(),
                            refresh_threshold,
                            report_threshold,
                        });
                    vms_request(&request, socket_path).is_ok()
                }
            } else {
                false
            }
        } else {
            false
        }
    })
    .unwrap_or(false)
}

/// Publicly exposed version enumeration of hypervisors, implemented as an
/// integral newtype for FFI safety.
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct HypervisorFfi(u32);

pub const HYPERVISOR_KVM: HypervisorFfi = HypervisorFfi(0);

impl TryFrom<&HypervisorKind> for HypervisorFfi {
    type Error = &'static str;

    fn try_from(hypervisor: &HypervisorKind) -> Result<Self, Self::Error> {
        match hypervisor {
            HypervisorKind::Kvm => Ok(HYPERVISOR_KVM),
            _ => Err("unsupported hypervisor"),
        }
    }
}

/// Hypervisor specific unique identifier of a VM.
#[repr(C)]
pub union HypervisorSpecificVmDescriptorFfi {
    // We use c_int instead of RawFd here because the std::os::fd crate is only available on unix
    // platforms.
    pub vm_fd: c_int,
    pub _reserved: u64,
}

/// A unique identifier of a VM.
#[repr(C)]
pub struct VmDescriptorFfi {
    pub hypervisor: HypervisorFfi,
    pub descriptor: HypervisorSpecificVmDescriptorFfi,
}

/// Get a descriptor representing a running VM.
///
/// The function returns true on success or false if an error occurred.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - `socket_path` should be a non-null pointer to a C
/// string that is valid for reads and not modified for the duration of the call. `vm_desc_out`
/// should be a pointer to a `VmDescriptorFfi` valid for writes that is not externally modified for
/// the duration of this call.
#[no_mangle]
pub unsafe extern "C" fn crosvm_get_vm_descriptor(
    socket_path: *const c_char,
    vm_desc_out: *mut VmDescriptorFfi,
) -> bool {
    catch_unwind(|| {
        let Some(socket_path) = validate_socket_path(socket_path) else {
            return false;
        };

        if vm_desc_out.is_null() {
            return false;
        }

        let resp = handle_request(&VmRequest::GetVmDescriptor, socket_path);
        if let Ok(VmResponse::VmDescriptor { hypervisor, vm_fd }) = resp {
            let Ok(hypervisor) = HypervisorFfi::try_from(&hypervisor) else {
                return false;
            };
            // SAFETY: just checked that `vm_desc_out` is not null.
            (*vm_desc_out).hypervisor = hypervisor;
            // On windows platforms RawDescriptor is actually a *mut c_void, hence cast to c_int
            // here.
            (*vm_desc_out).descriptor.vm_fd = vm_fd.into_raw_descriptor() as c_int;
            true
        } else {
            false
        }
    })
    .unwrap_or(false)
}

/// Platform agnostic wrapper over a file descriptor.
#[repr(C)]
pub union FdWrapper {
    /// File descriptor on linux systems.
    pub linux_fd: c_int,
    /// File descriptor on windows systems.
    pub windows_fd: *mut c_void,
}

/// Arguments structure for crosvm_add_memory.
#[repr(C)]
pub struct AddMemoryArgs {
    /// File descriptor representing memory (e.g. memfd or dma_buf_fd) shared with the VM.
    pub fd: FdWrapper,
    /// Offset.
    pub offset: u64,
    /// Start of the memory range in the guest VM that this memory will be mapped to.
    pub range_start: u64,
    /// End of the memory range in the guest VM that this memory will be mapped to.
    pub range_end: u64,
    /// Whether this memory is cache coherent or not.
    pub cache_coherent: bool,
    /// Padding for the future extensions.
    // TODO(ioffe): is one u64 enough?
    pub _reserved: u64,
}

/// Registers memory represented by `memory_args` to the guest VM.
///
/// The function returns true on success or false if an error occurred. On success the
/// `out_region_id` will contain the unique id representing the registered memory in guest.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - `socket_path` should be a non-null pointer to a C
/// string that is valid for reads and not modified for the duration of the call. `memory_args`
/// should be a pointer to `AddMemoryArgs` struct valid for read and not modified for the duration
/// of this call. `out_region_id` should be a pointer to a `u64` valid for writes that is not
/// externally modified for the duration of this call.
/// This function takes the ownership of the `memory_args.fd` file descriptor.
#[no_mangle]
pub unsafe extern "C" fn crosvm_register_memory(
    socket_path: *const c_char,
    memory_args: *const AddMemoryArgs,
    out_region_id: *mut u64,
) -> bool {
    catch_unwind(|| {
        // SAFETY: `memory_args.fd` is valid during the duration of this function.
        let fd = unsafe {
            #[cfg(not(target_os = "windows"))]
            {
                SafeDescriptor::from_raw_descriptor((*memory_args).fd.linux_fd)
            }
            #[cfg(target_os = "windows")]
            {
                SafeDescriptor::from_raw_descriptor((*memory_args).fd.windows_fd)
            }
        };

        let Some(socket_path) = validate_socket_path(socket_path) else {
            return false;
        };

        if out_region_id.is_null() {
            return false;
        }

        let req = VmRequest::RegisterMemory {
            fd,
            offset: (*memory_args).offset,
            range_start: (*memory_args).range_start,
            range_end: (*memory_args).range_end,
            cache_coherent: (*memory_args).cache_coherent,
        };
        let resp = handle_request(&req, socket_path);
        if let Ok(VmResponse::RegisterMemory2 { region_id }) = resp {
            *out_region_id = region_id;
            true
        } else {
            false
        }
    })
    .unwrap_or(false)
}

/// Unregisters memory represented by the `region_id` from the guest IPA space.
///
/// The function returns true on success or false if an error occurred.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - `socket_path` should be a non-null pointer to a C
/// string that is valid for reads and not modified for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn crosvm_unregister_memory(
    socket_path: *const c_char,
    region_id: u64,
) -> bool {
    catch_unwind(|| {
        let Some(socket_path) = validate_socket_path(socket_path) else {
            return false;
        };

        let req = VmRequest::UnregisterMemory { region_id };
        let resp = handle_request(&req, socket_path);
        matches!(resp, Ok(VmResponse::Ok))
    })
    .unwrap_or(false)
}
