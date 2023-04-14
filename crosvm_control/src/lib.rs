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
//! Email: crosvm-dev@chromium.org
//! For more information see:
//! <https://crosvm.dev/book/running_crosvm/programmatic_interaction.html#usage>

use std::convert::TryFrom;
use std::convert::TryInto;
use std::ffi::CStr;
use std::panic::catch_unwind;
use std::path::Path;
use std::path::PathBuf;

use libc::c_char;
use libc::ssize_t;
use vm_control::client::*;
use vm_control::BalloonControlCommand;
use vm_control::BalloonStats;
use vm_control::BalloonWSS;
use vm_control::DiskControlCommand;
use vm_control::RegisteredEvent;
use vm_control::UsbControlAttachedDevice;
use vm_control::UsbControlResult;
use vm_control::VmRequest;
use vm_control::VmResponse;
use vm_control::WSSBucket;
use vm_control::USB_CONTROL_MAX_PORTS;

fn validate_socket_path(socket_path: *const c_char) -> Option<PathBuf> {
    if !socket_path.is_null() {
        // SAFETY: just checked that `socket_path` is not null.
        let socket_path = unsafe { CStr::from_ptr(socket_path) };
        Some(PathBuf::from(socket_path.to_str().ok()?))
    } else {
        None
    }
}

/// Stops the crosvm instance whose control socket is listening on `socket_path`.
///
/// The function returns true on success or false if an error occured.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - a null pointer could be passed in. Usage of
/// !raw_pointer.is_null() checks should prevent unsafe behavior but the caller should ensure no
/// null pointers are passed.
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
/// The function returns true on success or false if an error occured.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - a null pointer could be passed in. Usage of
/// !raw_pointer.is_null() checks should prevent unsafe behavior but the caller should ensure no
/// null pointers are passed.
#[no_mangle]
pub unsafe extern "C" fn crosvm_client_suspend_vm(socket_path: *const c_char) -> bool {
    catch_unwind(|| {
        if let Some(socket_path) = validate_socket_path(socket_path) {
            vms_request(&VmRequest::Suspend, socket_path).is_ok()
        } else {
            false
        }
    })
    .unwrap_or(false)
}

/// Resumes the crosvm instance whose control socket is listening on `socket_path`.
///
/// The function returns true on success or false if an error occured.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - a null pointer could be passed in. Usage of
/// !raw_pointer.is_null() checks should prevent unsafe behavior but the caller should ensure no
/// null pointers are passed.
#[no_mangle]
pub unsafe extern "C" fn crosvm_client_resume_vm(socket_path: *const c_char) -> bool {
    catch_unwind(|| {
        if let Some(socket_path) = validate_socket_path(socket_path) {
            vms_request(&VmRequest::Resume, socket_path).is_ok()
        } else {
            false
        }
    })
    .unwrap_or(false)
}

/// Creates an RT vCPU for the crosvm instance whose control socket is listening on `socket_path`.
///
/// The function returns true on success or false if an error occured.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - a null pointer could be passed in. Usage of
/// !raw_pointer.is_null() checks should prevent unsafe behavior but the caller should ensure no
/// null pointers are passed.
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
/// The function returns true on success or false if an error occured.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - a null pointer could be passed in. Usage of
/// !raw_pointer.is_null() checks should prevent unsafe behavior but the caller should ensure no
/// null pointers are passed.
#[no_mangle]
pub unsafe extern "C" fn crosvm_client_balloon_vms(
    socket_path: *const c_char,
    num_bytes: u64,
) -> bool {
    catch_unwind(|| {
        if let Some(socket_path) = validate_socket_path(socket_path) {
            let command = BalloonControlCommand::Adjust { num_bytes };
            vms_request(&VmRequest::BalloonCommand(command), socket_path).is_ok()
        } else {
            false
        }
    })
    .unwrap_or(false)
}

/// Enable vmm swap for crosvm instance whose control socket is listening on `socket_path`.
///
/// The function returns true on success or false if an error occured.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - a null pointer could be passed in. Usage of
/// !raw_pointer.is_null() checks should prevent unsafe behavior but the caller should ensure no
/// null pointers are passed.
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
/// The function returns true on success or false if an error occured.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - a null pointer could be passed in. Usage of
/// !raw_pointer.is_null() checks should prevent unsafe behavior but the caller should ensure no
/// null pointers are passed.
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

/// Disable vmm swap for crosvm instance whose control socket is listening on `socket_path`.
///
/// The function returns true on success or false if an error occured.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - a null pointer could be passed in. Usage of
/// !raw_pointer.is_null() checks should prevent unsafe behavior but the caller should ensure no
/// null pointers are passed.
#[no_mangle]
pub unsafe extern "C" fn crosvm_client_swap_disable_vm(socket_path: *const c_char) -> bool {
    catch_unwind(|| {
        if let Some(socket_path) = validate_socket_path(socket_path) {
            vms_request(&VmRequest::Swap(SwapCommand::Disable), socket_path).is_ok()
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
    port: u8,
    /// USB vendor ID
    vendor_id: u16,
    /// USB product ID
    product_id: u16,
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

/// Returns all USB devices passed through the crosvm instance whose control socket is listening on `socket_path`.
///
/// The function returns the amount of entries written.
/// # Arguments
///
/// * `socket_path` - Path to the crosvm control socket
/// * `entries` - Pointer to an array of `UsbDeviceEntry` where the details about the attached
///               devices will be written to
/// * `entries_length` - Amount of entries in the array specified by `entries`
///
/// Use the value returned by [`crosvm_client_max_usb_devices()`] to determine the size of the input
/// array to this function.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - a null pointer could be passed in. Usage of
/// !raw_pointer.is_null() checks should prevent unsafe behavior but the caller should ensure no
/// null pointers are passed.
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
            if let Ok(UsbControlResult::Devices(res)) = do_usb_list(&socket_path) {
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
/// The function returns true on success or false if an error occured.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - a null pointer could be passed in. Usage of
/// !raw_pointer.is_null() checks should prevent unsafe behavior but the caller should ensure no
/// null pointers are passed.
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
/// The function returns true on success or false if an error occured.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - a null pointer could be passed in. Usage of
/// !raw_pointer.is_null() checks should prevent unsafe behavior but the caller should ensure no
/// null pointers are passed.
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

/// Modifies the battery status of crosvm instance whose control socket is listening on
/// `socket_path`.
///
/// The function returns true on success or false if an error occured.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - a null pointer could be passed in. Usage of
/// !raw_pointer.is_null() checks should prevent unsafe behavior but the caller should ensure no
/// null pointers are passed.
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
            let battery_type = unsafe { CStr::from_ptr(battery_type) };
            let property = unsafe { CStr::from_ptr(property) };
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

/// Resizes the disk of the crosvm instance whose control socket is listening on `socket_path`.
///
/// The function returns true on success or false if an error occured.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - a null pointer could be passed in. Usage of
/// !raw_pointer.is_null() checks should prevent unsafe behavior but the caller should ensure no
/// null pointers are passed.
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

/// Similar to internally used `BalloonStats` but using i64 instead of
/// Option<u64>. `None` (or values bigger than i64::max) will be encoded as -1.
#[repr(C)]
pub struct BalloonStatsFfi {
    swap_in: i64,
    swap_out: i64,
    major_faults: i64,
    minor_faults: i64,
    free_memory: i64,
    total_memory: i64,
    available_memory: i64,
    disk_caches: i64,
    hugetlb_allocations: i64,
    hugetlb_failures: i64,
    shared_memory: i64,
    unevictable_memory: i64,
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
/// The function returns true on success or false if an error occured.
///
/// # Note
///
/// Entries in `BalloonStatsFfi` that are not available will be set to `-1`.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - a null pointer could be passed in. Usage of
/// !raw_pointer.is_null() checks should prevent unsafe behavior but the caller should ensure no
/// null pointers are passed.
#[no_mangle]
pub unsafe extern "C" fn crosvm_client_balloon_stats(
    socket_path: *const c_char,
    stats: *mut BalloonStatsFfi,
    actual: *mut u64,
) -> bool {
    catch_unwind(|| {
        if let Some(socket_path) = validate_socket_path(socket_path) {
            let request = &VmRequest::BalloonCommand(BalloonControlCommand::Stats {});
            if let Ok(VmResponse::BalloonStats {
                stats: ref balloon_stats,
                balloon_actual,
            }) = handle_request(request, socket_path)
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

/// Externally exposed variant of BalloonWss/WSSBucket, used for FFI.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct WSSBucketFfi {
    age: u64,
    bytes: [u64; 2],
}

impl WSSBucketFfi {
    fn new() -> Self {
        Self {
            age: 0,
            bytes: [0, 0],
        }
    }
}

impl From<WSSBucket> for WSSBucketFfi {
    fn from(other: WSSBucket) -> Self {
        Self {
            age: other.age,
            bytes: other.bytes,
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct BalloonWSSFfi {
    wss: [WSSBucketFfi; 4],
}

impl From<&BalloonWSS> for BalloonWSSFfi {
    fn from(other: &BalloonWSS) -> Self {
        let mut ffi = Self {
            wss: [WSSBucketFfi::new(); 4],
        };
        for (ffi_wss, other_wss) in ffi.wss.iter_mut().zip(other.wss) {
            *ffi_wss = other_wss.into();
        }
        ffi
    }
}

impl BalloonWSSFfi {
    pub fn new() -> Self {
        Self {
            wss: [WSSBucketFfi::new(); 4],
        }
    }
}

/// Returns balloon working set size of the crosvm instance whose control socket is listening on socket_path.
///
/// The function returns true on success or false if an error occured.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - a null pointer could be passed in. Usage of
/// !raw_pointer.is_null() checks should prevent unsafe behavior but the caller should ensure no
/// null pointers are passed.
#[no_mangle]
pub unsafe extern "C" fn crosvm_client_balloon_wss(
    socket_path: *const c_char,
    wss: *mut BalloonWSSFfi,
    actual: *mut u64,
) -> bool {
    catch_unwind(|| {
        if let Some(socket_path) = validate_socket_path(socket_path) {
            let request = &VmRequest::BalloonCommand(BalloonControlCommand::WorkingSetSize);
            if let Ok(VmResponse::BalloonWSS {
                wss: ref balloon_wss,
                balloon_actual,
            }) = handle_request(request, socket_path)
            {
                if !wss.is_null() {
                    // SAFETY: just checked that `wss` is not null.
                    unsafe {
                        *wss = balloon_wss.into();
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

pub const REGISTERED_EVENT_VIRTIO_BALLOON_WSS_REPORT: RegisteredEventFfi = RegisteredEventFfi(0);
pub const REGISTERED_EVENT_VIRTIO_BALLOON_RESIZE: RegisteredEventFfi = RegisteredEventFfi(1);
pub const REGISTERED_EVENT_VIRTIO_BALLOON_OOM_DEFLATION: RegisteredEventFfi = RegisteredEventFfi(2);

impl TryFrom<RegisteredEventFfi> for RegisteredEvent {
    type Error = &'static str;

    fn try_from(value: RegisteredEventFfi) -> Result<Self, Self::Error> {
        match value.0 {
            0 => Ok(RegisteredEvent::VirtioBalloonWssReport),
            1 => Ok(RegisteredEvent::VirtioBalloonResize),
            2 => Ok(RegisteredEvent::VirtioBalloonOOMDeflation),
            _ => Err("RegisteredEventFFi outside of known RegisteredEvent enum range"),
        }
    }
}

/// Registers the connected process as a listener for `event`.
///
/// The function returns true on success or false if an error occured.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - a null pointer could be passed in. Usage of
/// !raw_pointer.is_null() checks should prevent unsafe behavior but the caller should ensure no
/// null pointers are passed.
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
/// The function returns true on success or false if an error occured.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - a null pointer could be passed in. Usage of
/// !raw_pointer.is_null() checks should prevent unsafe behavior but the caller should ensure no
/// null pointers are passed.
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
/// The function returns true on success or false if an error occured.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - a null pointer could be passed in. Usage of
/// !raw_pointer.is_null() checks should prevent unsafe behavior but the caller should ensure no
/// null pointers are passed.
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

/// Set Working Set Size config in guest.
///
/// The function returns true on success or false if an error occured.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - a null pointer could be passed in. Usage of
/// !raw_pointer.is_null() checks should prevent unsafe behavior but the caller should ensure no
/// null pointers are passed.
#[no_mangle]
pub unsafe extern "C" fn crosvm_client_balloon_wss_config(
    socket_path: *const c_char,
    config: *const [u64; 5],
) -> bool {
    catch_unwind(|| {
        if let Some(socket_path) = validate_socket_path(socket_path) {
            if !config.is_null() {
                // SAFETY: just checked that `config` is not null.
                unsafe {
                    let request =
                        VmRequest::BalloonCommand(BalloonControlCommand::WorkingSetSizeConfig {
                            config: *config,
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
