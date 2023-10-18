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
#[cfg(any(target_os = "android", target_os = "linux"))]
use std::time::Duration;

use libc::c_char;
use libc::ssize_t;
pub use swap::SwapStatus;
use vm_control::client::*;
use vm_control::BalloonControlCommand;
use vm_control::BalloonStats;
use vm_control::BalloonWS;
use vm_control::DiskControlCommand;
#[cfg(feature = "registered_events")]
use vm_control::RegisteredEvent;
use vm_control::UsbControlAttachedDevice;
use vm_control::UsbControlResult;
use vm_control::VmRequest;
use vm_control::VmResponse;
use vm_control::WSBucket;
use vm_control::USB_CONTROL_MAX_PORTS;

pub const VIRTIO_BALLOON_WS_MAX_NUM_BINS: usize = 16;
pub const VIRTIO_BALLOON_WS_MAX_NUM_INTERVALS: usize = 15;

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
/// The function returns true on success or false if an error occurred.
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
/// The function returns true on success or false if an error occurred.
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
            vms_request(&VmRequest::SuspendVcpus, socket_path).is_ok()
        } else {
            false
        }
    })
    .unwrap_or(false)
}

/// Resumes the crosvm instance whose control socket is listening on `socket_path`.
///
/// The function returns true on success or false if an error occurred.
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
            vms_request(&VmRequest::ResumeVcpus, socket_path).is_ok()
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
/// The function returns true on success or false if an error occurred.
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
#[cfg(any(target_os = "android", target_os = "linux"))]
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
            println!("adjust failure: {:?}", resp);
        }
        false
    })
    .unwrap_or(false)
}

/// Enable vmm swap for crosvm instance whose control socket is listening on `socket_path`.
///
/// The function returns true on success or false if an error occurred.
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
/// The function returns true on success or false if an error occurred.
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

/// Arguments structure for crosvm_client_swap_disable_vm2.
#[repr(C)]
pub struct SwapDisableArgs {
    /// The path of the control socket to target.
    socket_path: *const c_char,
    /// Whether or not the swap file should be cleaned up in the background.
    slow_file_cleanup: bool,
}

/// Disable vmm swap according to `args`.
///
/// The function returns true on success or false if an error occurred.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - a null pointer could be passed in. Usage of
/// !raw_pointer.is_null() checks should prevent unsafe behavior but the caller should ensure no
/// null pointers are passed.
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
/// Function is unsafe due to raw pointer usage - a null pointer could be passed in. Usage of
/// !raw_pointer.is_null() checks should prevent unsafe behavior but the caller should ensure no
/// null pointers are passed.
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
/// Function is unsafe due to raw pointer usage - a null pointer could be passed in. Usage of
/// !raw_pointer.is_null() checks should prevent unsafe behavior but the caller should ensure no
/// null pointers are passed.
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
/// The function returns true on success or false if an error occurred.
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
/// The function returns true on success or false if an error occurred.
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
/// The function returns true on success or false if an error occurred.
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

/// Similar to internally used `BalloonStats` but using `i64` instead of
/// `Option<u64>`. `None` (or values bigger than `i64::max`) will be encoded as -1.
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
/// The function returns true on success or false if an error occurred.
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
    crosvm_client_balloon_stats_impl(
        socket_path,
        #[cfg(any(target_os = "android", target_os = "linux"))]
        None,
        stats,
        actual,
    )
}

/// See crosvm_client_balloon_stats.
#[cfg(any(target_os = "android", target_os = "linux"))]
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

fn crosvm_client_balloon_stats_impl(
    socket_path: *const c_char,
    #[cfg(any(target_os = "android", target_os = "linux"))] timeout_ms: Option<Duration>,
    stats: *mut BalloonStatsFfi,
    actual: *mut u64,
) -> bool {
    catch_unwind(|| {
        if let Some(socket_path) = validate_socket_path(socket_path) {
            let request = &VmRequest::BalloonCommand(BalloonControlCommand::Stats {});
            #[cfg(not(unix))]
            let resp = handle_request(request, socket_path);
            #[cfg(any(target_os = "android", target_os = "linux"))]
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
    age: u64,
    bytes: [u64; 2],
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
    ws: [WorkingSetBucketFfi; VIRTIO_BALLOON_WS_MAX_NUM_BINS],
    num_bins: u8,
    _reserved: [u8; 7],
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
    intervals: [u64; VIRTIO_BALLOON_WS_MAX_NUM_INTERVALS],
    num_intervals: u8,
    _reserved: [u8; 7],
    refresh_threshold: u64,
    report_threshold: u64,
}

/// Returns balloon working set of the crosvm instance whose control socket is listening on socket_path.
///
/// The function returns true on success or false if an error occurred.
///
/// # Safety
///
/// Function is unsafe due to raw pointer usage - a null pointer could be passed in. Usage of
/// !raw_pointer.is_null() checks should prevent unsafe behavior but the caller should ensure no
/// null pointers are passed.
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
#[cfg(feature = "registered_events")]
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct RegisteredEventFfi(u32);

#[cfg(feature = "registered_events")]
pub const REGISTERED_EVENT_VIRTIO_BALLOON_WS_REPORT: RegisteredEventFfi = RegisteredEventFfi(0);
#[cfg(feature = "registered_events")]
pub const REGISTERED_EVENT_VIRTIO_BALLOON_RESIZE: RegisteredEventFfi = RegisteredEventFfi(1);
#[cfg(feature = "registered_events")]
pub const REGISTERED_EVENT_VIRTIO_BALLOON_OOM_DEFLATION: RegisteredEventFfi = RegisteredEventFfi(2);

#[cfg(feature = "registered_events")]
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
/// Function is unsafe due to raw pointer usage - a null pointer could be passed in. Usage of
/// !raw_pointer.is_null() checks should prevent unsafe behavior but the caller should ensure no
/// null pointers are passed.
#[cfg(feature = "registered_events")]
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
/// Function is unsafe due to raw pointer usage - a null pointer could be passed in. Usage of
/// !raw_pointer.is_null() checks should prevent unsafe behavior but the caller should ensure no
/// null pointers are passed.
#[cfg(feature = "registered_events")]
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
/// Function is unsafe due to raw pointer usage - a null pointer could be passed in. Usage of
/// !raw_pointer.is_null() checks should prevent unsafe behavior but the caller should ensure no
/// null pointers are passed.
#[cfg(feature = "registered_events")]
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
/// Function is unsafe due to raw pointer usage - a null pointer could be passed in. Usage of
/// !raw_pointer.is_null() checks should prevent unsafe behavior but the caller should ensure no
/// null pointers are passed.
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
