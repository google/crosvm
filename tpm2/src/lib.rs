// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::os::raw::{c_int, c_uint};
use std::ptr;
use std::slice;
use std::sync::atomic::{AtomicBool, Ordering};

static SIMULATOR_EXISTS: AtomicBool = AtomicBool::new(false);

/// A libtpm2-based TPM simulator.
///
/// At most one simulator may exist per process because libtpm2 uses a static
/// global response buffer.
///
/// # Examples
///
/// ```no_run
/// let mut simulator = tpm2::Simulator::singleton_in_current_directory();
///
/// let command = &[ /* ... */ ];
/// let response = simulator.execute_command(command);
/// println!("{:?}", response);
/// ```
pub struct Simulator {
    _priv: (),
}

impl Simulator {
    /// Initializes a TPM simulator in the current working directory.
    ///
    /// # Panics
    ///
    /// Panics if a TPM simulator has already been initialized by this process.
    pub fn singleton_in_current_directory() -> Self {
        let already_existed = SIMULATOR_EXISTS.swap(true, Ordering::SeqCst);
        if already_existed {
            panic!("libtpm2 simulator singleton already exists");
        }

        // Based on trunks:
        // https://chromium.googlesource.com/chromiumos/platform2/+/e4cf13c05773f3446bd76a13c4e37f0b80728711/trunks/tpm_simulator_handle.cc
        tpm_manufacture(true);
        plat_set_nv_avail();
        plat_signal_power_on();
        tpm_init();

        let mut simulator = Simulator { _priv: () };

        // Send TPM2_Startup(TPM_SU_CLEAR), ignore the result. This is normally
        // done by firmware.
        let startup_command = &[
            0x80, 0x01, // TPM_ST_NO_SESSIONS
            0x00, 0x00, 0x00, 0x0c, // commandSize = 12
            0x00, 0x00, 0x01, 0x44, // TPM_CC_Startup
            0x00, 0x00, // TPM_SU_CLEAR
        ];
        let _ = simulator.execute_command(startup_command);

        simulator
    }

    /// Sends a TPM command to the TPM simulator, waits for the work to be
    /// performed, and receives back the TPM response.
    ///
    /// Executing a command requires exclusive access to the TPM simulator
    /// because it mutates libtpm2 static state.
    ///
    /// The returned response buffer remains valid until the next TPM command is
    /// executed.
    #[must_use]
    pub fn execute_command<'a>(&'a mut self, command: &[u8]) -> &'a [u8] {
        let request_size = command.len() as c_uint;
        let request = command.as_ptr() as *mut u8;
        let mut response_size: c_uint = 0;
        let mut response: *mut u8 = ptr::null_mut();

        // We need to provide the following guarantees in order for this block
        // of code to be safe:
        //
        //   - The TPM must have been initialized.
        //
        //   - There must not be a concurrently executing call to
        //     ExecuteCommand.
        //
        //   - The `request` pointer must be a valid pointer to `request_size`
        //     bytes of data that remain valid and constant for the full
        //     duration of the call to ExecuteCommand. The implementation may
        //     read up to `request_size` bytes of data from this address.
        //
        //   - The `response_size` pointer must be a valid pointer to a mutable
        //     unsigned int. The implementation will write the response buffer
        //     size to this address.
        //
        //   - The `response` pointer must be a valid pointer to a mutable
        //     unsigned char pointer. The implementation will write a pointer to
        //     the start of the response buffer to this address.
        //
        //   - No more than `response_size` bytes may be read from the response
        //     buffer after the call returns.
        //
        //   - Data may be read from the response buffer only until the next
        //     call to ExecuteCommand.
        //
        // The first guarantee is enforced by the public API of the Simulator
        // struct, and in particular the singleton_in_current_directory
        // constructor, which only makes a value of type Simulator available
        // outside of this module after TPM initialization has been performed.
        // Thus any Simulator on which the caller may be calling execute_command
        // from outside of this module is witness that initialization has taken
        // place.
        //
        // The second guarantee is made jointly by the &mut self reference in
        // execute_command and the singleton_in_current_directory constructor
        // which uses the SIMULATOR_EXISTS atomic flag to ensure that at most
        // one value of type Simulator is ever made available to code outside of
        // this module. Since at most one Simulator exists, and the caller is
        // holding an exclusive reference to a Simulator, we know that no other
        // code can be calling execute_command at the same time because they too
        // would need their own exclusive reference to the same Simulator. We
        // assume here that all use of libtpm2 within crosvm happens through the
        // safe bindings provided by this tpm2 crate, so that the codebase
        // contains no other unsafe calls to ExecuteCommand.
        //
        // The remaining guarantees are upheld by the signature and
        // implementation of execute_command. In particular, note the lifetime
        // 'a which ties the lifetime of the response slice we return to the
        // caller to the lifetime of their exclusively held reference to
        // Simulator. This signature looks the same to Rust as if the response
        // buffer were a field inside the Simulator struct, rather than a
        // statically allocated buffer inside libtpm2. As soon as the caller
        // "mutates" the Simulator by performing another call to
        // execute_command, the response buffer returned by the previous call is
        // assumed to be invalidated and is made inaccessible by the borrow
        // checker.
        //
        // Altogether we have guaranteed that execute_command is a safe
        // abstraction around unsafe code and is entirely safe to call from
        // outside of this module.
        //
        // Note additionally that the call to ExecuteCommand is over FFI so we
        // need to know that the signature declared by tpm2-sys is
        // ABI-compatible with the symbol provided by libtpm2.
        unsafe {
            tpm2_sys::ExecuteCommand(request_size, request, &mut response_size, &mut response);
            slice::from_raw_parts(response, response_size as usize)
        }
    }
}

fn tpm_manufacture(first_time: bool) {
    // From libtpm2 documentation:
    //
    //     This function initializes the TPM values in preparation for the TPM's
    //     first use. This function will fail if previously called. The TPM can
    //     be re-manufactured by calling TPM_Teardown() first and then calling
    //     this function again.
    //
    //     Arguments
    //
    //         firstTime: indicates if this is the first call from main()
    //
    //     Return value
    //
    //         0 = success
    //         1 = manufacturing process previously performed
    //
    // Unsafe only because this is over FFI and we need to know that the
    // signature declared by tpm2-sys is ABI-compatible with the symbol provided
    // by libtpm2. There are no other invariants to uphold.
    let ret: c_int = unsafe { tpm2_sys::TPM_Manufacture(first_time as c_int) };

    // We expect that the TPM must not already have been manufactured. The
    // SIMULATOR_EXISTS atomic flag guards calls to this function such that only
    // one call can ever be performed by a process.
    assert!(ret == 0);
}

fn plat_set_nv_avail() {
    // From libtpm2 documentation:
    //
    //     Set the current NV state to available. This function is for testing
    //     purpose only. It is not part of the platform NV logic.
    //
    // The "for testing purpose only" is unsettling but trunks performs the same
    // call during initialization so we trust that it is okay.
    //
    // Unsafe only because this is over FFI and we need to know that the
    // signature declared by tpm2-sys is ABI-compatible with the symbol provided
    // by libtpm2. There are no other invariants to uphold.
    unsafe {
        tpm2_sys::_plat__SetNvAvail();
    }
}

fn plat_signal_power_on() {
    // From libtpm2 documentation:
    //
    //     Signal platform power on.
    //
    // The libtpm2 implementation always returns 0 but does not document what
    // the return value means, so we aren't checking it.
    //
    // Unsafe only because this is over FFI and we need to know that the
    // signature declared by tpm2-sys is ABI-compatible with the symbol provided
    // by libtpm2. There are no other invariants to uphold.
    unsafe {
        let _: c_int = tpm2_sys::_plat__Signal_PowerOn();
    }
}

fn tpm_init() {
    // This function is not documented in libtpm2. Trunks performs the same call
    // during initialization so we trust that it is okay.
    //
    // Unsafe only because this is over FFI and we need to know that the
    // signature declared by tpm2-sys is ABI-compatible with the symbol provided
    // by libtpm2. There are no other invariants to uphold.
    unsafe {
        tpm2_sys::_TPM_Init();
    }
}
