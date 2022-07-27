// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(windows)]

use std::ffi::CStr;
use std::fmt;
use std::marker::PhantomData;
use std::sync::Once;

use base::named_pipes;
use base::AsRawDescriptor;
use base::FromRawDescriptor;
use base::SafeDescriptor;
use win_util::win32_wide_string;

#[cfg_attr(windows, path = "../bindings.rs")]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
#[allow(deref_nullptr)]
pub mod bindings;

pub mod policy;

pub use bindings::IntegrityLevel;
pub use bindings::JobLevel;
pub use bindings::MitigationFlags;
pub use bindings::ResultCode;
pub use bindings::Semantics;
pub use bindings::SubSystem;
pub use bindings::TokenLevel;

use bindings::DWORD;
pub use bindings::MITIGATION_BOTTOM_UP_ASLR;
pub use bindings::MITIGATION_CET_DISABLED;
pub use bindings::MITIGATION_DEP;
pub use bindings::MITIGATION_DEP_NO_ATL_THUNK;
pub use bindings::MITIGATION_DLL_SEARCH_ORDER;
pub use bindings::MITIGATION_DYNAMIC_CODE_DISABLE;
pub use bindings::MITIGATION_DYNAMIC_CODE_DISABLE_WITH_OPT_OUT;
pub use bindings::MITIGATION_DYNAMIC_CODE_OPT_OUT_THIS_THREAD;
pub use bindings::MITIGATION_EXTENSION_POINT_DISABLE;
pub use bindings::MITIGATION_FORCE_MS_SIGNED_BINS;
pub use bindings::MITIGATION_HARDEN_TOKEN_IL_POLICY;
pub use bindings::MITIGATION_HEAP_TERMINATE;
pub use bindings::MITIGATION_HIGH_ENTROPY_ASLR;
pub use bindings::MITIGATION_IMAGE_LOAD_NO_LOW_LABEL;
pub use bindings::MITIGATION_IMAGE_LOAD_NO_REMOTE;
pub use bindings::MITIGATION_IMAGE_LOAD_PREFER_SYS32;
pub use bindings::MITIGATION_KTM_COMPONENT;
pub use bindings::MITIGATION_NONSYSTEM_FONT_DISABLE;
pub use bindings::MITIGATION_RELOCATE_IMAGE;
pub use bindings::MITIGATION_RELOCATE_IMAGE_REQUIRED;
pub use bindings::MITIGATION_RESTRICT_INDIRECT_BRANCH_PREDICTION;
pub use bindings::MITIGATION_SEHOP;
pub use bindings::MITIGATION_STRICT_HANDLE_CHECKS;
pub use bindings::MITIGATION_WIN32K_DISABLE;

pub use bindings::JOB_OBJECT_UILIMIT_ALL;
pub use bindings::JOB_OBJECT_UILIMIT_DESKTOP;
pub use bindings::JOB_OBJECT_UILIMIT_DISPLAYSETTINGS;
pub use bindings::JOB_OBJECT_UILIMIT_EXITWINDOWS;
pub use bindings::JOB_OBJECT_UILIMIT_GLOBALATOMS;
pub use bindings::JOB_OBJECT_UILIMIT_HANDLES;
pub use bindings::JOB_OBJECT_UILIMIT_NONE;
pub use bindings::JOB_OBJECT_UILIMIT_READCLIPBOARD;
pub use bindings::JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS;
pub use bindings::JOB_OBJECT_UILIMIT_WRITECLIPBOARD;

use bindings::PROCESS_INFORMATION;

type Result<T> = std::result::Result<T, SandboxError>;

#[derive(Debug, Copy, Clone)]
pub struct SandboxError {
    result_code: ResultCode,
    error_code: Option<u32>,
}

impl fmt::Display for SandboxError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.error_code {
            Some(error_code) => write!(
                f,
                "Sandbox error code: {:?}, win32 error code: {}",
                self.result_code, error_code,
            ),
            None => write!(f, "Sandbox error code: {:?}", self.result_code),
        }
    }
}

impl std::error::Error for SandboxError {
    fn description(&self) -> &str {
        "sandbox error"
    }
}

impl SandboxError {
    pub fn new(result_code: ResultCode) -> SandboxError {
        if result_code == bindings::ResultCode::SBOX_ERROR_GENERIC {
            return SandboxError::from(std::io::Error::last_os_error());
        }
        SandboxError {
            result_code,
            error_code: None,
        }
    }
}

impl From<std::io::Error> for SandboxError {
    fn from(error: std::io::Error) -> Self {
        let error_code = error.raw_os_error().map(|e| e as u32);
        SandboxError {
            result_code: bindings::ResultCode::SBOX_ERROR_GENERIC,
            error_code,
        }
    }
}

pub type SandboxWarning = SandboxError;

/// Encapsulates broker-related functionality for the sandbox.
///
/// This struct and its methods are not thread safe, in general. Only a single
/// thread should call the methods on this struct.
#[derive(Debug, PartialEq, Clone)]
pub struct BrokerServices {
    broker: *mut bindings::BrokerServices,
}

/// Encapsulates target-related functionality for the sandbox.
#[derive(Debug, PartialEq, Clone)]
pub struct TargetServices {
    target: *mut bindings::TargetServices,
}

/// Defines sandbox policies for target processes.
pub struct TargetPolicy<'a> {
    policy: TargetPolicyWrapper,
    _marker: PhantomData<&'a dyn AsRawDescriptor>,
}

struct TargetPolicyWrapper(*mut bindings::TargetPolicy);

impl Drop for TargetPolicyWrapper {
    fn drop(&mut self) {
        // Safe because TargetPolicyWrapper can only be constructed with a non-null pointer.
        unsafe { bindings::sbox_release_policy(self.0) };
    }
}

pub struct ProcessInformation {
    pub process: SafeDescriptor,
    pub thread: SafeDescriptor,
    pub process_id: u32,
    pub thread_id: u32,
}

pub struct PolicyInfo {
    policy_info: *mut bindings::PolicyInfo,
}

impl Drop for PolicyInfo {
    fn drop(&mut self) {
        unsafe { bindings::sbox_release_policy_info(self.policy_info) }
    }
}

/// Returns true if this process is the broker process.
pub fn is_sandbox_broker() -> bool {
    // Safe because the returned raw pointer is a non-owning pointer and we are free
    // to let it drop unmanaged.
    unsafe { !bindings::get_broker_services().is_null() }
}

/// Returns true if this process is a target process.
pub fn is_sandbox_target() -> bool {
    // Safe because the returned raw pointer is a non-owning pointer and we are
    // free to let it drop unmanaged.
    unsafe { !bindings::get_target_services().is_null() }
}

impl BrokerServices {
    /// Returns an initialized broker API interface if the process is the broker.
    pub fn get() -> Result<Option<BrokerServices>> {
        static INIT: Once = Once::new();
        static mut RESULT: Result<()> = Ok(());
        static mut BROKER: Option<BrokerServices> = None;

        // Initialize broker services. Should be called once before use.
        // Safe because RESULT is only written once, and call_once will cause
        // other readers to block until execution of the block is complete.
        // Also checks for and eliminates any null pointers.
        unsafe {
            INIT.call_once(|| {
                let broker = bindings::get_broker_services();
                if broker.is_null() {
                    return;
                }
                BROKER = Some(BrokerServices { broker });
                RESULT = BROKER.as_mut().unwrap().init();
            });
            if BROKER.is_none() {
                return Ok(None);
            }
            match RESULT {
                Err(e) => Err(e),
                Ok(_) => Ok(Some(BROKER.as_mut().unwrap().clone())),
            }
        }
    }

    /// Initializes the broker. Must be called once before calling any other
    /// methods.
    ///
    /// Takes a &mut self because sbox_broker_init mutates the underlying broker
    /// object.
    fn init(&mut self) -> Result<()> {
        // Safe because BrokerServices can only be constructed with a non-null
        // pointer.
        let result_code = unsafe { bindings::sbox_broker_init(self.broker) };
        if result_code != ResultCode::SBOX_ALL_OK {
            Err(SandboxError::new(result_code))
        } else {
            Ok(())
        }
    }

    /// Create a new policy object.
    pub fn create_policy<'a>(&self) -> TargetPolicy<'a> {
        // Safe because BrokerServices can only be constructed with a non-null pointer.
        let policy = unsafe { bindings::sbox_create_policy(self.broker) };
        TargetPolicy {
            policy: TargetPolicyWrapper(policy),
            _marker: PhantomData,
        }
    }

    /// Spawn a new target process. This process is created with the main thread
    /// in a suspended state.
    ///
    /// Takes a `&mut self` because `sbox_spawn_target()` mutates the underlying
    /// broker object.
    pub fn spawn_target(
        &mut self,
        exe_path: &str,
        command_line: &str,
        policy: &TargetPolicy,
    ) -> Result<(ProcessInformation, Option<SandboxWarning>)> {
        let mut last_warning = ResultCode::SBOX_ALL_OK;
        let mut last_error: DWORD = 0;
        let mut target = PROCESS_INFORMATION {
            dwProcessId: 0,
            dwThreadId: 0,
            hThread: std::ptr::null_mut(),
            hProcess: std::ptr::null_mut(),
        };
        // Safe because the external arguments must be constructed in a safe
        // way, and the rest of the arguments are pointers to valid objects
        // created in this function.
        let result = unsafe {
            bindings::sbox_spawn_target(
                self.broker,
                win32_wide_string(exe_path).as_ptr(),
                win32_wide_string(command_line).as_ptr(),
                policy.policy.0,
                &mut last_warning,
                &mut last_error,
                &mut target,
            )
        };
        if result != ResultCode::SBOX_ALL_OK {
            return Err(SandboxError {
                result_code: result,
                error_code: Some(last_error),
            });
        }
        // Safe because we are adopting the process and thread handles here,
        // and they won't be used outside of the SafeDescriptor after this
        // function returns.
        let process = unsafe {
            ProcessInformation {
                process: SafeDescriptor::from_raw_descriptor(target.hProcess),
                thread: SafeDescriptor::from_raw_descriptor(target.hThread),
                process_id: target.dwProcessId,
                thread_id: target.dwThreadId,
            }
        };
        if last_warning != ResultCode::SBOX_ALL_OK {
            Ok((
                process,
                Some(SandboxWarning {
                    result_code: last_warning,
                    error_code: Some(last_error),
                }),
            ))
        } else {
            Ok((process, None))
        }
    }

    /// Waits (blocks) for all target processes to exit.
    ///
    /// Takes a `&mut self` because `sbox_wait_for_all_targets()` mutates the
    /// underlying broker object.
    pub fn wait_for_all_targets(&mut self) -> Result<()> {
        // Safe because BrokerServices can only be constructed with a non-null pointer.
        let result_code = unsafe { bindings::sbox_wait_for_all_targets(self.broker) };
        if result_code != ResultCode::SBOX_ALL_OK {
            Err(SandboxError::new(result_code))
        } else {
            Ok(())
        }
    }
}

impl TargetServices {
    /// Returns an initialized target API interface if the process is the target.
    pub fn get() -> Result<Option<TargetServices>> {
        static INIT: Once = Once::new();
        static mut RESULT: Result<()> = Ok(());
        static mut TARGET: Option<TargetServices> = None;

        // Initialize target services. Should be called once before use.
        // Safe because RESULT is only written once, and call_once will cause
        // other readers to block until execution of the block is complete.
        // Also checks for and eliminates any null pointers.
        unsafe {
            INIT.call_once(|| {
                let target = bindings::get_target_services();
                if target.is_null() {
                    return;
                }
                TARGET = Some(TargetServices { target });
                RESULT = TARGET.as_mut().unwrap().init()
            });
            if TARGET.is_none() {
                return Ok(None);
            }
            // Initialize target services. If TargetServices is already initialized,
            // this is a no-op.
            match RESULT {
                Err(e) => Err(e),
                Ok(_) => Ok(Some(TARGET.as_mut().unwrap().clone())),
            }
        }
    }

    /// Initializes the target. Must be called once before calling any other
    /// methods.
    ///
    /// Takes a `&mut self` because `sbox_target_init()` mutates the underlying
    /// target object.
    fn init(&mut self) -> Result<()> {
        // Safe because TargetServices can only be constructed with a non-null pointer.
        let result_code = unsafe { bindings::sbox_target_init(self.target) };
        if result_code != ResultCode::SBOX_ALL_OK {
            Err(SandboxError::new(result_code))
        } else {
            Ok(())
        }
    }

    /// Discards the targets impersonation token and uses the lower token.
    ///
    /// Takes a `&mut self` because `sbox_lower_token()` mutates the underlying
    /// target object.
    pub fn lower_token(&mut self) {
        // Safe because TargetServices can only be constructed with a non-null pointer.
        unsafe { bindings::sbox_lower_token(self.target) };
    }
}

impl<'a> TargetPolicy<'a> {
    /// Sets the security level for the process' two tokens.
    ///
    /// Takes a `&mut self` because `sbox_set_token_level()` mutates the
    /// underlying policy object.
    pub fn set_token_level(&mut self, initial: TokenLevel, lockdown: TokenLevel) -> Result<()> {
        // Safe because TargetPolicy can only be constructed with a non-null policy pointer.
        match unsafe { bindings::sbox_set_token_level(self.policy.0, initial, lockdown) } {
            ResultCode::SBOX_ALL_OK => Ok(()),
            result_code => Err(SandboxError::new(result_code)),
        }
    }

    /// Gets the initial token level.
    pub fn initial_token_level(&self) -> TokenLevel {
        // Safe because TargetPolicy can only be constructed with a non-null policy pointer.
        unsafe { bindings::sbox_get_initial_token_level(self.policy.0) }
    }

    /// Gets the lockdown token level.
    pub fn lockdown_token_level(&self) -> TokenLevel {
        // Safe because TargetPolicy can only be constructed with a non-null policy pointer.
        unsafe { bindings::sbox_get_lockdown_token_level(self.policy.0) }
    }

    /// Sets the security level of the job object to which the process will
    /// belong.
    ///
    /// Takes a `&mut self` because `sbox_set_job_level()` mutates the
    /// underlying policy object.
    pub fn set_job_level(&mut self, job_level: JobLevel, ui_exceptions: u32) -> Result<()> {
        // Safe because TargetPolicy can only be constructed with a non-null policy pointer.
        match unsafe { bindings::sbox_set_job_level(self.policy.0, job_level, ui_exceptions) } {
            ResultCode::SBOX_ALL_OK => Ok(()),
            result_code => Err(SandboxError::new(result_code)),
        }
    }

    /// Returns the job level.
    pub fn job_level(&self) -> JobLevel {
        // Safe because TargetPolicy can only be constructed with a non-null policy pointer.
        unsafe { bindings::sbox_get_job_level(self.policy.0) }
    }

    /// Sets the initial integrity level of the process in the sandbox.
    ///
    /// Takes a `&mut self` because `sbox_set_integrity_level()` mutates the
    /// underlying policy object.
    pub fn set_integrity_level(&mut self, level: IntegrityLevel) -> Result<()> {
        // Safe because TargetPolicy can only be constructed with a non-null policy pointer.
        match unsafe { bindings::sbox_set_integrity_level(self.policy.0, level) } {
            ResultCode::SBOX_ALL_OK => Ok(()),
            result_code => Err(SandboxError::new(result_code)),
        }
    }

    /// Sets the delayed integrity level of the process in the sandbox.
    ///
    /// Takes a `&mut self` because `sbox_set_delayed_integrity_level()` mutates the
    /// underlying policy object.
    pub fn set_delayed_integrity_level(&mut self, level: IntegrityLevel) -> Result<()> {
        // Safe because TargetPolicy can only be constructed with a non-null policy pointer.
        match unsafe { bindings::sbox_set_delayed_integrity_level(self.policy.0, level) } {
            ResultCode::SBOX_ALL_OK => Ok(()),
            result_code => Err(SandboxError::new(result_code)),
        }
    }

    /// Returns the initial integrity level used.
    pub fn integrity_level(&self) -> IntegrityLevel {
        // Safe because TargetPolicy can only be constructed with a non-null policy pointer.
        unsafe { bindings::sbox_get_integrity_level(self.policy.0) }
    }

    /// Specifies that the process should run on an alternate desktop. If
    /// `alternate_winstation` is set to `true`, the desktop will be created on an
    /// alternate windows station.
    ///
    /// Takes a `&mut self` because `sbox_set_alternate_desktop` mutates the
    /// underlying policy object.
    pub fn set_alternate_desktop(&mut self, alternate_winstation: bool) -> Result<()> {
        // Safe because TargetPolicy can only be constructed with a non-null policy pointer.
        match unsafe { bindings::sbox_set_alternate_desktop(self.policy.0, alternate_winstation) } {
            ResultCode::SBOX_ALL_OK => Ok(()),
            result_code => Err(SandboxError::new(result_code)),
        }
    }

    /// Precreates the alternate desktop and winstation, if any.
    ///
    /// Takes a `&mut self` because `sbox_create_alternate_desktop` mutates the
    /// underlying policy object.
    pub fn create_alternate_desktop(&mut self, alternate_winstation: bool) -> Result<()> {
        // Safe because TargetPolicy can only be constructed with a non-null policy pointer.
        match unsafe {
            bindings::sbox_create_alternate_desktop(self.policy.0, alternate_winstation)
        } {
            ResultCode::SBOX_ALL_OK => Ok(()),
            result_code => Err(SandboxError::new(result_code)),
        }
    }

    /// Destroys the desktop and windows station.
    ///
    /// Takes a `&mut self` because `sbox_destroy_alternate_desktop` mutates the
    /// underlying policy object.
    pub fn destroy_alternate_desktop(&mut self) {
        // Safe because TargetPolicy can only be constructed with a non-null policy pointer.
        unsafe { bindings::sbox_destroy_alternate_desktop(self.policy.0) }
    }

    /// Sets the LowBox token for sandboxed process. This is mutually exclusive
    /// with the `add_app_container_profile()` method.
    ///
    /// Takes a `&mut self` because `sbox_set_lowbox` mutates the underlying
    /// policy object.
    pub fn set_lowbox(&mut self, sid: &str) -> Result<()> {
        // Safe because TargetPolicy can only be constructed with a non-null policy pointer.
        match unsafe { bindings::sbox_set_lowbox(self.policy.0, win32_wide_string(sid).as_ptr()) } {
            ResultCode::SBOX_ALL_OK => Ok(()),
            result_code => Err(SandboxError::new(result_code)),
        }
    }

    /// Sets the mitigations enabled when the process is created.
    ///
    /// Takes a `&mut self` because `sbox_set_process_mitigations` mutates the
    /// underlying policy object.
    pub fn set_process_mitigations(&mut self, flags: MitigationFlags) -> Result<()> {
        // Safe because TargetPolicy can only be constructed with a non-null policy pointer.
        match unsafe { bindings::sbox_set_process_mitigations(self.policy.0, flags) } {
            ResultCode::SBOX_ALL_OK => Ok(()),
            result_code => Err(SandboxError::new(result_code)),
        }
    }

    /// Returns the currently set mitigation flags.
    pub fn process_mitigations(&self) -> MitigationFlags {
        // Safe because TargetPolicy can only be constructed with a non-null policy pointer.
        unsafe { bindings::sbox_get_process_mitigations(self.policy.0) }
    }

    /// Sets process mitigation flags that don't take effect before the call to
    /// lower_token().
    ///
    /// Takes a `&mut self` because `sbox_set_delayed_process_mitigations`
    /// mutates the underlying policy object.
    pub fn set_delayed_process_mitigations(&mut self, flags: MitigationFlags) -> Result<()> {
        // Safe because TargetPolicy can only be constructed with a non-null policy pointer.
        match unsafe { bindings::sbox_set_delayed_process_mitigations(self.policy.0, flags) } {
            ResultCode::SBOX_ALL_OK => Ok(()),
            result_code => Err(SandboxError::new(result_code)),
        }
    }

    /// Returns the currently set delayed_ mitigation flags.
    pub fn delayed_process_mitigations(&self) -> MitigationFlags {
        // Safe because TargetPolicy can only be constructed with a non-null policy pointer.
        unsafe { bindings::sbox_get_delayed_process_mitigations(self.policy.0) }
    }

    /// Disconnect the target from CSRSS when TargetServices::lower_token() is
    /// called inside the target.
    ///
    /// Takes a `&mut self` because `sbox_set_disconnect_csrss` mutates the
    /// underlying policy object.
    pub fn set_disconnect_csrss(&mut self) -> Result<()> {
        // Safe because TargetPolicy can only be constructed with a non-null policy pointer.
        match unsafe { bindings::sbox_set_disconnect_csrss(self.policy.0) } {
            ResultCode::SBOX_ALL_OK => Ok(()),
            result_code => Err(SandboxError::new(result_code)),
        }
    }

    /// Sets the interceptions to operate in strict mode.
    ///
    /// Takes a `&mut self` because `sbox_set_delayed_process_mitigations`
    /// mutates the underlying policy object.
    pub fn set_strict_interceptions(&mut self) {
        // Safe because TargetPolicy can only be constructed with a non-null policy pointer.
        unsafe { bindings::sbox_set_strict_interceptions(self.policy.0) }
    }

    /// Sets a file as the handle that the process should inherit for stdout.
    pub fn set_stdout_from_file(&mut self, file: &'a std::fs::File) -> Result<()> {
        self.set_stdout_handle(file)
    }

    /// Sets a pipe as the handle that the process should inherit for stdout.
    pub fn set_stdout_from_pipe(&mut self, pipe: &'a named_pipes::PipeConnection) -> Result<()> {
        self.set_stdout_handle(pipe)
    }

    /// Sets the handle that the process should inherit for stdout.
    ///
    /// Takes a `&mut self` because `sbox_set_stdout_handle()` mutates the underlying policy object.
    fn set_stdout_handle(&mut self, handle: &'a dyn AsRawDescriptor) -> Result<()> {
        // Safe because TargetPolicy can only be constructed with a non-null policy pointer.
        match unsafe { bindings::sbox_set_stdout_handle(self.policy.0, handle.as_raw_descriptor()) }
        {
            ResultCode::SBOX_ALL_OK => {
                win_util::set_handle_inheritance(
                    handle.as_raw_descriptor(),
                    /* inheritable= */ true,
                )?;
                Ok(())
            }
            result_code => Err(SandboxError::new(result_code)),
        }
    }

    /// Sets a file as the handle that the process should inherit for stderr.
    pub fn set_stderr_from_file(&mut self, file: &'a std::fs::File) -> Result<()> {
        self.set_stderr_handle(file)
    }

    /// Sets a pipe as the handle that the process should inherit for stderr.
    pub fn set_stderr_from_pipe(&mut self, pipe: &'a named_pipes::PipeConnection) -> Result<()> {
        self.set_stderr_handle(pipe)
    }

    /// Sets the handle that the process should inherit for stderr.
    ///
    /// Takes a `&mut self` because `sbox_set_stderr_handle` mutates the underlying policy object.
    fn set_stderr_handle(&mut self, handle: &'a dyn AsRawDescriptor) -> Result<()> {
        // Safe because TargetPolicy can only be constructed with a non-null policy pointer.
        match unsafe { bindings::sbox_set_stderr_handle(self.policy.0, handle.as_raw_descriptor()) }
        {
            ResultCode::SBOX_ALL_OK => {
                win_util::set_handle_inheritance(
                    handle.as_raw_descriptor(),
                    /* inheritable= */ true,
                )?;
                Ok(())
            }
            result_code => Err(SandboxError::new(result_code)),
        }
    }

    /// Adds a policy rule effective for processes spawned using this policy.
    ///
    /// # Arguments:
    ///
    /// * subsystem: One of the enumerated Subsystems.
    /// * semantics: One of the enumerated Semantics.
    /// * pattern: A specific full path or a full path with wildcard patterns.
    ///
    ///   The valid wildcards are:
    ///   * `*`: Matches zero or more character. Only one in series allowed.
    ///   * `?`: Matches a single character. One or more in series are allowed.
    ///
    ///   Examples:
    ///   * `"c:\\documents and settings\\vince\\*.dmp"`
    ///   * `"c:\\documents and settings\\*\\crashdumps\\*.dmp"`
    ///   * `"c:\\temp\\app_log_?????_chrome.txt"`
    ///
    /// Takes a `&mut self` because `sbox_add_rule` mutates the underlying
    /// policy object.
    pub fn add_rule<T: AsRef<str>>(
        &mut self,
        subsystem: SubSystem,
        semantics: Semantics,
        pattern: T,
    ) -> Result<()> {
        // Safe because TargetPolicy can only be constructed with a non-null policy pointer.
        // The function does not modify the pattern pointer, so that usage is safe.
        match unsafe {
            bindings::sbox_add_rule(
                self.policy.0,
                subsystem,
                semantics,
                win32_wide_string(pattern.as_ref()).as_ptr(),
            )
        } {
            ResultCode::SBOX_ALL_OK => Ok(()),
            result_code => Err(SandboxError::new(result_code)),
        }
    }

    /// Adds a dll that will be unloaded in the target process before it gets
    /// a chance to initialize itself.
    ///
    /// Takes a `&mut self` because `sbox_add_dll_to_unload` mutates the
    /// underlying policy object.
    pub fn add_dll_to_unload(&mut self, dll_name: &str) -> Result<()> {
        // Safe because TargetPolicy can only be constructed with a non-null policy pointer.
        // The function does not modify the dll_name pointer, so that usage is safe.
        match unsafe {
            bindings::sbox_add_dll_to_unload(self.policy.0, win32_wide_string(dll_name).as_ptr())
        } {
            ResultCode::SBOX_ALL_OK => Ok(()),
            result_code => Err(SandboxError::new(result_code)),
        }
    }

    /// Adds a handle that will be closed in the target process after lockdown.
    /// Specifying `None` for `handle_name` indicates all handles of the specified
    /// type. An empty string for `handle_name` indicates the handle is unnamed.
    ///
    /// Takes a `&mut self` because `sbox_add_kernel_object_to_close` mutates the
    /// underlying policy object.
    pub fn add_kernel_object_to_close(
        &mut self,
        handle_type: &str,
        handle_name: Option<&str>,
    ) -> Result<()> {
        let handle_name_wide = handle_name.map(win32_wide_string);
        let handle_name_ptr = handle_name_wide
            .as_ref()
            .map_or(std::ptr::null(), Vec::<u16>::as_ptr);
        // Safe because TargetPolicy can only be constructed with a non-null policy pointer.
        // The function does not modify either of the string pointers, so that usage is safe.
        // The function safely handles null pointers for the handle name.
        match unsafe {
            bindings::sbox_add_kernel_object_to_close(
                self.policy.0,
                win32_wide_string(handle_type).as_ptr(),
                handle_name_ptr,
            )
        } {
            ResultCode::SBOX_ALL_OK => Ok(()),
            result_code => Err(SandboxError::new(result_code)),
        }
    }

    /// Adds a handle that will be shared with the target process.
    ///
    /// Takes a `&mut self` because `sbox_add_handle_to_share()` mutates the underlying policy object.
    pub fn add_handle_to_share(&mut self, handle: &'a dyn AsRawDescriptor) {
        // Safe because TargetPolicy can only be constructed with a non-null policy pointer.
        unsafe {
            bindings::sbox_add_handle_to_share(self.policy.0, handle.as_raw_descriptor());
        }
    }

    /// Locks down the default DACL of the created lockdown and initial tokens
    /// to restrict what other processes are allowed to access a process' kernel
    /// resources.
    ///
    /// Takes a `&mut self` because `sbox_set_lockdown_default_dacl()` mutates
    /// the underlying policy object.
    pub fn set_lockdown_default_dacl(&mut self) {
        // Safe because TargetPolicy can only be constructed with a non-null policy pointer.
        unsafe {
            bindings::sbox_set_lockdown_default_dacl(self.policy.0);
        }
    }

    /// Adds a restricting random SID to the restricted SIDs list as well as
    /// the default DACL.
    ///
    /// Takes a `&mut self` because `sbox_add_restricting_random_sid()` mutates
    /// the underlying policy object.
    pub fn add_restricting_random_sid(&mut self) {
        // Safe because TargetPolicy can only be constructed with a non-null policy pointer.
        unsafe {
            bindings::sbox_add_restricting_random_sid(self.policy.0);
        }
    }

    /// Configure policy to use an AppContainer profile.
    ///
    /// # Arguments:
    /// * `package_name`: the name of the profile to use.
    /// * `create_profile`: Specifying `true` for `create_profile` ensures
    ///   the profile exists, if set to `false` process creation will fail if the
    ///   profile has not already been created.
    ///
    /// Takes a `&mut self` because `sbox_add_dll_to_unload` mutates the
    /// underlying policy object.
    pub fn add_app_container_profile(
        &mut self,
        package_name: &str,
        create_profile: bool,
    ) -> Result<()> {
        // Safe because TargetPolicy can only be constructed with a non-null policy pointer.
        // The function does not modify the package_name pointer, so that usage is safe.
        match unsafe {
            bindings::sbox_add_app_container_profile(
                self.policy.0,
                win32_wide_string(package_name).as_ptr(),
                create_profile,
            )
        } {
            ResultCode::SBOX_ALL_OK => Ok(()),
            result_code => Err(SandboxError::new(result_code)),
        }
    }

    /// Returns a snapshot of the policy configuration.
    pub fn policy_info(&self) -> PolicyInfo {
        // Safe because TargetPolicy can only be constructed with a non-null
        // policy pointer. The underlying PolicyInfo object contains a copy of
        // the data from the TargetPolicy object, but does not hold any
        // references to it, so the lifetimes are independent.
        PolicyInfo {
            policy_info: unsafe { bindings::sbox_get_policy_info(self.policy.0) },
        }
    }
}

impl PolicyInfo {
    /// Returns a JSON representation of the policy snapshot.
    /// This pointer has the same lifetime as the PolicyInfo object.
    pub fn json(&self) -> &str {
        // Safe because PolicyInfo can only be constructed with a non-null
        // policy pointer. The string returned will be a valid pointer to a
        // valid c string. We bind the lifetime of the string to the lifetime
        // of the PolicyInfo object, as is guaranteed by the underlying
        // library. This is a string representation of a snapshot of the
        // policy, so it will not change.
        let c_str =
            unsafe { CStr::from_ptr(bindings::sbox_policy_info_json_string(self.policy_info)) };
        c_str.to_str().unwrap()
    }
}

// TODO(b/196996588): Develop more tests, especially policy-related, once we
// have a way to launch and test target processes.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_the_target() {
        let target = TargetServices::get().unwrap();
        assert_eq!(target, None);
    }

    #[test]
    fn is_the_broker() {
        let broker = BrokerServices::get().unwrap();
        assert_ne!(broker, None);
    }

    #[test]
    fn policy_handles_live_long_enough() {
        let broker = BrokerServices::get().unwrap().unwrap();
        let mut policy = broker.create_policy();
        let pipe = named_pipes::pair(
            &named_pipes::FramingMode::Byte,
            &named_pipes::BlockingMode::NoWait,
            0,
        )
        .unwrap();
        policy.set_stdout_handle(&pipe.0).unwrap();
        policy.set_stderr_handle(&pipe.0).unwrap();
        policy.add_handle_to_share(&pipe.0);
    }
}
