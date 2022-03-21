// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::alloc::{alloc_zeroed, dealloc, handle_alloc_error, Layout};
use std::convert::{TryFrom, TryInto};
use std::mem::size_of;
use std::os::windows::io::RawHandle;
use std::{io, ptr};
use winapi::shared::minwindef::{FALSE, HLOCAL, LPDWORD, LPVOID, TRUE};
use winapi::shared::winerror::{ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS};
use winapi::um::accctrl::{
    EXPLICIT_ACCESS_A, NO_INHERITANCE, NO_MULTIPLE_TRUSTEE, PEXPLICIT_ACCESSA, SET_ACCESS,
    TRUSTEE_A, TRUSTEE_IS_SID, TRUSTEE_IS_USER,
};
use winapi::um::aclapi::SetEntriesInAclA;
use winapi::um::handleapi::CloseHandle;
use winapi::um::minwinbase::SECURITY_ATTRIBUTES;
use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
use winapi::um::securitybaseapi::{
    GetTokenInformation, InitializeSecurityDescriptor, MakeSelfRelativeSD,
    SetSecurityDescriptorDacl,
};
use winapi::um::winbase::LocalFree;
use winapi::um::winnt::{
    TokenUser, ACL, GENERIC_ALL, PACL, PSECURITY_DESCRIPTOR, SECURITY_DESCRIPTOR,
    SECURITY_DESCRIPTOR_REVISION, TOKEN_ALL_ACCESS, TOKEN_INFORMATION_CLASS, TOKEN_USER,
};

use lazy_static::lazy_static;

/// Struct for wrapping `SECURITY_ATTRIBUTES` and `SECURITY_DESCRIPTOR`.
pub struct SecurityAttributes<T: SecurityDescriptor> {
    // The security descriptor shouldn't move, as it will be referenced by the
    // security attributes. We already limit what can be done with the security
    // attributes by only providing a reference to it, but we also want to
    // ensure the security descriptor pointer remains valid even if this struct
    // moves around.
    _security_descriptor: T,
    security_attributes: SECURITY_ATTRIBUTES,
}

impl<T: SecurityDescriptor> SecurityAttributes<T> {
    /// Create a new `SecurityAttributes` struct with the provided `security_descriptor`.
    pub fn new_with_security_descriptor(security_descriptor: T, inherit: bool) -> Self {
        let sd = security_descriptor.security_descriptor();
        let security_attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd as PSECURITY_DESCRIPTOR,
            bInheritHandle: if inherit { TRUE } else { FALSE },
        };
        SecurityAttributes {
            _security_descriptor: security_descriptor,
            security_attributes,
        }
    }
}

impl SecurityAttributes<SelfRelativeSecurityDescriptor> {
    /// Create a new `SecurityAttributes` struct. This struct will have a
    /// `SECURITY_DESCRIPTOR` that allows full access (`GENERIC_ALL`) to only
    /// the current user.
    pub fn new(inherit: bool) -> io::Result<Self> {
        Ok(Self::new_with_security_descriptor(
            SelfRelativeSecurityDescriptor::new()?,
            inherit,
        ))
    }
}

impl<T: SecurityDescriptor> AsRef<SECURITY_ATTRIBUTES> for SecurityAttributes<T> {
    fn as_ref(&self) -> &SECURITY_ATTRIBUTES {
        &self.security_attributes
    }
}

impl<T: SecurityDescriptor> AsMut<SECURITY_ATTRIBUTES> for SecurityAttributes<T> {
    fn as_mut(&mut self) -> &mut SECURITY_ATTRIBUTES {
        &mut self.security_attributes
    }
}

trait TokenClass {
    fn class() -> TOKEN_INFORMATION_CLASS;
}

impl TokenClass for TOKEN_USER {
    fn class() -> TOKEN_INFORMATION_CLASS {
        TokenUser
    }
}

struct TokenInformation<T> {
    token_info: *mut T,
    layout: Layout,
}

impl<T: TokenClass> TokenInformation<T> {
    fn new(mut token: ProcessToken) -> io::Result<Self> {
        let token_handle = token.get();
        // Retrieve the size of the struct.
        let mut size: u32 = 0;
        // Safe because size is valid, and TokenInformation is optional and allowed to be null.
        if unsafe {
            // The idiomatic usage of GetTokenInformation() requires two calls
            // to the function: the first to get the length of the data that the
            // function would return, and the second to fetch the data.
            GetTokenInformation(
                /* TokenHandle= */ token_handle,
                /* TokenInformationClass= */ T::class(),
                /* TokenInformation= */ ptr::null_mut(),
                /* TokenInformationLength= */ 0,
                /* ReturnLength= */ &mut size,
            ) == 0
        } {
            const INSUFFICIENT_BUFFER: i32 = ERROR_INSUFFICIENT_BUFFER as i32;
            match io::Error::last_os_error().raw_os_error() {
                Some(INSUFFICIENT_BUFFER) => {
                    // Despite returning failure, the function will fill in the
                    // expected buffer length into the ReturnLength parameter.
                    // It may fail in other ways (e.g. if an invalid TokenHandle
                    // is provided), so we check that we receive the expected
                    // error code before assuming that we received a valid
                    // ReturnLength. In this case, we can ignore the error.
                }
                _ => return Err(io::Error::last_os_error()),
            };
        }

        // size must be > 0. 0-sized layouts break alloc()'s assumptions.
        assert!(size > 0, "Unable to get size of token information");

        // Since we don't statically know the full size of the struct, we
        // allocate memory for it based on the previous call, aligned to pointer
        // size.
        let layout = Layout::from_size_align(size as usize, size_of::<LPVOID>())
            .expect("Failed to create layout");
        assert!(layout.size() > 0, "Failed to create valid layout");
        // Safe as we assert that layout's size is non-zero.
        let token_info = unsafe { alloc_zeroed(layout) } as *mut T;
        if token_info.is_null() {
            handle_alloc_error(layout);
        }

        let token_info = TokenInformation::<T> { token_info, layout };

        // Safe because token_user and size are valid.
        if unsafe {
            GetTokenInformation(
                /* TokenHandle= */ token_handle,
                /* TokenInformationClass= */ T::class(),
                /* TokenInformation= */ token_info.token_info as LPVOID,
                /* TokenInformationLength= */ size,
                /* ReturnLength= */ &mut size,
            ) == 0
        } {
            return Err(io::Error::last_os_error());
        }

        Ok(token_info)
    }
}

impl<T> AsRef<T> for TokenInformation<T> {
    fn as_ref(&self) -> &T {
        // Safe because the underlying pointer is guaranteed to be properly
        // aligned, dereferenceable, and point to a valid T. The underlying
        // value will not be modified through the pointer and can only be
        // accessed through these returned references.
        unsafe { &*self.token_info }
    }
}

impl<T> AsMut<T> for TokenInformation<T> {
    fn as_mut(&mut self) -> &mut T {
        // Safe because the underlying pointer is guaranteed to be properly
        // aligned, dereferenceable, and point to a valid T. The underlying
        // value will not be modified through the pointer and can only be
        // accessed through these returned references.
        unsafe { &mut *self.token_info }
    }
}

impl<T> Drop for TokenInformation<T> {
    fn drop(&mut self) {
        // Safe because we ensure the pointer is valid in the constructor, and
        // we are using the same layout struct as during the allocation.
        unsafe { dealloc(self.token_info as *mut u8, self.layout) }
    }
}

struct ProcessToken {
    token: RawHandle,
}

impl ProcessToken {
    fn new() -> io::Result<Self> {
        let mut token: RawHandle = ptr::null_mut();

        // Safe because token is valid.
        if unsafe {
            OpenProcessToken(
                /* ProcessHandle= */ GetCurrentProcess(),
                /* DesiredAccess= */ TOKEN_ALL_ACCESS,
                /* TokenHandle= */ &mut token,
            ) == 0
        } {
            return Err(io::Error::last_os_error());
        }
        Ok(ProcessToken { token })
    }

    fn get(&mut self) -> RawHandle {
        self.token
    }
}

impl Drop for ProcessToken {
    fn drop(&mut self) {
        // Safe as token is valid, but the call should be safe regardless.
        unsafe {
            CloseHandle(self.token);
        }
    }
}

pub trait SecurityDescriptor {
    fn security_descriptor(&self) -> *const SECURITY_DESCRIPTOR;
}

pub struct AbsoluteSecurityDescriptor {
    descriptor: SECURITY_DESCRIPTOR,
    acl: *mut ACL,
}

impl AbsoluteSecurityDescriptor {
    /// Creates a `SECURITY_DESCRIPTOR` struct which gives full access rights
    /// (`GENERIC_ALL`) to only the current user.
    fn new() -> io::Result<AbsoluteSecurityDescriptor> {
        let token = ProcessToken::new()?;
        let token_user = TokenInformation::<TOKEN_USER>::new(token)?;
        let sid = token_user.as_ref().User.Sid;

        let mut ea = EXPLICIT_ACCESS_A {
            grfAccessPermissions: GENERIC_ALL,
            grfAccessMode: SET_ACCESS,
            grfInheritance: NO_INHERITANCE,
            Trustee: TRUSTEE_A {
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_USER,
                ptstrName: sid as *mut i8,
                pMultipleTrustee: ptr::null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            },
        };

        let mut security_descriptor: std::mem::MaybeUninit<AbsoluteSecurityDescriptor> =
            std::mem::MaybeUninit::uninit();

        let ptr = security_descriptor.as_mut_ptr();

        // Safe because security_descriptor is valid but uninitialized, and
        // InitializeSecurityDescriptor will initialize it.
        if unsafe {
            InitializeSecurityDescriptor(
                /* pSecurityDescriptor= */
                ptr::addr_of_mut!((*ptr).descriptor) as PSECURITY_DESCRIPTOR,
                /* dwRevision= */ SECURITY_DESCRIPTOR_REVISION,
            ) == 0
        } {
            return Err(io::Error::last_os_error());
        }

        // Safe because ea and acl are valid and OldAcl is allowed to be null.
        if unsafe {
            SetEntriesInAclA(
                /* cCountOfExplicitEntries= */ 1,
                /* pListOfExplicitEntries= */ &mut ea as PEXPLICIT_ACCESSA,
                /* OldAcl= */ ptr::null_mut(),
                /* NewAcl= */
                ptr::addr_of_mut!((*ptr).acl) as *mut PACL,
            )
        } != ERROR_SUCCESS
        {
            return Err(io::Error::last_os_error());
        }

        // Safe because security_descriptor is valid and initialized after
        // InitializeSecurityDescriptor() and SetEntriesInAclA().
        let mut security_descriptor = unsafe { security_descriptor.assume_init() };
        let sd = &mut security_descriptor.descriptor as *mut SECURITY_DESCRIPTOR;

        // Safe because the descriptor is valid, and acl is valid after SetEntriesInAclA()
        if unsafe {
            SetSecurityDescriptorDacl(
                /* pSecurityDescriptor= */ sd as PSECURITY_DESCRIPTOR,
                /* bDaclPresent= */ TRUE,
                /* pDacl= */ security_descriptor.acl,
                /* bDaclDefaulted= */ FALSE,
            ) == 0
        } {
            return Err(io::Error::last_os_error());
        }

        Ok(security_descriptor)
    }
}

impl SecurityDescriptor for AbsoluteSecurityDescriptor {
    fn security_descriptor(&self) -> *const SECURITY_DESCRIPTOR {
        &self.descriptor as *const SECURITY_DESCRIPTOR
    }
}

impl Drop for AbsoluteSecurityDescriptor {
    fn drop(&mut self) {
        // Safe because we guarantee that on creation acl is initialized to a
        // pointer that can be freed.
        unsafe { LocalFree(self.acl as HLOCAL) };
    }
}

pub struct SelfRelativeSecurityDescriptor {
    descriptor: *mut SECURITY_DESCRIPTOR,
    layout: Layout,
}

impl Drop for SelfRelativeSecurityDescriptor {
    fn drop(&mut self) {
        unsafe { dealloc(self.descriptor as *mut u8, self.layout) }
    }
}

impl Clone for SelfRelativeSecurityDescriptor {
    fn clone(&self) -> Self {
        // Safe because we know that the layout's size is non-zero.
        let descriptor = unsafe { alloc_zeroed(self.layout) } as *mut SECURITY_DESCRIPTOR;
        if descriptor.is_null() {
            handle_alloc_error(self.layout);
        }
        let sd = SelfRelativeSecurityDescriptor {
            descriptor,
            layout: self.layout,
        };
        // Safe because:
        //  * `src` is at least `count` bytes, as it was allocated using the above layout.
        //  * `dst` is at least `count` bytes, as we just allocated it using the above layout.
        //  * `src` and `dst` are aligned according to the layout, and we are copying byte-wise.
        //  * `src` and `dst` do not overlap, as we just allocated new memory for `dst`.
        unsafe {
            std::ptr::copy_nonoverlapping::<u8>(
                /* src= */ self.descriptor as *const u8,
                /* dst= */ sd.descriptor as *mut u8,
                /* count= */ self.layout.size(),
            )
        };
        sd
    }
}

impl TryFrom<AbsoluteSecurityDescriptor> for SelfRelativeSecurityDescriptor {
    type Error = io::Error;

    fn try_from(sd: AbsoluteSecurityDescriptor) -> io::Result<Self> {
        let mut size: u32 = 0;
        let descriptor = &sd.descriptor as *const SECURITY_DESCRIPTOR;

        // Safe because descriptor and size are valid, and pSelfRelativeSD is
        // optional and allowed to be null.
        if unsafe {
            MakeSelfRelativeSD(
                /* pAbsoluteSD= */ descriptor as PSECURITY_DESCRIPTOR,
                /* pSelfRelativeSD= */ ptr::null_mut(),
                /* lpdwBufferLength= */ &mut size as LPDWORD,
            )
        } == 0
        {
            const INSUFFICIENT_BUFFER: i32 = ERROR_INSUFFICIENT_BUFFER as i32;
            match io::Error::last_os_error().raw_os_error() {
                Some(INSUFFICIENT_BUFFER) => {
                    // Despite returning failure, the function will fill in the
                    // expected buffer length into the lpdwBufferLength parameter.
                    // It may fail in other ways (e.g. if an invalid pAbsoluteSD
                    // is provided), so we check that we receive the expected
                    // error code before assuming that we received a valid
                    // lpdwBufferLength. In this case, we can ignore the error.
                }
                _ => return Err(io::Error::last_os_error()),
            }
        }
        // size must be > 0. 0-sized layouts break alloc()'s assumptions.
        assert!(size > 0, "Unable to get size of self-relative SD");

        // Since we don't statically know the full size of the struct, we
        // allocate memory for it based on the previous call, aligned to pointer
        // size.
        let layout = Layout::from_size_align(size as usize, size_of::<LPVOID>())
            .expect("Failed to create layout");
        assert!(layout.size() > 0, "Failed to create valid layout");
        // Safe as we assert that layout's size is non-zero.
        let self_relative_sd = unsafe { alloc_zeroed(layout) } as *mut SECURITY_DESCRIPTOR;
        if self_relative_sd.is_null() {
            handle_alloc_error(layout);
        }

        let self_relative_sd = SelfRelativeSecurityDescriptor {
            descriptor: self_relative_sd,
            layout,
        };

        // Safe because descriptor is valid, the newly allocated
        // self_relative_sd descriptor is valid, and size is valid.
        if unsafe {
            MakeSelfRelativeSD(
                /* pAbsoluteSD= */ descriptor as PSECURITY_DESCRIPTOR,
                /* pSelfRelativeSD= */ self_relative_sd.descriptor as PSECURITY_DESCRIPTOR,
                /* lpdwBufferLength= */ &mut size as LPDWORD,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }

        Ok(self_relative_sd)
    }
}

lazy_static! {
    static ref DEFAULT_SECURITY_DESCRIPTOR: SelfRelativeSecurityDescriptor =
        SelfRelativeSecurityDescriptor::new().expect("Failed to create security descriptor");
}

impl SelfRelativeSecurityDescriptor {
    /// Creates a `SECURITY_DESCRIPTOR` struct which gives full access rights
    /// (`GENERIC_ALL`) to only the current user.
    fn new() -> io::Result<Self> {
        AbsoluteSecurityDescriptor::new()?.try_into()
    }

    /// Gets a copy of a singleton `SelfRelativeSecurityDescriptor`.
    pub fn get_singleton() -> SelfRelativeSecurityDescriptor {
        DEFAULT_SECURITY_DESCRIPTOR.clone()
    }
}

impl SecurityDescriptor for SelfRelativeSecurityDescriptor {
    fn security_descriptor(&self) -> *const SECURITY_DESCRIPTOR {
        self.descriptor
    }
}

// Safe because the descriptor and ACLs are treated as immutable by consuming
// functions and can be safely shared between threads.
unsafe impl Send for SelfRelativeSecurityDescriptor {}

// Safe because the descriptor and ACLs are treated as immutable by consuming
// functions.
unsafe impl Sync for SelfRelativeSecurityDescriptor {}
