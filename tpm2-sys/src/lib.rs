// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::os::raw::{c_int, c_uchar, c_uint};

extern "C" {
    pub fn TPM_Manufacture(firstTime: c_int) -> c_int;
    pub fn _plat__SetNvAvail();
    pub fn _plat__Signal_PowerOn() -> c_int;
    pub fn _TPM_Init();
    pub fn ExecuteCommand(
        requestSize: c_uint,
        request: *mut c_uchar,
        responseSize: *mut c_uint,
        response: *mut *mut c_uchar,
    );
}
