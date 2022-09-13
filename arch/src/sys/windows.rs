// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::MsrValueFrom;

impl MsrValueFrom {
    /// Get the physical(host) CPU id from MsrValueFrom type.
    pub fn get_cpu_id(&self) -> usize {
        match self {
            MsrValueFrom::RWFromCPU0 => 0,
            MsrValueFrom::RWFromRunningCPU => {
                unimplemented!();
            }
        }
    }
}
