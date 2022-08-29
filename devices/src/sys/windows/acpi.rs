// Copyright 2022 The ChromiumOS Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;

use base::Descriptor;
use sync::Mutex;

use crate::acpi::ACPIPMError;
use crate::acpi::GpeResource;

pub(crate) fn get_acpi_event_sock() -> Result<Option<Descriptor>, ACPIPMError> {
    Ok(None)
}

pub(crate) fn acpi_event_run(
    _acpi_event_sock: &Option<Descriptor>,
    _gpe0: &Arc<Mutex<GpeResource>>,
    _ignored_gpe: &[u32],
) {
}
