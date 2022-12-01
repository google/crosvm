// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;

use base::Descriptor;
use sync::Mutex;

use crate::ac_adapter::AcAdapter;
use crate::acpi::ACPIPMError;
use crate::acpi::GpeResource;
use crate::IrqLevelEvent;

pub(crate) fn get_acpi_event_sock() -> Result<Option<Descriptor>, ACPIPMError> {
    Ok(None)
}

pub(crate) fn acpi_event_run(
    sci_evt: &IrqLevelEvent,
    _acpi_event_sock: &Option<Descriptor>,
    _gpe0: &Arc<Mutex<GpeResource>>,
    _ignored_gpe: &[u32],
    _ac_adapter: &Option<Arc<Mutex<AcAdapter>>>,
) {
}
