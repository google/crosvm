// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::Descriptor;

use crate::acpi::ACPIPMError;
use crate::IrqLevelEvent;

pub(crate) fn get_acpi_event_sock() -> Result<Option<Descriptor>, ACPIPMError> {
    Ok(None)
}

pub(crate) fn acpi_event_run(_sci_evt: &IrqLevelEvent, _acpi_event_sock: &Option<Descriptor>) {}
