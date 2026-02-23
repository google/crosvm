// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::acpi::ACPIPMError;

/// On macOS, ACPI events are not available.
pub(crate) fn get_acpi_event_sock() -> Result<Option<()>, ACPIPMError> {
    Ok(None)
}
