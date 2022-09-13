// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod acpi;
pub(crate) mod serial_device;

pub(crate) use acpi::acpi_event_run;
pub(crate) use acpi::get_acpi_event_sock;
