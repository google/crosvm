// Copyright 2025 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Centralized mock device implementations, for unit-tests.

use std::cmp::PartialEq;

use anyhow::Context;
use serde::Deserialize;
use serde::Serialize;
use snapshot::AnySnapshot;
use vm_control::DeviceId;
use vm_control::PlatformDeviceId;

use crate::BusDevice;
use crate::Suspendable;

/// A mock device, for unit-tests.
#[derive(Copy, Clone, Serialize, Deserialize, Eq, PartialEq, Debug)]
pub struct MockDevice;

impl BusDevice for MockDevice {
    fn device_id(&self) -> DeviceId {
        PlatformDeviceId::Mock.into()
    }

    fn debug_label(&self) -> String {
        "mock device".to_owned()
    }
}

impl Suspendable for MockDevice {
    fn snapshot(&mut self) -> anyhow::Result<AnySnapshot> {
        AnySnapshot::to_any(self).context("error serializing")
    }

    fn restore(&mut self, data: AnySnapshot) -> anyhow::Result<()> {
        *self = AnySnapshot::from_any(data).context("error deserializing")?;
        Ok(())
    }

    fn sleep(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    fn wake(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
}
