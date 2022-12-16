// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Trait to suspend virtual hardware.

use anyhow::anyhow;
use serde::Deserialize;
use serde::Serialize;

#[derive(Copy, Clone, Serialize, Deserialize)]
pub enum DeviceState {
    Awake,
    Sleep,
}

/// This trait provides the functions required for a device to implement to successfully
/// suspend/resume in crosvm.
pub trait Suspendable {
    /// Save the device state in an image that can be restored.
    fn snapshot(&self) -> anyhow::Result<serde_json::Value> {
        Err(anyhow!(
            "Suspendable::snapshot not implemented for {}",
            std::any::type_name::<Self>()
        ))
    }
    /// Load a saved snapshot of an image.
    fn restore(&mut self, _data: serde_json::Value) -> anyhow::Result<()> {
        Err(anyhow!(
            "Suspendable::restore not implemented for {}",
            std::any::type_name::<Self>()
        ))
    }
    /// Stop all threads related to the device.
    /// Sleep should be idempotent.
    fn sleep(&mut self) -> anyhow::Result<()> {
        Err(anyhow!(
            "Suspendable::sleep not implemented for {}",
            std::any::type_name::<Self>()
        ))
    }
    /// Create/Resume all threads related to the device.
    /// Wake should be idempotent.
    fn wake(&mut self) -> anyhow::Result<()> {
        Err(anyhow!(
            "Suspendable::wake not implemented for {}",
            std::any::type_name::<Self>()
        ))
    }
}

// General tests that should pass on all suspendables.
// Do implement device-specific tests to validate the functionality of the device.
// Those tests are not a replacement for regular tests. Only an extension specific to the trait's
// basic functionality.
#[macro_export]
macro_rules! suspendable_tests {
    ($($name:ident: $expr:expr,)*) => {
        $(
            mod $name {
                use super::*;

                #[test]
                fn test_sleep_idempotent() {
                    let unit = &mut $expr;
                    let res = unit.sleep();
                    let res2 = unit.sleep();
                    match res {
                        Ok(()) => (),
                        Err(e) => println!("{}", e),
                    }
                    match res2 {
                        Ok(()) => (),
                        Err(e) => println!("idempotent: {}", e),
                    }
                }

                #[test]
                fn test_snapshot_restore() {
                    let unit = &mut $expr;
                    let snap = unit.snapshot();
                    match snap {
                        Ok(snap_res) => {
                            let res = unit.restore(snap_res);
                            match res {
                                Ok(()) => (),
                                Err(e) => println!("{}", e),
                            }
                        },
                        Err(e) => println!("{}", e),
                    }
                }

                #[test]
                fn test_sleep_snapshot() {
                    let unit = &mut $expr;
                    let sleep_result = unit.sleep();
                    let snap_result = unit.snapshot();
                    match sleep_result {
                        Ok(()) => (),
                        Err(e) => println!("{}", e),
                    }
                    match snap_result {
                        Ok(_res) => (),
                        Err(e) => println!("{}", e),
                    }
                }

                #[test]
                fn test_sleep_snapshot_restore_wake() {
                    let unit = &mut $expr;
                    let sleep_result = unit.sleep();
                    let snap_result = unit.snapshot();
                    match sleep_result {
                        Ok(()) => (),
                        Err(e) => println!("{}", e),
                    }
                    match snap_result {
                        Ok(snap_res) => {
                            let res = unit.restore(snap_res);
                            match res {
                                Ok(()) => (),
                                Err(e) => println!("{}", e),
                            }
                        },
                        Err(e) => println!("{}", e),
                    }
                    let wake_res = unit.wake();
                    match wake_res {
                        Ok(()) => (),
                        Err(e) => println!("{}", e),
                    }
                }

                #[test]
                fn test_sleep_snapshot_wake() {
                    let unit = &mut $expr;
                    let sleep_result = unit.sleep();
                    let snap_result = unit.snapshot();
                    match sleep_result {
                        Ok(()) => (),
                        Err(e) => println!("{}", e),
                    }
                    match snap_result {
                        Ok(_snap_res) => (),
                        Err(e) => println!("{}", e),
                    }
                    let wake_res = unit.wake();
                    match wake_res {
                        Ok(()) => (),
                        Err(e) => println!("{}", e),
                    }
                }

                #[test]
                fn test_snapshot() {
                    let unit = &mut $expr;
                    let snap_result = unit.snapshot();
                    match snap_result {
                        Ok(_snap_res) => (),
                        Err(e) => println!("{}", e),
                    }
                }
            }
        )*
    }
}
