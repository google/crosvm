// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Emulates virtual and hardware devices.

mod cmos;
mod serial;
mod i8042;
mod bus;

pub use self::cmos::Cmos;
pub use self::serial::Serial;
pub use self::i8042::I8042Device;
pub use self::bus::{Bus, BusDevice};
