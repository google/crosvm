// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::descriptor::{AsRawDescriptor, FromRawDescriptor, IntoRawDescriptor};
use crate::{FakeClock, RawDescriptor, Result};

use crate::platform::{FakeTimerFd, TimerFd};
use std::{
    os::unix::io::{AsRawFd, FromRawFd, IntoRawFd},
    sync::Arc,
    time::Duration,
};
use sync::Mutex;

/// See [TimerFd](crate::platform::TimerFd) for struct- and method-level
/// documentation.
pub struct Timer(pub TimerFd);
impl Timer {
    pub fn new() -> Result<Timer> {
        TimerFd::new().map(Timer)
    }
}

/// See [FakeTimerFd](crate::platform::FakeTimerFd) for struct- and method-level
/// documentation.
pub struct FakeTimer(FakeTimerFd);
impl FakeTimer {
    pub fn new(clock: Arc<Mutex<FakeClock>>) -> Self {
        FakeTimer(FakeTimerFd::new(clock))
    }
}

macro_rules! build_timer {
    ($timer:ident, $inner:ident) => {
        impl $timer {
            pub fn reset(&mut self, dur: Duration, interval: Option<Duration>) -> Result<()> {
                self.0.reset(dur, interval)
            }

            pub fn wait(&mut self) -> Result<()> {
                self.0.wait().map(|_| ())
            }

            pub fn clear(&mut self) -> Result<()> {
                self.0.clear()
            }

            pub fn resolution() -> Result<Duration> {
                $inner::resolution()
            }
        }

        impl AsRawDescriptor for $timer {
            fn as_raw_descriptor(&self) -> RawDescriptor {
                self.0.as_raw_fd()
            }
        }

        impl IntoRawDescriptor for $timer {
            fn into_raw_descriptor(self) -> RawDescriptor {
                self.0.into_raw_fd()
            }
        }
    };
}

build_timer!(Timer, TimerFd);
build_timer!(FakeTimer, FakeTimerFd);

impl FromRawDescriptor for Timer {
    unsafe fn from_raw_descriptor(descriptor: RawDescriptor) -> Self {
        Timer(TimerFd::from_raw_fd(descriptor))
    }
}
