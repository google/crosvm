// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::{
    AsRawDescriptor, FakeClock, FromRawDescriptor, IntoRawDescriptor, RawDescriptor, Result,
};

use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};
use std::sync::Arc;
use std::time::Duration;
use sync::Mutex;
use sys_util::{FakeTimerFd, TimerFd};

/// See [TimerFd](sys_util::TimerFd) for struct- and method-level
/// documentation.
pub struct Timer(pub TimerFd);
impl Timer {
    pub fn new() -> Result<Timer> {
        TimerFd::new().map(Timer)
    }
}

/// See [FakeTimerFd](sys_util::FakeTimerFd) for struct- and method-level
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

            pub fn is_armed(&self) -> Result<bool> {
                self.0.is_armed()
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
