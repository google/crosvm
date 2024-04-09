// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::mem;
use std::time::Duration;

use crate::errno::errno_result;
use crate::errno::Error;
use crate::errno::Result;
use crate::sys::macos::kqueue::make_kevent;
use crate::sys::macos::kqueue::Kqueue;
use crate::sys::unix::clone_descriptor;
use crate::SafeDescriptor;
use crate::Timer;

impl Timer {
    pub fn new() -> Result<Timer> {
        Ok(Timer {
            handle: SafeDescriptor::from(Kqueue::new()?),
            interval: None,
        })
    }

    fn queue(&self) -> Result<Kqueue> {
        Ok(Kqueue::from(clone_descriptor(&self.handle)?))
    }
}

impl crate::TimerTrait for Timer {
    fn reset(&mut self, delay: Duration, interval: Option<Duration>) -> Result<()> {
        match (delay, interval) {
            (delay, None) => {
                let mut event = make_kevent(
                    libc::EVFILT_TIMER,
                    libc::EV_ADD | libc::EV_ONESHOT,
                    libc::NOTE_NSECONDS,
                );
                event.data = delay
                    .as_nanos()
                    .try_into()
                    .map_err(|_| Error::new(libc::EINVAL))?;
                self.queue()?.kevent(&[event], &mut [], None)?;
            }
            (delay, Some(interval)) if delay.as_millis() <= 1 => {
                let mut event = make_kevent(libc::EVFILT_TIMER, libc::EV_ADD, libc::NOTE_NSECONDS);
                event.data = interval
                    .as_nanos()
                    .try_into()
                    .map_err(|_| Error::new(libc::EINVAL))?;
                self.queue()?.kevent(&[event], &mut [], None)?;
            }
            // Can't set a timer that starts after a delay
            (_delay, Some(_)) => {
                return Err(Error::new(libc::EINVAL));
            }
        }
        Ok(())
    }

    fn wait(&mut self) -> Result<()> {
        let mut event = [make_kevent(0, 0, 0)];
        self.queue()?.kevent(&[], &mut event[..], None)?;
        Ok(())
    }

    fn mark_waited(&mut self) -> Result<bool> {
        // Timers cannot be tested without consuming the event
        Ok(false)
    }

    fn clear(&mut self) -> Result<()> {
        let delete = make_kevent(libc::EVFILT_TIMER, libc::EV_DELETE, 0);
        self.queue()?.kevent(&[delete], &mut [], None)?;
        Ok(())
    }

    fn resolution(&self) -> Result<Duration> {
        // SAFETY:
        // Safe because we are zero-initializing a struct with only primitive member fields.
        let mut res: libc::timespec = unsafe { mem::zeroed() };

        // SAFETY:
        // Safe because it only modifies a local struct and we check the return value.
        let ret = unsafe { libc::clock_getres(libc::CLOCK_MONOTONIC, &mut res) };

        if ret != 0 {
            return errno_result();
        }
        println!("{:?}", res);

        Ok(Duration::new(res.tv_sec as u64, res.tv_nsec as u32))
    }
}
