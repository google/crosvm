// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::os::fd::AsFd;
use std::time::Duration;

use nix::sys::epoll::Epoll;
use nix::sys::epoll::EpollCreateFlags;
use nix::sys::epoll::EpollEvent;
use nix::sys::epoll::EpollFlags;
use nix::sys::epoll::EpollTimeout;

use crate::rutabaga_os::WaitEvent;
use crate::rutabaga_os::WAIT_CONTEXT_MAX;
use crate::rutabaga_utils::RutabagaResult;

pub struct WaitContext {
    epoll_ctx: Epoll,
}

impl WaitContext {
    pub fn new() -> RutabagaResult<WaitContext> {
        let epoll = Epoll::new(EpollCreateFlags::empty())?;
        Ok(WaitContext { epoll_ctx: epoll })
    }

    pub fn add<Waitable: AsFd>(
        &mut self,
        connection_id: u64,
        waitable: Waitable,
    ) -> RutabagaResult<()> {
        self.epoll_ctx.add(
            waitable,
            EpollEvent::new(EpollFlags::EPOLLIN, connection_id),
        )?;
        Ok(())
    }

    pub fn wait(&mut self, duration_opt: Option<Duration>) -> RutabagaResult<Vec<WaitEvent>> {
        let mut events = [EpollEvent::empty(); WAIT_CONTEXT_MAX];

        let epoll_timeout = duration_opt
            .map(|duration| {
                if duration.is_zero() {
                    EpollTimeout::ZERO
                } else {
                    // We shouldn't need timeouts greater than 60s.
                    let timeout: u16 = duration.as_millis().try_into().unwrap_or(u16::MAX);
                    EpollTimeout::from(timeout)
                }
            })
            .unwrap_or(EpollTimeout::NONE);

        let count = loop {
            match self.epoll_ctx.wait(&mut events, epoll_timeout) {
                Err(nix::errno::Errno::EINTR) => (),
                result => break result?,
            }
        };

        let events = events[0..count]
            .iter()
            .map(|e| WaitEvent {
                connection_id: e.data(),
                readable: e.events() & EpollFlags::EPOLLIN == EpollFlags::EPOLLIN,
                hung_up: e.events() & EpollFlags::EPOLLHUP == EpollFlags::EPOLLHUP,
            })
            .collect();

        Ok(events)
    }

    pub fn delete<Waitable: AsFd>(&mut self, waitable: Waitable) -> RutabagaResult<()> {
        self.epoll_ctx.delete(waitable)?;
        Ok(())
    }
}
