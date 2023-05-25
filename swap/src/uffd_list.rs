// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![deny(missing_docs)]

use anyhow::Context;
use base::error;
use base::EventToken;
use base::WaitContext;

use crate::pagesize::pages_to_bytes;
use crate::userfaultfd::Error as UffdError;
use crate::userfaultfd::Userfaultfd;

/// Token for each [Userfaultfd] in [UffdList].
pub trait Token: EventToken {
    fn uffd_token(idx: u32) -> Self;
}

/// The list of [Userfaultfd].
pub struct UffdList<'a, T: Token> {
    list: Vec<Userfaultfd>,
    dummy_mmap_addr: *mut u8,
    wait_ctx: &'a WaitContext<T>,
    num_static_uffd: Option<usize>,
}

impl<'a, T: Token> UffdList<'a, T> {
    const ID_MAIN_UFFD: u32 = 0;

    /// Creates [UffdList].
    ///
    /// The [Userfaultfd] for the main process is required.
    pub fn new(
        main_uffd: Userfaultfd,
        dummy_mmap_addr: *mut u8,
        wait_ctx: &'a WaitContext<T>,
    ) -> anyhow::Result<Self> {
        let mut list = Self {
            list: Vec::with_capacity(1),
            dummy_mmap_addr,
            wait_ctx,
            num_static_uffd: None,
        };
        list.register(main_uffd)?;
        Ok(list)
    }

    /// Set the count of static devices.
    ///
    /// Devices attached after guest booting are treated as dynamic device which can be detached (e.g. hotplug devices)
    pub fn set_num_static_devices(&mut self, num_static_devices: u32) -> bool {
        if self.num_static_uffd.is_some() {
            return false;
        }
        // +1 corresponds to the uffd of the main process.
        let num_static_uffd = num_static_devices as usize + 1;
        self.num_static_uffd = Some(num_static_uffd);
        true
    }

    /// Registers a new [Userfaultfd] to this list and [WaitContext].
    pub fn register(&mut self, uffd: Userfaultfd) -> anyhow::Result<bool> {
        let is_dynamic_uffd = self
            .num_static_uffd
            .map(|num_static_uffd| self.list.len() >= num_static_uffd)
            .unwrap_or(false);
        if is_dynamic_uffd {
            // Dynamic uffds are target of GC. uffd GC uses dummy mmap to check the liveness of the
            // userfaultfd.
            // SAFETY: no one except UffdList access dummy_mmap.
            unsafe { uffd.register(self.dummy_mmap_addr as usize, pages_to_bytes(1)) }
                .context("register dummy mmap")?;
        }

        let id_uffd = self
            .list
            .len()
            .try_into()
            .context("too many userfaultfd forked")?;

        self.wait_ctx
            .add(&uffd, T::uffd_token(id_uffd))
            .context("add to wait context")?;
        self.list.push(uffd);

        Ok(is_dynamic_uffd)
    }

    fn free_dummy_page(&self) {
        // SAFETY: no one except UffdList access dummy_mmap.
        let res = unsafe {
            libc::madvise(
                self.dummy_mmap_addr as *mut libc::c_void,
                pages_to_bytes(1),
                libc::MADV_REMOVE,
            )
        };
        if res < 0 {
            error!("failed to clear dummy mmap: {:?}", base::Error::last());
        }
    }

    /// Remove all dead [Userfaultfd] in the list.
    pub fn gc_dead_uffds(&mut self) -> anyhow::Result<()> {
        let mut idx = self.num_static_uffd.unwrap();
        let mut is_swapped = false;
        while idx < self.list.len() {
            // UFFDIO_ZEROPAGE returns ESRCH for dead uffd.
            let is_dead_uffd = matches!(
                self.list[idx].zero(self.dummy_mmap_addr as usize, pages_to_bytes(1), false),
                Err(UffdError::UffdClosed)
            );
            if is_dead_uffd {
                self.wait_ctx
                    .delete(&self.list[idx])
                    .context("delete dead uffd from wait context")?;
                self.list.swap_remove(idx);
                is_swapped = true;
            } else {
                if is_swapped {
                    self.wait_ctx
                        .modify(
                            &self.list[idx],
                            base::EventType::ReadWrite,
                            T::uffd_token(idx as u32),
                        )
                        .context("update token")?;
                    is_swapped = false;
                }
                idx += 1;
            }
        }
        self.free_dummy_page();
        Ok(())
    }

    /// Returns the reference of [Userfaultfd] if exists.
    pub fn get(&self, id: u32) -> Option<&Userfaultfd> {
        self.list.get(id as usize)
    }

    /// Returns the reference of the [Userfaultfd] of the main process.
    pub fn main_uffd(&self) -> &Userfaultfd {
        &self.list[Self::ID_MAIN_UFFD as usize]
    }

    /// Returns cloned [Userfaultfd] of the main process.
    pub fn clone_main_uffd(&self) -> crate::userfaultfd::Result<Userfaultfd> {
        self.list[Self::ID_MAIN_UFFD as usize].try_clone()
    }

    /// Returns the all [Userfaultfd] registered.
    pub fn get_list(&self) -> &[Userfaultfd] {
        &self.list
    }
}
