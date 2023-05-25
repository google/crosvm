// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![deny(missing_docs)]

use anyhow::Context;
use base::error;
use base::EventToken;
use base::WaitContext;

use crate::userfaultfd::DeadUffdChecker;
use crate::userfaultfd::Userfaultfd;

/// Token for each [Userfaultfd] in [UffdList].
pub trait Token: EventToken {
    fn uffd_token(idx: u32) -> Self;
}

/// The list of [Userfaultfd].
pub struct UffdList<'a, T: Token, D: DeadUffdChecker> {
    list: Vec<Userfaultfd>,
    dead_uffd_checker: &'a D,
    wait_ctx: &'a WaitContext<T>,
    num_static_uffd: Option<usize>,
}

impl<'a, T: Token, D: DeadUffdChecker> UffdList<'a, T, D> {
    const ID_MAIN_UFFD: u32 = 0;

    /// Creates [UffdList].
    ///
    /// The [Userfaultfd] for the main process is required.
    pub fn new(
        main_uffd: Userfaultfd,
        dead_uffd_checker: &'a D,
        wait_ctx: &'a WaitContext<T>,
    ) -> anyhow::Result<Self> {
        let mut list = Self {
            list: Vec::with_capacity(1),
            dead_uffd_checker,
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
            // Dynamic uffds are target of GC.
            self.dead_uffd_checker.register(&uffd)?;
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

    /// Remove all dead [Userfaultfd] in the list.
    pub fn gc_dead_uffds(&mut self) -> anyhow::Result<()> {
        let mut idx = self.num_static_uffd.unwrap();
        let mut is_swapped = false;
        while idx < self.list.len() {
            if self.dead_uffd_checker.is_dead(&self.list[idx]) {
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

        // Error on removing page is not severe. It just wastes 1 page of memory which may reused
        // later.
        if let Err(e) = self.dead_uffd_checker.reset() {
            error!("failed to reset dead uffd checker: {:?}", e);
        }
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

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::time::Duration;

    use base::AsRawDescriptor;
    use base::Event;
    use base::FromRawDescriptor;
    use base::IntoRawDescriptor;
    use base::RawDescriptor;

    use super::*;

    #[derive(EventToken, Clone, Copy)]
    enum TestToken {
        UffdEvents(u32),
    }

    impl TestToken {
        fn get_idx(&self) -> u32 {
            match self {
                Self::UffdEvents(idx) => *idx,
            }
        }
    }

    impl Token for TestToken {
        fn uffd_token(idx: u32) -> Self {
            TestToken::UffdEvents(idx)
        }
    }

    struct FakeDeadUffdChecker {
        /// The pair of (file descriptor, is_dead)
        list: RefCell<Vec<(RawDescriptor, bool)>>,
    }

    impl FakeDeadUffdChecker {
        fn new() -> Self {
            Self {
                list: RefCell::new(Vec::new()),
            }
        }

        /// Creates a fake [Userfaultfd] backed by temporary [Event].
        ///
        /// Returned [Userfaultfd] only supports registering to epoll and close(2). You should not
        /// call any userfaultfd(2) related syscalls to the object.
        fn create_fake_uffd(&self) -> Userfaultfd {
            let raw_desc = Event::new().unwrap().into_raw_descriptor();

            self.list.borrow_mut().push((raw_desc, false));

            unsafe { Userfaultfd::from_raw_descriptor(raw_desc) }
        }

        fn make_readable(&self, raw_desc: RawDescriptor) {
            let ev = unsafe { Event::from_raw_descriptor(raw_desc) };
            ev.signal().unwrap();
            // Keep the file descriptor opened. The generated fake Userfaultfd has the actual
            // ownership of the RawDescriptor.
            ev.into_raw_descriptor();
        }

        fn mark_as_dead(&self, raw_desc: RawDescriptor) {
            for (rd, is_dead) in self.list.borrow_mut().iter_mut() {
                if *rd == raw_desc {
                    *is_dead = true;
                }
            }
        }
    }

    impl DeadUffdChecker for FakeDeadUffdChecker {
        fn register(&self, _uffd: &Userfaultfd) -> anyhow::Result<()> {
            // Do nothing
            Ok(())
        }

        fn is_dead(&self, uffd: &Userfaultfd) -> bool {
            for (raw_desc, is_alive) in self.list.borrow().iter() {
                if *raw_desc == uffd.as_raw_descriptor() {
                    return *is_alive;
                }
            }
            false
        }

        fn reset(&self) -> anyhow::Result<()> {
            // Do nothing
            Ok(())
        }
    }

    #[test]
    fn new_success() {
        let wait_ctx = WaitContext::<TestToken>::new().unwrap();
        let fake_checker = FakeDeadUffdChecker::new();
        let main_uffd = fake_checker.create_fake_uffd();

        assert!(UffdList::new(main_uffd, &fake_checker, &wait_ctx).is_ok());
    }

    #[test]
    fn register_success() {
        let wait_ctx = WaitContext::<TestToken>::new().unwrap();
        let fake_checker = FakeDeadUffdChecker::new();
        let main_uffd = fake_checker.create_fake_uffd();
        let uffd = fake_checker.create_fake_uffd();
        let mut uffd_list = UffdList::new(main_uffd, &fake_checker, &wait_ctx).unwrap();

        let result = uffd_list.register(uffd);
        assert!(result.is_ok());
        // is not dynamic device
        assert!(!result.unwrap());
    }

    #[test]
    fn register_dynamic_device() {
        let wait_ctx = WaitContext::<TestToken>::new().unwrap();
        let fake_checker = FakeDeadUffdChecker::new();
        let main_uffd = fake_checker.create_fake_uffd();
        let uffd1 = fake_checker.create_fake_uffd();
        let uffd2 = fake_checker.create_fake_uffd();
        let uffd3 = fake_checker.create_fake_uffd();
        let mut uffd_list = UffdList::new(main_uffd, &fake_checker, &wait_ctx).unwrap();

        // not dynamic
        assert!(!uffd_list.register(uffd1).unwrap());
        assert!(uffd_list.set_num_static_devices(2));
        // not dynamic
        assert!(!uffd_list.register(uffd2).unwrap());
        // dynamic
        assert!(uffd_list.register(uffd3).unwrap());
    }

    #[test]
    fn set_num_static_devices_twice() {
        let wait_ctx = WaitContext::<TestToken>::new().unwrap();
        let fake_checker = FakeDeadUffdChecker::new();
        let main_uffd = fake_checker.create_fake_uffd();
        let mut uffd_list = UffdList::new(main_uffd, &fake_checker, &wait_ctx).unwrap();

        assert!(uffd_list.set_num_static_devices(2));
        assert!(!uffd_list.set_num_static_devices(2));
    }

    #[test]
    fn register_token() {
        let wait_ctx = WaitContext::<TestToken>::new().unwrap();
        let fake_checker = FakeDeadUffdChecker::new();
        let main_uffd = fake_checker.create_fake_uffd();
        let uffd1 = fake_checker.create_fake_uffd();
        let uffd2 = fake_checker.create_fake_uffd();
        let rd2 = uffd2.as_raw_descriptor();
        let uffd3 = fake_checker.create_fake_uffd();
        let mut uffd_list = UffdList::new(main_uffd, &fake_checker, &wait_ctx).unwrap();
        uffd_list.register(uffd1).unwrap();
        uffd_list.register(uffd2).unwrap();
        uffd_list.register(uffd3).unwrap();

        fake_checker.make_readable(rd2);

        let events = wait_ctx.wait_timeout(Duration::from_millis(1)).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(
            uffd_list
                .get(events[0].token.get_idx())
                .unwrap()
                .as_raw_descriptor(),
            rd2
        );
    }

    #[test]
    fn gc_dead_uffds_with_all_alive() {
        let wait_ctx = WaitContext::<TestToken>::new().unwrap();
        let fake_checker = FakeDeadUffdChecker::new();
        let main_uffd = fake_checker.create_fake_uffd();
        let uffd1 = fake_checker.create_fake_uffd();
        let uffd2 = fake_checker.create_fake_uffd();
        let uffd3 = fake_checker.create_fake_uffd();
        let mut uffd_list = UffdList::new(main_uffd, &fake_checker, &wait_ctx).unwrap();
        uffd_list.set_num_static_devices(1);
        uffd_list.register(uffd1).unwrap();
        uffd_list.register(uffd2).unwrap();
        uffd_list.register(uffd3).unwrap();

        assert!(uffd_list.gc_dead_uffds().is_ok());
        assert_eq!(uffd_list.get_list().len(), 4);
    }

    #[test]
    fn gc_dead_uffds_with_dead_static_device() {
        let wait_ctx = WaitContext::<TestToken>::new().unwrap();
        let fake_checker = FakeDeadUffdChecker::new();
        let main_uffd = fake_checker.create_fake_uffd();
        let uffd1 = fake_checker.create_fake_uffd();
        let uffd2 = fake_checker.create_fake_uffd();
        let rd2 = uffd2.as_raw_descriptor();
        let uffd3 = fake_checker.create_fake_uffd();
        let mut uffd_list = UffdList::new(main_uffd, &fake_checker, &wait_ctx).unwrap();
        uffd_list.set_num_static_devices(2);
        uffd_list.register(uffd1).unwrap();
        uffd_list.register(uffd2).unwrap();
        uffd_list.register(uffd3).unwrap();
        fake_checker.mark_as_dead(rd2);

        assert!(uffd_list.gc_dead_uffds().is_ok());
        assert_eq!(uffd_list.get_list().len(), 4);
    }

    #[test]
    fn gc_dead_uffds_with_dead_dynamic_device() {
        let wait_ctx = WaitContext::<TestToken>::new().unwrap();
        let fake_checker = FakeDeadUffdChecker::new();
        let main_uffd = fake_checker.create_fake_uffd();
        let uffd1 = fake_checker.create_fake_uffd();
        let uffd2 = fake_checker.create_fake_uffd();
        let rd2 = uffd2.as_raw_descriptor();
        let uffd3 = fake_checker.create_fake_uffd();
        let rd3 = uffd3.as_raw_descriptor();
        let mut uffd_list = UffdList::new(main_uffd, &fake_checker, &wait_ctx).unwrap();
        uffd_list.set_num_static_devices(1);
        uffd_list.register(uffd1).unwrap();
        uffd_list.register(uffd2).unwrap();
        uffd_list.register(uffd3).unwrap();
        fake_checker.mark_as_dead(rd2);

        assert!(uffd_list.gc_dead_uffds().is_ok());
        // UffdList shrinks
        assert_eq!(uffd_list.get_list().len(), 3);
        fake_checker.make_readable(rd3);
        let events = wait_ctx.wait_timeout(Duration::from_millis(1)).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(
            uffd_list
                .get(events[0].token.get_idx())
                .unwrap()
                .as_raw_descriptor(),
            rd3
        );
    }

    #[test]
    fn gc_dead_uffds_with_dead_dynamic_device_readable_before_gc() {
        let wait_ctx = WaitContext::<TestToken>::new().unwrap();
        let fake_checker = FakeDeadUffdChecker::new();
        let main_uffd = fake_checker.create_fake_uffd();
        let uffd1 = fake_checker.create_fake_uffd();
        let uffd2 = fake_checker.create_fake_uffd();
        let rd2 = uffd2.as_raw_descriptor();
        let uffd3 = fake_checker.create_fake_uffd();
        let rd3 = uffd3.as_raw_descriptor();
        let mut uffd_list = UffdList::new(main_uffd, &fake_checker, &wait_ctx).unwrap();
        uffd_list.set_num_static_devices(1);
        uffd_list.register(uffd1).unwrap();
        uffd_list.register(uffd2).unwrap();
        uffd_list.register(uffd3).unwrap();
        fake_checker.mark_as_dead(rd2);
        fake_checker.make_readable(rd3);

        assert!(uffd_list.gc_dead_uffds().is_ok());
        // UffdList shrinks
        assert_eq!(uffd_list.get_list().len(), 3);
        let events = wait_ctx.wait_timeout(Duration::from_millis(1)).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(
            uffd_list
                .get(events[0].token.get_idx())
                .unwrap()
                .as_raw_descriptor(),
            rd3
        );
    }

    #[test]
    fn gc_dead_uffds_with_many_dead_dynamic_device() {
        let wait_ctx = WaitContext::<TestToken>::new().unwrap();
        let fake_checker = FakeDeadUffdChecker::new();
        let main_uffd = fake_checker.create_fake_uffd();
        let uffd1 = fake_checker.create_fake_uffd();
        let uffd2 = fake_checker.create_fake_uffd();
        fake_checker.mark_as_dead(uffd2.as_raw_descriptor());
        let uffd3 = fake_checker.create_fake_uffd();
        fake_checker.mark_as_dead(uffd3.as_raw_descriptor());
        let uffd4 = fake_checker.create_fake_uffd();
        let uffd5 = fake_checker.create_fake_uffd();
        fake_checker.mark_as_dead(uffd5.as_raw_descriptor());
        let rd4 = uffd4.as_raw_descriptor();
        let mut uffd_list = UffdList::new(main_uffd, &fake_checker, &wait_ctx).unwrap();
        uffd_list.set_num_static_devices(0);
        uffd_list.register(uffd1).unwrap();
        uffd_list.register(uffd2).unwrap();
        uffd_list.register(uffd3).unwrap();
        uffd_list.register(uffd4).unwrap();
        uffd_list.register(uffd5).unwrap();

        assert!(uffd_list.gc_dead_uffds().is_ok());
        // UffdList shrinks
        assert_eq!(uffd_list.get_list().len(), 3);
        fake_checker.make_readable(rd4);
        let events = wait_ctx.wait_timeout(Duration::from_millis(1)).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(
            uffd_list
                .get(events[0].token.get_idx())
                .unwrap()
                .as_raw_descriptor(),
            rd4
        );
    }
}
