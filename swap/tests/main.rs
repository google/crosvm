// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Integration tests for vmm-swap feature

#[cfg(all(unix, feature = "enable"))]
mod common;

#[cfg(all(unix, feature = "enable"))]
mod test {
    use std::time::Duration;

    use base::pagesize;
    use base::sys::wait_for_pid;
    use base::AsRawDescriptor;
    use base::FromRawDescriptor;
    use base::IntoRawDescriptor;
    use base::SafeDescriptor;
    use base::Tube;
    use swap::userfaultfd::register_regions;
    use swap::userfaultfd::unregister_regions;
    use swap::userfaultfd::Userfaultfd;
    use swap::SwapController;
    use swap::SwapState;
    use vm_memory::GuestAddress;
    use vm_memory::GuestMemory;
    use vm_memory::MemoryRegionOptions;

    use super::common::*;

    pub fn register_region_skip_obsolete_process() {
        let shm = create_shared_memory("test", 3 * pagesize());
        let uffd = create_uffd_for_test();
        let base_addr = shm.base_addr();
        let region = base_addr..(base_addr + 3 * pagesize());
        let regions = [region];
        let (tube_main, tube_child) = Tube::pair().unwrap();
        // SAFETY: trivially safe
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            // child process
            let uffd = create_uffd_for_test();
            // TODO(b/315998194): Add safety comment
            #[allow(clippy::undocumented_unsafe_blocks)]
            tube_child
                .send(&unsafe { SafeDescriptor::from_raw_descriptor(uffd.as_raw_descriptor()) })
                .unwrap();
            std::process::exit(0);
        }
        let uffd_descriptor = tube_main
            .recv::<SafeDescriptor>()
            .unwrap()
            .into_raw_descriptor();
        wait_for_pid(pid, 0).unwrap();
        // TODO(b/315998194): Add safety comment
        #[allow(clippy::undocumented_unsafe_blocks)]
        let uffd_child = unsafe { Userfaultfd::from_raw_descriptor(uffd_descriptor) };

        // TODO(b/315998194): Add safety comment
        #[allow(clippy::undocumented_unsafe_blocks)]
        let result = unsafe { register_regions(&regions, &[uffd, uffd_child]) };

        // no error from ENOMEM
        assert_eq!(result.is_ok(), true);
    }

    pub fn unregister_region_skip_obsolete_process() {
        let shm = create_shared_memory("test", 3 * pagesize());
        let uffd = create_uffd_for_test();
        let base_addr = shm.base_addr();
        let region = base_addr..(base_addr + 3 * pagesize());
        let regions = [region];
        let (tube_main, tube_child) = Tube::pair().unwrap();
        // SAFETY: trivially safe
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            // child process
            let uffd = create_uffd_for_test();
            // TODO(b/315998194): Add safety comment
            #[allow(clippy::undocumented_unsafe_blocks)]
            tube_child
                .send(&unsafe { SafeDescriptor::from_raw_descriptor(uffd.as_raw_descriptor()) })
                .unwrap();
            tube_child.recv::<u8>().unwrap();
            std::process::exit(0);
        }
        let uffd_descriptor = tube_main
            .recv::<SafeDescriptor>()
            .unwrap()
            .into_raw_descriptor();
        // TODO(b/315998194): Add safety comment
        #[allow(clippy::undocumented_unsafe_blocks)]
        let uffd_child = unsafe { Userfaultfd::from_raw_descriptor(uffd_descriptor) };
        let uffds = [uffd, uffd_child];

        // TODO(b/315998194): Add safety comment
        #[allow(clippy::undocumented_unsafe_blocks)]
        unsafe { register_regions(&regions, &uffds) }.unwrap();
        tube_main.send(&0_u8).unwrap();
        // wait until the child process die and the uffd_child become obsolete.
        wait_for_pid(pid, 0).unwrap();
        let result = unregister_regions(&regions, &uffds);

        // no error from ENOMEM
        assert_eq!(result.is_ok(), true);
    }

    fn create_guest_memory() -> GuestMemory {
        // guest memory with 2 regions. The address and size are from a real device.
        GuestMemory::new_with_options(&[
            (
                GuestAddress(0x0000000000000000),
                3489660928,
                MemoryRegionOptions::new(),
            ),
            (
                GuestAddress(0x0000000100000000),
                3537895424,
                MemoryRegionOptions::new(),
            ),
        ])
        .unwrap()
    }

    fn wait_for_state(controller: &SwapController, state: SwapState) -> bool {
        for _ in 0..20 {
            if controller.status().unwrap().state == state {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        false
    }

    pub fn controller_enable() {
        let dir = tempfile::tempdir().unwrap();
        let guest_memory = create_guest_memory();

        let controller = SwapController::launch(guest_memory.clone(), dir.path(), &None).unwrap();

        guest_memory
            .write_all_at_addr(&[1u8; 4096], GuestAddress(0x0000000000000000))
            .unwrap();
        guest_memory
            .write_all_at_addr(&[2u8; 4096], GuestAddress(0x0000000000000000 + 4096))
            .unwrap();
        guest_memory
            .write_all_at_addr(&[3u8; 4096], GuestAddress(0x0000000000000000 + 10 * 4096))
            .unwrap();
        guest_memory
            .write_all_at_addr(
                &[4u8; 3 * 1024 * 1024],
                GuestAddress(0x0000000000000000 + 20 * 4096),
            )
            .unwrap();
        guest_memory
            .write_all_at_addr(&[5u8; 4096], GuestAddress(0x0000000100000000))
            .unwrap();
        guest_memory
            .write_all_at_addr(&[6u8; 4096], GuestAddress(0x0000000100000000 + 4096))
            .unwrap();
        guest_memory
            .write_all_at_addr(&[7u8; 4096], GuestAddress(0x0000000100000000 + 10 * 4096))
            .unwrap();
        guest_memory
            .write_all_at_addr(
                &[8u8; 3 * 1024 * 1024],
                GuestAddress(0x0000000100000000 + 20 * 4096),
            )
            .unwrap();

        controller.enable().unwrap();

        let status = controller.status().unwrap();
        assert_eq!(status.state, SwapState::Pending);
        assert_eq!(status.state_transition.pages, 1542);

        let mut buf = [0u8; 4096];
        let mut long_buf = [0u8; 3 * 1024 * 1024];

        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000000000000))
            .unwrap();
        assert_eq!(buf, [1u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000000000000 + 4096))
            .unwrap();
        assert_eq!(buf, [2u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000000000000 + 2 * 4096))
            .unwrap();
        assert_eq!(buf, [0u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000000000000 + 10 * 4096))
            .unwrap();
        assert_eq!(buf, [3u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut long_buf, GuestAddress(0x0000000000000000 + 20 * 4096))
            .unwrap();
        assert_eq!(long_buf, [4u8; 3 * 1024 * 1024]);

        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000100000000))
            .unwrap();
        assert_eq!(buf, [5u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000100000000 + 4096))
            .unwrap();
        assert_eq!(buf, [6u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000100000000 + 2 * 4096))
            .unwrap();
        assert_eq!(buf, [0u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000100000000 + 10 * 4096))
            .unwrap();
        assert_eq!(buf, [7u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut long_buf, GuestAddress(0x0000000100000000 + 20 * 4096))
            .unwrap();
        assert_eq!(long_buf, [8u8; 3 * 1024 * 1024]);

        controller.enable().unwrap();
        assert_eq!(controller.status().unwrap().state_transition.pages, 1544);

        guest_memory
            .write_all_at_addr(&[9u8; 4096], GuestAddress(0x0000000000000000 + 4096))
            .unwrap();
        guest_memory
            .write_all_at_addr(&[10u8; 4096], GuestAddress(0x0000000000000000 + 2 * 4096))
            .unwrap();

        controller.enable().unwrap();
        assert_eq!(controller.status().unwrap().state_transition.pages, 2);

        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000000000000))
            .unwrap();
        assert_eq!(buf, [1u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000000000000 + 4096))
            .unwrap();
        assert_eq!(buf, [9u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000000000000 + 2 * 4096))
            .unwrap();
        assert_eq!(buf, [10u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000000000000 + 10 * 4096))
            .unwrap();
        assert_eq!(buf, [3u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut long_buf, GuestAddress(0x0000000000000000 + 20 * 4096))
            .unwrap();
        assert_eq!(long_buf, [4u8; 3 * 1024 * 1024]);

        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000100000000))
            .unwrap();
        assert_eq!(buf, [5u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000100000000 + 4096))
            .unwrap();
        assert_eq!(buf, [6u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000100000000 + 2 * 4096))
            .unwrap();
        assert_eq!(buf, [0u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000100000000 + 10 * 4096))
            .unwrap();
        assert_eq!(buf, [7u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut long_buf, GuestAddress(0x0000000100000000 + 20 * 4096))
            .unwrap();
        assert_eq!(long_buf, [8u8; 3 * 1024 * 1024]);

        controller.enable().unwrap();
        drop(controller);

        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000000000000))
            .unwrap();
        assert_eq!(buf, [1u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000000000000 + 4096))
            .unwrap();
        assert_eq!(buf, [9u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000000000000 + 2 * 4096))
            .unwrap();
        assert_eq!(buf, [10u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000000000000 + 10 * 4096))
            .unwrap();
        assert_eq!(buf, [3u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut long_buf, GuestAddress(0x0000000000000000 + 20 * 4096))
            .unwrap();
        assert_eq!(long_buf, [4u8; 3 * 1024 * 1024]);

        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000100000000))
            .unwrap();
        assert_eq!(buf, [5u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000100000000 + 4096))
            .unwrap();
        assert_eq!(buf, [6u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000100000000 + 2 * 4096))
            .unwrap();
        assert_eq!(buf, [0u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000100000000 + 10 * 4096))
            .unwrap();
        assert_eq!(buf, [7u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut long_buf, GuestAddress(0x0000000100000000 + 20 * 4096))
            .unwrap();
        assert_eq!(long_buf, [8u8; 3 * 1024 * 1024]);
    }

    pub fn controller_swap_out() {
        let dir = tempfile::tempdir().unwrap();
        let guest_memory = create_guest_memory();

        let controller = SwapController::launch(guest_memory.clone(), dir.path(), &None).unwrap();

        guest_memory
            .write_all_at_addr(&[1u8; 4096], GuestAddress(0x0000000000000000))
            .unwrap();
        guest_memory
            .write_all_at_addr(&[2u8; 4096], GuestAddress(0x0000000000000000 + 4096))
            .unwrap();
        guest_memory
            .write_all_at_addr(&[3u8; 4096], GuestAddress(0x0000000000000000 + 10 * 4096))
            .unwrap();
        guest_memory
            .write_all_at_addr(
                &[4u8; 3 * 1024 * 1024],
                GuestAddress(0x0000000000000000 + 20 * 4096),
            )
            .unwrap();
        guest_memory
            .write_all_at_addr(&[5u8; 4096], GuestAddress(0x0000000100000000))
            .unwrap();
        guest_memory
            .write_all_at_addr(&[6u8; 4096], GuestAddress(0x0000000100000000 + 4096))
            .unwrap();
        guest_memory
            .write_all_at_addr(&[7u8; 4096], GuestAddress(0x0000000100000000 + 10 * 4096))
            .unwrap();
        guest_memory
            .write_all_at_addr(
                &[8u8; 3 * 1024 * 1024],
                GuestAddress(0x0000000100000000 + 20 * 4096),
            )
            .unwrap();

        controller.enable().unwrap();
        controller.swap_out().unwrap();
        assert!(wait_for_state(&controller, SwapState::Active));
        assert_eq!(controller.status().unwrap().state_transition.pages, 1542);

        let mut buf = [0u8; 4096];
        let mut long_buf = [0u8; 3 * 1024 * 1024];

        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000000000000))
            .unwrap();
        assert_eq!(buf, [1u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000000000000 + 4096))
            .unwrap();
        assert_eq!(buf, [2u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000000000000 + 2 * 4096))
            .unwrap();
        assert_eq!(buf, [0u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000000000000 + 10 * 4096))
            .unwrap();
        assert_eq!(buf, [3u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut long_buf, GuestAddress(0x0000000000000000 + 20 * 4096))
            .unwrap();
        assert_eq!(long_buf, [4u8; 3 * 1024 * 1024]);

        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000100000000))
            .unwrap();
        assert_eq!(buf, [5u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000100000000 + 4096))
            .unwrap();
        assert_eq!(buf, [6u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000100000000 + 2 * 4096))
            .unwrap();
        assert_eq!(buf, [0u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000100000000 + 10 * 4096))
            .unwrap();
        assert_eq!(buf, [7u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut long_buf, GuestAddress(0x0000000100000000 + 20 * 4096))
            .unwrap();
        assert_eq!(long_buf, [8u8; 3 * 1024 * 1024]);

        controller.enable().unwrap();
        controller.swap_out().unwrap();
        assert!(wait_for_state(&controller, SwapState::Active));
        assert_eq!(controller.status().unwrap().state_transition.pages, 1544);

        guest_memory
            .write_all_at_addr(&[9u8; 4096], GuestAddress(0x0000000000000000 + 4096))
            .unwrap();
        guest_memory
            .write_all_at_addr(&[10u8; 4096], GuestAddress(0x0000000000000000 + 2 * 4096))
            .unwrap();

        controller.enable().unwrap();
        controller.swap_out().unwrap();
        assert!(wait_for_state(&controller, SwapState::Active));
        assert_eq!(controller.status().unwrap().state_transition.pages, 2);

        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000000000000))
            .unwrap();
        assert_eq!(buf, [1u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000000000000 + 4096))
            .unwrap();
        assert_eq!(buf, [9u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000000000000 + 2 * 4096))
            .unwrap();
        assert_eq!(buf, [10u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000000000000 + 10 * 4096))
            .unwrap();
        assert_eq!(buf, [3u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut long_buf, GuestAddress(0x0000000000000000 + 20 * 4096))
            .unwrap();
        assert_eq!(long_buf, [4u8; 3 * 1024 * 1024]);

        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000100000000))
            .unwrap();
        assert_eq!(buf, [5u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000100000000 + 4096))
            .unwrap();
        assert_eq!(buf, [6u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000100000000 + 2 * 4096))
            .unwrap();
        assert_eq!(buf, [0u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000100000000 + 10 * 4096))
            .unwrap();
        assert_eq!(buf, [7u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut long_buf, GuestAddress(0x0000000100000000 + 20 * 4096))
            .unwrap();
        assert_eq!(long_buf, [8u8; 3 * 1024 * 1024]);

        controller.enable().unwrap();
        controller.swap_out().unwrap();
        assert!(wait_for_state(&controller, SwapState::Active));
        drop(controller);

        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000000000000))
            .unwrap();
        assert_eq!(buf, [1u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000000000000 + 4096))
            .unwrap();
        assert_eq!(buf, [9u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000000000000 + 2 * 4096))
            .unwrap();
        assert_eq!(buf, [10u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000000000000 + 10 * 4096))
            .unwrap();
        assert_eq!(buf, [3u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut long_buf, GuestAddress(0x0000000000000000 + 20 * 4096))
            .unwrap();
        assert_eq!(long_buf, [4u8; 3 * 1024 * 1024]);

        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000100000000))
            .unwrap();
        assert_eq!(buf, [5u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000100000000 + 4096))
            .unwrap();
        assert_eq!(buf, [6u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000100000000 + 2 * 4096))
            .unwrap();
        assert_eq!(buf, [0u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000100000000 + 10 * 4096))
            .unwrap();
        assert_eq!(buf, [7u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut long_buf, GuestAddress(0x0000000100000000 + 20 * 4096))
            .unwrap();
        assert_eq!(long_buf, [8u8; 3 * 1024 * 1024]);
    }

    pub fn controller_trim() {
        let dir = tempfile::tempdir().unwrap();
        let guest_memory = create_guest_memory();

        let controller = SwapController::launch(guest_memory.clone(), dir.path(), &None).unwrap();

        guest_memory
            .write_all_at_addr(&[1u8; 4096], GuestAddress(0x0000000000000000))
            .unwrap();
        guest_memory
            .write_all_at_addr(&[2u8; 4096], GuestAddress(0x0000000000000000 + 4096))
            .unwrap();
        guest_memory
            .write_all_at_addr(&[0u8; 4096], GuestAddress(0x0000000000000000 + 2 * 4096))
            .unwrap();
        guest_memory
            .write_all_at_addr(&[3u8; 4096], GuestAddress(0x0000000000000000 + 10 * 4096))
            .unwrap();
        guest_memory
            .write_all_at_addr(
                &[4u8; 3 * 1024 * 1024],
                GuestAddress(0x0000000000000000 + 20 * 4096),
            )
            .unwrap();
        guest_memory
            .write_all_at_addr(&[5u8; 4096], GuestAddress(0x0000000100000000))
            .unwrap();
        guest_memory
            .write_all_at_addr(&[6u8; 4096], GuestAddress(0x0000000100000000 + 4096))
            .unwrap();
        guest_memory
            .write_all_at_addr(&[0u8; 4096], GuestAddress(0x0000000100000000 + 2 * 4096))
            .unwrap();
        guest_memory
            .write_all_at_addr(&[7u8; 4096], GuestAddress(0x0000000100000000 + 10 * 4096))
            .unwrap();
        guest_memory
            .write_all_at_addr(
                &[8u8; 3 * 1024 * 1024],
                GuestAddress(0x0000000100000000 + 20 * 4096),
            )
            .unwrap();

        controller.enable().unwrap();
        controller.trim().unwrap();
        assert!(wait_for_state(&controller, SwapState::Pending));
        assert_eq!(controller.status().unwrap().state_transition.pages, 2);
        controller.swap_out().unwrap();
        assert!(wait_for_state(&controller, SwapState::Active));
        assert_eq!(controller.status().unwrap().state_transition.pages, 1542);

        let mut buf = [0u8; 4096];
        let mut long_buf = [0u8; 3 * 1024 * 1024];

        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000000000000))
            .unwrap();
        assert_eq!(buf, [1u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000000000000 + 4096))
            .unwrap();
        assert_eq!(buf, [2u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000000000000 + 2 * 4096))
            .unwrap();
        assert_eq!(buf, [0u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000000000000 + 3 * 4096))
            .unwrap();
        assert_eq!(buf, [0u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000000000000 + 10 * 4096))
            .unwrap();
        assert_eq!(buf, [3u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut long_buf, GuestAddress(0x0000000000000000 + 20 * 4096))
            .unwrap();
        assert_eq!(long_buf, [4u8; 3 * 1024 * 1024]);

        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000100000000))
            .unwrap();
        assert_eq!(buf, [5u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000100000000 + 4096))
            .unwrap();
        assert_eq!(buf, [6u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000100000000 + 2 * 4096))
            .unwrap();
        assert_eq!(buf, [0u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000100000000 + 3 * 4096))
            .unwrap();
        assert_eq!(buf, [0u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000100000000 + 10 * 4096))
            .unwrap();
        assert_eq!(buf, [7u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut long_buf, GuestAddress(0x0000000100000000 + 20 * 4096))
            .unwrap();
        assert_eq!(long_buf, [8u8; 3 * 1024 * 1024]);

        guest_memory
            .write_all_at_addr(&[9u8; 4096], GuestAddress(0x0000000000000000 + 4096))
            .unwrap();
        guest_memory
            .write_all_at_addr(&[10u8; 4096], GuestAddress(0x0000000000000000 + 3 * 4096))
            .unwrap();

        controller.enable().unwrap();
        controller.trim().unwrap();
        assert!(wait_for_state(&controller, SwapState::Pending));
        assert_eq!(controller.status().unwrap().state_transition.pages, 1544);
        controller.swap_out().unwrap();
        assert!(wait_for_state(&controller, SwapState::Active));
        assert_eq!(controller.status().unwrap().state_transition.pages, 2);
        drop(controller);

        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000000000000))
            .unwrap();
        assert_eq!(buf, [1u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000000000000 + 4096))
            .unwrap();
        assert_eq!(buf, [9u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000000000000 + 2 * 4096))
            .unwrap();
        assert_eq!(buf, [0u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000000000000 + 3 * 4096))
            .unwrap();
        assert_eq!(buf, [10u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000000000000 + 10 * 4096))
            .unwrap();
        assert_eq!(buf, [3u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut long_buf, GuestAddress(0x0000000000000000 + 20 * 4096))
            .unwrap();
        assert_eq!(long_buf, [4u8; 3 * 1024 * 1024]);

        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000100000000))
            .unwrap();
        assert_eq!(buf, [5u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000100000000 + 4096))
            .unwrap();
        assert_eq!(buf, [6u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000100000000 + 2 * 4096))
            .unwrap();
        assert_eq!(buf, [0u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000100000000 + 10 * 4096))
            .unwrap();
        assert_eq!(buf, [7u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut long_buf, GuestAddress(0x0000000100000000 + 20 * 4096))
            .unwrap();
        assert_eq!(long_buf, [8u8; 3 * 1024 * 1024]);
    }

    pub fn controller_disable() {
        let dir = tempfile::tempdir().unwrap();
        let guest_memory = create_guest_memory();

        let controller = SwapController::launch(guest_memory.clone(), dir.path(), &None).unwrap();

        guest_memory
            .write_all_at_addr(&[1u8; 4096], GuestAddress(0x0000000000000000))
            .unwrap();
        guest_memory
            .write_all_at_addr(&[2u8; 4096], GuestAddress(0x0000000000000000 + 4096))
            .unwrap();
        guest_memory
            .write_all_at_addr(&[0u8; 4096], GuestAddress(0x0000000000000000 + 2 * 4096))
            .unwrap();
        guest_memory
            .write_all_at_addr(&[3u8; 4096], GuestAddress(0x0000000000000000 + 10 * 4096))
            .unwrap();
        guest_memory
            .write_all_at_addr(
                &[4u8; 3 * 1024 * 1024],
                GuestAddress(0x0000000000000000 + 20 * 4096),
            )
            .unwrap();
        guest_memory
            .write_all_at_addr(&[5u8; 4096], GuestAddress(0x0000000100000000))
            .unwrap();
        guest_memory
            .write_all_at_addr(&[6u8; 4096], GuestAddress(0x0000000100000000 + 4096))
            .unwrap();
        guest_memory
            .write_all_at_addr(&[0u8; 4096], GuestAddress(0x0000000100000000 + 2 * 4096))
            .unwrap();
        guest_memory
            .write_all_at_addr(&[7u8; 4096], GuestAddress(0x0000000100000000 + 10 * 4096))
            .unwrap();
        guest_memory
            .write_all_at_addr(
                &[8u8; 3 * 1024 * 1024],
                GuestAddress(0x0000000100000000 + 20 * 4096),
            )
            .unwrap();

        controller.enable().unwrap();
        controller.disable(false).unwrap();
        assert!(wait_for_state(&controller, SwapState::Ready));
        assert_eq!(controller.status().unwrap().state_transition.pages, 1544);

        let mut buf = [0u8; 4096];
        let mut long_buf = [0u8; 3 * 1024 * 1024];

        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000000000000))
            .unwrap();
        assert_eq!(buf, [1u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000000000000 + 4096))
            .unwrap();
        assert_eq!(buf, [2u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000000000000 + 2 * 4096))
            .unwrap();
        assert_eq!(buf, [0u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000000000000 + 3 * 4096))
            .unwrap();
        assert_eq!(buf, [0u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000000000000 + 10 * 4096))
            .unwrap();
        assert_eq!(buf, [3u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut long_buf, GuestAddress(0x0000000000000000 + 20 * 4096))
            .unwrap();
        assert_eq!(long_buf, [4u8; 3 * 1024 * 1024]);

        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000100000000))
            .unwrap();
        assert_eq!(buf, [5u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000100000000 + 4096))
            .unwrap();
        assert_eq!(buf, [6u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000100000000 + 2 * 4096))
            .unwrap();
        assert_eq!(buf, [0u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000100000000 + 3 * 4096))
            .unwrap();
        assert_eq!(buf, [0u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000100000000 + 10 * 4096))
            .unwrap();
        assert_eq!(buf, [7u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut long_buf, GuestAddress(0x0000000100000000 + 20 * 4096))
            .unwrap();
        assert_eq!(long_buf, [8u8; 3 * 1024 * 1024]);

        controller.enable().unwrap();
        controller.trim().unwrap();
        assert!(wait_for_state(&controller, SwapState::Pending));
        controller.swap_out().unwrap();
        assert!(wait_for_state(&controller, SwapState::Active));
        controller.disable(false).unwrap();
        assert!(wait_for_state(&controller, SwapState::Ready));
        assert_eq!(controller.status().unwrap().state_transition.pages, 1542);

        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000000000000))
            .unwrap();
        assert_eq!(buf, [1u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000000000000 + 4096))
            .unwrap();
        assert_eq!(buf, [2u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000000000000 + 2 * 4096))
            .unwrap();
        assert_eq!(buf, [0u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000000000000 + 3 * 4096))
            .unwrap();
        assert_eq!(buf, [0u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000000000000 + 10 * 4096))
            .unwrap();
        assert_eq!(buf, [3u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut long_buf, GuestAddress(0x0000000000000000 + 20 * 4096))
            .unwrap();
        assert_eq!(long_buf, [4u8; 3 * 1024 * 1024]);

        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000100000000))
            .unwrap();
        assert_eq!(buf, [5u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000100000000 + 4096))
            .unwrap();
        assert_eq!(buf, [6u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000100000000 + 2 * 4096))
            .unwrap();
        assert_eq!(buf, [0u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000100000000 + 3 * 4096))
            .unwrap();
        assert_eq!(buf, [0u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut buf, GuestAddress(0x0000000100000000 + 10 * 4096))
            .unwrap();
        assert_eq!(buf, [7u8; 4096]);
        guest_memory
            .read_exact_at_addr(&mut long_buf, GuestAddress(0x0000000100000000 + 20 * 4096))
            .unwrap();
        assert_eq!(long_buf, [8u8; 3 * 1024 * 1024]);
    }
}

fn main() {
    let args = libtest_mimic::Arguments {
        // Force single-threaded execution to allow safe use of libc::fork in these tests.
        test_threads: Some(1),
        ..libtest_mimic::Arguments::from_args()
    };

    let tests = vec![
        #[cfg(all(unix, feature = "enable"))]
        libtest_mimic::Trial::test("register_region_skip_obsolete_process", move || {
            base::test_utils::call_test_with_sudo("register_region_skip_obsolete_process_impl");
            Ok(())
        }),
        #[cfg(all(unix, feature = "enable"))]
        libtest_mimic::Trial::test("unregister_region_skip_obsolete_process", move || {
            base::test_utils::call_test_with_sudo("unregister_region_skip_obsolete_process_impl");
            Ok(())
        }),
        #[cfg(all(unix, feature = "enable"))]
        libtest_mimic::Trial::test("register_region_skip_obsolete_process_impl", move || {
            test::register_region_skip_obsolete_process();
            Ok(())
        })
        .with_ignored_flag(true),
        #[cfg(all(unix, feature = "enable"))]
        libtest_mimic::Trial::test("unregister_region_skip_obsolete_process_impl", move || {
            test::unregister_region_skip_obsolete_process();
            Ok(())
        })
        .with_ignored_flag(true),
        #[cfg(all(unix, feature = "enable"))]
        libtest_mimic::Trial::test("controller_enable", move || {
            base::test_utils::call_test_with_sudo("controller_enable_impl");
            Ok(())
        }),
        #[cfg(all(unix, feature = "enable"))]
        libtest_mimic::Trial::test("controller_enable_impl", move || {
            test::controller_enable();
            Ok(())
        })
        .with_ignored_flag(true),
        #[cfg(all(unix, feature = "enable"))]
        libtest_mimic::Trial::test("controller_swap_out", move || {
            base::test_utils::call_test_with_sudo("controller_swap_out_impl");
            Ok(())
        }),
        #[cfg(all(unix, feature = "enable"))]
        libtest_mimic::Trial::test("controller_swap_out_impl", move || {
            test::controller_swap_out();
            Ok(())
        })
        .with_ignored_flag(true),
        #[cfg(all(unix, feature = "enable"))]
        libtest_mimic::Trial::test("controller_trim", move || {
            base::test_utils::call_test_with_sudo("controller_trim_impl");
            Ok(())
        }),
        #[cfg(all(unix, feature = "enable"))]
        libtest_mimic::Trial::test("controller_trim_impl", move || {
            test::controller_trim();
            Ok(())
        })
        .with_ignored_flag(true),
        #[cfg(all(unix, feature = "enable"))]
        libtest_mimic::Trial::test("controller_disable", move || {
            base::test_utils::call_test_with_sudo("controller_disable_impl");
            Ok(())
        }),
        #[cfg(all(unix, feature = "enable"))]
        libtest_mimic::Trial::test("controller_disable_impl", move || {
            test::controller_disable();
            Ok(())
        })
        .with_ignored_flag(true),
    ];
    libtest_mimic::run(&args, tests).exit();
}
