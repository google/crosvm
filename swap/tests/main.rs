// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Integration tests for vmm-swap feature

#[cfg(all(unix, feature = "enable"))]
mod common;

#[cfg(all(unix, feature = "enable"))]
mod test {
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
    ];
    libtest_mimic::run(&args, tests).exit();
}
