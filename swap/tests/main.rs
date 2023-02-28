// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Integration tests for vmm-swap feature

#[cfg(unix)]
mod common;

#[cfg(unix)]
mod test {
    use super::common::*;
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

    pub fn register_region_skip_obsolete_process() {
        let shm = create_shared_memory("test", 3 * pagesize());
        let uffd = create_uffd_for_test();
        let base_addr = shm.base_addr();
        let regions = [base_addr..(base_addr + 3 * pagesize())];
        let (tube_main, tube_child) = Tube::pair().unwrap();
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            // child process
            let uffd = create_uffd_for_test();
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
        let uffd_child = unsafe { Userfaultfd::from_raw_descriptor(uffd_descriptor) };

        let result = unsafe { register_regions(&regions, &[uffd, uffd_child]) };

        // no error from ENOMEM
        assert_eq!(result.is_ok(), true);
    }

    pub fn unregister_region_skip_obsolete_process() {
        let shm = create_shared_memory("test", 3 * pagesize());
        let uffd = create_uffd_for_test();
        let base_addr = shm.base_addr();
        let regions = [base_addr..(base_addr + 3 * pagesize())];
        let (tube_main, tube_child) = Tube::pair().unwrap();
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            // child process
            let uffd = create_uffd_for_test();
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
        let uffd_child = unsafe { Userfaultfd::from_raw_descriptor(uffd_descriptor) };
        let uffds = [uffd, uffd_child];

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
        #[cfg(unix)]
        libtest_mimic::Trial::test("register_region_skip_obsolete_process", move || {
            test::register_region_skip_obsolete_process();
            Ok(())
        }),
        #[cfg(unix)]
        libtest_mimic::Trial::test("unregister_region_skip_obsolete_process", move || {
            test::unregister_region_skip_obsolete_process();
            Ok(())
        }),
    ];
    libtest_mimic::run(&args, tests).exit();
}
