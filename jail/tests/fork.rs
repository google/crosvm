// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(any(target_os = "android", target_os = "linux"))]
mod test {
    use std::thread;
    use std::time::Duration;

    use base::getpid;
    use base::AsRawDescriptor;
    use base::Tube;
    use jail::fork::fork_process;
    use minijail::Minijail;

    pub fn pid_diff() {
        let (tube, fork_tube) = Tube::pair().expect("failed to create tube");
        let jail = Minijail::new().unwrap();
        let keep_rds = vec![fork_tube.as_raw_descriptor()];

        let pid = getpid();
        let child = fork_process(jail, keep_rds, None, || {
            // checks that this is a genuine fork with a new PID
            if pid != getpid() {
                fork_tube.send(&1).unwrap()
            } else {
                fork_tube.send(&2).unwrap()
            }
        })
        .expect("failed to fork");

        assert_eq!(tube.recv::<u32>().unwrap(), 1);
        child.wait().unwrap();
    }

    pub fn thread_name() {
        let (tube, fork_tube) = Tube::pair().expect("failed to create tube");
        let jail = Minijail::new().unwrap();
        let keep_rds = vec![fork_tube.as_raw_descriptor()];
        let thread_name = String::from("thread_name");

        let child = fork_process(jail, keep_rds, Some(thread_name.clone()), || {
            fork_tube.send::<u32>(&1).unwrap();
            thread::sleep(Duration::from_secs(10));
        })
        .expect("failed to fork");

        // wait the forked process running.
        tube.recv::<u32>().unwrap();
        let thread_comm =
            std::fs::read_to_string(format!("/proc/{0}/task/{0}/comm", child.pid)).unwrap();

        assert_eq!(thread_comm, thread_name + "\n");

        // SAFETY: child pid is expected to be valid and we wait on the child
        unsafe { libc::kill(child.pid, libc::SIGKILL) };
        child.wait().unwrap();
    }

    pub fn thread_name_trimmed() {
        let (tube, fork_tube) = Tube::pair().expect("failed to create tube");
        let jail = Minijail::new().unwrap();
        let keep_rds = vec![fork_tube.as_raw_descriptor()];
        let thread_name = String::from("12345678901234567890");

        let child = fork_process(jail, keep_rds, Some(thread_name), || {
            fork_tube.send::<u32>(&1).unwrap();
            thread::sleep(Duration::from_secs(10));
        })
        .expect("failed to fork");

        // wait the forked process running.
        tube.recv::<u32>().unwrap();
        let thread_comm =
            std::fs::read_to_string(format!("/proc/{0}/task/{0}/comm", child.pid)).unwrap();

        assert_eq!(thread_comm, "123456789012345\n");

        // SAFETY: child pid is expected to be valid and we wait on the child
        unsafe { libc::kill(child.pid, libc::SIGKILL) };
        child.wait().unwrap();
    }

    pub fn wait_for_success() {
        let jail = Minijail::new().unwrap();
        let child = fork_process(jail, vec![], None, || {
            // exit successfully
        })
        .expect("failed to fork");

        assert_eq!(child.wait().unwrap(), 0);
    }

    pub fn wait_for_panic() {
        let jail = Minijail::new().unwrap();
        let child = fork_process(jail, vec![], None, || {
            panic!("fails");
        })
        .expect("failed to fork");

        assert_eq!(child.wait().unwrap(), 101);
    }
}

fn main() {
    let args = libtest_mimic::Arguments {
        // Force single-threaded execution to allow safe use of libc::fork in these tests.
        test_threads: Some(1),
        ..libtest_mimic::Arguments::from_args()
    };

    let tests = vec![
        #[cfg(any(target_os = "android", target_os = "linux"))]
        libtest_mimic::Trial::test("pid_diff", move || {
            test::pid_diff();
            Ok(())
        }),
        #[cfg(any(target_os = "android", target_os = "linux"))]
        libtest_mimic::Trial::test("thread_name", move || {
            test::thread_name();
            Ok(())
        }),
        #[cfg(any(target_os = "android", target_os = "linux"))]
        libtest_mimic::Trial::test("thread_name_trimmed", move || {
            test::thread_name_trimmed();
            Ok(())
        }),
        #[cfg(any(target_os = "android", target_os = "linux"))]
        libtest_mimic::Trial::test("wait_for_success", move || {
            test::wait_for_success();
            Ok(())
        }),
        #[cfg(any(target_os = "android", target_os = "linux"))]
        libtest_mimic::Trial::test("wait_for_panic", move || {
            test::wait_for_panic();
            Ok(())
        }),
    ];
    libtest_mimic::run(&args, tests).exit();
}
