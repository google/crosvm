// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(any(target_os = "android", target_os = "linux"))]

use std::collections::BTreeSet;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::IoSlice;
use std::io::IoSliceMut;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::mem;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::RawFd;
use std::path::Path;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::sync::Barrier;
use std::thread;
use std::time::Duration;

use base::pipe;
use base::EventType;
use base::WaitContext;
use data_model::IoBufMut;
use io_uring::Error;
use io_uring::URingAllowlist;
use io_uring::URingContext;
use io_uring::UserData;
use libc::EACCES;
use sync::Condvar;
use sync::Mutex;
use tempfile::tempfile;
use tempfile::TempDir;

fn append_file_name(path: &Path, name: &str) -> PathBuf {
    let mut joined = path.to_path_buf();
    joined.push(name);
    joined
}

unsafe fn add_one_read(
    uring: &URingContext,
    ptr: *mut u8,
    len: usize,
    fd: RawFd,
    offset: Option<u64>,
    user_data: UserData,
) -> Result<(), Error> {
    uring.add_readv(
        Pin::from(vec![IoBufMut::from_raw_parts(ptr, len)].into_boxed_slice()),
        fd,
        offset,
        user_data,
    )
}

unsafe fn add_one_write(
    uring: &URingContext,
    ptr: *const u8,
    len: usize,
    fd: RawFd,
    offset: Option<u64>,
    user_data: UserData,
) -> Result<(), Error> {
    uring.add_writev(
        Pin::from(vec![IoBufMut::from_raw_parts(ptr as *mut u8, len)].into_boxed_slice()),
        fd,
        offset,
        user_data,
    )
}

fn create_test_file(size: u64) -> std::fs::File {
    let f = tempfile().unwrap();
    f.set_len(size).unwrap();
    f
}

#[test]
// Queue as many reads as possible and then collect the completions.
fn read_parallel() {
    const QUEUE_SIZE: usize = 10;
    const BUF_SIZE: usize = 0x1000;

    let uring = URingContext::new(QUEUE_SIZE, None).unwrap();
    let mut buf = [0u8; BUF_SIZE * QUEUE_SIZE];
    let f = create_test_file((BUF_SIZE * QUEUE_SIZE) as u64);

    // check that the whole file can be read and that the queues wrapping is handled by reading
    // double the quue depth of buffers.
    for i in 0..QUEUE_SIZE * 64 {
        let index = i as u64;
        unsafe {
            let offset = (i % QUEUE_SIZE) * BUF_SIZE;
            match add_one_read(
                &uring,
                buf[offset..].as_mut_ptr(),
                BUF_SIZE,
                f.as_raw_fd(),
                Some(offset as u64),
                index,
            ) {
                Ok(_) => (),
                Err(Error::NoSpace) => {
                    let _ = uring.wait().unwrap().next().unwrap();
                }
                Err(_) => panic!("unexpected error from uring wait"),
            }
        }
    }
}

#[test]
fn read_readv() {
    let queue_size = 128;

    let uring = URingContext::new(queue_size, None).unwrap();
    let mut buf = [0u8; 0x1000];
    let f = create_test_file(0x1000 * 2);

    // check that the whole file can be read and that the queues wrapping is handled by reading
    // double the quue depth of buffers.
    for i in 0..queue_size * 2 {
        let index = i as u64;
        let io_vecs = unsafe {
            //safe to transmut from IoSlice to iovec.
            vec![IoSliceMut::new(&mut buf)]
                .into_iter()
                .map(|slice| std::mem::transmute::<IoSliceMut, libc::iovec>(slice))
        };
        let (user_data_ret, res) = unsafe {
            // Safe because the `wait` call waits until the kernel is done with `buf`.
            uring
                .add_readv_iter(io_vecs, f.as_raw_fd(), Some((index % 2) * 0x1000), index)
                .unwrap();
            uring.wait().unwrap().next().unwrap()
        };
        assert_eq!(user_data_ret, index);
        assert_eq!(res.unwrap(), buf.len() as u32);
    }
}

#[test]
fn readv_vec() {
    let queue_size = 128;
    const BUF_SIZE: usize = 0x2000;

    let uring = URingContext::new(queue_size, None).unwrap();
    let mut buf = [0u8; BUF_SIZE];
    let mut buf2 = [0u8; BUF_SIZE];
    let mut buf3 = [0u8; BUF_SIZE];
    let io_vecs = unsafe {
        //safe to transmut from IoSlice to iovec.
        vec![
            IoSliceMut::new(&mut buf),
            IoSliceMut::new(&mut buf2),
            IoSliceMut::new(&mut buf3),
        ]
        .into_iter()
        .map(|slice| std::mem::transmute::<IoSliceMut, libc::iovec>(slice))
        .collect::<Vec<libc::iovec>>()
    };
    let total_len = io_vecs.iter().fold(0, |a, iovec| a + iovec.iov_len);
    let f = create_test_file(total_len as u64 * 2);
    let (user_data_ret, res) = unsafe {
        // Safe because the `wait` call waits until the kernel is done with `buf`.
        uring
            .add_readv_iter(io_vecs.into_iter(), f.as_raw_fd(), Some(0), 55)
            .unwrap();
        uring.wait().unwrap().next().unwrap()
    };
    assert_eq!(user_data_ret, 55);
    assert_eq!(res.unwrap(), total_len as u32);
}

#[test]
fn write_one_block() {
    let uring = URingContext::new(16, None).unwrap();
    let mut buf = [0u8; 4096];
    let mut f = create_test_file(0);
    f.write_all(&buf).unwrap();
    f.write_all(&buf).unwrap();

    unsafe {
        // Safe because the `wait` call waits until the kernel is done mutating `buf`.
        add_one_write(
            &uring,
            buf.as_mut_ptr(),
            buf.len(),
            f.as_raw_fd(),
            Some(0),
            55,
        )
        .unwrap();
        let (user_data, res) = uring.wait().unwrap().next().unwrap();
        assert_eq!(user_data, 55_u64);
        assert_eq!(res.unwrap(), buf.len() as u32);
    }
}

#[test]
fn write_one_submit_poll() {
    let uring = URingContext::new(16, None).unwrap();
    let mut buf = [0u8; 4096];
    let mut f = create_test_file(0);
    f.write_all(&buf).unwrap();
    f.write_all(&buf).unwrap();

    let ctx: WaitContext<u64> = WaitContext::build_with(&[(&uring, 1)]).unwrap();
    {
        // Test that the uring context isn't readable before any events are complete.
        let events = ctx.wait_timeout(Duration::from_millis(1)).unwrap();
        assert!(events.iter().next().is_none());
    }

    unsafe {
        // Safe because the `wait` call waits until the kernel is done mutating `buf`.
        add_one_write(
            &uring,
            buf.as_mut_ptr(),
            buf.len(),
            f.as_raw_fd(),
            Some(0),
            55,
        )
        .unwrap();
        uring.submit().unwrap();
        // Poll for completion with epoll.
        let events = ctx.wait().unwrap();
        let event = events.iter().next().unwrap();
        assert!(event.is_readable);
        assert_eq!(event.token, 1);
        let (user_data, res) = uring.wait().unwrap().next().unwrap();
        assert_eq!(user_data, 55_u64);
        assert_eq!(res.unwrap(), buf.len() as u32);
    }
}

#[test]
fn writev_vec() {
    let queue_size = 128;
    const BUF_SIZE: usize = 0x2000;
    const OFFSET: u64 = 0x2000;

    let uring = URingContext::new(queue_size, None).unwrap();
    let buf = [0xaau8; BUF_SIZE];
    let buf2 = [0xffu8; BUF_SIZE];
    let buf3 = [0x55u8; BUF_SIZE];
    let io_vecs = unsafe {
        //safe to transmut from IoSlice to iovec.
        vec![IoSlice::new(&buf), IoSlice::new(&buf2), IoSlice::new(&buf3)]
            .into_iter()
            .map(|slice| std::mem::transmute::<IoSlice, libc::iovec>(slice))
            .collect::<Vec<libc::iovec>>()
    };
    let total_len = io_vecs.iter().fold(0, |a, iovec| a + iovec.iov_len);
    let mut f = create_test_file(total_len as u64 * 2);
    let (user_data_ret, res) = unsafe {
        // Safe because the `wait` call waits until the kernel is done with `buf`.
        uring
            .add_writev_iter(io_vecs.into_iter(), f.as_raw_fd(), Some(OFFSET), 55)
            .unwrap();
        uring.wait().unwrap().next().unwrap()
    };
    assert_eq!(user_data_ret, 55);
    assert_eq!(res.unwrap(), total_len as u32);

    let mut read_back = [0u8; BUF_SIZE];
    f.seek(SeekFrom::Start(OFFSET)).unwrap();
    f.read_exact(&mut read_back).unwrap();
    assert!(!read_back.iter().any(|&b| b != 0xaa));
    f.read_exact(&mut read_back).unwrap();
    assert!(!read_back.iter().any(|&b| b != 0xff));
    f.read_exact(&mut read_back).unwrap();
    assert!(!read_back.iter().any(|&b| b != 0x55));
}

#[test]
fn fallocate_fsync() {
    let tempdir = TempDir::new().unwrap();
    let file_path = append_file_name(tempdir.path(), "test");

    {
        let buf = [0u8; 4096];
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&file_path)
            .unwrap();
        f.write_all(&buf).unwrap();
    }

    let init_size = std::fs::metadata(&file_path).unwrap().len() as usize;
    let set_size = init_size + 1024 * 1024 * 50;
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&file_path)
        .unwrap();

    let uring = URingContext::new(16, None).unwrap();
    uring
        .add_fallocate(f.as_raw_fd(), 0, set_size as u64, 0, 66)
        .unwrap();
    let (user_data, res) = uring.wait().unwrap().next().unwrap();
    assert_eq!(user_data, 66_u64);
    match res {
        Err(e) => {
            if e.kind() == std::io::ErrorKind::InvalidInput {
                // skip on kernels that don't support fallocate.
                return;
            }
            panic!("Unexpected fallocate error: {}", e);
        }
        Ok(val) => assert_eq!(val, 0_u32),
    }

    // Add a few writes and then fsync
    let buf = [0u8; 4096];
    let mut pending = std::collections::BTreeSet::new();
    unsafe {
        add_one_write(&uring, buf.as_ptr(), buf.len(), f.as_raw_fd(), Some(0), 67).unwrap();
        pending.insert(67u64);
        add_one_write(
            &uring,
            buf.as_ptr(),
            buf.len(),
            f.as_raw_fd(),
            Some(4096),
            68,
        )
        .unwrap();
        pending.insert(68);
        add_one_write(
            &uring,
            buf.as_ptr(),
            buf.len(),
            f.as_raw_fd(),
            Some(8192),
            69,
        )
        .unwrap();
        pending.insert(69);
    }
    uring.add_fsync(f.as_raw_fd(), 70).unwrap();
    pending.insert(70);

    let mut wait_calls = 0;

    while !pending.is_empty() && wait_calls < 5 {
        let events = uring.wait().unwrap();
        for (user_data, res) in events {
            assert!(res.is_ok());
            assert!(pending.contains(&user_data));
            pending.remove(&user_data);
        }
        wait_calls += 1;
    }
    assert!(pending.is_empty());

    uring
        .add_fallocate(
            f.as_raw_fd(),
            init_size as u64,
            (set_size - init_size) as u64,
            (libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE) as u32,
            68,
        )
        .unwrap();
    let (user_data, res) = uring.wait().unwrap().next().unwrap();
    assert_eq!(user_data, 68_u64);
    assert_eq!(res.unwrap(), 0_u32);

    drop(f); // Close to ensure directory entires for metadata are updated.

    let new_size = std::fs::metadata(&file_path).unwrap().len() as usize;
    assert_eq!(new_size, set_size);
}

#[test]
fn dev_zero_readable() {
    let f = File::open(Path::new("/dev/zero")).unwrap();
    let uring = URingContext::new(16, None).unwrap();
    uring
        .add_poll_fd(f.as_raw_fd(), EventType::Read, 454)
        .unwrap();
    let (user_data, res) = uring.wait().unwrap().next().unwrap();
    assert_eq!(user_data, 454_u64);
    assert_eq!(res.unwrap(), 1_u32);
}

#[test]
fn queue_many_ebusy_retry() {
    let num_entries = 16;
    let f = File::open(Path::new("/dev/zero")).unwrap();
    let uring = URingContext::new(num_entries, None).unwrap();
    // Fill the sumbit ring.
    for sqe_batch in 0..3 {
        for i in 0..num_entries {
            uring
                .add_poll_fd(
                    f.as_raw_fd(),
                    EventType::Read,
                    (sqe_batch * num_entries + i) as u64,
                )
                .unwrap();
        }
        uring.submit().unwrap();
    }
    // Adding more than the number of cqes will cause the uring to return ebusy, make sure that
    // is handled cleanly and wait still returns the completed entries.
    uring
        .add_poll_fd(f.as_raw_fd(), EventType::Read, (num_entries * 3) as u64)
        .unwrap();
    // The first wait call should return the cques that are already filled.
    {
        let mut results = uring.wait().unwrap();
        for _i in 0..num_entries * 2 {
            assert_eq!(results.next().unwrap().1.unwrap(), 1_u32);
        }
        assert!(results.next().is_none());
    }
    // The second will finish submitting any more sqes and return the rest.
    let mut results = uring.wait().unwrap();
    for _i in 0..num_entries + 1 {
        assert_eq!(results.next().unwrap().1.unwrap(), 1_u32);
    }
    assert!(results.next().is_none());
}

#[test]
fn wake_with_nop() {
    const PIPE_READ: UserData = 0;
    const NOP: UserData = 1;
    const BUF_DATA: [u8; 16] = [0xf4; 16];

    let uring = URingContext::new(4, None).map(Arc::new).unwrap();
    let (pipe_out, mut pipe_in) = pipe(true).unwrap();
    let (tx, rx) = channel();

    let uring2 = uring.clone();
    let wait_thread = thread::spawn(move || {
        let mut buf = [0u8; BUF_DATA.len()];
        unsafe {
            add_one_read(
                &uring2,
                buf.as_mut_ptr(),
                buf.len(),
                pipe_out.as_raw_fd(),
                Some(0),
                0,
            )
            .unwrap();
        }

        // This is still a bit racy as the other thread may end up adding the NOP before we make
        // the syscall but I'm not aware of a mechanism that will notify the other thread
        // exactly when we make the syscall.
        tx.send(()).unwrap();
        let mut events = uring2.wait().unwrap();
        let (user_data, result) = events.next().unwrap();
        assert_eq!(user_data, NOP);
        assert_eq!(result.unwrap(), 0);

        tx.send(()).unwrap();
        let mut events = uring2.wait().unwrap();
        let (user_data, result) = events.next().unwrap();
        assert_eq!(user_data, PIPE_READ);
        assert_eq!(result.unwrap(), buf.len() as u32);
        assert_eq!(&buf, &BUF_DATA);
    });

    // Wait until the other thread is about to make the syscall.
    rx.recv_timeout(Duration::from_secs(10)).unwrap();

    // Now add a NOP operation. This should wake up the other thread even though it cannot yet
    // read from the pipe.
    uring.add_nop(NOP).unwrap();
    uring.submit().unwrap();

    // Wait for the other thread to process the NOP result.
    rx.recv_timeout(Duration::from_secs(10)).unwrap();

    // Now write to the pipe to finish the uring read.
    pipe_in.write_all(&BUF_DATA).unwrap();

    wait_thread.join().unwrap();
}

#[test]
fn complete_from_any_thread() {
    let num_entries = 16;
    let uring = URingContext::new(num_entries, None).map(Arc::new).unwrap();

    // Fill the sumbit ring.
    for sqe_batch in 0..3 {
        for i in 0..num_entries {
            uring.add_nop((sqe_batch * num_entries + i) as u64).unwrap();
        }
        uring.submit().unwrap();
    }

    // Spawn a bunch of threads that pull cqes out of the uring and make sure none of them see a
    // duplicate.
    const NUM_THREADS: usize = 7;
    let completed = Arc::new(Mutex::new(BTreeSet::new()));
    let cv = Arc::new(Condvar::new());
    let barrier = Arc::new(Barrier::new(NUM_THREADS));

    let mut threads = Vec::with_capacity(NUM_THREADS);
    for _ in 0..NUM_THREADS {
        let uring = uring.clone();
        let completed = completed.clone();
        let barrier = barrier.clone();
        let cv = cv.clone();
        threads.push(thread::spawn(move || {
            barrier.wait();

            'wait: while completed.lock().len() < num_entries * 3 {
                for (user_data, result) in uring.wait().unwrap() {
                    assert_eq!(result.unwrap(), 0);

                    let mut completed = completed.lock();
                    assert!(completed.insert(user_data));
                    if completed.len() >= num_entries * 3 {
                        break 'wait;
                    }
                }
            }

            cv.notify_one();
        }));
    }

    // Wait until all the operations have completed.
    let mut c = completed.lock();
    while c.len() < num_entries * 3 {
        c = cv.wait(c);
    }
    mem::drop(c);

    // Let the OS clean up the still-waiting threads after the test run.
}

#[test]
fn submit_from_any_thread() {
    const NUM_THREADS: usize = 7;
    const ITERATIONS: usize = 113;
    const NUM_ENTRIES: usize = 16;

    fn wait_for_completion_thread(in_flight: &Mutex<isize>, cv: &Condvar) {
        let mut in_flight = in_flight.lock();
        while *in_flight > NUM_ENTRIES as isize {
            in_flight = cv.wait(in_flight);
        }
    }

    let uring = URingContext::new(NUM_ENTRIES, None).map(Arc::new).unwrap();
    let in_flight = Arc::new(Mutex::new(0));
    let cv = Arc::new(Condvar::new());

    let mut threads = Vec::with_capacity(NUM_THREADS);
    for idx in 0..NUM_THREADS {
        let uring = uring.clone();
        let in_flight = in_flight.clone();
        let cv = cv.clone();
        threads.push(thread::spawn(move || {
            for iter in 0..ITERATIONS {
                loop {
                    match uring.add_nop(((idx * NUM_THREADS) + iter) as UserData) {
                        Ok(()) => *in_flight.lock() += 1,
                        Err(Error::NoSpace) => {
                            wait_for_completion_thread(&in_flight, &cv);
                            continue;
                        }
                        Err(e) => panic!("Failed to add nop: {}", e),
                    }

                    // We don't need to wait for the completion queue if the submit fails with
                    // EBUSY because we already added the operation to the submit queue. It will
                    // get added eventually.
                    match uring.submit() {
                        Ok(()) => break,
                        Err(Error::RingEnter(libc::EBUSY)) => break,
                        Err(e) => panic!("Failed to submit ops: {}", e),
                    }
                }
            }
        }));
    }

    let mut completed = 0;
    while completed < NUM_THREADS * ITERATIONS {
        for (_, res) in uring.wait().unwrap() {
            assert_eq!(res.unwrap(), 0);
            completed += 1;

            let mut in_flight = in_flight.lock();
            *in_flight -= 1;
            let notify_submitters = *in_flight <= NUM_ENTRIES as isize;
            mem::drop(in_flight);

            if notify_submitters {
                cv.notify_all();
            }

            if completed >= NUM_THREADS * ITERATIONS {
                break;
            }
        }
    }

    for t in threads {
        t.join().unwrap();
    }

    // Make sure we didn't submit more entries than expected.
    assert_eq!(*in_flight.lock(), 0);
    assert_eq!(uring.submit_ring.lock().added, 0);
    assert_eq!(uring.complete_ring.num_ready(), 0);
}

// TODO(b/183722981): Fix and re-enable test
#[test]
#[ignore]
fn multi_thread_submit_and_complete() {
    const NUM_SUBMITTERS: usize = 7;
    const NUM_COMPLETERS: usize = 3;
    const ITERATIONS: usize = 113;
    const NUM_ENTRIES: usize = 16;

    fn wait_for_completion_thread(in_flight: &Mutex<isize>, cv: &Condvar) {
        let mut in_flight = in_flight.lock();
        while *in_flight > NUM_ENTRIES as isize {
            in_flight = cv.wait(in_flight);
        }
    }

    let uring = URingContext::new(NUM_ENTRIES, None).map(Arc::new).unwrap();
    let in_flight = Arc::new(Mutex::new(0));
    let cv = Arc::new(Condvar::new());

    let mut threads = Vec::with_capacity(NUM_SUBMITTERS + NUM_COMPLETERS);
    for idx in 0..NUM_SUBMITTERS {
        let uring = uring.clone();
        let in_flight = in_flight.clone();
        let cv = cv.clone();
        threads.push(thread::spawn(move || {
            for iter in 0..ITERATIONS {
                loop {
                    match uring.add_nop(((idx * NUM_SUBMITTERS) + iter) as UserData) {
                        Ok(()) => *in_flight.lock() += 1,
                        Err(Error::NoSpace) => {
                            wait_for_completion_thread(&in_flight, &cv);
                            continue;
                        }
                        Err(e) => panic!("Failed to add nop: {}", e),
                    }

                    // We don't need to wait for the completion queue if the submit fails with
                    // EBUSY because we already added the operation to the submit queue. It will
                    // get added eventually.
                    match uring.submit() {
                        Ok(()) => break,
                        Err(Error::RingEnter(libc::EBUSY)) => break,
                        Err(e) => panic!("Failed to submit ops: {}", e),
                    }
                }
            }
        }));
    }

    let completed = Arc::new(AtomicUsize::new(0));
    for _ in 0..NUM_COMPLETERS {
        let uring = uring.clone();
        let in_flight = in_flight.clone();
        let cv = cv.clone();
        let completed = completed.clone();
        threads.push(thread::spawn(move || {
            while completed.load(Ordering::Relaxed) < NUM_SUBMITTERS * ITERATIONS {
                for (_, res) in uring.wait().unwrap() {
                    assert_eq!(res.unwrap(), 0);
                    completed.fetch_add(1, Ordering::Relaxed);

                    let mut in_flight = in_flight.lock();
                    *in_flight -= 1;
                    let notify_submitters = *in_flight <= NUM_ENTRIES as isize;
                    mem::drop(in_flight);

                    if notify_submitters {
                        cv.notify_all();
                    }

                    if completed.load(Ordering::Relaxed) >= NUM_SUBMITTERS * ITERATIONS {
                        break;
                    }
                }
            }
        }));
    }

    for t in threads.drain(..NUM_SUBMITTERS) {
        t.join().unwrap();
    }

    // Now that all submitters are finished, add NOPs to wake up any completers blocked on the
    // syscall.
    for i in 0..NUM_COMPLETERS {
        uring
            .add_nop((NUM_SUBMITTERS * ITERATIONS + i) as UserData)
            .unwrap();
    }
    uring.submit().unwrap();

    for t in threads {
        t.join().unwrap();
    }

    // Make sure we didn't submit more entries than expected. Only the last few NOPs added to
    // wake up the completer threads may still be in the completion ring.
    assert!(uring.complete_ring.num_ready() <= NUM_COMPLETERS as u32);
    assert_eq!(
        in_flight.lock().unsigned_abs() as u32 + uring.complete_ring.num_ready(),
        NUM_COMPLETERS as u32
    );
    assert_eq!(uring.submit_ring.lock().added, 0);
}

#[test]
fn restrict_ops() {
    const TEST_DATA: &[u8; 4] = b"foo!";

    let queue_size = 128;

    // Allow only Readv operation
    let mut restriction = URingAllowlist::new();
    restriction.allow_submit_operation(io_uring::URingOperation::Readv);

    let uring = URingContext::new(queue_size, Some(&restriction)).unwrap();

    let mut buf = [0u8; 4];
    let mut f = create_test_file(4);
    f.write_all(TEST_DATA).unwrap();

    // add_read, which submits Readv, should succeed

    unsafe {
        add_one_read(
            &uring,
            buf.as_mut_ptr(),
            buf.len(),
            f.as_raw_fd(),
            Some(0),
            0,
        )
        .unwrap();
    }
    let result = uring.wait().unwrap().next().unwrap();
    assert!(result.1.is_ok(), "uring read should succeed");
    assert_eq!(&buf, TEST_DATA, "file should be read to buf");
    drop(f);

    // add_write should be rejected.

    let mut buf: [u8; 4] = TEST_DATA.to_owned(); // fake data, which should not be written
    let mut f = create_test_file(4);

    unsafe {
        add_one_write(
            &uring,
            buf.as_mut_ptr(),
            buf.len(),
            f.as_raw_fd(),
            Some(0),
            0,
        )
        .unwrap();
    }
    let result = uring.wait().unwrap().next().unwrap();
    assert!(result.1.is_err(), "uring write should fail");
    assert_eq!(
        result.1.unwrap_err().raw_os_error(),
        Some(EACCES),
        "the error should be permission denied"
    );
    let mut result_f = vec![];
    f.seek(SeekFrom::Start(0)).unwrap(); // rewind to read from the beginning
    f.read_to_end(&mut result_f).unwrap();
    assert_eq!(
        result_f.as_slice(),
        &[0, 0, 0, 0],
        "file should not be written and should stay empty"
    );
}
