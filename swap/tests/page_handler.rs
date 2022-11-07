// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Integration tests for [PageHandler]. these are more than unit tests since [PageHandler] rely on
//! the userfaultfd(2) kernel feature.

mod common;

use std::array;
use std::thread;
use std::time;

use base::pagesize;
use common::*;
use data_model::VolatileMemory;
use swap::page_handler::Error;
use swap::page_handler::PageHandler;
use swap::register_regions;
use swap::unregister_regions;

#[test]
fn create_success() {
    let dir_path = tempfile::tempdir().unwrap();
    let shm = create_shared_memory("shm", 6 * pagesize());
    let base_addr = shm.base_addr();

    let result = PageHandler::create(
        dir_path.path(),
        &[
            base_addr..(base_addr + 3 * pagesize()),
            (base_addr + 3 * pagesize())..(base_addr + 6 * pagesize()),
        ],
    );

    assert_eq!(result.is_ok(), true);
}

#[test]
fn create_partially_overlap() {
    let dir_path = tempfile::tempdir().unwrap();
    let shm = create_shared_memory("shm", 3 * pagesize());
    let base_addr = shm.base_addr();

    for range in [
        // the same address range
        base_addr..(base_addr + 3 * pagesize()),
        // left of the existing region overlaps
        (base_addr - pagesize())..(base_addr + pagesize()),
        // new region is inside
        (base_addr + pagesize())..(base_addr + 2 * pagesize()),
        // right of the existing region overlaps
        (base_addr + 2 * pagesize())..(base_addr + 4 * pagesize()),
        // new region covers whole the existing region
        (base_addr - pagesize())..(base_addr + 4 * pagesize()),
    ] {
        let result = PageHandler::create(
            dir_path.path(),
            &[base_addr..(base_addr + 3 * pagesize()), range],
        );
        assert_eq!(result.is_err(), true);
        match result {
            Err(Error::RegionOverlap(_, _)) => {}
            _ => {
                unreachable!("not overlap")
            }
        }
    }
}

fn wait_thread_with_timeout<T>(join_handle: thread::JoinHandle<T>, timeout_millis: u64) -> T {
    for _ in 0..timeout_millis {
        if join_handle.is_finished() {
            return join_handle.join().unwrap();
        }
        thread::sleep(time::Duration::from_millis(1));
    }
    panic!("thread join timeout");
}

#[test]
fn handle_page_fault_success() {
    let dir_path = tempfile::tempdir().unwrap();
    let uffd = create_uffd_for_test();
    let shm = create_shared_memory("shm", 3 * pagesize());
    let base_addr = shm.base_addr();
    let regions = [base_addr..(base_addr + 3 * pagesize())];
    let mut page_handler = PageHandler::create(dir_path.path(), &regions).unwrap();
    unsafe { register_regions(&regions, array::from_ref(&uffd)) }.unwrap();

    page_handler.handle_page_fault(&uffd, base_addr).unwrap();
    page_handler
        .handle_page_fault(&uffd, base_addr + pagesize() + 1)
        .unwrap();
    page_handler
        .handle_page_fault(&uffd, base_addr + 3 * pagesize() - 1)
        .unwrap();

    // read values on another thread to avoid blocking forever
    let join_handle = thread::spawn(move || {
        let mut result = Vec::new();
        for i in 0..(3 * pagesize()) {
            let ptr = shm.mmap.get_ref::<u8>(i).unwrap().as_mut_ptr();
            unsafe {
                result.push(*ptr);
            }
        }
        result
    });

    let result = wait_thread_with_timeout(join_handle, 100);

    assert_eq!(result, vec![0; 3 * pagesize()]);
}

#[test]
fn handle_page_fault_invalid_address() {
    let dir_path = tempfile::tempdir().unwrap();
    let uffd = create_uffd_for_test();
    let shm = create_shared_memory("shm", 3 * pagesize());
    let base_addr = shm.base_addr();
    let regions = [base_addr..(base_addr + 3 * pagesize())];
    let mut page_handler = PageHandler::create(dir_path.path(), &regions).unwrap();
    unsafe { register_regions(&regions, array::from_ref(&uffd)) }.unwrap();

    assert_eq!(
        page_handler
            .handle_page_fault(&uffd, base_addr - 1)
            .is_err(),
        true
    );
    assert_eq!(
        page_handler
            .handle_page_fault(&uffd, base_addr + 3 * pagesize())
            .is_err(),
        true
    );
}

#[test]
fn handle_page_fault_duplicated_page_fault() {
    let dir_path = tempfile::tempdir().unwrap();
    let uffd = create_uffd_for_test();
    let shm = create_shared_memory("shm", 3 * pagesize());
    let base_addr = shm.base_addr();
    let regions = [base_addr..(base_addr + 3 * pagesize())];
    let mut page_handler = PageHandler::create(dir_path.path(), &regions).unwrap();
    unsafe { register_regions(&regions, array::from_ref(&uffd)) }.unwrap();

    assert_eq!(
        page_handler.handle_page_fault(&uffd, base_addr).is_ok(),
        true
    );
    assert_eq!(
        page_handler.handle_page_fault(&uffd, base_addr + 1).is_ok(),
        true
    );
}

#[test]
fn handle_page_remove_success() {
    let dir_path = tempfile::tempdir().unwrap();
    let uffd = create_uffd_for_test();
    let shm = create_shared_memory("shm", 3 * pagesize());
    let base_addr = shm.base_addr();
    let regions = [base_addr..(base_addr + 3 * pagesize())];
    let mut page_handler = PageHandler::create(dir_path.path(), &regions).unwrap();
    unsafe { register_regions(&regions, array::from_ref(&uffd)) }.unwrap();

    // fill the first page with zero
    page_handler.handle_page_fault(&uffd, base_addr).unwrap();
    // write value on another thread to avoid blocking forever
    let join_handle = thread::spawn(move || {
        let ptr = base_addr as *mut u8;
        unsafe {
            *ptr = 1;
        }
    });
    wait_thread_with_timeout(join_handle, 100);
    let second_page_addr = base_addr + pagesize();
    page_handler
        .handle_page_remove(base_addr, second_page_addr)
        .unwrap();
    unsafe {
        libc::madvise(
            base_addr as *mut libc::c_void,
            pagesize(),
            libc::MADV_REMOVE,
        );
    }
    // fill the first page with zero again
    page_handler.handle_page_fault(&uffd, base_addr).unwrap();
    // read value on another thread to avoid blocking forever
    let join_handle = thread::spawn(move || {
        let ptr = base_addr as *mut u8;
        unsafe { *ptr }
    });

    assert_eq!(wait_thread_with_timeout(join_handle, 100), 0);
}

#[test]
fn handle_page_remove_invalid_address() {
    let dir_path = tempfile::tempdir().unwrap();
    let uffd = create_uffd_for_test();
    let shm = create_shared_memory("shm", 3 * pagesize());
    let base_addr = shm.base_addr();
    let regions = [base_addr..(base_addr + 3 * pagesize())];
    let mut page_handler = PageHandler::create(dir_path.path(), &regions).unwrap();
    unsafe { register_regions(&regions, array::from_ref(&uffd)) }.unwrap();

    page_handler.handle_page_fault(&uffd, base_addr).unwrap();
    page_handler
        .handle_page_fault(&uffd, base_addr + pagesize())
        .unwrap();
    page_handler
        .handle_page_fault(&uffd, base_addr + 2 * pagesize())
        .unwrap();
    assert_eq!(
        page_handler
            .handle_page_remove(base_addr - 1, base_addr + 3 * pagesize())
            .is_err(),
        true
    );
    assert_eq!(
        page_handler
            .handle_page_remove(base_addr, base_addr + 3 * pagesize() + 1)
            .is_err(),
        true
    );
    // remove for whole region should succeed.
    assert_eq!(
        page_handler
            .handle_page_remove(base_addr, base_addr + 3 * pagesize())
            .is_ok(),
        true
    );
}

#[test]
fn swap_out_success() {
    let uffd = create_uffd_for_test();
    let dir_path = tempfile::tempdir().unwrap();
    let shm1 = create_shared_memory("shm1", 3 * pagesize());
    let base_addr1 = shm1.base_addr();
    let shm2 = create_shared_memory("shm2", 3 * pagesize());
    let base_addr2 = shm2.base_addr();
    let regions = [
        base_addr1..(base_addr1 + 3 * pagesize()),
        base_addr2..(base_addr2 + 3 * pagesize()),
    ];
    let mut page_handler = PageHandler::create(dir_path.path(), &regions).unwrap();
    unsafe { register_regions(&regions, array::from_ref(&uffd)) }.unwrap();

    page_handler.handle_page_fault(&uffd, base_addr1).unwrap();
    page_handler
        .handle_page_fault(&uffd, (base_addr1) + 2 * pagesize())
        .unwrap();
    page_handler.handle_page_fault(&uffd, base_addr2).unwrap();
    page_handler
        .handle_page_fault(&uffd, (base_addr2) + 2 * pagesize())
        .unwrap();
    // write values on another thread to avoid blocking forever
    let base_addr1_usize = base_addr1;
    let base_addr2_usize = base_addr2;
    let join_handle = thread::spawn(move || {
        for i in 0..pagesize() {
            let ptr = (base_addr1_usize + i) as *mut u8;
            unsafe {
                *ptr = 1;
            }
        }
        for i in 0..pagesize() {
            let ptr = (base_addr1_usize + 2 * pagesize() + i) as *mut u8;
            unsafe {
                *ptr = 2;
            }
        }
        for i in 0..pagesize() {
            let ptr = (base_addr2_usize + i) as *mut u8;
            unsafe {
                *ptr = 3;
            }
        }
        for i in 0..pagesize() {
            let ptr = (base_addr2_usize + 2 * pagesize() + i) as *mut u8;
            unsafe {
                *ptr = 4;
            }
        }
    });
    wait_thread_with_timeout(join_handle, 100);
    unsafe {
        page_handler.swap_out(base_addr1, &shm1.shm, 0).unwrap();
        page_handler.swap_out(base_addr2, &shm2.shm, 0).unwrap();
    }

    // page faults on all pages. page 0 and page 2 will be swapped in from the file. page 1 will
    // be filled with zero.
    for i in 0..3 {
        page_handler
            .handle_page_fault(&uffd, (base_addr1) + i * pagesize())
            .unwrap();
        page_handler
            .handle_page_fault(&uffd, (base_addr2) + i * pagesize())
            .unwrap();
    }
    // read values on another thread to avoid blocking forever
    let join_handle = thread::spawn(move || {
        let mut result = Vec::new();
        for i in 0..3 {
            for j in 0..pagesize() {
                let ptr = (base_addr1_usize + i * pagesize() + j) as *mut u8;
                unsafe {
                    result.push(*ptr);
                }
            }
        }
        for i in 0..3 {
            for j in 0..pagesize() {
                let ptr = (base_addr2_usize + i * pagesize() + j) as *mut u8;
                unsafe {
                    result.push(*ptr);
                }
            }
        }
        result
    });
    let result = wait_thread_with_timeout(join_handle, 100);
    let values: Vec<u8> = vec![1, 0, 2, 3, 0, 4];
    for (i, v) in values.iter().enumerate() {
        for j in 0..pagesize() {
            assert_eq!(&result[i * pagesize() + j], v);
        }
    }
}

#[test]
fn swap_out_twice() {
    let uffd = create_uffd_for_test();
    let dir_path = tempfile::tempdir().unwrap();
    let shm1 = create_shared_memory("shm1", 3 * pagesize());
    let base_addr1 = shm1.base_addr();
    let shm2 = create_shared_memory("shm2", 3 * pagesize());
    let base_addr2 = shm2.base_addr();
    let regions = [
        base_addr1..(base_addr1 + 3 * pagesize()),
        base_addr2..(base_addr2 + 3 * pagesize()),
    ];
    let mut page_handler = PageHandler::create(dir_path.path(), &regions).unwrap();
    unsafe { register_regions(&regions, array::from_ref(&uffd)) }.unwrap();

    page_handler.handle_page_fault(&uffd, base_addr1).unwrap();
    page_handler
        .handle_page_fault(&uffd, (base_addr1) + 2 * pagesize())
        .unwrap();
    page_handler.handle_page_fault(&uffd, base_addr2).unwrap();
    page_handler
        .handle_page_fault(&uffd, (base_addr2) + 2 * pagesize())
        .unwrap();
    // write values on another thread to avoid blocking forever
    let base_addr1_usize = base_addr1;
    let base_addr2_usize = base_addr2;
    let join_handle = thread::spawn(move || {
        for i in 0..pagesize() {
            let ptr = (base_addr1_usize + i) as *mut u8;
            unsafe {
                *ptr = 1;
            }
        }
        for i in 0..pagesize() {
            let ptr = (base_addr1_usize + 2 * pagesize() + i) as *mut u8;
            unsafe {
                *ptr = 2;
            }
        }
        for i in 0..pagesize() {
            let ptr = (base_addr2_usize + i) as *mut u8;
            unsafe {
                *ptr = 3;
            }
        }
        for i in 0..pagesize() {
            let ptr = (base_addr2_usize + 2 * pagesize() + i) as *mut u8;
            unsafe {
                *ptr = 4;
            }
        }
    });
    wait_thread_with_timeout(join_handle, 100);
    unsafe {
        page_handler.swap_out(base_addr1, &shm1.shm, 0).unwrap();
        page_handler.swap_out(base_addr2, &shm2.shm, 0).unwrap();
    }
    // page faults on all pages in mmap1.
    for i in 0..3 {
        page_handler
            .handle_page_fault(&uffd, (base_addr1) + i * pagesize())
            .unwrap();
    }
    let join_handle = thread::spawn(move || {
        for i in 0..pagesize() {
            let ptr = (base_addr1_usize + pagesize() + i) as *mut u8;
            unsafe {
                *ptr = 5;
            }
        }
        for i in 0..pagesize() {
            let ptr = (base_addr1_usize + 2 * pagesize() + i) as *mut u8;
            unsafe {
                *ptr = 6;
            }
        }
    });
    wait_thread_with_timeout(join_handle, 100);
    unsafe {
        page_handler.swap_out(base_addr1, &shm1.shm, 0).unwrap();
        page_handler.swap_out(base_addr2, &shm2.shm, 0).unwrap();
    }

    // page faults on all pages.
    for i in 0..3 {
        page_handler
            .handle_page_fault(&uffd, (base_addr1) + i * pagesize())
            .unwrap();
        page_handler
            .handle_page_fault(&uffd, (base_addr2) + i * pagesize())
            .unwrap();
    }
    // read values on another thread to avoid blocking forever
    let join_handle = thread::spawn(move || {
        let mut result = Vec::new();
        for i in 0..3 {
            for j in 0..pagesize() {
                let ptr = (base_addr1_usize + i * pagesize() + j) as *mut u8;
                unsafe {
                    result.push(*ptr);
                }
            }
        }
        for i in 0..3 {
            for j in 0..pagesize() {
                let ptr = (base_addr2_usize + i * pagesize() + j) as *mut u8;
                unsafe {
                    result.push(*ptr);
                }
            }
        }
        result
    });
    let result = wait_thread_with_timeout(join_handle, 100);
    let values: Vec<u8> = vec![1, 5, 6, 3, 0, 4];
    for (i, v) in values.iter().enumerate() {
        for j in 0..pagesize() {
            assert_eq!(&result[i * pagesize() + j], v);
        }
    }
}

#[test]
fn swap_out_invalid_base_addr() {
    let uffd = create_uffd_for_test();
    let dir_path = tempfile::tempdir().unwrap();
    let shm = create_shared_memory("shm1", 3 * pagesize());
    let base_addr = shm.base_addr();
    let regions = [base_addr..(base_addr + 3 * pagesize())];
    let mut page_handler = PageHandler::create(dir_path.path(), &regions).unwrap();
    unsafe { register_regions(&regions, array::from_ref(&uffd)) }.unwrap();

    // the base_addr is within the region
    assert_eq!(
        unsafe { page_handler.swap_out(base_addr + pagesize(), &shm.shm, 0) }.is_err(),
        true
    );
    // the base_addr is outside of the region
    assert_eq!(
        unsafe { page_handler.swap_out(base_addr - pagesize(), &shm.shm, 0) }.is_err(),
        true
    );
}

#[test]
fn swap_in_success() {
    let uffd = create_uffd_for_test();
    let dir_path = tempfile::tempdir().unwrap();
    let shm1 = create_shared_memory("shm1", 3 * pagesize());
    let base_addr1 = shm1.base_addr();
    let shm2 = create_shared_memory("shm2", 3 * pagesize());
    let base_addr2 = shm2.base_addr();
    let shm3 = create_shared_memory("shm3", 3 * pagesize());
    let base_addr3 = shm3.base_addr();
    for i in 0..3 {
        let ptr = (base_addr1 + i * pagesize()) as *mut u8;
        unsafe {
            *ptr = i as u8 + 10;
        }
        let ptr = (base_addr2 + i * pagesize()) as *mut u8;
        unsafe {
            *ptr = i as u8 + 13;
        }
    }
    let regions = [
        base_addr1..(base_addr1 + 3 * pagesize()),
        base_addr2..(base_addr2 + 3 * pagesize()),
        base_addr3..(base_addr3 + 3 * pagesize()),
    ];
    let mut page_handler = PageHandler::create(dir_path.path(), &regions).unwrap();
    unsafe { register_regions(&regions, array::from_ref(&uffd)) }.unwrap();

    unsafe {
        page_handler.swap_out(base_addr1, &shm1.shm, 0).unwrap();
        page_handler.swap_out(base_addr2, &shm2.shm, 0).unwrap();
        page_handler.swap_out(base_addr3, &shm3.shm, 0).unwrap();
    }
    page_handler
        .handle_page_fault(&uffd, base_addr2 + pagesize())
        .unwrap();
    let ptr = (base_addr2 + pagesize()) as *mut u8;
    unsafe {
        *ptr = 20;
    }

    assert_eq!(page_handler.swap_in(&uffd).is_ok(), true);
    unregister_regions(&regions, array::from_ref(&uffd)).unwrap();
    // read values on another thread to avoid blocking forever
    let join_handle = thread::spawn(move || {
        let mut result = Vec::new();
        for i in 0..3 {
            let ptr = (base_addr1 + i * pagesize()) as *mut u8;
            unsafe {
                result.push(*ptr);
            }
        }
        for i in 0..3 {
            let ptr = (base_addr2 + i * pagesize()) as *mut u8;
            unsafe {
                result.push(*ptr);
            }
        }
        for i in 0..3 {
            let ptr = (base_addr3 + i * pagesize()) as *mut u8;
            unsafe {
                result.push(*ptr);
            }
        }
        result
    });
    let result = wait_thread_with_timeout(join_handle, 100);
    assert_eq!(result[0], 10);
    assert_eq!(result[1], 11);
    assert_eq!(result[2], 12);
    assert_eq!(result[3], 13);
    assert_eq!(result[4], 20);
    assert_eq!(result[5], 15);
    assert_eq!(result[6], 0);
    assert_eq!(result[7], 0);
    assert_eq!(result[8], 0);
}
