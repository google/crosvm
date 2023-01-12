// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Integration tests for [PageHandler]. these are more than unit tests since [PageHandler] rely on
//! the userfaultfd(2) kernel feature.

mod common;

use std::array;
use std::ops::Range;
use std::thread;
use std::time;

use base::pagesize;
use base::MappedRegion;
use base::MemoryMappingBuilder;
use base::SharedMemory;
use common::*;
use data_model::VolatileMemory;
use swap::page_handler::Error;
use swap::page_handler::PageHandler;
use swap::register_regions;
use swap::unregister_regions;

const HUGEPAGE_SIZE: usize = 2 * 1024 * 1024; // 2MB

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
fn handle_page_fault_zero_success() {
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
fn move_to_staging_data_written_before_enabling() {
    let uffd = create_uffd_for_test();
    let dir_path = tempfile::tempdir().unwrap();
    let shm = SharedMemory::new("shm", 6 * pagesize() as u64).unwrap();
    let mmap1 = MemoryMappingBuilder::new(3 * pagesize())
        .from_shared_memory(&shm)
        .build()
        .unwrap();
    let mmap2 = MemoryMappingBuilder::new(3 * pagesize())
        .from_shared_memory(&shm)
        .offset(3 * pagesize() as u64)
        .build()
        .unwrap();
    let base_addr1 = mmap1.as_ptr() as usize;
    let base_addr2 = mmap2.as_ptr() as usize;

    let regions = [
        base_addr1..(base_addr1 + 3 * pagesize()),
        base_addr2..(base_addr2 + 3 * pagesize()),
    ];
    let mut page_handler = PageHandler::create(dir_path.path(), &regions).unwrap();
    // write data before registering to userfaultfd
    unsafe {
        for i in base_addr1 + pagesize()..base_addr1 + 2 * pagesize() {
            *(i as *mut u8) = 1;
        }
        for i in base_addr2 + pagesize()..base_addr2 + 2 * pagesize() {
            *(i as *mut u8) = 2;
        }
        for i in base_addr2 + 2 * pagesize()..base_addr2 + 3 * pagesize() {
            *(i as *mut u8) = 3;
        }
    }
    unsafe { register_regions(&regions, array::from_ref(&uffd)) }.unwrap();

    unsafe {
        page_handler.move_to_staging(base_addr1, &shm, 0).unwrap();
        page_handler
            .move_to_staging(base_addr2, &shm, 3 * pagesize() as u64)
            .unwrap();
    }
    // page faults on all pages.
    for i in 0..3 {
        page_handler
            .handle_page_fault(&uffd, base_addr1 + i * pagesize())
            .unwrap();
        page_handler
            .handle_page_fault(&uffd, base_addr2 + i * pagesize())
            .unwrap();
    }

    // read values on another thread to avoid blocking forever
    let join_handle = thread::spawn(move || {
        let mut result = Vec::new();
        for i in 0..3 {
            for j in 0..pagesize() {
                let ptr = (base_addr1 + i * pagesize() + j) as *mut u8;
                unsafe {
                    result.push(*ptr);
                }
            }
        }
        for i in 0..3 {
            for j in 0..pagesize() {
                let ptr = (base_addr2 + i * pagesize() + j) as *mut u8;
                unsafe {
                    result.push(*ptr);
                }
            }
        }
        result
    });
    let result = wait_thread_with_timeout(join_handle, 100);
    let values: Vec<u8> = vec![0, 1, 0, 0, 2, 3];
    for (i, v) in values.iter().enumerate() {
        for j in 0..pagesize() {
            assert_eq!(&result[i * pagesize() + j], v);
        }
    }
}

fn page_idx_range(start_addr: usize, end_addr: usize) -> Range<usize> {
    (start_addr / pagesize())..(end_addr / pagesize())
}

fn page_idx_to_addr(page_idx: usize) -> usize {
    page_idx * pagesize()
}

#[test]
fn move_to_staging_hugepage_chunks() {
    let uffd = create_uffd_for_test();
    let dir_path = tempfile::tempdir().unwrap();
    let shm = SharedMemory::new("shm", 10 * HUGEPAGE_SIZE as u64).unwrap();
    let mmap1 = MemoryMappingBuilder::new(5 * HUGEPAGE_SIZE)
        .from_shared_memory(&shm)
        .build()
        .unwrap();
    let mmap2 = MemoryMappingBuilder::new(5 * HUGEPAGE_SIZE)
        .from_shared_memory(&shm)
        .offset(5 * HUGEPAGE_SIZE as u64)
        .build()
        .unwrap();
    let base_addr1 = mmap1.as_ptr() as usize;
    let base_addr2 = mmap2.as_ptr() as usize;

    let regions = [
        base_addr1..(base_addr1 + 5 * HUGEPAGE_SIZE),
        base_addr2..(base_addr2 + 5 * HUGEPAGE_SIZE),
    ];
    let mut page_handler = PageHandler::create(dir_path.path(), &regions).unwrap();
    // write data before registering to userfaultfd
    unsafe {
        for i in page_idx_range(base_addr1 + pagesize(), base_addr1 + 3 * pagesize()) {
            *(page_idx_to_addr(i) as *mut u8) = 1;
        }
        for i in page_idx_range(
            base_addr1 + HUGEPAGE_SIZE - pagesize(),
            base_addr1 + HUGEPAGE_SIZE + pagesize(),
        ) {
            *(page_idx_to_addr(i) as *mut u8) = 2;
        }
        for i in page_idx_range(
            base_addr1 + 2 * HUGEPAGE_SIZE + pagesize(),
            base_addr1 + 3 * HUGEPAGE_SIZE + pagesize(),
        ) {
            *(page_idx_to_addr(i) as *mut u8) = 3;
        }
        for i in page_idx_range(base_addr2 + HUGEPAGE_SIZE, base_addr2 + 2 * HUGEPAGE_SIZE) {
            *(page_idx_to_addr(i) as *mut u8) = 4;
        }
        for i in page_idx_range(
            base_addr2 + 2 * HUGEPAGE_SIZE + pagesize(),
            base_addr2 + 5 * HUGEPAGE_SIZE - pagesize(),
        ) {
            *(page_idx_to_addr(i) as *mut u8) = 5;
        }
    }
    unsafe { register_regions(&regions, array::from_ref(&uffd)) }.unwrap();

    unsafe {
        page_handler.move_to_staging(base_addr1, &shm, 0).unwrap();
        page_handler
            .move_to_staging(base_addr2, &shm, 5 * HUGEPAGE_SIZE as u64)
            .unwrap();
    }
    // page faults on all pages.
    for i in 0..5 * HUGEPAGE_SIZE / pagesize() {
        page_handler
            .handle_page_fault(&uffd, base_addr1 + i * pagesize())
            .unwrap();
        page_handler
            .handle_page_fault(&uffd, base_addr2 + i * pagesize())
            .unwrap();
    }

    // read values on another thread to avoid blocking forever
    let join_handle = thread::spawn(move || {
        let mut result = Vec::new();
        for i in page_idx_range(base_addr1, base_addr1 + 5 * HUGEPAGE_SIZE) {
            let ptr = (page_idx_to_addr(i)) as *mut u8;
            unsafe {
                result.push(*ptr);
            }
        }
        for i in page_idx_range(base_addr2, base_addr2 + 5 * HUGEPAGE_SIZE) {
            let ptr = (page_idx_to_addr(i)) as *mut u8;
            unsafe {
                result.push(*ptr);
            }
        }
        result
    });
    let result = wait_thread_with_timeout(join_handle, 100);
    assert_eq!(result[0], 0);
    assert_eq!(result[1], 1);
    assert_eq!(result[2], 1);
    for i in page_idx_range(3 * pagesize(), HUGEPAGE_SIZE - pagesize()) {
        assert_eq!(result[i], 0);
    }
    for i in page_idx_range(HUGEPAGE_SIZE - pagesize(), HUGEPAGE_SIZE + pagesize()) {
        assert_eq!(result[i], 2);
    }
    for i in page_idx_range(HUGEPAGE_SIZE + pagesize(), 2 * HUGEPAGE_SIZE + pagesize()) {
        assert_eq!(result[i], 0);
    }
    for i in page_idx_range(
        2 * HUGEPAGE_SIZE + pagesize(),
        3 * HUGEPAGE_SIZE + pagesize(),
    ) {
        assert_eq!(result[i], 3);
    }
    for i in page_idx_range(3 * HUGEPAGE_SIZE + pagesize(), 6 * HUGEPAGE_SIZE) {
        assert_eq!(result[i], 0);
    }
    for i in page_idx_range(6 * HUGEPAGE_SIZE, 7 * HUGEPAGE_SIZE) {
        assert_eq!(result[i], 4);
    }
    for i in page_idx_range(7 * HUGEPAGE_SIZE, 7 * HUGEPAGE_SIZE + pagesize()) {
        assert_eq!(result[i], 0);
    }
    for i in page_idx_range(
        7 * HUGEPAGE_SIZE + pagesize(),
        10 * HUGEPAGE_SIZE - pagesize(),
    ) {
        assert_eq!(result[i], 5);
    }
    for i in page_idx_range(10 * HUGEPAGE_SIZE - pagesize(), 10 * HUGEPAGE_SIZE) {
        assert_eq!(result[i], 0);
    }
}

#[test]
fn move_to_staging_invalid_base_addr() {
    let uffd = create_uffd_for_test();
    let dir_path = tempfile::tempdir().unwrap();
    let shm = create_shared_memory("shm1", 3 * pagesize());
    let base_addr = shm.base_addr();
    let regions = [base_addr..(base_addr + 3 * pagesize())];
    let mut page_handler = PageHandler::create(dir_path.path(), &regions).unwrap();
    unsafe { register_regions(&regions, array::from_ref(&uffd)) }.unwrap();

    // the base_addr is within the region
    assert_eq!(
        unsafe { page_handler.move_to_staging(base_addr + pagesize(), &shm.shm, 0,) }.is_err(),
        true
    );
    // the base_addr is outside of the region
    assert_eq!(
        unsafe { page_handler.move_to_staging(base_addr - pagesize(), &shm.shm, 0,) }.is_err(),
        true
    );
}

fn swap_out_all(page_handler: &mut PageHandler) {
    while page_handler.swap_out(1024 * 1024).unwrap() != 0 {}
}

#[test]
fn swap_out_success() {
    let uffd = create_uffd_for_test();
    let dir_path = tempfile::tempdir().unwrap();
    let shm = SharedMemory::new("shm", 6 * pagesize() as u64).unwrap();
    let mmap1 = MemoryMappingBuilder::new(3 * pagesize())
        .from_shared_memory(&shm)
        .build()
        .unwrap();
    let mmap2 = MemoryMappingBuilder::new(3 * pagesize())
        .from_shared_memory(&shm)
        .offset(3 * pagesize() as u64)
        .build()
        .unwrap();
    let base_addr1 = mmap1.as_ptr() as usize;
    let base_addr2 = mmap2.as_ptr() as usize;
    let regions = [
        base_addr1..(base_addr1 + 3 * pagesize()),
        base_addr2..(base_addr2 + 3 * pagesize()),
    ];
    let mut page_handler = PageHandler::create(dir_path.path(), &regions).unwrap();
    // write data before registering to userfaultfd
    unsafe {
        for i in base_addr1 + pagesize()..base_addr1 + 2 * pagesize() {
            *(i as *mut u8) = 1;
        }
        for i in base_addr2 + pagesize()..base_addr2 + 2 * pagesize() {
            *(i as *mut u8) = 2;
        }
    }
    unsafe { register_regions(&regions, array::from_ref(&uffd)) }.unwrap();

    unsafe {
        page_handler.move_to_staging(base_addr1, &shm, 0).unwrap();
        page_handler
            .move_to_staging(base_addr2, &shm, 3 * pagesize() as u64)
            .unwrap();
    }
    swap_out_all(&mut page_handler);
    // page faults on all pages. page 0 and page 2 will be swapped in from the file. page 1 will
    // be filled with zero.
    for i in 0..3 {
        page_handler
            .handle_page_fault(&uffd, base_addr1 + i * pagesize())
            .unwrap();
        page_handler
            .handle_page_fault(&uffd, base_addr2 + i * pagesize())
            .unwrap();
    }

    // read values on another thread to avoid blocking forever
    let join_handle = thread::spawn(move || {
        let mut result = Vec::new();
        for i in 0..3 {
            for j in 0..pagesize() {
                let ptr = (base_addr1 + i * pagesize() + j) as *mut u8;
                unsafe {
                    result.push(*ptr);
                }
            }
        }
        for i in 0..3 {
            for j in 0..pagesize() {
                let ptr = (base_addr2 + i * pagesize() + j) as *mut u8;
                unsafe {
                    result.push(*ptr);
                }
            }
        }
        result
    });
    let result = wait_thread_with_timeout(join_handle, 100);
    let values: Vec<u8> = vec![0, 1, 0, 0, 2, 0];
    for (i, v) in values.iter().enumerate() {
        for j in 0..pagesize() {
            assert_eq!(&result[i * pagesize() + j], v);
        }
    }
}

#[test]
fn swap_out_handled_page() {
    let uffd = create_uffd_for_test();
    let dir_path = tempfile::tempdir().unwrap();
    let shm = SharedMemory::new("shm", 6 * pagesize() as u64).unwrap();
    let mmap1 = MemoryMappingBuilder::new(3 * pagesize())
        .from_shared_memory(&shm)
        .build()
        .unwrap();
    let base_addr1 = mmap1.as_ptr() as usize;

    let regions = [base_addr1..(base_addr1 + 3 * pagesize())];
    let mut page_handler = PageHandler::create(dir_path.path(), &regions).unwrap();
    // write data before registering to userfaultfd
    unsafe {
        for i in base_addr1 + pagesize()..base_addr1 + 2 * pagesize() {
            *(i as *mut u8) = 1;
        }
    }
    unsafe { register_regions(&regions, array::from_ref(&uffd)) }.unwrap();

    unsafe {
        page_handler.move_to_staging(base_addr1, &shm, 0).unwrap();
    }
    // page in before swap_out()
    page_handler
        .handle_page_fault(&uffd, base_addr1 + pagesize())
        .unwrap();
    swap_out_all(&mut page_handler);

    // read values on another thread to avoid blocking forever
    let join_handle = thread::spawn(move || {
        let mut result = Vec::new();
        for i in 0..pagesize() {
            let ptr = (base_addr1 + pagesize() + i) as *mut u8;
            unsafe {
                result.push(*ptr);
            }
        }
        result
    });
    // reading the page is not blocked.s
    let result = wait_thread_with_timeout(join_handle, 100);
    for v in result {
        assert_eq!(v, 1);
    }
}

#[test]
fn swap_out_twice() {
    let uffd = create_uffd_for_test();
    let dir_path = tempfile::tempdir().unwrap();
    let shm = SharedMemory::new("shm", 6 * pagesize() as u64).unwrap();
    let mmap1 = MemoryMappingBuilder::new(3 * pagesize())
        .from_shared_memory(&shm)
        .build()
        .unwrap();
    let mmap2 = MemoryMappingBuilder::new(3 * pagesize())
        .from_shared_memory(&shm)
        .offset(3 * pagesize() as u64)
        .build()
        .unwrap();
    let base_addr1 = mmap1.as_ptr() as usize;
    let base_addr2 = mmap2.as_ptr() as usize;
    let regions = [
        base_addr1..(base_addr1 + 3 * pagesize()),
        base_addr2..(base_addr2 + 3 * pagesize()),
    ];
    let mut page_handler = PageHandler::create(dir_path.path(), &regions).unwrap();
    unsafe {
        for i in 0..pagesize() {
            *((base_addr1 + i) as *mut u8) = 1;
            *((base_addr1 + 2 * pagesize() + i) as *mut u8) = 2;
            *((base_addr2 + i) as *mut u8) = 3;
            *((base_addr2 + 2 * pagesize() + i) as *mut u8) = 4;
        }
    }
    unsafe { register_regions(&regions, array::from_ref(&uffd)) }.unwrap();

    unsafe {
        page_handler.move_to_staging(base_addr1, &shm, 0).unwrap();
        page_handler
            .move_to_staging(base_addr2, &shm, 3 * pagesize() as u64)
            .unwrap();
    }
    swap_out_all(&mut page_handler);
    // page faults on all pages in mmap1.
    for i in 0..3 {
        page_handler
            .handle_page_fault(&uffd, (base_addr1) + i * pagesize())
            .unwrap();
    }
    // write values on another thread to avoid blocking forever
    let join_handle = thread::spawn(move || {
        for i in 0..pagesize() {
            let ptr = (base_addr1 + pagesize() + i) as *mut u8;
            unsafe {
                *ptr = 5;
            }
        }
        for i in 0..pagesize() {
            let ptr = (base_addr1 + 2 * pagesize() + i) as *mut u8;
            unsafe {
                *ptr = 6;
            }
        }
    });
    wait_thread_with_timeout(join_handle, 100);
    unsafe {
        page_handler.move_to_staging(base_addr1, &shm, 0).unwrap();
        page_handler
            .move_to_staging(base_addr2, &shm, 3 * pagesize() as u64)
            .unwrap();
    }
    swap_out_all(&mut page_handler);

    // page faults on all pages.
    for i in 0..3 {
        page_handler
            .handle_page_fault(&uffd, base_addr1 + i * pagesize())
            .unwrap();
        page_handler
            .handle_page_fault(&uffd, base_addr2 + i * pagesize())
            .unwrap();
    }
    // read values on another thread to avoid blocking forever
    let join_handle = thread::spawn(move || {
        let mut result = Vec::new();
        for i in 0..3 {
            for j in 0..pagesize() {
                let ptr = (base_addr1 + i * pagesize() + j) as *mut u8;
                unsafe {
                    result.push(*ptr);
                }
            }
        }
        for i in 0..3 {
            for j in 0..pagesize() {
                let ptr = (base_addr2 + i * pagesize() + j) as *mut u8;
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
fn swap_in_success() {
    let uffd = create_uffd_for_test();
    let dir_path = tempfile::tempdir().unwrap();
    let shm = SharedMemory::new("shm", 6 * pagesize() as u64).unwrap();
    let mmap1 = MemoryMappingBuilder::new(3 * pagesize())
        .from_shared_memory(&shm)
        .build()
        .unwrap();
    let mmap2 = MemoryMappingBuilder::new(3 * pagesize())
        .from_shared_memory(&shm)
        .offset(3 * pagesize() as u64)
        .build()
        .unwrap();
    let base_addr1 = mmap1.as_ptr() as usize;
    let base_addr2 = mmap2.as_ptr() as usize;
    let regions = [
        base_addr1..(base_addr1 + 3 * pagesize()),
        base_addr2..(base_addr2 + 3 * pagesize()),
    ];
    let mut page_handler = PageHandler::create(dir_path.path(), &regions).unwrap();
    unsafe {
        for i in base_addr1 + pagesize()..base_addr1 + 2 * pagesize() {
            *(i as *mut u8) = 1;
        }
        for i in base_addr2 + pagesize()..base_addr2 + 2 * pagesize() {
            *(i as *mut u8) = 2;
        }
        for i in base_addr2 + 2 * pagesize()..base_addr2 + 3 * pagesize() {
            *(i as *mut u8) = 3;
        }
    }
    unsafe { register_regions(&regions, array::from_ref(&uffd)) }.unwrap();

    unsafe {
        page_handler.move_to_staging(base_addr1, &shm, 0).unwrap();
        page_handler
            .move_to_staging(base_addr2, &shm, 3 * pagesize() as u64)
            .unwrap();
    }
    swap_out_all(&mut page_handler);
    page_handler
        .handle_page_fault(&uffd, base_addr1 + pagesize())
        .unwrap();
    page_handler
        .handle_page_fault(&uffd, base_addr2 + pagesize())
        .unwrap();
    page_handler
        .handle_page_fault(&uffd, base_addr2 + 2 * pagesize())
        .unwrap();
    unsafe {
        for i in base_addr2 + pagesize()..base_addr2 + 2 * pagesize() {
            *(i as *mut u8) = 4;
        }
    }
    // move to staging memory.
    unsafe {
        page_handler
            .move_to_staging(base_addr2, &shm, 3 * pagesize() as u64)
            .unwrap();
    }
    assert_eq!(page_handler.swap_in(&uffd).is_ok(), true);
    unregister_regions(&regions, array::from_ref(&uffd)).unwrap();

    // read values on another thread to avoid blocking forever
    let join_handle = thread::spawn(move || {
        let mut result = Vec::new();
        for i in 0..3 {
            for j in 0..pagesize() {
                let ptr = (base_addr1 + i * pagesize() + j) as *mut u8;
                unsafe {
                    result.push(*ptr);
                }
            }
        }
        for i in 0..3 {
            for j in 0..pagesize() {
                let ptr = (base_addr2 + i * pagesize() + j) as *mut u8;
                unsafe {
                    result.push(*ptr);
                }
            }
        }
        result
    });
    let result = wait_thread_with_timeout(join_handle, 100);
    let values: Vec<u8> = vec![0, 1, 0, 0, 4, 3];
    for (i, v) in values.iter().enumerate() {
        for j in 0..pagesize() {
            assert_eq!(&result[i * pagesize() + j], v);
        }
    }
}
