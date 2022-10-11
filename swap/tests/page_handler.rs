// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Integration tests for [PageHandler]. these are more than unit tests since [PageHandler] rely on
//! the userfaultfd(2) kernel feature.

use userfaultfd::UffdBuilder;

use std::array;
use std::thread;
use std::time;

use base::pagesize;
use base::MemoryMappingBuilder;
use base::SharedMemory;
use data_model::VolatileMemory;
use swap::page_handler::Error;
use swap::page_handler::PageHandler;
use swap::userfaultfd::Userfaultfd;

fn create_uffd_for_test() -> Userfaultfd {
    UffdBuilder::new()
        .non_blocking(false)
        .create()
        .unwrap()
        .into()
}

#[test]
fn register_region_success() {
    let dir_path = tempfile::tempdir().unwrap().into_path();
    let mmap = MemoryMappingBuilder::new(6 * pagesize()).build().unwrap();
    let uffd: Userfaultfd = create_uffd_for_test();
    let base_addr = mmap.get_ref::<u8>(0).unwrap().as_mut_ptr() as usize;

    let result = unsafe {
        PageHandler::register_regions(
            array::from_ref(&uffd),
            &dir_path,
            &[
                base_addr..(base_addr + 3 * pagesize()),
                (base_addr + 3 * pagesize())..(base_addr + 6 * pagesize()),
            ],
        )
    };

    assert_eq!(result.is_ok(), true);
}

#[test]
fn register_region_partially_overlap() {
    let dir_path = tempfile::tempdir().unwrap().into_path();
    let mmap = MemoryMappingBuilder::new(3 * pagesize()).build().unwrap();
    let uffd: Userfaultfd = create_uffd_for_test();
    let base_addr = mmap.get_ref::<u8>(0).unwrap().as_mut_ptr() as usize;

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
        let result = unsafe {
            PageHandler::register_regions(
                array::from_ref(&uffd),
                &dir_path,
                &[base_addr..(base_addr + 3 * pagesize()), range],
            )
        };
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
    let dir_path = tempfile::tempdir().unwrap().into_path();
    let mmap = MemoryMappingBuilder::new(3 * pagesize()).build().unwrap();
    let uffd: Userfaultfd = create_uffd_for_test();
    let base_addr = mmap.get_ref::<u8>(0).unwrap().as_mut_ptr() as usize;
    let mut page_handler = unsafe {
        PageHandler::register_regions(
            array::from_ref(&uffd),
            &dir_path,
            &[base_addr..(base_addr + 3 * pagesize())],
        )
    }
    .unwrap();

    page_handler
        .handle_page_fault(&uffd, base_addr as usize)
        .unwrap();
    page_handler
        .handle_page_fault(
            &uffd,
            mmap.get_ref::<u8>(pagesize() + 1).unwrap().as_mut_ptr() as usize,
        )
        .unwrap();
    page_handler
        .handle_page_fault(
            &uffd,
            mmap.get_ref::<u8>(3 * pagesize() - 1).unwrap().as_mut_ptr() as usize,
        )
        .unwrap();

    // read values on another thread to avoid blocking forever
    let join_handle = thread::spawn(move || {
        let mut result = Vec::new();
        for i in 0..(3 * pagesize()) {
            let ptr = mmap.get_ref::<u8>(i).unwrap().as_mut_ptr();
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
    let dir_path = tempfile::tempdir().unwrap().into_path();
    let mmap = MemoryMappingBuilder::new(3 * pagesize()).build().unwrap();
    let uffd: Userfaultfd = create_uffd_for_test();
    let base_addr = mmap.get_ref::<u8>(0).unwrap().as_mut_ptr() as usize;
    let mut page_handler = unsafe {
        PageHandler::register_regions(
            array::from_ref(&uffd),
            &dir_path,
            &[base_addr..(base_addr + 3 * pagesize())],
        )
    }
    .unwrap();

    assert_eq!(
        page_handler
            .handle_page_fault(&uffd, (base_addr as usize) - 1)
            .is_err(),
        true
    );
    assert_eq!(
        page_handler
            .handle_page_fault(&uffd, (base_addr as usize) + 3 * pagesize())
            .is_err(),
        true
    );
}

#[test]
fn handle_page_fault_duplicated_page_fault() {
    let dir_path = tempfile::tempdir().unwrap().into_path();
    let mmap = MemoryMappingBuilder::new(3 * pagesize()).build().unwrap();
    let uffd: Userfaultfd = create_uffd_for_test();
    let base_addr = mmap.get_ref::<u8>(0).unwrap().as_mut_ptr() as usize;
    let mut page_handler = unsafe {
        PageHandler::register_regions(
            array::from_ref(&uffd),
            &dir_path,
            &[base_addr..(base_addr + 3 * pagesize())],
        )
    }
    .unwrap();

    assert_eq!(
        page_handler
            .handle_page_fault(&uffd, base_addr as usize)
            .is_ok(),
        true
    );
    assert_eq!(
        page_handler
            .handle_page_fault(&uffd, (base_addr as usize) + 1)
            .is_ok(),
        true
    );
}

#[test]
fn handle_page_remove_success() {
    let dir_path = tempfile::tempdir().unwrap().into_path();
    let mmap = MemoryMappingBuilder::new(3 * pagesize()).build().unwrap();
    let uffd: Userfaultfd = create_uffd_for_test();
    let base_addr = mmap.get_ref::<u8>(0).unwrap().as_mut_ptr() as usize;
    let mut page_handler = unsafe {
        PageHandler::register_regions(
            array::from_ref(&uffd),
            &dir_path,
            &[base_addr..(base_addr + 3 * pagesize())],
        )
    }
    .unwrap();

    // fill the first page with zero
    page_handler
        .handle_page_fault(&uffd, base_addr as usize)
        .unwrap();
    // write value on another thread to avoid blocking forever
    let base_addr_usize = base_addr as usize;
    let join_handle = thread::spawn(move || {
        let base_addr = base_addr_usize as *mut u8;
        unsafe {
            *base_addr = 1;
        }
    });
    wait_thread_with_timeout(join_handle, 100);
    let second_page_addr = mmap.get_ref::<u8>(pagesize()).unwrap().as_mut_ptr();
    page_handler
        .handle_page_remove(base_addr as usize, second_page_addr as usize)
        .unwrap();
    unsafe {
        libc::madvise(
            base_addr as *mut libc::c_void,
            pagesize(),
            libc::MADV_REMOVE,
        );
    }
    // fill the first page with zero again
    page_handler
        .handle_page_fault(&uffd, base_addr as usize)
        .unwrap();
    // read value on another thread to avoid blocking forever
    let join_handle = thread::spawn(move || {
        let base_addr = base_addr_usize as *mut u8;
        unsafe { *base_addr }
    });

    assert_eq!(wait_thread_with_timeout(join_handle, 100), 0);
}

#[test]
fn handle_page_remove_invalid_address() {
    let dir_path = tempfile::tempdir().unwrap().into_path();
    let mmap = MemoryMappingBuilder::new(3 * pagesize()).build().unwrap();
    let uffd: Userfaultfd = create_uffd_for_test();
    let base_addr = mmap.get_ref::<u8>(0).unwrap().as_mut_ptr() as usize;
    let mut page_handler = unsafe {
        PageHandler::register_regions(
            array::from_ref(&uffd),
            &dir_path,
            &[base_addr..(base_addr + 3 * pagesize())],
        )
    }
    .unwrap();

    page_handler
        .handle_page_fault(&uffd, base_addr as usize)
        .unwrap();
    page_handler
        .handle_page_fault(&uffd, (base_addr as usize) + pagesize())
        .unwrap();
    page_handler
        .handle_page_fault(&uffd, (base_addr as usize) + 2 * pagesize())
        .unwrap();
    assert_eq!(
        page_handler
            .handle_page_remove(
                (base_addr as usize) - 1,
                (base_addr as usize) + 3 * pagesize()
            )
            .is_err(),
        true
    );
    assert_eq!(
        page_handler
            .handle_page_remove(
                base_addr as usize,
                (base_addr as usize) + 3 * pagesize() + 1
            )
            .is_err(),
        true
    );
    // remove for whole region should succeed.
    assert_eq!(
        page_handler
            .handle_page_remove(base_addr as usize, (base_addr as usize) + 3 * pagesize())
            .is_ok(),
        true
    );
}

#[test]
fn swap_out_success() {
    let uffd: Userfaultfd = create_uffd_for_test();
    let dir_path = tempfile::tempdir().unwrap().into_path();
    let shm1 = SharedMemory::new("shm1", 3 * pagesize() as u64).unwrap();
    let mmap1 = MemoryMappingBuilder::new(3 * pagesize())
        .from_shared_memory(&shm1)
        .build()
        .unwrap();
    let base_addr1 = mmap1.get_ref::<u8>(0).unwrap().as_mut_ptr() as usize;
    let shm2 = SharedMemory::new("shm2", 3 * pagesize() as u64).unwrap();
    let mmap2 = MemoryMappingBuilder::new(3 * pagesize())
        .from_shared_memory(&shm2)
        .build()
        .unwrap();
    let base_addr2 = mmap2.get_ref::<u8>(0).unwrap().as_mut_ptr() as usize;
    let mut page_handler = unsafe {
        PageHandler::register_regions(
            array::from_ref(&uffd),
            &dir_path,
            &[
                base_addr1..(base_addr1 + 3 * pagesize()),
                base_addr2..(base_addr2 + 3 * pagesize()),
            ],
        )
    }
    .unwrap();

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
    page_handler.swap_out(base_addr1, &shm1, 0).unwrap();
    page_handler.swap_out(base_addr2, &shm2, 0).unwrap();

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
    let uffd: Userfaultfd = create_uffd_for_test();
    let dir_path = tempfile::tempdir().unwrap().into_path();
    let shm1 = SharedMemory::new("shm1", 3 * pagesize() as u64).unwrap();
    let mmap1 = MemoryMappingBuilder::new(3 * pagesize())
        .from_shared_memory(&shm1)
        .build()
        .unwrap();
    let base_addr1 = mmap1.get_ref::<u8>(0).unwrap().as_mut_ptr() as usize;
    let shm2 = SharedMemory::new("shm2", 3 * pagesize() as u64).unwrap();
    let mmap2 = MemoryMappingBuilder::new(3 * pagesize())
        .from_shared_memory(&shm2)
        .build()
        .unwrap();
    let base_addr2 = mmap2.get_ref::<u8>(0).unwrap().as_mut_ptr() as usize;
    let mut page_handler = unsafe {
        PageHandler::register_regions(
            array::from_ref(&uffd),
            &dir_path,
            &[
                base_addr1..(base_addr1 + 3 * pagesize()),
                base_addr2..(base_addr2 + 3 * pagesize()),
            ],
        )
    }
    .unwrap();

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
    page_handler.swap_out(base_addr1, &shm1, 0).unwrap();
    page_handler.swap_out(base_addr2, &shm2, 0).unwrap();
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
    page_handler.swap_out(base_addr1, &shm1, 0).unwrap();
    page_handler.swap_out(base_addr2, &shm2, 0).unwrap();

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
    let uffd: Userfaultfd = create_uffd_for_test();
    let dir_path = tempfile::tempdir().unwrap().into_path();
    let shm = SharedMemory::new("shm1", 3 * pagesize() as u64).unwrap();
    let mmap = MemoryMappingBuilder::new(3 * pagesize())
        .from_shared_memory(&shm)
        .build()
        .unwrap();
    let base_addr = mmap.get_ref::<u8>(0).unwrap().as_mut_ptr() as usize;
    let mut page_handler = unsafe {
        PageHandler::register_regions(
            array::from_ref(&uffd),
            &dir_path,
            &[base_addr..(base_addr + 3 * pagesize())],
        )
    }
    .unwrap();

    // the base_addr is within the region
    assert_eq!(
        page_handler
            .swap_out(base_addr + pagesize(), &shm, 0)
            .is_err(),
        true
    );
    // the base_addr is outside of the region
    assert_eq!(
        page_handler
            .swap_out(base_addr - pagesize(), &shm, 0)
            .is_err(),
        true
    );
}
