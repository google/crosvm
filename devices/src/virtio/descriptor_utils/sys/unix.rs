// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(test)]
mod tests {
    use std::fs::File;

    use cros_async::Executor;
    use tempfile::tempfile;

    use crate::virtio::descriptor_utils::*;

    #[test]
    fn region_reader_failing_io() {
        let ex = Executor::new().unwrap();
        ex.run_until(region_reader_failing_io_async(&ex)).unwrap();
    }
    async fn region_reader_failing_io_async(ex: &Executor) {
        use DescriptorType::*;

        let memory_start_addr = GuestAddress(0x0);
        let memory = GuestMemory::new(&[(memory_start_addr, 0x10000)]).unwrap();

        let chain = create_descriptor_chain(
            &memory,
            GuestAddress(0x0),
            GuestAddress(0x100),
            vec![(Readable, 256), (Readable, 256)],
            0,
        )
        .expect("create_descriptor_chain failed");

        let mut reader = Reader::new(&chain);

        // TODO(b/235104127): Potentially use tempfile for ro_file so that this
        // test can run on Windows.
        // Open a file in read-only mode so writes to it to trigger an I/O error.
        let ro_file = File::open("/dev/zero").expect("failed to open /dev/zero");
        let async_ro_file = disk::SingleFileDisk::new(ro_file, ex).expect("Failed to crate SFD");

        reader
            .read_exact_to_at_fut(&async_ro_file, 512, 0)
            .await
            .expect_err("successfully read more bytes than SharedMemory size");

        // The write above should have failed entirely, so we end up not writing any bytes at all.
        assert_eq!(reader.available_bytes(), 512);
        assert_eq!(reader.bytes_read(), 0);
    }

    #[test]
    fn region_writer_failing_io() {
        let ex = Executor::new().unwrap();
        ex.run_until(region_writer_failing_io_async(&ex)).unwrap()
    }
    async fn region_writer_failing_io_async(ex: &Executor) {
        use DescriptorType::*;

        let memory_start_addr = GuestAddress(0x0);
        let memory = GuestMemory::new(&[(memory_start_addr, 0x10000)]).unwrap();

        let chain = create_descriptor_chain(
            &memory,
            GuestAddress(0x0),
            GuestAddress(0x100),
            vec![(Writable, 256), (Writable, 256)],
            0,
        )
        .expect("create_descriptor_chain failed");

        let mut writer = Writer::new(&chain);

        let file = tempfile().expect("failed to create temp file");

        file.set_len(384).unwrap();
        let async_file = disk::SingleFileDisk::new(file, ex).expect("Failed to crate SFD");

        writer
            .write_all_from_at_fut(&async_file, 512, 0)
            .await
            .expect_err("successfully wrote more bytes than in SharedMemory");

        assert_eq!(writer.available_bytes(), 128);
        assert_eq!(writer.bytes_written(), 384);
    }
}
