// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs;

use fixture::vm::Config;
use fixture::vm::TestVm;
use tempfile::TempDir;

/// Tests audio playback on virtio-snd with file backend
///
/// 1. Create a temporal directory for the audio file.
/// 2. Start a VM with a virtiofs device for the temporal directory
///    and a virtio-snd device with file backend.
/// 3. Create a raw audio file in the temporal directory with sox.
/// 4. Do playback with aplay.
/// 5. Compare the generated audio file and the output from virtio-snd.
#[test]
fn do_playback() {
    let temp_dir = tempfile::tempdir().unwrap();
    let temp_dir_path_str = temp_dir.path().to_str().unwrap();

    let config = Config::new().extra_args(vec![
        "--shared-dir".to_string(),
        format!("{}:tmp2:type=fs:cache=always", temp_dir_path_str),
        "--virtio-snd".to_string(),
        format!(
            "backend=file,playback_path={},playback_size=400000",
            temp_dir_path_str
        ),
    ]);

    let mut vm = TestVm::new(config).unwrap();
    vm.exec_in_guest("mount -t virtiofs tmp2 /mnt").unwrap();
    vm.exec_in_guest("ls /mnt 1>&2").unwrap();
    vm.exec_in_guest(
        "sox -n -b 16 -r 48000 -c 2 -e signed -t raw \
        /mnt/test_440_48000.raw synth 1 sine 440 vol -10dB",
    )
    .unwrap();
    vm.exec_in_guest(
        "aplay --buffer-size=2048 --period-size=1024 \
        -d 1 -f dat -Dhw:0,0 /mnt/test_440_48000.raw",
    )
    .unwrap();

    assert!(compare_files(
        temp_dir,
        "test_440_48000.raw",
        "stream-0.out"
    ));
}

fn compare_files(temp_dir: TempDir, golden_file_name: &str, output_file_name: &str) -> bool {
    // 1 second, 2 channels, 16 bit (2 byte) format, 48000 frame rate.
    const BYTES_TO_COMPARE: usize = 1 * 2 * 2 * 48000;
    // Skip the first 2 * buffer-size bytes as it's 0 pads.
    const SKIP_OFFSET: usize = 2 * 2048;

    // Open the second file for reading
    let buf1 = fs::read(temp_dir.path().join(golden_file_name)).unwrap();
    let buf2 = fs::read(temp_dir.path().join(output_file_name)).unwrap();

    if buf1[..BYTES_TO_COMPARE] != buf2[SKIP_OFFSET..(SKIP_OFFSET + BYTES_TO_COMPARE)] {
        println!("Files differ");
        return false;
    }

    true
}
