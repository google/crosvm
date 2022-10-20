// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::sync::Once;

use base::syslog::*;

static EARLY_INIT_ONCE: Once = Once::new();

pub fn setup() {
    EARLY_INIT_ONCE.call_once(|| {
        early_init();
    });
}

#[test]
fn fds() {
    setup();
    let mut fds = Vec::new();
    push_descriptors(&mut fds);
    assert!(!fds.is_empty());
    for fd in fds {
        assert!(fd >= 0);
    }
}

#[test]
fn syslog_file() {
    setup();
    let mut file = tempfile::tempfile().expect("failed to create tempfile");

    let syslog_file = file.try_clone().expect("error cloning shared memory file");
    let state = State::new(LogConfig {
        pipe: Some(Box::new(syslog_file)),
        ..Default::default()
    })
    .unwrap();

    const TEST_STR: &str = "hello shared memory file";
    state.log(
        &log::RecordBuilder::new()
            .level(Level::Error)
            .args(format_args!("{}", TEST_STR))
            .build(),
    );

    file.seek(SeekFrom::Start(0))
        .expect("error seeking shared memory file");
    let mut buf = String::new();
    file.read_to_string(&mut buf)
        .expect("error reading shared memory file");
    assert!(buf.contains(TEST_STR));
}

#[test]
fn macros() {
    setup();
    log::error!("this is an error {}", 3);
    log::warn!("this is a warning {}", "uh oh");
    log::info!("this is info {}", true);
    log::debug!("this is debug info {:?}", Some("helpful stuff"));
}
