// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Integration tests using LibVDA fake decode implemenation.

#![cfg(unix)]

use libvda::decode::*;
use libvda::*;

fn create_vda_instance() -> VdaInstance {
    VdaInstance::new(VdaImplType::Fake).expect("failed to create VDAInstance")
}

#[test]
#[cfg_attr(feature = "libvda-stub", ignore = "Ignored when using libvda-stub")]
fn test_create_instance() {
    let instance = create_vda_instance();
    let caps = instance.get_capabilities();

    assert_ne!(caps.input_formats.len(), 0);
    assert_ne!(caps.output_formats.len(), 0);
}

#[test]
#[cfg_attr(feature = "libvda-stub", ignore = "Ignored when using libvda-stub")]
fn test_initialize_decode_session() {
    let instance = create_vda_instance();
    let _session = instance
        .open_session(Profile::VP8)
        .expect("failed to open a session for VP8");
}

#[test]
#[cfg_attr(feature = "libvda-stub", ignore = "Ignored when using libvda-stub")]
fn test_decode_and_get_picture_ready_fake() {
    let instance = create_vda_instance();
    let mut session = instance
        .open_session(Profile::VP8)
        .expect("failed to open a session");

    // Call decode() with dummy arguments.
    let fake_bitstream_id = 12345;
    session
        .decode(
            fake_bitstream_id,
            1, // fd
            0, // offset
            0, // bytes_used
        )
        .expect("failed to send a decode request");

    // Since we are using the fake backend,
    // we must get a event immediately after calling decode().
    match session.read_event() {
        Ok(Event::PictureReady { bitstream_id, .. }) => {
            assert_eq!(bitstream_id, fake_bitstream_id);
        }
        Ok(event) => panic!("Obtained event is not PictureReady but {:?}", event),
        Err(msg) => panic!("{}", msg),
    }
}
