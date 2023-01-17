// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Integration tests using LibVDA fake encode implementation.

#![cfg(unix)]

use libvda::encode::*;
use libvda::*;

fn create_vea_instance() -> VeaInstance {
    VeaInstance::new(VeaImplType::Fake).expect("failed to create VeaInstance")
}

fn create_config() -> Config {
    Config {
        input_format: PixelFormat::YV12,
        input_visible_height: 320,
        input_visible_width: 192,
        output_profile: Profile::H264ProfileBaseline,
        bitrate: Bitrate {
            mode: BitrateMode::CBR,
            target: 100,
            peak: 0,
        },
        initial_framerate: None,
        h264_output_level: None,
    }
}

#[test]
#[cfg_attr(feature = "libvda-stub", ignore = "Ignored when using libvda-stub")]
fn test_create_instance() {
    let instance = create_vea_instance();
    let caps = instance.get_capabilities();

    assert_ne!(caps.input_formats.len(), 0);
    assert_ne!(caps.output_formats.len(), 0);
}

#[test]
#[cfg_attr(feature = "libvda-stub", ignore = "Ignored when using libvda-stub")]
fn test_initialize_encode_session() {
    let instance = create_vea_instance();
    let config = create_config();

    let _session = instance
        .open_session(config)
        .expect("failed to open a session");
}

#[test]
#[cfg_attr(feature = "libvda-stub", ignore = "Ignored when using libvda-stub")]
fn test_encode_and_get_buffer_back() {
    let instance = create_vea_instance();
    let config = create_config();
    let mut session = instance
        .open_session(config)
        .expect("failed to open a session");

    // Call encode() with dummy arguments.
    let fake_input_buffer_id = 12345;
    let fake_planes = vec![];
    session
        .encode(
            fake_input_buffer_id,
            1,            // fd
            &fake_planes, // planes
            0,            // timestamp
            false,        // force_keyframe
        )
        .expect("failed to send an encode request");

    // Since we are using the fake backend, we should get back
    // the input buffer right away.
    match session.read_event() {
        Ok(Event::ProcessedInputBuffer(returned_input_buffer_id)) => {
            assert_eq!(fake_input_buffer_id, returned_input_buffer_id);
        }
        Ok(event) => panic!("Obtained event is not ProcessedInputBuffer but {:?}", event),
        Err(msg) => panic!("{}", msg),
    }
}

#[test]
#[cfg_attr(feature = "libvda-stub", ignore = "Ignored when using libvda-stub")]
fn test_use_output_buffer_and_get_buffer_back() {
    let instance = create_vea_instance();
    let config = create_config();
    let mut session = instance
        .open_session(config)
        .expect("failed to open a session");

    // Call use_output_buffer with dummy arguments.
    let fake_output_buffer_id = 12345;
    session
        .use_output_buffer(
            fake_output_buffer_id,
            2, // fd
            0, // offset
            0, // size
        )
        .expect("failed to send use_output_buffer request");

    // Since we are using the fake backend, we should get back
    // the input buffer right away.
    match session.read_event() {
        Ok(Event::ProcessedOutputBuffer {
            output_buffer_id: returned_output_buffer_id,
            ..
        }) => {
            assert_eq!(fake_output_buffer_id, returned_output_buffer_id);
        }
        Ok(event) => panic!(
            "Obtained event is not ProcessedOutputBuffer but {:?}",
            event
        ),
        Err(msg) => panic!("{}", msg),
    }
}
