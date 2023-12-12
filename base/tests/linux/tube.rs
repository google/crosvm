// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::time;

use base::deserialize_with_descriptors;
use base::BlockingMode;
use base::EventContext;
use base::EventToken;
use base::FramingMode;
use base::FromRawDescriptor;
use base::ReadNotifier;
use base::SafeDescriptor;
use base::SerializeDescriptors;
use base::StreamChannel;
use base::Tube;
use base::UnixSeqpacket;

#[derive(EventToken, Debug, Eq, PartialEq, Copy, Clone)]
enum Token {
    ReceivedData,
}

const EVENT_WAIT_TIME: time::Duration = time::Duration::from_secs(10);

#[test]
fn test_serialize_tube_new() {
    let (sock_send, sock_recv) =
        StreamChannel::pair(BlockingMode::Nonblocking, FramingMode::Message).unwrap();
    let tube_send = Tube::new(sock_send).unwrap();
    let tube_recv = Tube::new(sock_recv).unwrap();

    // Serialize the Tube
    let msg_serialize = SerializeDescriptors::new(&tube_send);
    let serialized = serde_json::to_vec(&msg_serialize).unwrap();
    let msg_descriptors = msg_serialize.into_descriptors();

    // Deserialize the Tube
    let msg_descriptors_safe = msg_descriptors.into_iter().map(|v|
            // SAFETY: Safe because `v` is a valid descriptor
            unsafe { SafeDescriptor::from_raw_descriptor(v) });
    let tube_deserialized: Tube =
        deserialize_with_descriptors(|| serde_json::from_slice(&serialized), msg_descriptors_safe)
            .unwrap();

    // Send a message through deserialized Tube
    tube_deserialized.send(&"hi".to_string()).unwrap();

    // Wait for the message to arrive
    let event_ctx: EventContext<Token> =
        EventContext::build_with(&[(tube_recv.get_read_notifier(), Token::ReceivedData)]).unwrap();
    let events = event_ctx.wait_timeout(EVENT_WAIT_TIME).unwrap();
    let tokens: Vec<Token> = events
        .iter()
        .filter(|e| e.is_readable)
        .map(|e| e.token)
        .collect();
    assert_eq!(tokens, vec! {Token::ReceivedData});

    assert_eq!(tube_recv.recv::<String>().unwrap(), "hi");
}

#[test]
fn test_send_recv_new_from_seqpacket() {
    let (sock_send, sock_recv) = UnixSeqpacket::pair().unwrap();
    let tube_send = Tube::new_from_unix_seqpacket(sock_send).unwrap();
    let tube_recv = Tube::new_from_unix_seqpacket(sock_recv).unwrap();

    tube_send.send(&"hi".to_string()).unwrap();

    // Wait for the message to arrive
    let event_ctx: EventContext<Token> =
        EventContext::build_with(&[(tube_recv.get_read_notifier(), Token::ReceivedData)]).unwrap();
    let events = event_ctx.wait_timeout(EVENT_WAIT_TIME).unwrap();
    let tokens: Vec<Token> = events
        .iter()
        .filter(|e| e.is_readable)
        .map(|e| e.token)
        .collect();
    assert_eq!(tokens, vec! {Token::ReceivedData});

    assert_eq!(tube_recv.recv::<String>().unwrap(), "hi");
}

#[test]
fn test_tube_new_byte_mode_error() {
    let (sock_byte_mode, _) =
        StreamChannel::pair(BlockingMode::Nonblocking, FramingMode::Byte).unwrap();
    let tube_error = Tube::new(sock_byte_mode);

    assert!(tube_error.is_err());
}
