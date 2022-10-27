// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Barrier;
use std::thread;
use std::time::Duration;

use base::descriptor::FromRawDescriptor;
use base::descriptor::SafeDescriptor;
use base::platform::deserialize_with_descriptors;
use base::platform::SerializeDescriptors;
use base::Event;
use base::EventToken;
use base::ReadNotifier;
use base::RecvTube;
use base::SendTube;
use base::Tube;
use base::WaitContext;
use serde::Deserialize;
use serde::Serialize;

#[derive(Serialize, Deserialize)]
struct DataStruct {
    x: u32,
}

#[derive(EventToken, Debug, Eq, PartialEq, Copy, Clone)]
enum Token {
    ReceivedData,
}

// Magics to identify which producer sent a message (& detect corruption).
const PRODUCER_ID_1: u32 = 801279273;
const PRODUCER_ID_2: u32 = 345234861;

#[track_caller]
fn test_event_pair(send: Event, recv: Event) {
    send.signal().unwrap();
    recv.wait_timeout(Duration::from_secs(1)).unwrap();
}

#[test]
fn send_recv_no_fd() {
    let (s1, s2) = Tube::pair().unwrap();

    let test_msg = "hello world";
    s1.send(&test_msg).unwrap();
    let recv_msg: String = s2.recv().unwrap();

    assert_eq!(test_msg, recv_msg);
}

#[test]
fn send_recv_one_fd() {
    #[derive(Serialize, Deserialize)]
    struct EventStruct {
        x: u32,
        b: Event,
    }

    let (s1, s2) = Tube::pair().unwrap();

    let test_msg = EventStruct {
        x: 100,
        b: Event::new().unwrap(),
    };
    s1.send(&test_msg).unwrap();
    let recv_msg: EventStruct = s2.recv().unwrap();

    assert_eq!(test_msg.x, recv_msg.x);

    test_event_pair(test_msg.b, recv_msg.b);
}

/// Send messages to a Tube with the given identifier (see `consume_messages`; we use this to
/// track different message producers).
#[track_caller]
fn produce_messages(tube: SendTube, data: u32, barrier: Arc<Barrier>) -> SendTube {
    let data = DataStruct { x: data };
    barrier.wait();
    for _ in 0..100 {
        tube.send(&data).unwrap();
    }
    tube
}

/// Consumes the given number of messages from a Tube, returning the number messages read with
/// each producer ID.
#[track_caller]
fn consume_messages(
    tube: RecvTube,
    count: usize,
    barrier: Arc<Barrier>,
) -> (RecvTube, usize, usize) {
    barrier.wait();

    let mut id1_count = 0usize;
    let mut id2_count = 0usize;

    for _ in 0..count {
        let msg = tube.recv::<DataStruct>().unwrap();
        match msg.x {
            PRODUCER_ID_1 => id1_count += 1,
            PRODUCER_ID_2 => id2_count += 1,
            _ => panic!(
                "want message with ID {} or {}; got message w/ ID {}.",
                PRODUCER_ID_1, PRODUCER_ID_2, msg.x
            ),
        }
    }
    (tube, id1_count, id2_count)
}

#[test]
fn test_serialize_tube_pair() {
    let (tube_send, tube_recv) = Tube::pair().unwrap();

    // Serialize the Tube
    let msg_serialize = SerializeDescriptors::new(&tube_send);
    let serialized = serde_json::to_vec(&msg_serialize).unwrap();
    let msg_descriptors = msg_serialize.into_descriptors();

    // Deserialize the Tube
    let mut msg_descriptors_safe = msg_descriptors
        .into_iter()
        .map(|v| Some(unsafe { SafeDescriptor::from_raw_descriptor(v) }))
        .collect();
    let tube_deserialized: Tube = deserialize_with_descriptors(
        || serde_json::from_slice(&serialized),
        &mut msg_descriptors_safe,
    )
    .unwrap();

    // Send a message through deserialized Tube
    tube_deserialized.send(&"hi".to_string()).unwrap();

    // Wait for the message to arrive
    let wait_ctx: WaitContext<Token> =
        WaitContext::build_with(&[(tube_recv.get_read_notifier(), Token::ReceivedData)]).unwrap();
    let events = wait_ctx.wait_timeout(Duration::from_secs(10)).unwrap();
    let tokens: Vec<Token> = events
        .iter()
        .filter(|e| e.is_readable)
        .map(|e| e.token)
        .collect();
    assert_eq!(tokens, vec! {Token::ReceivedData});

    assert_eq!(tube_recv.recv::<String>().unwrap(), "hi");
}

#[test]
fn send_recv_mpsc() {
    let (p1, consumer) = Tube::directional_pair().unwrap();
    let p2 = p1.try_clone().unwrap();
    let start_block_p1 = Arc::new(Barrier::new(3));
    let start_block_p2 = start_block_p1.clone();
    let start_block_consumer = start_block_p1.clone();

    let p1_thread = thread::spawn(move || produce_messages(p1, PRODUCER_ID_1, start_block_p1));
    let p2_thread = thread::spawn(move || produce_messages(p2, PRODUCER_ID_2, start_block_p2));

    let (_tube, id1_count, id2_count) = consume_messages(consumer, 200, start_block_consumer);
    assert_eq!(id1_count, 100);
    assert_eq!(id2_count, 100);

    p1_thread.join().unwrap();
    p2_thread.join().unwrap();
}

#[test]
fn send_recv_hash_map() {
    let (s1, s2) = Tube::pair().unwrap();

    let mut test_msg = HashMap::new();
    test_msg.insert("Red".to_owned(), Event::new().unwrap());
    test_msg.insert("White".to_owned(), Event::new().unwrap());
    test_msg.insert("Blue".to_owned(), Event::new().unwrap());
    test_msg.insert("Orange".to_owned(), Event::new().unwrap());
    test_msg.insert("Green".to_owned(), Event::new().unwrap());
    s1.send(&test_msg).unwrap();
    let mut recv_msg: HashMap<String, Event> = s2.recv().unwrap();

    let mut test_msg_keys: Vec<_> = test_msg.keys().collect();
    test_msg_keys.sort();
    let mut recv_msg_keys: Vec<_> = recv_msg.keys().collect();
    recv_msg_keys.sort();
    assert_eq!(test_msg_keys, recv_msg_keys);

    for (key, test_event) in test_msg {
        let recv_event = recv_msg.remove(&key).unwrap();
        test_event_pair(test_event, recv_event);
    }
}
