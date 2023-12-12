// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io::ErrorKind;
use std::time::Duration;

use base::AsRawDescriptor;
use base::UnixSeqpacket;
use base::UnixSeqpacketListener;
use base::UnlinkUnixSeqpacketListener;
use tempfile::tempdir;

#[test]
fn unix_seqpacket_path_not_exists() {
    let res = UnixSeqpacket::connect("/path/not/exists");
    assert!(res.is_err());
}

#[test]
fn unix_seqpacket_listener_path() {
    let temp_dir = tempdir().expect("failed to create tempdir");
    let socket_path = temp_dir.path().join("unix_seqpacket_listener_path");
    let listener = UnlinkUnixSeqpacketListener(
        UnixSeqpacketListener::bind(&socket_path).expect("failed to create UnixSeqpacketListener"),
    );
    let listener_path = listener.path().expect("failed to get socket listener path");
    assert_eq!(socket_path, listener_path);
}

#[test]
fn unix_seqpacket_listener_from_fd() {
    let temp_dir = tempdir().expect("failed to create tempdir");
    let socket_path = temp_dir.path().join("unix_seqpacket_listener_from_fd");
    let listener = UnlinkUnixSeqpacketListener(
        UnixSeqpacketListener::bind(&socket_path).expect("failed to create UnixSeqpacketListener"),
    );
    // UnixSeqpacketListener should succeed on a valid listening descriptor.
    // SAFETY: Safe because `listener` is valid and the return value is checked.
    let good_dup = UnixSeqpacketListener::bind(format!("/proc/self/fd/{}", unsafe {
        libc::dup(listener.as_raw_descriptor())
    }));
    let good_dup_path = good_dup
        .expect("failed to create dup UnixSeqpacketListener")
        .path();
    // Path of socket created by descriptor should be hidden.
    assert!(good_dup_path.is_err());
    // UnixSeqpacketListener must fail on an existing non-listener socket.
    let s1 = UnixSeqpacket::connect(socket_path.as_path()).expect("UnixSeqpacket::connect failed");
    // SAFETY: Safe because `s1` is valid and the return value is checked.
    let bad_dup = UnixSeqpacketListener::bind(format!("/proc/self/fd/{}", unsafe {
        libc::dup(s1.as_raw_descriptor())
    }));
    assert!(bad_dup.is_err());
}

#[test]
fn unix_seqpacket_path_exists_pass() {
    let temp_dir = tempdir().expect("failed to create tempdir");
    let socket_path = temp_dir.path().join("path_to_socket");
    let _listener = UnlinkUnixSeqpacketListener(
        UnixSeqpacketListener::bind(&socket_path).expect("failed to create UnixSeqpacketListener"),
    );
    let _res =
        UnixSeqpacket::connect(socket_path.as_path()).expect("UnixSeqpacket::connect failed");
}

#[test]
fn unix_seqpacket_path_listener_accept_with_timeout() {
    let temp_dir = tempdir().expect("failed to create tempdir");
    let socket_path = temp_dir.path().join("path_listerner_accept_with_timeout");
    let listener = UnlinkUnixSeqpacketListener(
        UnixSeqpacketListener::bind(&socket_path).expect("failed to create UnixSeqpacketListener"),
    );

    for d in [Duration::from_millis(10), Duration::ZERO] {
        let _ = listener.accept_with_timeout(d).expect_err(&format!(
            "UnixSeqpacket::accept_with_timeout {:?} connected",
            d
        ));

        let s1 = UnixSeqpacket::connect(socket_path.as_path())
            .unwrap_or_else(|_| panic!("UnixSeqpacket::connect {:?} failed", d));

        let s2 = listener
            .accept_with_timeout(d)
            .unwrap_or_else(|_| panic!("UnixSeqpacket::accept {:?} failed", d));

        let data1 = &[0, 1, 2, 3, 4];
        let data2 = &[10, 11, 12, 13, 14];
        s2.send(data2).expect("failed to send data2");
        s1.send(data1).expect("failed to send data1");
        let recv_data = &mut [0; 5];
        s2.recv(recv_data).expect("failed to recv data");
        assert_eq!(data1, recv_data);
        s1.recv(recv_data).expect("failed to recv data");
        assert_eq!(data2, recv_data);
    }
}

#[test]
fn unix_seqpacket_path_listener_accept() {
    let temp_dir = tempdir().expect("failed to create tempdir");
    let socket_path = temp_dir.path().join("path_listerner_accept");
    let listener = UnlinkUnixSeqpacketListener(
        UnixSeqpacketListener::bind(&socket_path).expect("failed to create UnixSeqpacketListener"),
    );
    let s1 = UnixSeqpacket::connect(socket_path.as_path()).expect("UnixSeqpacket::connect failed");

    let s2 = listener.accept().expect("UnixSeqpacket::accept failed");

    let data1 = &[0, 1, 2, 3, 4];
    let data2 = &[10, 11, 12, 13, 14];
    s2.send(data2).expect("failed to send data2");
    s1.send(data1).expect("failed to send data1");
    let recv_data = &mut [0; 5];
    s2.recv(recv_data).expect("failed to recv data");
    assert_eq!(data1, recv_data);
    s1.recv(recv_data).expect("failed to recv data");
    assert_eq!(data2, recv_data);
}

#[test]
fn unix_seqpacket_zero_timeout() {
    let (s1, _s2) = UnixSeqpacket::pair().expect("failed to create socket pair");
    // Timeouts less than a microsecond are too small and round to zero.
    s1.set_read_timeout(Some(Duration::from_nanos(10)))
        .expect_err("successfully set zero timeout");
}

#[test]
fn unix_seqpacket_read_timeout() {
    let (s1, _s2) = UnixSeqpacket::pair().expect("failed to create socket pair");
    s1.set_read_timeout(Some(Duration::from_millis(1)))
        .expect("failed to set read timeout for socket");
    let _ = s1.recv(&mut [0]);
}

#[test]
fn unix_seqpacket_write_timeout() {
    let (s1, _s2) = UnixSeqpacket::pair().expect("failed to create socket pair");
    s1.set_write_timeout(Some(Duration::from_millis(1)))
        .expect("failed to set write timeout for socket");
}

#[test]
fn unix_seqpacket_send_recv() {
    let (s1, s2) = UnixSeqpacket::pair().expect("failed to create socket pair");
    let data1 = &[0, 1, 2, 3, 4];
    let data2 = &[10, 11, 12, 13, 14];
    s2.send(data2).expect("failed to send data2");
    s1.send(data1).expect("failed to send data1");
    let recv_data = &mut [0; 5];
    s2.recv(recv_data).expect("failed to recv data");
    assert_eq!(data1, recv_data);
    s1.recv(recv_data).expect("failed to recv data");
    assert_eq!(data2, recv_data);
}

#[test]
fn unix_seqpacket_send_fragments() {
    let (s1, s2) = UnixSeqpacket::pair().expect("failed to create socket pair");
    let data1 = &[0, 1, 2, 3, 4];
    let data2 = &[10, 11, 12, 13, 14, 15, 16];
    s1.send(data1).expect("failed to send data1");
    s1.send(data2).expect("failed to send data2");

    let recv_data = &mut [0; 32];
    let size = s2.recv(recv_data).expect("failed to recv data");
    assert_eq!(size, data1.len());
    assert_eq!(data1, &recv_data[0..size]);

    let size = s2.recv(recv_data).expect("failed to recv data");
    assert_eq!(size, data2.len());
    assert_eq!(data2, &recv_data[0..size]);
}

#[test]
fn unix_seqpacket_get_readable_bytes() {
    let (s1, s2) = UnixSeqpacket::pair().expect("failed to create socket pair");
    assert_eq!(s1.get_readable_bytes().unwrap(), 0);
    assert_eq!(s2.get_readable_bytes().unwrap(), 0);
    let data1 = &[0, 1, 2, 3, 4];
    s1.send(data1).expect("failed to send data");

    assert_eq!(s1.get_readable_bytes().unwrap(), 0);
    assert_eq!(s2.get_readable_bytes().unwrap(), data1.len());

    let recv_data = &mut [0; 5];
    s2.recv(recv_data).expect("failed to recv data");
    assert_eq!(s1.get_readable_bytes().unwrap(), 0);
    assert_eq!(s2.get_readable_bytes().unwrap(), 0);
}

#[test]
fn unix_seqpacket_next_packet_size() {
    let (s1, s2) = UnixSeqpacket::pair().expect("failed to create socket pair");
    let data1 = &[0, 1, 2, 3, 4];
    s1.send(data1).expect("failed to send data");

    assert_eq!(s2.next_packet_size().unwrap(), 5);
    s1.set_read_timeout(Some(Duration::from_micros(1)))
        .expect("failed to set read timeout");
    assert_eq!(
        s1.next_packet_size().unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
    drop(s2);
    assert_eq!(
        s1.next_packet_size().unwrap_err().kind(),
        ErrorKind::ConnectionReset
    );
}

#[test]
fn unix_seqpacket_recv_to_vec() {
    let (s1, s2) = UnixSeqpacket::pair().expect("failed to create socket pair");
    let data1 = &[0, 1, 2, 3, 4];
    s1.send(data1).expect("failed to send data");

    let recv_data = &mut vec![];
    s2.recv_to_vec(recv_data).expect("failed to recv data");
    assert_eq!(recv_data, &mut vec![0, 1, 2, 3, 4]);
}

#[test]
fn unix_seqpacket_recv_as_vec() {
    let (s1, s2) = UnixSeqpacket::pair().expect("failed to create socket pair");
    let data1 = &[0, 1, 2, 3, 4];
    s1.send(data1).expect("failed to send data");

    let recv_data = s2.recv_as_vec().expect("failed to recv data");
    assert_eq!(recv_data, vec![0, 1, 2, 3, 4]);
}
