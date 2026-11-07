//! The HTTPJet batch extension's syscall-level loopback regressions.
use quinn_udp::{EcnCodepoint, RecvMeta, Transmit, UdpSocketState};
use std::io::IoSliceMut;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::time::Duration;

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn send_batch_preserves_each_message_metadata_and_bounded_prefix() {
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let state = UdpSocketState::new((&sender).into()).unwrap();
    let recv_state = UdpSocketState::new((&receiver).into()).unwrap();
    // UdpSocketState switches the descriptor to nonblocking; the bounded test
    // timeout applies after restoring blocking mode for each one-message read.
    receiver.set_nonblocking(false).unwrap();
    let payloads: Vec<_> = (0..quinn_udp::MAX_SEND_BATCH + 1)
        .map(|n| vec![n as u8; 32])
        .collect();
    let messages: Vec<_> = payloads
        .iter()
        .enumerate()
        .map(|(n, contents)| Transmit {
            destination: receiver.local_addr().unwrap(),
            ecn: Some(if n % 2 == 0 {
                EcnCodepoint::Ect0
            } else {
                EcnCodepoint::Ect1
            }),
            contents,
            segment_size: None,
            src_ip: Some(Ipv4Addr::LOCALHOST.into()),
        })
        .collect();
    assert_eq!(state.try_send_batch((&sender).into(), &[]).unwrap(), 0);
    assert_eq!(
        state.try_send_batch((&sender).into(), &messages).unwrap(),
        quinn_udp::MAX_SEND_BATCH
    );
    assert_eq!(
        state
            .try_send_batch((&sender).into(), &messages[quinn_udp::MAX_SEND_BATCH..])
            .unwrap(),
        1
    );
    for (index, expected) in payloads.iter().enumerate() {
        let mut bytes = [0u8; 128];
        let mut slices = [IoSliceMut::new(&mut bytes)];
        let mut meta = [RecvMeta::default()];
        assert_eq!(
            recv_state
                .recv((&receiver).into(), &mut slices, &mut meta)
                .unwrap(),
            1
        );
        assert_eq!(&bytes[..meta[0].len], expected);
        assert_eq!(meta[0].addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(
            meta[0].ecn,
            Some(if index % 2 == 0 {
                EcnCodepoint::Ect0
            } else {
                EcnCodepoint::Ect1
            })
        );
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn send_batch_partial_success_does_not_repeat_the_accepted_prefix() {
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let state = UdpSocketState::new((&sender).into()).unwrap();
    let messages = [
        Transmit {
            destination: receiver.local_addr().unwrap(),
            ecn: None,
            contents: b"first",
            segment_size: None,
            src_ip: None,
        },
        Transmit {
            // An IPv4-only socket cannot send an IPv6 destination. Linux reports
            // the successful prefix before this error, then the failing head alone.
            destination: "[::1]:12345".parse().unwrap(),
            ecn: None,
            contents: b"invalid",
            segment_size: None,
            src_ip: None,
        },
        Transmit {
            destination: receiver.local_addr().unwrap(),
            ecn: None,
            contents: b"last",
            segment_size: None,
            src_ip: None,
        },
    ];
    assert_eq!(
        state.try_send_batch((&sender).into(), &messages).unwrap(),
        1
    );
    assert!(
        state
            .try_send_batch((&sender).into(), &messages[1..])
            .is_err()
    );
    assert_eq!(
        state
            .try_send_batch((&sender).into(), &messages[2..])
            .unwrap(),
        1
    );
    let mut bytes = [0u8; 32];
    let count = receiver.recv(&mut bytes).unwrap();
    assert_eq!(&bytes[..count], b"first");
    let count = receiver.recv(&mut bytes).unwrap();
    assert_eq!(&bytes[..count], b"last");
    receiver.set_nonblocking(true).unwrap();
    assert_eq!(
        receiver.recv(&mut bytes).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn send_batch_keeps_scalar_dynamic_gso_error_fallback() {
    use std::os::fd::AsRawFd;
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let state = UdpSocketState::new((&sender).into()).unwrap();
    assert!(
        state.max_gso_segments() > 1,
        "qualification requires UDP GSO"
    );
    let on: libc::c_int = 1;
    // Linux rejects UDP segmentation when checksumming is disabled. This is an
    // owned socket; no host routing, interface, qdisc or sysctl is changed.
    assert_eq!(
        unsafe {
            libc::setsockopt(
                sender.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_NO_CHECK,
                (&on as *const libc::c_int).cast(),
                std::mem::size_of_val(&on) as _,
            )
        },
        0
    );
    let body = [7u8; 2400];
    let messages = [
        Transmit {
            destination: receiver.local_addr().unwrap(),
            ecn: None,
            contents: &body,
            segment_size: Some(1200),
            src_ip: None,
        },
        Transmit {
            destination: receiver.local_addr().unwrap(),
            ecn: None,
            contents: b"after fallback",
            segment_size: None,
            src_ip: None,
        },
    ];
    assert!(state.try_send_batch((&sender).into(), &messages).is_err());
    assert_eq!(state.max_gso_segments(), 1);
    assert_eq!(
        state
            .try_send_batch((&sender).into(), &messages[1..])
            .unwrap(),
        1
    );
    let mut bytes = [0u8; 32];
    let count = receiver.recv(&mut bytes).unwrap();
    assert_eq!(&bytes[..count], b"after fallback");
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn send_batch_keeps_distinct_destination_storage() {
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    let first = UdpSocket::bind("127.0.0.1:0").unwrap();
    let second = UdpSocket::bind("127.0.0.1:0").unwrap();
    first
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    second
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let state = UdpSocketState::new((&sender).into()).unwrap();
    let messages = [
        Transmit {
            destination: first.local_addr().unwrap(),
            ecn: None,
            contents: b"first socket",
            segment_size: None,
            src_ip: None,
        },
        Transmit {
            destination: second.local_addr().unwrap(),
            ecn: None,
            contents: b"second socket",
            segment_size: None,
            src_ip: None,
        },
    ];
    assert_eq!(
        state.try_send_batch((&sender).into(), &messages).unwrap(),
        2
    );
    let mut bytes = [0u8; 32];
    let count = first.recv(&mut bytes).unwrap();
    assert_eq!(&bytes[..count], b"first socket");
    let count = second.recv(&mut bytes).unwrap();
    assert_eq!(&bytes[..count], b"second socket");
}
