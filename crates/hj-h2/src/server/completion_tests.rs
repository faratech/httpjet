use super::*;

#[test]
fn bulk_framing_headroom_preserves_small_batches_and_is_reserved_once() {
    let mut out = OutQueue {
        data_remaining: Some(64 * 1024),
        reserve_headroom_on_bulk: true,
        ..OutQueue::default()
    };
    out.reserve_bulk_headroom(1024);
    out.body(Bytes::from_static(&[0; 1024]));
    assert_eq!(out.remaining_data_for(1024), 63 * 1024);
    assert_eq!(out.remaining_data_for(16 * 1024), 62 * 1024);
    out.reserve_bulk_headroom(16 * 1024);
    assert_eq!(out.remaining_data(), 62 * 1024);
    out.reserve_bulk_headroom(16 * 1024);
    assert_eq!(out.remaining_data(), 62 * 1024);
}

use hj_core::{Body, ResponseCompletion, ResponseEnd};
use std::sync::{Arc, Mutex};

type Events = Arc<Mutex<Vec<ResponseEnd>>>;

#[test]
fn borrowed_h2_sender_matches_ordinary_settings_hints_and_window_pressure() {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::CONTENT_LENGTH,
        http::HeaderValue::from_static("2"),
    );
    headers.insert(
        http::header::LINK,
        http::HeaderValue::from_static("<https://static.test>; rel=preconnect"),
    );
    let headers = Arc::new(headers);
    let mut ordinary_encoder = Encoder::new();
    let mut borrowed_encoder = Encoder::new();
    let mut decoder = Decoder::new(4096, 65536);
    for (sid, table_limit, credit) in [(1, 4096, 65535), (3, 0, 0), (5, 4096, 65535)] {
        ordinary_encoder.set_peer_max_size(table_limit);
        borrowed_encoder.set_peer_max_size(table_limit);
        let mut ordinary = Response::new(Body::Full(Bytes::from_static(b"ok")));
        ordinary
            .extensions_mut()
            .insert(hj_core::SharedHeaders(headers.clone()));
        let mut ordinary_out = OutQueue::default();
        let mut borrowed_out = OutQueue::default();
        let mut ordinary_streams = FxHashMap::default();
        let mut borrowed_streams = FxHashMap::default();
        let (mut a_window, mut b_window) = (credit, credit);
        send::begin_response(
            sid,
            false,
            ordinary,
            &mut ordinary_encoder,
            &mut ordinary_out,
            &mut ordinary_streams,
            &mut SendSchedule::default(),
            &mut FxHashMap::default(),
            &mut a_window,
            &PeerSettings::default(),
            &mut Vec::new(),
        );
        send::begin_ready_response(
            sid,
            false,
            ReadyResponse::SharedFull(SharedFullResponse {
                headers: headers.clone(),
                body: Bytes::from_static(b"ok"),
            }),
            &mut borrowed_encoder,
            &mut borrowed_out,
            &mut borrowed_streams,
            &mut SendSchedule::default(),
            &mut FxHashMap::default(),
            &mut b_window,
            &PeerSettings::default(),
            &mut Vec::new(),
        );
        assert_eq!(ordinary_out.inline, borrowed_out.inline);
        assert_eq!(a_window, b_window);
        assert_eq!(ordinary_streams.len(), borrowed_streams.len());
        if credit == 0 {
            assert_eq!(&borrowed_streams[&sid].pending[..], b"ok");
            cancel_outstream(&mut borrowed_streams, sid);
            cancel_outstream(&mut ordinary_streams, sid);
            assert!(
                borrowed_streams.is_empty() && ordinary_streams.is_empty(),
                "RST drops either queued full body"
            );
        } else {
            assert!(borrowed_streams.is_empty());
        }
        let mut wire = borrowed_out.inline.as_slice();
        let mut statuses = Vec::new();
        let mut data = Vec::new();
        while !wire.is_empty() {
            let header = FrameHeader::parse(wire).unwrap();
            assert_eq!(header.stream_id, sid);
            let end = FrameHeader::LEN + header.length as usize;
            match header.kind {
                frame::kind::HEADERS => decoder
                    .decode(&wire[FrameHeader::LEN..end], |name, value| {
                        if name == ":status" {
                            statuses.push(value.to_owned());
                        }
                    })
                    .unwrap(),
                frame::kind::DATA => data.extend_from_slice(&wire[FrameHeader::LEN..end]),
                _ => panic!("unexpected frame"),
            }
            wire = &wire[end..];
        }
        assert_eq!(statuses, ["103", "200"]);
        assert_eq!(
            data,
            if credit == 0 {
                b"".as_slice()
            } else {
                b"ok".as_slice()
            }
        );
    }
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[test]
fn canonical_link_replays_and_preconnect_keeps_its_interim_block() {
    let mut encoder = Encoder::new();
    let mut decoder = Decoder::new(4096, 65536);
    let canonical = "</style.css>; rel=\"canonical\"";
    let preconnect = "<https://static.example>; rel=preconnect";
    let enabled =
        std::env::var_os("HJ_H2_HEADER_REPLAY").as_deref() != Some(std::ffi::OsStr::new("0"));
    let mut stream_id = 1;
    for with_hint in [false, true] {
        let mut headers = http::HeaderMap::new();
        headers.append(
            http::header::LINK,
            http::HeaderValue::from_static(canonical),
        );
        if with_hint {
            headers.append(
                http::header::LINK,
                http::HeaderValue::from_static(preconnect),
            );
        }
        let shared = Arc::new(headers);
        for _ in 0..3 {
            let mut response = http::Response::new(Body::Empty);
            response
                .extensions_mut()
                .insert(hj_core::SharedHeaders(shared.clone()));
            let mut out = OutQueue::default();
            let mut window = 65535;
            send::begin_response(
                stream_id,
                false,
                response,
                &mut encoder,
                &mut out,
                &mut FxHashMap::default(),
                &mut SendSchedule::default(),
                &mut FxHashMap::default(),
                &mut window,
                &PeerSettings::default(),
                &mut Vec::new(),
            );
            let mut wire = out.inline.as_slice();
            let mut statuses = Vec::new();
            while !wire.is_empty() {
                let frame = FrameHeader::parse(wire).unwrap();
                assert_eq!(frame.kind, frame::kind::HEADERS);
                assert_eq!(frame.stream_id, stream_id);
                assert_ne!(frame.flags & frame::flags::END_HEADERS, 0);
                let end = FrameHeader::LEN + frame.length as usize;
                let mut status = String::new();
                let mut links = Vec::new();
                decoder
                    .decode(&wire[FrameHeader::LEN..end], |n, v| match n {
                        ":status" => status = v.to_owned(),
                        "link" => links.push(v.to_owned()),
                        _ => {}
                    })
                    .unwrap();
                if status == "103" {
                    assert_eq!(links, [preconnect]);
                    assert_eq!(frame.flags & frame::flags::END_STREAM, 0);
                } else {
                    assert_eq!(status, "200");
                    let expected = if with_hint {
                        vec![canonical, preconnect]
                    } else {
                        vec![canonical]
                    };
                    assert_eq!(links, expected);
                    assert_ne!(frame.flags & frame::flags::END_STREAM, 0);
                }
                statuses.push(status);
                wire = &wire[end..];
            }
            let expected = if with_hint {
                vec!["103", "200"]
            } else {
                vec!["200"]
            };
            assert_eq!(statuses, expected);
            stream_id += 2;
        }
        assert_eq!(
            encoder.replay_shared_response(&shared).is_some(),
            enabled && !with_hint
        );
    }
}

fn prepare(body: Body) -> (OutQueue, FxHashMap<u32, OutStream>, SendSchedule, Events) {
    let events = Events::default();
    let copy = events.clone();
    let mut response = http::Response::new(body);
    response
        .extensions_mut()
        .insert(ResponseCompletion::new(move |end| {
            copy.lock().unwrap().push(end)
        }));
    let mut out = OutQueue::default();
    let mut streams = FxHashMap::default();
    let mut schedule = SendSchedule::default();
    let mut send_conn = 0i64;
    send::begin_response(
        1,
        false,
        response,
        &mut Encoder::new(),
        &mut out,
        &mut streams,
        &mut schedule,
        &mut FxHashMap::default(),
        &mut send_conn,
        &PeerSettings::default(),
        &mut Vec::new(),
    );
    (out, streams, schedule, events)
}

#[tokio::test]
async fn flow_control_retains_completion_until_final_flush() {
    let (mut out, mut streams, mut schedule, events) =
        prepare(Body::Full(Bytes::from_static(b"body")));
    streams.get_mut(&1).unwrap().window = 0;
    let mut credit = 4;
    send::pump_streams(
        &mut streams,
        &mut schedule,
        &mut out,
        &mut credit,
        &mut send::Pulls::new(),
        &PeerSettings::default(),
    );
    flush(&mut tokio::io::sink(), &mut out).await.unwrap();
    assert!(
        events.lock().unwrap().is_empty(),
        "headers are not full-response completion"
    );
    let stream = streams.get_mut(&1).unwrap();
    stream.window = 4;
    schedule.wake(1, stream);
    send::pump_streams(
        &mut streams,
        &mut schedule,
        &mut out,
        &mut credit,
        &mut send::Pulls::new(),
        &PeerSettings::default(),
    );
    assert!(streams.is_empty());
    assert!(
        events.lock().unwrap().is_empty(),
        "queued END_STREAM is not write completion"
    );
    flush(&mut tokio::io::sink(), &mut out).await.unwrap();
    assert_eq!(*events.lock().unwrap(), vec![ResponseEnd::Complete]);
}

#[tokio::test]
async fn headers_only_flush_failure_reports_error() {
    let (mut out, _, _, events) = prepare(Body::Empty);
    assert!(events.lock().unwrap().is_empty());
    let (mut writer, reader) = tokio::io::duplex(64);
    drop(reader);
    assert!(flush(&mut writer, &mut out).await.is_err());
    drop(out);
    assert_eq!(*events.lock().unwrap(), vec![ResponseEnd::Error]);
}

#[test]
fn reset_and_connection_drop_report_cancellation() {
    let (_, mut streams, _, events) = prepare(Body::Full(Bytes::from_static(b"body")));
    send::cancel_outstream(&mut streams, 1);
    assert_eq!(*events.lock().unwrap(), vec![ResponseEnd::Cancelled]);
    let (out, _, _, events) = prepare(Body::Empty);
    drop(out);
    assert_eq!(*events.lock().unwrap(), vec![ResponseEnd::Cancelled]);
}

#[tokio::test]
async fn uncached_file_retains_completion_until_eof_and_flush() {
    use futures_util::StreamExt;
    let path = std::env::temp_dir().join(format!(
        "hj-h2-completion-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(&path, b"file data").unwrap();
    let body = Body::File(hj_core::FileBody {
        path: path.clone(),
        file: None,
        len: 9,
        range: None,
        cached: None,
    });
    let (mut out, mut streams, mut schedule, events) = prepare(body);
    let mut credit = 100;
    let mut pulls = send::Pulls::new();
    while !streams.is_empty() {
        send::pump_streams(
            &mut streams,
            &mut schedule,
            &mut out,
            &mut credit,
            &mut pulls,
            &PeerSettings::default(),
        );
        assert!(events.lock().unwrap().is_empty());
        if !pulls.is_empty() {
            let (sid, body, chunk) =
                tokio::time::timeout(std::time::Duration::from_secs(2), pulls.next())
                    .await
                    .unwrap()
                    .unwrap();
            send::apply_pull(sid, body, chunk, &mut streams, &mut out, &mut schedule);
        }
    }
    flush(&mut tokio::io::sink(), &mut out).await.unwrap();
    assert_eq!(*events.lock().unwrap(), vec![ResponseEnd::Complete]);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn body_error_reports_error_once() {
    use http_body_util::BodyExt;
    let (mut out, mut streams, mut schedule, events) =
        prepare(Body::Full(Bytes::from_static(b"body")));
    let body = http_body_util::Empty::<Bytes>::new()
        .map_err(|e| -> hj_core::BoxError { match e {} })
        .boxed();
    send::apply_pull(
        1,
        body,
        Some(Err(std::io::Error::other("synthetic failure").into())),
        &mut streams,
        &mut out,
        &mut schedule,
    );
    drop(streams);
    drop(out);
    assert_eq!(*events.lock().unwrap(), vec![ResponseEnd::Error]);
}

#[cfg(feature = "monoio")]
#[test]
fn monoio_flush_completes_only_after_writing_final_batch() {
    use std::io::Read;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let client = std::thread::spawn(move || {
        let mut stream = std::net::TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        // Read the final HTTP/2 frame, not TCP EOF: monoio may defer socket
        // destruction until the runtime next polls its completion queue.
        let mut head = [0; crate::frame::FrameHeader::LEN];
        stream.read_exact(&mut head).unwrap();
        let frame = crate::frame::FrameHeader::parse(&head).unwrap();
        assert_ne!(frame.flags & crate::frame::flags::END_STREAM, 0);
        let mut payload = vec![0; frame.length as usize];
        stream.read_exact(&mut payload).unwrap();
    });
    let mut runtime = monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
        .enable_timer()
        .build()
        .unwrap();
    runtime.block_on(async {
        let listener = monoio::net::TcpListener::from_std(listener).unwrap();
        let (mut stream, _) = listener.accept().await.unwrap();
        let (mut out, _, _, events) = prepare(Body::Empty);
        assert!(events.lock().unwrap().is_empty());
        monoio_flush(&mut stream, &mut out, None).await.unwrap();
        assert_eq!(*events.lock().unwrap(), vec![ResponseEnd::Complete]);
    });
    client.join().unwrap();
}

#[test]
fn adjacent_inline_frames_share_one_segment() {
    let mut out = OutQueue::default();
    out.frames(|b| b.extend_from_slice(b"ab"));
    out.frames(|b| b.extend_from_slice(b"cd"));
    // Small bodies (<= 2 KiB) coalesce into the trailing inline segment.
    out.body(Bytes::from_static(b"tiny"));
    assert_eq!(out.segs.len(), 1);
    assert!(matches!(out.segs[0], Seg::Inline(0, 8)));
    // Bodies larger than the inline threshold remain zero-copy Seg::Body entries.
    let big = Bytes::from(vec![b'x'; 2049]);
    out.body(big);
    out.frames(|b| b.extend_from_slice(b"ef"));
    out.frames(|_| {});
    assert_eq!(out.segs.len(), 3);
    assert!(matches!(out.segs[0], Seg::Inline(0, 8)));
    assert!(matches!(out.segs[1], Seg::Body(_)));
    assert!(matches!(out.segs[2], Seg::Inline(8, 2)));
    assert_eq!(out.total_bytes(), 2059);
}

#[cfg(feature = "monoio")]
#[test]
fn monoio_flush_reuses_bounded_metadata_and_releases_bodies() {
    use std::io::Read;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TrackedBody(Arc<AtomicUsize>);
    impl AsRef<[u8]> for TrackedBody {
        fn as_ref(&self) -> &[u8] {
            b"one"
        }
    }
    impl Drop for TrackedBody {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    let over = RETAINED_FLUSH_METADATA + 1;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let client = std::thread::spawn(move || {
        let mut stream = std::net::TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let mut expected = b"HoneTHoneT".to_vec();
        expected.extend(std::iter::repeat_n(b'x', over));
        expected.extend(std::iter::repeat_n(b'y', 1025));
        let mut received = vec![0; expected.len()];
        stream.read_exact(&mut received).unwrap();
        assert_eq!(received, expected);
    });
    let mut runtime = monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
        .enable_timer()
        .build()
        .unwrap();
    runtime.block_on(async {
        let listener = monoio::net::TcpListener::from_std(listener).unwrap();
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut out = OutQueue::default();
        let dropped = Arc::new(AtomicUsize::new(0));
        let mut previous = None;
        for iteration in 1..=2 {
            out.frames(|b| b.extend_from_slice(b"H"));
            out.body(Bytes::from_owner(TrackedBody(dropped.clone())));
            out.frames(|b| b.extend_from_slice(b"T"));
            monoio_flush(&mut stream, &mut out, None).await.unwrap();
            assert_eq!(dropped.load(Ordering::Relaxed), iteration);
            assert!(out.is_empty() && out.write_backings.is_empty() && out.write_spans.is_empty());
            assert!(out.segs.capacity() > 0 && out.segs.capacity() <= RETAINED_FLUSH_METADATA);
            for capacity in [out.write_backings.capacity(), out.write_spans.capacity()] {
                assert!(capacity <= RETAINED_FLUSH_METADATA);
            }
            let storage = (
                out.segs.as_ptr(),
                out.write_backings.as_ptr(),
                out.write_spans.as_ptr(),
            );
            if let Some(previous) = previous {
                assert_eq!(
                    storage, previous,
                    "small flushes must reuse metadata storage"
                );
            }
            previous = Some(storage);
        }

        // Below IOV_MAX but above the retained allowance: delivered intact, and no
        // oversized metadata is kept afterwards.
        for _ in 0..over {
            out.segs.push(Seg::Body(Bytes::from_static(b"x")));
        }
        monoio_flush(&mut stream, &mut out, None).await.unwrap();
        assert_eq!(out.segs.capacity(), 0);
        assert_eq!(out.write_backings.capacity(), 0);
        assert_eq!(out.write_spans.capacity(), 0);

        // Above IOV_MAX takes the coalescing fallback under the same bound.
        for _ in 0..1025 {
            out.segs.push(Seg::Body(Bytes::from_static(b"y")));
        }
        monoio_flush(&mut stream, &mut out, None).await.unwrap();
        assert_eq!(out.segs.capacity(), 0);
    });
    client.join().unwrap();
}

// Additional borrowed-response wire regressions; deliberately use the existing sender
// and actual monoio connection loop instead of simulating frame-outcome handling.
mod borrowed_h2_wire_regressions {
    use super::*;

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn borrowed_h2_no_hint_replay_tracks_date_and_peer_table_changes() {
        let mut encoder = Encoder::new();
        let mut decoder = Decoder::new(4096, 65536);
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_static("0"),
        );
        headers.insert(
            http::header::DATE,
            http::HeaderValue::from_static("Wed, 25 Nov 2026 00:00:00 GMT"),
        );
        headers.insert(
            "x-borrowed-fixture",
            http::HeaderValue::from_static("retained"),
        );
        let mut shared = Arc::new(headers);
        let replay_enabled =
            std::env::var_os("HJ_H2_HEADER_REPLAY").as_deref() != Some(std::ffi::OsStr::new("0"));
        for (index, table_size) in [4096, 4096, 4096, 4096, 0, 0, 4096, 4096, 4096]
            .into_iter()
            .enumerate()
        {
            if index == 3 {
                // The encoder's Weak must make mutation invalidate the old replay
                // identity even when this is the only strong Arc reference.
                Arc::make_mut(&mut shared).insert(
                    http::header::DATE,
                    http::HeaderValue::from_static("Wed, 25 Nov 2026 00:00:01 GMT"),
                );
                assert!(encoder.replay_shared_response(&shared).is_none());
            }
            encoder.set_peer_max_size(table_size);
            let sid = 1 + 2 * index as u32;
            let mut out = OutQueue::default();
            let mut streams = FxHashMap::default();
            let mut window = 65535;
            send::begin_ready_response(
                sid,
                false,
                ReadyResponse::SharedFull(SharedFullResponse {
                    headers: shared.clone(),
                    body: Bytes::new(),
                }),
                &mut encoder,
                &mut out,
                &mut streams,
                &mut SendSchedule::default(),
                &mut FxHashMap::default(),
                &mut window,
                &PeerSettings::default(),
                &mut Vec::new(),
            );
            assert!(streams.is_empty());
            assert_eq!(window, 65535, "an empty response consumes no DATA credit");
            let header = FrameHeader::parse(&out.inline).unwrap();
            assert_eq!(header.kind, frame::kind::HEADERS);
            assert_eq!(header.stream_id, sid);
            assert_eq!(
                header.flags,
                frame::flags::END_HEADERS | frame::flags::END_STREAM
            );
            assert_eq!(
                out.inline.len(),
                FrameHeader::LEN + header.length as usize,
                "there is one final block, without an interim 103 or DATA"
            );
            let mut fields = Vec::new();
            decoder
                .decode(&out.inline[FrameHeader::LEN..], |name, value| {
                    fields.push((name.to_owned(), value.to_owned()));
                })
                .unwrap();
            assert_eq!(
                fields
                    .iter()
                    .filter(|(n, _)| n == ":status")
                    .map(|(_, v)| v.as_str())
                    .collect::<Vec<_>>(),
                ["200"]
            );
            assert_eq!(
                fields
                    .iter()
                    .find(|(n, _)| n == "content-length")
                    .unwrap()
                    .1,
                "0"
            );
            assert_eq!(
                fields
                    .iter()
                    .find(|(n, _)| n == "x-borrowed-fixture")
                    .unwrap()
                    .1,
                "retained"
            );
            assert_eq!(
                fields.iter().find(|(n, _)| n == "date").unwrap().1,
                if index < 3 {
                    "Wed, 25 Nov 2026 00:00:00 GMT"
                } else {
                    "Wed, 25 Nov 2026 00:00:01 GMT"
                }
            );
            assert!(!fields.iter().any(|(n, _)| n == "link"));
            if index == 2 || index == 8 {
                assert_eq!(
                    encoder.replay_shared_response(&shared).is_some(),
                    replay_enabled,
                    "the no-hint stable borrowed response must reach header replay"
                );
            }
        }
    }

    #[cfg(feature = "monoio")]
    fn visible_frame(stream: &mut std::net::TcpStream) -> (FrameHeader, Vec<u8>) {
        use std::io::{Read, Write};
        loop {
            let mut bytes = [0; FrameHeader::LEN];
            stream.read_exact(&mut bytes).unwrap();
            let header = FrameHeader::parse(&bytes).unwrap();
            let mut payload = vec![0; header.length as usize];
            stream.read_exact(&mut payload).unwrap();
            if header.kind == frame::kind::SETTINGS {
                if header.flags & frame::flags::ACK == 0 {
                    let mut ack = Vec::new();
                    frame::write_settings_ack(&mut ack);
                    stream.write_all(&ack).unwrap();
                }
                continue;
            }
            if header.kind == frame::kind::WINDOW_UPDATE && header.stream_id == 0 {
                continue; // Server grants request-side credit; no body is uploaded.
            }
            assert_ne!(
                header.kind,
                frame::kind::GOAWAY,
                "unexpected GOAWAY: {payload:?}"
            );
            assert_ne!(
                header.kind,
                frame::kind::RST_STREAM,
                "unexpected RST: {payload:?}"
            );
            return (header, payload);
        }
    }

    #[cfg(feature = "monoio")]
    fn final_head(stream: &mut std::net::TcpStream, decoder: &mut Decoder, sid: u32, ended: bool) {
        let (header, payload) = visible_frame(stream);
        assert_eq!((header.kind, header.stream_id), (frame::kind::HEADERS, sid));
        assert_ne!(header.flags & frame::flags::END_HEADERS, 0);
        assert_eq!(header.flags & frame::flags::END_STREAM != 0, ended);
        let mut statuses = Vec::new();
        decoder
            .decode(&payload, |name, value| {
                if name == ":status" {
                    statuses.push(value.to_owned());
                }
            })
            .unwrap();
        assert_eq!(statuses, ["200"]);
    }

    #[cfg(feature = "monoio")]
    fn ping_without_data(stream: &mut std::net::TcpStream, value: u8) {
        use std::io::Write;
        let mut bytes = Vec::new();
        frame::write_frame(&mut bytes, frame::kind::PING, 0, 0, &[value; 8]);
        stream.write_all(&bytes).unwrap();
        let (header, payload) = visible_frame(stream);
        assert_eq!(
            (header.kind, header.stream_id, header.flags),
            (frame::kind::PING, 0, frame::flags::ACK),
            "no DATA may pass the flow-control/reset barrier"
        );
        assert_eq!(payload, [value; 8]);
    }

    #[cfg(feature = "monoio")]
    #[test]
    fn borrowed_h2_native_windows_resume_and_received_reset_cancel_bulk() {
        use std::io::Write;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;
        // The optional spare-core dispatch deliberately omits this synchronous hook.
        let _occupied: Vec<_> = (0..worker_count()).map(|_| ConnGuard::new()).collect();
        let calls = Arc::new(AtomicUsize::new(0));
        let hits = Arc::new(AtomicUsize::new(0));
        let body: Vec<u8> = (0..98304).map(|i| (i % 251) as u8).collect();
        let expected = body.clone();
        let body = Bytes::from(body);
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_static("98304"),
        );
        let headers = Arc::new(headers);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let client = std::thread::spawn(move || {
            let mut stream = std::net::TcpStream::connect(address).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut wire = crate::conn::PREFACE.to_vec();
            frame::write_settings(&mut wire, &[(frame::settings::INITIAL_WINDOW_SIZE, 0)]);
            stream.write_all(&wire).unwrap();
            let mut decoder = Decoder::new(4096, 65536);
            // Literal-without-indexing fields keep the HPACK table unchanged; the
            // exact same complete GET head is used for both warmups and both hits.
            let block = b"\x82\x87\x04\x05/bulk\x01\x0bfirst.local";
            for sid in [1, 3, 5] {
                let mut bytes = Vec::new();
                frame::write_frame(
                    &mut bytes,
                    frame::kind::HEADERS,
                    frame::flags::END_HEADERS | frame::flags::END_STREAM,
                    sid,
                    block,
                );
                stream.write_all(&bytes).unwrap();
                final_head(&mut stream, &mut decoder, sid, sid != 5);
            }
            ping_without_data(&mut stream, 1); // Stream 5 has zero stream credit.
            let mut grant = Vec::new();
            frame::write_window_update(&mut grant, 5, 65535);
            stream.write_all(&grant).unwrap();
            let mut received = Vec::new();
            while received.len() < 65535 {
                let (header, payload) = visible_frame(&mut stream);
                assert_eq!((header.kind, header.stream_id), (frame::kind::DATA, 5));
                assert!(header.length > 0 && header.length <= 16384);
                assert_eq!(header.flags & frame::flags::END_STREAM, 0);
                received.extend_from_slice(&payload);
            }
            assert_eq!(received.len(), 65535);
            assert_eq!(received, expected[..65535]);
            // Stream credit alone cannot release more DATA after consuming the
            // connection's original 65535 bytes of credit.
            grant.clear();
            frame::write_window_update(&mut grant, 5, 32769);
            stream.write_all(&grant).unwrap();
            ping_without_data(&mut stream, 2);
            grant.clear();
            frame::write_window_update(&mut grant, 0, 32769);
            stream.write_all(&grant).unwrap();
            while received.len() < expected.len() {
                let (header, payload) = visible_frame(&mut stream);
                assert_eq!((header.kind, header.stream_id), (frame::kind::DATA, 5));
                assert!(header.length > 0 && header.length <= 16384);
                received.extend_from_slice(&payload);
                assert_eq!(
                    header.flags & frame::flags::END_STREAM != 0,
                    received.len() == expected.len(),
                    "END_STREAM belongs to the exact final byte"
                );
            }
            assert_eq!(received, expected);
            // A second actual borrowed response is reset after one full DATA
            // frame, while both windows are exhausted and a large tail remains.
            wire.clear();
            frame::write_frame(
                &mut wire,
                frame::kind::HEADERS,
                frame::flags::END_HEADERS | frame::flags::END_STREAM,
                7,
                block,
            );
            stream.write_all(&wire).unwrap();
            final_head(&mut stream, &mut decoder, 7, false);
            ping_without_data(&mut stream, 3);
            grant.clear();
            frame::write_window_update(&mut grant, 0, 16384);
            frame::write_window_update(&mut grant, 7, 16384);
            stream.write_all(&grant).unwrap();
            let (header, payload) = visible_frame(&mut stream);
            assert_eq!(
                (header.kind, header.stream_id, header.length),
                (frame::kind::DATA, 7, 16384)
            );
            assert_eq!(header.flags & frame::flags::END_STREAM, 0);
            assert_eq!(payload, expected[..16384]);
            grant.clear();
            frame::write_rst_stream(&mut grant, 7, frame::error_code::CANCEL);
            frame::write_window_update(&mut grant, 0, 98304);
            frame::write_window_update(&mut grant, 7, 98304);
            stream.write_all(&grant).unwrap();
            ping_without_data(&mut stream, 4); // New credit cannot revive the reset tail.
            wire.clear();
            frame::write_frame(
                &mut wire,
                frame::kind::HEADERS,
                frame::flags::END_HEADERS | frame::flags::END_STREAM,
                9,
                b"\x82\x87\x04\x06/after\x01\x0bfirst.local",
            );
            stream.write_all(&wire).unwrap();
            final_head(&mut stream, &mut decoder, 9, true);
            stream.shutdown(std::net::Shutdown::Both).unwrap();
        });
        let probe_hits = hits.clone();
        let service_calls = calls.clone();
        let mut runtime = monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
            .enable_timer()
            .build()
            .unwrap();
        let result = runtime.block_on(async move {
            let listener = monoio::net::TcpListener::from_std(listener).unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            let config = Config {
                conn_idle_timeout: Some(Duration::from_secs(2)),
                borrowed_memo_probe: Some(BorrowedMemoProbe(Arc::new(move |head| {
                    if head.uri.path() != "/bulk" {
                        return None;
                    }
                    assert_eq!(head.headers[http::header::HOST], "first.local");
                    probe_hits.fetch_add(1, Ordering::Relaxed);
                    Some(SharedFullResponse {
                        headers: headers.clone(),
                        body: body.clone(),
                    })
                }))),
                ..Config::default()
            };
            serve_local_with_prefix(
                stream,
                Vec::new(),
                move |_request: Request| {
                    service_calls.fetch_add(1, Ordering::Relaxed);
                    std::future::ready(Response::new(Body::Empty))
                },
                config,
                None,
                None,
            )
            .await
        });
        client.join().unwrap();
        assert!(
            result.is_ok(),
            "native H2 connection must close cleanly: {result:?}"
        );
        assert_eq!(
            hits.load(Ordering::Relaxed),
            2,
            "both bulk responses must use the borrowed hook"
        );
        assert_eq!(
            calls.load(Ordering::Relaxed),
            3,
            "only the two warmups and /after use the handler"
        );
    }
}
