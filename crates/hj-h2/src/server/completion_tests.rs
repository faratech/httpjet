use super::*;
use hj_core::{Body, ResponseCompletion, ResponseEnd};
use std::sync::{Arc, Mutex};

type Events = Arc<Mutex<Vec<ResponseEnd>>>;
fn prepare(body: Body) -> (OutQueue, FxHashMap<u32, OutStream>, VecDeque<u32>, Events) {
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
    let mut schedule = VecDeque::new();
    send::begin_response(
        1,
        false,
        response,
        &mut Encoder::new(),
        &mut out,
        &mut streams,
        &mut schedule,
        &mut FxHashMap::default(),
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
    streams.get_mut(&1).unwrap().window = 4;
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
            send::apply_pull(sid, body, chunk, &mut streams, &mut out);
        }
    }
    flush(&mut tokio::io::sink(), &mut out).await.unwrap();
    assert_eq!(*events.lock().unwrap(), vec![ResponseEnd::Complete]);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn body_error_reports_error_once() {
    use http_body_util::BodyExt;
    let (mut out, mut streams, _, events) = prepare(Body::Full(Bytes::from_static(b"body")));
    let body = http_body_util::Empty::<Bytes>::new()
        .map_err(|e| -> hj_core::BoxError { match e {} })
        .boxed();
    send::apply_pull(
        1,
        body,
        Some(Err(std::io::Error::other("synthetic failure").into())),
        &mut streams,
        &mut out,
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
    out.body(Bytes::from_static(b"body"));
    out.frames(|b| b.extend_from_slice(b"ef"));
    out.frames(|_| {});
    assert_eq!(out.segs.len(), 3);
    assert!(matches!(out.segs[0], Seg::Inline(0, 4)));
    assert!(matches!(out.segs[1], Seg::Body(_)));
    assert!(matches!(out.segs[2], Seg::Inline(4, 2)));
    assert_eq!(out.total_bytes(), 10);
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
            for capacity in [
                out.segs.capacity(),
                out.write_backings.capacity(),
                out.write_spans.capacity(),
            ] {
                assert!(capacity > 0 && capacity <= RETAINED_FLUSH_METADATA);
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
            out.body(Bytes::from_static(b"x"));
        }
        monoio_flush(&mut stream, &mut out, None).await.unwrap();
        assert_eq!(out.segs.capacity(), 0);
        assert_eq!(out.write_backings.capacity(), 0);
        assert_eq!(out.write_spans.capacity(), 0);

        // Above IOV_MAX takes the coalescing fallback under the same bound.
        for _ in 0..1025 {
            out.body(Bytes::from_static(b"y"));
        }
        monoio_flush(&mut stream, &mut out, None).await.unwrap();
        assert_eq!(out.segs.capacity(), 0);
    });
    client.join().unwrap();
}
