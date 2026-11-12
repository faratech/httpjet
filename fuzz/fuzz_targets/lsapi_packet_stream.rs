//! Fuzz the production LSAPI packet reader (the one that parses every lsphp
//! response) on a whole packet stream. The packets it yields must not depend on how
//! the bytes were split across socket reads, and must be the packets the reference
//! codec (`LsapiCodec`) decodes from the same bytes.
#![no_main]

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use tokio_util::codec::Decoder;

thread_local! {
    static RUNTIME: tokio::runtime::Runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .expect("runtime");
}

type Packets = (Vec<(u8, u8, Vec<u8>)>, bool);

fn read(chunks: Vec<Vec<u8>>) -> Packets {
    RUNTIME.with(|runtime| runtime.block_on(hj_lsapi::handler::fuzz_read_packets(chunks)))
}

fuzz_target!(|data: &[u8]| {
    let Some((&split, wire)) = data.split_first() else {
        return;
    };
    let whole = read(vec![wire.to_vec()]);
    let step = usize::from(split % 32) + 1;
    let pieces = read(wire.chunks(step).map(<[u8]>::to_vec).collect());
    assert_eq!(whole, pieces, "packets depend on how the bytes arrived");

    let mut codec = hj_lsapi::proto::LsapiCodec::new();
    let mut buffer = BytesMut::from(wire);
    let mut decoded = Vec::new();
    let mut failed = false;
    loop {
        match codec.decode(&mut buffer) {
            Ok(Some(frame)) => decoded.push((frame.ptype as u8, frame.flag, frame.body.to_vec())),
            // The codec leaves a partial packet buffered; the reader, which sees the end
            // of the stream, reports it as truncated.
            Ok(None) => {
                failed = !buffer.is_empty();
                break;
            }
            Err(_) => {
                failed = true;
                break;
            }
        }
    }
    assert_eq!(
        whole.0, decoded,
        "the reader and the codec disagree on the packets"
    );
    assert_eq!(
        whole.1, failed,
        "the reader and the codec disagree on rejecting the stream"
    );
});
