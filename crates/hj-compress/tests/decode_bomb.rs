use hj_compress::{Encoding, Levels, MAX_DECODE, decode_bytes, encode_bytes};

/// Build a highly compressible payload that decodes to more than MAX_DECODE
/// bytes and verify decode_bytes returns None rather than allocating the full
/// expansion.
///
/// We construct the bomb by compressing a buffer of zeros whose uncompressed
/// size exceeds MAX_DECODE. The compressed form is tiny; a decode without a
/// cap would allocate the full expansion.
fn make_bomb(enc: Encoding) -> Vec<u8> {
    // (MAX_DECODE + 1) zeros compresses to a tiny stream but expands past cap.
    let zeros = vec![0u8; (MAX_DECODE + 1) as usize];
    encode_bytes(enc, &zeros, &Levels::default()).expect("encode bomb")
}

#[test]
fn gzip_bomb_returns_none() {
    let bomb = make_bomb(Encoding::Gzip);
    // The compressed form is small but expands past MAX_DECODE.
    assert!(
        bomb.len() < (MAX_DECODE / 100) as usize,
        "bomb should be much smaller than MAX_DECODE compressed"
    );
    let result = decode_bytes(Encoding::Gzip, &bomb);
    assert!(
        result.is_none(),
        "gzip bomb must return None, not allocate {MAX_DECODE}+ bytes"
    );
}

#[test]
fn zstd_bomb_returns_none() {
    let bomb = make_bomb(Encoding::Zstd);
    let result = decode_bytes(Encoding::Zstd, &bomb);
    assert!(result.is_none(), "zstd bomb must return None");
}

#[test]
fn brotli_bomb_returns_none() {
    let bomb = make_bomb(Encoding::Brotli);
    let result = decode_bytes(Encoding::Brotli, &bomb);
    assert!(result.is_none(), "brotli bomb must return None");
}

/// Normal content well below MAX_DECODE must still decode successfully.
#[test]
fn normal_decode_still_works() {
    let data = b"normal page content ".repeat(100); // ~2 KiB
    let lv = Levels::default();
    for enc in [Encoding::Gzip, Encoding::Brotli, Encoding::Zstd] {
        let encoded = encode_bytes(enc, &data, &lv).expect("encode");
        let decoded = decode_bytes(enc, &encoded).expect("decode normal");
        assert_eq!(decoded, data, "{:?} normal round-trip failed", enc);
    }
}

/// Malformed (random) input still returns None without panicking.
#[test]
fn malformed_input_returns_none() {
    let garbage = b"this is not a valid compressed stream at all...";
    assert!(decode_bytes(Encoding::Gzip, garbage).is_none());
    assert!(decode_bytes(Encoding::Zstd, garbage).is_none());
    assert!(decode_bytes(Encoding::Brotli, garbage).is_none());
}
