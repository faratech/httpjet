//! Deterministic, socket-free replay of the same invariants used by libFuzzer.
use httpjet::codec;
#[path = "../../../fuzz/h1_properties.rs"]
mod properties;

fn replay(text: &str, check: fn(&[u8])) -> usize {
    let mut cases = 0;
    for (line_no, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut bytes = Vec::new();
        if line != "-" {
            assert_eq!(line.len() % 2, 0, "invalid seed line {}", line_no + 1);
            assert!(line.is_ascii());
            for offset in (0..line.len()).step_by(2) {
                bytes.push(u8::from_str_radix(&line[offset..offset + 2], 16).unwrap());
            }
        }
        assert!(bytes.len() <= 4096, "keep deterministic replay bounded");
        check(&bytes);
        cases += 1;
        // Replay every truncation and single-byte mutation, preserving malformed
        // framing boundaries in normal stable-Rust CI without a fuzz runtime.
        for end in 0..bytes.len() {
            check(&bytes[..end]);
            cases += 1;
        }
        for offset in 0..bytes.len() {
            let saved = bytes[offset];
            for value in [0, b'\r', b'\n', b':', b'0', b'9', 255] {
                bytes[offset] = value;
                check(&bytes);
                cases += 1;
            }
            bytes[offset] = saved;
        }
    }
    assert!(cases > 100, "empty or unexpectedly sparse corpus");
    cases
}

#[test]
fn h1_chunked_corpus_replay() {
    let count = replay(
        include_str!("../../../fuzz/seeds/h1_chunked_decode.hex"),
        properties::h1_chunked_decode,
    );
    eprintln!("replayed {count} chunked cases");
}

#[test]
fn h1_framing_corpus_replay() {
    let count = replay(
        include_str!("../../../fuzz/seeds/h1_request_framing.hex"),
        properties::h1_request_framing,
    );
    eprintln!("replayed {count} framing cases");
}
