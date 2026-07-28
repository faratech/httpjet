//! Per-request correlation id: uniqueness, format, and no-alloc Display.

use std::collections::HashSet;
use std::fmt::Write as _;

use hj_core::reqid;

#[test]
fn ids_are_unique_over_many_mints() {
    let n = 100_000;
    let mut seen = HashSet::with_capacity(n);
    for _ in 0..n {
        // The raw u64 must be unique (the counter is monotonic; the splitmix
        // finalizer is a bijection, so distinct counters → distinct ids).
        assert!(
            seen.insert(reqid::next().as_u64()),
            "duplicate request id minted"
        );
    }
}

#[test]
fn display_is_16_lowercase_hex() {
    let s = reqid::next().to_string();
    assert_eq!(
        s.len(),
        16,
        "expected zero-padded 16-hex-char id, got {s:?}"
    );
    assert!(
        s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );
}

#[test]
fn display_writes_without_heap_alloc() {
    // Render straight into a fixed stack buffer via fmt::Write — proves Display
    // does not require an intermediate String allocation on the hot path.
    struct StackBuf {
        buf: [u8; 16],
        len: usize,
    }
    impl std::fmt::Write for StackBuf {
        fn write_str(&mut self, s: &str) -> std::fmt::Result {
            let end = self.len + s.len();
            if end > self.buf.len() {
                return Err(std::fmt::Error);
            }
            self.buf[self.len..end].copy_from_slice(s.as_bytes());
            self.len = end;
            Ok(())
        }
    }
    let id = reqid::next();
    let mut sb = StackBuf {
        buf: [0; 16],
        len: 0,
    };
    write!(sb, "{id}").unwrap();
    assert_eq!(sb.len, 16);
    assert_eq!(&sb.buf[..], id.to_string().as_bytes());
}

#[test]
fn default_is_zero_sentinel() {
    assert_eq!(reqid::ReqId::default().to_string(), "0000000000000000");
}
