//! HPACK Huffman coding (RFC 7541 §5.2 + Appendix B).
//!
//! The canonical static Huffman code from Appendix B. [`encode`] appends the
//! bit-packed code for each byte and pads the final octet with 1-bits (the EOS
//! prefix), per §5.2. [`decode`] walks the bitstream against the code table.
//! [`encoded_len`] lets the caller choose Huffman only when it is actually smaller
//! than the raw literal (matching what compliant encoders do).

/// `(code, bit_length)` for symbols 0..=255 then EOS (index 256). From RFC 7541
/// Appendix B.
pub(crate) static TABLE: [(u32, u8); 257] = [
    (0x1ff8, 13),
    (0x7fffd8, 23),
    (0xfffffe2, 28),
    (0xfffffe3, 28),
    (0xfffffe4, 28),
    (0xfffffe5, 28),
    (0xfffffe6, 28),
    (0xfffffe7, 28),
    (0xfffffe8, 28),
    (0xffffea, 24),
    (0x3ffffffc, 30),
    (0xfffffe9, 28),
    (0xfffffea, 28),
    (0x3ffffffd, 30),
    (0xfffffeb, 28),
    (0xfffffec, 28),
    (0xfffffed, 28),
    (0xfffffee, 28),
    (0xfffffef, 28),
    (0xffffff0, 28),
    (0xffffff1, 28),
    (0xffffff2, 28),
    (0x3ffffffe, 30),
    (0xffffff3, 28),
    (0xffffff4, 28),
    (0xffffff5, 28),
    (0xffffff6, 28),
    (0xffffff7, 28),
    (0xffffff8, 28),
    (0xffffff9, 28),
    (0xffffffa, 28),
    (0xffffffb, 28),
    (0x14, 6),
    (0x3f8, 10),
    (0x3f9, 10),
    (0xffa, 12),
    (0x1ff9, 13),
    (0x15, 6),
    (0xf8, 8),
    (0x7fa, 11),
    (0x3fa, 10),
    (0x3fb, 10),
    (0xf9, 8),
    (0x7fb, 11),
    (0xfa, 8),
    (0x16, 6),
    (0x17, 6),
    (0x18, 6),
    (0x0, 5),
    (0x1, 5),
    (0x2, 5),
    (0x19, 6),
    (0x1a, 6),
    (0x1b, 6),
    (0x1c, 6),
    (0x1d, 6),
    (0x1e, 6),
    (0x1f, 6),
    (0x5c, 7),
    (0xfb, 8),
    (0x7ffc, 15),
    (0x20, 6),
    (0xffb, 12),
    (0x3fc, 10),
    (0x1ffa, 13),
    (0x21, 6),
    (0x5d, 7),
    (0x5e, 7),
    (0x5f, 7),
    (0x60, 7),
    (0x61, 7),
    (0x62, 7),
    (0x63, 7),
    (0x64, 7),
    (0x65, 7),
    (0x66, 7),
    (0x67, 7),
    (0x68, 7),
    (0x69, 7),
    (0x6a, 7),
    (0x6b, 7),
    (0x6c, 7),
    (0x6d, 7),
    (0x6e, 7),
    (0x6f, 7),
    (0x70, 7),
    (0x71, 7),
    (0x72, 7),
    (0xfc, 8),
    (0x73, 7),
    (0xfd, 8),
    (0x1ffb, 13),
    (0x7fff0, 19),
    (0x1ffc, 13),
    (0x3ffc, 14),
    (0x22, 6),
    (0x7ffd, 15),
    (0x3, 5),
    (0x23, 6),
    (0x4, 5),
    (0x24, 6),
    (0x5, 5),
    (0x25, 6),
    (0x26, 6),
    (0x27, 6),
    (0x6, 5),
    (0x74, 7),
    (0x75, 7),
    (0x28, 6),
    (0x29, 6),
    (0x2a, 6),
    (0x7, 5),
    (0x2b, 6),
    (0x76, 7),
    (0x2c, 6),
    (0x8, 5),
    (0x9, 5),
    (0x2d, 6),
    (0x77, 7),
    (0x78, 7),
    (0x79, 7),
    (0x7a, 7),
    (0x7b, 7),
    (0x7ffe, 15),
    (0x7fc, 11),
    (0x3ffd, 14),
    (0x1ffd, 13),
    (0xffffffc, 28),
    (0xfffe6, 20),
    (0x3fffd2, 22),
    (0xfffe7, 20),
    (0xfffe8, 20),
    (0x3fffd3, 22),
    (0x3fffd4, 22),
    (0x3fffd5, 22),
    (0x7fffd9, 23),
    (0x3fffd6, 22),
    (0x7fffda, 23),
    (0x7fffdb, 23),
    (0x7fffdc, 23),
    (0x7fffdd, 23),
    (0x7fffde, 23),
    (0xffffeb, 24),
    (0x7fffdf, 23),
    (0xffffec, 24),
    (0xffffed, 24),
    (0x3fffd7, 22),
    (0x7fffe0, 23),
    (0xffffee, 24),
    (0x7fffe1, 23),
    (0x7fffe2, 23),
    (0x7fffe3, 23),
    (0x7fffe4, 23),
    (0x1fffdc, 21),
    (0x3fffd8, 22),
    (0x7fffe5, 23),
    (0x3fffd9, 22),
    (0x7fffe6, 23),
    (0x7fffe7, 23),
    (0xffffef, 24),
    (0x3fffda, 22),
    (0x1fffdd, 21),
    (0xfffe9, 20),
    (0x3fffdb, 22),
    (0x3fffdc, 22),
    (0x7fffe8, 23),
    (0x7fffe9, 23),
    (0x1fffde, 21),
    (0x7fffea, 23),
    (0x3fffdd, 22),
    (0x3fffde, 22),
    (0xfffff0, 24),
    (0x1fffdf, 21),
    (0x3fffdf, 22),
    (0x7fffeb, 23),
    (0x7fffec, 23),
    (0x1fffe0, 21),
    (0x1fffe1, 21),
    (0x3fffe0, 22),
    (0x1fffe2, 21),
    (0x7fffed, 23),
    (0x3fffe1, 22),
    (0x7fffee, 23),
    (0x7fffef, 23),
    (0xfffea, 20),
    (0x3fffe2, 22),
    (0x3fffe3, 22),
    (0x3fffe4, 22),
    (0x7ffff0, 23),
    (0x3fffe5, 22),
    (0x3fffe6, 22),
    (0x7ffff1, 23),
    (0x3ffffe0, 26),
    (0x3ffffe1, 26),
    (0xfffeb, 20),
    (0x7fff1, 19),
    (0x3fffe7, 22),
    (0x7ffff2, 23),
    (0x3fffe8, 22),
    (0x1ffffec, 25),
    (0x3ffffe2, 26),
    (0x3ffffe3, 26),
    (0x3ffffe4, 26),
    (0x7ffffde, 27),
    (0x7ffffdf, 27),
    (0x3ffffe5, 26),
    (0xfffff1, 24),
    (0x1ffffed, 25),
    (0x7fff2, 19),
    (0x1fffe3, 21),
    (0x3ffffe6, 26),
    (0x7ffffe0, 27),
    (0x7ffffe1, 27),
    (0x3ffffe7, 26),
    (0x7ffffe2, 27),
    (0xfffff2, 24),
    (0x1fffe4, 21),
    (0x1fffe5, 21),
    (0x3ffffe8, 26),
    (0x3ffffe9, 26),
    (0xffffffd, 28),
    (0x7ffffe3, 27),
    (0x7ffffe4, 27),
    (0x7ffffe5, 27),
    (0xfffec, 20),
    (0xfffff3, 24),
    (0xfffed, 20),
    (0x1fffe6, 21),
    (0x3fffe9, 22),
    (0x1fffe7, 21),
    (0x1fffe8, 21),
    (0x7ffff3, 23),
    (0x3fffea, 22),
    (0x3fffeb, 22),
    (0x1ffffee, 25),
    (0x1ffffef, 25),
    (0xfffff4, 24),
    (0xfffff5, 24),
    (0x3ffffea, 26),
    (0x7ffff4, 23),
    (0x3ffffeb, 26),
    (0x7ffffe6, 27),
    (0x3ffffec, 26),
    (0x3ffffed, 26),
    (0x7ffffe7, 27),
    (0x7ffffe8, 27),
    (0x7ffffe9, 27),
    (0x7ffffea, 27),
    (0x7ffffeb, 27),
    (0xffffffe, 28),
    (0x7ffffec, 27),
    (0x7ffffed, 27),
    (0x7ffffee, 27),
    (0x7ffffef, 27),
    (0x7fffff0, 27),
    (0x3ffffee, 26),
    (0x3fffffff, 30),
];

/// Number of octets `data` would occupy Huffman-encoded (RFC 7541 §5.2 padding).
pub(crate) fn encoded_len(data: &[u8]) -> usize {
    let bits: usize = data.iter().map(|&b| TABLE[b as usize].1 as usize).sum();
    bits.div_ceil(8)
}

/// Append the Huffman encoding of `data` to `out`, padding the last octet with the
/// EOS prefix (1-bits).
pub fn encode(out: &mut Vec<u8>, data: &[u8]) {
    let mut acc: u64 = 0;
    let mut nbits: u32 = 0;
    for &b in data {
        let (code, len) = TABLE[b as usize];
        acc = (acc << len) | code as u64;
        nbits += len as u32;
        while nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    if nbits > 0 {
        // Pad the remaining bits with 1s (the most-significant bits of EOS).
        let pad = 8 - nbits;
        acc = (acc << pad) | ((1u64 << pad) - 1);
        out.push(acc as u8);
    }
}

/// Root lookup width. A `2^ROOT_BITS` table resolves any code ≤ ROOT_BITS bits in a
/// single indexed read; all HTTP header characters that matter use ≤ 13-bit codes, so
/// the slow path (codes 17..=30 bits, for rare control/high bytes) is almost never hit.
const ROOT_BITS: u32 = 16;

/// `(symbol, code_len)` indexed by the next ROOT_BITS bits; `len == 0` means "no code
/// of length ≤ ROOT_BITS has this prefix" (a long code or padding). Built once.
fn decode_table() -> &'static [(u16, u8)] {
    static T: std::sync::OnceLock<Vec<(u16, u8)>> = std::sync::OnceLock::new();
    T.get_or_init(|| {
        let mut t = vec![(0u16, 0u8); 1usize << ROOT_BITS];
        for (sym, &(code, len)) in TABLE.iter().enumerate() {
            let len = len as u32;
            if sym == 256 || len > ROOT_BITS {
                continue; // EOS is never emitted; long codes use the slow path
            }
            // Left-align the code and fill every index sharing this prefix.
            let base = (code << (ROOT_BITS - len)) as usize;
            for slot in &mut t[base..base + (1usize << (ROOT_BITS - len))] {
                *slot = (sym as u16, len as u8);
            }
        }
        t
    })
}

/// Decode a complete Huffman bitstream (table-driven). Returns `None` on an invalid
/// code or invalid trailing padding (RFC 7541 §5.2).
pub fn decode(data: &[u8]) -> Option<Vec<u8>> {
    decode_limited(data, usize::MAX)
}

/// Decode while refusing to produce more than `max_output` bytes. This lets callers
/// enforce a decoded field-section limit before a compact Huffman literal expands into
/// a large allocation.
pub fn decode_limited(data: &[u8], max_output: usize) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    decode_into_limited(&mut out, data, max_output)?;
    Some(out)
}

/// Decode into a caller-provided buffer (cleared first), so the HPACK decode loop can reuse one
/// per-connection scratch across Huffman-coded header strings instead of allocating a fresh `Vec`
/// per field. Byte-identical to [`decode`]; on a decode error the caller treats the whole block as
/// fatal, so the buffer's (possibly partial) contents are never read.
pub(crate) fn decode_into(out: &mut Vec<u8>, data: &[u8]) -> Option<()> {
    decode_into_limited(out, data, usize::MAX)
}

fn decode_into_limited(out: &mut Vec<u8>, data: &[u8], max_output: usize) -> Option<()> {
    out.clear();
    let t = decode_table();
    let mask = (1u64 << ROOT_BITS) - 1;
    let estimate = (data.len().saturating_mul(8) / 5).saturating_add(1);
    out.reserve(estimate.min(max_output));
    let mut acc: u64 = 0;
    let mut nbits: u32 = 0;
    let mut i = 0;

    loop {
        // Keep enough bits buffered to resolve even the longest (30-bit) code, while
        // staying within u64 (cap at 56 so the next `<<8` never overflows).
        while nbits <= 48 && i < data.len() {
            acc = (acc << 8) | data[i] as u64;
            i += 1;
            nbits += 8;
        }
        if nbits == 0 {
            break;
        }
        // Form a ROOT_BITS window, padding the tail with 1-bits (the EOS prefix) when
        // fewer than ROOT_BITS real bits remain.
        let window = if nbits >= ROOT_BITS {
            ((acc >> (nbits - ROOT_BITS)) & mask) as usize
        } else {
            (((acc << (ROOT_BITS - nbits)) | ((1u64 << (ROOT_BITS - nbits)) - 1)) & mask) as usize
        };
        let (sym, len) = t[window];
        if len != 0 {
            let len = len as u32;
            if len > nbits {
                break; // the matched prefix was padding, not a real code -> done
            }
            if out.len() == max_output {
                return None;
            }
            out.push(sym as u8);
            nbits -= len;
        } else if nbits < ROOT_BITS {
            break; // no full code and out of input -> remaining bits are padding
        } else {
            // A code longer than ROOT_BITS (rare). Resolve it bit-exactly.
            let (sym, len) = decode_long(acc, nbits)?;
            if sym == 256 {
                return None;
            }
            if out.len() == max_output {
                return None;
            }
            out.push(sym as u8);
            nbits -= len;
        }
    }

    // Trailing padding must be ≤7 bits and all-1s (a prefix of EOS).
    if nbits > 7 {
        return None;
    }
    if nbits > 0 {
        let pad = acc & ((1u64 << nbits) - 1);
        if pad != (1u64 << nbits) - 1 {
            return None;
        }
    }
    Some(())
}

/// Long codes (length `ROOT_BITS+1..=30`) grouped by bit-length, each group sorted by code,
/// so [`decode_long`] binary-searches (O(log n)) instead of linear-scanning the whole 257-entry
/// `TABLE` once per candidate length. The old nested scan was O(162 symbols × 14 lengths) per
/// long symbol; a crafted all-long-code header block (RFC-conformant input) turned that into a
/// ~60× HPACK-decode CPU amplification that head-of-line-blocks every stream on the connection.
/// Index = `code_len - (ROOT_BITS + 1)`. EOS (sym 256) is intentionally INCLUDED so a literal EOS
/// in the data resolves to 256 and is rejected by the caller, matching the old scan. Built once.
fn long_table() -> &'static [Vec<(u32, u16)>] {
    static T: std::sync::OnceLock<Vec<Vec<(u32, u16)>>> = std::sync::OnceLock::new();
    T.get_or_init(|| {
        let groups_n = (30 - ROOT_BITS) as usize; // lengths ROOT_BITS+1 ..= 30
        let mut groups: Vec<Vec<(u32, u16)>> = vec![Vec::new(); groups_n];
        for (sym, &(code, len)) in TABLE.iter().enumerate() {
            let len = len as u32;
            if len <= ROOT_BITS {
                continue; // resolved by the root table
            }
            groups[(len - ROOT_BITS - 1) as usize].push((code, sym as u16));
        }
        // Huffman codes of a given length are unique, so a code-sorted group binary-searches exactly.
        for g in &mut groups {
            g.sort_unstable_by_key(|&(c, _)| c);
        }
        groups
    })
}

/// Resolve a single code of length 17..=30 bits (the rare long codes) by exact match.
fn decode_long(acc: u64, nbits: u32) -> Option<(u16, u32)> {
    let groups = long_table();
    for len in (ROOT_BITS + 1)..=30 {
        if nbits < len {
            return None;
        }
        let code = ((acc >> (nbits - len)) & ((1u64 << len) - 1)) as u32;
        let g = &groups[(len - ROOT_BITS - 1) as usize];
        if let Ok(idx) = g.binary_search_by_key(&code, |&(c, _)| c) {
            return Some((g[idx].1, len));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_c4_1_huffman_www_example_com() {
        // RFC 7541 §C.4.1: "www.example.com" Huffman-encodes to these 12 octets.
        let want = [
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ];
        let mut out = Vec::new();
        encode(&mut out, b"www.example.com");
        assert_eq!(out, want);
        assert_eq!(encoded_len(b"www.example.com"), 12);
        assert_eq!(decode(&want).unwrap(), b"www.example.com");
        assert_eq!(decode_limited(&want, 15).unwrap(), b"www.example.com");
        assert!(decode_limited(&want, 14).is_none());
    }

    #[test]
    fn rfc_c4_2_huffman_no_cache() {
        // RFC 7541 §C.4.2: "no-cache".
        let want = [0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf];
        let mut out = Vec::new();
        encode(&mut out, b"no-cache");
        assert_eq!(out, want);
        assert_eq!(decode(&want).unwrap(), b"no-cache");
    }

    #[test]
    fn rfc_c6_1_huffman_date_value() {
        // RFC 7541 §C.6.1 status/date example value: "Mon, 21 Oct 2013 20:13:21 GMT".
        let s = b"Mon, 21 Oct 2013 20:13:21 GMT";
        let mut out = Vec::new();
        encode(&mut out, s);
        assert_eq!(decode(&out).unwrap(), s);
    }

    #[test]
    fn roundtrip_all_bytes_and_sizes() {
        // Every byte value, and a few realistic header values.
        let all: Vec<u8> = (0u16..=255).map(|b| b as u8).collect();
        for sample in [
            &all[..],
            b"\"400-6a1ce183-3e6b8b;;;\"",
            b"public, max-age=300",
            b"application/octet-stream",
            b"",
        ] {
            let mut out = Vec::new();
            encode(&mut out, sample);
            assert_eq!(
                encoded_len(sample),
                out.len(),
                "len mismatch for {sample:?}"
            );
            assert_eq!(&decode(&out).unwrap(), sample, "roundtrip for {sample:?}");
        }
    }

    #[test]
    fn long_codes_decode_via_binary_search() {
        // Bytes 1 (23-bit), 2/8 (28-bit), 10/13/22 (30-bit) all use the decode_long slow path.
        // Round-tripping them confirms the length-grouped binary-search lookup returns the same
        // symbols the old linear TABLE scan did.
        let long_bytes: &[u8] = &[1, 2, 8, 10, 13, 22, 0xfe, 0xff];
        let mut out = Vec::new();
        encode(&mut out, long_bytes);
        assert_eq!(&decode(&out).unwrap(), long_bytes);

        // A literal EOS (the 30-bit all-ones code) in the data must be rejected, not emitted —
        // 0xFFFFFFFF is the 30-bit EOS code plus 2 padding 1-bits. decode_long resolves it to
        // sym 256 (EOS), which decode() rejects.
        assert_eq!(decode(&[0xff, 0xff, 0xff, 0xff]), None);
    }
}
