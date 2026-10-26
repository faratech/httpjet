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

/// The code and bit length of octet `b` (the table also holds EOS at 256).
#[inline(always)]
fn code_of(b: u8) -> (u32, u8) {
    TABLE[b as usize]
}

/// Number of octets `data` would occupy Huffman-encoded (RFC 7541 §5.2 padding).
pub(crate) fn encoded_len(data: &[u8]) -> usize {
    let bits: usize = data.iter().map(|&b| code_of(b).1 as usize).sum();
    bits.div_ceil(8)
}

/// Append the Huffman encoding of `data` to `out`, padding the last octet with the
/// EOS prefix (1-bits).
pub fn encode(out: &mut Vec<u8>, data: &[u8]) {
    encode_sized(out, data, encoded_len(data));
}

/// [`encode`] when the caller already has `encoded_len(data)`. The output is sized once
/// and filled 32 bits at a time: long header values (a page's preload `Link` set runs to
/// kilobytes and repeats on every response) made a per-octet `push` the bulk of HPACK
/// encode time. A wrong `encoded_len` falls back to encoding octet by octet; it never
/// panics.
pub(crate) fn encode_sized(out: &mut Vec<u8>, data: &[u8], encoded_len: usize) {
    let start = out.len();
    out.resize(start + encoded_len, 0);
    if !fill(out.get_mut(start..).unwrap_or_default(), data) {
        out.truncate(start);
        encode_octets(out, data);
    }
}

/// Encode `data` into exactly `dst`; `false` when it does not fit exactly.
#[inline(always)]
fn fill(mut dst: &mut [u8], data: &[u8]) -> bool {
    // At most 31 pending bits plus one code of at most 30: never past 61 bits.
    let mut acc: u64 = 0;
    let mut nbits: u32 = 0;
    for &b in data {
        let (code, len) = code_of(b);
        acc = (acc << len) | code as u64;
        nbits += len as u32;
        if nbits >= 32 {
            nbits -= 32;
            let Some((word, rest)) = std::mem::take(&mut dst).split_first_chunk_mut::<4>() else {
                return false;
            };
            *word = ((acc >> nbits) as u32).to_be_bytes();
            dst = rest;
        }
    }
    while nbits >= 8 {
        nbits -= 8;
        let Some((octet, rest)) = std::mem::take(&mut dst).split_first_mut() else {
            return false;
        };
        *octet = (acc >> nbits) as u8;
        dst = rest;
    }
    if nbits > 0 {
        // Pad the remaining bits with 1s (the most-significant bits of EOS).
        let pad = 8 - nbits;
        let Some((octet, rest)) = std::mem::take(&mut dst).split_first_mut() else {
            return false;
        };
        *octet = ((acc << pad) | ((1u64 << pad) - 1)) as u8;
        dst = rest;
    }
    dst.is_empty()
}

#[cold]
#[inline(never)]
fn encode_octets(out: &mut Vec<u8>, data: &[u8]) {
    let mut acc: u64 = 0;
    let mut nbits: u32 = 0;
    for &b in data {
        let (code, len) = code_of(b);
        acc = (acc << len) | code as u64;
        nbits += len as u32;
        while nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    if nbits > 0 {
        let pad = 8 - nbits;
        out.push(((acc << pad) | ((1u64 << pad) - 1)) as u8);
    }
}

/// Root lookup width. Every code of at most ROOT_BITS bits resolves in one read of a
/// 4 KiB table, which stays cache-resident between requests; the flat 2^16-entry
/// (256 KiB) table it replaced was evicted at production request rates, so a decode
/// paid a cache miss for nearly every symbol (~3x slower cold).
const ROOT_BITS: u32 = 11;
/// Codes of ROOT_BITS+1..=WIN_BITS bits resolve through one small sub table per root
/// prefix; longer codes (rare control/high bytes) take [`decode_long`].
const WIN_BITS: u32 = 16;
const SUB_BITS: u32 = WIN_BITS - ROOT_BITS;
/// Root entry flag: the low bits index `DecodeTables::sub` instead of naming a symbol.
const SUB_TABLE: u16 = 0x8000;

/// Entries are `code_len << 8 | symbol`. A sub-table entry of 0 means no code of at most
/// WIN_BITS bits has that prefix (a long code, or padding). Every root entry is non-zero
/// because the code is complete.
struct DecodeTables {
    root: [u16; 1 << ROOT_BITS],
    sub: Vec<[u16; 1 << SUB_BITS]>,
}

fn decode_tables() -> &'static DecodeTables {
    static T: std::sync::OnceLock<DecodeTables> = std::sync::OnceLock::new();
    T.get_or_init(|| {
        let mut t = DecodeTables {
            root: [0; 1 << ROOT_BITS],
            sub: Vec::new(),
        };
        for (sym, &(code, len)) in TABLE.iter().enumerate() {
            let len = len as u32;
            if sym == 256 {
                continue; // EOS is never emitted; decode_long resolves and rejects it
            }
            let entry = (len as u16) << 8 | sym as u16;
            // Every index below is in range by construction (`code < 2^len`); the unit test
            // checks all 2^WIN_BITS windows, so a skipped slot cannot go unnoticed.
            if len <= ROOT_BITS {
                // Left-align the code and fill every index sharing this prefix.
                let base = (code << (ROOT_BITS - len)) as usize;
                if let Some(slots) = t.root.get_mut(base..base + (1 << (ROOT_BITS - len))) {
                    slots.fill(entry);
                }
                continue;
            }
            let Some(slot) = t.root.get_mut((code >> (len - ROOT_BITS)) as usize) else {
                continue;
            };
            if *slot & SUB_TABLE == 0 {
                t.sub.push([0; 1 << SUB_BITS]);
                *slot = SUB_TABLE | (t.sub.len() - 1) as u16;
            }
            if len <= WIN_BITS {
                let low = (code & ((1 << (len - ROOT_BITS)) - 1)) as usize;
                let base = low << (WIN_BITS - len);
                let span = base..base + (1 << (WIN_BITS - len));
                let sub = t.sub.get_mut((*slot & !SUB_TABLE) as usize);
                if let Some(slots) = sub.and_then(|sub| sub.get_mut(span)) {
                    slots.fill(entry);
                }
            }
        }
        t
    })
}

/// The next `width` bits of the right-aligned `acc`, padded with 1-bits (the EOS prefix)
/// when fewer than `width` real bits remain.
#[inline(always)]
fn window(acc: u64, nbits: u32, width: u32) -> usize {
    let mask = (1u64 << width) - 1;
    if nbits >= width {
        ((acc >> (nbits - width)) & mask) as usize
    } else {
        (((acc << (width - nbits)) | ((1u64 << (width - nbits)) - 1)) & mask) as usize
    }
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
    let t = decode_tables();
    let estimate = (data.len().saturating_mul(8) / 5).saturating_add(1);
    out.reserve(estimate.min(max_output));
    let mut acc: u64 = 0;
    let mut nbits: u32 = 0;
    let mut i = 0;

    loop {
        // While input remains, keep at least 32 bits buffered: enough for the longest
        // (30-bit) code. Refilling a word at a time keeps the refill branch off most
        // symbols; a byte-at-a-time refill mispredicted on nearly every one.
        if nbits <= 32 {
            if let Some(&[a, b, c, d]) = data.get(i..i + 4) {
                acc = (acc << 32) | u32::from_be_bytes([a, b, c, d]) as u64;
                i += 4;
                nbits += 32;
            } else {
                // Cap at 56 so the next `<<8` never overflows.
                while nbits <= 48
                    && let Some(&byte) = data.get(i)
                {
                    acc = (acc << 8) | byte as u64;
                    i += 1;
                    nbits += 8;
                }
            }
        }
        if nbits == 0 {
            break;
        }
        // `window` masks to its width, so the root lookup cannot miss.
        let mut e = t
            .root
            .get(window(acc, nbits, ROOT_BITS))
            .copied()
            .unwrap_or(0);
        if e & SUB_TABLE != 0 {
            let w = window(acc, nbits, WIN_BITS) & ((1 << SUB_BITS) - 1);
            let sub = t.sub.get((e & !SUB_TABLE) as usize);
            e = sub.and_then(|sub| sub.get(w)).copied().unwrap_or(0);
        }
        let len = (e >> 8) as u32;
        if len != 0 {
            if len > nbits {
                break; // the matched prefix was padding, not a real code -> done
            }
            if out.len() == max_output {
                return None;
            }
            out.push(e as u8);
            nbits -= len;
        } else if nbits < WIN_BITS {
            break; // no full code and out of input -> remaining bits are padding
        } else {
            // A code longer than WIN_BITS (rare). Resolve it bit-exactly.
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

/// Long codes (length `WIN_BITS+1..=30`) grouped by bit-length, each group sorted by code,
/// so [`decode_long`] binary-searches (O(log n)) instead of linear-scanning the whole 257-entry
/// `TABLE` once per candidate length. The old nested scan was O(162 symbols × 14 lengths) per
/// long symbol; a crafted all-long-code header block (RFC-conformant input) turned that into a
/// ~60× HPACK-decode CPU amplification that head-of-line-blocks every stream on the connection.
/// Index = `code_len - (WIN_BITS + 1)`. EOS (sym 256) is intentionally INCLUDED so a literal EOS
/// in the data resolves to 256 and is rejected by the caller, matching the old scan. Built once.
fn long_table() -> &'static [Vec<(u32, u16)>] {
    static T: std::sync::OnceLock<Vec<Vec<(u32, u16)>>> = std::sync::OnceLock::new();
    T.get_or_init(|| {
        let groups_n = (30 - WIN_BITS) as usize; // lengths WIN_BITS+1 ..= 30
        let mut groups: Vec<Vec<(u32, u16)>> = vec![Vec::new(); groups_n];
        for (sym, &(code, len)) in TABLE.iter().enumerate() {
            let len = len as u32;
            if len <= WIN_BITS {
                continue; // resolved by the lookup tables
            }
            groups[(len - WIN_BITS - 1) as usize].push((code, sym as u16));
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
    for len in (WIN_BITS + 1)..=30 {
        if nbits < len {
            return None;
        }
        let code = ((acc >> (nbits - len)) & ((1u64 << len) - 1)) as u32;
        let g = &groups[(len - WIN_BITS - 1) as usize];
        if let Ok(idx) = g.binary_search_by_key(&code, |&(c, _)| c) {
            return Some((g[idx].1, len));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A caller's wrong `encoded_len` (too small or too large) still yields the exact
    /// encoding, through the octet-by-octet fallback.
    #[test]
    fn a_wrong_encoded_len_still_encodes_exactly() {
        let data = b"</styles/fonts/fa-regular-400.woff2>; rel=preload; as=font; crossorigin";
        let mut want = Vec::new();
        encode(&mut want, data);
        let n = encoded_len(data);
        for len in [0, 1, n - 1, n + 1, n + 7] {
            let mut out = vec![0xAA];
            encode_sized(&mut out, data, len);
            assert_eq!(&out[1..], &want[..], "encoded_len {len}");
            assert_eq!(out[0], 0xAA);
        }
    }

    /// The octet-at-a-time encoder the word-at-a-time one replaced.
    fn encode_by_octet(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut acc: u64 = 0;
        let mut nbits: u32 = 0;
        for &b in data {
            let (code, len) = code_of(b);
            acc = (acc << len) | code as u64;
            nbits += len as u32;
            while nbits >= 8 {
                nbits -= 8;
                out.push((acc >> nbits) as u8);
            }
        }
        if nbits > 0 {
            let pad = 8 - nbits;
            acc = (acc << pad) | ((1u64 << pad) - 1);
            out.push(acc as u8);
        }
        out
    }

    #[test]
    fn word_encoder_matches_the_octet_encoder() {
        let mut inputs: Vec<Vec<u8>> = (0..=255u8).map(|b| vec![b]).collect();
        inputs.push(Vec::new());
        inputs.push((0..=255u8).collect());
        inputs.push((0..=255u8).rev().cycle().take(3000).collect());
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        for len in 0..600 {
            let v = (0..len)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    // Mostly printable, sometimes any octet (long 20-30 bit codes).
                    if x % 7 == 0 {
                        (x >> 8) as u8
                    } else {
                        b' ' + (x >> 8) as u8 % 95
                    }
                })
                .collect();
            inputs.push(v);
        }
        for data in inputs {
            let mut out = b"prefix".to_vec();
            encode(&mut out, &data);
            assert_eq!(&out[..6], b"prefix");
            assert_eq!(out[6..], encode_by_octet(&data), "input {data:?}");
            assert_eq!(decode(&out[6..]).unwrap(), data);
        }
    }

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

    /// The code of at most `width` bits that prefixes the `width`-bit window `w`, by scan.
    fn scan_prefix(w: u32, width: u32) -> Option<(u16, u32)> {
        TABLE
            .iter()
            .take(256)
            .enumerate()
            .find_map(|(sym, &(code, len))| {
                let len = len as u32;
                (len <= width && w >> (width - len) == code).then_some((sym as u16, len))
            })
    }

    #[test]
    fn lookup_tables_match_a_scan_of_every_16_bit_window() {
        let t = decode_tables();
        assert!(t.root.iter().all(|&e| e != 0), "every root prefix resolves");
        for w in 0..(1u32 << WIN_BITS) {
            let mut e = t.root[(w >> SUB_BITS) as usize];
            if e & SUB_TABLE != 0 {
                e = t.sub[(e & !SUB_TABLE) as usize][(w & ((1 << SUB_BITS) - 1)) as usize];
            }
            let got = (e != 0).then_some((e & 0xff, (e >> 8) as u32));
            assert_eq!(got, scan_prefix(w, WIN_BITS), "window {w:#06x}");
        }
    }

    /// RFC 7541 §5.2 decoded one bit at a time: EOS in the data, more than 7 bits of
    /// padding, or padding that is not all 1-bits is an error.
    fn reference_decode(data: &[u8]) -> Option<Vec<u8>> {
        let (mut out, mut code, mut len) = (Vec::new(), 0u32, 0u32);
        for &byte in data {
            for k in (0..8).rev() {
                code = code << 1 | ((byte >> k) & 1) as u32;
                len += 1;
                if let Some(sym) = TABLE
                    .iter()
                    .position(|&(c, l)| l as u32 == len && c == code)
                {
                    if sym == 256 {
                        return None;
                    }
                    out.push(sym as u8);
                    (code, len) = (0, 0);
                }
            }
        }
        (len <= 7 && code == (1 << len) - 1).then_some(out)
    }

    fn assert_matches_reference(data: &[u8], max_output: usize) {
        let want = reference_decode(data).filter(|v| v.len() <= max_output);
        assert_eq!(
            decode_limited(data, max_output),
            want,
            "{data:02x?} limit {max_output}"
        );
    }

    #[test]
    fn decode_matches_a_bitwise_reference_on_every_short_input() {
        assert_matches_reference(&[], usize::MAX);
        for x in 0..=0xffffu32 {
            let [_, _, a, b] = x.to_be_bytes();
            assert_matches_reference(&[a, b], usize::MAX);
            assert_matches_reference(&[a, b], 1);
            if x <= 0xff {
                assert_matches_reference(&[b], usize::MAX);
            }
        }
    }

    #[test]
    fn decode_matches_a_bitwise_reference_on_random_encodings() {
        let mut s: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut rnd = move || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        const TEXT: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789-_./=;, ABCXYZ\\\"{}<>#$@[]~^`|";
        for _ in 0..20_000 {
            let raw: Vec<u8> = (0..rnd() % 48)
                .map(|_| match rnd() {
                    r if r % 6 == 0 => (r >> 8) as u8,
                    r => TEXT[(r >> 8) as usize % TEXT.len()],
                })
                .collect();
            let mut enc = Vec::new();
            encode(&mut enc, &raw);
            let limit = match rnd() % 4 {
                0 => (rnd() % 50) as usize,
                _ => usize::MAX,
            };
            assert_matches_reference(&enc, limit);
            if !enc.is_empty() {
                let mut flipped = enc.clone();
                let bit = (rnd() % (enc.len() as u64 * 8)) as usize;
                flipped[bit / 8] ^= 1 << (bit % 8);
                assert_matches_reference(&flipped, limit);
                assert_matches_reference(&enc[..(rnd() % enc.len() as u64) as usize], limit);
            }
            let junk: Vec<u8> = (0..rnd() % 40).map(|_| rnd() as u8).collect();
            assert_matches_reference(&junk, usize::MAX);
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
