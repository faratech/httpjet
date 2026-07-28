//! HPACK integer representation (RFC 7541 §5.1).
//!
//! An integer is encoded with an `n`-bit prefix in the first octet (the high bits
//! of which carry a representation flag the caller supplies via `flag`). Values that
//! fit in the prefix are inlined; larger values continue in 7-bit little-endian
//! continuation octets with the high bit set on all but the last.

/// Encode `value` with an `n`-bit prefix, OR-ing the representation `flag` into the
/// high `8 - n` bits of the first octet. Appends to `out` (no allocation of its own).
pub fn encode(out: &mut Vec<u8>, value: u64, prefix_bits: u8, flag: u8) {
    debug_assert!((1..=8).contains(&prefix_bits));
    let max = (1u64 << prefix_bits) - 1;
    if value < max {
        out.push(flag | value as u8);
        return;
    }
    out.push(flag | max as u8);
    let mut v = value - max;
    while v >= 128 {
        out.push((v as u8 & 0x7f) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// Decode an `n`-bit-prefix integer from `buf[*pos..]`, advancing `*pos`. The first
/// octet's prefix bits are taken from `buf[*pos]` (the caller's flag bits are ignored
/// via masking). Returns `None` on truncation or overflow.
pub fn decode(buf: &[u8], pos: &mut usize, prefix_bits: u8) -> Option<u64> {
    let max = (1u64 << prefix_bits) - 1;
    let first = *buf.get(*pos)? as u64 & max;
    *pos += 1;
    if first < max {
        return Some(first);
    }
    let mut value = max;
    let mut shift = 0u32;
    loop {
        // Guard BEFORE consuming the byte: a continuation byte at shift > 56 would
        // place its low 7 bits at bit positions 57–63, which is representable in u64,
        // but any non-zero contribution at shift > 56 implies a value > 2^57 — far
        // beyond any valid HPACK integer (SETTINGS values are 31-bit). More importantly,
        // accepting non-canonical oversized varints (e.g. a zero-contribution tail byte
        // with the continuation bit clear) would let an attacker probe for parser
        // divergence across implementations. Reject any continuation whose 7-bit payload
        // is non-zero at shift > 56; this covers shift=63 where checked_shl returns None.
        let b = *buf.get(*pos)?;
        if shift > 56 && (b & 0x7f) != 0 {
            return None;
        }
        *pos += 1;
        value = value.checked_add(((b & 0x7f) as u64) << shift)?;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        // A well-formed varint never needs more than 10 bytes total (prefix + 9 continuation
        // bytes). Any non-zero contribution at shift > 56 is already rejected above, so a byte
        // that would sit at shift 63 can only be non-canonical zero padding (an 11th total
        // byte). `shift > 63` let that through (after 9 continuations shift == 63, and 63 > 63
        // is false); reject once shift exceeds 56 so oversized non-canonical sequences are not
        // accepted contrary to the 10-byte guarantee.
        if shift > 56 {
            return None;
        }
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 7541 §C.1 worked examples.
    #[test]
    fn c1_1_ten_with_5bit_prefix() {
        // 10 fits in a 5-bit prefix -> single octet 0b000_01010.
        let mut out = Vec::new();
        encode(&mut out, 10, 5, 0b1110_0000); // flag bits in the top 3
        assert_eq!(out, vec![0b1110_1010]);
        let mut pos = 0;
        assert_eq!(decode(&out, &mut pos, 5), Some(10));
    }

    #[test]
    fn c1_2_1337_with_5bit_prefix() {
        // 1337 with a 5-bit prefix -> 0x1f 0x9a 0x0a (RFC §C.1.2).
        let mut out = Vec::new();
        encode(&mut out, 1337, 5, 0x00);
        assert_eq!(out, vec![0x1f, 0x9a, 0x0a]);
        let mut pos = 0;
        assert_eq!(decode(&out, &mut pos, 5), Some(1337));
    }

    #[test]
    fn c1_3_42_with_8bit_prefix() {
        let mut out = Vec::new();
        encode(&mut out, 42, 8, 0x00);
        assert_eq!(out, vec![42]);
        let mut pos = 0;
        assert_eq!(decode(&out, &mut pos, 8), Some(42));
    }

    #[test]
    fn roundtrip_many() {
        for v in [
            0u64,
            1,
            30,
            31,
            127,
            128,
            255,
            256,
            16384,
            1 << 20,
            u32::MAX as u64,
        ] {
            for bits in 1..=8u8 {
                let mut out = Vec::new();
                encode(&mut out, v, bits, 0);
                let mut pos = 0;
                assert_eq!(decode(&out, &mut pos, bits), Some(v), "v={v} bits={bits}");
                assert_eq!(pos, out.len());
            }
        }
    }

    #[test]
    fn decode_truncated_is_none() {
        // Prefix maxed but no continuation octet.
        let buf = [0xffu8];
        let mut pos = 0;
        assert_eq!(decode(&buf, &mut pos, 8), None);
    }

    #[test]
    fn non_canonical_oversized_varint_is_rejected() {
        // (#32 follow-up) 8-bit prefix maxed (0xff) then 9 zero-payload continuation bytes
        // and a zero terminator encodes 255 NON-canonically (canonical is [0xff, 0x00]).
        // The decoder must reject it (honor its own ≤10-byte guarantee), not accept 255 —
        // the prior `shift > 63` guard let this 11-byte sequence through.
        let buf = [
            0xff, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00,
        ];
        let mut pos = 0;
        assert_eq!(decode(&buf, &mut pos, 8), None);

        // A canonical large value still decodes — the guard only trips on oversized tails.
        let mut out = Vec::new();
        encode(&mut out, u32::MAX as u64, 8, 0);
        let mut p = 0;
        assert_eq!(decode(&out, &mut p, 8), Some(u32::MAX as u64));
    }
}
