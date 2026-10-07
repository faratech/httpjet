//! QPACK field-section decoding for HTTP/3 requests (RFC 9204): the static table,
//! literals and Huffman. The dynamic table is never used (SETTINGS advertise capacity 0).
//! Std + hj-h2 only, so the fuzz workspace can include this file directly.

/// RFC 9204 Appendix A QPACK static table (index 0..=98). The dynamic table is unused
/// (we advertise SETTINGS_QPACK_MAX_TABLE_CAPACITY=0), so this + literals + Huffman fully
/// decode any conformant request header block.
pub(crate) static QPACK_STATIC: &[(&str, &str)] = &[
    (":authority", ""),
    (":path", "/"),
    ("age", "0"),
    ("content-disposition", ""),
    ("content-length", "0"),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("referer", ""),
    ("set-cookie", ""),
    (":method", "CONNECT"),
    (":method", "DELETE"),
    (":method", "GET"),
    (":method", "HEAD"),
    (":method", "OPTIONS"),
    (":method", "POST"),
    (":method", "PUT"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "103"),
    (":status", "200"),
    (":status", "304"),
    (":status", "404"),
    (":status", "503"),
    ("accept", "*/*"),
    ("accept", "application/dns-message"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-ranges", "bytes"),
    ("access-control-allow-headers", "cache-control"),
    ("access-control-allow-headers", "content-type"),
    ("access-control-allow-origin", "*"),
    ("cache-control", "max-age=0"),
    ("cache-control", "max-age=2592000"),
    ("cache-control", "max-age=604800"),
    ("cache-control", "no-cache"),
    ("cache-control", "no-store"),
    ("cache-control", "public, max-age=31536000"),
    ("content-encoding", "br"),
    ("content-encoding", "gzip"),
    ("content-type", "application/dns-message"),
    ("content-type", "application/javascript"),
    ("content-type", "application/json"),
    ("content-type", "application/x-www-form-urlencoded"),
    ("content-type", "image/gif"),
    ("content-type", "image/jpeg"),
    ("content-type", "image/png"),
    ("content-type", "text/css"),
    ("content-type", "text/html; charset=utf-8"),
    ("content-type", "text/plain"),
    ("content-type", "text/plain;charset=utf-8"),
    ("range", "bytes=0-"),
    ("strict-transport-security", "max-age=31536000"),
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains",
    ),
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains; preload",
    ),
    ("vary", "accept-encoding"),
    ("vary", "origin"),
    ("x-content-type-options", "nosniff"),
    ("x-xss-protection", "1; mode=block"),
    (":status", "100"),
    (":status", "204"),
    (":status", "206"),
    (":status", "302"),
    (":status", "400"),
    (":status", "403"),
    (":status", "421"),
    (":status", "425"),
    (":status", "500"),
    ("accept-language", ""),
    ("access-control-allow-credentials", "FALSE"),
    ("access-control-allow-credentials", "TRUE"),
    ("access-control-allow-headers", "*"),
    ("access-control-allow-methods", "get"),
    ("access-control-allow-methods", "get, post, options"),
    ("access-control-allow-methods", "options"),
    ("access-control-expose-headers", "content-length"),
    ("access-control-request-headers", "content-type"),
    ("access-control-request-method", "get"),
    ("access-control-request-method", "post"),
    ("alt-svc", "clear"),
    ("authorization", ""),
    (
        "content-security-policy",
        "script-src 'none'; object-src 'none'; base-uri 'none'",
    ),
    ("early-data", "1"),
    ("expect-ct", ""),
    ("forwarded", ""),
    ("if-range", ""),
    ("origin", ""),
    ("purpose", "prefetch"),
    ("server", ""),
    ("timing-allow-origin", "*"),
    ("upgrade-insecure-requests", "1"),
    ("user-agent", ""),
    ("x-forwarded-for", ""),
    ("x-frame-options", "deny"),
    ("x-frame-options", "sameorigin"),
];

/// Read a QPACK prefixed integer (RFC 7541 §5.1) starting at the type byte `buf[*pos]`,
/// using the low `prefix_bits` bits; consumes the first byte + any continuation bytes.
fn qpack_read_int(buf: &[u8], pos: &mut usize, prefix_bits: u32) -> Option<u64> {
    let first = *buf.get(*pos)?;
    *pos += 1;
    let max = (1u64 << prefix_bits) - 1;
    let mut val = (first as u64) & max;
    if val < max {
        return Some(val);
    }
    let mut m = 0u32;
    loop {
        let b = *buf.get(*pos)?;
        *pos += 1;
        val = val.checked_add(((b & 0x7f) as u64) << m)?;
        if b & 0x80 == 0 {
            break;
        }
        m += 7;
        if m > 62 {
            return None;
        }
    }
    Some(val)
}

/// Read a QPACK string literal: an `H` (Huffman) bit at bit position `prefix_bits`, a
/// `prefix_bits`-prefixed length, then the bytes (Huffman-decoded when H=1).
fn qpack_read_str_limited(
    buf: &[u8],
    pos: &mut usize,
    prefix_bits: u32,
    max_output: usize,
) -> Option<Vec<u8>> {
    let huff = (*buf.get(*pos)? >> prefix_bits) & 1 == 1;
    let len = qpack_read_int(buf, pos, prefix_bits)? as usize;
    let raw = buf.get(*pos..(*pos).checked_add(len)?)?;
    *pos += len;
    if huff {
        hj_h2::hpack::huffman::decode_limited(raw, max_output)
    } else {
        (raw.len() <= max_output).then(|| raw.to_vec())
    }
}

/// Decode a QPACK encoded field section (RFC 9204 §4.5) into (name, value) pairs. Supports
/// the static table + literals + Huffman; rejects any dynamic/post-base reference (unused).
#[cfg(test)]
pub(crate) fn qpack_decode(buf: &[u8]) -> Option<Vec<(Vec<u8>, Vec<u8>)>> {
    qpack_decode_limited(buf, usize::MAX).map(|(headers, _)| headers)
}

pub(crate) fn qpack_decode_limited(
    buf: &[u8],
    max_field_section_size: usize,
) -> Option<(Vec<(Vec<u8>, Vec<u8>)>, usize)> {
    let mut pos = 0usize;
    qpack_read_int(buf, &mut pos, 8)?; // Required Insert Count (0)
    qpack_read_int(buf, &mut pos, 7)?; // Delta Base (sign bit + 7-bit prefix; 0)
    let mut out = Vec::new();
    let mut decoded_size = 0usize;
    while pos < buf.len() {
        let first = buf[pos];
        if first & 0x80 != 0 {
            // Indexed Field Line; T (bit6): 1=static.
            let is_static = (first >> 6) & 1 == 1;
            let idx = qpack_read_int(buf, &mut pos, 6)? as usize;
            if !is_static {
                return None;
            }
            let (n, v) = QPACK_STATIC.get(idx)?;
            decoded_size = decoded_size
                .checked_add(n.len())?
                .checked_add(v.len())?
                .checked_add(32)?;
            if decoded_size > max_field_section_size {
                return None;
            }
            out.push((n.as_bytes().to_vec(), v.as_bytes().to_vec()));
        } else if first & 0x40 != 0 {
            // Literal Field Line with Name Reference; T (bit4): 1=static.
            let is_static = (first >> 4) & 1 == 1;
            let idx = qpack_read_int(buf, &mut pos, 4)? as usize;
            if !is_static {
                return None;
            }
            let name_bytes = QPACK_STATIC.get(idx)?.0.as_bytes();
            let base = decoded_size
                .checked_add(name_bytes.len())?
                .checked_add(32)?;
            if base > max_field_section_size {
                return None;
            }
            let value = qpack_read_str_limited(buf, &mut pos, 7, max_field_section_size - base)?;
            decoded_size = base.checked_add(value.len())?;
            let name = name_bytes.to_vec();
            out.push((name, value));
        } else if first & 0x20 != 0 {
            // Literal Field Line with Literal Name (001 N H + 3-bit name length).
            let base = decoded_size.checked_add(32)?;
            if base > max_field_section_size {
                return None;
            }
            let name = qpack_read_str_limited(buf, &mut pos, 3, max_field_section_size - base)?;
            let with_name = base.checked_add(name.len())?;
            let value =
                qpack_read_str_limited(buf, &mut pos, 7, max_field_section_size - with_name)?;
            decoded_size = with_name.checked_add(value.len())?;
            out.push((name, value));
        } else {
            return None; // post-base / dynamic — unsupported (table capacity 0)
        }
    }
    Some((out, decoded_size))
}
