//! LSAPI packet builders: assemble the BEGIN_REQUEST packet (req header, CGI
//! env table, the raw HTTP-header block + index) from a request's env + headers.
//!
//! The wire-frame parsing/encoding side lives in [`super::frame`]; this module is
//! the producing half. All constants + [`PacketType`] / [`known_header_index`]
//! come from the parent [`super`] module.

use bytes::{BufMut, Bytes, BytesMut};

use super::*;

/// LSAPI "special-env" permission level for a php.ini override. On the wire the
/// php.ini key is prefixed with `\x01` then this byte; lsphp's `alter_ini` treats
/// `\x04` as `PHP_INI_SYSTEM` (`php_admin_value`/`php_admin_flag`, can set any
/// setting) and anything else (`\x02`) as `PHP_INI_PERDIR` at the htaccess stage
/// (`php_value`/`php_flag`, which PHP itself refuses to use for stronger settings).
/// These reach PHP ONLY via the special-env section — the regular CGI env is
/// ignored by the lsphp SAPI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SpecialEnvType {
    User = 0x02,
    Admin = 0x04,
}

/// Build the BEGIN_REQUEST packet *body* (everything after the 8-byte packet
/// header) from a list of CGI env vars.
///
/// IMPORTANT: per `lsapilib.c::parseRequest`, the request body is **NOT** part of
/// the BEGIN_REQUEST packet — `m_packetLen` must end exactly after the (empty)
/// HTTP-header block. The body bytes are written to the socket *after* the packet
/// as raw bytes, and `m_reqBodyLen` (the `req_body_len` argument here) tells PHP
/// how many to read. So pass the body length here, but write the body separately:
///
/// ```text
/// let frame_body = build_begin_request_body(&env, req_body.len() as i32);
/// codec.encode(LsapiFrame::new(PacketType::BeginRequest, frame_body), &mut buf)?;
/// stream.write_all(&buf).await?;      // the BEGIN_REQUEST packet
/// stream.write_all(&req_body).await?; // then the raw body bytes
/// ```
///
/// `req_body_len` is the on-wire `m_reqBodyLen` (`fields[1]`): pass a concrete
/// byte count (>= 0) of the body that follows the packet, or the `-2` sentinel to
/// tell lsphp to re-read Content-Length from the raw header block. Do NOT pass
/// `-1`: lsphp reads it as a zero-length body, not as a stream-to-EOF marker.
///
/// `env` is the full CGI environment (REQUEST_METHOD, SCRIPT_FILENAME, ...). The
/// four "special" vars are looked up by name and their value offsets recorded in
/// the req-header so PHP can resolve them directly.
pub fn build_begin_request_body<K: AsRef<str>>(env: &[(K, String)], req_body_len: i32) -> Bytes {
    build_begin_request(env, &[], &[] as &[(&str, &str)], req_body_len)
}

/// Build the BEGIN_REQUEST packet *body* including the raw HTTP request-header
/// block and the `lsapi_http_header_index` / unknown-header offset table.
///
/// This is the form a real lsphp needs: PHP resolves `$_SERVER['HTTP_*']`,
/// `getallheaders()` and `apache_request_headers()` **from the header index +
/// unknown-header table over the raw header block** (see `GetHeaderVar` /
/// `LSAPI_ForeachOrgHeader_r` in lsapilib.c). It does NOT read request headers
/// from the CGI env table. So the `HTTP_*` env vars alone are invisible to PHP;
/// the headers MUST be carried here.
///
/// `headers` is the request's `(name, value)` list in wire order (names need not
/// be canonicalized; matching against the well-known slots is case-insensitive).
///
/// Wire layout appended after the env tables (mirrors `LsapiReq::buildReq` +
/// `HttpReq::appendHeaderIndexes`):
///   - 8-byte alignment padding (relative to the start of the whole packet)
///   - `lsapi_http_header_index` (152 bytes): `u16 len[25]` + 2 pad + `i32 off[25]`,
///     where `off[i]`/`len[i]` locate the VALUE of well-known header `i` inside
///     the raw header block (`off == 0` means "header absent")
///   - `lsapi_header_offset[cntUnknown]`: `{nameOff,nameLen,valueOff,valueLen}` for
///     each non-well-known header, all offsets relative to the raw header block
///   - the raw header block itself (`m_httpHeaderLen` bytes)
///
/// The request body is still NOT part of this packet; it follows on the wire.
pub fn build_begin_request<K, V, HN, HV>(
    env: &[(K, V)],
    special_env: &[(SpecialEnvType, String, String)],
    headers: &[(HN, HV)],
    req_body_len: i32,
) -> Bytes
where
    K: AsRef<str>,
    V: AsRef<str>,
    HN: AsRef<str>,
    HV: AsRef<str>,
{
    // Legacy body-only form (no packet header): the codec prepends the 8-byte
    // header. Offsets are absolute *including* that header (see the helper).
    let mut out = BytesMut::with_capacity(REQ_HEADER_LEN + env.len() * 32);
    build_begin_request_into(&mut out, env, special_env, headers, req_body_len);
    out.freeze()
}

/// Build a complete, framed BEGIN_REQUEST packet (8-byte packet header + body) in
/// a SINGLE allocation. Equivalent to `encode_frame(build_begin_request(...))` but
/// without the second buffer + whole-packet memcpy: because the body is written
/// directly behind the reserved packet header, each value's absolute offset is
/// simply its index in the buffer. The 8-byte header is backfilled last (its
/// `total` length is only known once the body is complete).
pub fn build_begin_request_framed<K, V, HN, HV>(
    env: &[(K, V)],
    special_env: &[(SpecialEnvType, String, String)],
    headers: &[(HN, HV)],
    req_body_len: i32,
) -> Bytes
where
    K: AsRef<str>,
    V: AsRef<str>,
    HN: AsRef<str>,
    HV: AsRef<str>,
{
    let mut out = BytesMut::new();
    build_begin_request_framed_into(&mut out, env, special_env, headers, req_body_len);
    out.freeze()
}

/// As [`build_begin_request_framed`] but builds into a CALLER-PROVIDED `out`
/// (cleared first), so the buffer can be RECYCLED across requests instead of a
/// fresh allocation per request. Byte-for-byte identical output to
/// [`build_begin_request_framed`] (the MEM1 gate covers this). `out`'s prior
/// contents are wiped by `clear()` before the full packet is written, so a
/// recycled buffer leaks nothing of the previous request.
pub fn build_begin_request_framed_into<K, V, HN, HV>(
    out: &mut BytesMut,
    env: &[(K, V)],
    special_env: &[(SpecialEnvType, String, String)],
    headers: &[(HN, HV)],
    req_body_len: i32,
) where
    K: AsRef<str>,
    V: AsRef<str>,
    HN: AsRef<str>,
    HV: AsRef<str>,
{
    out.clear();
    let est = PACKET_HEADER_LEN
        + REQ_HEADER_LEN
        + env.len() * 36
        + special_env.len() * 24
        + headers.len() * 64
        + HEADER_INDEX_LEN;
    out.reserve(est);
    out.put_bytes(0, PACKET_HEADER_LEN); // packet-header placeholder, backfilled below
    build_begin_request_into(out, env, special_env, headers, req_body_len);
    // Backfill the 8-byte packet header now that `total` is known (mirrors
    // `encode_frame`): "LS", type, endian, then the little-endian total length.
    let total = out.len() as u32;
    out[0] = VERSION_B0;
    out[1] = VERSION_B1;
    out[2] = PacketType::BeginRequest as u8;
    out[3] = HOST_LSAPI_ENDIAN;
    out[4..8].copy_from_slice(&total.to_le_bytes());
}

/// Core BEGIN_REQUEST body builder, writing into `out`. `out` may already hold the
/// 8-byte packet header (framed form) or be empty (legacy body-only form). All
/// LSAPI offsets are absolute *including* the packet header; `body_start` (the
/// length of `out` on entry) lets the same offset math serve both callers.
fn build_begin_request_into<K, V, HN, HV>(
    out: &mut BytesMut,
    env: &[(K, V)],
    special_env: &[(SpecialEnvType, String, String)],
    headers: &[(HN, HV)],
    req_body_len: i32,
) where
    K: AsRef<str>,
    V: AsRef<str>,
    HN: AsRef<str>,
    HV: AsRef<str>,
{
    // CGI vars go in the normal env table; php.ini overrides (php_value/...) go in
    // the special-env table (cntSpecialEnv) — lsphp reads ini overrides ONLY there.
    let body_start = out.len();

    // --- fixed req_header int32 fields ---
    // We fill m_*Off after we know where each value lands. Reserve 36 bytes now.
    let header_fields_start = out.len(); // == body_start
    out.put_bytes(0, REQ_HEADER_LEN - PACKET_HEADER_LEN); // 36 bytes of req_header

    // Absolute packet offset of buffer index `idx` = PACKET_HEADER_LEN + (idx -
    // body_start). For the framed form (body_start == 8) this is just `idx`; for
    // the legacy form (body_start == 0) it is `8 + idx`, matching the codec prefix.
    let abs = |idx: usize| (PACKET_HEADER_LEN + idx - body_start) as i32;

    let mut script_file_off = 0i32;
    let mut script_name_off = 0i32;
    let mut query_string_off = 0i32;
    let mut request_method_off = 0i32;

    // --- special-env table (php.ini overrides) ---
    // Same wire encoding as the env table, but each KEY is prefixed with `\x01`
    // then the permission byte (`\x02` user / `\x04` admin) per LiteSpeed's
    // encoding and lsphp's `alter_ini` (`'\001'==*pKey` then `*(pKey+1)==4`). The
    // length prefix counts the 2 control bytes + name + NUL. `parseEnv` always
    // consumes the 4-NUL terminator, so emit it even when the count is zero.
    for (ty, name, value) in special_env {
        let nb = name.as_bytes();
        let vb = value.as_bytes();
        let klen = 2 + nb.len() + 1; // \x01 + type + name + NUL
        let vlen = vb.len() + 1;
        debug_assert!(
            klen <= u16::MAX as usize && vlen <= u16::MAX as usize,
            "LSAPI special-env field exceeds u16 length prefix (klen={klen}, vlen={vlen})"
        );
        out.put_u16(klen as u16); // big-endian
        out.put_u16(vlen as u16); // big-endian
        out.put_u8(0x01);
        out.put_u8(*ty as u8);
        out.extend_from_slice(nb);
        out.put_u8(0);
        out.extend_from_slice(vb);
        out.put_u8(0);
    }
    out.put_bytes(0, 4);

    // --- env table ---
    for (k, v) in env {
        let kb = k.as_ref().as_bytes();
        let vb = v.as_ref().as_bytes();
        // lengths include the trailing NUL
        let klen = kb.len() + 1;
        let vlen = vb.len() + 1;
        // (#3) The u16 length prefix would silently wrap (desyncing lsphp's env
        // parser) past 65535. The LSAPI handler rejects such requests with 431
        // before reaching here; this assertion catches any caller that bypasses
        // that guard during testing.
        debug_assert!(
            klen <= u16::MAX as usize && vlen <= u16::MAX as usize,
            "LSAPI env field exceeds u16 length prefix (klen={klen}, vlen={vlen})"
        );
        out.put_u16(klen as u16); // big-endian
        out.put_u16(vlen as u16); // big-endian
        out.extend_from_slice(kb);
        out.put_u8(0);
        let value_pos = out.len(); // absolute buffer index of the value bytes
        out.extend_from_slice(vb);
        out.put_u8(0);

        match k.as_ref() {
            "SCRIPT_FILENAME" => script_file_off = abs(value_pos),
            "SCRIPT_NAME" => script_name_off = abs(value_pos),
            "QUERY_STRING" => query_string_off = abs(value_pos),
            "REQUEST_METHOD" => request_method_off = abs(value_pos),
            _ => {}
        }
    }
    // env table terminator
    out.put_bytes(0, 4);

    // --- 8-byte alignment for the http_header_index, measured on the whole packet ---
    let cur_abs = PACKET_HEADER_LEN + out.len() - body_start;
    let pad = (8 - (cur_abs % 8)) % 8;
    out.put_bytes(0, pad);

    // --- build the raw HTTP header block + the index over it -----------------
    // The header block is a synthetic, original encoding of the request headers
    // as `Name: value\r\n` lines. lsphp only ever indexes into the VALUE bytes
    // (offset/length per header); the name text and CRLF are scratch. Offsets in
    // the index/offset table are relative to the START of this block, exactly as
    // in OLS. A well-known header's VALUE can never land at block offset 0 (it is
    // always preceded by `Name: `), so PHP's `off == 0 => absent` test for the
    // index slots stays correct without any sentinel; unknown headers are driven
    // by m_cntUnknownHeaders, not an offset-zero sentinel.
    // (#327) Single-buffer encode: the tables are RESERVED in `out` first (their
    // sizes are computable up front after one no-copy counting pass), the raw
    // header block is appended DIRECTLY to `out`, and the tables are backfilled
    // in place - eliminating the intermediate hdr_block BytesMut + wholesale
    // memcpy this function used despite its single-allocation contract.

    // Per-slot (len, off) for the 25 well-known headers (off 0 == absent).
    let mut known: [(u16, i32); KNOWN_HEADER_COUNT] = [(0, 0); KNOWN_HEADER_COUNT];
    // Pass 1: count unknown headers so the offset-table reservation is exact.
    let unknown_cnt = headers
        .iter()
        .filter(|(name, _)| known_header_index(name.as_ref()).is_none())
        .count();
    let unknown_table_len = unknown_cnt * 16; // (nameOff, nameLen, valueOff, valueLen)

    // --- reserve: lsapi_http_header_index + lsapi_header_offset[unknown] ------
    let index_start = out.len();
    out.put_bytes(0, HEADER_INDEX_LEN + unknown_table_len);

    // --- raw HTTP header block, encoded straight into `out` --------------------
    // Offsets in the tables are RELATIVE TO THE START OF THE BLOCK (exactly as in
    // OLS), so track them from zero while writing at the absolute tail.
    let block_abs_start = out.len();
    let mut block_rel: i32 = 0;
    let mut unknown_written = 0usize;
    let mut unknown_wpos = index_start + HEADER_INDEX_LEN;
    for (name, value) in headers {
        let nb = name.as_ref().as_bytes();
        let vb = value.as_ref().as_bytes();
        let name_off = block_rel;
        out.extend_from_slice(nb);
        out.extend_from_slice(b": ");
        block_rel += (nb.len() + 2) as i32;
        let value_off = block_rel;
        out.extend_from_slice(vb);
        // The byte right after the value must be present & writable: lsphp may
        // overwrite it with NUL (LSAPI_GetHeader_r). Our `\r\n` provides it.
        out.extend_from_slice(b"\r\n");
        block_rel += (vb.len() + 2) as i32;

        match known_header_index(name.as_ref()) {
            // Last occurrence wins, matching how a single indexed slot behaves.
            Some(i) => {
                // (#3) The known-header index `len` slot is also a u16; a value
                // over 65535 bytes would truncate it. Guarded by the handler's
                // 431 reject; assert in debug for any bypassing caller.
                debug_assert!(
                    vb.len() <= u16::MAX as usize,
                    "LSAPI known-header value exceeds u16 len slot ({})",
                    vb.len()
                );
                known[i] = (vb.len() as u16, value_off);
            }
            None => {
                // Write the unknown entry straight into its reserved slot.
                for f in [name_off, nb.len() as i32, value_off, vb.len() as i32] {
                    out[unknown_wpos..unknown_wpos + 4].copy_from_slice(&f.to_le_bytes());
                    unknown_wpos += 4;
                }
                unknown_written += 1;
            }
        }
    }
    let http_header_len = block_rel;
    debug_assert_eq!(unknown_written, unknown_cnt);
    debug_assert_eq!(
        unknown_wpos,
        index_start + HEADER_INDEX_LEN + unknown_table_len
    );

    // --- backfill lsapi_http_header_index: u16 len[25], 2 pad, i32 off[25] ----
    {
        let mut w = index_start;
        for (len, _off) in &known {
            out[w..w + 2].copy_from_slice(&len.to_le_bytes());
            w += 2;
        }
        w += 2; // alignment padding before the i32 array
        for (_len, off) in &known {
            out[w..w + 4].copy_from_slice(&off.to_le_bytes());
            w += 4;
        }
        debug_assert_eq!(w - index_start, HEADER_INDEX_LEN);
    }

    // NOTE: the request body is intentionally NOT appended here; it follows the
    // packet on the wire as raw bytes (see the doc comment above).

    // --- backfill the req_header int32 fields (little-endian) ---
    let mut fields = [0i32; 9];
    // [0]=httpHeaderLen, [1]=reqBodyLen, [2]=scriptFileOff, [3]=scriptNameOff,
    // [4]=queryStringOff, [5]=requestMethodOff, [6]=cntUnknownHeaders,
    // [7]=cntEnv, [8]=cntSpecialEnv
    fields[0] = http_header_len;
    // `req_body_len` is already the on-wire m_reqBodyLen: a concrete length (>= 0)
    // or the -2 sentinel (lsphp re-reads Content-Length from the raw header block).
    // Never pass -1: lsphp treats it as a zero-length body, not stream-to-EOF.
    fields[1] = req_body_len;
    fields[2] = script_file_off;
    fields[3] = script_name_off;
    fields[4] = query_string_off;
    fields[5] = request_method_off;
    fields[6] = unknown_cnt as i32;
    fields[7] = env.len() as i32;
    fields[8] = special_env.len() as i32;
    for (i, f) in fields.iter().enumerate() {
        let at = header_fields_start + i * 4;
        out[at..at + 4].copy_from_slice(&f.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn begin_request_special_env_roundtrips() {
        // php_value auto_prepend_file (user) + php_admin_value open_basedir (admin).
        let env = vec![("REQUEST_METHOD".to_string(), "GET".to_string())];
        let special_env = vec![
            (
                SpecialEnvType::User,
                "auto_prepend_file".to_string(),
                "/web/pagecache.php".to_string(),
            ),
            (
                SpecialEnvType::Admin,
                "open_basedir".to_string(),
                "/safe".to_string(),
            ),
        ];
        let body = build_begin_request(&env, &special_env, &[] as &[(&str, &str)], 0);
        let rd = |i: usize| i32::from_le_bytes([body[i], body[i + 1], body[i + 2], body[i + 3]]);
        assert_eq!(rd(28), env.len() as i32, "cnt_env");
        assert_eq!(rd(32), special_env.len() as i32, "cnt_special");

        // The special-env table begins right after the 36-byte req-header fields.
        let mut p = &body[REQ_HEADER_LEN - PACKET_HEADER_LEN..];
        for (ty, name, value) in &special_env {
            let klen = ((p[0] as usize) << 8) | p[1] as usize;
            let vlen = ((p[2] as usize) << 8) | p[3] as usize;
            p = &p[4..];
            assert_eq!(p[0], 0x01, "special-env key must start with 0x01");
            assert_eq!(p[1], *ty as u8, "permission byte (0x02 user / 0x04 admin)");
            assert_eq!(&p[2..klen - 1], name.as_bytes(), "php.ini key name");
            assert_eq!(p[klen - 1], 0, "key NUL");
            p = &p[klen..];
            assert_eq!(&p[..vlen - 1], value.as_bytes(), "php.ini value");
            assert_eq!(p[vlen - 1], 0, "val NUL");
            p = &p[vlen..];
        }
        assert_eq!(&p[..4], b"\0\0\0\0", "special-env table terminator");
    }

    #[test]
    fn begin_request_env_table_roundtrips() {
        let env = vec![
            ("REQUEST_METHOD".to_string(), "GET".to_string()),
            ("SCRIPT_FILENAME".to_string(), "/web/index.php".to_string()),
            ("SCRIPT_NAME".to_string(), "/index.php".to_string()),
            ("QUERY_STRING".to_string(), "a=1&b=2".to_string()),
            ("HTTP_HOST".to_string(), "example.com".to_string()),
        ];
        let req_body = b"name=value";
        let body = build_begin_request_body(&env, req_body.len() as i32);

        // Re-parse exactly like lsapilib's parseRequest does.
        // The body we built is everything *after* the 8-byte packet header, so
        // absolute offsets recorded inside are PACKET_HEADER_LEN + body-relative.
        let full_packet_len = PACKET_HEADER_LEN + body.len();
        // req-header int32 fields are at the start of `body` (offset 8..44 absolute).
        let rd = |b: &[u8], i: usize| i32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
        let http_header_len = rd(&body, 0);
        let req_body_len = rd(&body, 4);
        let script_file_off = rd(&body, 8);
        let script_name_off = rd(&body, 12);
        let query_string_off = rd(&body, 16);
        let request_method_off = rd(&body, 20);
        let cnt_unknown = rd(&body, 24);
        let cnt_env = rd(&body, 28);
        let cnt_special = rd(&body, 32);

        assert_eq!(http_header_len, 0);
        assert_eq!(req_body_len, req_body.len() as i32);
        assert_eq!(cnt_unknown, 0);
        assert_eq!(cnt_env, env.len() as i32);
        assert_eq!(cnt_special, 0);

        // Reconstruct the full packet to resolve absolute offsets.
        let mut full = Vec::with_capacity(full_packet_len);
        full.extend_from_slice(&[VERSION_B0, VERSION_B1, PacketType::BeginRequest as u8, 0]);
        full.extend_from_slice(&(full_packet_len as u32).to_le_bytes());
        full.extend_from_slice(&body);

        let read_cstr = |off: i32| -> String {
            let off = off as usize;
            let end = full[off..].iter().position(|&b| b == 0).unwrap() + off;
            String::from_utf8(full[off..end].to_vec()).unwrap()
        };
        assert_eq!(read_cstr(script_file_off), "/web/index.php");
        assert_eq!(read_cstr(script_name_off), "/index.php");
        assert_eq!(read_cstr(query_string_off), "a=1&b=2");
        assert_eq!(read_cstr(request_method_off), "GET");

        // Walk the env table the way parseEnv does and confirm every pair decodes.
        // The special-env table (count 0) comes first as a bare 4-NUL terminator.
        let mut p = &body[REQ_HEADER_LEN - PACKET_HEADER_LEN..];
        assert_eq!(&p[..4], b"\0\0\0\0", "special-env table terminator");
        p = &p[4..];
        let mut seen = std::collections::HashMap::new();
        for _ in 0..cnt_env {
            let klen = ((p[0] as usize) << 8) + p[1] as usize;
            let vlen = ((p[2] as usize) << 8) + p[3] as usize;
            p = &p[4..];
            let key = String::from_utf8(p[..klen - 1].to_vec()).unwrap();
            assert_eq!(p[klen - 1], 0, "key must be NUL terminated");
            p = &p[klen..];
            let val = String::from_utf8(p[..vlen - 1].to_vec()).unwrap();
            assert_eq!(p[vlen - 1], 0, "value must be NUL terminated");
            p = &p[vlen..];
            seen.insert(key, val);
        }
        assert_eq!(&p[..4], b"\0\0\0\0", "env table must end with 4 NULs");
        assert_eq!(seen.get("HTTP_HOST").unwrap(), "example.com");
        assert_eq!(seen.get("REQUEST_METHOD").unwrap(), "GET");
    }

    /// Parse the BEGIN_REQUEST body exactly like lsphp's `parseRequest` +
    /// `GetHeaderVar`/`LSAPI_ForeachOrgHeader_r` would, and assert every request
    /// header is recoverable from the index / unknown-header table.
    #[test]
    fn begin_request_carries_request_headers_in_index() {
        let env = vec![
            ("REQUEST_METHOD".to_string(), "GET".to_string()),
            ("SCRIPT_FILENAME".to_string(), "/web/index.php".to_string()),
            ("SCRIPT_NAME".to_string(), "/index.php".to_string()),
            ("QUERY_STRING".to_string(), String::new()),
        ];
        // Mix of well-known (host, user-agent, cookie) and unknown (x-custom) headers.
        let headers = vec![
            ("host".to_string(), "forum.example".to_string()),
            ("user-agent".to_string(), "curl/8.5".to_string()),
            ("cookie".to_string(), "sid=abc123".to_string()),
            ("x-custom-thing".to_string(), "hello-world".to_string()),
            ("accept".to_string(), "*/*".to_string()),
        ];
        let body = build_begin_request(&env, &[], &headers, 0);

        // Reconstruct the full packet (offsets are absolute from packet start; the
        // header-block offsets are relative to the block, resolved below).
        let full_len = PACKET_HEADER_LEN + body.len();
        let mut full = Vec::with_capacity(full_len);
        full.extend_from_slice(&[VERSION_B0, VERSION_B1, PacketType::BeginRequest as u8, 0]);
        full.extend_from_slice(&(full_len as u32).to_le_bytes());
        full.extend_from_slice(&body);

        // req_header int32s start at packet offset 8.
        let rd = |i: usize| i32::from_le_bytes([full[i], full[i + 1], full[i + 2], full[i + 3]]);
        let http_header_len = rd(8) as usize;
        let cnt_unknown = rd(8 + 24) as usize; // m_cntUnknownHeaders
        assert_eq!(cnt_unknown, 1, "x-custom-thing is the only unknown header");

        // Walk the env tables to find where the header index begins (parseRequest
        // skips the 44-byte req_header, both env tables, then 8-aligns).
        // Easier: recompute the same way build_begin_request laid it out.
        // body cursor starts after the 36-byte req_header tail.
        let mut p = REQ_HEADER_LEN - PACKET_HEADER_LEN;
        // special-env terminator
        assert_eq!(&body[p..p + 4], b"\0\0\0\0");
        p += 4;
        // env table
        for _ in 0..env.len() {
            let klen = ((body[p] as usize) << 8) + body[p + 1] as usize;
            let vlen = ((body[p + 2] as usize) << 8) + body[p + 3] as usize;
            p += 4 + klen + vlen;
        }
        assert_eq!(&body[p..p + 4], b"\0\0\0\0", "env terminator");
        p += 4;
        // 8-byte align relative to packet start.
        let abs = PACKET_HEADER_LEN + p;
        p += (8 - (abs % 8)) % 8;

        // lsapi_http_header_index: u16 len[25], 2 pad, i32 off[25].
        let index_at = p;
        let mut known_len = [0u16; KNOWN_HEADER_COUNT];
        let mut known_off = [0i32; KNOWN_HEADER_COUNT];
        for i in 0..KNOWN_HEADER_COUNT {
            known_len[i] = u16::from_le_bytes([body[index_at + i * 2], body[index_at + i * 2 + 1]]);
        }
        let off_at = index_at + KNOWN_HEADER_COUNT * 2 + 2;
        for i in 0..KNOWN_HEADER_COUNT {
            known_off[i] =
                i32::from_le_bytes(body[off_at + i * 4..off_at + i * 4 + 4].try_into().unwrap());
        }
        // unknown header offset table
        let unk_at = index_at + HEADER_INDEX_LEN;
        let unk: [i32; 4] = {
            let mut a = [0i32; 4];
            for (j, slot) in a.iter_mut().enumerate() {
                *slot = i32::from_le_bytes(
                    body[unk_at + j * 4..unk_at + j * 4 + 4].try_into().unwrap(),
                );
            }
            a
        };
        // raw header block follows the unknown table.
        let block_at = unk_at + cnt_unknown * HEADER_OFFSET_LEN;
        assert_eq!(
            block_at + http_header_len,
            body.len(),
            "block ends the body"
        );
        let block = &body[block_at..block_at + http_header_len];

        // Resolve a well-known header value the way GetHeaderVar does.
        let get_known = |name: &str| -> Option<String> {
            let i = known_header_index(name).unwrap();
            let off = known_off[i];
            if off == 0 {
                return None;
            }
            let off = off as usize;
            let len = known_len[i] as usize;
            Some(String::from_utf8(block[off..off + len].to_vec()).unwrap())
        };
        assert_eq!(get_known("host").as_deref(), Some("forum.example"));
        assert_eq!(get_known("HOST").as_deref(), Some("forum.example")); // case-insensitive
        assert_eq!(get_known("user-agent").as_deref(), Some("curl/8.5"));
        assert_eq!(get_known("cookie").as_deref(), Some("sid=abc123"));
        assert_eq!(get_known("accept").as_deref(), Some("*/*"));
        assert_eq!(get_known("referer"), None, "absent header => offset 0");

        // Resolve the unknown header (name + value) from its offset table entry.
        let [name_off, name_len, val_off, val_len] = unk;
        let uname =
            String::from_utf8(block[name_off as usize..(name_off + name_len) as usize].to_vec())
                .unwrap();
        let uval =
            String::from_utf8(block[val_off as usize..(val_off + val_len) as usize].to_vec())
                .unwrap();
        assert_eq!(uname, "x-custom-thing");
        assert_eq!(uval, "hello-world");

        // Every PRESENT well-known header must have a non-zero value offset, since
        // PHP's index lookup treats off == 0 as "absent". A known value can never
        // land at offset 0 because it is always preceded by `Name: `.
        for name in ["host", "user-agent", "cookie", "accept"] {
            let i = known_header_index(name).unwrap();
            assert!(known_off[i] > 0, "present header {name} must have off > 0");
        }
        // Unknown-header offsets are used directly (count-driven), so val_off here
        // is simply the correct location; in this fixture it is well past 0.
        let _ = name_off;
        assert!(val_off > 0);
    }

    #[test]
    fn framed_packet_byte_identical_to_legacy_body_plus_header() {
        // MEM1 correctness gate: build_begin_request_framed must produce EXACTLY
        // the bytes the old `encode_frame(build_begin_request(..))` did — the legacy
        // body with the 8-byte packet header ("LS", type, host-endian flag, then the
        // little-endian total length) prepended. Cover several req_body_len values
        // (incl. the -2 stream sentinel) and verify offsets still resolve.
        let env = vec![
            ("REQUEST_METHOD".to_string(), "POST".to_string()),
            ("SCRIPT_FILENAME".to_string(), "/web/index.php".to_string()),
            ("SCRIPT_NAME".to_string(), "/index.php".to_string()),
            ("QUERY_STRING".to_string(), "a=1&b=2".to_string()),
        ];
        let headers = vec![
            ("host".to_string(), "forum.example".to_string()),
            ("user-agent".to_string(), "curl/8.5".to_string()),
            ("cookie".to_string(), "sid=abc123".to_string()),
            ("x-custom-thing".to_string(), "hello-world".to_string()),
            ("accept".to_string(), "*/*".to_string()),
        ];
        for req_body_len in [0i32, 17, -2] {
            let body = build_begin_request(&env, &[], &headers, req_body_len);
            let total = (PACKET_HEADER_LEN + body.len()) as u32;
            let mut expected = Vec::with_capacity(total as usize);
            expected.extend_from_slice(&[
                VERSION_B0,
                VERSION_B1,
                PacketType::BeginRequest as u8,
                HOST_LSAPI_ENDIAN,
            ]);
            expected.extend_from_slice(&total.to_le_bytes());
            expected.extend_from_slice(&body);

            let framed = build_begin_request_framed(&env, &[], &headers, req_body_len);
            assert_eq!(
                framed.as_ref(),
                expected.as_slice(),
                "framed packet must equal legacy body + header (req_body_len={req_body_len})"
            );
        }
    }

    #[test]
    fn legacy_env_only_builder_has_zeroed_index() {
        // build_begin_request_body keeps the old env-only behavior (no headers):
        // httpHeaderLen == 0, cntUnknownHeaders == 0, zeroed index.
        let env = vec![("REQUEST_METHOD".to_string(), "GET".to_string())];
        let body = build_begin_request_body(&env, 0);
        let rd = |i: usize| i32::from_le_bytes([body[i], body[i + 1], body[i + 2], body[i + 3]]);
        // fields start at body offset 0 (== packet offset 8).
        assert_eq!(rd(0), 0, "httpHeaderLen == 0");
        assert_eq!(rd(24), 0, "cntUnknownHeaders == 0");
    }
}
