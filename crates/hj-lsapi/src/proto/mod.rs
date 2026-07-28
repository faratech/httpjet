//! LSAPI wire protocol: constants, packet header, codec, and frame types.
//!
//! Everything here is transcribed from the PHP `litespeed` SAPI sources vendored
//! under `crates/hj-lsapi/vendor/` (`lsapidef.h`, `lsapilib.c`, BSD-3-Clause).
//!
//! This module is split into two halves over the shared constants below:
//!   - [`frame`] — the wire [`LsapiFrame`] type, the [`LsapiCodec`]
//!     (`Encoder`/`Decoder`) that adds/strips the 8-byte packet header, and the
//!     RESP_HEADER parser ([`RespHeader`] / [`parse_resp_header`]).
//!   - [`builder`] — the BEGIN_REQUEST packet builders
//!     ([`build_begin_request`], [`build_begin_request_body`],
//!     [`build_begin_request_framed`]).
//!
//! # CONSTANTS (verbatim from `lsapidef.h`)
//!
//! ## Magic / version
//! - `LSAPI_VERSION_B0 = b'L'`, `LSAPI_VERSION_B1 = b'S'` — every packet starts `L S`.
//!
//! ## `m_flag` endianness bit
//! - `LSAPI_ENDIAN_LITTLE = 0`, `LSAPI_ENDIAN_BIG = 1`, `LSAPI_ENDIAN_BIT = 1`.
//! - On x86/x86_64 `LSAPI_ENDIAN = LSAPI_ENDIAN_LITTLE = 0`; the flag byte equals
//!   the endianness the *sender* used for the 4-byte length. The receiver compares
//!   its own `LSAPI_ENDIAN` to `(m_flag & LSAPI_ENDIAN_BIT)` and byte-swaps the
//!   length (and all the req-header int32s) if they differ. We always emit
//!   little-endian (flag bit 0) and we honor the bit when decoding.
//!
//! ## Packet types (`m_type`)
//! ```text
//! LSAPI_BEGIN_REQUEST   = 1   (web server -> php: full request packet)
//! LSAPI_ABORT_REQUEST   = 2   (web server -> php: client went away)
//! LSAPI_RESP_HEADER     = 3   (php -> web server: status + response headers)
//! LSAPI_RESP_STREAM     = 4   (php -> web server: a chunk of the response body)
//! LSAPI_RESP_END        = 5   (php -> web server: end of response, body=empty)
//! LSAPI_STDERR_STREAM   = 6   (php -> web server: raw stderr text)
//! LSAPI_REQ_RECEIVED    = 7   (php -> web server: ACK, only with ACCEPT_NOTIFY)
//! LSAPI_CONN_CLOSE      = 8   (either side: close this connection)
//! LSAPI_INTERNAL_ERROR  = 9
//! ```
//!
//! ## Packet header — 8 bytes, `struct lsapi_packet_header`
//! ```text
//! off 0: char  m_versionB0   = 'L'
//! off 1: char  m_versionB1   = 'S'
//! off 2: char  m_type        (one of the LSAPI_* type constants)
//! off 3: char  m_flag        (endianness bit + reserved)
//! off 4: int32 m_packetLen   (TOTAL packet length INCLUDING these 8 header bytes)
//! ```
//! The length field **includes the 8-byte header** (see `lsapi_buildPacketHeader`
//! in lsapilib.c, e.g. `RESP_END` is sent with `len = LSAPI_PACKET_HEADER_LEN = 8`).
//!
//! ## BEGIN_REQUEST body — the full request packet (`struct lsapi_req_header`)
//! Following the 8-byte packet header (so absolute offsets are measured from the
//! very start of the packet buffer), `lsapi_req_header` continues with 9 int32s:
//! ```text
//! off  8: int32 m_httpHeaderLen     (length of the raw HTTP header block; we use 0)
//! off 12: int32 m_reqBodyLen        (request body length, -1 if unknown/chunked)
//! off 16: int32 m_scriptFileOff     (abs offset to SCRIPT_FILENAME value bytes)
//! off 20: int32 m_scriptNameOff     (abs offset to SCRIPT_NAME value bytes)
//! off 24: int32 m_queryStringOff    (abs offset to QUERY_STRING value bytes)
//! off 28: int32 m_requestMethodOff  (abs offset to REQUEST_METHOD value bytes)
//! off 32: int32 m_cntUnknownHeaders (count of lsapi_header_offset entries; we use 0)
//! off 36: int32 m_cntEnv            (count of CGI env pairs)
//! off 40: int32 m_cntSpecialEnv     (count of special env pairs; we use 0)
//! ```
//! So the fixed header is **44 bytes** (8 + 9*4). It is then followed, in order, by:
//!   1. special-env table (`m_cntSpecialEnv` pairs) + 4 NUL terminator bytes
//!   2. env table          (`m_cntEnv` pairs)          + 4 NUL terminator bytes
//!   3. 8-byte alignment padding
//!   4. `lsapi_http_header_index` (known-header len/off table, offsets relative
//!      to the raw header block; slot off == 0 means the header is absent)
//!   5. `lsapi_header_offset` * m_cntUnknownHeaders (one per non-well-known header)
//!   6. raw HTTP header block (m_httpHeaderLen bytes)
//!   7. request body (m_reqBodyLen bytes) — NOT in this packet; sent after it
//!
//! ## Why the header block + index matter (lsphp behavior)
//! lsphp resolves request headers for PHP (`$_SERVER['HTTP_*']`,
//! `getallheaders()`, `apache_request_headers()`) **exclusively** from the header
//! index + unknown-header table over the raw header block — see `GetHeaderVar` /
//! `LSAPI_GetEnv_r` / `LSAPI_ForeachOrgHeader_r` in lsapilib.c. It never reads
//! request headers from the CGI env table. So sending `HTTP_*` only in the env
//! table makes them invisible to PHP. [`build_begin_request`] emits the index +
//! block; [`build_begin_request_body`] is the legacy env-only form (no headers).
//! `CONTENT_TYPE`/`CONTENT_LENGTH` are also resolved via the index slots 6/7.
//!
//! ## Env-table pair encoding (`parseEnv` in lsapilib.c)
//! Each key/value pair is:
//! ```text
//! u16 keyLen   (BIG-ENDIAN; INCLUDES the trailing NUL)
//! u16 valLen   (BIG-ENDIAN; INCLUDES the trailing NUL)
//! key bytes    (keyLen bytes, last byte == 0)
//! value bytes  (valLen bytes, last byte == 0)
//! ```
//! i.e. PHP records `keyLen-1` / `valLen-1` as the real string lengths. After the
//! last pair the table is terminated by 4 NUL bytes (`"\0\0\0\0"`). The two length
//! prefixes are read as unsigned bytes shifted `(<<8)+next`, hence **big-endian**,
//! independent of the packet's endianness flag.
//!
//! ## RESP_HEADER body (`struct lsapi_resp_header` / `lsapi_resp_info`)
//! After the 8-byte packet header:
//! ```text
//! int32 m_cntHeaders   (number of response header lines)
//! int32 m_status       (HTTP status code, e.g. 200)
//! u16   len[0..m_cntHeaders]   (per-header byte length INCLUDING trailing NUL)
//! bytes                         (m_cntHeaders concatenated "Name: Value\0" strings)
//! ```
//! The int32s and the u16 length array follow the packet's endianness flag.
//! Each header line is `Name: Value` with a single trailing NUL; `len[i]` counts
//! that NUL (see `LSAPI_AppendRespHeader2_r`, `len = nameLen + valLen + 1; ++len`).
//!
//! ## RESP_STREAM / STDERR_STREAM body
//! Raw bytes, no inner framing. Body length = `m_packetLen - 8`.
//!
//! ## RESP_END / CONN_CLOSE / REQ_RECEIVED / ABORT
//! Header-only packets (`m_packetLen == 8`, empty body).
//!
//! ## fd handoff (lsphp spawn)
//! `LSAPI_SOCK_FILENO = 0`: the listening socket is handed to the spawned `lsphp`
//! on **file descriptor 0** (stdin). `LSAPI_InitRequest(&g_req, LSAPI_SOCK_FILENO)`
//! accepts on fd 0; if that fd is stdin it `dup()`s it and reopens `/dev/null` on
//! fd 0. So the supervisor must `dup2(listen_fd, 0)` before `exec`.

mod builder;
mod frame;

pub use builder::{
    SpecialEnvType, build_begin_request, build_begin_request_body, build_begin_request_framed,
    build_begin_request_framed_into,
};
pub use frame::{LsapiCodec, LsapiFrame, RespHeader, parse_resp_header};

/// Packet magic byte 0 (`'L'`).
pub const VERSION_B0: u8 = b'L';
/// Packet magic byte 1 (`'S'`).
pub const VERSION_B1: u8 = b'S';

/// `m_flag` endianness bit mask.
pub const ENDIAN_BIT: u8 = 1;
/// Little-endian flag value (what we always emit on x86/x86_64).
pub const ENDIAN_LITTLE: u8 = 0;
/// Big-endian flag value.
pub const ENDIAN_BIG: u8 = 1;
/// The `m_flag` endianness value lsphp's `lsapilib` uses on THIS host, matching
/// the compile-time `LSAPI_ENDIAN` macro in lsapidef.h:
/// `#if defined(__i386__)||defined(__x86_64) → LITTLE  #else → BIG`.
/// It is LITTLE only on x86/x86_64 and BIG on every other arch (incl. aarch64) —
/// EVEN THOUGH aarch64 is little-endian and writes the length in LE bytes; the
/// macro just predates non-x86 little-endian targets. lsphp sets the packet flag
/// to this value, and a co-located receiver compares against the SAME value
/// (swapping only on a true mismatch). We must use this — not a hardcoded
/// LITTLE — or on aarch64 we wrongly swap lsphp's LE length → "implausible packet
/// length". No-op on x86 (equals ENDIAN_LITTLE there).
pub const HOST_LSAPI_ENDIAN: u8 = if cfg!(any(target_arch = "x86", target_arch = "x86_64")) {
    ENDIAN_LITTLE
} else {
    ENDIAN_BIG
};

/// Fixed packet header length (bytes). The `m_packetLen` field counts this in.
pub const PACKET_HEADER_LEN: usize = 8;

/// Total bytes of the fixed `lsapi_req_header` (8-byte pkt header + 9 int32s).
pub const REQ_HEADER_LEN: usize = 44;

/// `sizeof(struct lsapi_http_header_index)` as the C compiler lays it out:
/// `uint16_t[25]` (50) + 2 bytes alignment padding + `int32_t[25]` (100) = 152.
pub const HEADER_INDEX_LEN: usize = 152;

/// Maximum data packet body length used by the reference lib (`LSAPI_MAX_DATA_PACKET_LEN`).
pub const MAX_DATA_PACKET_LEN: usize = 16384;

/// File descriptor the listen socket is handed to lsphp on (`LSAPI_SOCK_FILENO`).
pub const SOCK_FILENO: i32 = 0;

/// Number of "well-known" request headers LSAPI indexes directly, i.e.
/// `H_TRANSFER_ENCODING + 1` (the `H_*` enum runs 0..=24). The
/// `lsapi_http_header_index` carries one `(len,off)` slot per entry.
pub const KNOWN_HEADER_COUNT: usize = 25;

/// The HTTP header names for each `H_*` index slot, in the exact `lsapidef.h`
/// enum order (`H_ACCEPT = 0` .. `H_TRANSFER_ENCODING = 24`). These are FACTS of
/// the wire format: lsphp's `GetHeaderVar`/`LSAPI_GetHeader_r` look up a request
/// header by matching this fixed slot, so a header sent in one of these slots is
/// what PHP returns for the corresponding `$_SERVER` / `getallheaders()` entry.
///
/// Note: `Content-Type` (slot 6) and `Content-Length` (slot 7) are indexed here
/// too — PHP resolves `CONTENT_TYPE`/`CONTENT_LENGTH` via the index, not the env
/// table, for these two (see `CGI_HEADERS` in lsapilib.c).
pub const KNOWN_HEADER_NAMES: [&str; KNOWN_HEADER_COUNT] = [
    "accept",              // H_ACCEPT = 0
    "accept-charset",      // H_ACC_CHARSET
    "accept-encoding",     // H_ACC_ENCODING
    "accept-language",     // H_ACC_LANG
    "authorization",       // H_AUTHORIZATION
    "connection",          // H_CONNECTION
    "content-type",        // H_CONTENT_TYPE
    "content-length",      // H_CONTENT_LENGTH
    "cookie",              // H_COOKIE
    "cookie2",             // H_COOKIE2
    "host",                // H_HOST
    "pragma",              // H_PRAGMA
    "referer",             // H_REFERER
    "user-agent",          // H_USERAGENT
    "cache-control",       // H_CACHE_CTRL
    "if-modified-since",   // H_IF_MODIFIED_SINCE
    "if-match",            // H_IF_MATCH
    "if-none-match",       // H_IF_NO_MATCH
    "if-range",            // H_IF_RANGE
    "if-unmodified-since", // H_IF_UNMOD_SINCE
    "keep-alive",          // H_KEEP_ALIVE
    "range",               // H_RANGE
    "x-forwarded-for",     // H_X_FORWARDED_FOR
    "via",                 // H_VIA
    "transfer-encoding",   // H_TRANSFER_ENCODING = 24
];

/// `sizeof(struct lsapi_header_offset)` — four int32s (`nameOff, nameLen,
/// valueOff, valueLen`), used for each "unknown" (non-well-known) header.
pub const HEADER_OFFSET_LEN: usize = 16;

/// Return the `H_*` index slot for a request header name (ASCII case-insensitive),
/// or `None` if it is not one of the well-known headers.
pub fn known_header_index(name: &str) -> Option<usize> {
    KNOWN_HEADER_NAMES
        .iter()
        .position(|known| known.eq_ignore_ascii_case(name))
}

/// Sanity ceiling on a single inbound packet so a corrupt length can't OOM us.
pub const MAX_PACKET_LEN: usize = 1024 * 1024;

/// LSAPI packet type byte (`m_type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    BeginRequest = 1,
    AbortRequest = 2,
    RespHeader = 3,
    RespStream = 4,
    RespEnd = 5,
    StderrStream = 6,
    ReqReceived = 7,
    ConnClose = 8,
    InternalError = 9,
}

impl PacketType {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => PacketType::BeginRequest,
            2 => PacketType::AbortRequest,
            3 => PacketType::RespHeader,
            4 => PacketType::RespStream,
            5 => PacketType::RespEnd,
            6 => PacketType::StderrStream,
            7 => PacketType::ReqReceived,
            8 => PacketType::ConnClose,
            9 => PacketType::InternalError,
            _ => return None,
        })
    }
}
