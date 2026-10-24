//! Detection of request-body bytes lsphp could parse as a new BEGIN_REQUEST.
//!
//! lsphp neither drains an unread request body at `LSAPI_Finish_r` nor skips it
//! before the next `readReq`, so a script that leaves part of a body unread hands
//! the rest to `readReq` as the next request. The checks below are the ones
//! `readReq` / `verifyHeader` / `parseRequest` (vendor/lsapilib.c) apply to the
//! fixed 44-byte `lsapi_req_header` before a request is accepted:
//!
//! - bytes 0..3 are `'L' 'S' LSAPI_BEGIN_REQUEST` (`verifyHeader`); byte 3, the
//!   flag, is free;
//! - every int32 is native order when `(flag & 1) == LSAPI_ENDIAN` and swapped
//!   otherwise (`verifyHeader`, `fixEndian`). `LSAPI_ENDIAN` is LITTLE on x86 and
//!   BIG elsewhere, so a given flag means different orders on different hosts:
//!   both orders are tried;
//! - `0 <= m_packetLen <= LSAPI_MAX_HEADER_LEN` (`readReq`);
//! - `0 <= m_cntSpecialEnv, m_cntEnv <= 8192` (`allocateEnvList`, `parseEnv`; a
//!   negative count never satisfies `parseEnv`'s loop);
//! - `0 <= m_scriptFileOff, m_scriptNameOff, m_queryStringOff,
//!   m_requestMethodOff < m_packetLen` (`parseRequest`), so `m_packetLen >= 1`.
//!
//! `m_httpHeaderLen`, `m_reqBodyLen` and `m_cntUnknownHeaders` are unconstrained
//! (negative values pass `validateHeaders`). The env tables and the header index
//! are not checked here: a candidate passing these checks is treated as a frame.
//!
//! `readReq` reads at least the 8-byte packet header and then exactly
//! `m_packetLen` bytes from the socket. Buffer bytes past `m_packetLen` are either
//! read ahead from the socket or left over from the previous request, so a field
//! that does not lie wholly inside the packet is not checked.

use super::{PACKET_HEADER_LEN, PacketType, REQ_HEADER_LEN, VERSION_B0, VERSION_B1};

/// `LSAPI_MAX_HEADER_LEN`: `readReq` refuses a larger BEGIN_REQUEST.
const MAX_BEGIN_REQUEST_LEN: i32 = 256 * 1024;
/// `parseEnv` and `allocateEnvList` refuse more pairs than this.
const MAX_ENV_PAIRS: i32 = 8192;
/// `m_scriptFileOff`, `m_scriptNameOff`, `m_queryStringOff`, `m_requestMethodOff`.
const OFFSET_FIELDS: [usize; 4] = [16, 20, 24, 28];
/// `m_cntEnv`, `m_cntSpecialEnv`.
const COUNT_FIELDS: [usize; 2] = [36, 40];
const MAGIC: [u8; 3] = [VERSION_B0, VERSION_B1, PacketType::BeginRequest as u8];

/// What the bytes known so far say about a BEGIN_REQUEST starting at their first
/// byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum BeginVerdict {
    /// lsphp would refuse it whatever bytes follow.
    Clean,
    /// Consistent so far, but lsphp needs bytes past the window to accept it.
    NeedMore,
    /// lsphp could accept it from the window's bytes alone.
    Frame,
}

/// Whether lsphp could accept a BEGIN_REQUEST that starts at `window[0]`, with
/// any bytes following `window`. Bytes past the fixed 44-byte request header
/// are ignored. True for every byte sequence lsphp accepts as a request start.
pub fn may_be_lsapi_begin_request(window: &[u8]) -> bool {
    classify_begin_request(window) != BeginVerdict::Clean
}

/// Whether lsphp could take a request from some offset of `body`, given that
/// nothing follows `body` on the connection.
pub(crate) fn body_embeds_begin_request(body: &[u8]) -> bool {
    magic_offsets(body).any(|at| {
        body.get(at..)
            .is_some_and(|window| classify_begin_request(window) == BeginVerdict::Frame)
    })
}

/// Offsets in `bytes` where the full magic starts.
pub(crate) fn magic_offsets(bytes: &[u8]) -> memchr::memmem::FindIter<'_, 'static> {
    memchr::memmem::find_iter(bytes, &MAGIC)
}

pub(crate) fn classify_begin_request(window: &[u8]) -> BeginVerdict {
    let window = window.get(..REQ_HEADER_LEN).unwrap_or(window);
    if window.iter().zip(MAGIC).any(|(&byte, magic)| byte != magic) {
        return BeginVerdict::Clean;
    }
    if window.len() < PACKET_HEADER_LEN {
        return BeginVerdict::NeedMore;
    }
    classify_in_order(window, i32::from_le_bytes).max(classify_in_order(window, i32::from_be_bytes))
}

fn classify_in_order(window: &[u8], decode: fn([u8; 4]) -> i32) -> BeginVerdict {
    let field = |at: usize| {
        window
            .get(at..at + 4)
            .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
            .map(decode)
    };
    let Some(packet_len) = field(4) else {
        return BeginVerdict::NeedMore;
    };
    if !(1..=MAX_BEGIN_REQUEST_LEN).contains(&packet_len) {
        return BeginVerdict::Clean;
    }
    let checked = (packet_len as usize).min(REQ_HEADER_LEN);
    let within =
        |at: usize, valid: &dyn Fn(i32) -> bool| at + 4 > checked || field(at).is_none_or(valid);
    let offsets_ok = OFFSET_FIELDS
        .iter()
        .all(|&at| within(at, &|v| (0..packet_len).contains(&v)));
    let counts_ok = COUNT_FIELDS
        .iter()
        .all(|&at| within(at, &|v| (0..=MAX_ENV_PAIRS).contains(&v)));
    // lsphp rejects such a frame, but parseEnv only bounds a count from above: a negative
    // count walks the env list past its allocation before the offsets are checked.
    let negative_count = COUNT_FIELDS
        .iter()
        .any(|&at| at + 4 <= checked && field(at).is_some_and(|v| v < 0));
    if !(offsets_ok && counts_ok) && !negative_count {
        BeginVerdict::Clean
    } else if window.len() >= checked {
        BeginVerdict::Frame
    } else {
        BeginVerdict::NeedMore
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{SpecialEnvType, build_begin_request_framed};

    fn sample_frames() -> Vec<Vec<u8>> {
        let script = "/web/test/evil.php".to_string();
        let env: Vec<(&str, String)> = vec![
            ("SCRIPT_FILENAME", script),
            ("SCRIPT_NAME", "/evil.php".into()),
            ("QUERY_STRING", String::new()),
            ("REQUEST_METHOD", "GET".into()),
            ("REMOTE_ADDR", "127.0.0.1".into()),
        ];
        let special = vec![(
            SpecialEnvType::User,
            "memory_limit".to_string(),
            "1G".to_string(),
        )];
        let mut frames = Vec::new();
        for special_env in [&[][..], &special[..]] {
            for headers in [&[][..], &[("Host", "localhost"), ("X-Test", "1")][..]] {
                for body_len in [0, -2, 4096, i32::MAX] {
                    let frame = build_begin_request_framed(&env, special_env, headers, body_len);
                    frames.push(frame.to_vec());
                }
            }
        }
        frames.push(
            build_begin_request_framed::<&str, &str, (&str, &str)>(&[], &[], &[], 0).to_vec(),
        );
        frames
    }

    /// The same request as lsphp reads it with the other flag value: every
    /// int32 of the fixed header byte-swapped.
    fn swapped(frame: &[u8]) -> Vec<u8> {
        let mut out = frame.to_vec();
        out[3] ^= 1;
        for at in (4..REQ_HEADER_LEN).step_by(4) {
            out[at..at + 4].reverse();
        }
        out
    }

    #[test]
    fn negative_env_counts_are_frames_even_with_bad_offsets() {
        for frame in sample_frames() {
            for count_at in COUNT_FIELDS {
                let mut forged = frame.clone();
                forged[count_at..count_at + 4].copy_from_slice(&(-3i32).to_le_bytes());
                for offset_at in OFFSET_FIELDS {
                    forged[offset_at..offset_at + 4].copy_from_slice(&i32::MAX.to_le_bytes());
                }
                for forged in [forged.clone(), swapped(&forged)] {
                    assert!(may_be_lsapi_begin_request(&forged));
                    assert!(body_embeds_begin_request(&forged));
                }
            }
        }
    }

    #[test]
    fn accepts_every_built_begin_request_in_both_byte_orders() {
        for frame in sample_frames() {
            for frame in [frame.clone(), swapped(&frame)] {
                assert_eq!(classify_begin_request(&frame), BeginVerdict::Frame);
                assert!(may_be_lsapi_begin_request(&frame));
                assert!(body_embeds_begin_request(&frame));
                for flag in 0..=u8::MAX {
                    let mut flagged = frame.clone();
                    flagged[3] = (flagged[3] & 1) | (flag & !1);
                    assert!(may_be_lsapi_begin_request(&flagged), "flag {flag:#x}");
                }
                for cut in 0..REQ_HEADER_LEN {
                    assert!(may_be_lsapi_begin_request(&frame[..cut]), "prefix {cut}");
                }
                let mut embedded = vec![b'x'; 8192 + 3];
                embedded.extend_from_slice(&frame);
                embedded.extend_from_slice(b"trailing");
                assert!(body_embeds_begin_request(&embedded));
            }
        }
    }

    #[test]
    fn short_packet_lengths_count_when_lsphp_has_the_whole_packet() {
        let mut frame = sample_frames().remove(0);
        frame[4..8].copy_from_slice(&9_i32.to_le_bytes());
        assert_eq!(classify_begin_request(&frame[..8]), BeginVerdict::NeedMore);
        assert_eq!(classify_begin_request(&frame[..9]), BeginVerdict::Frame);
        assert!(body_embeds_begin_request(&frame[..9]));
        assert!(!body_embeds_begin_request(&frame[..8]));
    }

    #[test]
    fn rejects_values_lsphp_refuses() {
        let frame = sample_frames().remove(0);
        let with = |at: usize, value: i32| {
            let mut out = frame.clone();
            out[at..at + 4].copy_from_slice(&value.to_le_bytes());
            out
        };
        let len = i32::from_le_bytes(frame[4..8].try_into().unwrap());
        for bad in [
            with(4, 0),
            with(4, -1),
            with(4, 256 * 1024 + 1),
            with(16, len),
            with(20, -1),
            with(24, i32::MAX),
            with(28, len + 7),
            with(36, 8193),
        ] {
            assert_eq!(classify_begin_request(&bad), BeginVerdict::Clean);
        }
        // lsphp refuses a negative count too, but only after writing past its env list.
        assert_eq!(classify_begin_request(&with(36, -1)), BeginVerdict::Frame);
        assert_eq!(classify_begin_request(&with(40, -1)), BeginVerdict::Frame);
        assert_eq!(
            classify_begin_request(&with(4, 256 * 1024)),
            BeginVerdict::Frame
        );
        assert_eq!(classify_begin_request(&with(36, 8192)), BeginVerdict::Frame);
        for magic in [b"LS\x02", b"LT\x01", b"ls\x01"] {
            let mut out = frame.clone();
            out[..3].copy_from_slice(magic);
            assert_eq!(classify_begin_request(&out), BeginVerdict::Clean);
        }
    }

    #[test]
    fn ordinary_bodies_never_match() {
        let text = "PUT /api/v1/items HTTP/1.1 LS LSAPI LS\x02 {\"LS\":1} "
            .repeat(4096)
            .into_bytes();
        assert!(!body_embeds_begin_request(&text));
        // xorshift: deterministic pseudo-random binary, 64 MiB in total.
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut random = vec![0u8; 4 << 20];
        for _ in 0..16 {
            for byte in random.iter_mut() {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }
            assert!(!body_embeds_begin_request(&random));
        }
        // Zero-heavy binary with the magic planted: lsphp's offset checks still
        // refuse a packet length of zero.
        let mut zeros = vec![0u8; 1 << 16];
        zeros[100..103].copy_from_slice(&MAGIC);
        assert!(!body_embeds_begin_request(&zeros));
    }
}
