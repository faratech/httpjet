use std::io::Read;
use std::sync::Arc;

use bytes::Bytes;
use hj_core::budget::{BodyBufferBudget, BodyBufferLease};
use http::{HeaderMap, HeaderValue, StatusCode, header};
use http_body_util::BodyExt;

/// Process-lifetime request decompression policy.
///
/// Gzip preserves the historical behavior and is always enabled. Brotli and
/// zstd are deliberately separate, default-off operator choices.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RequestDecompression {
    pub(crate) brotli: bool,
    pub(crate) zstd: bool,
}

impl RequestDecompression {
    pub(crate) fn parse_extra(value: &str) -> Result<Self, String> {
        let mut policy = Self::default();
        for item in value
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
        {
            match item.to_ascii_lowercase().as_str() {
                "br" | "brotli" => policy.brotli = true,
                "zstd" => policy.zstd = true,
                "gzip" => {
                    return Err(
                        "gzip is already enabled; --request-decompression-extra accepts only br,zstd"
                            .into(),
                    );
                }
                other => {
                    return Err(format!(
                        "unsupported request decompression coding {other:?}; expected br or zstd"
                    ));
                }
            }
        }
        Ok(policy)
    }

    fn allows(self, coding: ContentCoding) -> bool {
        match coding {
            ContentCoding::Gzip => true,
            ContentCoding::Brotli => self.brotli,
            ContentCoding::Zstd => self.zstd,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContentCoding {
    Gzip,
    Brotli,
    Zstd,
}

impl ContentCoding {
    fn from_headers(headers: &HeaderMap) -> Option<Self> {
        // Content-Encoding is an ordered list. Decoding stacked or repeated
        // codings would require applying them in reverse order; leave any such
        // representation untouched rather than guessing or partly decoding it.
        let value = headers.get_all(header::CONTENT_ENCODING);
        let mut values = value.iter();
        let first = values.next()?.to_str().ok()?.trim();
        if values.next().is_some() || first.contains(',') {
            return None;
        }
        if first.eq_ignore_ascii_case("gzip") {
            Some(Self::Gzip)
        } else if first.eq_ignore_ascii_case("br") {
            Some(Self::Brotli)
        } else if first.eq_ignore_ascii_case("zstd") {
            Some(Self::Zstd)
        } else {
            None
        }
    }

    /// Account decoder-owned memory that is otherwise invisible to the body
    /// budget. Brotli's standard stream format tops out at a 2^24-byte window;
    /// zstd is explicitly configured to the same maximum. The extra MiB covers
    /// decoder tables and input/output scratch. Gzip retains its historical
    /// behavior and small fixed decoder allocation.
    fn workspace_charge(self) -> u64 {
        match self {
            Self::Gzip => 0,
            Self::Brotli | Self::Zstd => 17 * 1024 * 1024,
        }
    }
}

#[inline]
fn enabled_content_coding(
    headers: &HeaderMap,
    policy: RequestDecompression,
) -> Option<ContentCoding> {
    ContentCoding::from_headers(headers).filter(|coding| policy.allows(*coding))
}

/// Whether a bridged request needs the asynchronous collect/decode path.
///
/// Keep this synchronous probe outside the bridge task's ordinary future so
/// requests without an enabled coding do not carry decoder state at all.
#[inline]
pub(super) fn needs_bridged_decompression(
    req: &hj_core::Request,
    policy: RequestDecompression,
) -> bool {
    req.extensions().get::<DecodeTried>().is_none()
        && enabled_content_coding(req.headers(), policy).is_some()
}

/// Marks an H1 request whose body [`finish_body`] already tried to decode. A body it
/// leaves encoded (malformed, or over the codec cap) keeps its Content-Encoding, and
/// the bridge would otherwise run the same full decode again to the same verdict.
#[derive(Clone, Copy)]
pub(super) struct DecodeTried;

/// Whether [`finish_body`] will try to decode `data`.
pub(super) fn finish_body_decodes(
    headers: &HeaderMap,
    data: &[u8],
    policy: RequestDecompression,
) -> bool {
    !data.is_empty() && enabled_content_coding(headers, policy).is_some()
}

/// Decoded output may always grow to this size, whatever the compression ratio,
/// so small legitimate bodies never meet the expansion rule below.
const EXPANSION_FLOOR: usize = 1 << 20;
/// Past the floor, output beyond this multiple of the encoded size takes the
/// codec-cap outcome (forwarded undecoded), as reaching `MAX_DECODE` does. Real
/// text/JSON uploads compress 3-20x; a run of zeros compresses ~1000x, so without
/// this a 16 KiB body bought 16 MiB of inflate before the cap discarded it.
const MAX_EXPANSION_RATIO: usize = 64;
/// Encoded bodies up to this size first try a decode on the serving thread...
const INLINE_MAX_ENCODED: usize = 16 * 1024;
/// ...which stops at this much output and restarts on the blocking pool. The
/// inline attempt therefore costs at most ~256 KiB of inflate (well under a
/// millisecond), and the pool round trip is reserved for bodies that need it.
const INLINE_MAX_DECODED: usize = 256 * 1024;

/// Concurrent off-thread decodes. Half the cores leaves the rest for the
/// serving threads; waiters hold only budget-charged encoded bodies.
static DECODE_SLOTS: std::sync::LazyLock<Arc<tokio::sync::Semaphore>> =
    std::sync::LazyLock::new(|| {
        let cores = std::thread::available_parallelism().map_or(1, usize::from);
        Arc::new(tokio::sync::Semaphore::new((cores / 2).max(1)))
    });

pub(super) async fn finish_body(
    headers: &mut HeaderMap,
    data: Vec<u8>,
    lease: Option<BodyBufferLease>,
    budget: &Arc<BodyBufferBudget>,
    max_body: usize,
    policy: RequestDecompression,
) -> Result<Bytes, StatusCode> {
    let encoded = match lease {
        Some(lease) => lease.into_bytes(data),
        None if data.is_empty() => Bytes::new(),
        None => {
            let mut lease = BodyBufferLease::new(budget.clone());
            if !lease.reserve(data.len() as u64) {
                return Err(StatusCode::SERVICE_UNAVAILABLE);
            }
            lease.into_bytes(data)
        }
    };
    // Bodyless requests dominate GET traffic. Avoid even probing the header
    // map for Content-Encoding when there is nothing a decoder could consume.
    if encoded.is_empty() {
        return Ok(encoded);
    }
    let Some(coding) = enabled_content_coding(headers, policy) else {
        return Ok(encoded);
    };
    // Boxed so the decode/offload state never enlarges the connection future
    // that every unencoded request runs through.
    Box::pin(decode_body(headers, coding, encoded, budget, max_body)).await
}

/// Apply request-content decoding to a fully buffered bridged request.
///
/// H2 and H3 already pass a single lease-backed `Full<Bytes>` body. Collecting
/// that frame does not duplicate its allocation, and the encoded lease remains
/// live while [`decode_body`] reserves and builds the decoded representation.
pub(super) async fn finish_bridged_request(
    req: hj_core::Request,
    budget: &Arc<BodyBufferBudget>,
    max_body: usize,
    policy: RequestDecompression,
) -> Result<hj_core::Request, StatusCode> {
    // The overwhelmingly common request has no supported Content-Encoding.
    // Preserve its body and parts verbatim instead of collecting, unboxing and
    // rebuilding the request merely to return the same bytes. This also makes
    // H1's second bridge-side pass free after finish_body() removed a coding
    // decoded on the monoio intake path.
    let Some(coding) = enabled_content_coding(req.headers(), policy) else {
        return Ok(req);
    };
    let (mut parts, body) = req.into_parts();
    let encoded = body
        .collect()
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .to_bytes();
    let decoded = if encoded.is_empty() {
        encoded
    } else {
        decode_body(&mut parts.headers, coding, encoded, budget, max_body).await?
    };
    let body = if decoded.is_empty() {
        hj_core::empty_incoming()
    } else {
        http_body_util::Full::new(decoded)
            .map_err(|never| match never {})
            .boxed()
    };
    Ok(http::Request::from_parts(parts, body))
}

/// Decode a non-empty body carrying an enabled coding. Small bodies try the
/// bounded inline attempt; anything else (or anything that outgrows it) runs
/// on the tokio blocking pool behind [`DECODE_SLOTS`], so neither a monoio
/// core nor a pipeline worker ever inflates more than [`INLINE_MAX_DECODED`].
async fn decode_body(
    headers: &mut HeaderMap,
    coding: ContentCoding,
    encoded: Bytes,
    budget: &Arc<BodyBufferBudget>,
    max_body: usize,
) -> Result<Bytes, StatusCode> {
    let inline = if encoded.len() <= INLINE_MAX_ENCODED {
        decode_entity(coding, &encoded, budget, max_body, INLINE_MAX_DECODED)
    } else {
        DecodeOutcome::Deferred
    };
    let outcome = match inline {
        DecodeOutcome::Deferred => {
            offload_decode(&DECODE_SLOTS, coding, encoded.clone(), budget, max_body).await
        }
        done => done,
    };
    match outcome {
        DecodeOutcome::Decoded(decoded) => {
            headers.insert(header::CONTENT_LENGTH, HeaderValue::from(decoded.len()));
            headers.remove(header::CONTENT_ENCODING);
            Ok(decoded)
        }
        // A full decode has no inline limit, so it never defers; were it to,
        // forwarding the original representation is the fail-safe outcome.
        DecodeOutcome::Undecoded | DecodeOutcome::Deferred => Ok(encoded),
        DecodeOutcome::Refused(status) => Err(status),
    }
}

async fn offload_decode(
    slots: &Arc<tokio::sync::Semaphore>,
    coding: ContentCoding,
    encoded: Bytes,
    budget: &Arc<BodyBufferBudget>,
    max_body: usize,
) -> DecodeOutcome {
    let Some(runtime) = crate::lscache::pipeline_handle() else {
        return decode_entity(coding, &encoded, budget, max_body, usize::MAX);
    };
    // The permit moves into the closure: a requester that disconnects while
    // its decode runs still holds the slot until the work actually ends.
    let Ok(permit) = slots.clone().acquire_owned().await else {
        return DecodeOutcome::Refused(StatusCode::SERVICE_UNAVAILABLE);
    };
    let budget = budget.clone();
    runtime
        .spawn_blocking(move || {
            let _permit = permit;
            decode_entity(coding, &encoded, &budget, max_body, usize::MAX)
        })
        .await
        .unwrap_or(DecodeOutcome::Refused(StatusCode::SERVICE_UNAVAILABLE))
}

#[derive(Debug)]
enum DecodeOutcome {
    Decoded(Bytes),
    /// Malformed, or past a server decode ceiling: forward the original bytes
    /// and Content-Encoding unchanged rather than silently truncating.
    Undecoded,
    Refused(StatusCode),
    /// Only from an inline attempt: the output outgrew `inline_limit`.
    Deferred,
}

fn decode_entity(
    coding: ContentCoding,
    encoded: &Bytes,
    budget: &Arc<BodyBufferBudget>,
    max_body: usize,
    inline_limit: usize,
) -> DecodeOutcome {
    // Charge the codec before constructing it. This makes concurrent decoder
    // windows participate in the same process-wide request-body ledger as the
    // encoded and decoded byte buffers.
    let mut workspace_lease = BodyBufferLease::new(budget.clone());
    if !workspace_lease.reserve(coding.workspace_charge()) {
        return DecodeOutcome::Refused(StatusCode::SERVICE_UNAVAILABLE);
    }

    let limits = DecodeLimits {
        max_body,
        expansion: encoded
            .len()
            .saturating_mul(MAX_EXPANSION_RATIO)
            .max(EXPANSION_FLOOR),
        inline: inline_limit,
    };
    let mut decoded = Vec::new();
    let mut decoded_lease = BodyBufferLease::new(budget.clone());
    let mut chunk = [0; 8192];
    let result = match coding {
        ContentCoding::Gzip => {
            // Multi-member gzip streams are valid RFC 1952; GzDecoder would
            // silently drop every member after the first.
            let mut decoder = flate2::read::MultiGzDecoder::new(encoded.as_ref());
            decode_reader(
                &mut decoder,
                &mut chunk,
                &mut decoded,
                &mut decoded_lease,
                limits,
            )
        }
        ContentCoding::Brotli => {
            // Standard Brotli streams cap lgwin at 24. The crate's default
            // decoder does not enable the non-standard large-window extension.
            let mut decoder = brotli::Decompressor::new(encoded.as_ref(), 8192);
            decode_reader(
                &mut decoder,
                &mut chunk,
                &mut decoded,
                &mut decoded_lease,
                limits,
            )
        }
        ContentCoding::Zstd => {
            let mut decoder = match zstd::stream::read::Decoder::new(encoded.as_ref()) {
                Ok(decoder) => decoder,
                Err(_) => return DecodeOutcome::Undecoded,
            };
            // Refuse frames that ask the native decoder to allocate a window
            // beyond the amount charged above.
            if decoder.window_log_max(24).is_err() {
                return DecodeOutcome::Undecoded;
            }
            decode_reader(
                &mut decoder,
                &mut chunk,
                &mut decoded,
                &mut decoded_lease,
                limits,
            )
        }
    };

    match result {
        DecodeResult::Complete => DecodeOutcome::Decoded(decoded_lease.into_bytes(decoded)),
        DecodeResult::MalformedOrCodecCap => DecodeOutcome::Undecoded,
        DecodeResult::TooLarge => DecodeOutcome::Refused(StatusCode::PAYLOAD_TOO_LARGE),
        DecodeResult::NoCapacity => DecodeOutcome::Refused(StatusCode::SERVICE_UNAVAILABLE),
        DecodeResult::InlineLimit => DecodeOutcome::Deferred,
    }
}

#[derive(Debug, Clone, Copy)]
struct DecodeLimits {
    max_body: usize,
    expansion: usize,
    inline: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecodeResult {
    Complete,
    MalformedOrCodecCap,
    TooLarge,
    NoCapacity,
    InlineLimit,
}

fn decode_reader(
    decoder: &mut impl Read,
    chunk: &mut [u8; 8192],
    decoded: &mut Vec<u8>,
    decoded_lease: &mut BodyBufferLease,
    limits: DecodeLimits,
) -> DecodeResult {
    loop {
        let n = match decoder.read(chunk) {
            Ok(n) => n,
            Err(_) => return DecodeResult::MalformedOrCodecCap,
        };
        if n == 0 {
            return DecodeResult::Complete;
        }
        let size = decoded.len().saturating_add(n);
        // Check order is fixed so an inline attempt that defers and the full
        // decode that replaces it reach the same verdict on the same input.
        if size > limits.max_body {
            return DecodeResult::TooLarge;
        }
        // Preserve the historical gzip codec-cap fallback: a valid compressed
        // representation that exceeds the server's decode ceiling is forwarded
        // unchanged rather than silently truncated. The expansion bound is the
        // same ceiling, reached as soon as the ratio proves the body abusive.
        if size as u64 >= hj_compress::MAX_DECODE || size > limits.expansion {
            return DecodeResult::MalformedOrCodecCap;
        }
        if size > limits.inline {
            return DecodeResult::InlineLimit;
        }
        if !decoded_lease.reserve(n as u64) {
            return DecodeResult::NoCapacity;
        }
        if decoded.try_reserve_exact(n).is_err() {
            return DecodeResult::NoCapacity;
        }
        decoded.extend_from_slice(&chunk[..n]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An H1 body finish_body already tried (and left encoded) is not decoded again
    /// on the bridge.
    #[test]
    fn a_tried_h1_body_is_not_decoded_again() {
        let policy = RequestDecompression::default();
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        assert!(finish_body_decodes(&headers, b"x", policy));
        assert!(!finish_body_decodes(&headers, b"", policy));
        let mut req = http::Request::new(hj_core::empty_incoming());
        *req.headers_mut() = headers;
        assert!(needs_bridged_decompression(&req, policy));
        req.extensions_mut().insert(DecodeTried);
        assert!(!needs_bridged_decompression(&req, policy));
    }

    fn encode(coding: ContentCoding, input: &[u8]) -> Vec<u8> {
        let encoding = match coding {
            ContentCoding::Gzip => hj_compress::Encoding::Gzip,
            ContentCoding::Brotli => hj_compress::Encoding::Brotli,
            ContentCoding::Zstd => hj_compress::Encoding::Zstd,
        };
        hj_compress::encode_bytes(encoding, input, &Default::default()).unwrap()
    }

    fn run(
        coding: ContentCoding,
        data: Vec<u8>,
        budget: &Arc<BodyBufferBudget>,
        max: usize,
        policy: RequestDecompression,
    ) -> (Result<Bytes, StatusCode>, HeaderMap) {
        let mut headers = HeaderMap::new();
        let value = match coding {
            ContentCoding::Gzip => "gzip",
            ContentCoding::Brotli => "br",
            ContentCoding::Zstd => "zstd",
        };
        headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static(value));
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from(data.len()));
        let mut lease = BodyBufferLease::new(budget.clone());
        assert!(lease.reserve(data.len() as u64));
        let result = block_on(finish_body(
            &mut headers,
            data,
            Some(lease),
            budget,
            max,
            policy,
        ));
        (result, headers)
    }

    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(fut)
    }

    #[test]
    fn multi_member_gzip_decodes_all_members() {
        // #624: concatenated gzip members must not truncate at member 1.
        let budget = Arc::new(BodyBufferBudget::new(64 * 1024 * 1024));
        let mut data = encode(ContentCoding::Gzip, b"hello ");
        data.extend(encode(ContentCoding::Gzip, b"world"));
        let (result, _) = run(
            ContentCoding::Gzip,
            data,
            &budget,
            64_000,
            RequestDecompression::default(),
        );
        assert_eq!(result.unwrap().as_ref(), b"hello world");
    }

    #[test]
    fn policy_is_gzip_only_by_default_and_strictly_parsed() {
        let default = RequestDecompression::default();
        assert!(default.allows(ContentCoding::Gzip));
        assert!(!default.allows(ContentCoding::Brotli));
        assert!(!default.allows(ContentCoding::Zstd));

        let both = RequestDecompression::parse_extra("br,zstd").unwrap();
        assert!(both.brotli && both.zstd);
        assert!(RequestDecompression::parse_extra("gzip").is_err());
        assert!(RequestDecompression::parse_extra("deflate").is_err());
    }

    #[test]
    fn expansion_remains_charged_until_last_frame_alias_drops() {
        let budget = Arc::new(BodyBufferBudget::new(100_000));
        let data = encode(ContentCoding::Gzip, &vec![b'x'; 32_000]);
        let (result, headers) = run(
            ContentCoding::Gzip,
            data,
            &budget,
            64_000,
            RequestDecompression::default(),
        );
        let body = result.unwrap();
        assert_eq!(headers[header::CONTENT_LENGTH], "32000");
        assert!(!headers.contains_key(header::CONTENT_ENCODING));
        assert_eq!(budget.in_flight(), 32_000);
        assert_eq!(body.as_ref(), &vec![b'x'; 32_000]);
        let alias = body.slice(1..);
        drop(body);
        assert_eq!(budget.in_flight(), 32_000);
        drop(alias);
        assert_eq!(budget.in_flight(), 0);
    }

    #[test]
    fn simultaneous_encoded_and_decoded_bytes_must_fit() {
        let data = encode(ContentCoding::Gzip, &vec![0; 8192]);
        let budget = Arc::new(BodyBufferBudget::new(8192));
        let (result, headers) = run(
            ContentCoding::Gzip,
            data,
            &budget,
            16384,
            RequestDecompression::default(),
        );
        assert_eq!(result.unwrap_err(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(headers[header::CONTENT_ENCODING], "gzip");
        assert_eq!(budget.in_flight(), 0);
        assert_eq!(budget.rejected(), 1);
    }

    #[test]
    fn each_enabled_codec_decodes_and_rewrites_entity_headers() {
        let policy = RequestDecompression {
            brotli: true,
            zstd: true,
        };
        for coding in [
            ContentCoding::Gzip,
            ContentCoding::Brotli,
            ContentCoding::Zstd,
        ] {
            let budget = Arc::new(BodyBufferBudget::new(64 * 1024 * 1024));
            let (result, headers) = run(
                coding,
                encode(coding, b"transport-independent body"),
                &budget,
                4096,
                policy,
            );
            let body = result.unwrap();
            assert_eq!(body.as_ref(), b"transport-independent body");
            assert_eq!(headers[header::CONTENT_LENGTH], "26");
            assert!(!headers.contains_key(header::CONTENT_ENCODING));
        }
    }

    #[test]
    fn optional_codecs_stay_encoded_without_opt_in() {
        for coding in [ContentCoding::Brotli, ContentCoding::Zstd] {
            let data = encode(coding, b"hello");
            let budget = Arc::new(BodyBufferBudget::new(1 << 20));
            let (result, headers) = run(
                coding,
                data.clone(),
                &budget,
                4096,
                RequestDecompression::default(),
            );
            assert_eq!(result.unwrap().as_ref(), data);
            assert!(headers.contains_key(header::CONTENT_ENCODING));
        }
    }

    #[test]
    fn expanded_body_obeys_request_limit_for_every_codec() {
        let policy = RequestDecompression {
            brotli: true,
            zstd: true,
        };
        for coding in [
            ContentCoding::Gzip,
            ContentCoding::Brotli,
            ContentCoding::Zstd,
        ] {
            let budget = Arc::new(BodyBufferBudget::new(64 * 1024 * 1024));
            assert_eq!(
                run(
                    coding,
                    encode(coding, &vec![0; 9000]),
                    &budget,
                    8192,
                    policy,
                )
                .0
                .unwrap_err(),
                StatusCode::PAYLOAD_TOO_LARGE
            );
            assert_eq!(budget.in_flight(), 0);
        }
    }

    #[test]
    fn malformed_codings_preserve_original_body_and_policy() {
        let policy = RequestDecompression {
            brotli: true,
            zstd: true,
        };
        for coding in [
            ContentCoding::Gzip,
            ContentCoding::Brotli,
            ContentCoding::Zstd,
        ] {
            let data = b"not a compressed stream".to_vec();
            let budget = Arc::new(BodyBufferBudget::new(64 * 1024 * 1024));
            let (result, headers) = run(coding, data.clone(), &budget, 100_000, policy);
            let body = result.unwrap();
            assert_eq!(body.as_ref(), data);
            assert!(headers.contains_key(header::CONTENT_ENCODING));
            assert_eq!(budget.in_flight(), data.len() as u64);
            drop(body);
            assert_eq!(budget.in_flight(), 0);
        }
    }

    #[test]
    fn codec_workspace_and_body_buffers_share_one_budget() {
        let policy = RequestDecompression {
            brotli: true,
            zstd: true,
        };
        for coding in [ContentCoding::Brotli, ContentCoding::Zstd] {
            let data = encode(coding, &vec![0; 8192]);
            let budget = Arc::new(BodyBufferBudget::new(17 * 1024 * 1024));
            let (result, headers) = run(coding, data, &budget, 16_384, policy);
            assert_eq!(result.unwrap_err(), StatusCode::SERVICE_UNAVAILABLE);
            assert!(headers.contains_key(header::CONTENT_ENCODING));
            assert_eq!(budget.in_flight(), 0);
            assert_eq!(budget.rejected(), 1);
        }
    }

    #[test]
    fn disabled_budget_still_decodes_and_empty_body_stays_empty() {
        let budget = Arc::new(BodyBufferBudget::new(0));
        let (result, _) = run(
            ContentCoding::Gzip,
            encode(ContentCoding::Gzip, b"hello"),
            &budget,
            100,
            RequestDecompression::default(),
        );
        assert_eq!(result.unwrap().as_ref(), b"hello");
        assert_eq!(budget.in_flight(), 0);
        let (result, headers) = run(
            ContentCoding::Gzip,
            Vec::new(),
            &budget,
            100,
            RequestDecompression::default(),
        );
        assert!(result.unwrap().is_empty());
        assert_eq!(headers[header::CONTENT_ENCODING], "gzip");
    }

    #[test]
    fn retained_expansion_blocks_another_request_until_released() {
        let budget = Arc::new(BodyBufferBudget::new(20_000));
        let data = encode(ContentCoding::Gzip, &vec![b'x'; 12_000]);
        let first = run(
            ContentCoding::Gzip,
            data.clone(),
            &budget,
            20_000,
            RequestDecompression::default(),
        )
        .0
        .unwrap();
        assert_eq!(budget.in_flight(), 12_000);
        assert_eq!(
            run(
                ContentCoding::Gzip,
                data.clone(),
                &budget,
                20_000,
                RequestDecompression::default(),
            )
            .0
            .unwrap_err(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(budget.in_flight(), 12_000);
        drop(first);
        let next = run(
            ContentCoding::Gzip,
            data,
            &budget,
            20_000,
            RequestDecompression::default(),
        )
        .0
        .unwrap();
        drop(next);
        assert_eq!(budget.in_flight(), 0);
    }

    #[test]
    fn late_decode_error_releases_partial_output_but_retains_encoded_input() {
        let mut data = encode(ContentCoding::Gzip, &vec![b'x'; 24_000]);
        let footer = data.len() - 8;
        data[footer] ^= 1;
        let budget = Arc::new(BodyBufferBudget::new(100_000));
        let body = run(
            ContentCoding::Gzip,
            data.clone(),
            &budget,
            100_000,
            RequestDecompression::default(),
        )
        .0
        .unwrap();
        assert_eq!(body.as_ref(), data);
        assert_eq!(budget.in_flight(), data.len() as u64);
        drop(body);
        assert_eq!(budget.in_flight(), 0);
    }

    #[test]
    fn stacked_or_repeated_content_codings_are_never_partly_decoded() {
        let data = encode(ContentCoding::Gzip, b"hello");
        let budget = Arc::new(BodyBufferBudget::new(100_000));
        for value in ["gzip, br", "gzip, gzip"] {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::CONTENT_ENCODING,
                HeaderValue::from_str(value).unwrap(),
            );
            let mut lease = BodyBufferLease::new(budget.clone());
            assert!(lease.reserve(data.len() as u64));
            let body = block_on(finish_body(
                &mut headers,
                data.clone(),
                Some(lease),
                &budget,
                100_000,
                RequestDecompression {
                    brotli: true,
                    zstd: true,
                },
            ))
            .unwrap();
            assert_eq!(body.as_ref(), data);
            assert_eq!(headers[header::CONTENT_ENCODING], value);
        }
    }

    #[tokio::test]
    async fn bridged_body_decoding_preserves_request_metadata_and_accounting() {
        let budget = Arc::new(BodyBufferBudget::new(64 * 1024 * 1024));
        let data = encode(ContentCoding::Brotli, b"hello over h2 or h3");
        let mut lease = BodyBufferLease::new(budget.clone());
        assert!(lease.reserve(data.len() as u64));
        let bytes = lease.into_bytes(data);
        let body = http_body_util::Full::new(bytes)
            .map_err(|never| match never {})
            .boxed();
        let mut req = http::Request::builder()
            .method("POST")
            .uri("/upload?transport=bridged")
            .header(header::CONTENT_ENCODING, "br")
            .header(header::CONTENT_LENGTH, "23")
            .header("x-test", "retained")
            .body(body)
            .unwrap();
        req.extensions_mut().insert(42_u32);

        let req = finish_bridged_request(
            req,
            &budget,
            4096,
            RequestDecompression {
                brotli: true,
                zstd: false,
            },
        )
        .await
        .unwrap();
        assert_eq!(req.method(), http::Method::POST);
        assert_eq!(req.uri(), "/upload?transport=bridged");
        assert_eq!(req.headers()["x-test"], "retained");
        assert_eq!(req.headers()[header::CONTENT_LENGTH], "19");
        assert!(!req.headers().contains_key(header::CONTENT_ENCODING));
        assert_eq!(req.extensions().get::<u32>(), Some(&42));
        let body = req.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), b"hello over h2 or h3");
        assert_eq!(budget.in_flight(), body.len() as u64);
        drop(body);
        assert_eq!(budget.in_flight(), 0);
    }

    #[tokio::test]
    async fn disabled_or_unencoded_bridged_body_is_not_polled_or_rebuilt() {
        use std::pin::Pin;
        use std::task::{Context, Poll};

        struct MustNotPoll;
        impl http_body::Body for MustNotPoll {
            type Data = Bytes;
            type Error = hj_core::BoxError;

            fn poll_frame(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
                panic!("unencoded bridge fast path must preserve the body without polling it")
            }
        }

        let budget = Arc::new(BodyBufferBudget::new(1024));
        for coding in [None, Some("unknown"), Some("br"), Some("zstd")] {
            let body = http_body_util::BodyExt::boxed(MustNotPoll);
            let mut builder = http::Request::builder()
                .method("POST")
                .uri("/opaque")
                .header("x-test", "retained");
            if let Some(coding) = coding {
                builder = builder.header(header::CONTENT_ENCODING, coding);
            }
            let mut req = builder.body(body).unwrap();
            req.extensions_mut().insert(42_u32);
            assert!(!needs_bridged_decompression(
                &req,
                RequestDecompression::default()
            ));

            let req = finish_bridged_request(req, &budget, 1024, RequestDecompression::default())
                .await
                .unwrap();
            assert_eq!(req.uri(), "/opaque");
            assert_eq!(req.headers()["x-test"], "retained");
            assert_eq!(req.extensions().get::<u32>(), Some(&42));
        }

        for (coding, policy) in [
            ("gzip", RequestDecompression::default()),
            (
                "br",
                RequestDecompression {
                    brotli: true,
                    zstd: false,
                },
            ),
            (
                "zstd",
                RequestDecompression {
                    brotli: false,
                    zstd: true,
                },
            ),
        ] {
            let req = http::Request::builder()
                .header(header::CONTENT_ENCODING, coding)
                .body(hj_core::empty_incoming())
                .unwrap();
            assert!(needs_bridged_decompression(&req, policy));
        }
    }

    fn gzip_fast(input: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(input).unwrap();
        enc.finish().unwrap()
    }

    /// Bytes a decoder hands back, so a test can bound the inflate work done.
    struct Counting<R> {
        inner: R,
        produced: usize,
    }
    impl<R: Read> Read for Counting<R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.inner.read(buf)?;
            self.produced += n;
            Ok(n)
        }
    }

    #[test]
    fn expansion_ratio_bails_out_long_before_the_decode_cap() {
        // #837: ~8 KiB of gzip that inflates to 8 MiB used to cost the full
        // 8 MiB (16 MiB for a larger bomb) before the cap discarded it.
        let data = encode(ContentCoding::Gzip, &vec![0; 8 << 20]);
        assert!(data.len() * MAX_EXPANSION_RATIO < EXPANSION_FLOOR);
        let budget = Arc::new(BodyBufferBudget::new(64 * 1024 * 1024));
        let mut lease = BodyBufferLease::new(budget.clone());
        let mut decoded = Vec::new();
        let mut decoder = Counting {
            inner: flate2::read::MultiGzDecoder::new(data.as_slice()),
            produced: 0,
        };
        let result = decode_reader(
            &mut decoder,
            &mut [0; 8192],
            &mut decoded,
            &mut lease,
            DecodeLimits {
                max_body: 100 << 20,
                expansion: EXPANSION_FLOOR,
                inline: usize::MAX,
            },
        );
        assert_eq!(result, DecodeResult::MalformedOrCodecCap);
        assert!(
            decoder.produced <= EXPANSION_FLOOR + 8192,
            "{}",
            decoder.produced
        );
        drop((lease, decoded));

        // End to end the bomb takes the codec-cap outcome: forwarded verbatim.
        let (result, headers) = run(
            ContentCoding::Gzip,
            data.clone(),
            &budget,
            100 << 20,
            RequestDecompression::default(),
        );
        let body = result.unwrap();
        assert_eq!(body.as_ref(), data);
        assert_eq!(headers[header::CONTENT_ENCODING], "gzip");
        assert_eq!(budget.in_flight(), data.len() as u64);
        drop(body);
        assert_eq!(budget.in_flight(), 0);
    }

    #[test]
    fn expansion_bound_scales_with_the_encoded_size() {
        // 3 MiB that compresses ~20x is past the floor but within the ratio.
        let mut x = 0x9e37_79b9_u32;
        let input: Vec<u8> = (0..3 << 20)
            .map(|i| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                if i % 16 == 0 {
                    b'a' + (x % 26) as u8
                } else {
                    b' '
                }
            })
            .collect();
        let data = encode(ContentCoding::Gzip, &input);
        assert!(data.len() * MAX_EXPANSION_RATIO > input.len());
        let budget = Arc::new(BodyBufferBudget::new(64 * 1024 * 1024));
        let (result, headers) = run(
            ContentCoding::Gzip,
            data,
            &budget,
            100 << 20,
            RequestDecompression::default(),
        );
        assert_eq!(result.unwrap().as_ref(), input);
        assert_eq!(headers[header::CONTENT_LENGTH], input.len().to_string());
        assert!(!headers.contains_key(header::CONTENT_ENCODING));
    }

    #[test]
    fn decode_cap_still_forwards_the_original_representation() {
        // Low-ratio input past MAX_DECODE: the expansion bound never trips, and
        // the historical cap outcome (raw body, coding retained) is unchanged.
        let mut x = 0x1234_5678_u32;
        let input: Vec<u8> = (0..hj_compress::MAX_DECODE as usize + 4096)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect();
        let data = gzip_fast(&input);
        drop(input);
        let budget = Arc::new(BodyBufferBudget::new(128 * 1024 * 1024));
        let (result, headers) = run(
            ContentCoding::Gzip,
            data.clone(),
            &budget,
            100 << 20,
            RequestDecompression::default(),
        );
        let body = result.unwrap();
        assert_eq!(body.as_ref(), data);
        assert_eq!(headers[header::CONTENT_ENCODING], "gzip");
        assert_eq!(budget.in_flight(), data.len() as u64);
    }

    #[test]
    fn small_body_that_outgrows_the_inline_attempt_is_decoded_off_thread() {
        let input = vec![b'x'; 600 * 1024];
        let data = encode(ContentCoding::Gzip, &input);
        assert!(data.len() <= INLINE_MAX_ENCODED);
        let budget = Arc::new(BodyBufferBudget::new(64 * 1024 * 1024));
        let encoded = Bytes::from(data.clone());
        assert!(matches!(
            decode_entity(
                ContentCoding::Gzip,
                &encoded,
                &budget,
                1 << 20,
                INLINE_MAX_DECODED
            ),
            DecodeOutcome::Deferred
        ));
        assert_eq!(budget.in_flight(), 0);
        let (result, headers) = run(
            ContentCoding::Gzip,
            data,
            &budget,
            1 << 20,
            RequestDecompression::default(),
        );
        let body = result.unwrap();
        assert_eq!(body.as_ref(), input);
        assert_eq!(headers[header::CONTENT_LENGTH], "614400");
        assert_eq!(budget.in_flight(), input.len() as u64);
        drop(body);
        assert_eq!(budget.in_flight(), 0);
        // A deferred decode reaches the inline verdicts too: 413 stays 413.
        let (result, _) = run(
            ContentCoding::Gzip,
            encode(ContentCoding::Gzip, &input),
            &budget,
            300 * 1024,
            RequestDecompression::default(),
        );
        assert_eq!(result.unwrap_err(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn offloaded_decodes_wait_for_a_free_slot() {
        use std::future::Future;
        use std::task::Poll;

        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        let held = slots.clone().acquire_owned().await.unwrap();
        let budget = Arc::new(BodyBufferBudget::new(64 * 1024 * 1024));
        let encoded = Bytes::from(encode(ContentCoding::Gzip, b"queued body"));
        let fut = offload_decode(&slots, ContentCoding::Gzip, encoded, &budget, 4096);
        let mut fut = std::pin::pin!(fut);
        for _ in 0..20 {
            let pending =
                std::future::poll_fn(|cx| Poll::Ready(fut.as_mut().poll(cx).is_pending())).await;
            assert!(pending, "decode ran without a slot");
            tokio::task::yield_now().await;
        }
        drop(held);
        match fut.await {
            DecodeOutcome::Decoded(body) => assert_eq!(body.as_ref(), b"queued body"),
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(slots.available_permits(), 1);
    }
}
