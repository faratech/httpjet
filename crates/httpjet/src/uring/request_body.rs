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
    enabled_content_coding(req.headers(), policy).is_some()
}

pub(super) fn finish_body(
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
    decode_body(headers, encoded, budget, max_body, policy)
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
    // rebuilding the request merely for decode_body() to return the same bytes.
    // This also makes H1's second bridge-side pass free after finish_body()
    // removed a coding decoded on the monoio intake path.
    if !needs_bridged_decompression(&req, policy) {
        return Ok(req);
    }
    let (mut parts, body) = req.into_parts();
    let encoded = body
        .collect()
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .to_bytes();
    let decoded = decode_body(&mut parts.headers, encoded, budget, max_body, policy)?;
    let body = if decoded.is_empty() {
        hj_core::empty_incoming()
    } else {
        http_body_util::Full::new(decoded)
            .map_err(|never| match never {})
            .boxed()
    };
    Ok(http::Request::from_parts(parts, body))
}

fn decode_body(
    headers: &mut HeaderMap,
    encoded: Bytes,
    budget: &Arc<BodyBufferBudget>,
    max_body: usize,
    policy: RequestDecompression,
) -> Result<Bytes, StatusCode> {
    // Bodyless requests dominate GET traffic. Avoid even probing the header
    // map for Content-Encoding when there is nothing a decoder could consume.
    if encoded.is_empty() {
        return Ok(encoded);
    }
    let Some(coding) = enabled_content_coding(headers, policy) else {
        return Ok(encoded);
    };

    // Charge the codec before constructing it. This makes concurrent decoder
    // windows participate in the same process-wide request-body ledger as the
    // encoded and decoded byte buffers.
    let mut workspace_lease = BodyBufferLease::new(budget.clone());
    if !workspace_lease.reserve(coding.workspace_charge()) {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }

    let mut decoded = Vec::new();
    let mut decoded_lease = BodyBufferLease::new(budget.clone());
    let mut chunk = [0; 8192];
    let result = match coding {
        ContentCoding::Gzip => {
            let mut decoder = flate2::read::GzDecoder::new(encoded.as_ref());
            decode_reader(
                &mut decoder,
                &mut chunk,
                &mut decoded,
                &mut decoded_lease,
                max_body,
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
                max_body,
            )
        }
        ContentCoding::Zstd => {
            let mut decoder = match zstd::stream::read::Decoder::new(encoded.as_ref()) {
                Ok(decoder) => decoder,
                Err(_) => return Ok(encoded),
            };
            // Refuse frames that ask the native decoder to allocate a window
            // beyond the amount charged above.
            if decoder.window_log_max(24).is_err() {
                return Ok(encoded);
            }
            decode_reader(
                &mut decoder,
                &mut chunk,
                &mut decoded,
                &mut decoded_lease,
                max_body,
            )
        }
    };

    match result {
        DecodeResult::Complete => {
            headers.insert(header::CONTENT_LENGTH, HeaderValue::from(decoded.len()));
            headers.remove(header::CONTENT_ENCODING);
            Ok(decoded_lease.into_bytes(decoded))
        }
        DecodeResult::MalformedOrCodecCap => Ok(encoded),
        DecodeResult::TooLarge => Err(StatusCode::PAYLOAD_TOO_LARGE),
        DecodeResult::NoCapacity => Err(StatusCode::SERVICE_UNAVAILABLE),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecodeResult {
    Complete,
    MalformedOrCodecCap,
    TooLarge,
    NoCapacity,
}

fn decode_reader(
    decoder: &mut impl Read,
    chunk: &mut [u8; 8192],
    decoded: &mut Vec<u8>,
    decoded_lease: &mut BodyBufferLease,
    max_body: usize,
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
        if size > max_body {
            return DecodeResult::TooLarge;
        }
        // Preserve the historical gzip codec-cap fallback: a valid compressed
        // representation that exceeds the server's decode ceiling is forwarded
        // unchanged rather than silently truncated.
        if size as u64 >= hj_compress::MAX_DECODE {
            return DecodeResult::MalformedOrCodecCap;
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
        let result = finish_body(&mut headers, data, Some(lease), budget, max, policy);
        (result, headers)
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
            let encoded = Bytes::copy_from_slice(&data);
            let body = decode_body(
                &mut headers,
                encoded,
                &budget,
                100_000,
                RequestDecompression {
                    brotli: true,
                    zstd: true,
                },
            )
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
}
