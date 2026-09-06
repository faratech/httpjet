use std::io::Read;
use std::sync::Arc;

use bytes::Bytes;
use hj_core::budget::{BodyBufferBudget, BodyBufferLease};
use http::{HeaderMap, HeaderValue, StatusCode, header};

pub(super) fn finish_body(
    headers: &mut HeaderMap,
    data: Vec<u8>,
    lease: Option<BodyBufferLease>,
    budget: &Arc<BodyBufferBudget>,
    max_body: usize,
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
    if encoded.is_empty()
        || !headers
            .get(header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("gzip"))
    {
        return Ok(encoded);
    }

    let mut decoder = flate2::read::GzDecoder::new(encoded.as_ref());
    let mut decoded = Vec::new();
    let mut decoded_lease = BodyBufferLease::new(budget.clone());
    let mut chunk = [0; 8192];
    loop {
        let n = match decoder.read(&mut chunk) {
            Ok(n) => n,
            Err(_) => return Ok(encoded),
        };
        if n == 0 {
            break;
        }
        let size = decoded.len().saturating_add(n);
        if size > max_body {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        // Preserve the existing codec-cap fallback, but never interpret a
        // capacity rejection as permission to forward an unaccounted expansion.
        if size as u64 >= hj_compress::MAX_DECODE {
            return Ok(encoded);
        }
        if !decoded_lease.reserve(n as u64) {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        decoded
            .try_reserve_exact(n)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        decoded.extend_from_slice(&chunk[..n]);
    }
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(decoded.len()));
    headers.remove(header::CONTENT_ENCODING);
    Ok(decoded_lease.into_bytes(decoded))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gzip(input: &[u8]) -> Vec<u8> {
        hj_compress::encode_bytes(hj_compress::Encoding::Gzip, input, &Default::default()).unwrap()
    }

    fn run(
        data: Vec<u8>,
        budget: &Arc<BodyBufferBudget>,
        max: usize,
    ) -> (Result<Bytes, StatusCode>, HeaderMap) {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from(data.len()));
        let mut lease = BodyBufferLease::new(budget.clone());
        assert!(lease.reserve(data.len() as u64));
        let result = finish_body(&mut headers, data, Some(lease), budget, max);
        (result, headers)
    }

    #[test]
    fn expansion_remains_charged_until_last_frame_alias_drops() {
        let budget = Arc::new(BodyBufferBudget::new(100_000));
        let (result, headers) = run(gzip(&vec![b'x'; 32_000]), &budget, 64_000);
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
        let data = gzip(&vec![0; 8192]);
        let budget = Arc::new(BodyBufferBudget::new(8192));
        let (result, headers) = run(data, &budget, 16384);
        assert_eq!(result.unwrap_err(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(headers[header::CONTENT_ENCODING], "gzip");
        assert_eq!(budget.in_flight(), 0);
        assert_eq!(budget.rejected(), 1);
    }

    #[test]
    fn expanded_body_obeys_request_limit() {
        let budget = Arc::new(BodyBufferBudget::new(100_000));
        assert_eq!(
            run(gzip(&vec![0; 9000]), &budget, 8192).0.unwrap_err(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(budget.in_flight(), 0);
    }

    #[test]
    fn malformed_gzip_preserves_original_body_and_policy() {
        let data = b"not a gzip stream".to_vec();
        let budget = Arc::new(BodyBufferBudget::new(100_000));
        let (result, headers) = run(data.clone(), &budget, 100_000);
        let body = result.unwrap();
        assert_eq!(body.as_ref(), data);
        assert_eq!(headers[header::CONTENT_ENCODING], "gzip");
        assert_eq!(budget.in_flight(), data.len() as u64);
        drop(body);
        assert_eq!(budget.in_flight(), 0);
    }

    #[test]
    fn disabled_budget_still_decodes_and_empty_body_stays_empty() {
        let budget = Arc::new(BodyBufferBudget::new(0));
        let (result, _) = run(gzip(b"hello"), &budget, 100);
        assert_eq!(result.unwrap().as_ref(), b"hello");
        assert_eq!(budget.in_flight(), 0);
        let (result, headers) = run(Vec::new(), &budget, 100);
        assert!(result.unwrap().is_empty());
        assert_eq!(headers[header::CONTENT_ENCODING], "gzip");
    }

    #[test]
    fn retained_expansion_blocks_another_request_until_released() {
        let budget = Arc::new(BodyBufferBudget::new(20_000));
        let data = gzip(&vec![b'x'; 12_000]);
        let first = run(data.clone(), &budget, 20_000).0.unwrap();
        assert_eq!(budget.in_flight(), 12_000);
        assert_eq!(
            run(data.clone(), &budget, 20_000).0.unwrap_err(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(budget.in_flight(), 12_000);
        drop(first);
        let next = run(data, &budget, 20_000).0.unwrap();
        assert_eq!(next.len(), 12_000);
        drop(next);
        assert_eq!(budget.in_flight(), 0);
    }

    #[test]
    fn late_decode_error_releases_partial_output_but_retains_encoded_input() {
        let mut data = gzip(&vec![b'x'; 24_000]);
        let footer = data.len() - 8;
        data[footer] ^= 1;
        let budget = Arc::new(BodyBufferBudget::new(100_000));
        let body = run(data.clone(), &budget, 100_000).0.unwrap();
        assert_eq!(body.as_ref(), data);
        assert_eq!(budget.in_flight(), data.len() as u64);
        drop(body);
        assert_eq!(budget.in_flight(), 0);
    }
}
