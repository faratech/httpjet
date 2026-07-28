use bytes::Bytes;
use hj_compress::{Compress, Encoding};
use hj_core::Body;
use http::header::{CACHE_CONTROL, CONTENT_TYPE, HeaderValue};

fn resp_html(body_size: usize) -> http::Response<Body> {
    let mut r = http::Response::new(Body::Full(Bytes::from(vec![b'x'; body_size])));
    r.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("text/html"));
    r
}

/// A proxied upstream that splits Cache-Control across two header lines must
/// have its no-transform directive honored even when it is on the SECOND line
/// (which headers().get() would not see — only get_all() scans all values).
#[test]
fn no_transform_on_second_cc_line_blocks_compression() {
    let c = Compress::new();
    let mut r = resp_html(1000);
    // Line 1: max-age only (no no-transform here).
    r.headers_mut()
        .append(CACHE_CONTROL, HeaderValue::from_static("max-age=3600"));
    // Line 2: no-transform (must be found even though it is the second value).
    r.headers_mut()
        .append(CACHE_CONTROL, HeaderValue::from_static("no-transform"));

    assert_eq!(
        c.should_compress(&r, "gzip, br, zstd"),
        None,
        "no-transform on second Cache-Control line must block compression"
    );
}

/// Baseline: a single Cache-Control header with no-transform still works.
#[test]
fn no_transform_on_single_cc_line_blocks_compression() {
    let c = Compress::new();
    let mut r = resp_html(1000);
    r.headers_mut().insert(
        CACHE_CONTROL,
        HeaderValue::from_static("private, no-transform"),
    );
    assert_eq!(c.should_compress(&r, "gzip"), None);
}

/// Inverse: two Cache-Control lines without no-transform must still compress.
#[test]
fn two_cc_lines_without_no_transform_allow_compression() {
    let c = Compress::new();
    let mut r = resp_html(1000);
    r.headers_mut()
        .append(CACHE_CONTROL, HeaderValue::from_static("max-age=3600"));
    r.headers_mut()
        .append(CACHE_CONTROL, HeaderValue::from_static("public"));
    assert_eq!(
        c.should_compress(&r, "gzip"),
        Some(Encoding::Gzip),
        "two CC lines without no-transform must allow compression"
    );
}

/// no-transform buried as a middle directive in a comma list on the second line.
#[test]
fn no_transform_buried_in_second_cc_line() {
    let c = Compress::new();
    let mut r = resp_html(1000);
    r.headers_mut()
        .append(CACHE_CONTROL, HeaderValue::from_static("max-age=0"));
    r.headers_mut().append(
        CACHE_CONTROL,
        HeaderValue::from_static("must-revalidate, no-transform, public"),
    );
    assert_eq!(c.should_compress(&r, "gzip"), None);
}
