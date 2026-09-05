use super::*;

fn response_with_content_type() -> Response {
    let mut resp = Response::new(Body::Empty);
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("text/plain"),
    );
    resp
}

#[test]
fn existing_expires_suppresses_the_entire_generated_pair() {
    let rules = hj_compress::ExpiresRules::from_pairs([("text/plain", "A604800")]);
    let mut resp = response_with_content_type();
    resp.headers_mut().insert(
        http::header::EXPIRES,
        http::HeaderValue::from_static("Thu, 01 Jan 1970 00:00:01 GMT"),
    );

    apply_expires(&rules, 1_700_000_000, &mut resp);

    assert_eq!(
        resp.headers().get(http::header::EXPIRES).unwrap(),
        "Thu, 01 Jan 1970 00:00:01 GMT"
    );
    assert!(
        !resp.headers().contains_key(http::header::CACHE_CONTROL),
        "an existing Expires header must suppress Cache-Control generation too"
    );
}

#[test]
fn huge_accepted_rules_render_a_bounded_coherent_header_pair() {
    let now = 1_700_000_000;
    for value in [
        "A9223372036854775807",
        "A315360000000",
        "access plus 315360000000 seconds",
    ] {
        let rules = hj_compress::ExpiresRules::from_pairs([("text/plain", value)]);
        let mut resp = response_with_content_type();

        apply_expires(&rules, now, &mut resp);

        assert_eq!(
            resp.headers().get(http::header::EXPIRES).unwrap(),
            "Fri, 31 Dec 9999 23:59:59 GMT",
            "rule {value} must remain within IMF-fixdate's supported range"
        );
        assert_eq!(
            resp.headers().get(http::header::CACHE_CONTROL).unwrap(),
            "public, max-age=251702300799",
            "Cache-Control must describe the same clamped instant for {value}"
        );
    }
}
