//! Unit tests for hj-static: path cleaning/traversal, range parsing,
//! conditional logic, and end-to-end handler behavior against temp files.

use super::*;

use std::collections::BTreeMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use hj_core::config::{MimeMap, ServerConfig, Tuning, VHostConfig};
use hj_core::{Body, HandlerError, Proto, ReqCtx};
use http::{Method, StatusCode};

// ----------------------------------------------------------------------------
// Pure-function tests: path cleaning / traversal
// ----------------------------------------------------------------------------

#[test]
fn clean_basic_paths() {
    assert_eq!(clean_request_path("/").unwrap(), PathBuf::from(""));
    assert_eq!(
        clean_request_path("/index.html").unwrap(),
        PathBuf::from("index.html")
    );
    assert_eq!(
        clean_request_path("/a/b/c.css").unwrap(),
        PathBuf::from("a/b/c.css")
    );
    // Redundant slashes and "." segments collapse.
    assert_eq!(
        clean_request_path("/a//b/./c").unwrap(),
        PathBuf::from("a/b/c")
    );
}

#[test]
fn clean_resolves_interior_dotdot() {
    // a/b/../c == a/c (stays beneath root).
    assert_eq!(
        clean_request_path("/a/b/../c").unwrap(),
        PathBuf::from("a/c")
    );
}

#[test]
fn clean_rejects_escape() {
    assert!(clean_request_path("/../etc/passwd").is_none());
    assert!(clean_request_path("/a/../../x").is_none());
    assert!(clean_request_path("/..").is_none());
}

#[test]
fn clean_percent_decoding() {
    // %2e%2e == ".." — must still be caught as traversal after decode.
    assert!(clean_request_path("/%2e%2e/secret").is_none());
    // Space and normal chars decode.
    assert_eq!(
        clean_request_path("/my%20file.txt").unwrap(),
        PathBuf::from("my file.txt")
    );
    // Encoded slash %2f does NOT act as a separator inside a segment; it
    // becomes a literal '/' in the decoded string, which we then split on.
    // The key safety property is no escape: %2e%2e%2f == "../"
    assert!(clean_request_path("/%2e%2e%2fpasswd").is_none());
}

#[test]
fn clean_rejects_nul() {
    assert!(clean_request_path("/foo%00bar").is_none());
}

#[test]
fn clean_rejects_bad_escape() {
    assert!(clean_request_path("/foo%zz").is_none());
    assert!(clean_request_path("/foo%2").is_none());
}

// ----------------------------------------------------------------------------
// Pure-function tests: range parsing
// ----------------------------------------------------------------------------

fn single(o: RangeOutcome) -> (u64, u64) {
    match o {
        RangeOutcome::Single(s, e) => (s, e),
        RangeOutcome::Unsatisfiable => panic!("expected single, got unsatisfiable"),
        RangeOutcome::Ignore => panic!("expected single, got ignore"),
    }
}

#[test]
fn range_full_explicit() {
    assert_eq!(single(parse_range(b"bytes=0-99", 100)), (0, 99));
    assert_eq!(single(parse_range(b"bytes=10-20", 100)), (10, 20));
}

#[test]
fn range_open_ended() {
    assert_eq!(single(parse_range(b"bytes=50-", 100)), (50, 99));
}

#[test]
fn range_suffix() {
    assert_eq!(single(parse_range(b"bytes=-20", 100)), (80, 99));
    // Suffix larger than file clamps to whole file.
    assert_eq!(single(parse_range(b"bytes=-500", 100)), (0, 99));
}

#[test]
fn range_end_clamped() {
    // End beyond EOF clamps to len-1.
    assert_eq!(single(parse_range(b"bytes=90-200", 100)), (90, 99));
}

#[test]
fn range_unsatisfiable() {
    assert!(matches!(
        parse_range(b"bytes=100-", 100),
        RangeOutcome::Unsatisfiable
    ));
    assert!(matches!(
        parse_range(b"bytes=200-300", 100),
        RangeOutcome::Unsatisfiable
    ));
    assert!(matches!(
        parse_range(b"bytes=-0", 100),
        RangeOutcome::Unsatisfiable
    ));
}

#[test]
fn range_ignored_forms() {
    // Non-bytes unit.
    assert!(matches!(
        parse_range(b"items=0-10", 100),
        RangeOutcome::Ignore
    ));
    // Multi-range.
    assert!(matches!(
        parse_range(b"bytes=0-10,20-30", 100),
        RangeOutcome::Ignore
    ));
    // Garbage.
    assert!(matches!(
        parse_range(b"bytes=abc", 100),
        RangeOutcome::Ignore
    ));
    assert!(matches!(parse_range(b"", 100), RangeOutcome::Ignore));
}

// ----------------------------------------------------------------------------
// Pure-function tests: conditional logic
// ----------------------------------------------------------------------------

#[test]
fn inm_star_and_match() {
    assert!(if_none_match_matches(b"*", "\"5-1a\""));
    assert!(if_none_match_matches(b"\"5-1a\"", "\"5-1a\""));
    assert!(if_none_match_matches(b"\"x\", \"5-1a\"", "\"5-1a\""));
    assert!(if_none_match_matches(b"W/\"5-1a\"", "\"5-1a\""));
    assert!(!if_none_match_matches(b"\"other\"", "\"5-1a\""));
}

#[test]
fn ims_logic() {
    let base = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    let later = base + Duration::from_secs(3600);
    let earlier = base - Duration::from_secs(3600);

    let hv_base = http::HeaderValue::from_str(&httpdate::fmt_http_date(base)).unwrap();
    let hv_later = http::HeaderValue::from_str(&httpdate::fmt_http_date(later)).unwrap();
    let hv_earlier = http::HeaderValue::from_str(&httpdate::fmt_http_date(earlier)).unwrap();

    // mtime == since → not modified (304).
    assert!(if_modified_since_not_modified(&hv_base, base));
    // mtime < since → not modified.
    assert!(if_modified_since_not_modified(&hv_later, base));
    // mtime > since → modified (serve 200).
    assert!(!if_modified_since_not_modified(&hv_earlier, base));
}

#[test]
fn if_range_etag_and_date() {
    let mtime = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    let etag = "\"a-b\"";
    let good_etag = http::HeaderValue::from_static("\"a-b\"");
    let bad_etag = http::HeaderValue::from_static("\"x-y\"");
    assert!(if_range_matches(&good_etag, Some(etag), mtime));
    assert!(!if_range_matches(&bad_etag, Some(etag), mtime));
    // No ETag on the entity: an ETag-form If-Range can never match.
    assert!(!if_range_matches(&good_etag, None, mtime));

    let good_date = http::HeaderValue::from_str(&httpdate::fmt_http_date(mtime)).unwrap();
    assert!(if_range_matches(&good_date, Some(etag), mtime));
    // Date-form If-Range matches purely on mtime, regardless of ETag presence.
    assert!(if_range_matches(&good_date, None, mtime));
    let bad_date =
        http::HeaderValue::from_str(&httpdate::fmt_http_date(mtime + Duration::from_secs(10)))
            .unwrap();
    assert!(!if_range_matches(&bad_date, Some(etag), mtime));
}

#[test]
fn etag_format_litespeed_28() {
    // fileETag=28 = Size|MTime|INode (all three), order Size-MTime-INode, then
    // ";;;" inside the quotes — byte-matching OLS buildFixedHeaders.
    let rf = ResolvedFile {
        path: PathBuf::from("/tmp/x"),
        len: 0x4a,
        mtime: SystemTime::UNIX_EPOCH + Duration::from_secs(0x69b4b394),
        inode: 0x4db0_94e9_ecec_531e,
        dev: 0,
        resolved_path: PathBuf::from("/tmp/x"),
    };
    // Mirrors the deployed server's observed `"4a-69b4b394-4db094e9ecec531e;;;"`.
    assert_eq!(rf.etag(28).unwrap(), "\"4a-69b4b394-4db094e9ecec531e;;;\"");
}

#[test]
fn etag_format_bitmask_variants() {
    let rf = ResolvedFile {
        path: PathBuf::from("/tmp/x"),
        len: 255,
        mtime: SystemTime::UNIX_EPOCH + Duration::from_secs(0x1234),
        inode: 0xabcd,
        dev: 0,
        resolved_path: PathBuf::from("/tmp/x"),
    };
    // Size only (16).
    assert_eq!(rf.etag(16).unwrap(), "\"ff;;;\"");
    // MTime only (8).
    assert_eq!(rf.etag(8).unwrap(), "\"1234;;;\"");
    // INode only (4).
    assert_eq!(rf.etag(4).unwrap(), "\"abcd;;;\"");
    // Size|MTime (24): no inode component, but order is still Size then MTime.
    assert_eq!(rf.etag(24).unwrap(), "\"ff-1234;;;\"");
    // MTime|INode (12).
    assert_eq!(rf.etag(12).unwrap(), "\"1234-abcd;;;\"");
    // All three via ETAG_ALL constant value 28.
    assert_eq!(rf.etag(28).unwrap(), "\"ff-1234-abcd;;;\"");
    // NONE (0): no ETag at all.
    assert!(rf.etag(0).is_none());
    // Mod bits (>=32) without any base bit also produce no ETag.
    assert!(rf.etag(32 | 64 | 128).is_none());
    // Mod bits combined with base bits: only base bits count.
    assert_eq!(rf.etag(28 | 32 | 64 | 128).unwrap(), "\"ff-1234-abcd;;;\"");
}

#[test]
fn needs_charset_matches_ols() {
    // text/* always.
    assert!(needs_charset("text/html"));
    assert!(needs_charset("text/plain"));
    assert!(needs_charset("text/css"));
    // application javascript/json subtypes (case-insensitive).
    assert!(needs_charset("application/javascript"));
    assert!(needs_charset("application/x-javascript"));
    assert!(needs_charset("application/json"));
    assert!(needs_charset("application/JSON"));
    // Not these.
    assert!(!needs_charset("application/octet-stream"));
    assert!(!needs_charset("application/xml"));
    assert!(!needs_charset("image/png"));
    assert!(!needs_charset("audio/mpeg"));
}

// ----------------------------------------------------------------------------
// End-to-end handler tests against temp files
// ----------------------------------------------------------------------------

fn test_mime() -> MimeMap {
    let mut by_suffix = BTreeMap::new();
    by_suffix.insert("html".to_string(), "text/html".to_string());
    by_suffix.insert("txt".to_string(), "text/plain".to_string());
    by_suffix.insert("css".to_string(), "text/css".to_string());
    MimeMap { by_suffix }
}

fn make_server() -> ServerConfig {
    ServerConfig {
        server_root: PathBuf::from("/tmp"),
        server_name: "test".into(),
        user: "nobody".into(),
        group: "nobody".into(),
        index_files: vec!["index.html".into()],
        tuning: Tuning::default(),
        quic_enable: false,
        use_ip_in_proxy_header: 0,
        expires: Default::default(),
        cache: Default::default(),
        security: Default::default(),
        suexec: Default::default(),
        ext_processors: vec![],
        php_config: None,
        listeners: vec![],
        vhosts: BTreeMap::new(),
        vhost_order: vec![],
        mime: test_mime(),
    }
}

fn make_ctx(server: Arc<ServerConfig>, vhost: Arc<VHostConfig>) -> ReqCtx {
    ReqCtx {
        server,
        vhost_name: "test".into(),
        vhost,
        peer_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        is_tls: false,
        protocol: Proto::Http1,
        trusted_proxy: false,
        env: vec![],
        local_addr: "127.0.0.1:8080".parse().unwrap(),
        peer_port: 0,
        request_time: SystemTime::now(),
        request_id: Default::default(),
        upstream_id: None,
        tls: None,
    }
}

/// Build a unique temp doc-root under the system temp dir.
fn temp_root(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    p.push(format!(
        "hj-static-test-{}-{}-{}",
        tag,
        std::process::id(),
        nanos
    ));
    fs::create_dir_all(&p).unwrap();
    p
}

fn empty_body() -> hj_core::IncomingBody {
    use http_body_util::{BodyExt, Empty, combinators::BoxBody};
    BoxBody::new(Empty::<bytes::Bytes>::new().map_err(|e| -> hj_core::BoxError { Box::new(e) }))
}

fn req(method: Method, uri: &str) -> http::Request<hj_core::IncomingBody> {
    http::Request::builder()
        .method(method)
        .uri(uri)
        .body(empty_body())
        .unwrap()
}

fn body_is_file(b: &Body) -> Option<(PathBuf, Option<(u64, u64)>)> {
    match b {
        Body::File(f) => Some((f.path.clone(), f.range)),
        _ => None,
    }
}

fn read_file_body(b: &Body) -> Vec<u8> {
    let Body::File(file) = b else {
        panic!("expected Body::File");
    };
    if let Some(bytes) = file.cached_ranged() {
        return bytes.to_vec();
    }
    let bytes = fs::read(&file.path).unwrap();
    match file.range {
        Some((start, end)) => bytes[start as usize..=end as usize].to_vec(),
        None => bytes,
    }
}

async fn serve(
    ctx: &mut ReqCtx,
    request: http::Request<hj_core::IncomingBody>,
) -> Result<Response<Body>, HandlerError> {
    StaticFiles::new().handle(ctx, request).await
}

/// `Body` has no `Debug` impl, so `Result::unwrap_err` is unavailable; extract
/// the error explicitly.
fn expect_err(r: Result<Response<Body>, HandlerError>) -> HandlerError {
    match r {
        Ok(_) => panic!("expected error, got Ok response"),
        Err(e) => e,
    }
}

#[tokio::test]
async fn serves_existing_file_200() {
    let root = temp_root("serve200");
    fs::write(root.join("hello.txt"), b"hello world").unwrap();

    let vhost = Arc::new(VHostConfig {
        doc_root: root.clone(),
        ..Default::default()
    });
    let mut ctx = make_ctx(Arc::new(make_server()), vhost);

    let resp = serve(&mut ctx, req(Method::GET, "/hello.txt"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()[CONTENT_TYPE], "text/plain");
    assert_eq!(resp.headers()[CONTENT_LENGTH], "11");
    assert!(resp.headers().contains_key(LAST_MODIFIED));
    assert_eq!(resp.headers()[ACCEPT_RANGES], "bytes");
    assert!(resp.headers().contains_key(ETAG));
    let (path, range) = body_is_file(resp.body()).expect("file body");
    assert_eq!(path, root.join("hello.txt"));
    assert_eq!(range, None);

    fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn range_on_symlink_off_vhost_serves_only_the_slice() {
    // With `followSymbolLink off` the handler serves from symlink-verified bytes via
    // FileBody.cached, which the transport emits WHOLE (only the uncached disk path seeks by
    // FileBody.range). A 206 must therefore carry ONLY the requested slice — pre-sliced into
    // `cached` — not the entire file under a partial Content-Range.
    let root = temp_root("rangesymoff");
    let data: Vec<u8> = (0u32..1000).map(|i| (i % 251) as u8).collect();
    fs::write(root.join("blob.bin"), &data).unwrap();
    let vhost = Arc::new(VHostConfig {
        doc_root: root.clone(),
        allow_symbol_link: false,
        ..Default::default()
    });
    let mut ctx = make_ctx(Arc::new(make_server()), vhost);
    let request = http::Request::builder()
        .method(Method::GET)
        .uri("/blob.bin")
        .header(RANGE, "bytes=10-19")
        .body(empty_body())
        .unwrap();
    let resp = serve(&mut ctx, request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(resp.headers()[CONTENT_LENGTH], "10");
    assert_eq!(resp.headers()[CONTENT_RANGE], "bytes 10-19/1000");
    match resp.into_body() {
        Body::File(f) => {
            // Design: `cached` carries the WHOLE file and `range` stays Some; the transport applies
            // the range via the single-sourced FileBody::cached_ranged (identical on H1 and H2).
            let cached = f
                .cached
                .as_ref()
                .expect("symlink-off serve must carry verified cached bytes");
            assert_eq!(
                cached.len(),
                1000,
                "cached holds the whole file (transport slices)"
            );
            assert_eq!(f.range, Some((10, 19)));
            // The bytes actually served (after the transport applies the range) are exactly the slice.
            let served = f.cached_ranged().expect("cached present");
            assert_eq!(
                served.len(),
                10,
                "served body is the requested slice, not the full file"
            );
            assert_eq!(&served[..], &data[10..=19]);
        }
        _ => panic!("expected file body"),
    }
    fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn served_etag_matches_litespeed_layout() {
    // Serve a real file and verify the emitted ETag byte-matches OLS
    // buildFixedHeaders for fileETag=28: "<size>-<mtime>-<inode>;;;".
    use std::os::unix::fs::MetadataExt;
    let root = temp_root("etaglive");
    let file = root.join("e.txt");
    fs::write(&file, b"hello world").unwrap(); // 11 bytes = 0xb
    let mtime = SystemTime::UNIX_EPOCH + Duration::from_secs(0x69b4b394);
    set_mtime(&file, filetime_from(mtime));

    let meta = fs::metadata(&file).unwrap();
    let inode = meta.ino();
    let expected = format!("\"{:x}-{:x}-{:x};;;\"", 11u64, 0x69b4b394u64, inode);

    let vhost = Arc::new(VHostConfig {
        doc_root: root.clone(),
        ..Default::default()
    });
    let mut ctx = make_ctx(Arc::new(make_server()), vhost);
    let resp = serve(&mut ctx, req(Method::GET, "/e.txt")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()[ETAG].to_str().unwrap(), expected);
    // No charset suffix by default (addDefaultCharset off in production).
    assert_eq!(resp.headers()[CONTENT_TYPE], "text/plain");
    fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn configured_default_charset_is_applied_to_eligible_types() {
    let root = temp_root("charset");
    fs::write(root.join("a.txt"), b"text").unwrap();
    fs::write(root.join("a.bin"), b"binary").unwrap();
    let vhost = Arc::new(VHostConfig {
        doc_root: root.clone(),
        ..Default::default()
    });
    let server = Arc::new(make_server());

    let mut text_req = req(Method::GET, "/a.txt");
    text_req
        .extensions_mut()
        .insert(DefaultCharsetOverride("ISO-8859-1".to_string()));
    let mut text_ctx = make_ctx(server.clone(), vhost.clone());
    let text = serve(&mut text_ctx, text_req).await.unwrap();
    assert_eq!(
        text.headers()[CONTENT_TYPE],
        "text/plain; charset=ISO-8859-1"
    );

    let mut binary_req = req(Method::GET, "/a.bin");
    binary_req
        .extensions_mut()
        .insert(DefaultCharsetOverride("UTF-8".to_string()));
    let mut binary_ctx = make_ctx(server, vhost);
    let binary = serve(&mut binary_ctx, binary_req).await.unwrap();
    assert_eq!(binary.headers()[CONTENT_TYPE], "application/octet-stream");

    fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn header_cache_hit_is_byte_identical() {
    // Two requests for the same file through ONE shared handler must produce
    // identical ETag / Last-Modified / Content-Type / Content-Length — the
    // second served from the per-file header cache, byte-identical to the first.
    let root = temp_root("hdrcache");
    fs::write(root.join("a.txt"), b"abcdefghij".repeat(30)).unwrap();
    let vhost = Arc::new(VHostConfig {
        doc_root: root.clone(),
        ..Default::default()
    });
    let server = Arc::new(make_server());
    let handler = StaticFiles::new();

    let pull = |h: &http::HeaderMap| {
        (
            h[ETAG].clone(),
            h[LAST_MODIFIED].clone(),
            h[CONTENT_TYPE].clone(),
            h[CONTENT_LENGTH].clone(),
        )
    };

    let mut ctx1 = make_ctx(server.clone(), vhost.clone());
    let r1 = handler
        .handle(&mut ctx1, req(Method::GET, "/a.txt"))
        .await
        .unwrap();
    let mut ctx2 = make_ctx(server.clone(), vhost.clone());
    let r2 = handler
        .handle(&mut ctx2, req(Method::GET, "/a.txt"))
        .await
        .unwrap();

    assert_eq!(r1.status(), StatusCode::OK);
    assert_eq!(r2.status(), StatusCode::OK);
    assert_eq!(
        pull(r1.headers()),
        pull(r2.headers()),
        "cache hit must be byte-identical"
    );
    assert_eq!(r1.headers()[CONTENT_TYPE], "text/plain");
    assert_eq!(r1.headers()[CONTENT_LENGTH], "300");
    assert!(r1.headers()[ETAG].to_str().unwrap().ends_with(";;;\""));

    fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn resolve_cache_keeps_distinct_files() {
    // The TTL resolution cache must key per (root, rel, ...): two distinct files
    // served through ONE shared handler, then re-served (cache-hit path), must
    // each keep their own resolved path + Content-Length — a key collision would
    // serve the wrong file. Also covers the directory→index resolution memo.
    let root = temp_root("resolvecache");
    fs::write(root.join("a.txt"), b"aaaa").unwrap(); // len 4
    fs::write(root.join("b.txt"), b"bbbbbbb").unwrap(); // len 7
    fs::create_dir_all(root.join("d")).unwrap();
    fs::write(root.join("d/index.html"), b"<i>idx</i>").unwrap(); // len 10
    let vhost = Arc::new(VHostConfig {
        doc_root: root.clone(),
        ..Default::default()
    });
    let server = Arc::new(make_server());
    let handler = StaticFiles::new();

    // Prime both files + the directory index, then hit each again from the cache.
    for uri in ["/a.txt", "/b.txt", "/d/", "/a.txt", "/b.txt", "/d/"] {
        let mut ctx = make_ctx(server.clone(), vhost.clone());
        let resp = handler
            .handle(&mut ctx, req(Method::GET, uri))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{uri}");
        let want_path = match uri {
            "/a.txt" => root.join("a.txt"),
            "/b.txt" => root.join("b.txt"),
            "/d/" => root.join("d/index.html"),
            _ => unreachable!(),
        };
        let want_len = match uri {
            "/a.txt" => "4",
            "/b.txt" => "7",
            _ => "10",
        };
        assert_eq!(
            resp.headers()[CONTENT_LENGTH],
            want_len,
            "{uri} content-length"
        );
        let (path, range) = body_is_file(resp.body()).expect("file body");
        assert_eq!(
            path, want_path,
            "{uri} resolved to wrong file (cache key collision?)"
        );
        assert_eq!(range, None);
    }

    fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn resolve_cache_revalidates_atomic_file_replacement() {
    let root = temp_root("resolve-replace");
    let path = root.join("a.txt");
    fs::write(&path, b"old").unwrap();
    let vhost = Arc::new(VHostConfig {
        doc_root: root.clone(),
        allow_symbol_link: true,
        ..Default::default()
    });
    let server = Arc::new(make_server());
    let handler = StaticFiles::new();

    let mut first_ctx = make_ctx(server.clone(), vhost.clone());
    let first = handler
        .handle(&mut first_ctx, req(Method::GET, "/a.txt"))
        .await
        .unwrap();
    let old_etag = first.headers()[ETAG].clone();
    assert_eq!(first.headers()[CONTENT_LENGTH], "3");

    let replacement = root.join("replacement.txt");
    fs::write(&replacement, b"replacement-body").unwrap();
    fs::rename(&replacement, &path).unwrap();

    let mut conditional = req(Method::GET, "/a.txt");
    conditional
        .headers_mut()
        .insert(IF_NONE_MATCH, old_etag.clone());
    let mut second_ctx = make_ctx(server.clone(), vhost.clone());
    let second = handler.handle(&mut second_ctx, conditional).await.unwrap();
    assert_eq!(second.status(), StatusCode::OK);
    assert_eq!(second.headers()[CONTENT_LENGTH], "16");
    assert_ne!(second.headers()[ETAG], old_etag);
    match second.body() {
        Body::File(f) => assert_eq!(f.len, 16),
        _ => panic!("expected file body"),
    }
    assert_eq!(read_file_body(second.body()), b"replacement-body");

    let same_size = root.join("same-size.txt");
    fs::write(&same_size, b"different-body!!").unwrap();
    let second_etag = second.headers()[ETAG].clone();
    fs::rename(&same_size, &path).unwrap();
    let mut third_req = req(Method::GET, "/a.txt");
    third_req
        .headers_mut()
        .insert(IF_NONE_MATCH, second_etag.clone());
    let mut third_ctx = make_ctx(server, vhost);
    let third = handler.handle(&mut third_ctx, third_req).await.unwrap();
    assert_eq!(third.status(), StatusCode::OK);
    assert_eq!(third.headers()[CONTENT_LENGTH], "16");
    assert_ne!(third.headers()[ETAG], second_etag);
    assert_eq!(read_file_body(third.body()), b"different-body!!");

    fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn head_has_no_body() {
    let root = temp_root("head");
    fs::write(root.join("a.txt"), b"abcdef").unwrap();
    let vhost = Arc::new(VHostConfig {
        doc_root: root.clone(),
        ..Default::default()
    });
    let mut ctx = make_ctx(Arc::new(make_server()), vhost);

    let resp = serve(&mut ctx, req(Method::HEAD, "/a.txt")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()[CONTENT_LENGTH], "6");
    assert!(matches!(resp.body(), Body::Empty));
    fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn head_ignores_range_and_keeps_full_representation_length() {
    let root = temp_root("headrange");
    fs::write(root.join("a.txt"), b"abcdef").unwrap();
    let vhost = Arc::new(VHostConfig {
        doc_root: root.clone(),
        ..Default::default()
    });
    let mut ctx = make_ctx(Arc::new(make_server()), vhost);
    let mut request = req(Method::HEAD, "/a.txt");
    request
        .headers_mut()
        .insert(RANGE, HeaderValue::from_static("bytes=0-2"));

    let resp = serve(&mut ctx, request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()[CONTENT_LENGTH], "6");
    assert!(!resp.headers().contains_key(CONTENT_RANGE));
    assert!(matches!(resp.body(), Body::Empty));
    fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn missing_file_404() {
    let root = temp_root("404");
    let vhost = Arc::new(VHostConfig {
        doc_root: root.clone(),
        ..Default::default()
    });
    let mut ctx = make_ctx(Arc::new(make_server()), vhost);

    let err = expect_err(serve(&mut ctx, req(Method::GET, "/nope.txt")).await);
    assert!(matches!(err, HandlerError::NotFound));
    assert_eq!(err.status(), StatusCode::NOT_FOUND);
    fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn directory_index_served() {
    let root = temp_root("index");
    fs::write(root.join("index.html"), b"<h1>hi</h1>").unwrap();
    // vhost has no index_files -> falls back to server index_files.
    let vhost = Arc::new(VHostConfig {
        doc_root: root.clone(),
        ..Default::default()
    });
    let mut ctx = make_ctx(Arc::new(make_server()), vhost);

    let resp = serve(&mut ctx, req(Method::GET, "/")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()[CONTENT_TYPE], "text/html");
    let (path, _) = body_is_file(resp.body()).unwrap();
    assert_eq!(path, root.join("index.html"));
    fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn directory_no_index_404() {
    // OLS parity: a directory (trailing slash) with no index file and autoindex
    // off returns SC_404, not 403. 403 is reserved for EACCES.
    let root = temp_root("noindex");
    fs::create_dir_all(root.join("sub")).unwrap();
    let vhost = Arc::new(VHostConfig {
        doc_root: root.clone(),
        ..Default::default()
    });
    let mut ctx = make_ctx(Arc::new(make_server()), vhost);

    let err = expect_err(serve(&mut ctx, req(Method::GET, "/sub/")).await);
    assert!(matches!(err, HandlerError::NotFound));
    assert_eq!(err.status(), StatusCode::NOT_FOUND);
    fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn traversal_rejected() {
    let root = temp_root("traverse");
    fs::create_dir_all(root.join("pub")).unwrap();
    fs::write(root.join("secret.txt"), b"TOP SECRET").unwrap();
    fs::write(root.join("pub/ok.txt"), b"ok").unwrap();

    // doc_root is the "pub" subdir; ../secret.txt must not be reachable.
    let vhost = Arc::new(VHostConfig {
        doc_root: root.join("pub"),
        ..Default::default()
    });
    let mut ctx = make_ctx(Arc::new(make_server()), vhost);

    // Lexical escape is caught by clean_request_path -> Forbidden.
    let err = expect_err(serve(&mut ctx, req(Method::GET, "/../secret.txt")).await);
    assert!(matches!(
        err,
        HandlerError::Forbidden | HandlerError::NotFound
    ));

    // Sanity: a legit file under doc_root still works.
    let ok = serve(&mut ctx, req(Method::GET, "/ok.txt")).await.unwrap();
    assert_eq!(ok.status(), StatusCode::OK);
    fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn no_symlink_vhost_serves_from_verified_bytes_not_path_reopen() {
    // (#10) With followSymbolLink off, the response body must carry bytes read through a fresh
    // symlink-safe open (FileBody.cached), so the transport never re-opens the followable path —
    // closing the resolve->serve TOCTOU. With symlinks allowed (the prod setting), the body stays
    // path-based (cached: None) so the zero-copy hot path is unchanged.
    let root = temp_root("nosym-cached");
    fs::write(root.join("hello.txt"), b"verified-bytes").unwrap();

    let vhost = Arc::new(VHostConfig {
        doc_root: root.clone(),
        allow_symbol_link: false,
        ..Default::default()
    });
    let mut ctx = make_ctx(Arc::new(make_server()), vhost);
    let resp = serve(&mut ctx, req(Method::GET, "/hello.txt"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    match resp.body() {
        Body::File(f) => {
            let c = f
                .cached
                .as_ref()
                .expect("followSymbolLink off must serve verified cached bytes");
            assert_eq!(&c[..], b"verified-bytes");
        }
        _ => panic!("expected Body::File"),
    }

    // allow_symbol_link = true (prod): path-based body, no cached bytes (hot path unchanged).
    let vhost2 = Arc::new(VHostConfig {
        doc_root: root.clone(),
        allow_symbol_link: true,
        ..Default::default()
    });
    let mut ctx2 = make_ctx(Arc::new(make_server()), vhost2);
    let resp2 = serve(&mut ctx2, req(Method::GET, "/hello.txt"))
        .await
        .unwrap();
    match resp2.body() {
        Body::File(f) => assert!(
            f.cached.is_none(),
            "symlinks allowed -> path-based body, no cached"
        ),
        _ => panic!("expected Body::File"),
    }

    fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn symlink_escape_blocked_when_disallowed() {
    let root = temp_root("symesc");
    fs::create_dir_all(root.join("pub")).unwrap();
    fs::write(root.join("outside.txt"), b"SECRET").unwrap();
    // symlink pub/leak -> ../outside.txt (escapes doc_root via symlink)
    std::os::unix::fs::symlink(root.join("outside.txt"), root.join("pub/leak.txt")).unwrap();

    // allow_symbol_link = false (default): RESOLVE_NO_SYMLINKS must block it.
    let vhost = Arc::new(VHostConfig {
        doc_root: root.join("pub"),
        allow_symbol_link: false,
        ..Default::default()
    });
    let mut ctx = make_ctx(Arc::new(make_server()), vhost);
    let res = serve(&mut ctx, req(Method::GET, "/leak.txt")).await;
    assert!(
        res.is_err(),
        "symlink escape should be blocked when symlinks disallowed"
    );

    fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn symlink_followed_when_allowed() {
    let root = temp_root("symok");
    fs::create_dir_all(root.join("pub")).unwrap();
    fs::write(root.join("pub/real.txt"), b"data123").unwrap();
    // symlink within the tree, target stays beneath doc_root.
    std::os::unix::fs::symlink(root.join("pub/real.txt"), root.join("pub/alias.txt")).unwrap();

    let vhost = Arc::new(VHostConfig {
        doc_root: root.join("pub"),
        allow_symbol_link: true,
        ..Default::default()
    });
    let mut ctx = make_ctx(Arc::new(make_server()), vhost);
    let resp = serve(&mut ctx, req(Method::GET, "/alias.txt"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()[CONTENT_LENGTH], "7");
    let target = resp
        .extensions()
        .get::<ResolvedTargetPath>()
        .expect("resolved target extension");
    assert_eq!(
        target.0,
        fs::canonicalize(root.join("pub/real.txt")).unwrap()
    );
    fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn symlink_target_is_pinned_into_file_body_before_consumption() {
    let root = temp_root("sym-pin");
    let first_target = root.join("first.txt");
    let second_target = root.join("second.txt");
    let alias = root.join("alias.txt");
    fs::write(&first_target, b"first-target").unwrap();
    fs::write(&second_target, b"second-target").unwrap();
    std::os::unix::fs::symlink(&first_target, &alias).unwrap();

    let vhost = Arc::new(VHostConfig {
        doc_root: root.clone(),
        allow_symbol_link: true,
        ..Default::default()
    });
    let server = Arc::new(make_server());
    let handler = StaticFiles::new();
    let mut first_ctx = make_ctx(server.clone(), vhost.clone());
    let first = handler
        .handle(&mut first_ctx, req(Method::GET, "/alias.txt"))
        .await
        .unwrap();
    let Body::File(first_body) = first.body() else {
        panic!("expected file body");
    };
    assert_eq!(first_body.path, fs::canonicalize(&first_target).unwrap());

    fs::remove_file(&alias).unwrap();
    std::os::unix::fs::symlink(&second_target, &alias).unwrap();
    assert_eq!(read_file_body(first.body()), b"first-target");

    let mut second_ctx = make_ctx(server, vhost);
    let second = handler
        .handle(&mut second_ctx, req(Method::GET, "/alias.txt"))
        .await
        .unwrap();
    assert_eq!(read_file_body(second.body()), b"second-target");
    fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn range_request_206() {
    let root = temp_root("range");
    fs::write(root.join("data.txt"), b"0123456789").unwrap();
    let vhost = Arc::new(VHostConfig {
        doc_root: root.clone(),
        ..Default::default()
    });
    let mut ctx = make_ctx(Arc::new(make_server()), vhost);

    let mut request = req(Method::GET, "/data.txt");
    request
        .headers_mut()
        .insert(RANGE, HeaderValue::from_static("bytes=2-5"));
    let resp = serve(&mut ctx, request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(resp.headers()[CONTENT_RANGE], "bytes 2-5/10");
    assert_eq!(resp.headers()[CONTENT_LENGTH], "4");
    let (_, range) = body_is_file(resp.body()).unwrap();
    assert_eq!(range, Some((2, 5)));
    fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn range_unsatisfiable_416() {
    let root = temp_root("range416");
    fs::write(root.join("data.txt"), b"0123456789").unwrap();
    let vhost = Arc::new(VHostConfig {
        doc_root: root.clone(),
        ..Default::default()
    });
    let mut ctx = make_ctx(Arc::new(make_server()), vhost);

    let mut request = req(Method::GET, "/data.txt");
    request
        .headers_mut()
        .insert(RANGE, HeaderValue::from_static("bytes=50-60"));
    let resp = serve(&mut ctx, request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(resp.headers()[CONTENT_RANGE], "bytes */10");
    fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn conditional_inm_304() {
    let root = temp_root("inm");
    fs::write(root.join("c.txt"), b"cacheable").unwrap();
    let vhost = Arc::new(VHostConfig {
        doc_root: root.clone(),
        ..Default::default()
    });
    let mut ctx = make_ctx(Arc::new(make_server()), vhost);

    // First fetch to learn the ETag.
    let first = serve(&mut ctx, req(Method::GET, "/c.txt")).await.unwrap();
    let etag = first.headers()[ETAG].to_str().unwrap().to_string();

    // Re-request with If-None-Match.
    let mut request = req(Method::GET, "/c.txt");
    request
        .headers_mut()
        .insert(IF_NONE_MATCH, HeaderValue::from_str(&etag).unwrap());
    let resp = serve(&mut ctx, request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
    assert!(matches!(resp.body(), Body::Empty));
    // ETag still present on 304.
    assert_eq!(resp.headers()[ETAG], etag.as_str());
    fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn conditional_inm_star_works_when_etags_are_disabled() {
    let root = temp_root("inm-star-no-etag");
    fs::write(root.join("c.txt"), b"cacheable").unwrap();
    let vhost = Arc::new(VHostConfig {
        doc_root: root.clone(),
        ..Default::default()
    });
    let mut server = make_server();
    server.tuning.file_etag = 0;
    let mut ctx = make_ctx(Arc::new(server), vhost);

    let mut request = req(Method::GET, "/c.txt");
    request
        .headers_mut()
        .insert(IF_NONE_MATCH, HeaderValue::from_static("*"));
    let resp = serve(&mut ctx, request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
    assert!(!resp.headers().contains_key(ETAG));
    assert!(matches!(resp.body(), Body::Empty));
    fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn conditional_ims_304() {
    let root = temp_root("ims");
    let file = root.join("c.txt");
    fs::write(&file, b"cacheable").unwrap();
    // Pin mtime well in the past so "now" If-Modified-Since yields 304.
    let mtime = SystemTime::now() - Duration::from_secs(3600);
    let ft = filetime_from(mtime);
    set_mtime(&file, ft);

    let vhost = Arc::new(VHostConfig {
        doc_root: root.clone(),
        ..Default::default()
    });
    let mut ctx = make_ctx(Arc::new(make_server()), vhost);

    let mut request = req(Method::GET, "/c.txt");
    let now = httpdate::fmt_http_date(SystemTime::now());
    request
        .headers_mut()
        .insert(IF_MODIFIED_SINCE, HeaderValue::from_str(&now).unwrap());
    let resp = serve(&mut ctx, request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
    fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn if_match_mismatch_returns_412() {
    let root = temp_root("ifmatch");
    fs::write(root.join("c.txt"), b"cacheable").unwrap();
    let vhost = Arc::new(VHostConfig {
        doc_root: root.clone(),
        ..Default::default()
    });
    let mut ctx = make_ctx(Arc::new(make_server()), vhost);

    let mut request = req(Method::GET, "/c.txt");
    request
        .headers_mut()
        .insert(IF_MATCH, HeaderValue::from_static("\"bogus\""));
    let resp = serve(&mut ctx, request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
    assert!(matches!(resp.body(), Body::Empty));
    fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn if_unmodified_since_stale_returns_412() {
    let root = temp_root("ius");
    let file = root.join("c.txt");
    fs::write(&file, b"cacheable").unwrap();
    let mtime = SystemTime::now();
    set_mtime(&file, filetime_from(mtime));
    let vhost = Arc::new(VHostConfig {
        doc_root: root.clone(),
        ..Default::default()
    });
    let mut ctx = make_ctx(Arc::new(make_server()), vhost);

    let mut request = req(Method::GET, "/c.txt");
    let stale = httpdate::fmt_http_date(mtime - Duration::from_secs(3600));
    request
        .headers_mut()
        .insert(IF_UNMODIFIED_SINCE, HeaderValue::from_str(&stale).unwrap());
    let resp = serve(&mut ctx, request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
    assert!(matches!(resp.body(), Body::Empty));
    fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn if_range_mismatch_serves_full() {
    let root = temp_root("ifrange");
    fs::write(root.join("d.txt"), b"0123456789").unwrap();
    let vhost = Arc::new(VHostConfig {
        doc_root: root.clone(),
        ..Default::default()
    });
    let mut ctx = make_ctx(Arc::new(make_server()), vhost);

    let mut request = req(Method::GET, "/d.txt");
    request
        .headers_mut()
        .insert(RANGE, HeaderValue::from_static("bytes=2-5"));
    // If-Range with a stale ETag → must ignore Range and return full 200.
    request
        .headers_mut()
        .insert(IF_RANGE, HeaderValue::from_static("\"stale-etag\""));
    let resp = serve(&mut ctx, request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let (_, range) = body_is_file(resp.body()).unwrap();
    assert_eq!(range, None);
    fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn post_method_405() {
    let root = temp_root("post");
    fs::write(root.join("x.txt"), b"x").unwrap();
    let vhost = Arc::new(VHostConfig {
        doc_root: root.clone(),
        ..Default::default()
    });
    let mut ctx = make_ctx(Arc::new(make_server()), vhost);

    let resp = serve(&mut ctx, req(Method::POST, "/x.txt")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(resp.headers()[http::header::ALLOW], "GET, HEAD");
    fs::remove_dir_all(&root).ok();
}

// ----------------------------------------------------------------------------
// Read-only smoke test against the live /web tree. Ignored by default (touches
// the production filesystem read-only); run with `--ignored` to exercise it.
// ----------------------------------------------------------------------------

#[tokio::test]
#[ignore = "reads the live /web production tree; run explicitly with --ignored"]
async fn real_web_public_html_index() {
    let root = PathBuf::from("/web/public_html");
    if !root.join("index.html").exists() {
        eprintln!("skipping: /web/public_html/index.html not present");
        return;
    }
    // Mirror the live install: vhost allows symlinks under public_html.
    let vhost = Arc::new(VHostConfig {
        doc_root: root.clone(),
        allow_symbol_link: true,
        ..Default::default()
    });
    let mut server = make_server();
    // Use a realistic html mime mapping.
    server
        .mime
        .by_suffix
        .insert("html".into(), "text/html".into());
    let mut ctx = make_ctx(Arc::new(server), vhost);

    // Directory -> index.html
    let resp = serve(&mut ctx, req(Method::GET, "/")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let (path, _) = body_is_file(resp.body()).unwrap();
    assert_eq!(path, root.join("index.html"));
    assert!(resp.headers().contains_key(ETAG));
    assert!(resp.headers().contains_key(LAST_MODIFIED));

    // A traversal attempt must never reach /etc/passwd.
    let escaped = serve(&mut ctx, req(Method::GET, "/../../etc/passwd")).await;
    assert!(escaped.is_err(), "traversal out of /web must fail");

    // robots.txt is a real file in this tree.
    if root.join("robots.txt").exists() {
        let r = serve(&mut ctx, req(Method::GET, "/robots.txt"))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(r.headers()[ACCEPT_RANGES], "bytes");
    }
}

// --- small mtime helpers (avoid extra deps; use libc utimensat via std) ----

/// We only need to push mtime into the past; do it with a direct utimensat
/// through rustix to avoid pulling in the `filetime` crate.
struct Ft {
    secs: i64,
}

fn filetime_from(t: SystemTime) -> Ft {
    let secs = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    Ft { secs }
}

fn set_mtime(path: &Path, ft: Ft) {
    use rustix::fs::Timespec;
    use rustix::fs::{AtFlags, Timestamps, utimensat};
    let ts = Timestamps {
        last_access: Timespec {
            tv_sec: ft.secs,
            tv_nsec: 0,
        },
        last_modification: Timespec {
            tv_sec: ft.secs,
            tv_nsec: 0,
        },
    };
    let dir = rustix::fs::open(
        path.parent().unwrap(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .unwrap();
    let name = path.file_name().unwrap().to_string_lossy().to_string();
    utimensat(&dir, name, &ts, AtFlags::empty()).unwrap();
}

// ---- DirectorySlash (Apache mod_dir / OLS redirectDir) ----------------------

/// A directory requested WITHOUT a trailing slash 301-redirects to add it,
/// regardless of whether an index exists (the index resolves on the re-request).
#[tokio::test]
async fn directory_no_slash_redirects_301() {
    let root = temp_root("dirslash");
    fs::create_dir(root.join("sub")).unwrap();
    fs::write(root.join("sub/index.html"), b"<h1>hi</h1>").unwrap();
    let vhost = Arc::new(VHostConfig {
        doc_root: root.clone(),
        ..Default::default()
    });
    let mut ctx = make_ctx(Arc::new(make_server()), vhost);

    let resp = serve(&mut ctx, req(Method::GET, "/sub")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::MOVED_PERMANENTLY);
    assert_eq!(resp.headers()[LOCATION], "/sub/");
    fs::remove_dir_all(&root).ok();
}

/// The slashed form serves the index (200) — the redirect target works.
#[tokio::test]
async fn directory_with_slash_serves_index_200() {
    let root = temp_root("dirslash_idx");
    fs::create_dir(root.join("sub")).unwrap();
    fs::write(root.join("sub/index.html"), b"<h1>hi</h1>").unwrap();
    let vhost = Arc::new(VHostConfig {
        doc_root: root.clone(),
        ..Default::default()
    });
    let mut ctx = make_ctx(Arc::new(make_server()), vhost);

    let resp = serve(&mut ctx, req(Method::GET, "/sub/")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let (path, _) = body_is_file(resp.body()).expect("file body");
    assert_eq!(path, root.join("sub/index.html"));
    fs::remove_dir_all(&root).ok();
}

/// The DirectorySlash redirect preserves the query string.
#[tokio::test]
async fn directory_no_slash_preserves_query() {
    let root = temp_root("dirslash_q");
    fs::create_dir(root.join("builds")).unwrap();
    let vhost = Arc::new(VHostConfig {
        doc_root: root.clone(),
        ..Default::default()
    });
    let mut ctx = make_ctx(Arc::new(make_server()), vhost);

    let resp = serve(&mut ctx, req(Method::GET, "/builds?a=1&b=2"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::MOVED_PERMANENTLY);
    assert_eq!(resp.headers()[LOCATION], "/builds/?a=1&b=2");
    fs::remove_dir_all(&root).ok();
}

/// Regression (#93): the DirectorySlash 301 Location is built from the lexically-normalized
/// path, not the raw `uri().path()` — redundant `.`/`..`/`//` segments collapse so the redirect
/// is canonical, and with exactly one leading slash it can never become a protocol-relative
/// (`//host`) off-origin redirect.
#[tokio::test]
async fn directory_no_slash_location_is_canonical() {
    let root = temp_root("dirslash_canon");
    fs::create_dir(root.join("sub")).unwrap();
    let vhost = Arc::new(VHostConfig {
        doc_root: root.clone(),
        ..Default::default()
    });
    let mut ctx = make_ctx(Arc::new(make_server()), vhost);

    // Each raw form resolves to the "sub" directory; the Location must be the canonical "/sub/".
    // (A leading `//` is parsed as a URI authority, not a path, so it's exercised by the unit
    // test on `directory_slash_redirect` rather than end-to-end here.)
    for raw in ["/./sub", "/a/../sub", "/sub/."] {
        let resp = serve(&mut ctx, req(Method::GET, raw)).await.unwrap();
        // "/sub/." has no trailing slash and maps to the dir → DirectorySlash like the others.
        assert_eq!(resp.status(), StatusCode::MOVED_PERMANENTLY, "{raw}");
        assert_eq!(
            resp.headers()[LOCATION],
            "/sub/",
            "{raw}: Location must be canonical + same-origin"
        );
    }
    fs::remove_dir_all(&root).ok();
}

/// A slashless directory with NO index still redirects (Apache order: add the
/// slash first; the 404-for-no-index happens on the slashed re-request).
#[tokio::test]
async fn directory_no_slash_no_index_still_redirects() {
    let root = temp_root("dirslash_noidx");
    fs::create_dir(root.join("data")).unwrap();
    fs::write(root.join("data/x.bin"), b"x").unwrap(); // non-index file present
    let vhost = Arc::new(VHostConfig {
        doc_root: root.clone(),
        ..Default::default()
    });
    let mut ctx = make_ctx(Arc::new(make_server()), vhost);

    let resp = serve(&mut ctx, req(Method::GET, "/data")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::MOVED_PERMANENTLY);
    assert_eq!(resp.headers()[LOCATION], "/data/");
    // ...and the slashed form with no index 404s (autoindex off).
    let resp2 = serve(&mut ctx, req(Method::GET, "/data/")).await;
    assert!(matches!(expect_err(resp2), HandlerError::NotFound));
    fs::remove_dir_all(&root).ok();
}

/// Nested directories redirect at the full path.
#[tokio::test]
async fn nested_directory_no_slash_redirects() {
    let root = temp_root("dirslash_nested");
    fs::create_dir_all(root.join("a/b")).unwrap();
    let vhost = Arc::new(VHostConfig {
        doc_root: root.clone(),
        ..Default::default()
    });
    let mut ctx = make_ctx(Arc::new(make_server()), vhost);

    let resp = serve(&mut ctx, req(Method::GET, "/a/b")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::MOVED_PERMANENTLY);
    assert_eq!(resp.headers()[LOCATION], "/a/b/");
    fs::remove_dir_all(&root).ok();
}

/// A regular file is served normally — no spurious redirect.
#[tokio::test]
async fn file_request_not_redirected() {
    let root = temp_root("dirslash_file");
    fs::write(root.join("page.html"), b"<h1>p</h1>").unwrap();
    let vhost = Arc::new(VHostConfig {
        doc_root: root.clone(),
        ..Default::default()
    });
    let mut ctx = make_ctx(Arc::new(make_server()), vhost);

    let resp = serve(&mut ctx, req(Method::GET, "/page.html"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    fs::remove_dir_all(&root).ok();
}

// ----------------------------------------------------------------------------
// Intermediate-component symlink traversal (item 17)
// ----------------------------------------------------------------------------
//
// With allow_symbol_link=false the resolver uses
// openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS). When openat2 is unsupported by
// the kernel *or filesystem* (ENOSYS/EOPNOTSUPP — overlayfs/Docker, some
// FUSE/NFS) the resolver now FAILS CLOSED instead of falling back to a single
// openat(O_NOFOLLOW), which would only guard the final component and let an
// in-docroot intermediate symlink (`link -> /etc`, request `link/passwd`)
// escape the tree. These tests assert the escape is refused end-to-end; the
// fallback branch itself is unreachable on a normal kernel, but its removal
// means no path can degrade to the weaker check.

/// `link -> /etc` is an in-docroot intermediate symlink with an absolute target;
/// `link/passwd` must be refused, never served, with symlinks disallowed.
#[tokio::test]
async fn intermediate_symlink_absolute_target_refused() {
    let root = temp_root("symint_abs");
    std::os::unix::fs::symlink("/etc", root.join("link")).unwrap();

    let vhost = Arc::new(VHostConfig {
        doc_root: root.clone(),
        allow_symbol_link: false,
        ..Default::default()
    });
    let mut ctx = make_ctx(Arc::new(make_server()), vhost);

    let res = serve(&mut ctx, req(Method::GET, "/link/passwd")).await;
    match res {
        Err(HandlerError::NotFound) | Err(HandlerError::Forbidden) => {}
        Err(other) => panic!("expected NotFound/Forbidden, got {other:?}"),
        Ok(resp) => panic!("intermediate symlink traversed; status {}", resp.status()),
    }
    fs::remove_dir_all(&root).ok();
}

/// `docroot/link -> ../outside` (relative target escaping the docroot through an
/// intermediate component); `link/secret.txt` must also be refused.
#[tokio::test]
async fn intermediate_symlink_sibling_target_refused() {
    let base = temp_root("symint_sib");
    let root = base.join("docroot");
    let outside = base.join("outside");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("secret.txt"), b"SECRET").unwrap();
    std::os::unix::fs::symlink("../outside", root.join("link")).unwrap();

    let vhost = Arc::new(VHostConfig {
        doc_root: root.clone(),
        allow_symbol_link: false,
        ..Default::default()
    });
    let mut ctx = make_ctx(Arc::new(make_server()), vhost);

    let res = serve(&mut ctx, req(Method::GET, "/link/secret.txt")).await;
    match res {
        Err(HandlerError::NotFound) | Err(HandlerError::Forbidden) => {}
        Err(other) => panic!("expected NotFound/Forbidden, got {other:?}"),
        Ok(resp) => panic!("intermediate symlink traversed; status {}", resp.status()),
    }
    fs::remove_dir_all(&base).ok();
}

/// Directly exercise the resolver primitive: opening a path whose *intermediate*
/// component is a symlink out of the tree must error, never return the escaped
/// file's metadata, when symlinks are disallowed.
#[test]
fn open_beneath_refuses_intermediate_symlink() {
    let root = temp_root("symint_unit");
    std::os::unix::fs::symlink("/etc", root.join("link")).unwrap();
    let root_fd = open_dir(&root).unwrap();

    let res = open_beneath(&root_fd, "link/passwd", false);
    assert!(
        res.is_err(),
        "open_beneath must refuse an intermediate symlink when allow_symlink=false"
    );
    fs::remove_dir_all(&root).ok();
}

/// Open-redirect guard: a path with extra leading slashes is normalized to a
/// single leading slash so the Location can't become protocol-relative.
#[test]
fn directory_slash_redirect_normalizes_leading_slashes() {
    use http::uri::{Authority, Parts, PathAndQuery, Scheme, Uri};
    // Force an origin path of "//evil.com" (can't go through normal parsing,
    // which would treat "//" as an authority) via Uri::from_parts.
    let mut parts = Parts::default();
    parts.scheme = Some(Scheme::HTTPS);
    parts.authority = Some(Authority::from_static("forum.example"));
    parts.path_and_query = Some(PathAndQuery::from_static("//evil.com"));
    let uri = Uri::from_parts(parts).unwrap();
    let resp = directory_slash_redirect(&uri);
    assert_eq!(resp.status(), StatusCode::MOVED_PERMANENTLY);
    // single leading slash → same-origin, NOT protocol-relative "//evil.com/"
    assert_eq!(resp.headers()[LOCATION], "/evil.com/");
}

/// Open-redirect guard (#93): a LITERAL backslash in the path (passed through by the
/// http/httparse parsers — NOT rejected) must be treated as a path separator, so a
/// "/\evil.com" request cannot yield a "/\evil.com/" Location that WHATWG browsers fold
/// to the off-origin "//evil.com/".
#[test]
fn directory_slash_redirect_neutralizes_backslash() {
    use http::uri::{Authority, Parts, PathAndQuery, Scheme, Uri};
    let pq = PathAndQuery::try_from("/\\evil.com")
        .expect("http accepts a literal backslash in the path (the reachability premise of #93)");
    let mut parts = Parts::default();
    parts.scheme = Some(Scheme::HTTPS);
    parts.authority = Some(Authority::from_static("forum.example"));
    parts.path_and_query = Some(pq);
    let uri = Uri::from_parts(parts).unwrap();
    let resp = directory_slash_redirect(&uri);
    assert_eq!(resp.status(), StatusCode::MOVED_PERMANENTLY);
    let loc = resp.headers()[LOCATION].to_str().unwrap();
    // The backslash is a separator now → "/evil.com/", same-origin (NOT "/\evil.com/").
    assert_eq!(
        loc, "/evil.com/",
        "a literal backslash must be neutralized to a same-origin Location"
    );
    assert!(
        !loc.contains('\\'),
        "the Location must contain no literal backslash"
    );
}
