//! Rewrite-outcome-cache differential replay against PRODUCTION traffic.
//!
//! Replays real request lines (method + URI + User-Agent from the combined
//! access logs under `/usr/local/lsws/logs` + `/usr/local/httpjet/logs`)
//! through `run_rewrite` with the outcome cache OFF, ON (raw-UA keying), and
//! ON + `--rewrite-ua-classify`, asserting an IDENTICAL `RwResult` for every
//! line — the correctness gate for enabling the cache on the representative forum
//! vhost — and reporting the would-be hit ratio of each keying mode.
//!
//! The combined log format carries no Host, Cookie, or Origin, so those fields
//! are SYNTHESIZED deterministically per line from the live `.htaccess` rule
//! patterns (admin/session cookies, CORS origins, OPTIONS preflights) — stated
//! per the task; URI/method/UA are real. Two `.htaccess` variants run:
//!   * AS-IS: the live file. Its `RewriteCond %{HTTP_COOKIE}` keeps the whole
//!     chain uncacheable, so the replay proves the bypass is total (every line
//!     counts `uncacheable`, outcomes identical trivially).
//!   * DRAFT: the live file with the admin-cookie cond replaced by the
//!     `SetEnvIfNoCase Cookie …` construction drafted in
//!     /var/log/wf-perf-audit/htaccess-setenvif.draft.txt. The chain becomes
//!     cacheable; this measures the hit ratio the deploy is banking on.
//!
//! Skips (with a message) when the live `.htaccess` or ≥10k log lines are
//! unavailable, so the suite stays green on other machines.

use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use hj_core::config::{ServerConfig, VHostConfig};
use hj_core::{Proto, ReqCtx, Request};
use hj_rewrite::Htaccess;

use crate::state::{RewriteTuning, ServerState, XfCapsuleConfig};

use super::htaccess_apply::{apply_set_env, seed_server_env};
use super::rewrite_glue::{decode_request_path, normalized_request_path, run_rewrite};

const LIVE_HTACCESS: &str = "/web/public_html/.htaccess";
const MIN_LINES: usize = 10_000;
const MAX_LINES: usize = 25_000;
const VHOST: &str = "forum.example";

/// The SetEnvIf admin construction DEPLOYED to the live .htaccess (2026-07-16,
/// from /var/log/wf-perf-audit/htaccess-setenvif.draft.txt) and the historical
/// cookie-poisoned cond pair it replaced. Variant A of the replay reconstructs
/// the poisoned file from the live one so the chain-poisoning regression stays
/// covered after the deploy.
const ADMIN_URI_COND_DEPLOYED: &str = "    RewriteCond %{REQUEST_URI} ^/admin.php\n";
const ADMIN_URI_COND_POISONED: &str = "    RewriteCond %{REQUEST_URI} ^/admin.php [OR]\n    RewriteCond %{HTTP_COOKIE} (xf_session_admin) [NC]\n";
const ADMIN_SETENVIF_CC: &str =
    "    SetEnvIfNoCase Cookie xf_session_admin Cache-Control=no-cache\n";
const ADMIN_SETENVIF_VARY: &str = "    SetEnvIfNoCase Cookie xf_session_admin cache-vary=admin\n";

#[derive(Clone)]
struct Line {
    method: String,
    uri: String,
    ua: String,
    cookie: Option<&'static str>,
    origin: Option<&'static str>,
}

/// Parse one combined-format line: `ip - - [t] "METHOD URI PROTO" st len "ref" "UA" …`.
fn parse_combined(line: &str) -> Option<(String, String, String)> {
    let mut quoted = Vec::with_capacity(3);
    let mut rest = line;
    while let Some(start) = rest.find('"') {
        let after = &rest[start + 1..];
        let end = after.find('"')?;
        quoted.push(&after[..end]);
        rest = &after[end + 1..];
        if quoted.len() == 3 {
            break;
        }
    }
    if quoted.len() < 3 {
        return None;
    }
    let mut req = quoted[0].split(' ');
    let method = req.next()?.to_string();
    let uri = req.next()?.to_string();
    if !method.chars().all(|c| c.is_ascii_uppercase()) || !uri.starts_with('/') {
        return None;
    }
    Some((method, uri, quoted[2].to_string()))
}

fn read_lines_into(path: &Path, out: &mut Vec<(String, String, String)>) {
    let Ok(bytes) = std::fs::read(path) else {
        return;
    };
    let text = if path.extension().is_some_and(|e| e == "gz") {
        let mut s = String::new();
        let mut dec = flate2::read::GzDecoder::new(&bytes[..]);
        if dec.read_to_string(&mut s).is_err() {
            return;
        }
        s
    } else {
        String::from_utf8_lossy(&bytes).into_owned()
    };
    for l in text.lines() {
        if out.len() >= MAX_LINES {
            return;
        }
        if let Some(p) = parse_combined(l) {
            out.push(p);
        }
    }
}

/// Real production request lines: the two live logs first, then rotated `.gz`
/// siblings (newest first) until `MAX_LINES`.
fn load_corpus() -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for dir in ["/usr/local/lsws/logs", "/usr/local/httpjet/logs"] {
        read_lines_into(&Path::new(dir).join("httpjet_access.log"), &mut out);
    }
    if out.len() < MAX_LINES {
        let mut rotated: Vec<PathBuf> = Vec::new();
        for dir in ["/usr/local/lsws/logs", "/usr/local/httpjet/logs"] {
            if let Ok(rd) = std::fs::read_dir(dir) {
                rotated.extend(rd.filter_map(|e| e.ok()).map(|e| e.path()).filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with("httpjet_access.log.") && n.ends_with(".gz"))
                }));
            }
        }
        rotated.sort();
        for p in rotated.iter().rev() {
            if out.len() >= MAX_LINES {
                break;
            }
            read_lines_into(p, &mut out);
        }
    }
    out
}

fn fnv(line_no: usize) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for b in line_no.to_le_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h
}

/// Deterministic cookie/Origin synthesis (the logs carry neither): ~2% admin
/// session, ~28% ordinary session, rest cookieless; ~1.5% carry an Origin.
fn synthesize(raw: Vec<(String, String, String)>) -> Vec<Line> {
    let mut out: Vec<Line> = raw
        .into_iter()
        .enumerate()
        .map(|(i, (method, uri, ua))| {
            let h = fnv(i);
            let cookie = match h % 100 {
                0..=1 => Some("xf_csrf=abc; xf_session_admin=deadbeef; xf_user=1%2Cx"),
                2..=29 => Some("xf_csrf=abc; xf_session=cafef00d"),
                _ => None,
            };
            let origin = match h % 1000 {
                990..=994 => Some("https://www.google.com"),
                995..=997 => Some("https://forum.example"),
                998 => Some(""),
                _ => None,
            };
            Line {
                method,
                uri,
                ua,
                cookie,
                origin,
            }
        })
        .collect();
    // Hand-crafted lines exercising the live rule patterns the sampled window
    // may lack: CORS preflights (allowed + foreign origin), admin, auth
    // actions, no-cache endpoints, crawler UAs, failover-test thread.
    let ua_browser = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/145.0.0.0 Safari/537.36";
    let mut push = |method: &str, uri: &str, ua: &str, cookie, origin| {
        out.push(Line {
            method: method.into(),
            uri: uri.into(),
            ua: ua.into(),
            cookie,
            origin,
        })
    };
    for origin in [
        Some("https://googleads.g.doubleclick.net"),
        Some("https://evil.example"),
        Some(""),
        None,
    ] {
        push(
            "OPTIONS",
            "/threads/some-thread.12345/",
            ua_browser,
            None,
            origin,
        );
        push("OPTIONS", "/", ua_browser, None, origin);
    }
    for uri in [
        "/admin.php?spam-cleaner/x",
        "/login/login",
        "/logout/",
        "/misc/cookies",
        "/api/threads/1/",
        "/proxy.php?image=https%3A%2F%2Fexample.com%2Fa.png&hash=x",
        "/proxy.php?link=https%3A%2F%2Fexample.com%2F",
        "/webmcp/tools",
        "/webmcp/manifest.json",
        "/vc.php",
        "/wp-login.php",
        "/sso/callback",
        "/builds/windows11",
        "/threads/for-the-second-time-i-have-had-a-windows-update-that-failed.400823/",
    ] {
        push("GET", uri, ua_browser, Some("xf_csrf=abc"), None);
        push(
            "GET",
            uri,
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            None,
            None,
        );
    }
    for ua in [
        "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
        "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
        "Mediapartners-Google",
        "curl/8.5.0",
        "",
    ] {
        push("GET", "/whats-new/", ua, None, None);
        push("GET", "/", ua, None, None);
    }
    out
}

fn temp_dir(tag: &str) -> PathBuf {
    super::e2e::sweep_stale_test_dirs();
    let p = std::env::temp_dir().join(format!(
        "hj-rwdiff-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// A docroot carrying `htaccess` plus a few real files/dirs so the live
/// `-f`/`-d`/static-prefix rules take both branches during the replay.
fn make_docroot(tag: &str, htaccess: &str) -> PathBuf {
    let root = temp_dir(tag);
    std::fs::write(root.join(".htaccess"), htaccess).unwrap();
    for d in ["js", "styles", "data", "builds"] {
        std::fs::create_dir_all(root.join(d)).unwrap();
    }
    std::fs::write(root.join("index.php"), "<?php\n").unwrap();
    std::fs::write(root.join("favicon.ico"), "x").unwrap();
    std::fs::write(root.join("robots.txt"), "User-agent: *\n").unwrap();
    std::fs::write(root.join("js/app.js"), "//\n").unwrap();
    root
}

fn make_state(tuning: RewriteTuning) -> Arc<ServerState> {
    let server_root = temp_dir("srv");
    std::fs::create_dir_all(server_root.join("logs")).unwrap();
    let server = ServerConfig {
        server_root,
        ..ServerConfig::default()
    };
    ServerState::new(
        Arc::new(server),
        None,
        None,
        None,
        Arc::new(hj_compress::PageDictRegistry::empty()),
        1,
        XfCapsuleConfig::disabled(),
        None,
        false,
        None,
        false,
        tuning,
    )
    .unwrap()
}

fn make_ctx(server: &Arc<ServerConfig>, vhost: &Arc<VHostConfig>) -> ReqCtx {
    ReqCtx {
        server: server.clone(),
        vhost_name: VHOST.into(),
        vhost: vhost.clone(),
        peer_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        is_tls: true,
        protocol: Proto::Http2,
        trusted_proxy: false,
        forwarding_trusted: false,
        env: Vec::with_capacity(8),
        local_addr: SocketAddr::from(([127, 0, 0, 1], 443)),
        peer_port: 40000,
        peer_unix: false,
        tls: None,
        redirect_guard: None,
        request_time: std::time::SystemTime::now(),
        request_id: Default::default(),
    }
}

fn build_request(l: &Line) -> Option<Request> {
    let mut b = http::Request::builder()
        .method(l.method.as_str())
        .uri(l.uri.as_str())
        .header(http::header::HOST, VHOST);
    if !l.ua.is_empty() {
        b = b.header(http::header::USER_AGENT, l.ua.as_str());
    }
    if let Some(c) = l.cookie {
        b = b.header(http::header::COOKIE, c);
    }
    if let Some(o) = l.origin {
        b = b.header(http::header::ORIGIN, o);
    }
    b.body(hj_core::empty_incoming()).ok()
}

struct ReplayStats {
    lines: usize,
    hits_raw: u64,
    misses_raw: u64,
    uncacheable_raw: u64,
    hits_classified: u64,
    misses_classified: u64,
    ua_classify_entries: usize,
}

/// Replay `corpus` through cache-off / cache-on(raw UA) / cache-on(ua-classify)
/// states over `docroot`, asserting identical `RwResult` per line.
fn replay(docroot: &Path, corpus: &[Line], tag: &str) -> ReplayStats {
    // Long TTL isolates KEYABILITY from replay speed (the production default is
    // 1 s; a multi-second replay would expire entries mid-run and understate
    // the intrinsic ratio — the report calls this out).
    let ttl = std::time::Duration::from_secs(600);
    let state_off = make_state(RewriteTuning {
        outcome_ttl: std::time::Duration::ZERO,
        ua_classify: false,
    });
    let state_raw = make_state(RewriteTuning {
        outcome_ttl: ttl,
        ua_classify: false,
    });
    let state_cls = make_state(RewriteTuning {
        outcome_ttl: ttl,
        ua_classify: true,
    });
    let vhost = Arc::new(VHostConfig {
        doc_root: docroot.to_path_buf(),
        ..VHostConfig::default()
    });

    let mut lines = 0usize;
    for (i, l) in corpus.iter().enumerate() {
        let Some(req) = build_request(l) else {
            continue;
        };
        let Some(decoded) = decode_request_path(req.uri().path()) else {
            continue;
        };
        let orig_path = normalized_request_path(&decoded);
        let orig_query = req.uri().query().unwrap_or("").to_string();
        // One parsed chain shared by all three states (identical file bytes;
        // what differs is only each state's outcome cache).
        let chain = state_off
            .rewrite_cache
            .load_chain_with_dirs(docroot, &orig_path, ".htaccess");
        let flat: Vec<Arc<Htaccess>> = chain.iter().map(|(_, h)| h.clone()).collect();
        let mut ctx = make_ctx(&state_off.server, &vhost);
        seed_server_env(&mut ctx);
        apply_set_env(&mut ctx, &flat, &req, &orig_path, &orig_query).unwrap();

        let r_off = run_rewrite(&state_off, &ctx, &req, &chain, &orig_path, &orig_query);
        let r_raw = run_rewrite(&state_raw, &ctx, &req, &chain, &orig_path, &orig_query);
        let r_cls = run_rewrite(&state_cls, &ctx, &req, &chain, &orig_path, &orig_query);
        assert_eq!(
            r_raw, r_off,
            "[{tag}] line {i}: outcome-cache(raw-UA) diverged for {} {} ua={:?} cookie={:?} origin={:?}",
            l.method, l.uri, l.ua, l.cookie, l.origin
        );
        assert_eq!(
            r_cls, r_off,
            "[{tag}] line {i}: outcome-cache(ua-classify) diverged for {} {} ua={:?} cookie={:?} origin={:?}",
            l.method, l.uri, l.ua, l.cookie, l.origin
        );
        lines += 1;
    }
    ReplayStats {
        lines,
        hits_raw: state_raw
            .metrics
            .rewrite_outcome_hits
            .load(Ordering::Relaxed),
        misses_raw: state_raw
            .metrics
            .rewrite_outcome_misses
            .load(Ordering::Relaxed),
        uncacheable_raw: state_raw
            .metrics
            .rewrite_outcome_uncacheable
            .load(Ordering::Relaxed),
        hits_classified: state_cls
            .metrics
            .rewrite_outcome_hits
            .load(Ordering::Relaxed),
        misses_classified: state_cls
            .metrics
            .rewrite_outcome_misses
            .load(Ordering::Relaxed),
        ua_classify_entries: state_cls.ua_classify.len(),
    }
}

/// One `run_rewrite` call over `docroot` for a GET with optional UA/Origin.
fn run_one(
    state: &Arc<ServerState>,
    docroot: &Path,
    path: &str,
    ua: Option<&str>,
    origin: Option<&str>,
) -> super::rewrite_glue::RwResult {
    let l = Line {
        method: "GET".into(),
        uri: path.into(),
        ua: ua.unwrap_or("").into(),
        cookie: None,
        origin: None,
    };
    let mut req = build_request(&l).unwrap();
    if let Some(o) = origin {
        req.headers_mut().insert(
            http::header::ORIGIN,
            http::HeaderValue::from_str(o).unwrap(),
        );
    }
    let orig_path = normalized_request_path(&decode_request_path(path).unwrap());
    let chain = state
        .rewrite_cache
        .load_chain_with_dirs(docroot, &orig_path, ".htaccess");
    let flat: Vec<Arc<Htaccess>> = chain.iter().map(|(_, h)| h.clone()).collect();
    let vhost = Arc::new(VHostConfig {
        doc_root: docroot.to_path_buf(),
        ..VHostConfig::default()
    });
    let mut ctx = make_ctx(&state.server, &vhost);
    seed_server_env(&mut ctx);
    apply_set_env(&mut ctx, &flat, &req, &orig_path, "").unwrap();
    run_rewrite(state, &ctx, &req, &chain, &orig_path, "")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn origin_absent_keys_distinctly_from_empty() {
    let root = make_docroot(
        "origin",
        "RewriteEngine On\n\
         RewriteCond %{HTTP:Origin} .+\n\
         RewriteRule .* - [E=HAS_ORIGIN:1]\n",
    );
    let state = make_state(RewriteTuning {
        outcome_ttl: std::time::Duration::from_secs(600),
        ua_classify: false,
    });
    let m = &state.metrics;
    let counts = || {
        (
            m.rewrite_outcome_hits.load(Ordering::Relaxed),
            m.rewrite_outcome_misses.load(Ordering::Relaxed),
        )
    };
    // Absent, then empty: SAME eval result today, but they MUST occupy two
    // distinct cache entries (two misses, no hit).
    let r_absent = run_one(&state, &root, "/p", None, None);
    let r_empty = run_one(&state, &root, "/p", None, Some(""));
    assert_eq!(r_absent, r_empty, "engine expands both to \"\" today");
    assert_eq!(
        counts(),
        (0, 2),
        "absent and empty Origin must not share an entry"
    );
    // Replays hit their own entries.
    run_one(&state, &root, "/p", None, None);
    run_one(&state, &root, "/p", None, Some(""));
    assert_eq!(counts(), (2, 2));
    // A real Origin value is a third entry, and its outcome differs.
    let r_val = run_one(&state, &root, "/p", None, Some("https://example.com"));
    assert_ne!(r_val, r_absent);
    assert_eq!(counts(), (2, 3));
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ua_classify_collapses_uas_onto_bitmap_entries() {
    let ht = "RewriteEngine On\n\
              RewriteCond %{HTTP_USER_AGENT} (Googlebot|Bingbot)\n\
              RewriteRule .* - [E=KNOWN_CRAWLER:1]\n";
    let root = make_docroot("uacls", ht);
    let raw = make_state(RewriteTuning {
        outcome_ttl: std::time::Duration::from_secs(600),
        ua_classify: false,
    });
    let cls = make_state(RewriteTuning {
        outcome_ttl: std::time::Duration::from_secs(600),
        ua_classify: true,
    });
    // Two DIFFERENT bot UAs matching the same cond: raw keying misses twice;
    // bitmap keying hits on the second (same signature ⇒ same entry).
    for state in [&raw, &cls] {
        run_one(state, &root, "/x", Some("Googlebot/2.1"), None);
        run_one(state, &root, "/x", Some("Bingbot/2.0"), None);
    }
    assert_eq!(raw.metrics.rewrite_outcome_hits.load(Ordering::Relaxed), 0);
    assert_eq!(
        raw.metrics.rewrite_outcome_misses.load(Ordering::Relaxed),
        2
    );
    assert_eq!(cls.metrics.rewrite_outcome_hits.load(Ordering::Relaxed), 1);
    assert_eq!(
        cls.metrics.rewrite_outcome_misses.load(Ordering::Relaxed),
        1
    );
    assert_eq!(cls.ua_classify.len(), 2, "one memo entry per distinct UA");
    // A non-matching UA lands in the other bitmap class — and its outcome
    // differs from the bot class (env set vs not).
    let human = run_one(&cls, &root, "/x", Some("Mozilla/5.0"), None);
    let bot = run_one(&cls, &root, "/x", Some("Googlebot/2.1"), None);
    assert_ne!(human, bot);
    assert_eq!(
        cls.metrics.rewrite_outcome_misses.load(Ordering::Relaxed),
        2
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn seeded_redirect_status_bypasses_outcome_cache() {
    // The assumed-empty guard: a chain reading %{ENV:REDIRECT_STATUS} is
    // cacheable while the seed lacks the name, but a request whose env seed
    // CARRIES it (here via SetEnvIf, the one runtime writer an operator could
    // add) must bypass the cache — the classification's purity argument no
    // longer holds for it.
    let root = make_docroot(
        "redirstatus",
        "RewriteEngine On\n\
         SetEnvIf X-Probe seed REDIRECT_STATUS=403\n\
         RewriteCond %{ENV:REDIRECT_STATUS} ^(403|5)\n\
         RewriteRule .* - [E=no-cache:1]\n",
    );
    let state = make_state(RewriteTuning {
        outcome_ttl: std::time::Duration::from_secs(600),
        ua_classify: false,
    });
    let m = &state.metrics;
    // No probe header: seed is clean, chain caches (miss then hit).
    run_one(&state, &root, "/a", None, None);
    run_one(&state, &root, "/a", None, None);
    assert_eq!(m.rewrite_outcome_misses.load(Ordering::Relaxed), 1);
    assert_eq!(m.rewrite_outcome_hits.load(Ordering::Relaxed), 1);
    assert_eq!(m.rewrite_outcome_uncacheable.load(Ordering::Relaxed), 0);
    // Probe header seeds REDIRECT_STATUS -> the request must bypass, and its
    // (differing) outcome must not poison the clean entry.
    let l = Line {
        method: "GET".into(),
        uri: "/a".into(),
        ua: String::new(),
        cookie: None,
        origin: None,
    };
    let mut req = build_request(&l).unwrap();
    req.headers_mut()
        .insert("x-probe", http::HeaderValue::from_static("seed"));
    let orig_path = normalized_request_path(&decode_request_path("/a").unwrap());
    let chain = state
        .rewrite_cache
        .load_chain_with_dirs(&root, &orig_path, ".htaccess");
    let flat: Vec<Arc<Htaccess>> = chain.iter().map(|(_, h)| h.clone()).collect();
    let vhost = Arc::new(VHostConfig {
        doc_root: root.to_path_buf(),
        ..VHostConfig::default()
    });
    let mut ctx = make_ctx(&state.server, &vhost);
    seed_server_env(&mut ctx);
    apply_set_env(&mut ctx, &flat, &req, &orig_path, "").unwrap();
    assert_eq!(ctx.get_env("REDIRECT_STATUS"), Some("403"));
    let seeded = run_rewrite(&state, &ctx, &req, &chain, &orig_path, "");
    assert_eq!(m.rewrite_outcome_uncacheable.load(Ordering::Relaxed), 1);
    match &seeded {
        super::rewrite_glue::RwResult::Unchanged { env } => {
            assert!(
                env.iter().any(|(k, _)| k == "no-cache"),
                "seeded request must see the 403-branch env set"
            );
        }
        other => panic!("expected Unchanged with env, got {other:?}"),
    }
    // The clean entry is still served untainted afterwards.
    let clean = run_one(&state, &root, "/a", None, None);
    match &clean {
        super::rewrite_glue::RwResult::Unchanged { env } => {
            assert!(
                env.iter().all(|(k, _)| k != "no-cache"),
                "clean request must not inherit the seeded outcome"
            );
        }
        other => panic!("expected Unchanged, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn differential_replay_production_corpus() {
    let Ok(live) = std::fs::read_to_string(LIVE_HTACCESS) else {
        println!("SKIP: {LIVE_HTACCESS} unreadable on this machine");
        return;
    };
    let raw = load_corpus();
    if raw.len() < MIN_LINES {
        println!(
            "SKIP: only {} parsable access-log lines found (need {MIN_LINES})",
            raw.len()
        );
        return;
    }
    let corpus = synthesize(raw);

    // ---- Variant A: the HISTORICAL cookie-poisoned .htaccess, rebuilt from ----
    // ---- the live (deployed-SetEnvIf) file by inverse replacement. One     ----
    // ---- %{HTTP_COOKIE} cond must poison the whole chain.                  ----
    for pin in [
        ADMIN_URI_COND_DEPLOYED,
        ADMIN_SETENVIF_CC,
        ADMIN_SETENVIF_VARY,
    ] {
        assert!(
            live.contains(pin),
            "live .htaccess admin block moved — update the ADMIN_* constants \
             (deployed from /var/log/wf-perf-audit/htaccess-setenvif.draft.txt)"
        );
    }
    let poisoned = live
        .replace(ADMIN_URI_COND_DEPLOYED, ADMIN_URI_COND_POISONED)
        .replace(ADMIN_SETENVIF_CC, "")
        .replace(ADMIN_SETENVIF_VARY, "");
    let root = make_docroot("asis", &poisoned);
    let s = replay(&root, &corpus, "poisoned");
    assert_eq!(
        s.hits_raw + s.misses_raw,
        0,
        "as-is chain must never enter the outcome cache"
    );
    assert_eq!(
        s.uncacheable_raw as usize, s.lines,
        "every as-is line must count uncacheable"
    );
    println!(
        "historical (cookie-poisoned) .htaccess: {} lines replayed, 0 mismatches, all uncacheable",
        s.lines
    );
    let _ = std::fs::remove_dir_all(&root);

    // ---- Variant B: the LIVE .htaccess (SetEnvIf construction deployed ----
    // ---- 2026-07-16). The chain is fully cacheable; measure hit ratios. ----
    let root = make_docroot("live", &live);
    let s = replay(&root, &corpus, "live");
    // The live chain is classified fully cacheable at PARSE time, but a request
    // whose headers trip a SetEnvIf seeding an env var the chain reads via
    // %{ENV:…} is DYNAMICALLY uncacheable per request (the outcome depends on the
    // seeded env, which is outside the cache key). Real traffic contains such
    // crawlers (e.g. UA-matched SetEnvIf + Feedspot), so assert the overwhelming
    // majority stays cacheable — outcome EQUALITY is asserted strictly per line
    // above and remains the correctness gate.
    assert!(
        (s.uncacheable_raw as usize) * 100 <= s.lines,
        "live (deployed) chain must remain overwhelmingly cacheable: \
         {} of {} lines dynamically uncacheable",
        s.uncacheable_raw,
        s.lines
    );
    let ratio = |h: u64, m: u64| {
        if h + m == 0 {
            0.0
        } else {
            h as f64 / (h + m) as f64
        }
    };
    println!(
        "live .htaccess: {} lines replayed, 0 mismatches\n\
         raw-UA keying:      hits={} misses={} hit-ratio={:.4}\n\
         ua-classify keying: hits={} misses={} hit-ratio={:.4} (classify-cache entries={})",
        s.lines,
        s.hits_raw,
        s.misses_raw,
        ratio(s.hits_raw, s.misses_raw),
        s.hits_classified,
        s.misses_classified,
        ratio(s.hits_classified, s.misses_classified),
        s.ua_classify_entries,
    );
    // ua-classify must never do WORSE than raw-UA keying on the same corpus.
    assert!(
        s.hits_classified >= s.hits_raw,
        "bitmap keying collapses UA diversity; it cannot hit less than raw-UA keying"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// (#822) Env assigned by an earlier ruleset (`[E=]`, `[E=!VAR]`) is what the
/// `%{ENV:}` reads of every later ruleset see: inline vhost → root → child.
fn env_carry_state(inline: Option<&str>) -> Arc<ServerState> {
    let mut state = make_state(RewriteTuning {
        outcome_ttl: std::time::Duration::from_secs(600),
        ua_classify: false,
    });
    if let Some(rules) = inline {
        Arc::get_mut(&mut state).unwrap().inline_rules.insert(
            VHOST.into(),
            Arc::new(hj_rewrite::RuleSet::parse(rules).unwrap()),
        );
    }
    state
}

fn rewritten_path(r: &super::rewrite_glue::RwResult) -> Option<&str> {
    match r {
        super::rewrite_glue::RwResult::Rewritten { path, .. } => Some(path),
        _ => None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inline_env_set_is_visible_to_htaccess_cond() {
    let root = make_docroot(
        "envcarry-inline",
        "RewriteEngine On\n\
         RewriteCond %{ENV:VFLAG} =1\n\
         RewriteRule ^p$ /hit.php [L]\n",
    );
    let state = env_carry_state(Some("RewriteEngine On\nRewriteRule ^/p$ - [E=VFLAG:1]\n"));
    let r = run_one(&state, &root, "/p", None, None);
    assert_eq!(rewritten_path(&r), Some("/hit.php"), "{r:?}");
    // A path the inline rule does not flag leaves the cond false.
    let other = run_one(&state, &root, "/q", None, None);
    assert_eq!(rewritten_path(&other), None, "{other:?}");
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn root_env_set_is_visible_to_child_htaccess_cond() {
    let root = make_docroot(
        "envcarry-child",
        "RewriteEngine On\nRewriteRule ^ - [E=RFLAG:1]\n",
    );
    std::fs::create_dir_all(root.join("sub")).unwrap();
    std::fs::write(
        root.join("sub/.htaccess"),
        "RewriteEngine On\nRewriteCond %{ENV:RFLAG} =1\nRewriteRule ^x$ /sub/hit [L]\n",
    )
    .unwrap();
    let state = env_carry_state(None);
    let r = run_one(&state, &root, "/sub/x", None, None);
    assert_eq!(rewritten_path(&r), Some("/sub/hit"), "{r:?}");
    match &r {
        super::rewrite_glue::RwResult::Rewritten { env, .. } => {
            assert!(env.iter().any(|(k, v)| k == "RFLAG" && v == "1"), "{env:?}");
        }
        _ => unreachable!(),
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn earlier_unset_hides_seed_from_later_ruleset() {
    // SetEnvIf seeds FOO=1 into ctx.env; the root ruleset unsets it, so the child's
    // cond must no longer see it.
    let root = make_docroot(
        "envcarry-unset",
        "SetEnvIf Request_URI ^/sub/ FOO=1\nRewriteEngine On\nRewriteRule ^ - [E=!FOO]\n",
    );
    std::fs::create_dir_all(root.join("sub")).unwrap();
    std::fs::write(
        root.join("sub/.htaccess"),
        "RewriteEngine On\nRewriteCond %{ENV:FOO} =1\nRewriteRule ^x$ /sub/hit [L]\n",
    )
    .unwrap();
    let state = env_carry_state(None);
    let r = run_one(&state, &root, "/sub/x", None, None);
    assert_eq!(rewritten_path(&r), None, "{r:?}");
    // An inline unset followed by a root re-set: the last layer wins.
    std::fs::write(
        root.join(".htaccess"),
        "SetEnvIf Request_URI ^/sub/ FOO=1\nRewriteEngine On\nRewriteRule ^ - [E=FOO:1]\n",
    )
    .unwrap();
    let state = env_carry_state(Some("RewriteEngine On\nRewriteRule ^ - [E=!FOO]\n"));
    let r = run_one(&state, &root, "/sub/x", None, None);
    assert_eq!(rewritten_path(&r), Some("/sub/hit"), "{r:?}");
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reserved_hj_env_is_not_carried_between_rulesets() {
    let root = make_docroot(
        "envcarry-hj",
        "RewriteEngine On\nRewriteCond %{ENV:HJ_X} =1\nRewriteRule ^p$ /hit.php [L]\n",
    );
    let state = env_carry_state(Some("RewriteEngine On\nRewriteRule ^/p$ - [E=HJ_X:1]\n"));
    let r = run_one(&state, &root, "/p", None, None);
    assert_eq!(rewritten_path(&r), None, "{r:?}");
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirect_status_writer_keeps_chain_out_of_outcome_cache() {
    // The REDIRECT_STATUS reader is classified constant-empty; an earlier ruleset
    // that writes the name would make that false, so the writer is uncacheable and
    // the reader observes the carried value.
    let root = make_docroot(
        "envcarry-redirstatus",
        "RewriteEngine On\n\
         RewriteCond %{ENV:REDIRECT_STATUS} ^403\n\
         RewriteRule ^p$ /err.php [L]\n",
    );
    let state = env_carry_state(Some(
        "RewriteEngine On\nRewriteRule ^/p$ - [E=REDIRECT_STATUS:403]\n",
    ));
    for _ in 0..2 {
        let r = run_one(&state, &root, "/p", None, None);
        assert_eq!(rewritten_path(&r), Some("/err.php"), "{r:?}");
    }
    let m = &state.metrics;
    assert_eq!(m.rewrite_outcome_hits.load(Ordering::Relaxed), 0);
    assert_eq!(m.rewrite_outcome_uncacheable.load(Ordering::Relaxed), 2);
    let _ = std::fs::remove_dir_all(&root);
}

/// (#826) `run_rewrite_traced` over `docroot` with `.htaccess` loading enabled
/// (so a rewrite into another directory can load that directory's chain).
fn run_hop(
    state: &Arc<ServerState>,
    docroot: &Path,
    path: &str,
) -> (super::rewrite_glue::RwResult, Vec<(PathBuf, Arc<Htaccess>)>) {
    let l = Line {
        method: "GET".into(),
        uri: path.into(),
        ua: String::new(),
        cookie: None,
        origin: None,
    };
    let req = build_request(&l).unwrap();
    let orig_path = normalized_request_path(&decode_request_path(path).unwrap());
    let chain = state
        .rewrite_cache
        .load_chain_with_dirs(docroot, &orig_path, ".htaccess");
    let vhost = Arc::new(VHostConfig {
        doc_root: docroot.to_path_buf(),
        allow_override: 1,
        ..VHostConfig::default()
    });
    let mut ctx = make_ctx(&state.server, &vhost);
    seed_server_env(&mut ctx);
    let mut trace = super::rewrite_glue::RewriteTrace::default();
    let r = super::rewrite_glue::run_rewrite_traced(
        state, &ctx, &req, &chain, &orig_path, "", &mut trace,
    );
    (r, trace.extra)
}

fn write_ht(root: &Path, dir: &str, rules: &str) {
    std::fs::create_dir_all(root.join(dir)).unwrap();
    std::fs::write(root.join(dir).join(".htaccess"), rules).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cross_dir_rewrite_runs_destination_front_controller() {
    let root = make_docroot(
        "dest-fc",
        "RewriteEngine On\nRewriteRule ^blog/(.*)$ /wp/$1 [L]\n",
    );
    write_ht(
        &root,
        "wp",
        "RewriteEngine On\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteRule . /wp/index.php [L]\n",
    );
    std::fs::write(root.join("wp/index.php"), "<?php\n").unwrap();
    let state = env_carry_state(None);
    let (direct, direct_extra) = run_hop(&state, &root, "/wp/post");
    assert_eq!(rewritten_path(&direct), Some("/wp/index.php"), "{direct:?}");
    assert!(direct_extra.is_empty());
    let (r, extra) = run_hop(&state, &root, "/blog/post");
    assert_eq!(rewritten_path(&r), Some("/wp/index.php"), "{r:?}");
    assert_eq!(
        extra.len(),
        1,
        "the wp chain ran outside the request's chain"
    );
    assert_eq!(extra[0].0, root.join("wp"));
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inline_rewrite_runs_the_rewritten_uris_htaccess() {
    let root = make_docroot(
        "dest-inline",
        "RewriteEngine On\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteRule ^ /index.php [L]\n",
    );
    let state = env_carry_state(Some(
        "RewriteEngine On\nRewriteRule ^/old/(.*)$ /new/$1 [L]\n",
    ));
    let (r, extra) = run_hop(&state, &root, "/old/x");
    assert_eq!(rewritten_path(&r), Some("/index.php"), "{r:?}");
    assert!(
        extra.is_empty(),
        "the destination chain is the request's chain"
    );
    // [END] in server context suppresses every per-directory pass.
    let state = env_carry_state(Some(
        "RewriteEngine On\nRewriteRule ^/old/(.*)$ /new/$1 [END]\n",
    ));
    let (r, _) = run_hop(&state, &root, "/old/x");
    assert_eq!(rewritten_path(&r), Some("/new/x"), "{r:?}");
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn end_flag_stops_before_the_destination_chain() {
    let root = make_docroot(
        "dest-end",
        "RewriteEngine On\nRewriteRule ^blog/(.*)$ /wp/$1 [END]\n",
    );
    write_ht(
        &root,
        "wp",
        "RewriteEngine On\nRewriteRule . /wp/index.php [L]\n",
    );
    let state = env_carry_state(None);
    let (r, extra) = run_hop(&state, &root, "/blog/post");
    assert_eq!(rewritten_path(&r), Some("/wp/post"), "{r:?}");
    assert!(extra.is_empty());
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rewrite_loop_across_directories_hits_the_recursion_limit() {
    let root = make_docroot("dest-loop", "RewriteEngine On\n");
    write_ht(
        &root,
        "a",
        "RewriteEngine On\nRewriteRule ^(.*)$ /b/$1 [L]\n",
    );
    write_ht(
        &root,
        "b",
        "RewriteEngine On\nRewriteRule ^(.*)$ /a/$1 [L]\n",
    );
    let state = env_carry_state(None);
    let (r, _) = run_hop(&state, &root, "/a/x");
    assert_eq!(
        r,
        super::rewrite_glue::RwResult::Failed {
            reason: super::rewrite_glue::INTERNAL_REDIRECT_LIMIT
        }
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirect_hops_up_to_the_limit_succeed() {
    // /d0/x -> /d1/x -> ... -> /d10/x is exactly ten internal redirects.
    let root = make_docroot("dest-chain10", "RewriteEngine On\n");
    for i in 0..10 {
        write_ht(
            &root,
            &format!("d{i}"),
            &format!("RewriteEngine On\nRewriteRule ^(.*)$ /d{}/$1 [L]\n", i + 1),
        );
    }
    write_ht(&root, "d10", "RewriteEngine On\n");
    let state = env_carry_state(None);
    let (r, _) = run_hop(&state, &root, "/d0/x");
    assert_eq!(rewritten_path(&r), Some("/d10/x"), "{r:?}");
    // One more hop is the eleventh internal redirect.
    write_ht(
        &root,
        "d10",
        "RewriteEngine On\nRewriteRule ^(.*)$ /d11/$1 [L]\n",
    );
    write_ht(&root, "d11", "RewriteEngine On\n");
    let state = env_carry_state(None);
    let (r, _) = run_hop(&state, &root, "/d0/x");
    assert_eq!(
        r,
        super::rewrite_glue::RwResult::Failed {
            reason: super::rewrite_glue::INTERNAL_REDIRECT_LIMIT
        }
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn internal_redirect_sees_redirect_status_and_carried_env() {
    let root = make_docroot(
        "dest-env",
        "RewriteEngine On\nRewriteRule ^blog/(.*)$ /wp/$1 [L,E=FROM_BLOG:1]\n",
    );
    write_ht(
        &root,
        "wp",
        "RewriteEngine On\n\
         RewriteCond %{ENV:REDIRECT_STATUS} =200\n\
         RewriteCond %{ENV:FROM_BLOG} =1\n\
         RewriteRule ^post$ /wp/redirected.php [L]\n",
    );
    let state = env_carry_state(None);
    let (r, _) = run_hop(&state, &root, "/blog/post");
    assert_eq!(rewritten_path(&r), Some("/wp/redirected.php"), "{r:?}");
    match &r {
        super::rewrite_glue::RwResult::Rewritten { env, .. } => {
            assert!(
                env.iter().any(|(k, v)| k == "FROM_BLOG" && v == "1"),
                "{env:?}"
            );
            assert!(
                !env.iter().any(|(k, _)| k == "REDIRECT_STATUS"),
                "REDIRECT_STATUS stays engine-only: {env:?}"
            );
        }
        _ => unreachable!(),
    }
    let (direct, _) = run_hop(&state, &root, "/wp/post");
    assert_eq!(rewritten_path(&direct), None, "{direct:?}");
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rewrite_into_a_parent_directory_reruns_the_parent_chain() {
    // The sub ruleset moves the request into the docroot's context; the root
    // rules then see the new URI (OLS context change / Apache internal redirect).
    let root = make_docroot(
        "dest-parent",
        "RewriteEngine On\n\
         RewriteCond %{ENV:REDIRECT_STATUS} =200\n\
         RewriteRule ^target\\.php$ /final.php [L]\n",
    );
    write_ht(
        &root,
        "sub",
        "RewriteEngine On\nRewriteRule ^x$ /target.php [L]\n",
    );
    let state = env_carry_state(None);
    for _ in 0..2 {
        let (r, extra) = run_hop(&state, &root, "/sub/x");
        assert_eq!(rewritten_path(&r), Some("/final.php"), "{r:?}");
        assert!(
            extra.is_empty(),
            "the parent chain is part of the request's chain"
        );
    }
    // Every ruleset that ran is in the request's chain, but the intermediate hop
    // (`/target.php`) must pass its own access phase in dispatch (#836): uncached.
    assert_eq!(
        state.metrics.rewrite_outcome_hits.load(Ordering::Relaxed),
        0
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// (#836) A hop straight to the final target, into a subset of the request's chain
/// (the subdirectory front controller), is covered by dispatch's final-target checks:
/// it stays cacheable and on-core. A realm in that subset is not (a deeper chain may
/// lift it), so the hop goes to dispatch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subset_hop_to_the_final_target_stays_cacheable_without_auth() {
    for auth in [false, true] {
        let root_rules = if auth {
            "AuthType Basic\nAuthName \"p\"\nAuthUserFile /nonexistent\nRequire valid-user\n"
        } else {
            ""
        };
        let root = make_docroot(
            if auth {
                "subset-hop-auth"
            } else {
                "subset-hop"
            },
            root_rules,
        );
        write_ht(
            &root,
            "sub",
            "RewriteEngine On\nRewriteRule ^x$ /index.php [L]\n",
        );
        let state = env_carry_state(None);
        let mut needs = Vec::new();
        for _ in 0..2 {
            let l = Line {
                method: "GET".into(),
                uri: "/sub/x".into(),
                ua: String::new(),
                cookie: None,
                origin: None,
            };
            let req = build_request(&l).unwrap();
            let chain = state
                .rewrite_cache
                .load_chain_with_dirs(&root, "/sub/x", ".htaccess");
            let vhost = Arc::new(VHostConfig {
                doc_root: root.clone(),
                allow_override: 1,
                ..VHostConfig::default()
            });
            let mut ctx = make_ctx(&state.server, &vhost);
            seed_server_env(&mut ctx);
            let mut trace = super::rewrite_glue::RewriteTrace::default();
            let r = super::rewrite_glue::run_rewrite_traced(
                &state, &ctx, &req, &chain, "/sub/x", "", &mut trace,
            );
            assert_eq!(rewritten_path(&r), Some("/index.php"), "{r:?}");
            needs.push(trace.needs_dispatch(&chain, &r));
        }
        let hits = state.metrics.rewrite_outcome_hits.load(Ordering::Relaxed);
        if auth {
            assert_eq!(needs, [true, true]);
            assert_eq!(hits, 0);
        } else {
            assert_eq!(needs, [false, false]);
            assert_eq!(hits, 1);
        }
        let _ = std::fs::remove_dir_all(&root);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn same_chain_rewrite_does_not_rerun_the_chain() {
    // The front-controller shape: a rewrite that stays inside the evaluated
    // chain is final (OLS keeps the context), so a REDIRECT_STATUS-gated rule
    // in the same ruleset never fires.
    let root = make_docroot(
        "dest-same",
        "RewriteEngine On\n\
         RewriteCond %{ENV:REDIRECT_STATUS} =200\n\
         RewriteRule ^index\\.php$ /looped.php [L]\n\
         RewriteCond %{REQUEST_FILENAME} !-f\n\
         RewriteRule ^ /index.php [L]\n",
    );
    let state = env_carry_state(None);
    let (r, extra) = run_hop(&state, &root, "/whats-new/");
    assert_eq!(rewritten_path(&r), Some("/index.php"), "{r:?}");
    assert!(extra.is_empty());
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn outcome_depending_on_a_foreign_chain_is_not_cached() {
    let root = make_docroot(
        "dest-nocache",
        "RewriteEngine On\nRewriteRule ^blog/(.*)$ /wp/$1 [L]\n",
    );
    write_ht(
        &root,
        "wp",
        "RewriteEngine On\nRewriteRule ^post$ /wp/index.php [L]\n",
    );
    let state = env_carry_state(None);
    for _ in 0..2 {
        let (r, extra) = run_hop(&state, &root, "/blog/post");
        assert_eq!(rewritten_path(&r), Some("/wp/index.php"), "{r:?}");
        assert_eq!(extra.len(), 1);
    }
    let m = &state.metrics;
    assert_eq!(m.rewrite_outcome_hits.load(Ordering::Relaxed), 0);
    assert_eq!(m.rewrite_outcome_misses.load(Ordering::Relaxed), 2);
    let _ = std::fs::remove_dir_all(&root);
}

/// Regression (#900): a vhost rewrite sets REDIRECT_STATUS for the per-directory
/// chain (OLS processRule), so a Symfony guard does not redirect its own target.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inline_rewrite_sets_redirect_status_for_the_htaccess_chain() {
    let root = make_docroot(
        "inline-redirect-status",
        "RewriteEngine On\n\
         RewriteCond %{ENV:REDIRECT_STATUS} =\"\"\n\
         RewriteRule ^index\\.php(?:/(.*)|$) /$1 [R=301,L]\n",
    );
    let state = env_carry_state(Some(
        "RewriteEngine On\nRewriteRule ^/api/(.*)$ /index.php/$1\n",
    ));
    let (r, _) = run_hop(&state, &root, "/api/foo");
    assert!(
        !matches!(r, super::rewrite_glue::RwResult::Redirect { .. }),
        "{r:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}
