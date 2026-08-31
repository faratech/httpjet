//! CGI/1.1 environment construction for an LSAPI (PHP) request.
//!
//! Produces the `(name, value)` env-var list that goes into the BEGIN_REQUEST
//! env table. PHP's litespeed SAPI exposes these as `$_SERVER`.

use std::borrow::Cow;
use std::path::Path;

use hj_core::{ReqCtx, Request};

/// Build the CGI environment for `req` targeting the resolved `script_filename`.
///
/// Includes the canonical CGI/1.1 vars (REQUEST_METHOD, SCRIPT_FILENAME,
/// SCRIPT_NAME, QUERY_STRING, REQUEST_URI, DOCUMENT_ROOT, REMOTE_ADDR/PORT,
/// SERVER_NAME/PORT/PROTOCOL/SOFTWARE, GATEWAY_INTERFACE, HTTPS when TLS,
/// CONTENT_TYPE, CONTENT_LENGTH, PATH_INFO) plus every request header as `HTTP_*`.
///
/// `script_name`/`path_info` default sensibly from the request URI; callers that
/// have already split PATH_INFO can override via [`CgiEnvBuilder`].
///
/// `remote_addr` is taken from `ctx.client_ip` (the proxy-resolved client IP).
pub fn build_cgi_env<'r>(
    req: &'r Request,
    ctx: &'r ReqCtx,
    script_filename: &'r Path,
) -> Vec<(Cow<'r, str>, Cow<'r, str>)> {
    CgiEnvBuilder::new(script_filename).build(req, ctx)
}

/// Builder offering control over SCRIPT_NAME / PATH_INFO splitting and extra
/// `PHP_VALUE` / `PHP_ADMIN_VALUE` passthrough (e.g. `auto_prepend_file`), the
/// per-context/ext-processor env, and the document root.
pub struct CgiEnvBuilder<'a> {
    script_filename: &'a Path,
    script_name: Option<String>,
    path_info: Option<String>,
    document_root: Option<String>,
    /// Extra env appended verbatim (ext-processor `env`, PHP_VALUE/PHP_ADMIN_VALUE, ...).
    extra: Vec<(String, String)>,
    /// Borrowed equivalent of `extra` for the hot path: the handler's `base_env`
    /// lives on the `Arc<Lsapi>` for the life of the process, so it can be borrowed
    /// per request instead of cloned. Applied before `extra` (both upsert; `extra`
    /// still wins last). Empty by default.
    extra_ref: &'a [(String, String)],
    server_software: String,
}

impl<'a> CgiEnvBuilder<'a> {
    pub fn new(script_filename: &'a Path) -> Self {
        CgiEnvBuilder {
            script_filename,
            script_name: None,
            path_info: None,
            document_root: None,
            extra: Vec::new(),
            extra_ref: &[],
            server_software: "LiteSpeed".to_string(),
        }
    }

    /// Override SCRIPT_NAME (the URL path of the script, before PATH_INFO).
    pub fn script_name(mut self, s: impl Into<String>) -> Self {
        self.script_name = Some(s.into());
        self
    }

    /// Set PATH_INFO (the trailing path after the script).
    pub fn path_info(mut self, s: impl Into<String>) -> Self {
        self.path_info = Some(s.into());
        self
    }

    /// Override DOCUMENT_ROOT (defaults to the vhost doc root in `ctx`).
    pub fn document_root(mut self, s: impl Into<String>) -> Self {
        self.document_root = Some(s.into());
        self
    }

    /// Set SERVER_SOFTWARE.
    pub fn server_software(mut self, s: impl Into<String>) -> Self {
        self.server_software = s.into();
        self
    }

    /// Append extra env vars (ext-processor `env`, `PHP_VALUE`, `PHP_ADMIN_VALUE`,
    /// `auto_prepend_file`, ...). Appended after the standard vars so they win on
    /// duplicate keys when PHP reads them (PHP keeps the last occurrence).
    pub fn extra(mut self, kv: impl IntoIterator<Item = (String, String)>) -> Self {
        self.extra.extend(kv);
        self
    }

    /// Like [`extra`](Self::extra) but BORROWS a long-lived slice (the handler's
    /// `base_env`) instead of taking ownership — no per-request clone. Applied
    /// before any owned [`extra`](Self::extra) (which still wins last on dup keys).
    pub fn extra_ref(mut self, kv: &'a [(String, String)]) -> Self {
        self.extra_ref = kv;
        self
    }

    pub fn build<'r>(self, req: &'r Request, ctx: &'r ReqCtx) -> Vec<(Cow<'r, str>, Cow<'r, str>)>
    where
        'a: 'r,
    {
        let mut env: Vec<(Cow<'r, str>, Cow<'r, str>)> =
            Vec::with_capacity(24 + req.headers().len());

        // Static constants: push once at the start (zero-alloc).
        env.push((Cow::Borrowed("GATEWAY_INTERFACE"), Cow::Borrowed("CGI/1.1")));

        macro_rules! push {
            ($k:expr, $v:expr) => {
                env.push((Cow::Borrowed($k), Cow::Owned($v)))
            };
        }
        // Fixed/constructed vars BORROW their sources wherever the source outlives the
        // encode (`req`/`ctx` are 'r; builder fields are 'a: 'r) — the former clones
        // here were ~10 owned Strings per PHP request (#282). Only true concats
        // (path?query / PATH_TRANSLATED) remain owned.
        macro_rules! push_borrow {
            ($k:expr, $v:expr) => {
                env.push((Cow::Borrowed($k), Cow::Borrowed($v)))
            };
        }
        let uri = req.uri();
        let path = uri.path();
        let query = uri.query().unwrap_or("");
        push_borrow!("REQUEST_METHOD", req.method().as_str());
        // Builder-owned fields are cloned (build consumes `self`, so they cannot
        // borrow out of it); everything sourced from `req`/`ctx` borrows.
        push!(
            "SCRIPT_FILENAME",
            self.script_filename
                .to_str()
                .map(|s| s.to_string())
                .unwrap_or_else(|| self.script_filename.to_string_lossy().into_owned())
        );
        push!(
            "SCRIPT_NAME",
            self.script_name.clone().unwrap_or_else(|| path.to_string())
        );
        push_borrow!("QUERY_STRING", query);
        if let Some(q) = uri.query() {
            env.push((
                Cow::Borrowed("REQUEST_URI"),
                Cow::Owned(format!("{path}?{q}")),
            ));
        } else {
            push_borrow!("REQUEST_URI", path);
        }
        let has_path_info = self.path_info.as_deref().is_some_and(|pi| !pi.is_empty());
        if has_path_info {
            push!("PATH_INFO", self.path_info.clone().unwrap_or_default());
        }

        let doc_root = self
            .document_root
            .clone()
            .unwrap_or_else(|| ctx.vhost.doc_root.to_string_lossy().into_owned());
        push!("DOCUMENT_ROOT", doc_root.clone());

        // PATH_TRANSLATED = doc root + PATH_INFO (only when PATH_INFO is set).
        if has_path_info {
            env.push((
                Cow::Borrowed("PATH_TRANSLATED"),
                Cow::Owned(format!(
                    "{doc_root}{}",
                    self.path_info.as_deref().unwrap_or_default()
                )),
            ));
        }

        // Client / remote. REMOTE_ADDR is the proxy-resolved client IP;
        // REMOTE_PORT is the directly-connected peer's TCP port.
        push!("REMOTE_ADDR", ctx.client_ip.to_string());
        push!("REMOTE_PORT", ctx.peer_port.to_string());

        // Server identity — SERVER_NAME/SOFTWARE now borrow (#282).
        let server_name = match host_header(req) {
            Some(h) => strip_port(h),
            None => ctx.vhost_name.as_str(),
        };
        env.push((Cow::Borrowed("SERVER_NAME"), Cow::Borrowed(server_name)));
        push!("SERVER_SOFTWARE", self.server_software.clone());
        push!("SERVER_ADDR", ctx.local_addr.ip().to_string());

        // Port: from the Host header if present, else the listener's bound port.
        let server_port = host_header(req)
            .and_then(|h| port_of(&h))
            .unwrap_or_else(|| ctx.local_addr.port());
        push!("SERVER_PORT", server_port.to_string());

        // Request arrival time. REQUEST_TIME is whole seconds; the _FLOAT variant
        // carries microsecond precision (e.g. "1700000000.123456").
        if let Ok(since) = ctx.request_time.duration_since(std::time::UNIX_EPOCH) {
            push!("REQUEST_TIME", since.as_secs().to_string());
            push!("REQUEST_TIME_FLOAT", format!("{:.6}", since.as_secs_f64()));
        }

        // (security #269) AUTH_TYPE / REMOTE_USER are SERVER-ASSERTED identity vars.
        // httpjet has no HTTP authentication module, so echoing the raw client
        // `Authorization` header into them let ANY unauthenticated request forge
        // `$_SERVER['REMOTE_USER']` for apps that trust it. They are now emitted only
        // from an authenticated source: a VERIFIED TLS client certificate (see the
        // SSL_CLIENT_* block below — apps check `SSL_CLIENT_VERIFY === 'SUCCESS'`).

        // TLS / SSL_* vars (present on TLS/QUIC connections).
        if let Some(tls) = &ctx.tls {
            env.push((Cow::Borrowed("SSL_PROTOCOL"), Cow::Borrowed(tls.protocol)));
            env.push((
                Cow::Borrowed("SSL_CIPHER"),
                Cow::Borrowed(tls.cipher.as_str()),
            ));
            if let Some(cc) = &tls.client_cert {
                env.push((
                    Cow::Borrowed("SSL_CLIENT_VERIFY"),
                    Cow::Borrowed(if cc.verified { "SUCCESS" } else { "NONE" }),
                ));
                env.push((
                    Cow::Borrowed("SSL_CLIENT_S_DN"),
                    Cow::Borrowed(cc.subject_dn.as_str()),
                ));
                env.push((
                    Cow::Borrowed("SSL_CLIENT_I_DN"),
                    Cow::Borrowed(cc.issuer_dn.as_str()),
                ));
                env.push((
                    Cow::Borrowed("SSL_CLIENT_M_SERIAL"),
                    Cow::Borrowed(cc.serial_hex.as_str()),
                ));
                env.push((
                    Cow::Borrowed("SSL_CLIENT_V_START"),
                    Cow::Borrowed(cc.not_before.as_str()),
                ));
                env.push((
                    Cow::Borrowed("SSL_CLIENT_V_END"),
                    Cow::Borrowed(cc.not_after.as_str()),
                ));
            }
        }

        // CONTENT_TYPE / CONTENT_LENGTH from headers (mirrored, not HTTP_-prefixed).
        if let Some(ct) = req
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
        {
            env.push((Cow::Borrowed("CONTENT_TYPE"), Cow::Borrowed(ct)));
        }
        if let Some(cl) = req
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
        {
            env.push((Cow::Borrowed("CONTENT_LENGTH"), Cow::Borrowed(cl)));
        }

        // All request headers as HTTP_*. Content-Type/Length are intentionally
        // duplicated here too (PHP & CGI both expect that). Iterate distinct header
        // NAMES (`keys()`) and pull each name's values with `get_all` — the `http`
        // HeaderMap already groups repeated headers, so this de-dups for free with
        // NO per-request HashMap allocation (the former O(1) map only existed to
        // avoid an O(n^2) linear scan over the env vec). `http_var_name` still runs
        // once per distinct name; the common single-value header stays borrowed.
        let mut have_host = false;
        for name in req.headers().keys() {
            let nm = name.as_str();
            // httpoxy (CVE-2016-5385): a client `Proxy` header would otherwise
            // become HTTP_PROXY in $_SERVER, which CGI-mode PHP libraries consult
            // for outbound calls — letting an attacker redirect them. It is never
            // a legitimate request header on the LSAPI path, so drop it.
            if nm.eq_ignore_ascii_case("proxy") {
                continue;
            }
            // An underscore in a header name collides with the `-`->`_` HTTP_* mapping
            // (`http_var_name` leaves `_` unchanged), so `X_Forwarded_For` and the real
            // `X-Forwarded-For` both become `HTTP_X_FORWARDED_FOR` — two entries with the
            // same key, and PHP's $_SERVER takes the last, letting a client spoof an
            // HTTP_* value an app may trust. Drop underscore-named headers, matching
            // nginx's default `underscores_in_headers off`. (Standard request headers
            // never contain `_`, so this only sheds the ambiguous/forged ones.)
            if nm.contains('_') {
                continue;
            }
            // Accept both UTF-8 and raw bytes (obs-text per RFC 7230). Borrow the
            // common UTF-8 case (zero-alloc); only a non-UTF-8 value (lossy) or a
            // repeated header allocates — restoring the pre-43a5aa7 borrow-first path
            // that the "lossy-only" rewrite regressed to a Vec<String>+clone per header
            // on every PHP request (#130).
            let mut values = req.headers().get_all(name).iter();
            let Some(first_hv) = values.next() else {
                continue;
            };
            let first: Cow<'r, str> = match first_hv.to_str() {
                Ok(v) => Cow::Borrowed(v),
                Err(_) => Cow::Owned(String::from_utf8_lossy(first_hv.as_bytes()).into_owned()),
            };
            let is_host = nm.eq_ignore_ascii_case("host");
            // Drop the scheme-default port from HTTP_HOST so it matches SERVER_NAME
            // and XenForo's port-less boardUrl (else a `:443` host triggers an XF
            // canonical 301 the page cache mistakes for a self-redirect).
            let first: Cow<'r, str> = if is_host {
                match first {
                    Cow::Borrowed(s) => Cow::Borrowed(host_without_default_port(s, ctx.is_tls)),
                    Cow::Owned(s) => host_without_default_port(&s, ctx.is_tls).to_owned().into(),
                }
            } else {
                first
            };
            // Common case: a single value -> use as-is (borrowed). Repeated header
            // -> join with ", " like CGI does (allocates only then).
            let value: Cow<'r, str> = match values.next() {
                None => first,
                Some(second_hv) => {
                    let mut joined = String::with_capacity(first.len() + 8);
                    joined.push_str(&first);
                    for hv in std::iter::once(second_hv).chain(values) {
                        joined.push_str(", ");
                        match hv.to_str() {
                            Ok(v) => joined.push_str(v),
                            Err(_) => joined.push_str(&String::from_utf8_lossy(hv.as_bytes())),
                        }
                    }
                    Cow::Owned(joined)
                }
            };
            have_host |= is_host;
            env.push((Cow::Owned(http_var_name(nm)), value));
        }

        // HTTP/2 and HTTP/3 clients send the `:authority` pseudo-header instead of a
        // `Host` header, so the loop above produced no HTTP_HOST. Synthesize it (full
        // host[:port]) from the URI authority, then the resolved vhost, so
        // $_SERVER['HTTP_HOST'] is always present (LiteSpeed maps :authority -> Host).
        // Only when absent, so the HTTP/1.x case (real Host header) is untouched.
        if !have_host {
            let host = req
                .uri()
                .authority()
                .map(|a| host_without_default_port(a.as_str(), ctx.is_tls).to_string())
                .unwrap_or_else(|| ctx.vhost_name.clone());
            env.push((Cow::Borrowed("HTTP_HOST"), Cow::Owned(host)));
        }

        // Speculation Rules fetches (prefetch/prerender) carry only
        // `Sec-Purpose: prefetch[;prerender]`. The PHP side gates its side
        // effects (XenForo's Request::isPrefetch() — read-marking, view
        // counting, session activity; vc.php; rt.php) on the LEGACY
        // X-Moz/X-Purpose/Purpose headers, and XF\Http\Request is constructed
        // without extendClass so an addon cannot teach it new headers.
        // Normalize here instead: surface a synthetic HTTP_X_PURPOSE=prefetch
        // so a prerendered page has no side effects until the user actually
        // activates it (the activation navigation carries no Sec-Purpose).
        if !req.headers().contains_key("x-purpose")
            && !req.headers().contains_key("purpose")
            && !req.headers().contains_key("x-moz")
        {
            if let Some(sp) = req
                .headers()
                .get("sec-purpose")
                .and_then(|v| v.to_str().ok())
            {
                // `prefetch;prerender` for prerenders; plain `prefetch` otherwise.
                if sp.to_ascii_lowercase().contains("prefetch") {
                    env.push((Cow::Borrowed("HTTP_X_PURPOSE"), Cow::Borrowed("prefetch")));
                }
            }
        }

        // Env set by rewrite [E=...] flags (exposed as $_SERVER in PHP too).
        // Borrowed from `ctx.env` (lives as long as `ctx`).
        for (k, v) in &ctx.env {
            upsert(
                &mut env,
                Cow::Borrowed(k.as_str()),
                Cow::Borrowed(v.as_str()),
            );
        }

        // Tell PHP the client accepts only identity: both PHP-side compressors key
        // off HTTP_ACCEPT_ENCODING (zlib.output_compression and XenForo's own
        // gzencode(..., 9) gate in contentIsCompressible), so forwarding the real
        // value makes the scarce lsphp worker gzip every render — which httpjet
        // then has to gzip-DEcode for cacheable stores and re-encode for egress
        // anyway. Egress compression is negotiated by hj-compress from the REAL
        // Accept-Encoding (snapshotted into ctx.env by the pipeline before
        // dispatch and read back from there, never from this CGI env). Must run
        // AFTER the ctx.env upsert above (which re-adds the real value); placed
        // before `extra` so an explicit caller override still wins.
        upsert(
            &mut env,
            Cow::Borrowed("HTTP_ACCEPT_ENCODING"),
            Cow::Borrowed("identity"),
        );

        // Caller passthrough (borrowed base_env first, then any owned extra which
        // wins last on duplicate keys). base_env is borrowed from the long-lived
        // handler — no per-request clone.
        for (k, v) in self.extra_ref {
            upsert(
                &mut env,
                Cow::Borrowed(k.as_str()),
                Cow::Borrowed(v.as_str()),
            );
        }
        for (k, v) in self.extra {
            upsert(&mut env, Cow::Owned(k), Cow::Owned(v));
        }

        // Static TLS/redirect-status/protocol DEFAULTS (zero-alloc). Inserted only if
        // NOT already present, so an earlier ctx.env `[E=...]` / SetEnvIf / `extra()`
        // entry of the same name WINS — restoring the pre-43a5aa7 "override beats
        // static" contract without shipping a duplicate key to lsphp (PHP's $_SERVER
        // takes the LAST occurrence, so a bare push here clobbered e.g. a PHP
        // ErrorDocument subrequest's REDIRECT_STATUS=<code> back to 200) (#129). Placed
        // after the upsert loops so the push closure's mutable borrow of `env` is done.
        set_default(
            &mut env,
            Cow::Borrowed("SERVER_PROTOCOL"),
            Cow::Borrowed(ctx.protocol.as_str()),
        );
        if ctx.is_tls {
            set_default(&mut env, Cow::Borrowed("HTTPS"), Cow::Borrowed("on"));
            set_default(
                &mut env,
                Cow::Borrowed("REQUEST_SCHEME"),
                Cow::Borrowed("https"),
            );
        } else {
            set_default(
                &mut env,
                Cow::Borrowed("REQUEST_SCHEME"),
                Cow::Borrowed("http"),
            );
        }
        set_default(
            &mut env,
            Cow::Borrowed("REDIRECT_STATUS"),
            Cow::Borrowed("200"),
        );

        env
    }
}

fn upsert<'r>(env: &mut Vec<(Cow<'r, str>, Cow<'r, str>)>, key: Cow<'r, str>, val: Cow<'r, str>) {
    if let Some(slot) = env.iter_mut().find(|(k, _)| k.as_ref() == key.as_ref()) {
        slot.1 = val;
    } else {
        env.push((key, val));
    }
}

/// Insert `key=val` ONLY if `key` is not already present (a default). Used for the
/// static TLS/protocol/redirect-status vars so an earlier ctx.env/extra override of
/// the same name wins and no duplicate key is shipped to lsphp (#129).
fn set_default<'r>(
    env: &mut Vec<(Cow<'r, str>, Cow<'r, str>)>,
    key: Cow<'r, str>,
    val: Cow<'r, str>,
) {
    if !env.iter().any(|(k, _)| k.as_ref() == key.as_ref()) {
        env.push((key, val));
    }
}

/// `Content-Type` -> `HTTP_CONTENT_TYPE`, `X-Forwarded-For` -> `HTTP_X_FORWARDED_FOR`.
fn http_var_name(header: &str) -> String {
    let mut s = String::with_capacity(header.len() + 5);
    s.push_str("HTTP_");
    for c in header.chars() {
        if c == '-' {
            s.push('_');
        } else {
            s.push(c.to_ascii_uppercase());
        }
    }
    s
}

fn host_header<'r>(req: &'r Request) -> Option<&'r str> {
    // Borrowed end-to-end (#282): the Host header value or the URI authority — no
    // per-request String for either arm.
    req.headers()
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .or_else(|| req.uri().host())
}

fn strip_port(host: &str) -> &str {
    // IPv6 literal like [::1]:8080
    if let Some(rest) = host.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            // `end` is the `]` index within `rest` (after the leading `[`), so the
            // `]` sits at byte `end + 1` of `host`; `..end + 2` keeps it. (#9: was
            // `end + 2 - 1`, which dropped the closing bracket → `[::1` for `[::1]`.)
            return &host[..end + 2];
        }
    }
    match host.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => h,
        _ => host,
    }
}

fn port_of(host: &str) -> Option<u16> {
    if let Some(rest) = host.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return host[end + 2..]
                .strip_prefix(':')
                .and_then(|p| p.parse().ok());
        }
    }
    match host.rsplit_once(':') {
        Some((_, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => p.parse().ok(),
        _ => None,
    }
}

/// Strip the port from a host ONLY when it is the default for the request scheme
/// (443 for TLS/https, 80 for cleartext); non-default ports (e.g. `:8443`) are kept.
///
/// This aligns `HTTP_HOST` with the already-port-less `SERVER_NAME` and with XenForo's
/// port-less `boardUrl`. Passing `forum.example:443` (h2 `:authority` carries the
/// port) made XF's canonical-host check (`getHost()` vs `boardUrl`) 301 to the port-less
/// host; the page cache then saw a self-redirect and refused to cache, starving hot pages
/// — most visibly on stale-while-revalidate full-render refreshes, which never converged.
/// See the homepage-self-redirect-cache-loop incident.
fn host_without_default_port(host: &str, is_tls: bool) -> &str {
    let default = if is_tls { 443 } else { 80 };
    match port_of(host) {
        Some(p) if p == default => strip_port(host),
        _ => host,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::net::IpAddr;
    use std::path::PathBuf;
    use std::sync::Arc;

    #[test]
    fn strip_port_keeps_ipv6_bracket() {
        // (#9) Regression: the closing `]` must be retained for SERVER_NAME.
        assert_eq!(strip_port("[::1]:8080"), "[::1]");
        assert_eq!(strip_port("[2001:db8::1]:443"), "[2001:db8::1]");
        assert_eq!(strip_port("[::1]"), "[::1]");
        // Plain host / host:port still work.
        assert_eq!(strip_port("example.com:80"), "example.com");
        assert_eq!(strip_port("example.com"), "example.com");
    }

    use hj_core::Proto;
    use hj_core::config::{ServerConfig, Tuning, VHostConfig};
    use http_body_util::{BodyExt, Empty, combinators::BoxBody};

    fn empty_incoming() -> hj_core::IncomingBody {
        BoxBody::new(Empty::<bytes::Bytes>::new().map_err(|e| {
            let e: hj_core::BoxError = Box::new(e);
            e
        }))
    }

    fn server() -> Arc<ServerConfig> {
        Arc::new(ServerConfig {
            server_root: PathBuf::from("/usr/local/lsws"),
            server_name: "test".into(),
            user: "nobody".into(),
            group: "nobody".into(),
            index_files: vec!["index.php".into()],
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
            mime: Default::default(),
        })
    }

    fn ctx(is_tls: bool) -> ReqCtx {
        let vh = VHostConfig {
            doc_root: PathBuf::from("/web/public_html"),
            ..Default::default()
        };
        ReqCtx {
            server: server(),
            vhost_name: "forum.example".into(),
            vhost: Arc::new(vh),
            peer_ip: "10.0.0.9".parse::<IpAddr>().unwrap(),
            client_ip: "203.0.113.7".parse::<IpAddr>().unwrap(),
            is_tls,
            protocol: Proto::Http2,
            trusted_proxy: true,
            env: vec![],
            local_addr: "192.0.2.1:8080".parse().unwrap(),
            peer_port: 54321,
            peer_unix: false,
            // Fixed instant so REQUEST_TIME assertions are deterministic.
            request_time: std::time::UNIX_EPOCH
                + std::time::Duration::new(1_700_000_000, 123_456_000),
            request_id: Default::default(),
            tls: None,
            redirect_guard: None,
        }
    }

    #[test]
    fn builds_core_cgi_vars() {
        let req = http::Request::builder()
            .method("POST")
            .uri("/blog/post.php?id=42")
            .header("Host", "forum.example:443")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Content-Length", "9")
            .header("User-Agent", "curl/8")
            .header("X-Forwarded-For", "203.0.113.7")
            // "aladdin:opensesame" base64-encoded.
            .header("Authorization", "Basic YWxhZGRpbjpvcGVuc2VzYW1l")
            .body(empty_incoming())
            .unwrap();

        let c = ctx(true);
        let env = build_cgi_env(&req, &c, Path::new("/web/public_html/blog/post.php"));
        let m: std::collections::HashMap<String, String> = env
            .into_iter()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();

        assert_eq!(m["REQUEST_METHOD"], "POST");
        assert_eq!(m["SCRIPT_FILENAME"], "/web/public_html/blog/post.php");
        assert_eq!(m["SCRIPT_NAME"], "/blog/post.php");
        assert_eq!(m["QUERY_STRING"], "id=42");
        assert_eq!(m["REQUEST_URI"], "/blog/post.php?id=42");
        assert_eq!(m["DOCUMENT_ROOT"], "/web/public_html");
        assert_eq!(m["REMOTE_ADDR"], "203.0.113.7");
        assert_eq!(m["REMOTE_PORT"], "54321");
        assert_eq!(m["SERVER_NAME"], "forum.example");
        assert_eq!(m["SERVER_ADDR"], "192.0.2.1");
        assert_eq!(m["SERVER_PROTOCOL"], "HTTP/2");
        assert_eq!(m["SERVER_SOFTWARE"], "LiteSpeed");
        assert_eq!(m["GATEWAY_INTERFACE"], "CGI/1.1");
        assert_eq!(m["HTTPS"], "on");
        assert_eq!(m["SERVER_PORT"], "443");
        assert_eq!(m["REDIRECT_STATUS"], "200");
        assert_eq!(m["REQUEST_TIME"], "1700000000");
        assert_eq!(m["REQUEST_TIME_FLOAT"], "1700000000.123456");
        // (security #269) AUTH_TYPE/REMOTE_USER are no longer derived from the raw
        // client Authorization header — they are server-asserted identity vars, and
        // httpjet has no HTTP authn module. The header stays available as HTTP_AUTHORIZATION.
        assert!(!m.contains_key("AUTH_TYPE"));
        assert!(!m.contains_key("REMOTE_USER"));
        assert_eq!(m["HTTP_AUTHORIZATION"], "Basic YWxhZGRpbjpvcGVuc2VzYW1l");
        assert_eq!(m["CONTENT_TYPE"], "application/x-www-form-urlencoded");
        assert_eq!(m["CONTENT_LENGTH"], "9");
        // HTTP_HOST drops the scheme-default :443 (matches SERVER_NAME + XF boardUrl);
        // SERVER_PORT still reports 443 (XF isSecure() relies on it — see line above).
        assert_eq!(m["HTTP_HOST"], "forum.example");
        assert_eq!(m["HTTP_USER_AGENT"], "curl/8");
        assert_eq!(m["HTTP_X_FORWARDED_FOR"], "203.0.113.7");
        // header mirror also present as HTTP_*
        assert_eq!(m["HTTP_CONTENT_TYPE"], "application/x-www-form-urlencoded");
    }

    #[test]
    fn ctx_env_redirect_status_wins_over_static_default_and_stays_unique() {
        // #129: run_php_error_document sets ctx.env REDIRECT_STATUS=<code> so the PHP
        // error page can detect it is an error subrequest. The static default must NOT
        // clobber it, and exactly ONE REDIRECT_STATUS may reach lsphp (PHP's $_SERVER
        // takes the last occurrence, so a duplicate with a trailing "200" would win).
        let req = http::Request::builder()
            .method("GET")
            .uri("/does-not-exist")
            .header("Host", "forum.example")
            .body(empty_incoming())
            .unwrap();
        let mut c = ctx(true);
        // Mirror the pipeline: seed_server_env pushes HTTPS=on on a TLS request, and the
        // ErrorDocument path pushes the original status.
        c.env = vec![
            ("HTTPS".to_string(), "on".to_string()),
            ("REDIRECT_STATUS".to_string(), "404".to_string()),
        ];
        let env = build_cgi_env(&req, &c, Path::new("/web/public_html/404.php"));

        let redirect_status: Vec<&str> = env
            .iter()
            .filter(|(k, _)| k.as_ref() == "REDIRECT_STATUS")
            .map(|(_, v)| v.as_ref())
            .collect();
        assert_eq!(
            redirect_status,
            vec!["404"],
            "ctx.env REDIRECT_STATUS must win and be the only entry"
        );
        // No duplicate HTTPS (seed_server_env already provided it on the TLS path).
        assert_eq!(
            env.iter().filter(|(k, _)| k.as_ref() == "HTTPS").count(),
            1,
            "HTTPS must not be duplicated"
        );
        // SERVER_PROTOCOL default still applies when ctx.env does not set it.
        assert_eq!(
            env.iter()
                .filter(|(k, _)| k.as_ref() == "SERVER_PROTOCOL")
                .count(),
            1
        );
    }

    #[test]
    fn underscore_header_cannot_spoof_http_var_via_collision() {
        // A client sends BOTH the real dashed header and an underscore variant. The
        // dashed `X-Forwarded-For` must survive; the underscore `X_Forwarded_For` must
        // be dropped so it cannot collide onto HTTP_X_FORWARDED_FOR and override it.
        let req = http::Request::builder()
            .uri("/index.php")
            .header("Host", "forum.example")
            .header("X-Forwarded-For", "203.0.113.7")
            .header("X_Forwarded_For", "127.0.0.1")
            .header("X_Custom_Auth", "spoofed")
            .body(empty_incoming())
            .unwrap();

        let c = ctx(true);
        let env = build_cgi_env(&req, &c, Path::new("/web/public_html/index.php"));
        // The underscore variants contribute NO HTTP_* env entry at all.
        let xff: Vec<&str> = env
            .iter()
            .filter(|(k, _)| k.as_ref() == "HTTP_X_FORWARDED_FOR")
            .map(|(_, v)| v.as_ref())
            .collect();
        assert_eq!(
            xff,
            vec!["203.0.113.7"],
            "only the dashed header maps to HTTP_X_FORWARDED_FOR"
        );
        assert!(
            !env.iter().any(|(k, _)| k.as_ref() == "HTTP_X_CUSTOM_AUTH"),
            "an underscore-named header must not become an HTTP_* var",
        );
    }

    #[test]
    fn accept_encoding_forced_to_identity_for_php() {
        // PHP must never see the real Accept-Encoding: zlib.output_compression and
        // XenForo's gzencode gate both key off it, burning lsphp CPU on gzip that
        // httpjet decodes for cacheable stores and re-encodes for egress anyway.
        // The override must win over both the header mirror AND the pipeline's
        // ctx.env snapshot of the real value.
        let req = http::Request::builder()
            .uri("/index.php")
            .header("Host", "forum.example")
            .header("Accept-Encoding", "gzip, deflate, br, zstd")
            .body(empty_incoming())
            .unwrap();
        let mut c = ctx(true);
        c.env.push((
            "HTTP_ACCEPT_ENCODING".into(),
            "gzip, deflate, br, zstd".into(),
        ));
        let env = build_cgi_env(&req, &c, Path::new("/web/public_html/index.php"));
        let ae: Vec<String> = env
            .iter()
            .filter(|(k, _)| k.as_ref() == "HTTP_ACCEPT_ENCODING")
            .map(|(_, v)| v.clone().into_owned())
            .collect();
        assert_eq!(
            ae,
            vec!["identity".to_string()],
            "single identity entry, real AE gone"
        );
    }

    #[test]
    fn http_host_synthesized_from_authority_when_no_host_header() {
        // HTTP/2 and HTTP/3 carry the host in the URI `:authority`, not a Host
        // header. HTTP_HOST must still be present (the article.php warning).
        let req = http::Request::builder()
            .uri("https://news.example.com/article.php?id=1")
            .body(empty_incoming())
            .unwrap();
        let c = ctx(true);
        let env = build_cgi_env(&req, &c, Path::new("/web/news/article.php"));
        let m: std::collections::HashMap<String, String> = env
            .into_iter()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        // Synthesized from :authority; a value of "news.example.com, news.example.com"
        // would mean it was duplicated — assert the exact single value.
        assert_eq!(m["HTTP_HOST"], "news.example.com");
    }

    #[test]
    fn http_host_strips_default_port_keeps_nondefault() {
        let hh = |host: &str, is_tls: bool| -> String {
            let req = http::Request::builder()
                .uri("/index.php")
                .header("Host", host)
                .body(empty_incoming())
                .unwrap();
            let c = ctx(is_tls);
            build_cgi_env(&req, &c, Path::new("/web/public_html/index.php"))
                .into_iter()
                .find(|(k, _)| k.as_ref() == "HTTP_HOST")
                .map(|(_, v)| v.into_owned())
                .unwrap()
        };
        // https: the default :443 is dropped, a non-default port is kept, bare unchanged.
        assert_eq!(hh("forum.example:443", true), "forum.example");
        assert_eq!(hh("forum.example:8443", true), "forum.example:8443");
        assert_eq!(hh("forum.example", true), "forum.example");
        // http: the default :80 is dropped, a non-default port is kept.
        assert_eq!(hh("tenant.example:80", false), "tenant.example");
        assert_eq!(hh("tenant.example:8080", false), "tenant.example:8080");
        // :443 on a cleartext request is NOT the http default -> kept (no false strip).
        assert_eq!(hh("tenant.example:443", false), "tenant.example:443");
    }

    #[test]
    fn http_host_synthesized_from_authority_strips_default_port() {
        // h2/h3 :authority carries the port; the synthesized HTTP_HOST drops :443 so XF's
        // canonical-host check matches (the thread self-redirect / no-cache root cause).
        let req = http::Request::builder()
            .uri("https://news.example.com:443/article.php")
            .body(empty_incoming())
            .unwrap();
        let c = ctx(true);
        let m: std::collections::HashMap<String, String> =
            build_cgi_env(&req, &c, Path::new("/web/news/article.php"))
                .into_iter()
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect();
        assert_eq!(m["HTTP_HOST"], "news.example.com");
    }

    #[test]
    fn http_host_falls_back_to_vhost_when_no_authority_or_host() {
        // Neither a Host header nor a URI authority (relative request target) ->
        // fall back to the resolved vhost so HTTP_HOST is never undefined.
        let req = http::Request::builder()
            .uri("/foo.php")
            .body(empty_incoming())
            .unwrap();
        let c = ctx(true); // vhost_name = "forum.example"
        let env = build_cgi_env(&req, &c, Path::new("/web/public_html/foo.php"));
        let m: std::collections::HashMap<String, String> = env
            .into_iter()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert_eq!(m["HTTP_HOST"], "forum.example");
    }

    #[test]
    fn non_tls_has_no_https_and_falls_back_to_local_port() {
        let req = http::Request::builder()
            .uri("/index.php")
            .header("Host", "tenant.example")
            .body(empty_incoming())
            .unwrap();
        let c = ctx(false);
        let env = build_cgi_env(&req, &c, Path::new("/srv/www/tenant/index.php"));
        let m: std::collections::HashMap<String, String> = env
            .into_iter()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert!(!m.contains_key("HTTPS"));
        // No port in Host -> fall back to the listener's bound port.
        assert_eq!(m["SERVER_PORT"], "8080");
        assert_eq!(m["REQUEST_SCHEME"], "http");
        // No TLS context -> no SSL_* and no AUTH_TYPE without an Authorization header.
        assert!(!m.contains_key("SSL_PROTOCOL"));
        assert!(!m.contains_key("AUTH_TYPE"));
    }

    #[test]
    fn extra_and_path_info_and_host_port() {
        let req = http::Request::builder()
            .uri("/wiki/index.php/Foo")
            .header("Host", "search.forum.example:8443")
            .body(empty_incoming())
            .unwrap();
        let c = ctx(true);
        let env = CgiEnvBuilder::new(Path::new("/web/search/index.php"))
            .script_name("/wiki/index.php")
            .path_info("/Foo")
            .extra([(
                "PHP_VALUE".to_string(),
                "auto_prepend_file=/x/p.php".to_string(),
            )])
            .build(&req, &c);
        let m: std::collections::HashMap<String, String> = env
            .into_iter()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert_eq!(m["SCRIPT_NAME"], "/wiki/index.php");
        assert_eq!(m["PATH_INFO"], "/Foo");
        assert_eq!(m["PATH_TRANSLATED"], "/web/public_html/Foo");
        assert_eq!(m["SERVER_NAME"], "search.forum.example");
        assert_eq!(m["SERVER_PORT"], "8443");
        assert_eq!(m["PHP_VALUE"], "auto_prepend_file=/x/p.php");
    }

    #[test]
    fn tls_params_emit_ssl_vars_and_client_cert() {
        use hj_core::{ClientCert, TlsParams};

        let req = http::Request::builder()
            .uri("/secure.php")
            .header("Host", "forum.example")
            // (security #269) A client-supplied Authorization header must NOT become
            // AUTH_TYPE/REMOTE_USER anymore.
            .header("Authorization", "Bearer abc.def.ghi")
            .body(empty_incoming())
            .unwrap();
        let mut c = ctx(true);
        c.tls = Some(TlsParams::new(
            "TLSv1.3",
            "TLS_AES_256_GCM_SHA384".to_string(),
            Some(ClientCert {
                subject_dn: "CN=client".to_string(),
                issuer_dn: "CN=Cloudflare Origin CA".to_string(),
                serial_hex: "0A1B2C".to_string(),
                verified: true,
                not_before: "Jan  1 00:00:00 2026 GMT".to_string(),
                not_after: "Jan  1 00:00:00 2027 GMT".to_string(),
            }),
        ));
        let env = build_cgi_env(&req, &c, Path::new("/web/public_html/secure.php"));
        let m: std::collections::HashMap<String, String> = env
            .into_iter()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert_eq!(m["SSL_PROTOCOL"], "TLSv1.3");
        assert_eq!(m["SSL_CIPHER"], "TLS_AES_256_GCM_SHA384");
        assert_eq!(m["SSL_CLIENT_VERIFY"], "SUCCESS");
        assert_eq!(m["SSL_CLIENT_S_DN"], "CN=client");
        assert_eq!(m["SSL_CLIENT_I_DN"], "CN=Cloudflare Origin CA");
        assert_eq!(m["SSL_CLIENT_M_SERIAL"], "0A1B2C");
        assert_eq!(m["SSL_CLIENT_V_START"], "Jan  1 00:00:00 2026 GMT");
        assert_eq!(m["SSL_CLIENT_V_END"], "Jan  1 00:00:00 2027 GMT");
        // Non-Basic auth: neither var may be forged from the client header.
        assert!(!m.contains_key("AUTH_TYPE"));
        assert!(!m.contains_key("REMOTE_USER"));
    }

    #[test]
    fn rewrite_env_is_exposed() {
        let req = http::Request::builder()
            .uri("/a.php")
            .header("Host", "x.com")
            .body(empty_incoming())
            .unwrap();
        let mut c = ctx(false);
        c.set_env("MY_FLAG", "1");
        let env = build_cgi_env(&req, &c, Path::new("/web/a.php"));
        let m: std::collections::HashMap<String, String> = env
            .into_iter()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert_eq!(m["MY_FLAG"], "1");
    }

    #[test]
    fn httpoxy_proxy_header_not_in_env() {
        // (#8 CVE-2016-5385) A client `Proxy` header must NOT become HTTP_PROXY in
        // the CGI env — that var would steer CGI-mode PHP's outbound calls to the
        // attacker. Other HTTP_* headers must still be present.
        let req = http::Request::builder()
            .uri("/index.php")
            .header("Host", "forum.example")
            .header("Proxy", "http://evil/")
            .header("User-Agent", "curl/8")
            .body(empty_incoming())
            .unwrap();
        let c = ctx(false);
        let env = build_cgi_env(&req, &c, Path::new("/web/public_html/index.php"));
        let m: std::collections::HashMap<String, String> = env
            .into_iter()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert!(
            !m.contains_key("HTTP_PROXY"),
            "HTTP_PROXY must be stripped (httpoxy)"
        );
        // A normal header still maps through to HTTP_*.
        assert_eq!(m["HTTP_USER_AGENT"], "curl/8");
    }
}
