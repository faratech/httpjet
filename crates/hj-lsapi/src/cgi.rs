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
/// Whether a client request header may reach a PHP/CGI backend. This is the one
/// rule for both LSAPI feeds (the CGI env table and the wire header block, which
/// lsphp also maps to `HTTP_*`) and for FastCGI params.
///
/// - httpoxy (CVE-2016-5385): a client `Proxy` header would become HTTP_PROXY,
///   which CGI-mode PHP libraries consult for outbound calls.
/// - Only letters, digits and `-` survive (Apache `http2env`): an underscore
///   collides with the `-`->`_` HTTP_* mapping, and PHP folds `.` and space to
///   `_` when registering `$_SERVER`, so `X_Forwarded_For` or `X.Forwarded.For`
///   would land on the real `HTTP_X_FORWARDED_FOR` and spoof a trusted value.
/// - Forwarding-authority headers (`CF-Connecting-IP`, `X-Forwarded-*`, ...) are
///   assertions only a trusted proxy may make; `REMOTE_ADDR` remains the truth.
pub fn header_forwardable(name: &str, forwarding_trusted: bool) -> bool {
    !name.eq_ignore_ascii_case("proxy")
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && (forwarding_trusted || !hj_core::is_forwarding_authority_header(name))
}

/// `remote_addr` is taken from `ctx.client_ip` (the proxy-resolved client IP).
pub fn build_cgi_env<'r>(
    req: &'r Request,
    ctx: &'r ReqCtx,
    script_filename: &'r Path,
) -> Vec<(Cow<'r, str>, Cow<'r, str>)> {
    CgiEnvBuilder::new(script_filename).build(req, ctx)
}

/// Stack-allocated formatting buffer for numeric/IP CGI environment values
/// (`REMOTE_ADDR`, `REMOTE_PORT`, `SERVER_ADDR`, `SERVER_PORT`, `REQUEST_TIME`,
/// `REQUEST_TIME_FLOAT`), eliminating 6 heap `String` allocations per PHP request.
pub struct CgiStackScratch {
    buf: [u8; 192],
    len: usize,
}

impl Default for CgiStackScratch {
    fn default() -> Self {
        Self::new()
    }
}

impl CgiStackScratch {
    pub const fn new() -> Self {
        Self {
            buf: [0u8; 192],
            len: 0,
        }
    }

    fn push_u64(&mut self, mut val: u64) -> Option<(usize, usize)> {
        let mut tmp = [0u8; 20];
        let mut i = tmp.len();
        loop {
            i = i.checked_sub(1)?;
            *tmp.get_mut(i)? = b'0' + (val % 10) as u8;
            val /= 10;
            if val == 0 {
                break;
            }
        }
        let digits = tmp.get(i..)?;
        let start = self.len;
        let dst = self.buf.get_mut(start..start + digits.len())?;
        dst.copy_from_slice(digits);
        self.len = start + digits.len();
        Some((start, self.len))
    }

    fn push_ip(&mut self, ip: std::net::IpAddr) -> Option<(usize, usize)> {
        match ip {
            std::net::IpAddr::V4(v4) => {
                let octets = v4.octets();
                let start = self.len;
                for (idx, &o) in octets.iter().enumerate() {
                    if idx > 0 {
                        let dot = self.buf.get_mut(self.len)?;
                        *dot = b'.';
                        self.len += 1;
                    }
                    self.push_u64(u64::from(o))?;
                }
                Some((start, self.len))
            }
            std::net::IpAddr::V6(_) => self.push_display(ip),
        }
    }

    fn push_display(&mut self, val: impl std::fmt::Display) -> Option<(usize, usize)> {
        use std::io::Write;
        let start = self.len;
        let mut slice = self.buf.get_mut(start..)?;
        let before = slice.len();
        write!(slice, "{val}").ok()?;
        let written = before - slice.len();
        self.len = start + written;
        Some((start, self.len))
    }

    fn push_float_time(&mut self, secs: u64, mut micros: u32) -> Option<(usize, usize)> {
        let start = self.len;
        self.push_u64(secs)?;
        let dot = self.buf.get_mut(self.len)?;
        *dot = b'.';
        self.len += 1;
        let frac = self.buf.get_mut(self.len..self.len + 6)?;
        for slot in frac.iter_mut().rev() {
            *slot = b'0' + (micros % 10) as u8;
            micros /= 10;
        }
        self.len += 6;
        Some((start, self.len))
    }

    fn slice(&self, range: (usize, usize)) -> &str {
        self.buf
            .get(range.0..range.1)
            .and_then(|b| std::str::from_utf8(b).ok())
            .unwrap_or("")
    }
}

/// Builder offering control over SCRIPT_NAME / PATH_INFO splitting and extra
/// `PHP_VALUE` / `PHP_ADMIN_VALUE` passthrough (e.g. `auto_prepend_file`), the
/// per-context/ext-processor env, and the document root.
pub struct CgiEnvBuilder<'a> {
    script_filename: &'a Path,
    script_name: Option<Cow<'a, str>>,
    path_info: Option<Cow<'a, str>>,
    document_root: Option<String>,
    /// Extra env appended verbatim (ext-processor `env`, PHP_VALUE/PHP_ADMIN_VALUE, ...).
    extra: Vec<(String, String)>,
    /// Borrowed equivalent of `extra` for the hot path: the handler's `base_env`
    /// lives on the `Arc<Lsapi>` for the life of the process, so it can be borrowed
    /// per request instead of cloned. Applied before `extra` (both upsert; `extra`
    /// still wins last). Empty by default.
    extra_ref: &'a [(String, String)],
    server_software: Cow<'a, str>,
    /// The request also travels as an LSAPI header block, so header copies that
    /// lsphp already registers from that block are left out of the env table.
    header_block: bool,
}

/// A request header bound for lsphp's header block, with its well-known index
/// slot resolved once: the name mapping and both builder passes all need it.
pub(crate) struct WireField<'r> {
    pub(crate) name: Cow<'r, str>,
    pub(crate) value: Cow<'r, str>,
    pub(crate) known: Option<usize>,
}

impl crate::proto::WireHeader for WireField<'_> {
    fn name(&self) -> &str {
        &self.name
    }
    fn value(&self) -> &str {
        &self.value
    }
    fn known_index(&self) -> Option<usize> {
        self.known
    }
    /// The name lsphp reports for a header (`getallheaders()`, #950). A well-known
    /// header is sent by index slot, so the SAPI names it from its own table and the
    /// name text is never read. Any other name is reported verbatim; the h1 case is
    /// gone by now (the `http` crate lower-cases), so restore the conventional
    /// Title-Case FPM/Apache present (`x-hub-signature-256` -> `X-Hub-Signature-256`).
    /// Only `[A-Za-z0-9-]` names get here ([`header_forwardable`]), so the
    /// mapping is case-only: `HTTP_*` names and duplicate grouping are unchanged. The
    /// builder applies it while copying the name, so no per-header String is built.
    fn title_case(&self) -> bool {
        self.known.is_none()
    }
}

/// Populate a caller-owned `Vec` with the CGI env entries using stack
/// scratch, allowing repeated bodyless requests to reuse one TLS `Vec`.
impl<'a> CgiEnvBuilder<'a> {
    pub fn new(script_filename: &'a Path) -> Self {
        CgiEnvBuilder {
            script_filename,
            script_name: None,
            path_info: None,
            document_root: None,
            extra: Vec::new(),
            extra_ref: &[],
            server_software: Cow::Borrowed("LiteSpeed"),
            header_block: false,
        }
    }

    /// Leave out each `HTTP_*` copy that lsphp registers from the LSAPI header block
    /// with the same name and value ([`header_block_registers_copy`]). lsphp fills
    /// `$_SERVER` from the block before the env table (`LSAPI_ForeachHeader`, then
    /// `LSAPI_ForeachEnv`), and a later write to an existing key keeps its position,
    /// so `$_SERVER` is unchanged; `getenv("HTTP_*")` reads only the block. Only for
    /// a backend that receives that block: FastCGI has none.
    pub fn header_block(mut self, enabled: bool) -> Self {
        self.header_block = enabled;
        self
    }

    /// Override SCRIPT_NAME (the URL path of the script, before PATH_INFO).
    pub fn script_name(mut self, s: impl Into<Cow<'a, str>>) -> Self {
        self.script_name = Some(s.into());
        self
    }

    /// Set PATH_INFO (the trailing path after the script).
    pub fn path_info(mut self, s: impl Into<Cow<'a, str>>) -> Self {
        self.path_info = Some(s.into());
        self
    }

    /// Override DOCUMENT_ROOT (defaults to the vhost doc root in `ctx`).
    pub fn document_root(mut self, s: impl Into<String>) -> Self {
        self.document_root = Some(s.into());
        self
    }

    /// Set SERVER_SOFTWARE.
    pub fn server_software(mut self, s: impl Into<Cow<'a, str>>) -> Self {
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
        self.build_with_content_length(req, ctx, None)
    }

    /// Build the CGI environment with an optional concrete body length.  LSAPI
    /// must provide a length for a chunked request after buffering it, but the
    /// override stays out of the caller's request headers so post-dispatch
    /// authorization and ErrorDocument policy still see the exact inbound head.
    pub fn build_with_content_length<'r>(
        self,
        req: &'r Request,
        ctx: &'r ReqCtx,
        content_length: Option<&'r str>,
    ) -> Vec<(Cow<'r, str>, Cow<'r, str>)>
    where
        'a: 'r,
    {
        self.build_inner(req, ctx, content_length, None)
    }

    /// Like [`Self::build_with_content_length`], but formats numeric and IP CGI
    /// variables (`REMOTE_ADDR`, `REMOTE_PORT`, `SERVER_ADDR`, `SERVER_PORT`,
    /// `REQUEST_TIME`, `REQUEST_TIME_FLOAT`) into `scratch` with zero heap
    /// allocations.
    pub fn build_with_content_length_scratch<'r>(
        self,
        req: &'r Request,
        ctx: &'r ReqCtx,
        content_length: Option<&'r str>,
        scratch: &'r mut CgiStackScratch,
    ) -> Vec<(Cow<'r, str>, Cow<'r, str>)>
    where
        'a: 'r,
    {
        let mut env = Vec::with_capacity(24 + req.headers().len());
        self.build_inner_into(req, ctx, content_length, Some(scratch), &mut env);
        env
    }

    /// Populate a caller-owned `Vec` with the CGI env entries using stack
    /// scratch, allowing repeated bodyless requests to reuse one TLS `Vec`.
    pub fn build_with_content_length_scratch_into<'r>(
        self,
        req: &'r Request,
        ctx: &'r ReqCtx,
        content_length: Option<&'r str>,
        scratch: &'r mut CgiStackScratch,
        out: &mut Vec<(Cow<'r, str>, Cow<'r, str>)>,
    ) where
        'a: 'r,
    {
        out.clear();
        self.build_inner_into(req, ctx, content_length, Some(scratch), out);
    }

    fn build_inner<'r>(
        self,
        req: &'r Request,
        ctx: &'r ReqCtx,
        content_length: Option<&'r str>,
        scratch: Option<&'r mut CgiStackScratch>,
    ) -> Vec<(Cow<'r, str>, Cow<'r, str>)>
    where
        'a: 'r,
    {
        let mut env: Vec<(Cow<'r, str>, Cow<'r, str>)> =
            Vec::with_capacity(24 + req.headers().len());
        self.build_inner_into(req, ctx, content_length, scratch, &mut env);
        env
    }

    fn build_inner_into<'r>(
        self,
        req: &'r Request,
        ctx: &'r ReqCtx,
        content_length: Option<&'r str>,
        mut scratch: Option<&'r mut CgiStackScratch>,
        env: &mut Vec<(Cow<'r, str>, Cow<'r, str>)>,
    ) where
        'a: 'r,
    {
        let min_cap = 24 + req.headers().len();
        if env.capacity() < min_cap {
            env.reserve(min_cap - env.len());
        }

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
        // `self.script_filename` has lifetime `'a: 'r`, so borrow directly when UTF-8;
        // owned fields (`script_name`, `path_info`, `document_root`) are moved out of
        // `self` instead of cloned, and fall back to borrowing `path` / `ctx.vhost.doc_root`.
        match self.script_filename.to_str() {
            Some(s) => push_borrow!("SCRIPT_FILENAME", s),
            None => push!(
                "SCRIPT_FILENAME",
                self.script_filename.to_string_lossy().into_owned()
            ),
        }
        match self.script_name {
            Some(s) => env.push((Cow::Borrowed("SCRIPT_NAME"), s)),
            None => push_borrow!("SCRIPT_NAME", path),
        }
        push_borrow!("QUERY_STRING", query);
        if let Some(q) = uri.query() {
            env.push((
                Cow::Borrowed("REQUEST_URI"),
                Cow::Owned(format!("{path}?{q}")),
            ));
        } else {
            push_borrow!("REQUEST_URI", path);
        }
        let path_info = self.path_info.filter(|pi| !pi.is_empty());
        let doc_root: Cow<'r, str> = match self.document_root {
            Some(d) => Cow::Owned(d),
            None => match ctx.vhost.doc_root.to_str() {
                Some(s) => Cow::Borrowed(s),
                None => Cow::Owned(ctx.vhost.doc_root.to_string_lossy().into_owned()),
            },
        };
        if let Some(pi) = path_info {
            let translated = format!("{doc_root}{pi}");
            env.push((Cow::Borrowed("PATH_INFO"), pi));
            env.push((Cow::Borrowed("DOCUMENT_ROOT"), doc_root));
            env.push((Cow::Borrowed("PATH_TRANSLATED"), Cow::Owned(translated)));
        } else {
            env.push((Cow::Borrowed("DOCUMENT_ROOT"), doc_root));
        }

        // Pre-format the 6 numeric/IP values into stack scratch when supplied so
        // `env` can borrow `&'r str` slices directly with zero heap allocations.
        let since_epoch = ctx.request_time.duration_since(std::time::UNIX_EPOCH).ok();
        let stack_ranges = if let Some(sc) = scratch.as_deref_mut() {
            let r_addr = sc.push_ip(ctx.client_ip);
            let r_port = sc.push_u64(u64::from(ctx.peer_port));
            let s_addr = sc.push_ip(ctx.local_addr.ip());
            let s_port = sc.push_u64(u64::from(ctx.local_addr.port()));
            let (r_time, r_time_f) = match since_epoch {
                Some(since) => (
                    sc.push_u64(since.as_secs()),
                    sc.push_float_time(since.as_secs(), since.subsec_micros()),
                ),
                None => (None, None),
            };
            Some((r_addr, r_port, s_addr, s_port, r_time, r_time_f))
        } else {
            None
        };
        let scratch_ref: Option<&'r CgiStackScratch> = scratch.map(|s| &*s);

        // Client / remote. REMOTE_ADDR is the proxy-resolved client IP;
        // REMOTE_PORT is the directly-connected peer's TCP port.
        match (scratch_ref, stack_ranges.and_then(|r| r.0)) {
            (Some(sc), Some(rng)) => push_borrow!("REMOTE_ADDR", sc.slice(rng)),
            _ => push!("REMOTE_ADDR", ctx.client_ip.to_string()),
        }
        match (scratch_ref, stack_ranges.and_then(|r| r.1)) {
            (Some(sc), Some(rng)) => push_borrow!("REMOTE_PORT", sc.slice(rng)),
            _ => push!("REMOTE_PORT", ctx.peer_port.to_string()),
        }

        // Server identity — SERVER_NAME/SOFTWARE now borrow (#282).
        let server_name = match host_header(req) {
            Some(h) => strip_port(h),
            None => ctx.vhost_name.as_str(),
        };
        env.push((Cow::Borrowed("SERVER_NAME"), Cow::Borrowed(server_name)));
        env.push((Cow::Borrowed("SERVER_SOFTWARE"), self.server_software));
        match (scratch_ref, stack_ranges.and_then(|r| r.2)) {
            (Some(sc), Some(rng)) => push_borrow!("SERVER_ADDR", sc.slice(rng)),
            _ => push!("SERVER_ADDR", ctx.local_addr.ip().to_string()),
        }

        // The listener's port, never the client's Host header: SERVER_PORT is
        // server-asserted (LSWS REF_SERVER_PORT; XenForo isSecure() trusts 443).
        match (scratch_ref, stack_ranges.and_then(|r| r.3)) {
            (Some(sc), Some(rng)) => push_borrow!("SERVER_PORT", sc.slice(rng)),
            _ => push!("SERVER_PORT", ctx.local_addr.port().to_string()),
        }

        // Request arrival time. REQUEST_TIME is whole seconds; the _FLOAT variant
        // carries microsecond precision (e.g. "1700000000.123456").
        if let Some(since) = since_epoch {
            match (scratch_ref, stack_ranges.and_then(|r| r.4)) {
                (Some(sc), Some(rng)) => push_borrow!("REQUEST_TIME", sc.slice(rng)),
                _ => push!("REQUEST_TIME", since.as_secs().to_string()),
            }
            match (scratch_ref, stack_ranges.and_then(|r| r.5)) {
                (Some(sc), Some(rng)) => push_borrow!("REQUEST_TIME_FLOAT", sc.slice(rng)),
                _ => push!(
                    "REQUEST_TIME_FLOAT",
                    format!("{}.{:06}", since.as_secs(), since.subsec_micros())
                ),
            }
        }

        // (security #269) AUTH_TYPE / REMOTE_USER are SERVER-ASSERTED identity vars.
        // httpjet has no HTTP authentication module, so echoing the raw client
        // `Authorization` header into them let ANY unauthenticated request forge
        // `$_SERVER['REMOTE_USER']` for apps that trust it. They are now emitted only
        // from an authenticated source: a VERIFIED TLS client certificate (see the
        // SSL_CLIENT_* block below — apps check `SSL_CLIENT_VERIFY === 'SUCCESS'`) or a
        // Basic-auth realm the pipeline verified ([`AUTH_USER_ENV`], mapped below).

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
        if let Some(cl) = content_length.or_else(|| {
            req.headers()
                .get(http::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
        }) {
            env.push((Cow::Borrowed("CONTENT_LENGTH"), Cow::Borrowed(cl)));
        }

        // All request headers as HTTP_*. Content-Type/Length are intentionally
        // duplicated here too (PHP & CGI both expect that). Iterate distinct header
        // NAMES (`keys()`) and pull each name's values with `get_all` — the `http`
        // HeaderMap already groups repeated headers, so this de-dups for free with
        // NO per-request HashMap allocation (the former O(1) map only existed to
        // avoid an O(n^2) linear scan over the env vec). `http_var_name` still runs
        // once per distinct name; the common single-value header stays borrowed.
        const SEEN_AE: u8 = 1 << 0;
        const SEEN_PROTO: u8 = 1 << 1;
        const SEEN_HTTPS: u8 = 1 << 2;
        const SEEN_SCHEME: u8 = 1 << 3;
        const SEEN_REDIRECT: u8 = 1 << 4;
        #[inline]
        fn special_env_bit(k: &str) -> u8 {
            match k {
                "HTTP_ACCEPT_ENCODING" => SEEN_AE,
                "SERVER_PROTOCOL" => SEEN_PROTO,
                "HTTPS" => SEEN_HTTPS,
                "REQUEST_SCHEME" => SEEN_SCHEME,
                "REDIRECT_STATUS" => SEEN_REDIRECT,
                _ => 0,
            }
        }
        let mut seen_flags: u8 = 0;

        let mut have_host = false;
        for name in req.headers().keys() {
            let nm = name.as_str();
            if !header_forwardable(nm, ctx.forwarding_trusted) {
                continue;
            }
            // A buffered chunked request has a synthesized concrete length.
            // Ignore every inbound Content-Length value (including malformed or
            // repeated values) and add the authoritative override below.
            if content_length.is_some() && name == http::header::CONTENT_LENGTH {
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
            let second_hv = values.next();
            if second_hv.is_none() && self.header_block && header_block_registers_copy(nm) {
                continue;
            }
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
            let value: Cow<'r, str> = match second_hv {
                None => first,
                Some(second_hv) => {
                    // Cookie crumbs join with `; ` (RFC 9113 §8.2.3), the form every
                    // cookie parser splits on (#671).
                    let sep = if nm.eq_ignore_ascii_case("cookie") {
                        "; "
                    } else {
                        ", "
                    };
                    let mut joined = String::with_capacity(first.len() + 8);
                    joined.push_str(&first);
                    for hv in std::iter::once(second_hv).chain(values) {
                        joined.push_str(sep);
                        match hv.to_str() {
                            Ok(v) => joined.push_str(v),
                            Err(_) => joined.push_str(&String::from_utf8_lossy(hv.as_bytes())),
                        }
                    }
                    Cow::Owned(joined)
                }
            };
            have_host |= is_host;
            if nm.eq_ignore_ascii_case("accept-encoding") {
                seen_flags |= SEEN_AE;
            }
            env.push((http_var_name(nm), value));
        }
        if let Some(cl) = content_length {
            env.push((Cow::Borrowed("HTTP_CONTENT_LENGTH"), Cow::Borrowed(cl)));
        }

        // HTTP/2 and HTTP/3 clients send the `:authority` pseudo-header instead of a
        // `Host` header, so the loop above produced no HTTP_HOST. Synthesize it (full
        // host[:port]) from the URI authority, then the resolved vhost, so
        // $_SERVER['HTTP_HOST'] is always present (LiteSpeed maps :authority -> Host).
        // Only when absent, so the HTTP/1.x case (real Host header) is untouched.
        if !have_host {
            let host = match req.uri().authority() {
                Some(a) => Cow::Borrowed(host_without_default_port(a.as_str(), ctx.is_tls)),
                None => Cow::Borrowed(ctx.vhost_name.as_str()),
            };
            env.push((Cow::Borrowed("HTTP_HOST"), host));
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
        // Check `sec-purpose` first (absent on 99% of requests -> 1 HeaderMap probe
        // instead of 4) and match "prefetch" ASCII case-insensitively without allocating.
        if let Some(sp) = req
            .headers()
            .get("sec-purpose")
            .and_then(|v| v.to_str().ok())
            && !req.headers().contains_key("x-purpose")
            && !req.headers().contains_key("purpose")
            && !req.headers().contains_key("x-moz")
            && sp
                .as_bytes()
                .windows(8)
                .any(|w| w.eq_ignore_ascii_case(b"prefetch"))
        {
            env.push((Cow::Borrowed("HTTP_X_PURPOSE"), Cow::Borrowed("prefetch")));
        }

        // Env set by rewrite [E=...] flags (exposed as $_SERVER in PHP too).
        // Borrowed from `ctx.env` (lives as long as `ctx`).
        for (k, v) in &ctx.env {
            if k == AUTH_USER_ENV {
                upsert(env, Cow::Borrowed("REMOTE_USER"), Cow::Borrowed(v.as_str()));
                upsert(env, Cow::Borrowed("AUTH_TYPE"), Cow::Borrowed("Basic"));
                continue;
            }
            if ctx_env_override_denied(k) {
                continue;
            }
            seen_flags |= special_env_bit(k);
            upsert(env, Cow::Borrowed(k.as_str()), Cow::Borrowed(v.as_str()));
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
        if seen_flags & SEEN_AE != 0 {
            upsert(
                env,
                Cow::Borrowed("HTTP_ACCEPT_ENCODING"),
                Cow::Borrowed("identity"),
            );
        } else {
            env.push((
                Cow::Borrowed("HTTP_ACCEPT_ENCODING"),
                Cow::Borrowed("identity"),
            ));
            seen_flags |= SEEN_AE;
        }

        // Caller passthrough (borrowed base_env first, then any owned extra which
        // wins last on duplicate keys). base_env is borrowed from the long-lived
        // handler — no per-request clone.
        for (k, v) in self.extra_ref {
            seen_flags |= special_env_bit(k);
            upsert(env, Cow::Borrowed(k.as_str()), Cow::Borrowed(v.as_str()));
        }
        for (k, v) in self.extra {
            seen_flags |= special_env_bit(&k);
            upsert(env, Cow::Owned(k), Cow::Owned(v));
        }

        // Static TLS/redirect-status/protocol DEFAULTS (zero-alloc). Inserted only if
        // NOT already present, so an earlier ctx.env `[E=...]` / SetEnvIf / `extra()`
        // entry of the same name WINS — restoring the pre-43a5aa7 "override beats
        // static" contract without shipping a duplicate key to lsphp (PHP's $_SERVER
        // takes the LAST occurrence, so a bare push here clobbered e.g. a PHP
        // ErrorDocument subrequest's REDIRECT_STATUS=<code> back to 200) (#129).
        if seen_flags & SEEN_PROTO == 0 {
            env.push((
                Cow::Borrowed("SERVER_PROTOCOL"),
                Cow::Borrowed(ctx.protocol.as_str()),
            ));
        }
        if ctx.is_tls {
            if seen_flags & SEEN_HTTPS == 0 {
                env.push((Cow::Borrowed("HTTPS"), Cow::Borrowed("on")));
            }
            if seen_flags & SEEN_SCHEME == 0 {
                env.push((Cow::Borrowed("REQUEST_SCHEME"), Cow::Borrowed("https")));
            }
        } else if seen_flags & SEEN_SCHEME == 0 {
            env.push((Cow::Borrowed("REQUEST_SCHEME"), Cow::Borrowed("http")));
        }
        if seen_flags & SEEN_REDIRECT == 0 {
            env.push((Cow::Borrowed("REDIRECT_STATUS"), Cow::Borrowed("200")));
        }
    }
}

/// Names a rewrite/`[E=...]`/SetEnvIf `ctx.env` entry may NOT override.
///
/// The operator's `extra()`/base_env path is already filtered by
/// [`safe_extra_env_name`]; `ctx.env` (directory-authored: `.htaccess`
/// authors, CMS plugins) bypassed that filter, so `[E=SCRIPT_FILENAME:...]`
/// could re-point execution at an arbitrary file and `[E=REMOTE_ADDR:...]` /
/// `[E=HTTPS:...]` / `SSL_CLIENT_VERIFY=SUCCESS` could forge the server-computed
/// identity vars PHP trusts.
///
/// Deliberately still overridable: `SCRIPT_NAME`/`QUERY_STRING` (the
/// front-controller contract), `REDIRECT_*` (the #129 ErrorDocument
/// subrequest contract), and `HTTP_*` (header mirrors whose wire values are
/// computed independently).
///
/// Judged on the key PHP will register ([`php_server_var_name`]), not the raw
/// spelling: `REMOTE.ADDR` or ` HTTPS` land on `$_SERVER['REMOTE_ADDR']` /
/// `['HTTPS']` after the server-computed value and would win (#1017). Any
/// other name keeps its raw spelling, so `my.var` still reaches the app as
/// `$_SERVER['my_var']`.
fn ctx_env_override_denied(name: &str) -> bool {
    let Some(php_name) = php_server_var_name(name) else {
        return true;
    };
    let php_name = php_name.as_ref();
    server_var_reserved(php_name)
        || (php_name.starts_with("HJ_")
            && !(php_name == name && FORWARDED_INTERNAL_ENV.contains(&name)))
}

fn server_var_reserved(name: &str) -> bool {
    const DENIED: &[&str] = &[
        "SCRIPT_FILENAME",
        "PATH_TRANSLATED",
        "DOCUMENT_ROOT",
        "VH_ROOT",
        "REMOTE_ADDR",
        "REMOTE_HOST",
        "REMOTE_PORT",
        "REMOTE_USER",
        "AUTH_TYPE",
        "HTTPS",
        "SERVER_NAME",
        "SERVER_ADDR",
        "SERVER_PORT",
        "SERVER_SOFTWARE",
        "SERVER_ADMIN",
        "SERVER_PROTOCOL",
        "REQUEST_SCHEME",
        "REQUEST_METHOD",
        "REQUEST_URI",
        "PATH_INFO",
        "CONTENT_LENGTH",
        "CONTENT_TYPE",
        "GATEWAY_INTERFACE",
        // php-fpm applies these FastCGI params as ini directives; `.htaccess` php_value
        // reaches PHP through the LSAPI special-env section instead (#1024).
        "PHP_VALUE",
        "PHP_ADMIN_VALUE",
    ];
    DENIED.contains(&name)
        || name.starts_with("REQUEST_TIME")
        || name.starts_with("LSAPI_")
        || name.starts_with("SSL_")
}

/// The `$_SERVER` key PHP registers for env name `name`
/// (`php_register_variable_ex`, which both the LSAPI and FastCGI SAPIs use):
/// leading spaces are dropped and ` `/`.` fold to `_`. A `[` opens array
/// syntax: with a `]` anywhere after it the key ends at the `[`; without one,
/// that `[` and every later ` `/`.`/`[` fold to `_` too (`A[b.c` -> `A_b_c`).
///
/// `None` when PHP registers nothing (the name is empty after the cut, e.g.
/// all spaces or a leading `[`) or holds a NUL, where PHP's C-string read
/// would see a different, truncated name.
pub fn php_server_var_name(name: &str) -> Option<Cow<'_, str>> {
    if name.as_bytes().contains(&0) {
        return None;
    }
    let name = name.trim_start_matches(' ');
    let key = match name.split_once('[') {
        Some(("", _)) => return None,
        Some((key, index)) if index.contains(']') => key,
        _ => name,
    };
    if key.is_empty() {
        return None;
    }
    const MANGLED: [char; 3] = [' ', '.', '['];
    if key.contains(MANGLED) {
        Some(Cow::Owned(key.replace(MANGLED, "_")))
    } else {
        Some(Cow::Borrowed(key))
    }
}

/// Internal `HJ_*` pipeline names that ARE forwarded to the app. Config-driven
/// writers (SetEnvIf, rewrite `[E=]`) already refuse the whole `HJ_` namespace,
/// so anything under it in `ctx.env` was set by the pipeline itself.
const FORWARDED_INTERNAL_ENV: &[&str] = &[CACHE_REFRESH_ENV];

/// Set on a stale-while-revalidate refresh so the app's own page cache
/// (`pagecache.php`) renders fresh instead of replaying its aging copy.
pub const CACHE_REFRESH_ENV: &str = "HJ_CACHE_REFRESH";

/// `ctx.env` name carrying a user the pipeline VERIFIED against a Basic-auth
/// realm. Emitted as `REMOTE_USER` + `AUTH_TYPE=Basic`; a directory-authored
/// `REMOTE_USER` stays refused (see [`ctx_env_override_denied`]).
pub const AUTH_USER_ENV: &str = "HJ_AUTH_USER";

fn upsert<'r>(env: &mut Vec<(Cow<'r, str>, Cow<'r, str>)>, key: Cow<'r, str>, val: Cow<'r, str>) {
    if let Some(slot) = env.iter_mut().find(|(k, _)| k.as_ref() == key.as_ref()) {
        slot.1 = val;
    } else {
        env.push((key, val));
    }
}

/// Whether lsphp registers a single-valued, forwardable header's `HTTP_*` key with
/// the env copy's exact value from the LSAPI header block. The exceptions:
/// - `Host`: the env copy drops the scheme-default port;
/// - `Content-Type` / `Content-Length`: the block registers them as `CONTENT_TYPE` /
///   `CONTENT_LENGTH`, so `HTTP_CONTENT_*` exist only in the env;
/// - `Transfer-Encoding`: `LSAPI_ForeachHeader` skips that index slot;
/// - a name over 250 bytes: lsphp truncates an unknown header's name there.
///
/// A repeated header never gets here: the env joins its values, while the block
/// keeps the last value of a well-known header and registers each other one in turn.
fn header_block_registers_copy(header: &str) -> bool {
    const ENV_ONLY: [&str; 4] = [
        "host",
        "content-type",
        "content-length",
        "transfer-encoding",
    ];
    header.len() <= 250 && !ENV_ONLY.iter().any(|n| header.eq_ignore_ascii_case(n))
}

/// `Content-Type` -> `HTTP_CONTENT_TYPE`, `X-Forwarded-For` -> `HTTP_X_FORWARDED_FOR`.
fn http_var_name(header: &str) -> Cow<'static, str> {
    // Fast static table for common lowercase HTTP header names (zero allocations).
    let known = match header {
        "host" => Some("HTTP_HOST"),
        "user-agent" => Some("HTTP_USER_AGENT"),
        "accept" => Some("HTTP_ACCEPT"),
        "accept-encoding" => Some("HTTP_ACCEPT_ENCODING"),
        "accept-language" => Some("HTTP_ACCEPT_LANGUAGE"),
        "cookie" => Some("HTTP_COOKIE"),
        "referer" => Some("HTTP_REFERER"),
        "origin" => Some("HTTP_ORIGIN"),
        "authorization" => Some("HTTP_AUTHORIZATION"),
        "cache-control" => Some("HTTP_CACHE_CONTROL"),
        "pragma" => Some("HTTP_PRAGMA"),
        "connection" => Some("HTTP_CONNECTION"),
        "if-none-match" => Some("HTTP_IF_NONE_MATCH"),
        "if-modified-since" => Some("HTTP_IF_MODIFIED_SINCE"),
        "range" => Some("HTTP_RANGE"),
        "x-requested-with" => Some("HTTP_X_REQUESTED_WITH"),
        "x-forwarded-for" => Some("HTTP_X_FORWARDED_FOR"),
        "x-forwarded-proto" => Some("HTTP_X_FORWARDED_PROTO"),
        "x-forwarded-host" => Some("HTTP_X_FORWARDED_HOST"),
        "x-real-ip" => Some("HTTP_X_REAL_IP"),
        "cf-connecting-ip" => Some("HTTP_CF_CONNECTING_IP"),
        "cf-ray" => Some("HTTP_CF_RAY"),
        "cf-ipcountry" => Some("HTTP_CF_IPCOUNTRY"),
        "cf-visitor" => Some("HTTP_CF_VISITOR"),
        "sec-fetch-mode" => Some("HTTP_SEC_FETCH_MODE"),
        "sec-fetch-site" => Some("HTTP_SEC_FETCH_SITE"),
        "sec-fetch-dest" => Some("HTTP_SEC_FETCH_DEST"),
        "sec-fetch-user" => Some("HTTP_SEC_FETCH_USER"),
        "sec-ch-ua" => Some("HTTP_SEC_CH_UA"),
        "sec-ch-ua-mobile" => Some("HTTP_SEC_CH_UA_MOBILE"),
        "sec-ch-ua-platform" => Some("HTTP_SEC_CH_UA_PLATFORM"),
        "upgrade-insecure-requests" => Some("HTTP_UPGRADE_INSECURE_REQUESTS"),
        "priority" => Some("HTTP_PRIORITY"),
        "dnt" => Some("HTTP_DNT"),
        _ => None,
    };
    if let Some(s) = known {
        return Cow::Borrowed(s);
    }
    let mut s = String::with_capacity(header.len() + 5);
    s.push_str("HTTP_");
    for c in header.chars() {
        if c == '-' {
            s.push('_');
        } else {
            s.push(c.to_ascii_uppercase());
        }
    }
    Cow::Owned(s)
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
pub(crate) mod tests {
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

    pub(crate) fn ctx(is_tls: bool) -> ReqCtx {
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
            forwarding_trusted: true,
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
    fn ctx_env_cannot_override_server_computed_vars() {
        let req = http::Request::builder()
            .method("GET")
            .uri("/x.php")
            .header("Host", "forum.example")
            .body(empty_incoming())
            .unwrap();

        let mut c = ctx(false);
        c.env = vec![
            ("SCRIPT_FILENAME".into(), "/etc/passwd".into()),
            ("REMOTE_ADDR".into(), "6.6.6.6".into()),
            ("HTTPS".into(), "on".into()),
            ("SERVER_PROTOCOL".into(), "HTTP/9".into()),
            ("SSL_CLIENT_VERIFY".into(), "SUCCESS".into()),
            ("REMOTE_USER".into(), "admin".into()),
            // (#586) Method/URI/PATH_INFO/content vars are server-computed too.
            ("REQUEST_METHOD".into(), "POST".into()),
            ("REQUEST_URI".into(), "/forged".into()),
            ("PATH_INFO".into(), "/forged".into()),
            ("CONTENT_TYPE".into(), "text/evil".into()),
            ("REQUEST_TIME_FLOAT".into(), "1.0".into()),
            ("HJ_ANYTHING".into(), "x".into()),
            // Contracts that must keep working:
            ("SCRIPT_NAME".into(), "/index.php".into()),
            ("QUERY_STRING".into(), "front=controller".into()),
            ("REDIRECT_STATUS".into(), "403".into()),
        ];
        let env = build_cgi_env(&req, &c, Path::new("/web/public_html/x.php"));
        let m: std::collections::HashMap<String, String> = env
            .into_iter()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();

        assert_eq!(m["SCRIPT_FILENAME"], "/web/public_html/x.php");
        assert_eq!(m["REMOTE_ADDR"], "203.0.113.7");
        assert!(!m.contains_key("HTTPS"));
        assert_eq!(m["SERVER_PROTOCOL"], "HTTP/2");
        assert!(!m.contains_key("SSL_CLIENT_VERIFY"));
        assert!(!m.contains_key("REMOTE_USER"));
        assert!(!m.contains_key("HJ_ANYTHING"));
        assert_eq!(m["SCRIPT_NAME"], "/index.php");
        assert_eq!(m["QUERY_STRING"], "front=controller");
        assert_eq!(m["REDIRECT_STATUS"], "403");
        // (#586) Forged computed vars keep their server-computed values.
        assert_eq!(m["REQUEST_METHOD"], "GET");
        assert_ne!(m.get("REQUEST_URI").map(String::as_str), Some("/forged"));
        assert_ne!(m.get("PATH_INFO").map(String::as_str), Some("/forged"));
        assert_ne!(m.get("CONTENT_TYPE").map(String::as_str), Some("text/evil"));
        assert_ne!(m.get("REQUEST_TIME_FLOAT").map(String::as_str), Some("1.0"));
    }

    /// Expected keys observed from PHP 8.5.11 `parse_str`, which registers
    /// through the same `php_register_variable_ex` as the LSAPI/FastCGI SAPIs.
    #[test]
    fn php_server_var_name_matches_php_registration() {
        let cases: &[(&str, Option<&str>)] = &[
            ("REMOTE_ADDR", Some("REMOTE_ADDR")),
            ("Cache-Control", Some("Cache-Control")),
            ("REMOTE.ADDR", Some("REMOTE_ADDR")),
            (" HTTPS", Some("HTTPS")),
            ("  SSL.CLIENT.VERIFY", Some("SSL_CLIENT_VERIFY")),
            ("ab ", Some("ab_")),
            ("REMOTE[USER]", Some("REMOTE")),
            ("REMOTE[USER", Some("REMOTE_USER")),
            ("REMOTE_ADDR[]", Some("REMOTE_ADDR")),
            ("REMOTE_ADDR[", Some("REMOTE_ADDR_")),
            ("A[b.c", Some("A_b_c")),
            ("A[b[c", Some("A_b_c")),
            ("A[b]c", Some("A")),
            ("A[ b]", Some("A")),
            ("A.[b", Some("A__b")),
            ("A]x[b", Some("A]x_b")),
            ("x.y[z.w", Some("x_y_z_w")),
            ("a]b", Some("a]b")),
            ("A\tB", Some("A\tB")),
            ("[REMOTE_ADDR]", None),
            ("[x", None),
            ("  [x]", None),
            (" ", None),
            ("", None),
            ("REMOTE_ADDR\0X", None),
        ];
        for (raw, want) in cases {
            assert_eq!(
                php_server_var_name(raw).as_deref(),
                *want,
                "PHP key for {raw:?}"
            );
        }
        assert!(matches!(
            php_server_var_name("WF_NOINDEX_PATH"),
            Some(Cow::Borrowed(_))
        ));
    }

    #[test]
    fn ctx_env_cannot_set_php_ini_params() {
        let req = http::Request::builder()
            .method("GET")
            .uri("/x.php")
            .header("Host", "forum.example")
            .body(empty_incoming())
            .unwrap();
        let mut c = ctx(false);
        c.env = vec![
            (
                "PHP_ADMIN_VALUE".into(),
                "auto_prepend_file=/tmp/x.php".into(),
            ),
            ("PHP_VALUE".into(), "auto_prepend_file=/tmp/x.php".into()),
            ("PHP.ADMIN.VALUE".into(), "open_basedir=/".into()),
            ("WF_NOINDEX_PATH".into(), "1".into()),
        ];
        let env = build_cgi_env(&req, &c, Path::new("/web/public_html/x.php"));
        let keys: Vec<&str> = env.iter().map(|(k, _)| k.as_ref()).collect();
        assert!(!keys.iter().any(|k| {
            php_server_var_name(k).is_some_and(|p| p == "PHP_VALUE" || p == "PHP_ADMIN_VALUE")
        }));
        assert!(keys.contains(&"WF_NOINDEX_PATH"));
    }

    #[test]
    fn php_mangled_ctx_env_names_cannot_forge_server_vars() {
        let req = http::Request::builder()
            .method("GET")
            .uri("/x.php")
            .header("Host", "forum.example")
            .body(empty_incoming())
            .unwrap();

        let mut c = ctx(false);
        c.env = vec![
            ("REMOTE.ADDR".into(), "6.6.6.6".into()),
            ("REMOTE_ADDR[]".into(), "6.6.6.6".into()),
            (" HTTPS".into(), "on".into()),
            ("SSL.CLIENT.VERIFY".into(), "SUCCESS".into()),
            ("SSL_CLIENT_S[DN".into(), "CN=admin".into()),
            ("REMOTE[USER".into(), "admin".into()),
            ("REMOTE[USER]".into(), "admin".into()),
            ("SCRIPT.FILENAME".into(), "/etc/passwd".into()),
            ("REQUEST.TIME".into(), "1".into()),
            ("HJ.CACHE.REFRESH".into(), "1".into()),
            (" HJ_CACHE_REFRESH".into(), "1".into()),
            ("HJ.AUTH.USER".into(), "admin".into()),
            ("REMOTE_ADDR\0".into(), "6.6.6.6".into()),
            ("[x]".into(), "1".into()),
            // Non-protected names PHP mangles still reach the app unchanged.
            ("my.flag".into(), "1".into()),
            ("WF_NOINDEX_PATH".into(), "1".into()),
        ];
        let env = build_cgi_env(&req, &c, Path::new("/web/public_html/x.php"));
        for (k, _) in &env {
            let php = php_server_var_name(k).expect("every emitted name registers in PHP");
            let protected = server_var_reserved(&php) || php.starts_with("HJ_");
            let server_owned = k == &php
                && matches!(
                    k.as_ref(),
                    "REMOTE_ADDR"
                        | "REMOTE_PORT"
                        | "SCRIPT_FILENAME"
                        | "DOCUMENT_ROOT"
                        | "REQUEST_METHOD"
                        | "REQUEST_URI"
                        | "REQUEST_TIME"
                        | "REQUEST_TIME_FLOAT"
                        | "REQUEST_SCHEME"
                        | "SERVER_NAME"
                        | "SERVER_ADDR"
                        | "SERVER_PORT"
                        | "SERVER_SOFTWARE"
                        | "SERVER_PROTOCOL"
                        | "GATEWAY_INTERFACE"
                );
            assert!(!protected || server_owned, "{k:?} reached PHP as {php:?}");
        }
        let m: std::collections::HashMap<String, String> = env
            .into_iter()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert_eq!(m["REMOTE_ADDR"], "203.0.113.7");
        assert_eq!(m["SCRIPT_FILENAME"], "/web/public_html/x.php");
        assert!(!m.contains_key("HTTPS"));
        assert!(!m.contains_key("REMOTE_USER"));
        assert!(!m.contains_key("AUTH_TYPE"));
        assert_eq!(m["REMOTE[USER]"], "admin");
        assert_eq!(m["my.flag"], "1");
        assert_eq!(m["WF_NOINDEX_PATH"], "1");
    }

    #[test]
    fn pipeline_internal_env_reaches_the_app() {
        let req = http::Request::builder()
            .method("GET")
            .uri("/")
            .header("Host", "forum.example")
            .body(empty_incoming())
            .unwrap();

        let mut c = ctx(false);
        c.env = vec![
            (CACHE_REFRESH_ENV.into(), "1".into()),
            (AUTH_USER_ENV.into(), "alice".into()),
        ];
        let env = build_cgi_env(&req, &c, Path::new("/web/public_html/index.php"));
        let m: std::collections::HashMap<String, String> = env
            .into_iter()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();

        assert_eq!(m["HJ_CACHE_REFRESH"], "1");
        assert_eq!(m["REMOTE_USER"], "alice");
        assert_eq!(m["AUTH_TYPE"], "Basic");
        assert!(!m.contains_key(AUTH_USER_ENV));
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
        assert_eq!(m["SERVER_PORT"], "8080");
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
        // SERVER_PORT is the listener's port, not the Host header's.
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

    fn forwarding_request() -> Request {
        http::Request::builder()
            .uri("/index.php")
            .header("Host", "forum.example")
            .header("User-Agent", "curl/8")
            .header("CF-Connecting-IP", "198.51.100.9")
            .header("X-Forwarded-For", "198.51.100.9")
            .header("X-Forwarded-Proto", "https")
            .header("X-Forwarded-Host", "evil.example")
            .header("X-Forwarded-Port", "443")
            .header("X-Real-IP", "198.51.100.9")
            .header("True-Client-IP", "198.51.100.9")
            .header("Forwarded", "for=198.51.100.9")
            .body(empty_incoming())
            .unwrap()
    }

    const FORWARDING_VARS: &[&str] = &[
        "HTTP_CF_CONNECTING_IP",
        "HTTP_X_FORWARDED_FOR",
        "HTTP_X_FORWARDED_PROTO",
        "HTTP_X_FORWARDED_HOST",
        "HTTP_X_FORWARDED_PORT",
        "HTTP_X_REAL_IP",
        "HTTP_TRUE_CLIENT_IP",
        "HTTP_FORWARDED",
    ];

    #[test]
    fn untrusted_peer_forwarding_headers_never_reach_the_cgi_env() {
        let req = forwarding_request();
        let mut c = ctx(true);
        c.forwarding_trusted = false;
        let env = build_cgi_env(&req, &c, Path::new("/web/public_html/index.php"));
        for var in FORWARDING_VARS {
            assert!(
                !env.iter().any(|(k, _)| k.as_ref() == *var),
                "{var} must not reach PHP from an untrusted peer"
            );
        }
        assert!(env.iter().any(|(k, _)| k.as_ref() == "HTTP_USER_AGENT"));
        let remote = env.iter().find(|(k, _)| k.as_ref() == "REMOTE_ADDR");
        assert_eq!(
            remote.map(|(_, v)| v.as_ref()),
            Some(c.client_ip.to_string().as_str())
        );
    }

    #[test]
    fn trusted_peer_forwarding_headers_reach_the_cgi_env() {
        let req = forwarding_request();
        let c = ctx(true);
        assert!(c.forwarding_trusted);
        let env = build_cgi_env(&req, &c, Path::new("/web/public_html/index.php"));
        for var in FORWARDING_VARS {
            assert!(
                env.iter().any(|(k, _)| k.as_ref() == *var),
                "{var} from a trusted proxy reaches PHP"
            );
        }
    }

    #[test]
    fn header_forwardable_is_one_rule_for_both_lsapi_feeds() {
        for (name, trusted, expected) in [
            ("proxy", true, false),
            ("Proxy", false, false),
            ("X_Real_Ip", true, false),
            ("x_forwarded_for", true, false),
            ("cf-connecting-ip", true, true),
            ("CF-Connecting-IP", false, false),
            ("forwarded", false, false),
            ("user-agent", false, true),
            ("cookie", false, true),
            ("X.Forwarded.For", true, false),
            ("CF.Connecting.IP", true, false),
            ("User.Agent", false, false),
            ("X-Test2", false, true),
        ] {
            assert_eq!(
                header_forwardable(name, trusted),
                expected,
                "{name} trusted={trusted}"
            );
        }
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
            .header("X.Forwarded.For", "127.0.0.2")
            .header("X.Custom.Auth", "spoofed")
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
        assert_eq!(m["SERVER_PORT"], "8080");
        assert_eq!(m["PHP_VALUE"], "auto_prepend_file=/x/p.php");
    }

    /// Regression (#602): a plaintext client cannot claim SERVER_PORT=443 (and
    /// with it XenForo's isSecure()) by putting `:443` in its Host header.
    #[test]
    fn server_port_comes_from_the_listener_not_host() {
        let req = http::Request::builder()
            .uri("/index.php")
            .header("Host", "tenant.example:443")
            .body(empty_incoming())
            .unwrap();
        let mut c = ctx(false);
        c.local_addr = "192.0.2.1:80".parse().unwrap();
        let m: std::collections::HashMap<String, String> =
            build_cgi_env(&req, &c, Path::new("/srv/www/tenant/index.php"))
                .into_iter()
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect();
        assert_eq!(m["SERVER_PORT"], "80");
        assert_eq!(m["REQUEST_SCHEME"], "http");
        assert!(!m.contains_key("HTTPS"));
        assert_eq!(m["SERVER_NAME"], "tenant.example");

        let req = http::Request::builder()
            .uri("/index.php")
            .header("Host", "tenant.example:8443")
            .body(empty_incoming())
            .unwrap();
        let mut c = ctx(true);
        c.local_addr = "192.0.2.1:443".parse().unwrap();
        let m: std::collections::HashMap<String, String> =
            build_cgi_env(&req, &c, Path::new("/srv/www/tenant/index.php"))
                .into_iter()
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect();
        assert_eq!(m["SERVER_PORT"], "443");
    }

    #[test]
    fn concrete_body_length_is_a_wire_view_only() {
        let req = http::Request::builder()
            .uri("/index.php")
            .header("Host", "tenant.example")
            .header("Content-Length", "malformed")
            .body(empty_incoming())
            .unwrap();
        let c = ctx(false);
        let env = CgiEnvBuilder::new(Path::new("/srv/www/tenant/index.php"))
            .build_with_content_length(&req, &c, Some("3"));
        let m: std::collections::HashMap<String, String> = env
            .into_iter()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert_eq!(m["CONTENT_LENGTH"], "3");
        assert_eq!(m["HTTP_CONTENT_LENGTH"], "3");
        assert_eq!(req.headers()[http::header::CONTENT_LENGTH], "malformed");
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
