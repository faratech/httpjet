//! The [`RewriteInput`] passed into [`crate::evaluate`]: everything a rule or
//! condition needs to read about the current request, plus the filesystem
//! `stat` hook used by the `-f`/`-d`/`-l`/`-s` tests.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fs::Metadata;
use std::path::{Path, PathBuf};

/// Result of `stat`-ing a candidate `%{REQUEST_FILENAME}`.
///
/// Either supply a live `stat` closure (the production path) or precompute the
/// boolean file tests (handy for tests and for callers that already stat'd).
#[derive(Clone, Copy, Default, Debug)]
pub struct FileTests {
    /// `-f`: exists and is a regular file.
    pub is_file: bool,
    /// `-d`: exists and is a directory.
    pub is_dir: bool,
    /// `-l`: exists and is a symbolic link.
    pub is_link: bool,
    /// `-s`: exists and has size > 0.
    pub is_nonempty: bool,
}

impl FileTests {
    /// Derive the four tests from a `Metadata` (uses `symlink_metadata` semantics
    /// for `-l` if the caller passes a `symlink_metadata` result).
    pub fn from_metadata(md: &Metadata) -> Self {
        FileTests {
            is_file: md.is_file(),
            is_dir: md.is_dir(),
            is_link: md.file_type().is_symlink(),
            is_nonempty: md.len() > 0,
        }
    }
}

/// How the engine learns about the filesystem for `%{REQUEST_FILENAME}` tests.
pub enum StatSource<'a> {
    /// Call this closure with the absolute candidate path. Returns `None` if the
    /// path does not exist. The engine derives `-f/-d/-l/-s` from the result.
    Live(&'a dyn Fn(&Path) -> Option<Metadata>),
    /// Like [`StatSource::Live`] but the closure returns the derived
    /// [`FileTests`] directly. Lets callers cache the cheap boolean result
    /// (a `Metadata` is not storable) behind a TTL so repeated `-f`/`-d`
    /// tests for the same path on the hot path skip the `statx`. `None`
    /// means the path does not exist.
    LiveTests(&'a dyn Fn(&Path) -> Option<FileTests>),
    /// Precomputed tests for the *current* `request_filename`.
    Precomputed(FileTests),
    /// No filesystem available — every test is false.
    None,
}

impl std::fmt::Debug for StatSource<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StatSource::Live(_) => f.write_str("StatSource::Live(<fn>)"),
            StatSource::LiveTests(_) => f.write_str("StatSource::LiveTests(<fn>)"),
            StatSource::Precomputed(t) => f.debug_tuple("Precomputed").field(t).finish(),
            StatSource::None => f.write_str("StatSource::None"),
        }
    }
}

/// Lazy request-header source: given a header name, return its value (the engine
/// never copies the full header set up front on the hot path). Wrapped in a
/// newtype so [`RewriteInput`] can keep `#[derive(Debug)]`. The callback MUST
/// reproduce the eager-path semantics: case-insensitive name match, and on a
/// duplicate header name the LAST decodable value wins (see `pipeline::do_rewrite`).
#[derive(Clone, Copy)]
pub struct HeaderLookup<'a>(pub &'a dyn Fn(&str) -> Option<String>);

impl std::fmt::Debug for HeaderLookup<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HeaderLookup(<fn>)")
    }
}

/// Everything the rewrite engine reads about the current request.
///
/// `uri` is the *path* portion the engine operates on (it is what `$0`/the rule
/// pattern matches against, minus any `RewriteBase`). `query` is the current
/// query string (no leading `?`). Header names are matched case-insensitively.
#[derive(Debug)]
pub struct RewriteInput<'a> {
    /// The current request path (percent-decoded, with leading `/`). In a
    /// per-directory (`.htaccess`) context Apache strips the matched directory
    /// prefix before matching `RewriteRule` patterns; callers that want that
    /// behavior should set `per_directory_prefix`.
    pub uri: Cow<'a, str>,
    /// Current query string without the leading `?` (may be empty).
    pub query: Cow<'a, str>,
    /// HTTP method, uppercase (`GET`, `POST`, ...).
    pub method: Cow<'a, str>,
    /// `Host` header value (no scheme, no port unless present in the header).
    pub host: Cow<'a, str>,
    /// Whether the request arrived over TLS (drives `%{HTTPS}`).
    pub https: bool,
    /// Client IP for `%{REMOTE_ADDR}` (the peer address as Apache sees it).
    /// Empty string -> the variable resolves to `""`. The pipeline populates
    /// this from `ReqCtx::client_ip`.
    pub remote_addr: Cow<'a, str>,
    /// Client source port for `%{REMOTE_PORT}`. `None` -> resolves to `""`.
    pub remote_port: Option<u16>,
    /// Server's own IP for `%{SERVER_ADDR}` (the local address the connection
    /// landed on). Empty -> `""`.
    pub server_addr: Cow<'a, str>,
    /// `%{SERVER_NAME}`: the configured canonical vhost name (NOT the `Host`
    /// header). Empty -> falls back to `host` so existing single-vhost configs
    /// keep working.
    pub server_name: Cow<'a, str>,
    /// `%{SERVER_PORT}`: the actual local listening port. `None` -> derived from
    /// `https` (443/80), matching the historic behavior.
    pub server_port: Option<u16>,
    /// `%{SERVER_PROTOCOL}` and the version token of `%{THE_REQUEST}`, e.g.
    /// `HTTP/1.1`, `HTTP/2`, `HTTP/3`. Defaults to `HTTP/1.1` so existing callers
    /// (tests) keep the historic behavior without setting it.
    pub protocol: Cow<'a, str>,
    /// Request headers eagerly supplied via the [`RewriteInput::header`] builder
    /// (used by tests and any caller that pre-populates them). On the production
    /// hot path this stays EMPTY and headers are resolved lazily via
    /// `header_lookup` instead, avoiding a per-request copy of the whole header set.
    pub headers: BTreeMap<String, String>,
    /// Lazy header source, consulted by [`RewriteInput::get_header`] when the
    /// eager `headers` map does not contain the name. `None` -> only the eager map
    /// is used (the test/builder path).
    pub header_lookup: Option<HeaderLookup<'a>>,
    /// The vhost document root; `%{REQUEST_FILENAME}` defaults to
    /// `docroot + uri` when no explicit filename is supplied.
    pub docroot: PathBuf,
    /// Filesystem hook for `-f/-d/-l/-s`.
    pub stat: StatSource<'a>,
    /// Pre-seeded environment (e.g. `%{ENV:REDIRECT_STATUS}`); the engine adds
    /// `[E=...]` sets on top. `%{HTTPS}` etc. are *not* stored here.
    pub env: BTreeMap<String, String>,
    /// Borrowed env seed for the hot path: the pipeline points this directly at the
    /// request's `ctx.env` instead of cloning every entry into `env` per request.
    /// Env reads (`%{ENV:NAME}` / bare `%{NAME}`) consult the `[E=]` overlay, then
    /// the owned `env`, then this borrowed seed. Tests populate the owned `env` and
    /// leave this `None`; on the hot path `env` is empty and this is `Some(&ctx.env)`
    /// — the two are never both populated, so precedence is unambiguous. A slice
    /// (not a map) because the pipeline's `ctx.env` is a key-deduped `Vec`, so an
    /// `iter().find()` is an exact-key lookup equivalent to the old `BTreeMap::get`.
    pub env_seed: Option<&'a [(String, String)]>,
    /// In a per-directory context, the path prefix (relative to docroot,
    /// no leading slash) that Apache strips before matching rule patterns.
    /// `None` for server/vhost-level rules. Example: rules from
    /// `/web/app/sub/.htaccess` with docroot `/web/app` -> `Some("sub/")`.
    pub per_directory_prefix: Option<String>,
}

impl<'a> RewriteInput<'a> {
    /// Convenience constructor with sane defaults: GET, no TLS, no headers,
    /// empty query, no filesystem.
    pub fn new(uri: impl Into<Cow<'a, str>>, docroot: impl Into<PathBuf>) -> Self {
        RewriteInput {
            uri: uri.into(),
            query: Cow::Borrowed(""),
            method: Cow::Borrowed("GET"),
            host: Cow::Borrowed(""),
            https: false,
            remote_addr: Cow::Borrowed(""),
            remote_port: None,
            server_addr: Cow::Borrowed(""),
            server_name: Cow::Borrowed(""),
            server_port: None,
            protocol: Cow::Borrowed("HTTP/1.1"),
            headers: BTreeMap::new(),
            header_lookup: None,
            docroot: docroot.into(),
            stat: StatSource::None,
            env: BTreeMap::new(),
            env_seed: None,
            per_directory_prefix: None,
        }
    }

    /// Builder: set the method.
    pub fn method(mut self, m: impl Into<Cow<'a, str>>) -> Self {
        let m = m.into();
        // Avoid an allocation when the method is already uppercase (the common case —
        // `http::Method` is canonical-uppercase); only own a copy if it must be folded.
        self.method = if m.bytes().any(|b| b.is_ascii_lowercase()) {
            Cow::Owned(m.to_ascii_uppercase())
        } else {
            m
        };
        self
    }
    /// Builder: set the host.
    pub fn host(mut self, h: impl Into<Cow<'a, str>>) -> Self {
        self.host = h.into();
        self
    }
    /// Builder: set the TLS flag.
    pub fn https(mut self, on: bool) -> Self {
        self.https = on;
        self
    }
    /// Builder: set `%{REMOTE_ADDR}` (client IP).
    pub fn remote_addr(mut self, ip: impl Into<Cow<'a, str>>) -> Self {
        self.remote_addr = ip.into();
        self
    }
    /// Builder: set `%{REMOTE_PORT}` (client source port).
    pub fn remote_port(mut self, port: u16) -> Self {
        self.remote_port = Some(port);
        self
    }
    /// Builder: set `%{SERVER_ADDR}` (the local/server IP).
    pub fn server_addr(mut self, ip: impl Into<Cow<'a, str>>) -> Self {
        self.server_addr = ip.into();
        self
    }
    /// Builder: set `%{SERVER_NAME}` (canonical vhost name).
    pub fn server_name(mut self, name: impl Into<Cow<'a, str>>) -> Self {
        self.server_name = name.into();
        self
    }
    /// Builder: set `%{SERVER_PORT}` (actual local listening port).
    pub fn server_port(mut self, port: u16) -> Self {
        self.server_port = Some(port);
        self
    }
    /// Builder: set `%{SERVER_PROTOCOL}` / the `THE_REQUEST` version token
    /// (`HTTP/1.1`, `HTTP/2`, `HTTP/3`).
    pub fn protocol(mut self, p: impl Into<Cow<'a, str>>) -> Self {
        self.protocol = p.into();
        self
    }
    /// Builder: set the query string (no leading `?`).
    pub fn query(mut self, q: impl Into<Cow<'a, str>>) -> Self {
        self.query = q.into();
        self
    }
    /// Builder: add a request header.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers
            .insert(normalize_header(&name.into()), value.into());
        self
    }
    /// Builder: install precomputed file tests.
    pub fn file_tests(mut self, t: FileTests) -> Self {
        self.stat = StatSource::Precomputed(t);
        self
    }

    /// Case-insensitive header lookup. The eager `headers` map (if populated)
    /// takes precedence; otherwise the lazy `header_lookup` callback is consulted.
    /// Returns `Cow::Borrowed` for an eager hit (zero alloc) and `Cow::Owned` for
    /// a lazy hit.
    pub fn get_header(&self, name: &str) -> Option<Cow<'_, str>> {
        // On the production (lazy) path `headers` is empty and `header_lookup` does
        // its own case-insensitive match, so skip building the normalized lookup key
        // (a per-read String alloc) — `.get()` on an empty map is always `None`.
        if !self.headers.is_empty() {
            if let Some(v) = self.headers.get(&normalize_header(name)) {
                return Some(Cow::Borrowed(v.as_str()));
            }
        }
        if let Some(hl) = &self.header_lookup {
            return (hl.0)(name).map(Cow::Owned);
        }
        None
    }
}

/// Header names are stored normalized to `Title-Case` so `%{HTTP:accept}` and
/// `%{HTTP:Accept}` resolve identically.
pub(crate) fn normalize_header(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut at_start = true;
    for ch in name.chars() {
        if ch == '-' {
            out.push('-');
            at_start = true;
        } else if at_start {
            out.extend(ch.to_uppercase());
            at_start = false;
        } else {
            out.extend(ch.to_lowercase());
        }
    }
    out
}
