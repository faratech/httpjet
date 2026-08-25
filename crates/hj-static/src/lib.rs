//! Static file serving handler for httpjet.
//!
//! [`StaticFiles`] implements [`hj_core::Handler`] and serves files from a
//! virtual host's document root. It is a zero-field unit struct: everything it
//! needs (`doc_root`, `index_files`, `allow_symbol_link`, the MIME map and ETag
//! convention) is read from [`hj_core::ReqCtx`] at request time, so a single
//! instance can serve every vhost.
//!
//! # Safety / traversal
//!
//! Path resolution is done with Linux `openat2(2)` using `RESOLVE_BENEATH`
//! (via [`rustix`]), so a request can never escape the document root via `..`
//! or an absolute path. When `allow_symbol_link` is `false` we additionally
//! pass `RESOLVE_NO_SYMLINKS`. If `openat2` is unavailable on this kernel or
//! filesystem (`ENOSYS`/`EOPNOTSUPP`) while symlinks are disallowed, we **fail
//! closed** (404) rather than degrading to `openat(O_NOFOLLOW)`, which only
//! guards the final path component and would let an intermediate in-docroot
//! symlink escape the tree.
//!
//! # Responses
//!
//! A successful hit yields `Body::File(FileBody { path, len, range, cached:None })`
//! with these headers set:
//!   - `Content-Type` from `ctx.server.mime.content_type(ext)`
//!     (default `application/octet-stream`),
//!   - `Content-Length`,
//!   - `Last-Modified` (RFC 1123 / `httpdate`),
//!   - `Accept-Ranges: bytes`,
//!   - `ETag`.
//!
//! ## ETag format
//!
//! LiteSpeed builds the ETag from the `fileETag` bitmask (server `<fileETag>`),
//! where the bits are `INode=4`, `MTime=8`, `Size=16` (OLS
//! `httpcontext.h` / `staticfilecachedata.cpp::buildFixedHeaders`). The live
//! config sets `fileETag=28`, which is `Size | MTime | INode` — **all three**
//! components enabled (not "Size|MTime" as older comments claimed).
//!
//! The validator is a **strong** ETag laid out as:
//!
//! ```text
//! "<size-hex>-<mtime-hex>-<inode-hex>;;;"
//! ```
//!
//! Components are emitted in the fixed order Size, MTime, INode — each only if
//! its bit is set — joined by `-`, each formatted with C `%lx` (lowercase hex,
//! no leading zeros). A literal `;;;` is appended *inside* the quotes; those are
//! three empty variant slots LiteSpeed reserves for compression/charset markers
//! (e.g. `;gz`, `;br`). `<mtime>` is whole seconds since the Unix epoch and
//! `<inode>` is the file's `st_ino`. An empty bitmask emits no `ETag` header.
//! This byte-matches the deployed server's `"4a-69b4b394-4db094e9ecec531e;;;"`.
//!
//! # Conditional & range requests
//!
//!   - `If-None-Match` / `If-Modified-Since` → `304 Not Modified` (no body).
//!   - `Range: bytes=` (single range) → `206 Partial Content` with
//!     `Content-Range` and `FileBody.range` set; multi-range is not split and
//!     falls back to a full `200`.
//!   - Unsatisfiable range → `416 Range Not Satisfiable` with `Content-Range:
//!     bytes */<len>`.
//!   - `If-Range` gates the range: if it does not match the current validator
//!     the full entity is returned (`200`).

use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use dashmap::DashMap;
use http::header::{
    ACCEPT_RANGES, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, ETAG, IF_MATCH, IF_MODIFIED_SINCE,
    IF_NONE_MATCH, IF_RANGE, IF_UNMODIFIED_SINCE, LAST_MODIFIED, LOCATION, RANGE,
};
use http::{HeaderValue, Method, Request, Response, StatusCode};

use hj_core::{Body, FileBody, Handler, HandlerError, ReqCtx};
use rustix::fs::{Mode, OFlags, ResolveFlags};

/// Default content type when the MIME map has no entry for the suffix.
const DEFAULT_CONTENT_TYPE: &str = "application/octet-stream";

// LiteSpeed `fileETag` bitmask bits (OLS `http/httpcontext.h`):
//   ETAG_INODE = 4, ETAG_MTIME = 8, ETAG_SIZE = 16.
// The deployed default `fileETag=28` is SIZE|MTIME|INODE (all three).
const ETAG_INODE: u32 = 4;
const ETAG_MTIME: u32 = 8;
const ETAG_SIZE: u32 = 16;
const ETAG_ALL: u32 = ETAG_INODE | ETAG_MTIME | ETAG_SIZE;

/// Bounded caps for the per-file header caches. Inserts are cap-gated (mirroring
/// `StatCache`/`HtaccessCache`): once full, cold entries simply aren't cached, so
/// memory is bounded without an eviction sweep.
const META_CACHE_CAP: usize = 16_384;
const CT_CACHE_CAP: usize = 1_024;

/// Path-resolution cache cap + freshness window. A successful directory→file
/// resolution (the `open_beneath`/`fstat`/`close` sequence — ~8.5% of CPU on a
/// hot static path under load) is memoized for this short window. A memo hit
/// performs one pathname metadata check so an atomic replacement cannot combine
/// stale validators with current bytes, but still avoids reopening the full
/// resolution chain. The TTL bounds how long an unchanged identity stays memoized.
const RESOLVE_CACHE_CAP: usize = 16_384;
const RESOLVE_TTL: Duration = Duration::from_secs(1);

/// Identity of a file *version* that determines its cacheable static headers:
/// ETag (size/mtime/inode under the `fileETag` mask), Last-Modified (mtime), and
/// Content-Length (size). Content-Type depends on the extension, so it is cached
/// separately (keeps hardlinks with differing extensions correct).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct MetaKey {
    inode: u64,
    len: u64,
    mtime_secs: u64,
    file_etag: u32,
}

/// Pre-built static response headers for a file version. Cheap `HeaderValue`
/// clones replace per-request date formatting, hex-ETag building, and
/// `HeaderValue` validation.
struct CachedMeta {
    etag: Option<HeaderValue>,
    last_modified: HeaderValue,
    content_length: HeaderValue,
}

#[derive(Default)]
struct HdrCache {
    /// File-version -> (ETag, Last-Modified, Content-Length).
    meta: DashMap<MetaKey, Arc<CachedMeta>>,
    /// Extension -> Content-Type (only used on the charset-off path, where the
    /// value depends solely on the extension; `mime` is server-global).
    ct: DashMap<Box<str>, HeaderValue>,
    /// (doc_root, rel, wants_dir) hash -> the resolved file, TTL-coalesced.
    /// Keyed by a hash with the originating (root, rel, wants_dir) stored in the
    /// entry for a collision guard (a hash clash degrades to a re-resolve, never
    /// wrong content). See [`RESOLVE_TTL`].
    resolve: DashMap<u64, Arc<ResolveEntry>>,
    /// Approximate entry counts for the cap gates — `DashMap::len()` sweeps every
    /// shard, and a full map paid that sweep on every uncached request. Entries
    /// are never removed, so counters bumped on new-key insert are exact up to
    /// insert races.
    meta_count: AtomicUsize,
    ct_count: AtomicUsize,
    resolve_count: AtomicUsize,
}

/// A memoized successful path resolution and its freshness deadline. The stored
/// (root, rel, wants_dir, allow_symlink) are the collision guard for the hashed
/// key — `index_files` also feeds the hash (it can change a directory→index
/// resolution) but is not compared, as a hash clash on it is astronomically
/// unlikely and still degrades to a re-resolve, never to wrong content.
struct ResolveEntry {
    root: PathBuf,
    rel: PathBuf,
    wants_dir: bool,
    allow_symlink: bool,
    file: ResolvedFile,
    expires: Instant,
}

/// Static-file handler with a small bounded per-file header cache. Construct
/// with [`StaticFiles::new`].
///
/// Reads `doc_root`, `index_files` and `allow_symbol_link` from `ctx.vhost`
/// (falling back to `ctx.server.index_files`) per request, so a single shared
/// instance serves all virtual hosts. The header cache is shared across vhosts —
/// safe because the cached values depend only on file identity / extension, not
/// on the vhost.
#[derive(Clone, Default)]
pub struct StaticFiles {
    hdr: Arc<HdrCache>,
}

impl StaticFiles {
    /// Create a new static-file handler.
    pub fn new() -> Self {
        StaticFiles::default()
    }

    /// Pre-built (ETag, Last-Modified, Content-Length) for a file version,
    /// formatted once per version and cloned thereafter. Byte-identical to the
    /// uncached path: it calls the same [`ResolvedFile::etag`] + `httpdate`
    /// formatting.
    fn meta_for(&self, key: MetaKey, resolved: &ResolvedFile) -> Arc<CachedMeta> {
        if let Some(v) = self.hdr.meta.get(&key) {
            return v.clone();
        }
        let etag = resolved
            .etag(key.file_etag)
            .and_then(|s| HeaderValue::from_str(&s).ok());
        let last_modified = HeaderValue::from_str(&httpdate::fmt_http_date(resolved.mtime))
            .unwrap_or_else(|_| HeaderValue::from_static(""));
        let content_length = HeaderValue::from_str(&resolved.len.to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("0"));
        let built = Arc::new(CachedMeta {
            etag,
            last_modified,
            content_length,
        });
        if self.hdr.meta_count.load(Ordering::Relaxed) < META_CACHE_CAP {
            if self.hdr.meta.insert(key, built.clone()).is_none() {
                self.hdr.meta_count.fetch_add(1, Ordering::Relaxed);
            }
        }
        built
    }

    /// Content-Type `HeaderValue` for `ext`. On the charset-off path (the
    /// deployed default) the value depends only on the extension and is cached;
    /// when a default charset is configured the value is rebuilt per request
    /// (it then depends on more than the extension).
    fn content_type_for(
        &self,
        ctx: &ReqCtx,
        ext: &str,
        default_charset: Option<&str>,
    ) -> HeaderValue {
        let charset_off = default_charset.is_none();
        if charset_off {
            if let Some(v) = self.hdr.ct.get(ext) {
                return v.clone();
            }
        }
        let mime = ctx
            .server
            .mime
            .content_type(ext)
            .unwrap_or(DEFAULT_CONTENT_TYPE);
        let hv = if let Some(charset) = default_charset {
            let mut ct = mime.to_string();
            if needs_charset(&ct) {
                ct.push_str("; charset=");
                ct.push_str(charset);
            }
            HeaderValue::from_str(&ct)
        } else {
            HeaderValue::from_str(mime)
        }
        .unwrap_or_else(|_| HeaderValue::from_static(DEFAULT_CONTENT_TYPE));
        if charset_off && self.hdr.ct_count.load(Ordering::Relaxed) < CT_CACHE_CAP {
            if self.hdr.ct.insert(ext.into(), hv.clone()).is_none() {
                self.hdr.ct_count.fetch_add(1, Ordering::Relaxed);
            }
        }
        hv
    }

    /// [`resolve_file`] with a short TTL memo on success, so a file requested
    /// repeatedly within [`RESOLVE_TTL`] skips the `open_beneath`/`fstat`/`close`
    /// chain after a cheap identity check. A changed identity or expired entry
    /// re-runs the safe resolver. Only `File` outcomes are cached;
    /// `DirectorySlash` (a redirect) and errors fall through.
    fn resolve_cached(
        &self,
        doc_root: &Path,
        rel: &Path,
        wants_dir: bool,
        index_files: &[String],
        allow_symlink: bool,
    ) -> Result<Resolved, HandlerError> {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        doc_root.hash(&mut h);
        rel.hash(&mut h);
        wants_dir.hash(&mut h);
        allow_symlink.hash(&mut h);
        index_files.hash(&mut h);
        let key = h.finish();

        let now = Instant::now();
        if allow_symlink {
            if let Some(e) = self.hdr.resolve.get(&key) {
                // Collision guard: serve the memo only when the originating identity
                // matches exactly and the pathname still resolves to the same file
                // version. The identity check keeps validators/body length coherent
                // across atomic deploy replacements inside the memo TTL.
                if e.expires > now
                    && e.wants_dir == wants_dir
                    && e.allow_symlink == allow_symlink
                    && e.root == doc_root
                    && e.rel == rel
                    && e.file.is_current()
                {
                    return Ok(Resolved::File(e.file.clone()));
                }
            }
        }
        let resolved = resolve_file(doc_root, rel, wants_dir, index_files, allow_symlink)?;
        if allow_symlink {
            if let Resolved::File(ref f) = resolved {
                // Cap-gated like the header caches, but always allow refreshing an
                // existing (now-expired) key so a hot entry keeps its memo when full.
                if self.hdr.resolve_count.load(Ordering::Relaxed) < RESOLVE_CACHE_CAP
                    || self.hdr.resolve.contains_key(&key)
                {
                    let prev = self.hdr.resolve.insert(
                        key,
                        Arc::new(ResolveEntry {
                            root: doc_root.to_path_buf(),
                            rel: rel.to_path_buf(),
                            wants_dir,
                            allow_symlink,
                            file: f.clone(),
                            expires: now + RESOLVE_TTL,
                        }),
                    );
                    if prev.is_none() {
                        self.hdr.resolve_count.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
        Ok(resolved)
    }
}

/// Metadata about a resolved, openable regular file.
#[derive(Clone)]
struct ResolvedFile {
    /// Absolute path on disk (doc_root joined with the cleaned request path).
    path: PathBuf,
    len: u64,
    mtime: SystemTime,
    /// `st_ino` of the resolved file; used for the INode component of the ETag.
    inode: u64,
    dev: u64,
    /// Canonical path of the exact fd opened during resolution. This is used by
    /// `accessDenyDir` and the transport; `path` remains the lexical identity for
    /// URI-derived metadata and resolve-memo revalidation.
    resolved_path: PathBuf,
}

impl ResolvedFile {
    fn is_current(&self) -> bool {
        std::fs::metadata(&self.path).is_ok_and(|meta| {
            meta.is_file()
                && meta.len() == self.len
                && meta.ino() == self.inode
                && meta.dev() == self.dev
                && meta.modified().unwrap_or(UNIX_EPOCH) == self.mtime
        })
    }

    /// Build the ETag string for a given LiteSpeed `fileETag` bitmask, byte-for-byte
    /// matching OLS `StaticFileCacheData::buildFixedHeaders`.
    ///
    /// Components are emitted in the fixed order **Size, MTime, INode**, each only
    /// when its bit is set, joined by `-`, each formatted as C `%lx` (lowercase
    /// hex, no leading zeros). A literal `;;;` (three empty variant slots) is then
    /// appended inside the quotes. Returns `None` when no component bit is set
    /// (`fileETag` resolves to NONE), meaning no `ETag` header should be emitted.
    ///
    /// Example: `fileETag=28` (Size|MTime|INode) with size `0x4a`, mtime
    /// `0x69b4b394`, inode `0x4db094e9ecec531e` yields
    /// `"4a-69b4b394-4db094e9ecec531e;;;"`.
    fn etag(&self, file_etag: u32) -> Option<String> {
        let bits = file_etag & ETAG_ALL;
        if bits == 0 {
            return None;
        }
        let secs = self
            .mtime
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let mut s = String::with_capacity(40);
        s.push('"');
        let mut first = true;
        let mut push_part = |val: u64, s: &mut String| {
            if first {
                first = false;
            } else {
                s.push('-');
            }
            // C `%lx`: lowercase hex, no leading zeros, "0" for zero.
            s.push_str(&format!("{:x}", val));
        };
        if bits & ETAG_SIZE != 0 {
            push_part(self.len, &mut s);
        }
        if bits & ETAG_MTIME != 0 {
            push_part(secs, &mut s);
        }
        if bits & ETAG_INODE != 0 {
            push_part(self.inode, &mut s);
        }
        // Trailing three empty variant markers (compression/charset slots).
        s.push_str(";;;");
        s.push('"');
        Some(s)
    }
}

/// Decide whether a charset suffix should be appended to `Content-Type`,
/// mirroring OLS `HttpMime::needCharset`: `text/*` always, plus
/// `application/{javascript,x-javascript,json}` (subtype matched
/// case-insensitively).
fn needs_charset(mime: &str) -> bool {
    let bytes = mime.as_bytes();
    match bytes.first() {
        Some(b't') => mime.starts_with("text/"),
        Some(b'a') => {
            if let Some(sub) = mime.strip_prefix("application/") {
                let sub = sub.to_ascii_lowercase();
                sub.starts_with("x-javascript")
                    || sub.starts_with("javascript")
                    || sub.starts_with("json")
            } else {
                false
            }
        }
        _ => false,
    }
}

/// Request extension selecting the effective static-context default charset.
/// Absence means `addDefaultCharset off`.
#[derive(Clone)]
pub struct DefaultCharsetOverride(pub String);

/// Canonical filesystem target selected by the static resolver. The pipeline
/// consumes this response extension for `accessDenyDir` parity.
#[derive(Clone, Debug)]
pub struct ResolvedTargetPath(pub PathBuf);

/// Request extension that overrides the document root the [`StaticFiles`] handler
/// resolves against, for a static `<context>` whose `location` differs from the
/// vhost docroot (LiteSpeed parity — e.g. a hybrid-docroot context). Set by the
/// pipeline before dispatch; absent ⇒ the vhost docroot is used as before.
#[derive(Clone)]
pub struct DocRootOverride(pub std::path::PathBuf);

/// Request extension that overrides the directory-index file list for this
/// request, after `.htaccess` `DirectoryIndex` resolution.
#[derive(Clone)]
pub struct IndexFilesOverride(pub Vec<String>);

#[async_trait]
impl Handler for StaticFiles {
    async fn handle(
        &self,
        ctx: &mut ReqCtx,
        req: Request<hj_core::IncomingBody>,
    ) -> Result<Response<Body>, HandlerError> {
        // Only GET/HEAD are servable as static content. Anything else is the
        // pipeline's concern (e.g. POST to a script handler); we 405 here so a
        // mistaken static route doesn't silently swallow the method.
        let is_head = req.method() == Method::HEAD;
        if !is_head && req.method() != Method::GET {
            let mut resp =
                hj_core::text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
            resp.headers_mut()
                .insert(http::header::ALLOW, HeaderValue::from_static("GET, HEAD"));
            return Ok(resp);
        }

        // A static <context> with a `location` differing from the vhost docroot
        // pins it here via the DocRootOverride extension (set by the pipeline);
        // otherwise resolve against the vhost docroot.
        let doc_root = match req.extensions().get::<DocRootOverride>() {
            Some(o) => o.0.clone(),
            None => ctx.vhost.doc_root.clone(),
        };
        let allow_symlink = ctx.vhost.allow_symbol_link;

        // Decode and clean the request path into doc_root-relative components.
        let rel = clean_request_path(req.uri().path()).ok_or(HandlerError::Forbidden)?;
        let wants_dir = req.uri().path().ends_with('/');

        // Resolve to a concrete regular file (handling directory -> index).
        // Borrow the index list (lives as long as `ctx`) instead of cloning the Vec<String>
        // on every static request — resolve_cached takes a slice.
        let index_files: &[String] = match req.extensions().get::<IndexFilesOverride>() {
            Some(o) => &o.0,
            None if ctx.vhost.index_files.is_empty() => &ctx.server.index_files,
            None => &ctx.vhost.index_files,
        };

        let resolved =
            match self.resolve_cached(&doc_root, &rel, wants_dir, index_files, allow_symlink)? {
                Resolved::File(f) => f,
                // DirectorySlash: the request maps to an existing directory but has
                // no trailing slash → 301 to the canonical slashed URL (Apache
                // mod_dir / LiteSpeed redirectDir). Done across the board so a bare
                // /dir never serves un-canonicalized or, behind a front-controller
                // `!-d` rule, gets routed into the app and 404s.
                Resolved::DirectorySlash(path) => {
                    return Ok(with_resolved_target(
                        directory_slash_redirect(req.uri()),
                        path,
                    ));
                }
            };
        let resolved_target = resolved.resolved_path.clone();

        // Static response headers are formatted once per file version / extension
        // and cached, then cloned per request — byte-identical to building them
        // inline. Content-Type depends on the extension; ETag / Last-Modified /
        // Content-Length on the file version. (AddDefaultCharset handling lives in
        // `content_type_for`; the deployed config is `addDefaultCharset off`.)
        let ext = resolved
            .path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
        let default_charset = req
            .extensions()
            .get::<DefaultCharsetOverride>()
            .map(|c| c.0.as_str());
        let content_type = self.content_type_for(ctx, ext, default_charset);

        // ETag from the server's fileETag bitmask (default 28 = Size|MTime|INode).
        // `meta.etag` is `None` when the bitmask is NONE (no ETag header emitted).
        let file_etag = ctx.server.tuning.file_etag;
        let mtime_secs = resolved
            .mtime
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        let meta = self.meta_for(
            MetaKey {
                inode: resolved.inode,
                len: resolved.len,
                mtime_secs,
                file_etag,
            },
            &resolved,
        );
        let etag_str = meta.etag.as_ref().and_then(|h| h.to_str().ok());

        // ---- Conditional requests (RFC 7232) -----------------------------
        let precondition_failed = if let Some(if_match) = req.headers().get(IF_MATCH) {
            !if_match_passes(if_match, etag_str)
        } else if let Some(ius) = req.headers().get(IF_UNMODIFIED_SINCE) {
            !if_unmodified_since_passes(ius, resolved.mtime)
        } else {
            false
        };
        if precondition_failed {
            let mut resp = Response::new(Body::Empty);
            *resp.status_mut() = StatusCode::PRECONDITION_FAILED;
            resp.headers_mut()
                .insert(CONTENT_LENGTH, HeaderValue::from_static("0"));
            return Ok(with_resolved_target(resp, resolved_target));
        }

        // If-None-Match takes precedence over If-Modified-Since. The wildcard tests
        // representation existence, so it remains meaningful when ETags are disabled.
        let not_modified = if let Some(inm) = req.headers().get(IF_NONE_MATCH) {
            inm.to_str().is_ok_and(|s| s.trim() == "*")
                || etag_str.is_some_and(|e| if_none_match_matches(inm.as_bytes(), e))
        } else if let Some(ims) = req.headers().get(IF_MODIFIED_SINCE) {
            if_modified_since_not_modified(ims, resolved.mtime)
        } else {
            false
        };

        if not_modified {
            let mut resp = Response::new(Body::Empty);
            *resp.status_mut() = StatusCode::NOT_MODIFIED;
            let h = resp.headers_mut();
            if let Some(ref e) = meta.etag {
                h.insert(ETAG, e.clone());
            }
            h.insert(LAST_MODIFIED, meta.last_modified.clone());
            h.insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
            h.insert(CONTENT_TYPE, content_type.clone());
            return Ok(with_resolved_target(resp, resolved_target));
        }

        // ---- Range handling (RFC 7233) -----------------------------------
        // If-Range: only honor Range if the validator still matches. A bare
        // date If-Range can still match even without an ETag.
        let honor_range = match req.headers().get(IF_RANGE) {
            None => true,
            Some(ir) => if_range_matches(ir, etag_str, resolved.mtime),
        };

        let range = if !is_head && honor_range {
            req.headers().get(RANGE)
        } else {
            None
        };

        // (#10) When symlinks are disallowed, serve from bytes read through a fresh symlink-safe
        // open instead of letting the transport re-open the (followable) path — closing the
        // resolve→serve TOCTOU. Read once here and reuse for the range and full bodies via
        // FileBody.cached (which the transports serve range-aware). HEAD has no body. allow_symlink
        // is true for every prod vhost, so this is inert in prod.
        let verified_cached: Option<bytes::Bytes> = if !allow_symlink && !is_head {
            Some(read_verified_no_symlink(&doc_root, &resolved.path)?)
        } else {
            None
        };

        if let Some(range_val) = range {
            match parse_range(range_val.as_bytes(), resolved.len) {
                RangeOutcome::Single(start, end) => {
                    let body = if is_head {
                        Body::Empty
                    } else {
                        // `cached` carries the WHOLE verified file; the transport applies `range`
                        // via the single-sourced, bounds-clamped FileBody::cached_ranged (the
                        // native-H2 path already did, and the io_uring bridge now does too). Slicing
                        // here instead would double-slice on H2 and could panic if the file shrank
                        // between the resolve stat and the verified read.
                        Body::File(FileBody {
                            path: resolved_target.clone(),
                            file: None,
                            len: resolved.len,
                            range: Some((start, end)),
                            cached: verified_cached.clone(),
                        })
                    };
                    let mut resp = Response::new(body);
                    *resp.status_mut() = StatusCode::PARTIAL_CONTENT;
                    let h = resp.headers_mut();
                    h.insert(CONTENT_TYPE, content_type.clone());
                    h.insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
                    if let Some(ref e) = meta.etag {
                        h.insert(ETAG, e.clone());
                    }
                    h.insert(LAST_MODIFIED, meta.last_modified.clone());
                    let clen = end - start + 1;
                    insert_static(h, CONTENT_LENGTH, &clen.to_string());
                    insert_static(
                        h,
                        CONTENT_RANGE,
                        &format!("bytes {}-{}/{}", start, end, resolved.len),
                    );
                    return Ok(with_resolved_target(resp, resolved_target));
                }
                RangeOutcome::Unsatisfiable => {
                    let mut resp = hj_core::text_response(
                        StatusCode::RANGE_NOT_SATISFIABLE,
                        "requested range not satisfiable",
                    );
                    let h = resp.headers_mut();
                    insert_static(h, CONTENT_RANGE, &format!("bytes */{}", resolved.len));
                    h.insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
                    return Ok(with_resolved_target(resp, resolved_target));
                }
                // Unparseable or multi-range: ignore Range, serve full entity.
                RangeOutcome::Ignore => {}
            }
        }

        // ---- Full 200 response -------------------------------------------
        let body = if is_head {
            Body::Empty
        } else {
            Body::File(FileBody {
                path: resolved_target.clone(),
                file: None,
                len: resolved.len,
                range: None,
                cached: verified_cached,
            })
        };
        let mut resp = Response::new(body);
        *resp.status_mut() = StatusCode::OK;
        let h = resp.headers_mut();
        h.insert(CONTENT_TYPE, content_type.clone());
        h.insert(CONTENT_LENGTH, meta.content_length.clone());
        h.insert(LAST_MODIFIED, meta.last_modified.clone());
        h.insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
        if let Some(ref e) = meta.etag {
            h.insert(ETAG, e.clone());
        }
        Ok(with_resolved_target(resp, resolved_target))
    }
}

fn with_resolved_target(mut resp: Response<Body>, path: PathBuf) -> Response<Body> {
    resp.extensions_mut().insert(ResolvedTargetPath(path));
    resp
}

/// Insert a header from a runtime string, ignoring invalid values (which can
/// only arise from corrupt config / paths, never from the literals above).
fn insert_static(headers: &mut http::HeaderMap, name: http::header::HeaderName, value: &str) {
    if let Ok(v) = HeaderValue::from_str(value) {
        headers.insert(name, v);
    }
}

/// Percent-decode and lexically clean a URL path into a sequence of safe,
/// doc_root-relative components.
///
/// Returns `None` if the path tries to escape the root (a `..` that would pop
/// above the top, or a NUL byte). An empty result (root request) is `Some` of
/// an empty `PathBuf`.
fn clean_request_path(uri_path: &str) -> Option<PathBuf> {
    let decoded = hj_core::percent_decode(uri_path)?;
    // Reject embedded NULs outright.
    if decoded.contains(&0) {
        return None;
    }
    let s = String::from_utf8(decoded).ok()?;

    let mut out: Vec<String> = Vec::new();
    for seg in s.split('/') {
        match seg {
            "" | "." => continue,
            ".." => {
                // Escape attempt if there is nothing to pop.
                out.pop()?;
            }
            other => {
                // Backslashes are not path separators on Linux, but reject any
                // segment that is purely a Windows-style traversal just in case.
                out.push(other.to_string());
            }
        }
    }

    let mut pb = PathBuf::new();
    for seg in out {
        pb.push(seg);
    }
    Some(pb)
}

/// Outcome of resolving a request path beneath the doc root.
enum Resolved {
    /// A concrete regular file to serve.
    File(ResolvedFile),
    /// The path is an existing directory requested WITHOUT a trailing slash.
    /// The caller must 301-redirect to the same path with `/` appended
    /// (DirectorySlash); index resolution happens on the slashed re-request.
    DirectorySlash(PathBuf),
}

/// Open `rel` beneath `doc_root` safely and resolve directories to an index
/// file. Returns a concrete regular file, a [`Resolved::DirectorySlash`] signal
/// for a slashless directory, or an appropriate [`HandlerError`].
fn resolve_file(
    doc_root: &Path,
    rel: &Path,
    wants_dir: bool,
    index_files: &[String],
    allow_symlink: bool,
) -> Result<Resolved, HandlerError> {
    // Open the document root directory once; all lookups are beneath it.
    let root_fd = open_dir(doc_root).map_err(|_| HandlerError::NotFound)?;

    let rel_str = rel.to_string_lossy();
    let rel_open = if rel_str.is_empty() {
        "."
    } else {
        rel_str.as_ref()
    };

    // First, stat the target itself (whether file or directory).
    let (fd, stat) = match open_beneath(&root_fd, rel_open, allow_symlink) {
        Ok(pair) => pair,
        Err(e) => return Err(map_open_err(e)),
    };

    if stat.is_dir() {
        // DirectorySlash (Apache mod_dir / OLS `redirectDir`): a directory
        // requested WITHOUT a trailing slash gets a 301 to add the slash, so
        // the index file and any relative links resolve against the canonical
        // `/dir/` URL. We signal it to the caller (which owns redirect
        // building) rather than serving the index off the bare path — serving
        // it un-canonicalized leaves relative links broken and, when a
        // front-controller `!-d` rule sits in front, lets the bare path fall
        // into the app and 404.
        if !wants_dir {
            let lexical = doc_root.join(rel);
            let resolved = resolved_fd_path(&fd, &lexical).map_err(map_open_err)?;
            return Ok(Resolved::DirectorySlash(resolved));
        }
        // With the trailing slash: serve an index file if one exists; otherwise
        // 404 (no autoindex). This matches OLS `HttpReq` directory handling:
        // with a trailing slash, no index found, and autoindex off, it returns
        // SC_404 (NOT 403). 403 is reserved for EACCES on open/stat, which
        // `map_open_err` already produces.
        for idx in index_files {
            if !safe_index_name(idx) {
                // (#244) Fail closed: skip the entry entirely, never open it.
                continue;
            }
            let child_rel = if rel_str.is_empty() {
                idx.clone()
            } else {
                format!("{}/{}", rel_str.trim_end_matches('/'), idx)
            };
            if let Ok((cfd, cstat)) = open_beneath(&root_fd, &child_rel, allow_symlink) {
                if cstat.is_file() {
                    let abs = doc_root.join(&child_rel);
                    let resolved_path = resolved_fd_path(&cfd, &abs).map_err(map_open_err)?;
                    return Ok(Resolved::File(ResolvedFile {
                        path: abs,
                        len: cstat.len,
                        mtime: cstat.mtime,
                        inode: cstat.inode,
                        dev: cstat.dev,
                        resolved_path,
                    }));
                }
            }
        }
        // Directory with no usable index and no autoindex → 404 (OLS parity).
        return Err(HandlerError::NotFound);
    }

    if !stat.is_file() {
        // Special file (socket, device, fifo): refuse.
        return Err(HandlerError::Forbidden);
    }

    let abs = doc_root.join(rel);
    let resolved_path = resolved_fd_path(&fd, &abs).map_err(map_open_err)?;
    Ok(Resolved::File(ResolvedFile {
        path: abs,
        len: stat.len,
        mtime: stat.mtime,
        inode: stat.inode,
        dev: stat.dev,
        resolved_path,
    }))
}

fn resolved_fd_path(fd: &OwnedFd, lexical: &Path) -> io::Result<PathBuf> {
    let proc_path = PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()));
    std::fs::read_link(proc_path).or_else(|_| std::fs::canonicalize(lexical))
}

/// Read the full bytes of an already-resolved file through a FRESH symlink-safe open beneath
/// `doc_root` (`RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`).
///
/// (#10) For a `followSymbolLink off` vhost the resolve step proves no symlink exists, then drops
/// the verified fd; the transport later re-opens the response BY PATH, which DOES follow symlinks —
/// so a symlink swapped into a path component between resolve and serve would be followed
/// out-of-tree (a TOCTOU the NO_SYMLINKS proof was meant to prevent). Reading the bytes here from a
/// fresh symlink-safe open and handing them to the transport via `FileBody.cached` means the
/// transport never re-opens the followable path. `allow_symlink` is true for every prod vhost, so
/// this is never taken in prod (no hot-path cost).
fn read_verified_no_symlink(
    doc_root: &Path,
    abs_path: &Path,
) -> Result<bytes::Bytes, HandlerError> {
    let rel = abs_path
        .strip_prefix(doc_root)
        .map_err(|_| HandlerError::Forbidden)?;
    let root_fd = open_dir(doc_root).map_err(|_| HandlerError::NotFound)?;
    let rel_str = rel.to_string_lossy();
    let rel_open = if rel_str.is_empty() {
        "."
    } else {
        rel_str.as_ref()
    };
    let (fd, stat) = open_beneath(&root_fd, rel_open, false).map_err(map_open_err)?;
    if !stat.is_file() {
        return Err(HandlerError::Forbidden);
    }
    // This path buffers the WHOLE file into RAM (the symlink-TOCTOU mitigation hands
    // the bytes to the transport via `FileBody.cached` so it never re-opens the
    // followable path). Cap it so a symlink-off vhost can't be made to fault an
    // arbitrarily large file into memory per request. Generous — a static file this
    // large on such a vhost is pathological; everything real fits.
    const MAX_VERIFIED_INMEM: u64 = 512 * 1024 * 1024;
    if stat.len > MAX_VERIFIED_INMEM {
        return Err(HandlerError::PayloadTooLarge);
    }
    let mut file = std::fs::File::from(fd);
    let mut buf = Vec::with_capacity(stat.len as usize);
    std::io::Read::read_to_end(&mut file, &mut buf).map_err(|_| HandlerError::NotFound)?;
    Ok(bytes::Bytes::from(buf))
}

/// Build the DirectorySlash 301: the request path with a trailing `/` appended,
/// preserving the query string. The `Location` is path-absolute (resolved by the
/// client against the request origin) — robust behind Cloudflare and free of any
/// scheme/host guessing. Mirrors Apache mod_dir DirectorySlash / OLS redirectDir.
fn directory_slash_redirect(uri: &http::Uri) -> Response<Body> {
    // Build a CANONICAL, same-origin Location from the request path: split on '/', drop empty
    // ("//") and "." segments, resolve ".." by popping, and re-join with single slashes — then a
    // single leading slash and the trailing slash. Normalizing (not just trimming leading slashes,
    // the old behavior) gives a canonical Location free of redundant `//`/`.`/`..` segments, and
    // the single leading slash means it can never become a protocol-relative `//host` off-origin
    // redirect. Each segment's percent-encoding is preserved VERBATIM (the path came from an
    // already-parsed URI, so no decode/re-encode hazard). We split on BOTH `/` and `\` because a
    // LITERAL backslash IS passed through by the http/httparse parsers (it is NOT rejected — #93);
    // treating `\` as a path separator stops `/\evil.com` from yielding a `/\evil.com/` Location
    // that WHATWG browsers fold to the off-origin `//evil.com/`. `%5C` stays percent-encoded
    // (same-origin) and is untouched. CR/LF/control chars can't appear and are rejected by
    // `HeaderValue::from_str` below regardless.
    let mut segs: Vec<&str> = Vec::new();
    for seg in uri.path().split(['/', '\\']) {
        match seg {
            "" | "." => continue,
            ".." => {
                segs.pop();
            }
            other => segs.push(other),
        }
    }
    let joined = segs.join("/");
    let mut location =
        String::with_capacity(joined.len() + 3 + uri.query().map_or(0, |q| q.len() + 1));
    location.push('/');
    location.push_str(&joined);
    if !joined.is_empty() {
        location.push('/');
    }
    if let Some(q) = uri.query() {
        location.push('?');
        location.push_str(q);
    }
    let mut resp = Response::new(Body::Empty);
    *resp.status_mut() = StatusCode::MOVED_PERMANENTLY;
    let h = resp.headers_mut();
    // The path/query come from an already-parsed URI, so this is valid; if it
    // somehow is not, fall back to a bare 404 rather than a Location-less 301.
    match HeaderValue::from_str(&location) {
        Ok(v) => {
            h.insert(LOCATION, v);
            h.insert(CONTENT_LENGTH, HeaderValue::from_static("0"));
        }
        Err(e) => {
            // (item 7) A directory-slash redirect we can't encode is a routing bug,
            // not a missing file — surface it instead of silently 404ing.
            tracing::warn!(target: "hj_static", %location, error = %e, "could not build redirect Location; serving 404");
            *resp.status_mut() = StatusCode::NOT_FOUND;
        }
    }
    resp
}

/// Lightweight stat result decoupled from the `rustix`/`std` metadata types.
struct MetaInfo {
    len: u64,
    mtime: SystemTime,
    inode: u64,
    dev: u64,
    mode_is_dir: bool,
    mode_is_file: bool,
}

impl MetaInfo {
    fn is_dir(&self) -> bool {
        self.mode_is_dir
    }
    fn is_file(&self) -> bool {
        self.mode_is_file
    }
}

/// Open the document root as a directory fd.
fn open_dir(path: &Path) -> io::Result<OwnedFd> {
    let oflags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
    // CWD-relative open of an absolute path is fine here; this is the root.
    rustix::fs::open(path, oflags, Mode::empty()).map_err(io::Error::from)
}

/// Open `rel` beneath `root_fd`, returning the opened fd and its metadata.
///
/// Two safety regimes, mirroring LiteSpeed's `followSymbolicLink`:
///
///   - `allow_symlink == false`: use `openat2` with
///     `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`, so neither `..` nor any symlink
///     can leave the document root. If `openat2` is unavailable on this kernel
///     *or filesystem* (`ENOSYS`/`EOPNOTSUPP` — overlayfs, some FUSE/NFS), we
///     **fail closed** with `ENOENT` rather than degrading to a single
///     `openat(O_NOFOLLOW)`. `O_NOFOLLOW` only rejects a symlink in the *final*
///     component, so an in-docroot intermediate symlink (`/link_to_etc/passwd`)
///     would traverse out of the tree; refusing to serve is the only safe
///     option when the filesystem cannot enforce `RESOLVE_NO_SYMLINKS`.
///   - `allow_symlink == true`: symlinks may be followed wherever they point
///     (LiteSpeed semantics). We do *not* use `RESOLVE_BENEATH` here, because
///     it rejects every absolute symlink with `EXDEV` even when the target is
///     inside the tree. The request path has already been lexically cleaned of
///     `..`, so the only escape vector is an intentional in-tree symlink, which
///     the operator opted into. A plain `openat` (following symlinks) is used.
/// (#244) A `.htaccess` `DirectoryIndex` entry reaches this module verbatim —
/// it is operator/app-controlled config, NOT the lexically-cleaned request
/// path. An entry like `../../../etc/passwd` formatted into `child_rel` would
/// escape the docroot through [`open_beneath`]'s follow-symlink `openat` arm,
/// whose safety rests on the caller having already cleaned `..` away. Reject
/// any index name that is not a safe root-confined relative path.
///
/// Also consumed by the pipeline's PHP dir-index resolver (`suffix_routing`),
/// which joins the same untrusted tokens onto docroot-relative paths — keep
/// both call sites on this one guard so they can never drift apart.
pub fn safe_index_name(idx: &str) -> bool {
    !idx.is_empty() && !idx.starts_with('/') && !idx.split(['/', '\\']).any(|seg| seg == "..")
}

fn open_beneath(
    root_fd: &OwnedFd,
    rel: &str,
    allow_symlink: bool,
) -> io::Result<(OwnedFd, MetaInfo)> {
    // NONBLOCK: the path components here come from request URLs (or .htaccess
    // config), so an attacker able to plant files in the served tree (e.g. via a
    // PHP write bug) could otherwise park this executor thread FOREVER inside
    // open(2) by naming a FIFO — one stalled thread per request.
    let oflags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK;

    let fd = if allow_symlink {
        // Follow symlinks; lexical cleaning already removed any `..` escape.
        rustix::fs::openat(root_fd, rel, oflags, Mode::empty())?
    } else {
        let resolve = ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS;
        match rustix::fs::openat2(root_fd, rel, oflags, Mode::empty(), resolve) {
            Ok(fd) => fd,
            Err(e) if e == rustix::io::Errno::NOSYS || e == rustix::io::Errno::OPNOTSUPP => {
                // openat2 unsupported by this kernel *or filesystem* (overlayfs /
                // Docker, some FUSE/NFS — even on kernels >=5.6). We must NOT fall
                // back to a single openat(O_NOFOLLOW): it only blocks a symlink in
                // the FINAL component, so an in-docroot intermediate symlink (e.g.
                // `/link_to_etc/passwd`, where `link_to_etc` -> `/etc`) would be
                // traversed and leak files outside the root. With followSymbolLink
                // off, the filesystem can no longer enforce RESOLVE_NO_SYMLINKS, so
                // fail closed (ENOENT -> 404) rather than serving with a weaker
                // guarantee than the operator asked for.
                return Err(io::Error::from(rustix::io::Errno::NOENT));
            }
            Err(e) => return Err(io::Error::from(e)),
        }
    };

    // Use std metadata for portable size/mtime/type extraction.
    let file = File::from(fd);
    let meta = file.metadata()?;
    // The NONBLOCK open above returns instantly whatever the name resolves to;
    // now fstat tells us what that IS. Only plain files/dirs continue — every
    // other type (fifo, socket, device) is refused here rather than at the
    // caller, because holding the fd would keep the kernel object alive.
    if !meta.is_file() && !meta.is_dir() {
        return Err(io::Error::from(rustix::io::Errno::NXIO));
    }
    // Real files must not carry NONBLOCK into serving (device/pipe semantics
    // leaking into the async file path); regular-file reads ignore the flag,
    // but clear it anyway so the fd behaves exactly as before.
    let fl = rustix::fs::fcntl_getfl(&file).map_err(io::Error::from)?;
    rustix::fs::fcntl_setfl(&file, fl.difference(OFlags::NONBLOCK)).map_err(io::Error::from)?;
    let mtime = meta.modified().unwrap_or(UNIX_EPOCH);
    let info = MetaInfo {
        len: meta.len(),
        mtime,
        inode: meta.ino(),
        dev: meta.dev(),
        mode_is_dir: meta.is_dir(),
        mode_is_file: meta.is_file(),
    };
    Ok((OwnedFd::from(file), info))
}

/// Map an open error to a handler error: NotFound for ENOENT, Forbidden for
/// EACCES / escape attempts (EXDEV/ELOOP from RESOLVE_BENEATH), else Io.
fn map_open_err(e: io::Error) -> HandlerError {
    use io::ErrorKind::*;
    match e.kind() {
        NotFound => HandlerError::NotFound,
        PermissionDenied => HandlerError::Forbidden,
        _ => {
            // RESOLVE_BENEATH escape returns EXDEV; NO_SYMLINKS returns ELOOP.
            // Both surface as "Other" io errorkinds across libc versions; treat
            // any directory/loop/xdev style failure as Forbidden, else 404.
            match e.raw_os_error() {
                Some(18) => HandlerError::Forbidden, // EXDEV
                Some(40) => HandlerError::Forbidden, // ELOOP
                Some(13) => HandlerError::Forbidden, // EACCES
                Some(2) => HandlerError::NotFound,   // ENOENT
                _ => HandlerError::NotFound,
            }
        }
    }
}

/// Outcome of parsing a `Range` header.
enum RangeOutcome {
    /// A single satisfiable byte range `[start, end_inclusive]`.
    Single(u64, u64),
    /// Range syntax present but unsatisfiable for this entity → 416.
    Unsatisfiable,
    /// Unparseable, non-bytes unit, or multi-range → ignore and serve 200.
    Ignore,
}

/// Parse a `Range` header value against a known entity length.
///
/// Supports the three single-range forms:
///   - `bytes=START-END`
///   - `bytes=START-`     (to end of file)
///   - `bytes=-SUFFIX`    (last SUFFIX bytes)
///
/// A header with multiple comma-separated ranges is treated as `Ignore` (we do
/// not emit multipart/byteranges); callers then send the full entity.
fn parse_range(value: &[u8], len: u64) -> RangeOutcome {
    let s = match std::str::from_utf8(value) {
        Ok(s) => s.trim(),
        Err(_) => return RangeOutcome::Ignore,
    };
    let spec = match s.strip_prefix("bytes=") {
        Some(rest) => rest.trim(),
        None => return RangeOutcome::Ignore,
    };
    if spec.is_empty() {
        return RangeOutcome::Ignore;
    }
    // Multiple ranges: not supported as a single body.
    if spec.contains(',') {
        return RangeOutcome::Ignore;
    }

    let (start_s, end_s) = match spec.split_once('-') {
        Some(parts) => parts,
        None => return RangeOutcome::Ignore,
    };
    let start_s = start_s.trim();
    let end_s = end_s.trim();

    if start_s.is_empty() {
        // Suffix range: last N bytes.
        let n: u64 = match end_s.parse() {
            Ok(n) => n,
            Err(_) => return RangeOutcome::Ignore,
        };
        if n == 0 {
            return RangeOutcome::Unsatisfiable;
        }
        if len == 0 {
            return RangeOutcome::Unsatisfiable;
        }
        let start = len.saturating_sub(n);
        return RangeOutcome::Single(start, len - 1);
    }

    let start: u64 = match start_s.parse() {
        Ok(n) => n,
        Err(_) => return RangeOutcome::Ignore,
    };

    if start >= len {
        // First-byte-pos beyond the entity → unsatisfiable.
        return RangeOutcome::Unsatisfiable;
    }

    let end: u64 = if end_s.is_empty() {
        len - 1
    } else {
        match end_s.parse::<u64>() {
            Ok(n) => n.min(len - 1),
            Err(_) => return RangeOutcome::Ignore,
        }
    };

    if end < start {
        return RangeOutcome::Unsatisfiable;
    }
    RangeOutcome::Single(start, end)
}

/// Evaluate an `If-None-Match` header value (raw header bytes) against the entity
/// ETag. Returns `true` if the precondition means "not modified". Delegates the
/// RFC 7232 weak comparison to the single-sourced [`hj_core::if_none_match_matches`].
fn if_none_match_matches(value: &[u8], etag: &str) -> bool {
    match std::str::from_utf8(value) {
        Ok(s) => hj_core::if_none_match_matches(s, etag),
        Err(_) => false,
    }
}

/// `If-Match`: true when the existing entity satisfies at least one strong validator.
fn if_match_passes(value: &HeaderValue, etag: Option<&str>) -> bool {
    let Ok(s) = value.to_str() else {
        return true; // malformed conditional headers are ignored
    };
    for tok in s.split(',').map(str::trim) {
        if tok == "*" {
            return true;
        }
        if !tok.starts_with("W/") && etag == Some(tok) {
            return true;
        }
    }
    false
}

/// `If-Modified-Since`: returns true (304) if the entity has NOT been modified
/// since the given date (mtime <= header date).
fn if_modified_since_not_modified(value: &HeaderValue, mtime: SystemTime) -> bool {
    let Ok(s) = value.to_str() else {
        return false;
    };
    let Ok(since) = httpdate::parse_http_date(s) else {
        return false;
    };
    // HTTP dates have 1-second resolution; truncate mtime before comparing.
    let mtime_secs = mtime
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let since_secs = since
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    mtime_secs <= since_secs
}

/// `If-Unmodified-Since`: true when the entity has not changed since the date.
/// Malformed dates are ignored and therefore pass.
fn if_unmodified_since_passes(value: &HeaderValue, mtime: SystemTime) -> bool {
    let Ok(s) = value.to_str() else {
        return true;
    };
    let Ok(since) = httpdate::parse_http_date(s) else {
        return true;
    };
    let mtime_secs = mtime
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let since_secs = since
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    mtime_secs <= since_secs
}

/// `If-Range`: returns true if the validator (ETag or HTTP-date) still matches
/// the current entity, meaning the `Range` should be honored. When the entity
/// has no ETag (`fileETag` NONE), an ETag-form If-Range can never match.
fn if_range_matches(value: &HeaderValue, etag: Option<&str>, mtime: SystemTime) -> bool {
    let Ok(s) = value.to_str() else {
        return false;
    };
    let s = s.trim();
    if s.starts_with('"') || s.starts_with("W/") {
        // ETag form: strong comparison required for If-Range.
        etag == Some(s)
    } else if let Ok(date) = httpdate::parse_http_date(s) {
        let mtime_secs = mtime
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let date_secs = date
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        mtime_secs == date_secs
    } else {
        false
    }
}

#[cfg(test)]
mod tests;
