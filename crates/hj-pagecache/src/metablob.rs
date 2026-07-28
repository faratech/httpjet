//! Compressed resident metadata for the page cache.
//!
//! A `MetaBlob` is the RAM-resident copy of an entry's key + headers + tags, held compressed so the
//! index footprint stays small (its `compressed_len()` is what `ResidentEntry::weight()` charges
//! against `--page-cache-mem`). It is **purely in-RAM**: the tmpfs file tier persists a separate
//! *plaintext* meta block (see `diskstore::encode_meta`/`read_meta`), and the boot scan re-encodes a
//! fresh `MetaBlob` from that — nothing on disk references this representation. So we are free to
//! compress it however we like with no on-disk format/version concern.
//!
//! The raw blob is tiny (~hundreds of bytes), and plain zstd barely shrinks sub-KiB inputs (the
//! frame overhead rivals the data). The repeated content here, though, is the *same header
//! vocabulary across every entry* (`content-type`, `cache-control`, `vary`, security headers, the
//! host, path prefixes). A small shared **content dictionary** ([`META_DICT`]) lets each blob
//! reference that vocabulary instead of re-emitting it, roughly halving the per-entry resident bytes.
//!
//! HOT PATH: `MetaBlob::decode` runs on **every cache HIT** (`store::get_entry` →
//! `ResidentEntry::to_cached`). zstd decompression speed is independent of the compression level and
//! the dictionary is prepared once, so an L19+dict blob decodes as fast as the old L9-no-dict one
//! (faster, even — fewer input bytes). To stay strictly at-or-below the old per-hit cost we reuse a
//! **thread-local `Decompressor`** (a loaded DCtx) rather than building one per call as
//! `zstd::bulk::decompress` did — mirroring the egress `ZSTD_CCTX` thread-local in `hj-compress`.

use std::cell::RefCell;
use std::fmt;
use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{HeaderName, HeaderValue};
use zstd::bulk::{Compressor, Decompressor};
use zstd::dict::{DecoderDictionary, EncoderDictionary};

use crate::key::PageCacheKey;
use crate::store::{CachedResponse, PageBody, PageScope};

const MAGIC: [u8; 4] = *b"HJPM";
// v2: explicit 1-byte scope flag replaces the `owner == 0` public sentinel (a private
// session hashing to owner 0 previously decoded as Public). RAM-only format, rebuilt each
// process, so the bump needs no migration.
const VERSION: u16 = 2;
/// High level: metadata is encoded off the hot path (only at store time) and held for the entry's
/// whole TTL, while decode (the hot path) is level-independent — so a high level is free shrink.
const ZSTD_LEVEL: i32 = 19;
const MAX_RAW_META: usize = 4 << 20;
const MAX_COMP_META: usize = 4 << 20;

/// Shared dictionary for the resident metadata blob. It is trained exclusively on deterministic,
/// synthetic `encode_raw` fixtures using reserved example domains; it contains no traffic captures
/// or production-derived values. [`../scripts/generate-synthetic-meta-dict.py`](../scripts/generate-synthetic-meta-dict.py)
/// pins the corpus, zstd trainer version, parameters, dictionary ID, and checksum so the embedded
/// bytes are reproducible and their provenance is reviewable.
///
/// Safe + self-contained: the blob never crosses a process boundary, so the running binary always
/// holds the dictionary that decodes what it encoded. Changing it cannot corrupt persisted cache
/// data; entries are re-encoded under the new dictionary on their next store.
const META_DICT: &[u8] = include_bytes!("pagecache-meta.dict");
/// Fixed by the synthetic generator; this acts as a cheap provenance/version marker in tests.
#[cfg(test)]
const SYNTHETIC_META_DICT_ID: u32 = u32::from_le_bytes(*b"HJSM") & 0x7fff_ffff;

/// Prepared (level-baked) dictionaries, built once. `::copy` owns the bytes → `'static`, so they can
/// back `'static` thread-local (de)compressors.
struct MetaDict {
    enc: EncoderDictionary<'static>,
    dec: DecoderDictionary<'static>,
}

fn meta_dict() -> &'static MetaDict {
    static D: OnceLock<MetaDict> = OnceLock::new();
    D.get_or_init(|| MetaDict {
        enc: EncoderDictionary::copy(META_DICT, ZSTD_LEVEL),
        dec: DecoderDictionary::copy(META_DICT),
    })
}

thread_local! {
    /// Reused per-thread compress context (off the hot path: store time only).
    static META_COMP: RefCell<Compressor<'static>> = RefCell::new(
        Compressor::with_prepared_dictionary(&meta_dict().enc).expect("meta compressor init"),
    );
    /// Reused per-thread decompress context — HOT PATH (one per cache hit). Reusing the loaded DCtx
    /// avoids the per-call allocation `zstd::bulk::decompress` paid.
    static META_DECOMP: RefCell<Decompressor<'static>> = RefCell::new(
        Decompressor::with_prepared_dictionary(&meta_dict().dec).expect("meta decompressor init"),
    );
}

#[derive(Debug, Clone)]
pub struct MetaBlob {
    compressed: Bytes,
    raw_len: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct MetaError(&'static str);

impl MetaError {
    fn encode(msg: &'static str) -> Self {
        MetaError(msg)
    }

    fn decode(msg: &'static str) -> Self {
        MetaError(msg)
    }
}

impl fmt::Display for MetaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

#[derive(Debug)]
pub struct DecodedMeta {
    pub key: PageCacheKey,
    pub status: u16,
    pub identity: String,
    pub headers: Vec<(HeaderName, HeaderValue)>,
    pub tags: Vec<Arc<str>>,
    pub vary_cookie_name: String,
    pub vary_value: String,
    pub scope: PageScope,
}

impl MetaBlob {
    pub fn encode(key: &PageCacheKey, entry: &CachedResponse) -> Result<Self, MetaError> {
        let raw = encode_raw(key, entry)?;
        let mut compressed = META_COMP
            .with(|c| c.borrow_mut().compress(&raw))
            .map_err(|_| MetaError::encode("zstd metadata encode failed"))?;
        compressed.shrink_to_fit();
        if compressed.len() > MAX_COMP_META {
            return Err(MetaError::encode("compressed metadata over format bound"));
        }
        Ok(MetaBlob {
            raw_len: raw.len() as u32,
            compressed: Bytes::from(compressed),
        })
    }

    pub fn decode(&self) -> Result<DecodedMeta, MetaError> {
        if self.compressed.len() > MAX_COMP_META || self.raw_len as usize > MAX_RAW_META {
            return Err(MetaError::decode("metadata length over format bound"));
        }
        let raw = META_DECOMP
            .with(|d| {
                d.borrow_mut()
                    .decompress(&self.compressed, self.raw_len as usize)
            })
            .map_err(|_| MetaError::decode("zstd metadata decode failed"))?;
        decode_raw(&raw)
    }

    /// Decode only the status and identity needed by cache diagnostics. The callback borrows
    /// the identity directly from the decompression buffer, so entries that do not make the
    /// top-N listing allocate no identity/header/tag objects.
    pub fn with_listing_fields<R>(
        &self,
        inspect: impl FnOnce(u16, &str) -> R,
    ) -> Result<R, MetaError> {
        if self.compressed.len() > MAX_COMP_META || self.raw_len as usize > MAX_RAW_META {
            return Err(MetaError::decode("metadata length over format bound"));
        }
        let raw = META_DECOMP
            .with(|d| {
                d.borrow_mut()
                    .decompress(&self.compressed, self.raw_len as usize)
            })
            .map_err(|_| MetaError::decode("zstd metadata decode failed"))?;
        let mut c = Cursor { buf: &raw, pos: 0 };
        if c.take(4)? != MAGIC || c.u16()? != VERSION {
            return Err(MetaError::decode("bad listing metadata header"));
        }
        let _ = c.u32()?;
        let _ = c.u8()?;
        for _ in 0..4 {
            let _ = c.lp()?;
        }
        let _ = c.u64()?;
        let status = c.u16()?;
        let _ = c.u8()?;
        let _ = c.u64()?;
        let identity =
            std::str::from_utf8(c.lp()?).map_err(|_| MetaError::decode("bad identity utf-8"))?;
        let _ = c.lp()?;
        let _ = c.lp()?;
        let tag_count = c.u16()?;
        for _ in 0..tag_count {
            let _ = c.lp()?;
        }
        let header_count = c.u16()?;
        for _ in 0..header_count {
            let _ = c.lp()?;
            let _ = c.lp()?;
        }
        if c.pos != raw.len() {
            return Err(MetaError::decode("trailing metadata bytes"));
        }
        Ok(inspect(status, identity))
    }

    pub fn compressed_len(&self) -> usize {
        self.compressed.len()
    }

    pub fn raw_len(&self) -> usize {
        self.raw_len as usize
    }
}

impl DecodedMeta {
    /// Build a `CachedResponse` from this (possibly memoized) decoded metadata plus the
    /// per-hit body/timing. Takes `&self` and clones the metadata fields so a single
    /// `DecodedMeta` decoded once can back every cache HIT for the entry (the resident
    /// `MetaBlob` is decoded at most once per entry — see `ResidentEntry::to_cached`).
    pub fn to_cached_response(
        &self,
        body: PageBody,
        variants: Vec<(String, Bytes)>,
        variants_filled: bool,
        dict_gen: u32,
        stored_at: Instant,
        ttl: Duration,
        swr: Duration,
        sie: Duration,
    ) -> CachedResponse {
        CachedResponse {
            status: self.status,
            identity: self.identity.clone(),
            headers: self.headers.clone(),
            body,
            variants,
            variants_filled,
            dict_gen,
            tags: self.tags.clone(),
            vary_cookie_name: self.vary_cookie_name.clone(),
            vary_value: self.vary_value.clone(),
            scope: self.scope,
            stored_at,
            ttl,
            swr,
            sie,
        }
    }
}

fn encode_raw(key: &PageCacheKey, entry: &CachedResponse) -> Result<Vec<u8>, MetaError> {
    if entry.tags.len() > u16::MAX as usize || entry.headers.len() > u16::MAX as usize {
        return Err(MetaError::encode("tag/header count over format bound"));
    }
    let mut m = Vec::with_capacity(512);
    m.extend_from_slice(&MAGIC);
    m.extend_from_slice(&VERSION.to_le_bytes());
    m.extend_from_slice(&key.vhost_id.to_le_bytes());
    m.push(key.secure as u8);
    push_lp(&mut m, key.host.as_bytes())?;
    push_lp(&mut m, key.path.as_bytes())?;
    push_lp(&mut m, key.normalized_query.as_bytes())?;
    push_lp(&mut m, key.vary_value.as_bytes())?;
    m.extend_from_slice(&key.private_owner.to_le_bytes());
    m.extend_from_slice(&entry.status.to_le_bytes());
    let (is_private, scope_owner) = match entry.scope {
        PageScope::Public => (0u8, 0u64),
        PageScope::Private { owner_hash } => (1u8, owner_hash),
    };
    m.push(is_private);
    m.extend_from_slice(&scope_owner.to_le_bytes());
    push_lp(&mut m, entry.identity.as_bytes())?;
    push_lp(&mut m, entry.vary_cookie_name.as_bytes())?;
    push_lp(&mut m, entry.vary_value.as_bytes())?;
    m.extend_from_slice(&(entry.tags.len() as u16).to_le_bytes());
    for t in &entry.tags {
        push_lp(&mut m, t.as_bytes())?;
    }
    m.extend_from_slice(&(entry.headers.len() as u16).to_le_bytes());
    for (n, v) in &entry.headers {
        push_lp(&mut m, n.as_str().as_bytes())?;
        push_lp(&mut m, v.as_bytes())?;
    }
    if m.len() > MAX_RAW_META {
        return Err(MetaError::encode("raw metadata over format bound"));
    }
    Ok(m)
}

fn decode_raw(raw: &[u8]) -> Result<DecodedMeta, MetaError> {
    let mut c = Cursor { buf: raw, pos: 0 };
    if c.take(4)? != MAGIC {
        return Err(MetaError::decode("bad metadata magic"));
    }
    if c.u16()? != VERSION {
        return Err(MetaError::decode("unknown metadata version"));
    }
    let vhost_id = c.u32()?;
    let secure = c.u8()? != 0;
    let host = c.string()?;
    let path = c.string()?;
    let normalized_query = c.string()?;
    let key_vary_value = c.string()?;
    let private_owner = c.u64()?;
    let status = c.u16()?;
    let is_private = c.u8()?;
    let scope_owner = c.u64()?;
    let identity = c.string()?;
    let vary_cookie_name = c.string()?;
    let vary_value = c.string()?;
    let tag_count = c.u16()?;
    let mut tags = Vec::with_capacity(tag_count as usize);
    for _ in 0..tag_count {
        tags.push(Arc::<str>::from(c.string()?));
    }
    let header_count = c.u16()?;
    let mut headers = Vec::with_capacity(header_count as usize);
    for _ in 0..header_count {
        let name =
            HeaderName::from_bytes(c.lp()?).map_err(|_| MetaError::decode("bad header name"))?;
        let value =
            HeaderValue::from_bytes(c.lp()?).map_err(|_| MetaError::decode("bad header value"))?;
        headers.push((name, value));
    }
    if c.pos != raw.len() {
        return Err(MetaError::decode("trailing metadata bytes"));
    }
    let scope = if is_private != 0 {
        PageScope::Private {
            owner_hash: scope_owner,
        }
    } else {
        PageScope::Public
    };
    Ok(DecodedMeta {
        key: PageCacheKey {
            vhost_id,
            secure,
            host,
            path,
            normalized_query,
            vary_value: key_vary_value,
            private_owner,
        },
        status,
        identity,
        headers,
        tags,
        vary_cookie_name,
        vary_value,
        scope,
    })
}

fn push_lp(buf: &mut Vec<u8>, bytes: &[u8]) -> Result<(), MetaError> {
    if bytes.len() > u32::MAX as usize {
        return Err(MetaError::encode("field over format bound"));
    }
    buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(bytes);
    Ok(())
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], MetaError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(MetaError::decode("length overflow"))?;
        if end > self.buf.len() {
            return Err(MetaError::decode("field past metadata end"));
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, MetaError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, MetaError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32, MetaError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, MetaError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn lp(&mut self) -> Result<&'a [u8], MetaError> {
        let n = self.u32()? as usize;
        self.take(n)
    }

    fn string(&mut self) -> Result<String, MetaError> {
        String::from_utf8(self.lp()?.to_vec()).map_err(|_| MetaError::decode("bad utf-8"))
    }
}

pub fn cloned_file_path(body: &PageBody) -> Option<Arc<Path>> {
    match body {
        PageBody::File { path, .. } => Some(path.clone()),
        PageBody::InMem(_) | PageBody::Derived { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::{
        CACHE_CONTROL, CONTENT_LANGUAGE, CONTENT_TYPE, REFERRER_POLICY, STRICT_TRANSPORT_SECURITY,
        VARY, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
    };

    fn entry() -> CachedResponse {
        CachedResponse {
            status: 200,
            identity: "https\nexample.com\n/threads/a".to_string(),
            headers: vec![
                (
                    CONTENT_TYPE,
                    HeaderValue::from_static("text/html; charset=utf-8"),
                ),
                (
                    CACHE_CONTROL,
                    HeaderValue::from_static("public, max-age=900"),
                ),
            ],
            body: PageBody::InMem(Bytes::from_static(b"body")),
            variants: Vec::new(),
            variants_filled: false,
            dict_gen: 0,
            tags: vec![Arc::from("T1"), Arc::from("F2")],
            vary_cookie_name: "xf_language_id".to_string(),
            vary_value: "1".to_string(),
            scope: PageScope::Public,
            stored_at: Instant::now(),
            ttl: Duration::from_secs(900),
            swr: Duration::ZERO,
            sie: Duration::ZERO,
        }
    }

    #[test]
    fn metadata_blob_round_trips() {
        let key = PageCacheKey::public(7, true, "example.com", "/threads/a", "b=2");
        let blob = MetaBlob::encode(&key, &entry()).unwrap();
        assert!(blob.compressed_len() < blob.raw_len());
        let got = blob.decode().unwrap();
        assert_eq!(got.key, key);
        assert_eq!(got.identity, "https\nexample.com\n/threads/a");
        assert_eq!(got.headers.len(), 2);
        assert_eq!(got.tags.len(), 2);
        assert_eq!(got.vary_cookie_name, "xf_language_id");
    }

    #[test]
    fn private_scope_round_trips_even_with_owner_zero() {
        // A private session whose owner hash is 0 must NOT decode as Public (the old
        // `owner == 0` sentinel did exactly that). The explicit scope flag fixes it.
        let key = PageCacheKey::public(7, true, "example.com", "/account/", "");
        let mut e = entry();
        e.scope = PageScope::Private { owner_hash: 0 };
        let got = MetaBlob::encode(&key, &e).unwrap().decode().unwrap();
        assert_eq!(got.scope, PageScope::Private { owner_hash: 0 });

        // A non-zero private owner and a public entry still round-trip correctly.
        e.scope = PageScope::Private { owner_hash: 42 };
        let got = MetaBlob::encode(&key, &e).unwrap().decode().unwrap();
        assert_eq!(got.scope, PageScope::Private { owner_hash: 42 });
        e.scope = PageScope::Public;
        let got = MetaBlob::encode(&key, &e).unwrap().decode().unwrap();
        assert_eq!(got.scope, PageScope::Public);
    }

    #[test]
    fn malformed_blob_fails_closed() {
        let blob = MetaBlob {
            compressed: Bytes::from_static(b"not zstd"),
            raw_len: 128,
        };
        assert!(blob.decode().is_err());
    }

    // A wholly synthetic public-page header set. It intentionally overlaps the generator's
    // reserved-domain fixtures so this test measures the checked-in dictionary without relying on
    // production-derived values.
    fn synthetic_entry() -> CachedResponse {
        CachedResponse {
            status: 200,
            identity: "https\ncache-a.example\n/articles/amber-atlas.12345/".to_string(),
            headers: vec![
                (
                    CONTENT_TYPE,
                    HeaderValue::from_static("text/html; charset=utf-8"),
                ),
                (
                    CACHE_CONTROL,
                    HeaderValue::from_static("public, max-age=900"),
                ),
                (VARY, HeaderValue::from_static("Accept-Encoding")),
                (X_FRAME_OPTIONS, HeaderValue::from_static("SAMEORIGIN")),
                (X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff")),
                (
                    REFERRER_POLICY,
                    HeaderValue::from_static("strict-origin-when-cross-origin"),
                ),
                (CONTENT_LANGUAGE, HeaderValue::from_static("en-US")),
                (
                    STRICT_TRANSPORT_SECURITY,
                    HeaderValue::from_static("max-age=31536000; includeSubDomains; preload"),
                ),
            ],
            body: PageBody::InMem(Bytes::from_static(b"body")),
            variants: Vec::new(),
            variants_filled: false,
            dict_gen: 0,
            tags: vec![
                Arc::from("public"),
                Arc::from("item_12345"),
                Arc::from("guest"),
            ],
            vary_cookie_name: "theme".to_string(),
            vary_value: String::new(),
            scope: PageScope::Public,
            stored_at: Instant::now(),
            ttl: Duration::from_secs(900),
            swr: Duration::ZERO,
            sie: Duration::ZERO,
        }
    }

    #[test]
    fn synthetic_dict_beats_no_dict_on_representative_headers() {
        // The synthetic dictionary must actually pay off on a representative fixture.
        let key = PageCacheKey::public(
            7,
            true,
            "cache-a.example",
            "/articles/amber-atlas.12345/",
            "",
        );
        let e = synthetic_entry();
        let raw = encode_raw(&key, &e).unwrap();
        let no_dict = zstd::bulk::compress(&raw, ZSTD_LEVEL).expect("no-dict encode");
        let blob = MetaBlob::encode(&key, &e).unwrap();
        assert!(
            blob.compressed_len() < no_dict.len(),
            "dict ({}) should beat no-dict ({}) on a realistic header set",
            blob.compressed_len(),
            no_dict.len()
        );
    }

    #[test]
    fn synthetic_entry_round_trips_through_dict() {
        let key = PageCacheKey::public(
            7,
            true,
            "cache-a.example",
            "/articles/amber-atlas.12345/",
            "page=2",
        );
        let e = synthetic_entry();
        let blob = MetaBlob::encode(&key, &e).unwrap();
        let got = blob.decode().unwrap();
        assert_eq!(got.key, key);
        assert_eq!(got.status, 200);
        assert_eq!(got.headers.len(), 8);
        assert_eq!(got.tags.len(), 3);
        assert_eq!(got.identity, e.identity);
    }

    #[test]
    fn over_bound_raw_len_is_rejected_before_decompress() {
        // The bomb guard must fire on a too-large declared raw_len even if the bytes are junk.
        let blob = MetaBlob {
            compressed: Bytes::from_static(b"\x28\xb5\x2f\xfd"),
            raw_len: (MAX_RAW_META + 1) as u32,
        };
        assert!(blob.decode().is_err());
    }

    #[test]
    fn embedded_dictionary_has_synthetic_provenance_marker() {
        assert_eq!(&META_DICT[..4], b"\x37\xa4\x30\xec");
        assert_eq!(
            u32::from_le_bytes(META_DICT[4..8].try_into().unwrap()),
            SYNTHETIC_META_DICT_ID,
        );
        assert_eq!(META_DICT.len(), 16_384);
    }
}
