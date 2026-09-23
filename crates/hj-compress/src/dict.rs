//! Shared-dictionary zstd compression for the origin page cache's **internal** storage.
//!
//! CMS pages (XenForo here) share a large amount of boilerplate — head, nav, footer, repeated
//! CSS-class names, common inline strings — but it is **position-shifted** by per-page tokens
//! (CSRF, titles, ids), so it does NOT deduplicate at fixed byte offsets. A zstd **dictionary**
//! trained on a page sample captures it: each body compressed *against* the dictionary references
//! the shared chrome instead of re-storing it, so stored bodies shrink dramatically (measured
//! ~63% cross-page redundancy on real threads) and far more pages fit in the same cache RAM.
//!
//! IMPORTANT — internal use only: dictionary-compressed output is **not decodable without the same
//! dictionary**, and browsers / Cloudflare don't hold ours (Compression-Dictionary-Transport is
//! not deployable here). So this only shrinks what the cache STORES; whatever is SERVED stays
//! standard zstd/br/gzip. The cache stores the body dict-compressed and [`PageDict::decode`]s it
//! with the dictionary when it needs the identity (to serve a non-precompressed encoding, or to
//! (re)build a precompressed variant).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError};

use zstd::bulk::Compressor;
use zstd::dict::DecoderDictionary;
use zstd::zstd_safe::CParameter;

/// Default zstd level for dict-compressing a stored body. Level 12 is the last level on zstd's
/// row-based lazy matcher; 13-15 switch to the binary-tree btlazy2 search, which was ~55% of all
/// httpjet CPU in a live `perf` profile (`ZSTD_DUBT_findBestMatch`). Measured with the prod
/// per-vhost dictionaries on real pages (2026-09-22): windowsforum 44 pages / 7.3 MiB took
/// 411 ms at 15 vs 152 ms at 12 for 960 vs 979 KiB out (+2%); moontimenow 25 pages / 2.8 MiB
/// took 112 ms vs 38 ms for 199 vs 201 KiB (+1%). The cross-page size win comes from the
/// dictionary, not the level. The store-path compress runs on the tokio worker pool, so its CPU
/// competes with request serving. zstd *decompression* speed is independent of the level, so
/// the cache-HIT serve path is unaffected, and the level is NOT part of `dict_gen` (that hashes
/// the dict bytes), so changing it does not invalidate already-stored bodies — they keep
/// decoding, new bodies just store at the new level.
pub const DEFAULT_DICT_LEVEL: i32 = 12;

/// Hash-table size for the pooled encode contexts. zstd sizes a CDict's tables for a small
/// assumed source, and the 256 KiB dictionaries push that onto a 4 MiB hash + 1 MiB row-tag
/// table which, above lazy2's 32 KB attach cutoff (every real page), is COPIED into the
/// context on every frame. Loading the dictionary into a context configured with HashLog 18
/// shrinks what each frame copies. Measured 2026-09-22 on real pages with the prod
/// dictionaries: windowsforum −20% time for +0.6% size, moontimenow −32% for +0%.
const DICT_HASH_LOG: u32 = 18;

/// Encode contexts kept per dictionary. Matches the page cache's dict-fill concurrency, so
/// steady state never builds a context; it is a global pool (not thread-local) because the
/// encode runs under `block_in_place`, which moves between threads.
const ENCODE_POOL_CAP: usize = 2;

/// A prepared shared dictionary for page-cache internal storage. Holds the raw dictionary bytes, a
/// non-zero **generation id** (so a cached body can be tied to the exact dictionary that decodes
/// it — a different dictionary ⇒ the entry is undecodable and must degrade to a miss), a small
/// pool of encode contexts with the dictionary loaded, and the prepared decoder dictionary.
/// Shared behind an `Arc` from `ServerState`.
pub struct PageDict {
    raw: Vec<u8>,
    generation: u32,
    level: i32,
    encoders: Mutex<Vec<Compressor<'static>>>,
    dec: DecoderDictionary<'static>,
}

impl PageDict {
    /// Prepare a dictionary from raw `dict` bytes; `level` is the zstd level used when compressing
    /// bodies against it. Returns `None` if `dict` is empty.
    pub fn new(dict: Vec<u8>, level: i32) -> Option<Self> {
        if dict.is_empty() {
            return None;
        }
        // generation: FNV-1a 32 of the dict bytes, forced non-zero (0 == "not dict-compressed"
        // sentinel on a cached entry).
        let generation = fnv1a32(&dict).max(1);
        // `copy` (vs `new`) owns the dictionary bytes → `'static`, so the prepared dictionary
        // can live in an `Arc<PageDict>` on `ServerState` without borrowing `raw`.
        let dec = DecoderDictionary::copy(&dict);
        Some(PageDict {
            raw: dict,
            generation,
            level,
            encoders: Mutex::new(Vec::with_capacity(ENCODE_POOL_CAP)),
            dec,
        })
    }

    /// A context with the dictionary loaded under [`DICT_HASH_LOG`]. Parameters are set before
    /// the load so zstd builds the context's local dictionary tables at that size.
    fn new_encoder(&self) -> Option<Compressor<'static>> {
        let mut c = Compressor::new(self.level).ok()?;
        c.set_parameter(CParameter::HashLog(DICT_HASH_LOG)).ok()?;
        c.set_dictionary(self.level, &self.raw).ok()?;
        Some(c)
    }

    /// The dictionary generation id (always non-zero).
    pub fn generation(&self) -> u32 {
        self.generation
    }

    /// Raw dictionary size in bytes (the fixed overhead held once, regardless of entry count).
    pub fn raw_len(&self) -> usize {
        self.raw.len()
    }

    /// Compress `input` against the dictionary (zstd). `None` only on a zstd failure.
    pub fn encode(&self, input: &[u8]) -> Option<Vec<u8>> {
        let pooled = self
            .encoders
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop();
        let mut c = match pooled {
            Some(c) => c,
            None => self.new_encoder()?,
        };
        // A failed frame may leave the context mid-stream, so only a clean one goes back.
        let mut out = c.compress(input).ok()?;
        {
            let mut pool = self.encoders.lock().unwrap_or_else(PoisonError::into_inner);
            if pool.len() < ENCODE_POOL_CAP {
                pool.push(c);
            }
        }
        // zstd sizes this Vec at compress_bound(input) ≈ input.len() and the page cache keeps
        // it for the entry's whole TTL — unshrunk, every "8-20 KiB" stored body pins an
        // identity-size (~60-150 KiB) heap block, usually one already fully faulted by an
        // ephemeral same-bin buffer, which is what put GiBs of cold [anon:mimalloc] in swap.
        out.shrink_to_fit();
        Some(out)
    }

    /// Decompress dictionary-compressed `input` back to identity, bounded to `max` bytes
    /// (decompression-bomb guard). `None` on malformed input, a dictionary mismatch, or if the
    /// content would exceed `max`.
    pub fn decode(&self, input: &[u8], max: usize) -> Option<Vec<u8>> {
        let mut d = zstd::bulk::Decompressor::with_prepared_dictionary(&self.dec).ok()?;
        d.decompress(input, max).ok()
    }
}

/// FNV-1a 32-bit hash of the dictionary bytes → its generation id.
fn fnv1a32(bytes: &[u8]) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for &b in bytes {
        h ^= b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

/// A set of [`PageDict`]s, one per vhost, plus an optional fallback used for any vhost without its
/// own entry. Each vhost's cached bodies compress against a dictionary trained on *that vhost's*
/// content — a shared dictionary trained on one site's boilerplate does little for a differently
/// templated site. Decode is vhost-agnostic: a stored entry's `dict_gen` alone identifies which
/// loaded dictionary decodes it (see [`PageDict::generation`]), so [`Self::by_generation`] serves
/// every read path regardless of which vhost originally wrote the entry.
#[derive(Default)]
pub struct PageDictRegistry {
    by_vhost: HashMap<String, Arc<PageDict>>,
    fallback: Option<Arc<PageDict>>,
    by_generation: HashMap<u32, Arc<PageDict>>,
}

impl PageDictRegistry {
    /// Build a registry from per-vhost dicts (vhost keys should already be lowercase) plus an
    /// optional fallback. Logs a warning if two configured dicts collide on generation (either an
    /// accidental duplicate file, or — astronomically unlikely — an FNV-1a32 collision); the later
    /// entry in iteration order wins the `by_generation` slot, matching `HashMap::insert` semantics.
    pub fn new(by_vhost: HashMap<String, Arc<PageDict>>, fallback: Option<Arc<PageDict>>) -> Self {
        let mut by_generation = HashMap::new();
        for (vhost, dict) in by_vhost.iter() {
            if let Some(prev) = by_generation.insert(dict.generation(), dict.clone()) {
                tracing::warn!(
                    vhost,
                    generation = dict.generation(),
                    prev_raw_len = prev.raw_len(),
                    "page-cache dict generation collision; one dict will shadow the other for decode"
                );
            }
        }
        if let Some(fb) = fallback.as_ref() {
            if let Some(prev) = by_generation.insert(fb.generation(), fb.clone()) {
                tracing::warn!(
                    generation = fb.generation(),
                    prev_raw_len = prev.raw_len(),
                    "page-cache fallback dict generation collides with a per-vhost dict"
                );
            }
        }
        PageDictRegistry {
            by_vhost,
            fallback,
            by_generation,
        }
    }

    /// An empty registry (no dicts configured at all) — dict compression is inert.
    pub fn empty() -> Self {
        PageDictRegistry::default()
    }

    /// The dictionary to compress a NEW body for `vhost` with (lowercase vhost name), falling back
    /// to the global fallback dict when this vhost has no dedicated entry.
    pub fn for_vhost(&self, vhost: &str) -> Option<&Arc<PageDict>> {
        self.by_vhost.get(vhost).or(self.fallback.as_ref())
    }

    /// The dictionary that decodes a stored entry carrying this `generation` id (0 = not
    /// dict-compressed, never matches).
    pub fn by_generation(&self, generation: u32) -> Option<&Arc<PageDict>> {
        if generation == 0 {
            return None;
        }
        self.by_generation.get(&generation)
    }

    /// Every generation id currently loaded (per-vhost dicts + fallback) — what a persisted-store
    /// boot scan should treat as valid.
    pub fn all_generations(&self) -> HashSet<u32> {
        self.by_generation.keys().copied().collect()
    }

    /// True when no dict — per-vhost or fallback — is configured at all.
    pub fn is_empty(&self) -> bool {
        self.by_vhost.is_empty() && self.fallback.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A stand-in "dictionary" of XenForo-ish boilerplate. zstd accepts arbitrary bytes as a
    // content dictionary (a trained dict is just better at it), which is all a unit test needs.
    const CHROME: &[u8] =
        b"<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title></title>\
          <link rel=\"stylesheet\" href=\"/css.php\"><nav class=\"p-nav\">Forums Home Help</nav>\
          </head><body class=\"template-thread\"><footer class=\"p-footer\">(c) Example Forum</footer>";

    fn dict() -> PageDict {
        PageDict::new(CHROME.to_vec(), DEFAULT_DICT_LEVEL).expect("non-empty dict")
    }

    #[test]
    fn empty_dict_is_none() {
        assert!(PageDict::new(Vec::new(), DEFAULT_DICT_LEVEL).is_none());
    }

    #[test]
    fn generation_is_nonzero_and_deterministic() {
        let a = dict();
        let b = dict();
        assert_ne!(a.generation(), 0);
        assert_eq!(
            a.generation(),
            b.generation(),
            "same bytes → same generation"
        );
        let other =
            PageDict::new(b"different dictionary bytes".to_vec(), DEFAULT_DICT_LEVEL).unwrap();
        assert_ne!(
            a.generation(),
            other.generation(),
            "different bytes → different generation"
        );
    }

    #[test]
    fn round_trips_identity() {
        let d = dict();
        let body = [
            CHROME,
            b"<article>unique thread content here, post #12345</article>",
        ]
        .concat();
        let comp = d.encode(&body).expect("encode");
        assert_eq!(d.decode(&comp, 1 << 20).expect("decode"), body);
    }

    #[test]
    fn dict_beats_no_dict_on_boilerplate_heavy_body() {
        // A body that is mostly chrome (the dict) + a little unique content compresses smaller
        // WITH the dict than without — this is the whole point.
        let d = dict();
        let body = [
            CHROME,
            CHROME,
            b"<article>tiny unique tail</article>",
            CHROME,
        ]
        .concat();
        let with_dict = d.encode(&body).expect("encode").len();
        let without_dict = crate::encode_bytes(
            crate::Encoding::Zstd,
            &body,
            &crate::Levels {
                zstd: DEFAULT_DICT_LEVEL,
                ..crate::Levels::default()
            },
        )
        .expect("no-dict encode")
        .len();
        assert!(
            with_dict < without_dict,
            "dict-compressed ({with_dict}) should beat no-dict ({without_dict})"
        );
    }

    #[test]
    fn wrong_dictionary_fails_to_decode() {
        // The generation-safety property: a body dict-compressed with one dict must NOT silently
        // decode with a different dict (it errors → the caller degrades the entry to a miss,
        // never corrupt output).
        let a = dict();
        let b = PageDict::new(
            b"a completely different dictionary corpus entirely".to_vec(),
            DEFAULT_DICT_LEVEL,
        )
        .unwrap();
        let body = [CHROME, b"unique"].concat();
        let comp = a.encode(&body).expect("encode with a");
        assert!(
            b.decode(&comp, 1 << 20).is_none(),
            "decode with the wrong dict must fail"
        );
    }

    #[test]
    fn pooled_encoders_are_reused_deterministically_and_capped() {
        let d = dict();
        let body = CHROME.repeat(8);
        let first = d.encode(&body).expect("encode");
        let second = d.encode(&body).expect("encode on a reused context");
        assert_eq!(
            first, second,
            "a reused context must produce the same frame"
        );
        assert_eq!(
            d.decode(&second, crate::MAX_DECODE as usize).as_deref(),
            Some(body.as_slice())
        );
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| d.encode(&body).expect("concurrent encode"));
            }
        });
        assert!(d.encoders.lock().unwrap().len() <= ENCODE_POOL_CAP);
    }

    #[test]
    fn encode_output_is_exact_sized() {
        // The encoded Vec is held by the page cache for the entry's whole TTL. zstd allocates
        // it at compress_bound(input) ≈ input.len(); unshrunk, a 64 KiB page stored as 8 KiB
        // still owned a ~64 KiB block — multiplied by the entry count this swapped GiBs of
        // cold heap. Capacity must equal length when it leaves encode().
        let d = dict();
        let body = [
            CHROME,
            CHROME,
            b"<article>post body</article>",
            CHROME,
            CHROME,
        ]
        .concat();
        let comp = d.encode(&body).expect("encode");
        assert!(comp.len() < body.len(), "compressible input must shrink");
        assert_eq!(
            comp.capacity(),
            comp.len(),
            "stored buffer must carry no capacity slack"
        );
    }

    #[test]
    fn decode_bounded_by_max() {
        // A body larger than the supplied cap must not decode (bomb guard).
        let d = dict();
        let body = vec![b'x'; 4096];
        let comp = d.encode(&body).expect("encode");
        assert!(
            d.decode(&comp, 1024).is_none(),
            "decode must respect the max-output cap"
        );
        assert!(d.decode(&comp, 8192).is_some(), "under the cap it decodes");
    }

    fn other_dict() -> PageDict {
        PageDict::new(
            b"a completely different dictionary corpus entirely".to_vec(),
            DEFAULT_DICT_LEVEL,
        )
        .unwrap()
    }

    #[test]
    fn empty_registry_resolves_nothing() {
        let reg = PageDictRegistry::empty();
        assert!(reg.is_empty());
        assert!(reg.for_vhost("forum.example").is_none());
        assert!(reg.by_generation(1).is_none());
        assert!(reg.all_generations().is_empty());
    }

    #[test]
    fn for_vhost_prefers_dedicated_dict_over_fallback() {
        let dedicated = Arc::new(dict());
        let fallback = Arc::new(other_dict());
        let mut by_vhost = HashMap::new();
        by_vhost.insert("forum.example".to_string(), dedicated.clone());
        let reg = PageDictRegistry::new(by_vhost, Some(fallback.clone()));

        assert!(!reg.is_empty());
        assert_eq!(
            reg.for_vhost("forum.example").unwrap().generation(),
            dedicated.generation()
        );
        assert_eq!(
            reg.for_vhost("moon.example").unwrap().generation(),
            fallback.generation(),
            "a vhost with no dedicated dict falls back to the global dict"
        );
    }

    #[test]
    fn for_vhost_none_without_fallback() {
        let mut by_vhost = HashMap::new();
        by_vhost.insert("forum.example".to_string(), Arc::new(dict()));
        let reg = PageDictRegistry::new(by_vhost, None);
        assert!(reg.for_vhost("moon.example").is_none());
    }

    #[test]
    fn by_generation_resolves_any_loaded_dict_regardless_of_vhost() {
        let a = Arc::new(dict());
        let b = Arc::new(other_dict());
        let mut by_vhost = HashMap::new();
        by_vhost.insert("forum.example".to_string(), a.clone());
        by_vhost.insert("moon.example".to_string(), b.clone());
        let reg = PageDictRegistry::new(by_vhost, None);

        assert_eq!(
            reg.by_generation(a.generation()).unwrap().generation(),
            a.generation()
        );
        assert_eq!(
            reg.by_generation(b.generation()).unwrap().generation(),
            b.generation()
        );
        assert!(reg.by_generation(0).is_none(), "0 is the no-dict sentinel");
        assert!(reg.by_generation(u32::MAX).is_none());
    }

    #[test]
    fn all_generations_dedups_across_vhosts_and_fallback() {
        let shared = Arc::new(dict());
        let mut by_vhost = HashMap::new();
        by_vhost.insert("forum.example".to_string(), shared.clone());
        by_vhost.insert("moon.example".to_string(), shared.clone());
        let reg = PageDictRegistry::new(by_vhost, Some(shared.clone()));

        let gens = reg.all_generations();
        assert_eq!(
            gens.len(),
            1,
            "identical dict bytes collapse to one generation"
        );
        assert!(gens.contains(&shared.generation()));
    }

    #[test]
    fn colliding_generations_do_not_panic() {
        // Two vhosts pointed at byte-identical dict files (a real, if unusual, config) share a
        // generation; construction must not panic and by_generation must still resolve.
        let shared = Arc::new(dict());
        let mut by_vhost = HashMap::new();
        by_vhost.insert("forum.example".to_string(), shared.clone());
        by_vhost.insert("news.forum.example".to_string(), shared.clone());
        let reg = PageDictRegistry::new(by_vhost, None);
        assert!(reg.by_generation(shared.generation()).is_some());
    }
}
