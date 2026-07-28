//! Origin response and static-body cache for httpjet.
//!
//! Its primary role is the clean-room LiteSpeed **LSCache** equivalent: caching
//! full HTTP responses, typically rendered PHP/LSAPI or proxy output, so a
//! cacheable guest pageview is served from memory/tmpfs instead of re-running
//! the application. The same sharded store also holds stat-validated static
//! file bodies, sharing the tmpfs backing store and byte budgets with page
//! entries.
//!
//! Cacheability is **opt-in by the application**, exactly as LSCache: the
//! backend signals it via the `X-LiteSpeed-Cache-Control` response header
//! (`public,max-age=N` / `private,max-age=N` / `no-cache`), tags entries with
//! `X-LiteSpeed-Tag` (for tag-based purge), and varies them with
//! `X-LiteSpeed-Vary`. The pipeline parses these (see [`proto`]), decides
//! cacheability (see [`classify`]), and stores/serves via the [`PageStore`].
//!
//! This crate is transport-agnostic: it knows `http` header/method types but
//! nothing about the httpjet pipeline. The pipeline glue lives in the binary
//! crate (`crates/httpjet/src/lscache.rs`).
//!
//! Private entries, vary dimensions, stale windows, tag purge, static bodies,
//! and the optional tmpfs file tier all use the same store. ESI remains out of
//! scope.

pub mod admission;
pub mod classify;
pub mod diskstore;
pub mod key;
mod metablob;
pub mod proto;
pub mod shared_paths;
pub mod store;

pub use admission::AdmissionFilter;
pub use classify::{Disposition, classify_response};
pub use key::{
    PageCacheKey, QsStrip, compute_vary_value, normalize_query, public_with_vary,
    vary_value_from_request,
};
pub use proto::{
    LsCacheControl, Purge, StdCacheControl, parse_lscache_control, parse_purge,
    parse_std_cache_control, parse_tags, parse_vary,
};
pub use shared_paths::{SharedPathMatcher, parse_shared_paths};
pub use store::{
    CacheListing, CacheStats, CachedResponse, EntryInfo, EntryState, FileId, Freshness, PageBody,
    PageScope, PageStore, StaticNode, StoreConfig,
};
