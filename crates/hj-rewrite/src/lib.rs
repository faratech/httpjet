//! # hj-rewrite — Apache `mod_rewrite` / `.htaccess` engine for httpjet
//!
//! A faithful, dependency-light implementation of the subset of Apache
//! `mod_rewrite` (and the surrounding `.htaccess` directives) that the live
//! LiteSpeed configuration on this host actually uses. It is built on
//! [`fancy_regex`] rather than `regex` because the real configs rely on
//! negative lookahead (e.g. `^\.(?!htaccess)`,
//! `^(?!robots\.txt$|ads\.txt$).*\.txt$`).
//!
//! ## What it does
//!
//! * Parses a raw rules snippet (the `<rewrite><rules>` text from a vhost, or
//!   the rewrite directives inside a `.htaccess`) into a [`RuleSet`] via
//!   [`RuleSet::parse`].
//! * Evaluates a [`RuleSet`] against a [`RewriteInput`] with
//!   [`evaluate`], implementing Apache's per-pass + restart-on-URI-change loop
//!   (bounded by [`MAX_ITERATIONS`]), honoring `[L]`, `[QSA]`, `[R=NNN]`, `[F]`,
//!   `[P]`, `[NC]`, `[NE]`, `[E=var:val]`, `[OR]`-chained conditions, the
//!   `-f/-d/-l/-s` file tests and lexical `<`/`>`/`=` comparisons, and the
//!   `%{...}` variable namespace (`REQUEST_FILENAME`, `REQUEST_URI`,
//!   `HTTP_HOST`, `HTTPS`, `REQUEST_METHOD`, `HTTP_USER_AGENT`, `QUERY_STRING`,
//!   `HTTP_COOKIE`, `HTTP:Header`, `THE_REQUEST`, `ENV:NAME`, ...).
//! * Parses the wider `.htaccess` directive set into [`Htaccess`]: `Header`
//!   ops, `ExpiresByType`, `DirectoryIndex`, `ErrorDocument`, `Options
//!   -Indexes`, the PHP handler-override directives `SetHandler
//!   application/x-httpd-php` / `AddHandler` / `AddType` (folded by
//!   [`php_handler_forced`] to force a file through lsphp regardless of its
//!   extension), `<Files>`/`<FilesMatch>`/
//!   `<DirectoryMatch>` access (allow/deny -> 403), `php_value`/`php_flag`
//!   passthrough, and `SetEnvIf`. LSCache vendor directives (`CacheLookup`,
//!   `CacheKeyModify`, `esi`, ...) are recognized as no-ops, but their
//!   `RewriteRule .* - [E=...]` side-effects still set env.
//! * Caches per-directory `.htaccess` files with mtime invalidation via
//!   [`HtaccessCache`].
//!
//! ## Integration
//!
//! The orchestrator's request pipeline should, per request:
//!
//! 1. For an inline vhost rewrite block: keep a [`RuleSet`] parsed once at
//!    config load and call [`evaluate`].
//! 2. For `.htaccess`: call [`HtaccessCache::load_chain`] to get the applicable
//!    `Arc<Htaccess>` chain, then evaluate each `.rules` in order and apply the
//!    recognized side directives.
//! 3. Translate the [`RewriteOutcome`] into pipeline actions: `Rewritten`
//!    updates the URI/query and re-dispatches; `Redirect` produces a 3xx;
//!    `Forbidden` produces a 403; `Proxy` hands `target_url` to `hj-proxy`;
//!    `env` mutations are written into `hj_core::ReqCtx::set_env`.
//!
//! This crate is intentionally synchronous and does no I/O of its own except
//! the optional `stat`/`.htaccess` reads behind [`RewriteInput`] /
//! [`HtaccessCache`]; it is cheap to call on the hot path.

#![forbid(unsafe_code)]

pub mod auth;
mod cache;
mod directives;
mod error;
mod htaccess;
mod input;
mod rules;

pub use auth::AuthRealm;
pub use cache::HtaccessCache;
pub use directives::{AccessDecision, ErrorDoc, HeaderOp, ReqAttrs};
pub use error::RewriteError;
pub use htaccess::{
    AccessMatcher, AccessOrder, AccessRule, AccessSubject, CacheDirectives, CacheKeyModifier,
    HostAccess, HostEntry, Htaccess, MemoClass, ResolvedPhp, Scope, ScopeIndex, ScopeKind,
    cache_directives, chain_cacheable_for_default, php_directives, php_handler_forced,
};
pub use input::{FileTests, HeaderLookup, RewriteInput, StatSource};
pub use rules::{CacheKeyVar, RewriteOutcome, RuleSet, evaluate};

#[cfg(test)]
mod tests;
