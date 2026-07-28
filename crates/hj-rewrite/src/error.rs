//! Error type produced while parsing Apache `mod_rewrite` / `.htaccess` rules.

use thiserror::Error;

/// Errors raised by [`crate::RuleSet::parse`] and friends.
///
/// Parsing is intentionally lenient: unknown directives are *recorded* or
/// ignored rather than rejected (real-world `.htaccess` files are full of
/// vendor-specific directives). A `RewriteError` is only produced for things
/// that genuinely cannot be turned into an evaluable rule — most commonly an
/// invalid regular expression in a `RewriteRule`/`RewriteCond` pattern.
#[derive(Debug, Error)]
pub enum RewriteError {
    /// A `RewriteRule`/`RewriteCond` pattern failed to compile as a regex.
    #[error("invalid regex on line {line}: {pattern:?}: {source}")]
    BadRegex {
        line: usize,
        pattern: String,
        #[source]
        source: Box<fancy_regex::Error>,
    },

    /// A directive was structurally malformed (e.g. `RewriteRule` with no
    /// substitution).
    #[error("malformed directive on line {line}: {msg}")]
    Malformed { line: usize, msg: String },
}
