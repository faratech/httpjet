//! Regression: `normalize_query` must NOT collapse a bare param (`?a`) and an
//! empty-value param (`?a=`) to the same normalized form. They produced the
//! identical key before the fix (`split_once('=').unwrap_or((kv,""))` plus
//! "emit `=` only when non-empty"), so `/page?a=&b=` and `/page?a&b` keyed the
//! same — and the path-only identity guard could not tell them apart, so the
//! first URL cached would be served for both.

use hj_pagecache::key::normalize_query;

#[test]
fn bare_and_empty_value_do_not_collide() {
    // The core collision: differs ONLY in presence-of-`=`.
    assert_ne!(
        normalize_query("a=&b=", &[]),
        normalize_query("a&b", &[]),
        "?a=&b= and ?a&b must not normalize to the same cache key"
    );
}

#[test]
fn presence_of_equals_round_trips_distinctly() {
    // `a=` keeps its `=` (empty value); `a` stays bare.
    assert_eq!(normalize_query("a=", &[]), "a=");
    assert_eq!(normalize_query("a", &[]), "a");
    // And in combination, each token keeps its own form.
    assert_eq!(normalize_query("a=&b=", &[]), "a=&b=");
    assert_eq!(normalize_query("a&b", &[]), "a&b");
    // Mixed forms preserve each token independently.
    assert_eq!(normalize_query("a&b=", &[]), "a&b=");
}
