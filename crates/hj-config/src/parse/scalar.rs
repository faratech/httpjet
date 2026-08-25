//! Scalar / unit helpers: string → typed value conversions used throughout the
//! parse layer. These are all pure functions with no side effects.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use crate::model::{AccessRule, ContextKind, ExtAddress};
use crate::units::{parse_bytes, parse_secs, split_list};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub(super) fn truthy(s: &Option<String>) -> bool {
    matches!(s.as_deref().map(str::trim), Some(v) if v == "1" || v == "2" || v.eq_ignore_ascii_case("true"))
}

/// Parse a `followSymbolLink` / `allowSymbolLink` value into "follow symlinks?".
///
/// LiteSpeed/OLS treat these as a TRI-STATE (`getLongValue(..,0,2)`): `0` = never, `1` = always,
/// `2` = follow only when the link's target owner matches the link's owner (a hardening mode
/// against attacker-planted symlinks). httpjet's static resolver (`open_beneath`) has no
/// owner-match path yet, so the secure mode `2` is mapped to **never-follow** (strictly safer /
/// fail-closed) rather than via the generic [`truthy`], which silently widened `2` to follow
/// UNCONDITIONALLY — the LEAST restrictive option, the exact opposite of what `2` requests. Only
/// `1`/`true` follows. (Full owner-restricted support is a follow-up; until then declining `2`
/// can never serve a planted out-of-tree symlink.) (#90)
pub(super) fn follow_symlink_value(s: &Option<String>) -> bool {
    matches!(s.as_deref().map(str::trim), Some(v) if v == "1" || v.eq_ignore_ascii_case("true"))
}

/// LSWS tri-state for `<allowSymbolLink>`-class knobs: `Some(explicit)` only when the
/// tag is PRESENT (`0` → false; `1`/`true` → true; `2` → false per [`follow_symlink_value`]'s
/// fail-closed #90 mapping); `None` when absent = INHERIT the server-wide default.
/// The old merge OR-ed this bool into the server value, so an explicit hardening `0`
/// could never disable following (audit M4).
pub(super) fn symlink_override(s: &Option<String>) -> Option<bool> {
    if s.is_some() {
        Some(follow_symlink_value(s))
    } else {
        None
    }
}

pub(super) fn u8_of(s: &Option<String>) -> u8 {
    s.as_deref()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0)
}

pub(super) fn u32_of(s: &Option<String>, default: u32) -> u32 {
    s.as_deref()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

/// LiteSpeed size literal (`50M`, `2G`, `10K`, bare bytes; trailing `B` allowed).
/// Unparsable/absent ⇒ `default`.
pub(super) fn lsws_size(s: &Option<String>, default: u64) -> u64 {
    let Some(v) = s.as_deref().map(str::trim).filter(|v| !v.is_empty()) else {
        return default;
    };
    let (digits, mult) = match v.as_bytes().last() {
        Some(b'M' | b'm') => (&v[..v.len() - 1], 1u64 << 20),
        Some(b'G' | b'g') => (&v[..v.len() - 1], 1u64 << 30),
        Some(b'K' | b'k') => (&v[..v.len() - 1], 1u64 << 10),
        Some(b'B' | b'b') if v.len() > 1 => (&v[..v.len() - 1], 1u64),
        _ => (v, 1u64),
    };
    digits
        .trim()
        .parse::<u64>()
        .map(|n| n.saturating_mul(mult))
        .unwrap_or(default)
}

/// Parse a bounded integer the way LiteSpeed's `ConfigCtx::getLongValue`
/// does: when the tag is absent, unparsable, or **out of the `[min, max]`
/// range**, fall back to `default` (LiteSpeed logs a warning and uses the
/// default; it does NOT clamp). See OLS `src/main/configctx.cpp:134`.
pub(super) fn bounded_u8(s: &Option<String>, min: u8, max: u8, default: u8) -> u8 {
    match s
        .as_deref()
        .map(str::trim)
        .and_then(|v| v.parse::<i64>().ok())
    {
        Some(v) if v >= min as i64 && v <= max as i64 => v as u8,
        _ => default,
    }
}

/// Like [`bounded_u8`] but `max` is treated as an upper clamp (mirrors OLS's
/// `max == INT_MAX` branch): values above `max` are clamped to `max`, values
/// below `min` fall back to `default`.
pub(super) fn bounded_u32_clamp_max(s: &Option<String>, min: u32, default: u32) -> u32 {
    match s
        .as_deref()
        .map(str::trim)
        .and_then(|v| v.parse::<i64>().ok())
    {
        Some(v) if v >= min as i64 => {
            if v > u32::MAX as i64 {
                u32::MAX
            } else {
                v as u32
            }
        }
        _ => default,
    }
}

pub(super) fn secs_of(s: &Option<String>, default: u64) -> Duration {
    Duration::from_secs(s.as_deref().and_then(parse_secs).unwrap_or(default))
}

pub(super) fn bytes_of(s: &Option<String>, default: u64) -> u64 {
    s.as_deref().and_then(parse_bytes).unwrap_or(default)
}

pub(super) fn nonempty(s: Option<String>) -> Option<String> {
    s.map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

/// Parse an `expiresByType` value: `image/*=A604800, text/css=A604800, ...`
pub(super) fn parse_expires_by_type(s: &str) -> Vec<(String, String)> {
    s.split(',')
        .filter_map(|pair| {
            let (t, v) = pair.split_once('=')?;
            let (t, v) = (t.trim(), v.trim());
            if t.is_empty() || v.is_empty() {
                None
            } else {
                Some((t.to_string(), v.to_string()))
            }
        })
        .collect()
}

/// Parse `<allow>`/`<deny>` text: `ALL, 1.2.3.0/24T, 5.6.7.0/24` → access rules.
///
/// OLS `AccessControl::checkTrust` (accesscontrol.cpp:472) strips a trailing
/// `T`/`t` from every entry, but only *upgrades* the entry to the TRUST level
/// when the entry came from the `<allow>` list (`if (allowed) allowed =
/// AC_TRUST`). A `T` on a `<deny>` entry is therefore stripped and otherwise
/// ignored — the network is plainly denied, never trusted. We mirror that:
/// `trusted` is only ever set on allow rules.
pub(super) fn parse_access(spec: &str, allow: bool) -> Vec<AccessRule> {
    split_list(spec)
        .into_iter()
        .map(|raw| {
            // The trailing T is stripped regardless of allow/deny, matching
            // checkTrust, so the CIDR/keyword is clean either way.
            let has_t = (raw.ends_with('T') || raw.ends_with('t')) && raw.len() > 1;
            let spec = if has_t {
                raw[..raw.len() - 1].to_string()
            } else {
                raw
            };
            // ...but only an allow entry becomes a trusted network.
            let trusted = has_t && allow;
            AccessRule {
                spec,
                trusted,
                allow,
            }
        })
        .collect()
}

pub(super) fn parse_env_pair(s: &str) -> Option<(String, String)> {
    let (k, v) = s.split_once('=')?;
    Some((k.trim().to_string(), v.trim().to_string()))
}

pub(super) fn ext_address(addr: &str) -> ExtAddress {
    let addr = addr.trim();
    if let Some(rest) = addr.strip_prefix("uds://") {
        // LiteSpeed writes UDS paths without a leading slash after the scheme.
        let p = if rest.starts_with('/') {
            rest.to_string()
        } else {
            format!("/{rest}")
        };
        ExtAddress::Uds(PathBuf::from(p))
    } else if let Ok(sa) = addr.parse::<SocketAddr>() {
        ExtAddress::Tcp(sa)
    } else {
        ExtAddress::HostPort(addr.to_string())
    }
}

pub(super) fn context_kind(s: &Option<String>) -> ContextKind {
    match s.as_deref().map(str::trim) {
        Some("proxy") => ContextKind::Proxy,
        Some("lsapi") => ContextKind::Lsapi,
        Some("cgi") => ContextKind::Cgi,
        Some("rails") | Some("appserver") => ContextKind::AppServer,
        Some("redirect") => ContextKind::Redirect,
        Some("static") | Some("") | None => ContextKind::Static,
        Some(_) => ContextKind::Other,
    }
}

/// Parse newline-delimited `extraHeaders` text into (name, value) pairs.
pub(super) fn parse_extra_headers(s: &str) -> Vec<(String, String)> {
    s.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }
            let (k, v) = line.split_once(':')?;
            Some((k.trim().to_string(), v.trim().to_string()))
        })
        .collect()
}

/// `addDefaultCharset` accepts `on`/`1`/`true` (true) and `off`/`0`/absent
/// (false). Distinct from [`truthy`] because the live configs use `on`/`off`.
pub(super) fn charset_on(s: &Option<String>) -> bool {
    matches!(
        s.as_deref().map(str::trim),
        Some(v) if v.eq_ignore_ascii_case("on")
            || v == "1"
            || v.eq_ignore_ascii_case("true")
            || v.eq_ignore_ascii_case("yes")
    )
}

/// Parse a `cacheStatusCode` value like `"200,301"` into a sorted, de-duped
/// list. Falls back to LiteSpeed's default `[200, 301]` when empty/invalid.
pub(super) fn parse_cacheable_status(s: &str) -> Vec<u16> {
    let mut codes: Vec<u16> = s
        .split(',')
        .filter_map(|t| t.trim().parse::<u16>().ok())
        .collect();
    codes.sort_unstable();
    codes.dedup();
    if codes.is_empty() {
        vec![200, 301]
    } else {
        codes
    }
}

/// Parse a positive integer (e.g. `procSoftLimit`). `0`, absent, or garbage
/// yields `None` ("inherit / no limit").
pub(super) fn parse_pos_u64(s: &str) -> Option<u64> {
    s.trim().parse::<u64>().ok().filter(|&n| n > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> Option<String> {
        Some(v.to_string())
    }

    #[test]
    fn follow_symlink_value_declines_owner_restricted_mode_2() {
        // Regression (#90): `2` (owner-restricted follow) must NOT be silently widened to
        // follow-unconditionally. Only `1`/`true` follows; `2`/`0`/absent do not. `truthy`
        // (the generic bool parser) DOES treat `2` as true — these two must differ on `2`.
        assert!(follow_symlink_value(&s("1")));
        assert!(follow_symlink_value(&s("true")));
        assert!(follow_symlink_value(&s(" 1 ")));
        assert!(
            !follow_symlink_value(&s("2")),
            "owner-restricted mode 2 must fail-closed (never-follow)"
        );
        assert!(!follow_symlink_value(&s("0")));
        assert!(!follow_symlink_value(&None));
        // Contrast: the generic truthy() still treats 2 as true (used elsewhere).
        assert!(truthy(&s("2")));
        assert!(follow_symlink_value(&s("2")) != truthy(&s("2")));
    }
}
