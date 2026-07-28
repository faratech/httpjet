//! Expires / Cache-Control emission helper.
//!
//! This mirrors LiteSpeed / OpenLiteSpeed's `expiresByType` (a.k.a. the
//! `<expires>` block) behavior so the pipeline can emit byte-identical
//! `Cache-Control` and `Expires` headers.
//!
//! ## Ground truth (OLS)
//!
//! - **Spec format** — `ExpiresCtrl::parse` (src/http/expiresctrl.cpp:52). A
//!   per-type value is `<base><seconds>` where `base` is a single letter:
//!   `A`/`a` = access-relative (now + seconds), `M`/`m` = modification-relative
//!   (last-modified + seconds). The live config uses the compact numeric form
//!   (`A604800`). OLS also accepts the verbose Apache form
//!   (`access plus 1 week`), which this helper additionally supports.
//! - **Header emission** — `HttpResp::addExpiresHeader`
//!   (src/http/httpresp.cpp:101). It emits **both** headers
//!   (`Cache-Control: public, max-age=<age>` and `Expires: <RFC1123 date>`)
//!   and computes them as:
//!
//!   - `A` (access): `age = seconds`,            `expire = now + seconds`
//!   - `M` (modify): `expire = last_modified + seconds`, `age = expire - now`
//!     (note: `age` may be **negative** for an already-stale modify rule; OLS
//!     prints it verbatim with `%d`, so we do too).
//! - **Suppression** — if the response already carries `Cache-Control` OR
//!   `Expires`, OLS emits nothing (returns early). The pipeline must honor that.
//! - **Type matching** — `expiresByType` globs use the same MIME wildcard rules
//!   as compressible types: `type/*` matches a whole type group, `*` (or `*/*`)
//!   matches everything, otherwise an exact `type/subtype` match
//!   (src/http/httpmime.cpp:504, MIMEMap::updateMIME). Matching ignores any
//!   `; charset=...` parameter and is case-insensitive.
//!
//! ## What the orchestrator must do
//!
//! 1. Only when `ExpiresConfig::enabled` is true.
//! 2. Find the first `by_type` entry whose glob matches the response
//!    `Content-Type` (see [`ExpiresRules::lookup`]). The live config order is
//!    significant: the first match wins, matching OLS's per-MIME assignment.
//! 3. If a rule matches, call [`ExpiresHeaders::compute`] with the rule, "now",
//!    and the resource's `Last-Modified` (for `M` rules), then set the two
//!    headers — **but only if neither `Cache-Control` nor `Expires` is already
//!    present** on the response.

/// The reference base for an expires rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpiresBase {
    /// `A` — relative to the access time (request time / "now").
    Access,
    /// `M` — relative to the resource's last-modified time.
    Modify,
}

/// A parsed per-type expires rule: a base and an age in seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpiresRule {
    pub base: ExpiresBase,
    /// Configured age in seconds. Always non-negative as parsed.
    pub age_secs: i64,
}

impl ExpiresRule {
    /// Parse an OLS `expiresByType` value such as `A604800` or `M2592000`, or
    /// the verbose Apache form `access plus 1 week 3 days`.
    ///
    /// Returns `None` for malformed input (matching OLS `parse()` returning
    /// `LS_FAIL`, in which case the rule is ignored).
    pub fn parse(value: &str) -> Option<ExpiresRule> {
        let s = value.trim().trim_matches(|c| c == '"' || c == '\'').trim();
        if s.is_empty() {
            return None;
        }

        // Compact numeric form: a single base letter immediately followed by a
        // digit, e.g. `A604800`. OLS checks `isdigit(*(p+1))`.
        let bytes = s.as_bytes();
        if bytes.len() >= 2 && bytes[1].is_ascii_digit() {
            let base = match bytes[0] {
                b'A' | b'a' => ExpiresBase::Access,
                b'M' | b'm' => ExpiresBase::Modify,
                _ => return None,
            };
            let age: i64 = s[1..].parse().ok()?;
            return Some(ExpiresRule {
                base,
                age_secs: age,
            });
        }

        // Verbose form: `access|now|modification [plus] N unit [N unit ...]`.
        Self::parse_verbose(s)
    }

    fn parse_verbose(s: &str) -> Option<ExpiresRule> {
        let mut toks = s.split_whitespace();
        let first = toks.next()?.to_ascii_lowercase();
        let base = match first.as_str() {
            "access" | "now" => ExpiresBase::Access,
            "modification" => ExpiresBase::Modify,
            _ => return None,
        };

        let mut rest: Vec<&str> = toks.collect();
        if rest.first().map(|t| t.eq_ignore_ascii_case("plus")) == Some(true) {
            rest.remove(0);
        }
        if rest.is_empty() {
            return None;
        }

        // Consume `N unit` pairs and accumulate seconds.
        let mut total: i64 = 0;
        let mut i = 0;
        while i + 1 < rest.len() + 1 {
            let num = rest.get(i)?;
            let n: i64 = num.parse().ok()?;
            let unit = rest.get(i + 1)?;
            let factor = unit_to_seconds(unit)?;
            // Checked arithmetic: an absurdly large value in trusted operator
            // config must not silently wrap to zero/negative in release builds.
            let product = n.checked_mul(factor)?;
            total = total.checked_add(product)?;
            i += 2;
            if i >= rest.len() {
                break;
            }
        }
        // If the loop didn't consume an even number of tokens, it's malformed.
        if i != rest.len() {
            return None;
        }
        Some(ExpiresRule {
            base,
            age_secs: total,
        })
    }
}

/// Apache/OLS time-unit factors (src/http/expiresctrl.cpp:116-141).
fn unit_to_seconds(unit: &str) -> Option<i64> {
    let u = unit.to_ascii_lowercase();
    let first = u.as_bytes().first().copied()?;
    let secs = match first {
        b'y' => 3600 * 24 * 365,
        b'w' => 3600 * 24 * 7,
        b'd' => 3600 * 24,
        b'h' => 3600,
        b's' => 1,
        b'm' => {
            // `mo*` = month (30 days), `mi*` = minute.
            match u.as_bytes().get(1).copied() {
                Some(b'o') => 3600 * 24 * 30,
                Some(b'i') => 60,
                _ => return None,
            }
        }
        _ => return None,
    };
    Some(secs)
}

/// The computed header pair for a matched expires rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiresHeaders {
    /// `Cache-Control` value, e.g. `public, max-age=604800`.
    pub cache_control: String,
    /// Absolute UNIX expiry time (seconds since epoch) for the `Expires`
    /// header. The pipeline formats this as an RFC 1123 date.
    pub expire_unix: i64,
    /// The `max-age` value as emitted (may be negative for stale `M` rules).
    pub max_age: i64,
}

impl ExpiresHeaders {
    /// Compute the `Cache-Control` / `Expires` pair exactly as OLS
    /// `HttpResp::addExpiresHeader` does.
    ///
    /// - `now_unix` is the current time (OLS `DateTime::s_curTime`).
    /// - `last_modified_unix` is the resource mtime; only used for `M` rules.
    ///   Pass `now_unix` (or anything) for `A` rules — it is ignored.
    pub fn compute(rule: ExpiresRule, now_unix: i64, last_modified_unix: i64) -> ExpiresHeaders {
        let (age, expire) = match rule.base {
            ExpiresBase::Access => {
                let age = rule.age_secs;
                (age, now_unix + age)
            }
            ExpiresBase::Modify => {
                let expire = last_modified_unix + rule.age_secs;
                let age = expire - now_unix;
                (age, expire)
            }
        };
        ExpiresHeaders {
            cache_control: format!("public, max-age={age}"),
            expire_unix: expire,
            max_age: age,
        }
    }
}

/// A compiled set of `expiresByType` rules with OLS MIME-glob matching.
///
/// Built from the parsed [`hj_config::model::ExpiresConfig::by_type`] pairs
/// (`(glob, "A604800")`). The orchestrator builds this once per context and
/// calls [`ExpiresRules::lookup`] per response.
#[derive(Debug, Clone, Default)]
pub struct ExpiresRules {
    /// `(matcher, rule)` pairs in configuration order (first match wins).
    entries: Vec<(TypeGlob, ExpiresRule)>,
}

impl ExpiresRules {
    /// Build from `(type-glob, value)` pairs as parsed from `expiresByType`.
    /// Malformed values are skipped (matching OLS, which logs and ignores).
    pub fn from_pairs<I, S>(pairs: I) -> ExpiresRules
    where
        I: IntoIterator<Item = (S, S)>,
        S: AsRef<str>,
    {
        let mut entries = Vec::new();
        for (glob, value) in pairs {
            if let Some(rule) = ExpiresRule::parse(value.as_ref()) {
                entries.push((TypeGlob::new(glob.as_ref()), rule));
            }
        }
        ExpiresRules { entries }
    }

    /// Find the first rule whose glob matches `content_type` (parameters and
    /// case ignored). Returns `None` if no rule applies.
    pub fn lookup(&self, content_type: &str) -> Option<ExpiresRule> {
        let base = ct_base(content_type).to_ascii_lowercase();
        if base.is_empty() {
            // OLS still matches a bare `*` rule even with no subtype context,
            // but in practice an empty content-type yields no MIME setting.
            return self
                .entries
                .iter()
                .find(|(g, _)| g.is_any())
                .map(|(_, r)| *r);
        }
        self.entries
            .iter()
            .find(|(g, _)| g.matches(&base))
            .map(|(_, r)| *r)
    }

    /// Number of compiled rules.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// A single MIME glob: `*`/`*/*` (any), `type/*` (prefix), or exact.
#[derive(Debug, Clone)]
enum TypeGlob {
    Any,
    Prefix(String),
    Exact(String),
}

impl TypeGlob {
    fn new(glob: &str) -> TypeGlob {
        let g = glob.trim().to_ascii_lowercase();
        if g == "*" || g == "*/*" {
            TypeGlob::Any
        } else if let Some(prefix) = g.strip_suffix("/*") {
            TypeGlob::Prefix(format!("{prefix}/"))
        } else {
            TypeGlob::Exact(g)
        }
    }

    fn is_any(&self) -> bool {
        matches!(self, TypeGlob::Any)
    }

    fn matches(&self, base_lower: &str) -> bool {
        match self {
            TypeGlob::Any => true,
            TypeGlob::Prefix(p) => base_lower.starts_with(p.as_str()),
            TypeGlob::Exact(e) => e == base_lower,
        }
    }
}

/// Strip a `;`-delimited parameter and surrounding whitespace from a
/// content-type.
fn ct_base(ct: &str) -> &str {
    ct.split(';').next().unwrap_or("").trim()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_compact_access() {
        let r = ExpiresRule::parse("A604800").unwrap();
        assert_eq!(r.base, ExpiresBase::Access);
        assert_eq!(r.age_secs, 604800);
    }

    #[test]
    fn parse_compact_modify_and_lowercase() {
        let r = ExpiresRule::parse("m2592000").unwrap();
        assert_eq!(r.base, ExpiresBase::Modify);
        assert_eq!(r.age_secs, 2592000);
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(ExpiresRule::parse("").is_none());
        assert!(ExpiresRule::parse("X100").is_none());
        assert!(ExpiresRule::parse("A").is_none()); // no digit after base
        assert!(ExpiresRule::parse("abc").is_none());
    }

    #[test]
    fn parse_verbose_apache_form() {
        // access plus 1 week == 604800
        let r = ExpiresRule::parse("access plus 1 week").unwrap();
        assert_eq!(r.base, ExpiresBase::Access);
        assert_eq!(r.age_secs, 604800);

        // modification plus 1 month 2 days
        let r = ExpiresRule::parse("modification plus 1 month 2 days").unwrap();
        assert_eq!(r.base, ExpiresBase::Modify);
        assert_eq!(r.age_secs, 3600 * 24 * 30 + 2 * 3600 * 24);

        // "now" is an alias for access; "plus" is optional.
        let r = ExpiresRule::parse("now 30 minutes").unwrap();
        assert_eq!(r.base, ExpiresBase::Access);
        assert_eq!(r.age_secs, 30 * 60);
    }

    #[test]
    fn compute_access_rule() {
        // A604800 at now=1000 => max-age=604800, expire=605800.
        let rule = ExpiresRule::parse("A604800").unwrap();
        let h = ExpiresHeaders::compute(rule, 1000, 500);
        assert_eq!(h.cache_control, "public, max-age=604800");
        assert_eq!(h.max_age, 604800);
        assert_eq!(h.expire_unix, 1000 + 604800);
    }

    #[test]
    fn compute_modify_rule() {
        // M1000 with last_modified=500, now=1000:
        // expire = 500 + 1000 = 1500; age = 1500 - 1000 = 500.
        let rule = ExpiresRule {
            base: ExpiresBase::Modify,
            age_secs: 1000,
        };
        let h = ExpiresHeaders::compute(rule, 1000, 500);
        assert_eq!(h.expire_unix, 1500);
        assert_eq!(h.max_age, 500);
        assert_eq!(h.cache_control, "public, max-age=500");
    }

    #[test]
    fn compute_modify_rule_can_go_negative() {
        // Stale modify rule: last_modified far in the past.
        // M10 with last_modified=0, now=1000: expire=10, age=10-1000=-990.
        let rule = ExpiresRule {
            base: ExpiresBase::Modify,
            age_secs: 10,
        };
        let h = ExpiresHeaders::compute(rule, 1000, 0);
        assert_eq!(h.max_age, -990);
        // OLS prints the negative age verbatim via "%d".
        assert_eq!(h.cache_control, "public, max-age=-990");
    }

    #[test]
    fn rules_lookup_live_config() {
        // Mirrors the live httpd_config.xml expiresByType, including wildcard +
        // exact entries.
        let rules = ExpiresRules::from_pairs([
            ("image/*", "A604800"),
            ("text/css", "A604800"),
            ("application/x-javascript", "A604800"),
            ("application/javascript", "A604800"),
            ("font/*", "A604800"),
            ("application/x-font-ttf", "A604800"),
        ]);
        assert_eq!(rules.len(), 6);

        // image/* wildcard.
        assert_eq!(rules.lookup("image/png").unwrap().age_secs, 604800);
        assert_eq!(
            rules.lookup("image/jpeg").unwrap().base,
            ExpiresBase::Access
        );
        // exact text/css (charset param ignored).
        assert_eq!(
            rules.lookup("text/css; charset=utf-8").unwrap().age_secs,
            604800
        );
        // font/* wildcard.
        assert!(rules.lookup("font/woff2").is_some());
        // exact application/x-font-ttf.
        assert!(rules.lookup("application/x-font-ttf").is_some());
        // Not configured => no rule.
        assert!(rules.lookup("text/html").is_none());
        assert!(rules.lookup("application/json").is_none());
    }

    #[test]
    fn rules_first_match_wins() {
        // A more-specific exact rule listed before a broader wildcard should
        // win for its exact type; the wildcard covers the rest.
        let rules = ExpiresRules::from_pairs([("image/svg+xml", "A100"), ("image/*", "A604800")]);
        assert_eq!(rules.lookup("image/svg+xml").unwrap().age_secs, 100);
        assert_eq!(rules.lookup("image/png").unwrap().age_secs, 604800);
    }

    #[test]
    fn rules_skip_malformed_values() {
        let rules = ExpiresRules::from_pairs([
            ("image/*", "A604800"),
            ("text/css", "bogus"), // skipped
        ]);
        assert_eq!(rules.len(), 1);
        assert!(rules.lookup("image/png").is_some());
        assert!(rules.lookup("text/css").is_none());
    }
}
