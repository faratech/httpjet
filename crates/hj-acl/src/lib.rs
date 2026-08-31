//! # hj-acl — Access control for httpjet
//!
//! This crate implements LiteSpeed-compatible access control:
//!
//! * **Peer IP allow/deny** evaluation from `<accessControl>` rules (`ALL`
//!   plus CIDRs), with the LiteSpeed *most-specific-rule-wins* precedence.
//! * **Trusted-proxy ("T" suffix) detection** — the Cloudflare authenticated
//!   origin ranges in this install are tagged trusted so their forwarded
//!   headers may be honored.
//! * **`useIpInProxyHeader` client-IP resolution** — the anti-spoofing logic
//!   for `X-Forwarded-For` / `CF-Connecting-IP`, including the `=2`
//!   "trusted-peer-only" mode used in production.
//! * **`accessDenyDir` filesystem globbing** — never serve a path under a
//!   denied directory (`/etc/*`, `$SERVER_ROOT/conf/*`, ...).
//!
//! ## Construction & use by the orchestrator
//!
//! Build once per [`ServerConfig`](hj_core::config::ServerConfig) from the
//! `security` block and keep it in an `Arc` for the lifetime of the server:
//!
//! ```
//! use hj_acl::AccessControl;
//! use hj_core::config::Security;
//!
//! let security = Security::default();
//! let acl = AccessControl::from_security(&security).unwrap();
//! ```
//!
//! Per request, in the accept/pipeline path:
//!
//! 1. `acl.check_peer(peer_ip)` — drop the connection on [`AclDecision::Deny`].
//! 2. `acl.resolve_client_ip(peer, &headers, cfg.use_ip_in_proxy_header, mtls_ok)`
//!    — the resulting IP is what you store in `ReqCtx::client_ip` and log.
//! 3. `acl.is_trusted(peer)` — to populate `ReqCtx::trusted_proxy`.
//! 4. After path resolution in the static handler:
//!    `acl.deny_dir_match(&resolved_path)` — return 403 if true.

pub mod throttle;
pub use throttle::ClientThrottle;

use std::net::IpAddr;
use std::path::Path;

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use http::HeaderMap;
use ipnet::IpNet;

use hj_core::config::Security;

/// The outcome of a peer-IP access check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclDecision {
    /// The peer is permitted to connect / be served.
    Allow,
    /// The peer is blocked — the caller should drop the connection or 403.
    Deny,
}

impl AclDecision {
    /// `true` if this decision is [`AclDecision::Allow`].
    #[inline]
    pub fn is_allowed(self) -> bool {
        matches!(self, AclDecision::Allow)
    }
}

/// A single parsed access-control matcher: either the catch-all `ALL` or a
/// CIDR network. Carries the `allow` verdict. The `trusted` ("T") flag is tracked
/// separately on [`AccessControl`] (`trusted_nets` for CIDR rules, `all_trusted`
/// for a trusted `ALL`), not on the rule.
#[derive(Debug, Clone)]
struct Rule {
    /// `None` means `ALL` (matches every IP, prefix length 0).
    net: Option<IpNet>,
    allow: bool,
}

impl Rule {
    /// Effective prefix length used for "most specific wins" ordering.
    /// `ALL` has length 0; a host CIDR has the full address width.
    #[inline]
    fn prefix_len(&self) -> u8 {
        match self.net {
            None => 0,
            Some(net) => net.prefix_len(),
        }
    }

    #[inline]
    fn matches(&self, ip: IpAddr) -> bool {
        match self.net {
            None => true,
            Some(net) => net_contains(&net, ip),
        }
    }
}

/// Access-control evaluator built from a server's [`Security`] block.
///
/// Cheap to clone-via-`Arc`; build once and share. All query methods are
/// read-only and `Sync`.
#[derive(Debug, Clone)]
pub struct AccessControl {
    /// Allow/deny rules, **sorted most-specific-first** (longest prefix first;
    /// `ALL` last). This lets [`check_peer`](Self::check_peer) take the first
    /// matching rule as authoritative. An `ALL` rule is always included when
    /// configured, so the loop always finds a match; no separate fallback is
    /// needed.
    rules: Vec<Rule>,
    /// Trusted ("T") networks only, for fast [`is_trusted`](Self::is_trusted).
    trusted_nets: Vec<IpNet>,
    /// A trusted catch-all (`allow ALL T`) marks EVERY peer trusted. Tracked separately because
    /// the `ALL` rule carries no CIDR to push into `trusted_nets`; without this the `T` on an
    /// `ALL` rule was silently dropped, so `is_trusted` returned false for all peers and forwarded
    /// client-IP headers were never honored under `useIpInProxyHeader=2`.
    all_trusted: bool,
    /// Compiled `accessDenyDir` globs.
    deny_globs: GlobSet,
}

impl AccessControl {
    /// Build an [`AccessControl`] from a [`Security`] block
    /// (`access_control` + `access_deny_dir`).
    ///
    /// Rule specs are parsed leniently: an unparseable CIDR is skipped with a
    /// warning rather than failing construction, mirroring LiteSpeed's
    /// tolerance of malformed config lines. A malformed `accessDenyDir` glob
    /// is the one fail-closed exception (#365): a skipped deny silently
    /// exposes exactly the tree the operator asked to protect, so it is a
    /// hard error — same philosophy as `--page-cache-shared-paths`.
    pub fn from_security(security: &Security) -> Result<Self, String> {
        let mut rules: Vec<Rule> = Vec::with_capacity(security.access_control.len());
        let mut trusted_nets: Vec<IpNet> = Vec::new();
        let mut all_trusted = false;

        for ar in &security.access_control {
            let spec = ar.spec.trim();
            if spec.eq_ignore_ascii_case("ALL") {
                // A trusted catch-all (`ALL T`) marks every peer trusted. Record it here — the
                // `ALL` rule has no CIDR for `trusted_nets`, so dropping `ar.trusted` (the old
                // behavior) silently lost the trust semantics for all peers.
                if ar.trusted {
                    all_trusted = true;
                }
                rules.push(Rule {
                    net: None,
                    allow: ar.allow,
                });
                continue;
            }

            match parse_cidr(spec) {
                Some(net) => {
                    if ar.trusted {
                        trusted_nets.push(net);
                    }
                    rules.push(Rule {
                        net: Some(net),
                        allow: ar.allow,
                    });
                }
                None => {
                    tracing::warn!(spec = %ar.spec, "hj-acl: ignoring unparseable access-control spec");
                }
            }
        }

        // Most-specific-first: longest prefix wins, `ALL` (len 0) sinks to the
        // bottom. Stable sort preserves config order among equal prefixes so
        // the *first-listed* of two equal-specificity rules stays first.
        rules.sort_by_key(|b| std::cmp::Reverse(b.prefix_len()));

        let deny_globs = build_deny_globs(&security.access_deny_dir)?;

        Ok(AccessControl {
            rules,
            trusted_nets,
            all_trusted,
            deny_globs,
        })
    }

    /// Evaluate the allow/deny verdict for a connecting peer.
    ///
    /// ## Precedence (LiteSpeed-compatible)
    ///
    /// The **most specific matching rule wins**. Rules are pre-sorted by CIDR
    /// prefix length (longest first), so the first rule that matches `ip` is
    /// authoritative; among rules with equal specificity the first-listed in
    /// config wins. `ALL` (prefix 0) is the least specific and therefore acts
    /// as the default/base verdict.
    ///
    /// If no rule matches at all the connection is **allowed** (LiteSpeed's
    /// open default when no access-control list is configured). In practice this
    /// path is only reached when there is no `ALL` rule; when `ALL` is present
    /// it is in `self.rules` (with prefix 0, sorted last) and always matches.
    ///
    /// This yields the familiar behavior: a base `allow ALL` with specific
    /// `deny <cidr>` entries blocks exactly those networks (first-deny within
    /// a network), and a base `deny ALL` with specific `allow <cidr>` entries
    /// permits only those networks.
    pub fn check_peer(&self, ip: IpAddr) -> AclDecision {
        // Canonicalize an IPv4-mapped IPv6 peer (`::ffff:a.b.c.d`) to its IPv4 form before
        // matching: configured CIDRs are address-family-strict, so on a dual-stack `[::]` listener
        // a `deny 1.2.3.0/24` would otherwise NOT match a v4 client arriving mapped — falling
        // through to the open default (fail-OPEN). Mirrors peer_purge.rs's canonicalization.
        let ip = ip.to_canonical();
        for rule in &self.rules {
            if rule.matches(ip) {
                return if rule.allow {
                    AclDecision::Allow
                } else {
                    AclDecision::Deny
                };
            }
        }
        // No rule matched (no access-control configured): LiteSpeed's open default.
        AclDecision::Allow
    }

    /// `true` if `ip` falls inside any network tagged trusted (`T` suffix) —
    /// e.g. the Cloudflare authenticated-origin ranges. Trusted peers are the
    /// only ones whose forwarded client-IP headers are honored under
    /// `useIpInProxyHeader=2`.
    pub fn is_trusted(&self, ip: IpAddr) -> bool {
        // A trusted catch-all (`allow ALL T`) trusts every peer.
        if self.all_trusted {
            return true;
        }
        // Canonicalize a v4-mapped v6 peer so family-strict CIDR matching works on a dual-stack
        // listener (see `check_peer`) — else a trusted CF v4 range fails to match a mapped peer
        // (fail-closed: real-IP resolution silently keeps the proxy IP).
        let ip = ip.to_canonical();
        self.trusted_nets.iter().any(|net| net_contains(net, ip))
    }

    /// Resolve the real client IP, applying `useIpInProxyHeader` semantics and
    /// guarding against `X-Forwarded-For` spoofing.
    ///
    /// * `peer` — the immediate TCP peer address.
    /// * `headers` — the request headers.
    /// * `use_ip_in_proxy_header` — server `useIpInProxyHeader`:
    ///   * `0` — never trust proxy headers; always return `peer`.
    ///   * `1` — always honor `X-Forwarded-For` (leftmost-untrusted) regardless
    ///     of peer. `CF-Connecting-IP` is **not** honored (OLS mode-1 parity).
    ///     Insecure-by-design; must not be used facing untrusted clients.
    ///   * `2` — honor a forwarded header **only when the peer is a trusted
    ///     proxy** (and, on TLS, only when mTLS validated). This is the
    ///     production setting and the safe default for any other value.
    ///   * `4` — always trust `X-Forwarded-For` (regardless of peer), ignore
    ///     `CF-Connecting-IP`, and take the **last (right-most)** valid XFF
    ///     entry — the LiteSpeed "use the IP from the proxy header, last hop"
    ///     mode for a fixed single-proxy front end.
    /// * `is_tls_mtls_ok` — for TLS connections, whether client-cert (mTLS)
    ///   verification against the configured CA succeeded. For plaintext
    ///   connections pass `true` (no mTLS gate applies). Under mode `2` a TLS
    ///   peer that has *not* passed mTLS is treated as untrusted.
    ///
    /// ## Header selection
    ///
    /// For modes 2/3: `CF-Connecting-IP` is preferred (single, authoritative
    /// value set by Cloudflare). Otherwise `X-Forwarded-For` is used: the chain
    /// is read **left to right** and we return the **left-most entry that is
    /// not itself one of our trusted proxies** — i.e. the original client, even
    /// if several trusted hops appended themselves. If every entry is trusted we
    /// fall back to the left-most entry; if the header is empty/garbage we fall
    /// back to `peer`. Mode 1 uses the same XFF semantics without `CF-Connecting-IP`.
    pub fn resolve_client_ip(
        &self,
        peer: IpAddr,
        headers: &HeaderMap,
        use_ip_in_proxy_header: u8,
        is_tls_mtls_ok: bool,
    ) -> IpAddr {
        // Canonicalize a v4-mapped v6 peer up front so the trust gate (`is_trusted(peer)`) and the
        // returned client IP are consistent with the family-strict CIDR matching (dual-stack
        // listener) — mirrors peer_purge.rs.
        let peer = peer.to_canonical();
        // Mode 4 is distinct from the honor/CF-priority path: it unconditionally trusts
        // `X-Forwarded-For` and takes the LAST valid entry, ignoring `CF-Connecting-IP`.
        if use_ip_in_proxy_header == 4 {
            return self.rightmost_valid_xff(headers).unwrap_or(peer);
        }

        // Mode 1: honor XFF from any peer, but only leftmost-untrusted XFF
        // semantics — NOT CF-Connecting-IP. OLS mode 1 does not give CF-header
        // privileges to untrusted peers; that is mode 2/3 only. Mode 1 is
        // insecure-by-design (trusts XFF without peer validation) and MUST NOT
        // be used facing untrusted clients; production uses mode 2.
        if use_ip_in_proxy_header == 1 {
            if let Some(ip) = self.leftmost_untrusted_xff(headers) {
                return ip;
            }
            return peer;
        }

        // Mode 2 (and any unknown value, fail-safe): trusted peer + mTLS required.
        let honor = match use_ip_in_proxy_header {
            0 => false,
            _ => self.is_trusted(peer) && is_tls_mtls_ok,
        };

        if !honor {
            return peer;
        }

        // Cloudflare's authoritative single-value header takes priority for
        // trusted peers (modes 2/3).
        if let Some(ip) = first_valid_ip(headers, "cf-connecting-ip") {
            return ip;
        }

        if let Some(ip) = self.leftmost_untrusted_xff(headers) {
            return ip;
        }

        peer
    }

    /// The last (right-most) parseable `X-Forwarded-For` address across all XFF header
    /// lines — the hop nearest this server. Used by `useIpInProxyHeader=4`. `None` if no
    /// XFF entry parses.
    fn rightmost_valid_xff(&self, headers: &HeaderMap) -> Option<IpAddr> {
        let mut last = None;
        for value in headers.get_all("x-forwarded-for").iter() {
            if let Ok(s) = value.to_str() {
                for part in s.split(',') {
                    if let Some(ip) = parse_ip(part.trim()) {
                        last = Some(ip);
                    }
                }
            }
        }
        last
    }

    /// Pick the left-most `X-Forwarded-For` entry that is not one of our own
    /// trusted proxies. Returns `None` if the header is absent or contains no
    /// parseable address.
    fn leftmost_untrusted_xff(&self, headers: &HeaderMap) -> Option<IpAddr> {
        // (#283) Fast paths before the per-entry trusted scans. (a) When EVERY
        // network is trusted there is no untrusted hop by construction: the
        // left-most entry is the answer and no CIDR scan may run at all.
        // (b) The Cloudflare shape is exactly ONE XFF entry — resolve it with a
        // single is_trusted check instead of entering the general walk.
        if self.all_trusted {
            return headers
                .get_all("x-forwarded-for")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .flat_map(|s| s.split(','))
                .filter_map(|p| parse_ip(p.trim()))
                .next();
        }
        {
            // Exactly one header VALUE that parses to exactly one IP: whether that
            // hop is trusted or not, it is both the only candidate and the
            // left-most — one is_trusted check replaces the general walk.
            let mut values = headers.get_all("x-forwarded-for").iter();
            if let (Some(v), None) = (values.next(), values.next()) {
                if let Ok(s) = v.to_str() {
                    let mut parts = s.split(',').filter_map(|p| parse_ip(p.trim()));
                    if let (Some(only), None) = (parts.next(), parts.next()) {
                        return Some(only);
                    }
                }
            }
        }
        let mut first_parsed: Option<IpAddr> = None;

        for value in headers.get_all("x-forwarded-for").iter() {
            let s = match value.to_str() {
                Ok(s) => s,
                Err(_) => continue,
            };
            for part in s.split(',') {
                if let Some(ip) = parse_ip(part.trim()) {
                    if first_parsed.is_none() {
                        first_parsed = Some(ip);
                    }
                    if !self.is_trusted(ip) {
                        return Some(ip);
                    }
                }
            }
        }

        // Every entry was a trusted hop (or only one entry): use the left-most.
        first_parsed
    }

    /// `true` if `resolved_path` matches any `accessDenyDir` glob and must not
    /// be served. The caller is expected to pass an already-resolved
    /// (canonicalized / variable-substituted) absolute path.
    ///
    /// Note the patterns are directory prefixes in LiteSpeed (`/etc/*`); a bare
    /// `*` segment does **not** cross `/` boundaries in globset by default, so
    /// for prefix semantics we also match the parent directory itself and any
    /// descendant. See [`build_deny_globs`].
    pub fn deny_dir_match(&self, resolved_path: &Path) -> bool {
        self.deny_globs.is_match(resolved_path)
    }

    /// True when any `accessDenyDir` rule is configured. Callers use this to decide
    /// whether the canonical (fd-verified) target path must be computed at all: with no
    /// rules the deny check can never fire, so hj-static can skip the per-resolve
    /// `/proc/self/fd` readlink entirely.
    pub fn has_deny_dirs(&self) -> bool {
        !self.deny_globs.is_empty()
    }
}

/// Build the compiled deny-dir [`GlobSet`].
///
/// LiteSpeed `accessDenyDir` entries are directory specs. A trailing `/*` (or
/// `/**`) means "this directory AND everything under it" (recursive); a BARE
/// directory denies ONLY the directory path itself, not its contents:
///
/// * `/etc/*`  → the directory `/etc` itself **and** `/etc/**` (recursive).
/// * `/`       → ONLY the filesystem-root path `/` (bare) — NOT every file under
///   it (a bare `<dir>/</dir>` ships in the stock config and must not 403 all
///   docroot traffic); `/ *` would be needed to deny the whole tree.
/// * a plain dir `/foo` → ONLY `/foo`; `/foo/*` → `/foo` and `/foo/**`.
///
/// globset's `literal_separator(true)` is enabled so a single `*` cannot leak
/// across `/`; recursion is expressed explicitly with `**`.
///
/// In addition to the configured dirs, a built-in **default** denies the
/// `.ht*` access-file family (`.htaccess`, `.htpasswd`, `.htgroups`, ...) at
/// any depth — LiteSpeed/Apache never serve these, so httpjet matches that even
/// when `<accessDenyDir>` is empty (the live config). The default only matches a
/// basename beginning with `.ht`, so ordinary files are never denied by it.
fn build_deny_globs(dirs: &[String]) -> Result<GlobSet, String> {
    let mut builder = GlobSetBuilder::new();

    // Built-in default: the `.ht*` family, anywhere in the tree. `**/.ht*`
    // matches `.ht*` at any nesting depth (the `**/` prefix matches zero or
    // more leading components, so a top-level `/web/.htaccess` matches too);
    // `.ht*` covers the bare-root `/.htaccess` form. `literal_separator(true)`
    // (see `add_glob`) keeps the trailing `*` from crossing a `/`, so only the
    // *basename* is matched — `.htfoo/bar.txt` is NOT denied, only the `.ht*`
    // file itself.
    // Case-INSENSITIVE: deny `.HTACCESS`/`.HtPasswd` too (defense-in-depth beyond
    // Apache's case-sensitive `^\.ht`; harmless on the case-sensitive FS here).
    add_glob_ci(&mut builder, "**/.ht*");
    add_glob_ci(&mut builder, ".ht*");

    // (security #262) Credential/config file classes that must never be served even
    // when an app drops them inside a docroot without its own protection. Same
    // basename-matched, any-depth, case-insensitive treatment as the `.ht*` family.
    add_glob_ci(&mut builder, "**/.env");
    add_glob_ci(&mut builder, ".env");
    add_glob_ci(&mut builder, "**/*.pem");
    add_glob_ci(&mut builder, "*.pem");
    add_glob_ci(&mut builder, "**/*.key");
    add_glob_ci(&mut builder, "*.key");
    add_glob_ci(&mut builder, "**/token*.json");
    add_glob_ci(&mut builder, "token*.json");
    add_glob_ci(&mut builder, "**/client_secret*.json");
    add_glob_ci(&mut builder, "client_secret*.json");
    // Whole-directory classes (basename match on the directory component): the OCI
    // CLI layout and VCS metadata. `**/.oci/**` covers every path under it at any
    // depth; `**/.git` alone would miss files INSIDE, hence the recursive form.
    add_glob_ci(&mut builder, "**/.oci/**");
    add_glob_ci(&mut builder, ".oci/**");
    add_glob_ci(&mut builder, "**/.git/**");
    add_glob_ci(&mut builder, ".git/**");

    for raw in dirs {
        let spec = raw.trim();
        if spec.is_empty() {
            continue;
        }

        // LiteSpeed semantics: a trailing `/*` (or `/**`) denies the directory
        // AND everything under it (recursive); a BARE directory denies ONLY the
        // directory path itself, not its contents. This distinction is
        // load-bearing — the stock config lists a bare `<dir>/</dir>` (deny the
        // filesystem-root path itself), which must NOT recursively deny every
        // docroot file. Treating a bare dir as recursive was a latent bug that
        // denied all traffic once `deny_dir_match` was actually wired in.
        let recursive = spec.ends_with("/*") || spec.ends_with("/**");
        let stem = spec
            .strip_suffix("/*")
            .or_else(|| spec.strip_suffix("/**"))
            .unwrap_or(spec)
            .trim_end_matches('/');

        // Special case: root.
        if stem.is_empty() {
            add_glob(&mut builder, "/")?; // the root path itself
            if recursive {
                add_glob(&mut builder, "/**")?; // only `/ *` denies the whole tree
            }
            continue;
        }

        // The directory path itself; plus everything under it only when recursive.
        add_glob(&mut builder, stem)?;
        if recursive {
            add_glob(&mut builder, &format!("{stem}/**"))?;
        }
    }

    builder
        .build()
        .map_err(|e| format!("hj-acl: deny-dir globset failed to compile: {e}"))
}

fn add_glob(builder: &mut GlobSetBuilder, pat: &str) -> Result<(), String> {
    // `literal_separator(true)`: a single `*` does NOT cross `/`, so it matches
    // within one path component only; recursion must be expressed explicitly
    // with `**`. This is what the deny-glob expansion above documents and relies
    // on — `stem/*` is one level, `stem/**` is recursive, and the built-in
    // `.ht*` default matches only a `.ht*` *basename* (never a `.htfoo/` subtree).
    match GlobBuilder::new(pat).literal_separator(true).build() {
        Ok(g) => {
            builder.add(g);
            Ok(())
        }
        Err(e) => Err(format!(
            "hj-acl: bad accessDenyDir pattern {pat:?}: {e} — fix or remove it; a skipped deny silently exposes the tree"
        )),
    }
}

/// Like [`add_glob`] but case-insensitive — used for the built-in `.ht*` default
/// so an uppercase/mixed-case access-file name (`.HTACCESS`) is also denied.
/// The patterns are compile-time constants known to compile; a failure is an
/// internal invariant break, not a config condition.
fn add_glob_ci(builder: &mut GlobSetBuilder, pat: &str) {
    let g = GlobBuilder::new(pat)
        .literal_separator(true)
        .case_insensitive(true)
        .build()
        .expect("built-in deny-dir glob must compile");
    builder.add(g);
}

/// Parse a CIDR or bare IP into an [`IpNet`]. A bare address becomes a host
/// route (`/32` or `/128`).
fn parse_cidr(spec: &str) -> Option<IpNet> {
    if let Ok(net) = spec.parse::<IpNet>() {
        return Some(net);
    }
    // Bare IP → host network.
    if let Ok(ip) = spec.parse::<IpAddr>() {
        let prefix = if ip.is_ipv4() { 32 } else { 128 };
        return IpNet::new(ip, prefix).ok();
    }
    None
}

/// Parse an IP address, tolerating an IPv6 zone id and surrounding brackets.
fn parse_ip(s: &str) -> Option<IpAddr> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    // Strip brackets from `[::1]` style and any `%zone` suffix.
    let s = s
        .strip_prefix('[')
        .and_then(|r| r.strip_suffix(']'))
        .unwrap_or(s);
    let s = s.split('%').next().unwrap_or(s);
    s.parse::<IpAddr>().ok()
}

/// First parseable IP from a single-valued header (e.g. `CF-Connecting-IP`).
fn first_valid_ip(headers: &HeaderMap, name: &str) -> Option<IpAddr> {
    let v = headers.get(name)?;
    let s = v.to_str().ok()?;
    parse_ip(s)
}

/// Family-aware containment check: an IPv4 network never contains an IPv6
/// address (and vice-versa). `ipnet`'s `contains` already enforces this, but we
/// keep a thin wrapper for clarity and to centralize the semantics.
#[inline]
fn net_contains(net: &IpNet, ip: IpAddr) -> bool {
    net.contains(&ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hj_core::config::AccessRule;
    use http::HeaderMap;
    use std::net::Ipv4Addr;

    /// The real Cloudflare ranges from this LiteSpeed install (allow ALL +
    /// trusted CF CIDRs).
    fn cf_security() -> Security {
        let cf = [
            "103.21.244.0/22",
            "103.22.200.0/22",
            "103.31.4.0/22",
            "104.16.0.0/12",
            "108.162.192.0/18",
            "131.0.72.0/22",
            "141.101.64.0/18",
            "162.158.0.0/15",
            "172.64.0.0/13",
            "173.245.48.0/20",
            "188.114.96.0/20",
            "190.93.240.0/20",
            "197.234.240.0/22",
            "198.41.128.0/17",
            "199.27.128.0/21",
        ];
        let mut rules = vec![AccessRule {
            spec: "ALL".into(),
            trusted: false,
            allow: true,
        }];
        for c in cf {
            rules.push(AccessRule {
                spec: c.into(),
                trusted: true,
                allow: true,
            });
        }
        Security {
            follow_symlink: false,
            access_deny_dir: vec![
                "/".into(),
                "/etc/*".into(),
                "/dev/*".into(),
                "/usr/local/lsws/conf/*".into(),
                "/usr/local/lsws/admin/conf/*".into(),
            ],
            access_control: rules,
            cgi_cpu_limit_secs: None,
            ..Default::default()
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn cf_range_trust() {
        let acl = AccessControl::from_security(&cf_security()).unwrap();
        // 173.245.48.0/20 covers 173.245.48.5.
        assert!(acl.is_trusted(ip("173.245.48.5")));
        // A few more from distinct ranges.
        assert!(acl.is_trusted(ip("104.16.0.1")));
        assert!(acl.is_trusted(ip("162.158.255.255")));
        // Public DNS — not Cloudflare.
        assert!(!acl.is_trusted(ip("8.8.8.8")));
        assert!(!acl.is_trusted(ip("1.1.1.1"))); // CF's resolver IP is NOT in the proxy ranges
    }

    #[test]
    fn allow_all_base_permits_everyone() {
        let acl = AccessControl::from_security(&cf_security()).unwrap();
        assert_eq!(acl.check_peer(ip("8.8.8.8")), AclDecision::Allow);
        assert_eq!(acl.check_peer(ip("173.245.48.5")), AclDecision::Allow);
    }

    #[test]
    fn most_specific_deny_wins_over_allow_all() {
        // allow ALL, but deny a specific /24.
        let sec = Security {
            follow_symlink: false,
            access_deny_dir: vec![],
            access_control: vec![
                AccessRule {
                    spec: "ALL".into(),
                    trusted: false,
                    allow: true,
                },
                AccessRule {
                    spec: "10.0.0.0/24".into(),
                    trusted: false,
                    allow: false,
                },
            ],
            cgi_cpu_limit_secs: None,
            ..Default::default()
        };
        let acl = AccessControl::from_security(&sec).unwrap();
        assert_eq!(acl.check_peer(ip("10.0.0.7")), AclDecision::Deny);
        assert_eq!(acl.check_peer(ip("10.0.1.7")), AclDecision::Allow);
        assert_eq!(acl.check_peer(ip("8.8.8.8")), AclDecision::Allow);
    }

    #[test]
    fn most_specific_allow_wins_over_deny_all() {
        // deny ALL, allow a specific host and a /16.
        let sec = Security {
            follow_symlink: false,
            access_deny_dir: vec![],
            access_control: vec![
                AccessRule {
                    spec: "ALL".into(),
                    trusted: false,
                    allow: false,
                },
                AccessRule {
                    spec: "192.168.0.0/16".into(),
                    trusted: false,
                    allow: true,
                },
                AccessRule {
                    spec: "203.0.113.9".into(),
                    trusted: false,
                    allow: true,
                },
            ],
            cgi_cpu_limit_secs: None,
            ..Default::default()
        };
        let acl = AccessControl::from_security(&sec).unwrap();
        assert_eq!(acl.check_peer(ip("192.168.5.5")), AclDecision::Allow);
        assert_eq!(acl.check_peer(ip("203.0.113.9")), AclDecision::Allow);
        assert_eq!(acl.check_peer(ip("203.0.113.10")), AclDecision::Deny);
        assert_eq!(acl.check_peer(ip("8.8.8.8")), AclDecision::Deny);
    }

    #[test]
    fn longest_prefix_wins_nested() {
        // allow /16, deny a /24 inside it, allow a /32 inside that.
        let sec = Security {
            follow_symlink: false,
            access_deny_dir: vec![],
            access_control: vec![
                AccessRule {
                    spec: "ALL".into(),
                    trusted: false,
                    allow: false,
                },
                AccessRule {
                    spec: "10.1.0.0/16".into(),
                    trusted: false,
                    allow: true,
                },
                AccessRule {
                    spec: "10.1.2.0/24".into(),
                    trusted: false,
                    allow: false,
                },
                AccessRule {
                    spec: "10.1.2.50/32".into(),
                    trusted: false,
                    allow: true,
                },
            ],
            cgi_cpu_limit_secs: None,
            ..Default::default()
        };
        let acl = AccessControl::from_security(&sec).unwrap();
        assert_eq!(acl.check_peer(ip("10.1.9.9")), AclDecision::Allow); // /16
        assert_eq!(acl.check_peer(ip("10.1.2.7")), AclDecision::Deny); // /24
        assert_eq!(acl.check_peer(ip("10.1.2.50")), AclDecision::Allow); // /32
        assert_eq!(acl.check_peer(ip("8.8.8.8")), AclDecision::Deny); // default
    }

    #[test]
    fn empty_acl_defaults_open() {
        let acl = AccessControl::from_security(&Security::default()).unwrap();
        assert_eq!(acl.check_peer(ip("8.8.8.8")), AclDecision::Allow);
        assert!(!acl.is_trusted(ip("8.8.8.8")));
    }

    fn xff(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", value.parse().unwrap());
        h
    }

    #[test]
    fn xff_mode_0_ignores_header() {
        let acl = AccessControl::from_security(&cf_security()).unwrap();
        let trusted_peer = ip("173.245.48.5");
        let h = xff("9.9.9.9");
        // Mode 0: always return peer, even from a trusted proxy.
        assert_eq!(
            acl.resolve_client_ip(trusted_peer, &h, 0, true),
            trusted_peer
        );
    }

    #[test]
    fn xff_mode_1_always_trusts_header() {
        let acl = AccessControl::from_security(&cf_security()).unwrap();
        let untrusted_peer = ip("8.8.8.8");
        let h = xff("9.9.9.9");
        // Mode 1: honor header regardless of peer trust.
        assert_eq!(
            acl.resolve_client_ip(untrusted_peer, &h, 1, true),
            ip("9.9.9.9")
        );
    }

    #[test]
    fn xff_mode_2_trusted_peer_honored() {
        let acl = AccessControl::from_security(&cf_security()).unwrap();
        let trusted_peer = ip("173.245.48.5");
        let h = xff("9.9.9.9");
        // Mode 2 + trusted peer + mTLS ok: honor the header.
        assert_eq!(
            acl.resolve_client_ip(trusted_peer, &h, 2, true),
            ip("9.9.9.9")
        );
    }

    #[test]
    fn xff_mode_2_untrusted_peer_rejected() {
        let acl = AccessControl::from_security(&cf_security()).unwrap();
        let untrusted_peer = ip("8.8.8.8");
        let h = xff("9.9.9.9");
        // Mode 2 + untrusted peer: ignore the (spoofed) header, return peer.
        assert_eq!(
            acl.resolve_client_ip(untrusted_peer, &h, 2, true),
            untrusted_peer
        );
    }

    #[test]
    fn xff_mode_2_tls_without_mtls_rejected() {
        let acl = AccessControl::from_security(&cf_security()).unwrap();
        let trusted_peer = ip("173.245.48.5");
        let h = xff("9.9.9.9");
        // Mode 2 + trusted peer but mTLS failed: do NOT honor header.
        assert_eq!(
            acl.resolve_client_ip(trusted_peer, &h, 2, false),
            trusted_peer
        );
    }

    #[test]
    fn xff_leftmost_untrusted_entry() {
        let acl = AccessControl::from_security(&cf_security()).unwrap();
        let trusted_peer = ip("173.245.48.5");
        // Real client, then two trusted CF hops appended on the right.
        let h = xff("203.0.113.7, 173.245.48.9, 162.158.1.1");
        assert_eq!(
            acl.resolve_client_ip(trusted_peer, &h, 2, true),
            ip("203.0.113.7")
        );
    }

    #[test]
    fn xff_skips_trusted_prefix_to_find_client() {
        let acl = AccessControl::from_security(&cf_security()).unwrap();
        let trusted_peer = ip("173.245.48.5");
        // Left-most is a trusted hop; the next is the real (untrusted) client.
        let h = xff("162.158.1.1, 203.0.113.7");
        assert_eq!(
            acl.resolve_client_ip(trusted_peer, &h, 2, true),
            ip("203.0.113.7")
        );
    }

    #[test]
    fn cf_connecting_ip_takes_priority() {
        let acl = AccessControl::from_security(&cf_security()).unwrap();
        let trusted_peer = ip("173.245.48.5");
        let mut h = HeaderMap::new();
        h.insert("cf-connecting-ip", "198.51.100.42".parse().unwrap());
        h.insert("x-forwarded-for", "203.0.113.7".parse().unwrap());
        assert_eq!(
            acl.resolve_client_ip(trusted_peer, &h, 2, true),
            ip("198.51.100.42")
        );
    }

    #[test]
    fn xff_garbage_falls_back_to_peer() {
        let acl = AccessControl::from_security(&cf_security()).unwrap();
        let trusted_peer = ip("173.245.48.5");
        let h = xff("not-an-ip, also-bad");
        assert_eq!(
            acl.resolve_client_ip(trusted_peer, &h, 2, true),
            trusted_peer
        );
    }

    #[test]
    fn xff_no_header_returns_peer() {
        let acl = AccessControl::from_security(&cf_security()).unwrap();
        let trusted_peer = ip("173.245.48.5");
        let h = HeaderMap::new();
        assert_eq!(
            acl.resolve_client_ip(trusted_peer, &h, 2, true),
            trusted_peer
        );
    }

    #[test]
    fn xff_all_entries_trusted_uses_leftmost() {
        let acl = AccessControl::from_security(&cf_security()).unwrap();
        let trusted_peer = ip("173.245.48.5");
        // Both hops are CF-trusted; no untrusted client present -> leftmost.
        let h = xff("162.158.1.1, 173.245.48.9");
        assert_eq!(
            acl.resolve_client_ip(trusted_peer, &h, 2, true),
            ip("162.158.1.1")
        );
    }

    #[test]
    fn xff_mode_4_takes_last_entry_from_any_peer() {
        let acl = AccessControl::from_security(&cf_security()).unwrap();
        // Untrusted peer, no mTLS: mode 4 still trusts XFF and takes the right-most entry.
        let untrusted_peer = ip("8.8.8.8");
        let h = xff("203.0.113.7, 198.51.100.9, 192.0.2.5");
        assert_eq!(
            acl.resolve_client_ip(untrusted_peer, &h, 4, false),
            ip("192.0.2.5"),
            "mode 4 selects the last (right-most) XFF entry"
        );
    }

    #[test]
    fn xff_mode_4_ignores_cf_connecting_ip() {
        let acl = AccessControl::from_security(&cf_security()).unwrap();
        let trusted_peer = ip("173.245.48.5");
        let mut h = HeaderMap::new();
        h.insert("cf-connecting-ip", "198.51.100.42".parse().unwrap());
        h.insert("x-forwarded-for", "203.0.113.7, 192.0.2.5".parse().unwrap());
        // Unlike modes 1/2, mode 4 does NOT consult CF-Connecting-IP.
        assert_eq!(
            acl.resolve_client_ip(trusted_peer, &h, 4, true),
            ip("192.0.2.5")
        );
    }

    #[test]
    fn xff_mode_4_no_header_returns_peer() {
        let acl = AccessControl::from_security(&cf_security()).unwrap();
        let peer = ip("8.8.8.8");
        assert_eq!(
            acl.resolve_client_ip(peer, &HeaderMap::new(), 4, true),
            peer
        );
    }

    #[test]
    fn deny_dir_root_bare_denies_only_root_not_contents() {
        // The stock config lists a BARE `<dir>/</dir>`. LiteSpeed denies only the
        // filesystem-root path itself with a bare entry — it must NOT recursively
        // deny docroot files (that would 403 ALL traffic, which was the bug once
        // `deny_dir_match` got wired into the pipeline). A recursive deny needs an
        // explicit `/*`.
        let acl = AccessControl::from_security(&cf_security()).unwrap();
        assert!(acl.deny_dir_match(Path::new("/"))); // the root path itself
        assert!(!acl.deny_dir_match(Path::new("/web/public_html/index.html")));
        assert!(!acl.deny_dir_match(Path::new("/web/public_html/robots.txt")));
        // `.ht*` default still applies regardless.
        assert!(acl.deny_dir_match(Path::new("/web/public_html/.htaccess")));
    }

    #[test]
    fn malformed_custom_deny_glob_is_a_hard_error_not_fail_open() {
        // (audit 2026-08-30 #365) A custom glob that fails to compile used to be
        // skipped with a warning — silently disabling exactly the deny the
        // operator meant to install. Construction must fail instead.
        let mut sec = cf_security();
        sec.access_deny_dir.push("/srv/secret[s/**".into());
        let Err(err) = AccessControl::from_security(&sec) else {
            panic!("an uncompilable custom deny glob must fail construction");
        };
        assert!(
            err.contains("/srv/secret[s"),
            "error names the pattern: {err}"
        );

        // The same config with the typo fixed constructs and denies normally.
        sec.access_deny_dir.pop();
        sec.access_deny_dir.push("/srv/secrets/**".into());
        let acl = AccessControl::from_security(&sec).unwrap();
        assert!(acl.deny_dir_match(Path::new("/srv/secrets/token.json")));
    }

    #[test]
    fn deny_dir_specific_globs() {
        // No root entry so non-denied paths pass.
        let sec = Security {
            follow_symlink: false,
            access_deny_dir: vec!["/etc/*".into(), "/usr/local/lsws/conf/*".into()],
            access_control: vec![],
            cgi_cpu_limit_secs: None,
            ..Default::default()
        };
        let acl = AccessControl::from_security(&sec).unwrap();

        assert!(acl.deny_dir_match(Path::new("/etc/passwd")));
        assert!(acl.deny_dir_match(Path::new("/etc/ssl/private/key.pem"))); // recursive
        assert!(acl.deny_dir_match(Path::new("/etc"))); // the dir itself
        assert!(acl.deny_dir_match(Path::new("/usr/local/lsws/conf/httpd_config.xml")));
        assert!(acl.deny_dir_match(Path::new("/usr/local/lsws/conf/vhosts/x.xml")));

        // Outside the denied trees.
        assert!(!acl.deny_dir_match(Path::new("/web/public_html/index.html")));
        assert!(!acl.deny_dir_match(Path::new("/usr/local/lsws/admin/index.html")));
        assert!(!acl.deny_dir_match(Path::new("/etcetera/file"))); // not /etc/*
    }

    #[test]
    fn deny_dir_ht_family_default() {
        // (M4) The `.ht*` family is denied by default for EVERY vhost — even when
        // `<accessDenyDir>` is empty (the live config) — matching LiteSpeed/Apache.
        let acl = AccessControl::from_security(&Security::default()).unwrap();
        // `.htaccess` / `.htpasswd` denied at any depth, including the bare root.
        assert!(acl.deny_dir_match(Path::new("/web/public_html/.htaccess")));
        assert!(acl.deny_dir_match(Path::new("/web/public_html/.htpasswd")));
        assert!(acl.deny_dir_match(Path::new("/web/public_html/sub/deep/.htpasswd")));
        assert!(acl.deny_dir_match(Path::new("/web/.htaccess")));
        assert!(acl.deny_dir_match(Path::new("/.htaccess")));
        // The default is basename-scoped: an ordinary file is NOT denied, and a
        // legitimately-named `.htfoo` directory's contents are NOT denied (the
        // `*` does not cross `/` under literal_separator).
        assert!(!acl.deny_dir_match(Path::new("/web/public_html/index.html")));
        assert!(!acl.deny_dir_match(Path::new("/web/public_html/normal.htm")));
        assert!(!acl.deny_dir_match(Path::new("/web/.htfoo/bar.txt")));
    }

    #[test]
    fn deny_dir_credential_file_classes_default() {
        // (security #262) Credential/config classes dropped into a docroot are denied
        // like the .ht* family: .env anywhere, key/pem material, token/client_secret
        // JSON, and the .oci / .git directory trees — at any depth, case-insensitively.
        let acl = AccessControl::from_security(&Security::default()).unwrap();
        for p in [
            "/web/stats/.env",
            "/web/ai/sub/.ENV",
            "/web/public_html/server.pem",
            "/web/public_html/deep/host.key",
            "/web/ai/token.json",
            "/web/ai/TOKEN2.json",
            "/web/ai/client_secret.json",
            "/web/ai/nested/client_secret_app.json",
            "/web/.oci/config",
            "/rootish/.git/config",
            "/web/app/.git/objects/ab/cdef",
        ] {
            assert!(acl.deny_dir_match(Path::new(p)), "{p} must be denied");
        }
        // Ordinary content is untouched.
        for p in [
            "/web/public_html/index.html",
            "/web/ai/tokens.txt",
            "/web/public_html/tokenizer.php",
            "/web/stats/envelope.png",
            "/web/public_html/keynote.html",
        ] {
            assert!(!acl.deny_dir_match(Path::new(p)), "{p} must NOT be denied");
        }
    }

    #[test]
    fn deny_dir_empty_config_only_denies_ht_family() {
        // The live config has an empty `<accessDenyDir>`. With no configured dirs,
        // ONLY the built-in `.ht*` default is active — ordinary docroot files are
        // served normally (no over-broad denies).
        let sec = Security {
            follow_symlink: false,
            access_deny_dir: vec![],
            access_control: vec![],
            cgi_cpu_limit_secs: None,
            ..Default::default()
        };
        let acl = AccessControl::from_security(&sec).unwrap();
        assert!(acl.deny_dir_match(Path::new("/web/public_html/.htaccess")));
        assert!(!acl.deny_dir_match(Path::new("/web/public_html/index.php")));
        assert!(!acl.deny_dir_match(Path::new("/web/public_html/assets/app.js")));
        assert!(!acl.deny_dir_match(Path::new("/etc/passwd"))); // no /etc rule configured
    }

    #[test]
    fn deny_dir_configured_glob_denies_matching_path() {
        // (M4) A configured `accessDenyDir` glob denies a matching path while
        // leaving non-matching paths servable; the `.ht*` default still applies.
        let sec = Security {
            follow_symlink: false,
            access_deny_dir: vec!["/web/app/secret/*".into()],
            access_control: vec![],
            cgi_cpu_limit_secs: None,
            ..Default::default()
        };
        let acl = AccessControl::from_security(&sec).unwrap();
        // The configured dir, its contents (one level), and recursively.
        assert!(acl.deny_dir_match(Path::new("/web/app/secret")));
        assert!(acl.deny_dir_match(Path::new("/web/app/secret/key.pem")));
        assert!(acl.deny_dir_match(Path::new("/web/app/secret/nested/db.conf")));
        // A sibling that merely shares a prefix is NOT denied.
        assert!(!acl.deny_dir_match(Path::new("/web/app/secretsauce.txt")));
        assert!(!acl.deny_dir_match(Path::new("/web/app/public/index.php")));
        // `.ht*` default coexists with the configured glob.
        assert!(acl.deny_dir_match(Path::new("/web/app/public/.htaccess")));
    }

    #[test]
    fn ipv4_net_does_not_match_ipv6() {
        let net: IpNet = "10.0.0.0/8".parse().unwrap();
        let v6 = IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1]);
        assert!(!net_contains(&net, v6));
    }

    #[test]
    fn ipv6_cidr_trust_and_check() {
        let sec = Security {
            follow_symlink: false,
            access_deny_dir: vec![],
            access_control: vec![
                AccessRule {
                    spec: "ALL".into(),
                    trusted: false,
                    allow: true,
                },
                AccessRule {
                    spec: "2400:cb00::/32".into(),
                    trusted: true,
                    allow: true,
                },
                AccessRule {
                    spec: "2001:db8::/32".into(),
                    trusted: false,
                    allow: false,
                },
            ],
            cgi_cpu_limit_secs: None,
            ..Default::default()
        };
        let acl = AccessControl::from_security(&sec).unwrap();
        assert!(acl.is_trusted(ip("2400:cb00::1")));
        assert!(!acl.is_trusted(ip("2001:db8::1")));
        assert_eq!(acl.check_peer(ip("2001:db8::1")), AclDecision::Deny);
        assert_eq!(acl.check_peer(ip("2400:cb00::1")), AclDecision::Allow);
    }

    #[test]
    fn bare_ip_spec_is_host_route() {
        let sec = Security {
            follow_symlink: false,
            access_deny_dir: vec![],
            access_control: vec![
                AccessRule {
                    spec: "ALL".into(),
                    trusted: false,
                    allow: true,
                },
                AccessRule {
                    spec: "203.0.113.9".into(),
                    trusted: false,
                    allow: false,
                },
            ],
            cgi_cpu_limit_secs: None,
            ..Default::default()
        };
        let acl = AccessControl::from_security(&sec).unwrap();
        assert_eq!(acl.check_peer(ip("203.0.113.9")), AclDecision::Deny);
        assert_eq!(acl.check_peer(ip("203.0.113.10")), AclDecision::Allow);
    }

    #[test]
    fn malformed_spec_is_skipped() {
        let sec = Security {
            follow_symlink: false,
            access_deny_dir: vec![],
            access_control: vec![
                AccessRule {
                    spec: "ALL".into(),
                    trusted: false,
                    allow: true,
                },
                AccessRule {
                    spec: "not-a-cidr".into(),
                    trusted: true,
                    allow: false,
                },
            ],
            cgi_cpu_limit_secs: None,
            ..Default::default()
        };
        let acl = AccessControl::from_security(&sec).unwrap();
        // Bad rule ignored; ALL allow stands; bad rule didn't register as trusted.
        assert_eq!(acl.check_peer(ip("8.8.8.8")), AclDecision::Allow);
        assert!(!acl.is_trusted(ip("8.8.8.8")));
    }

    #[test]
    fn xff_bracketed_ipv6_parsed() {
        assert_eq!(parse_ip("[2001:db8::1]"), Some(ip("2001:db8::1")));
        assert_eq!(parse_ip("fe80::1%eth0"), Some(ip("fe80::1")));
        assert_eq!(
            parse_ip("  10.0.0.1 "),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );
        assert_eq!(parse_ip(""), None);
    }

    #[test]
    fn ipv4_mapped_ipv6_peer_is_canonicalized() {
        // Regression (#91): a v4 client on a dual-stack [::] listener arrives as ::ffff:a.b.c.d.
        // A `deny 1.2.3.0/24` (v4 CIDR) must still match it — else check_peer falls through to
        // the open default (fail-OPEN). And a trusted CF v4 range must recognize the mapped peer.
        let sec = Security {
            follow_symlink: false,
            access_deny_dir: vec![],
            access_control: vec![
                AccessRule {
                    spec: "ALL".into(),
                    trusted: false,
                    allow: true,
                },
                AccessRule {
                    spec: "1.2.3.0/24".into(),
                    trusted: false,
                    allow: false,
                },
                AccessRule {
                    spec: "173.245.48.0/20".into(),
                    trusted: true,
                    allow: true,
                },
            ],
            cgi_cpu_limit_secs: None,
            ..Default::default()
        };
        let acl = AccessControl::from_security(&sec).unwrap();
        // Mapped form of a denied v4 address must be denied (was fail-open).
        assert_eq!(acl.check_peer(ip("::ffff:1.2.3.5")), AclDecision::Deny);
        assert_eq!(acl.check_peer(ip("1.2.3.5")), AclDecision::Deny);
        // Mapped form of a trusted CF v4 address must be trusted (was fail-closed).
        assert!(acl.is_trusted(ip("::ffff:173.245.48.9")));
        assert!(acl.is_trusted(ip("173.245.48.9")));
        // A mapped, non-denied address is still allowed.
        assert_eq!(acl.check_peer(ip("::ffff:8.8.8.8")), AclDecision::Allow);
    }

    #[test]
    fn trusted_all_catch_all_marks_every_peer_trusted() {
        // Regression (#92): `allow ALL T` (trusted catch-all) must make is_trusted true for every
        // peer — the `T` on an ALL rule was previously dropped, so forwarded client-IP headers
        // were never honored under useIpInProxyHeader=2.
        let sec = Security {
            follow_symlink: false,
            access_deny_dir: vec![],
            access_control: vec![AccessRule {
                spec: "ALL".into(),
                trusted: true,
                allow: true,
            }],
            cgi_cpu_limit_secs: None,
            ..Default::default()
        };
        let acl = AccessControl::from_security(&sec).unwrap();
        assert!(acl.is_trusted(ip("8.8.8.8")));
        assert!(acl.is_trusted(ip("2001:db8::1")));
        // And a forwarded header IS now honored from any peer under mode 2 (mTLS ok).
        let mut h = HeaderMap::new();
        h.insert("cf-connecting-ip", "198.51.100.7".parse().unwrap());
        assert_eq!(
            acl.resolve_client_ip(ip("203.0.113.1"), &h, 2, true),
            ip("198.51.100.7")
        );

        // Sanity: an untrusted bare `ALL` does NOT trust peers (no regression).
        let sec_untrusted = Security {
            follow_symlink: false,
            access_deny_dir: vec![],
            access_control: vec![AccessRule {
                spec: "ALL".into(),
                trusted: false,
                allow: true,
            }],
            cgi_cpu_limit_secs: None,
            ..Default::default()
        };
        let acl2 = AccessControl::from_security(&sec_untrusted).unwrap();
        assert!(!acl2.is_trusted(ip("8.8.8.8")));
    }
}

/// (Tier 2) Resolved GeoIP/ASN rules: label lists (country ISO codes, ASN
/// numbers) resolved against a [`hj_geo::GeoSource`] into CIDR sets ONCE at
/// state build, so the per-request check is deny-first binary-search set
/// membership — never a database lookup, never a network fetch.
///
/// Precedence, deliberately simple and documented: a deny-list hit denies;
/// else, when any allow list is configured, the address must be in it (so an
/// allow list alone is a fail-closed whitelist); else the request passes
/// through to the ordinary `AccessControl` CIDR rules, which remain the
/// final word.
#[derive(Debug, Default, Clone)]
pub struct GeoRules {
    denies: Option<hj_geo::IntervalSet>,
    allows: Option<hj_geo::IntervalSet>,
}

impl GeoRules {
    /// Resolve label lists against `source`. An unknown label is an ERROR —
    /// a typo in a country code must fail the state build, not silently
    /// exempt a region.
    pub fn resolve(
        source: &dyn hj_geo::GeoSource,
        geo_allow: &[String],
        geo_deny: &[String],
        asn_allow: &[u32],
        asn_deny: &[u32],
    ) -> Result<Self, String> {
        let mut deny_prefixes: Vec<ipnet::IpNet> = Vec::new();
        let mut allow_prefixes: Vec<ipnet::IpNet> = Vec::new();
        for label in geo_deny {
            let prefixes = source
                .country_prefixes(label)
                .ok_or_else(|| format!("geoDeny label {label:?} is not known to the geo source"))?;
            deny_prefixes.extend(prefixes);
        }
        for label in geo_allow {
            let prefixes = source.country_prefixes(label).ok_or_else(|| {
                format!("geoAllow label {label:?} is not known to the geo source")
            })?;
            allow_prefixes.extend(prefixes);
        }
        for asn in asn_deny {
            let prefixes = source
                .asn_prefixes(*asn)
                .ok_or_else(|| format!("asnDeny {asn} is not known to the geo source"))?;
            deny_prefixes.extend(prefixes);
        }
        for asn in asn_allow {
            let prefixes = source
                .asn_prefixes(*asn)
                .ok_or_else(|| format!("asnAllow {asn} is not known to the geo source"))?;
            allow_prefixes.extend(prefixes);
        }
        Ok(GeoRules {
            denies: (!deny_prefixes.is_empty())
                .then(|| hj_geo::IntervalSet::from_prefixes(&deny_prefixes)),
            allows: (!allow_prefixes.is_empty())
                .then(|| hj_geo::IntervalSet::from_prefixes(&allow_prefixes)),
        })
    }

    /// `true` when no rule list is configured (the check can be skipped).
    pub fn is_empty(&self) -> bool {
        self.denies.is_none() && self.allows.is_none()
    }

    /// Evaluate one (already resolved) client address.
    pub fn allows(&self, ip: IpAddr) -> bool {
        if let Some(denies) = &self.denies
            && denies.contains(ip)
        {
            return false;
        }
        match &self.allows {
            Some(allows) => allows.contains(ip),
            None => true,
        }
    }
}

#[cfg(test)]
mod geo_rules_tests {
    use super::*;

    const SOURCE: &str =
        "country US 203.0.113.0/24\ncountry DE 198.51.100.0/24\nasn 64512 10.0.0.0/8\n";

    fn source() -> hj_geo::CidrList {
        hj_geo::CidrList::parse(SOURCE).unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn deny_list_blocks_labelled_networks_only() {
        let rules = GeoRules::resolve(&source(), &[], &["US".to_string()], &[], &[]).unwrap();
        assert!(!rules.allows(ip("203.0.113.9")));
        assert!(rules.allows(ip("198.51.100.9")));
        assert!(rules.allows(ip("8.8.8.8")));
    }

    #[test]
    fn allow_list_alone_is_fail_closed_whitelist() {
        let rules = GeoRules::resolve(&source(), &["US".to_string()], &[], &[], &[]).unwrap();
        assert!(rules.allows(ip("203.0.113.9")));
        assert!(!rules.allows(ip("198.51.100.9")), "unlabelled = denied");
    }

    #[test]
    fn deny_wins_over_allow() {
        let rules = GeoRules::resolve(
            &source(),
            &["US".to_string(), "DE".to_string()],
            &["DE".to_string()],
            &[],
            &[],
        )
        .unwrap();
        assert!(rules.allows(ip("203.0.113.9")));
        assert!(!rules.allows(ip("198.51.100.9")), "deny-first precedence");
    }

    #[test]
    fn asn_lists_resolve_too() {
        let rules = GeoRules::resolve(&source(), &[], &[], &[], &[64512]).unwrap();
        assert!(!rules.allows(ip("10.1.2.3")));
        assert!(rules.allows(ip("203.0.113.9")));
    }

    #[test]
    fn unknown_label_fails_the_build() {
        assert!(GeoRules::resolve(&source(), &["ZZ".to_string()], &[], &[], &[]).is_err());
        assert!(GeoRules::resolve(&source(), &[], &["GB".to_string()], &[], &[]).is_err());
        assert!(GeoRules::resolve(&source(), &[], &[], &[], &[99999]).is_err());
    }

    #[test]
    fn empty_rules_allow_everything_and_report_skippable() {
        let rules = GeoRules::resolve(&source(), &[], &[], &[], &[]).unwrap();
        assert!(rules.is_empty());
        assert!(rules.allows(ip("8.8.8.8")));
    }
}
