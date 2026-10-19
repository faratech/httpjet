//! Legacy `mod_access_compat` model: a per-scope `Order` plus the `Allow from`
//! / `Deny from` entry lists it orders, evaluated against the resolved client
//! IP and the post-`SetEnvIf` env. Every non-`all` form used to be dropped on
//! the floor, so `Order allow,deny` + `Allow from <cidr>` — the classic admin
//! lockdown Apache and LSWS Enterprise both honor — served to the world (#359).
//! Hostname/domain entries need a reverse DNS lookup this engine never does;
//! they are recorded as un-evaluable and fail CLOSED (an allow never matches, a
//! deny always matches), mirroring how an unrecognized `Require` predicate is
//! treated.

use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AccessOrder {
    /// `Order deny,allow` — Apache's default when no `Order` is given. Access is
    /// allowed unless a `Deny` matches and no `Allow` overrides it.
    #[default]
    DenyAllow,
    /// `Order allow,deny` — denied by default; an `Allow` must match and no
    /// `Deny` may.
    AllowDeny,
    /// `Order mutual-failure` — allowed only when an `Allow` matches and no
    /// `Deny` does (same truth table as `allow,deny`).
    MutualFailure,
}

impl AccessOrder {
    /// `Order`'s argument (whitespace-tolerant, case-insensitive). An unknown
    /// argument is a config error in Apache; fail closed to the deny-by-default
    /// order rather than the permissive one.
    pub fn parse(arg: &str) -> AccessOrder {
        let norm: String = arg
            .chars()
            .filter(|c| !c.is_whitespace())
            .map(|c| c.to_ascii_lowercase())
            .collect();
        match norm.as_str() {
            "deny,allow" => AccessOrder::DenyAllow,
            "allow,deny" => AccessOrder::AllowDeny,
            "mutual-failure" => AccessOrder::MutualFailure,
            _ => AccessOrder::AllowDeny,
        }
    }
}

/// One `Allow from` / `Deny from` operand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostEntry {
    /// `all`.
    All,
    /// A full address, CIDR, dotted netmask, or partial dotted-quad, reduced to
    /// a network prefix.
    Net { addr: IpAddr, prefix: u8 },
    /// `env=NAME` / `env=!NAME`.
    Env { name: String, negate: bool },
    /// A hostname / domain suffix (needs reverse DNS) or an unparsable token.
    Unevaluable(String),
}

/// What an access decision is evaluated against. `None` fields mean "unknown"
/// and resolve fail-closed (a deny entry matches, an allow entry does not).
#[derive(Clone, Copy, Default)]
pub struct AccessSubject<'a> {
    pub client_ip: Option<IpAddr>,
    pub env_set: Option<&'a dyn Fn(&str) -> bool>,
}

impl std::fmt::Debug for AccessSubject<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessSubject")
            .field("client_ip", &self.client_ip)
            .field("env_set", &self.env_set.is_some())
            .finish()
    }
}

impl HostEntry {
    /// Parse one operand token. Never fails: anything not recognized is an
    /// [`HostEntry::Unevaluable`] so a restriction is never silently lost.
    pub fn parse(token: &str) -> HostEntry {
        if token.eq_ignore_ascii_case("all") {
            return HostEntry::All;
        }
        if let Some(env) = token
            .get(..4)
            .filter(|p| p.eq_ignore_ascii_case("env="))
            .and_then(|_| token.get(4..))
        {
            let (negate, name) = match env.strip_prefix('!') {
                Some(n) => (true, n),
                None => (false, env),
            };
            if name.is_empty() {
                return HostEntry::Unevaluable(token.to_string());
            }
            return HostEntry::Env {
                name: name.to_string(),
                negate,
            };
        }
        if let Some((addr, mask)) = token.split_once('/') {
            let Ok(addr) = addr.parse::<IpAddr>() else {
                return HostEntry::Unevaluable(token.to_string());
            };
            let max = if addr.is_ipv4() { 32 } else { 128 };
            let prefix = match mask.parse::<u8>() {
                Ok(p) if p <= max => Some(p),
                Ok(_) => None,
                Err(_) => mask
                    .parse::<Ipv4Addr>()
                    .ok()
                    .filter(|_| addr.is_ipv4())
                    .and_then(contiguous_mask_prefix),
            };
            return prefix
                .and_then(|prefix| net_entry(addr, prefix))
                .unwrap_or_else(|| HostEntry::Unevaluable(token.to_string()));
        }
        if let Ok(addr) = token.parse::<IpAddr>() {
            let prefix = if addr.is_ipv4() { 32 } else { 128 };
            return net_entry(addr, prefix)
                .unwrap_or_else(|| HostEntry::Unevaluable(token.to_string()));
        }
        // Partial dotted-quad (`10`, `10.1`, `10.1.2`): the leading 1-3 octets.
        // Apache also accepts the documented trailing-dot spelling (`10.1.`).
        let octets: Vec<&str> = token
            .strip_suffix('.')
            .unwrap_or(token)
            .split('.')
            .collect();
        if (1..=3).contains(&octets.len()) && octets.iter().all(|o| o.parse::<u8>().is_ok()) {
            let mut b = [0u8; 4];
            for (i, o) in octets.iter().enumerate() {
                b[i] = o.parse().unwrap();
            }
            return HostEntry::Net {
                addr: IpAddr::V4(Ipv4Addr::from(b)),
                prefix: (octets.len() * 8) as u8,
            };
        }
        HostEntry::Unevaluable(token.to_string())
    }

    /// Does this entry match `subject`? `deny_polarity` is the fail-closed
    /// answer for anything that cannot be evaluated (unknown IP/env, hostname).
    fn matches(&self, subject: &AccessSubject<'_>, deny_polarity: bool) -> bool {
        match self {
            HostEntry::All => true,
            HostEntry::Net { addr, prefix } => subject
                .client_ip
                .map(|ip| net_contains(*addr, *prefix, ip))
                .unwrap_or(deny_polarity),
            HostEntry::Env { name, negate } => subject
                .env_set
                .map(|f| f(name) != *negate)
                .unwrap_or(deny_polarity),
            HostEntry::Unevaluable(_) => deny_polarity,
        }
    }

    pub fn is_unevaluable(&self) -> bool {
        matches!(self, HostEntry::Unevaluable(_))
    }
}

/// The accumulated `Order` + `Allow from` + `Deny from` lines of one scope.
///
/// Apache keeps ONE `mod_access_compat` config per section: `<IfModule>` is
/// transparent and `<Limit>`/`<LimitExcept>` only tags the enclosed lines with a
/// method mask (`order[method]`, `allowdeny.limited`) inside that same config, so
/// a `<Limit GET> Allow from …` refines the enclosing `Order`/`Deny` rather than
/// starting a fresh, default-open block (#778).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostAccess {
    /// The `Order` for every method no later `<Limit>`-scoped `Order` overrides.
    pub order: AccessOrder,
    /// Unlimited (all-method) `Allow from` entries.
    pub allow: Vec<HostEntry>,
    /// Unlimited (all-method) `Deny from` entries.
    pub deny: Vec<HostEntry>,
    /// Whether any line outside a `<Limit>` was recorded (the block then has an
    /// opinion on every method).
    pub unlimited: bool,
    /// `<Limit>`/`<LimitExcept>` refinements, in source order.
    pub limited: Vec<LimitedAccess>,
}

/// The lines of one `<Limit>`/`<LimitExcept>` section within a [`HostAccess`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitedAccess {
    pub methods: Vec<String>,
    pub except: bool,
    /// A `Order` line inside this section (cleared by a later unlimited `Order`,
    /// which in Apache rewrites `order[]` for every method).
    pub order: Option<AccessOrder>,
    pub allow: Vec<HostEntry>,
    pub deny: Vec<HostEntry>,
}

impl LimitedAccess {
    pub fn covers(&self, method: &str) -> bool {
        method_listed(&self.methods, method) != self.except
    }
}

/// Apache's built-in method names (`lookup_builtin_method`). `.htaccess` cannot
/// register new ones, and the lookup is case-sensitive, so anything else in a
/// `<Limit>`/`<LimitExcept>` is a configuration error.
const BUILTIN_METHODS: &[&str] = &[
    "GET",
    "HEAD",
    "PUT",
    "POST",
    "DELETE",
    "CONNECT",
    "OPTIONS",
    "TRACE",
    "PATCH",
    "PROPFIND",
    "PROPPATCH",
    "MKCOL",
    "COPY",
    "MOVE",
    "LOCK",
    "UNLOCK",
    "VERSION-CONTROL",
    "CHECKOUT",
    "UNCHECKOUT",
    "CHECKIN",
    "UPDATE",
    "LABEL",
    "REPORT",
    "MKWORKSPACE",
    "MKACTIVITY",
    "BASELINE-CONTROL",
    "MERGE",
];

pub(crate) fn is_builtin_method(method: &str) -> bool {
    BUILTIN_METHODS.contains(&method)
}

/// Apache numbers `HEAD` as `M_GET`, so each one names the other in a method
/// mask: `<Limit HEAD>` restricts GET exactly as `<Limit GET>` restricts HEAD.
fn method_number(method: &str) -> &str {
    if method == "HEAD" { "GET" } else { method }
}

pub(crate) fn method_listed(methods: &[String], method: &str) -> bool {
    let want = method_number(method);
    methods.iter().any(|m| method_number(m) == want)
}

impl HostAccess {
    /// Apache's `mod_access_compat` truth table for a method-agnostic check
    /// (only the unlimited lines).
    pub fn permits(&self, subject: &AccessSubject<'_>) -> bool {
        let allowed = self.allow.iter().any(|e| e.matches(subject, false));
        let denied = self.deny.iter().any(|e| e.matches(subject, true));
        Self::verdict(self.order, allowed, denied)
    }

    /// The truth table for `method`: unlimited lines plus every `<Limit>`
    /// section covering it, under the last `Order` that applies to it.
    pub fn permits_method(&self, subject: &AccessSubject<'_>, method: &str) -> bool {
        let mut order = self.order;
        let mut allowed = self.allow.iter().any(|e| e.matches(subject, false));
        let mut denied = self.deny.iter().any(|e| e.matches(subject, true));
        for l in self.limited.iter().filter(|l| l.covers(method)) {
            if let Some(o) = l.order {
                order = o;
            }
            allowed |= l.allow.iter().any(|e| e.matches(subject, false));
            denied |= l.deny.iter().any(|e| e.matches(subject, true));
        }
        Self::verdict(order, allowed, denied)
    }

    /// Whether any recorded line applies to `method`. A block holding only
    /// `<Limit POST>` lines has no opinion on a `GET`.
    pub fn applies_to(&self, method: &str) -> bool {
        self.unlimited || self.limited.iter().any(|l| l.covers(method))
    }

    fn verdict(order: AccessOrder, allowed: bool, denied: bool) -> bool {
        match order {
            AccessOrder::DenyAllow => !denied || allowed,
            AccessOrder::AllowDeny | AccessOrder::MutualFailure => allowed && !denied,
        }
    }
}

/// Parse the operand list of an `Allow`/`Deny` line (`from a b c`). `None` when
/// the line lacks the mandatory `from` keyword.
pub(super) fn parse_host_entries(rest: &str) -> Option<Vec<HostEntry>> {
    let rest = rest.trim();
    let (kw, list) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
    if !kw.eq_ignore_ascii_case("from") {
        return None;
    }
    Some(list.split_whitespace().map(HostEntry::parse).collect())
}

fn normalize(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// An IPv4-mapped IPv6 network folds to its V4 form, so its prefix drops the
/// 96-bit `::ffff:` head; a mapped prefix shorter than that spans non-mapped
/// space and is rejected.
fn net_entry(addr: IpAddr, prefix: u8) -> Option<HostEntry> {
    match addr {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => prefix.checked_sub(96).map(|prefix| HostEntry::Net {
                addr: IpAddr::V4(v4),
                prefix,
            }),
            None => Some(HostEntry::Net { addr, prefix }),
        },
        IpAddr::V4(_) => Some(HostEntry::Net { addr, prefix }),
    }
}

fn contiguous_mask_prefix(mask: Ipv4Addr) -> Option<u8> {
    let bits = u32::from(mask);
    let ones = bits.leading_ones();
    (bits == u32::MAX.checked_shl(32 - ones).unwrap_or(0)).then_some(ones as u8)
}

fn net_contains(net: IpAddr, prefix: u8, ip: IpAddr) -> bool {
    match (net, normalize(ip)) {
        (IpAddr::V4(n), IpAddr::V4(a)) => {
            let Some(shift) = 32u32.checked_sub(u32::from(prefix)) else {
                return false;
            };
            shift >= 32 || (u32::from(n) >> shift) == (u32::from(a) >> shift)
        }
        (IpAddr::V6(n), IpAddr::V6(a)) => {
            let Some(shift) = 128u32.checked_sub(u32::from(prefix)) else {
                return false;
            };
            shift >= 128 || (u128::from(n) >> shift) == (u128::from(a) >> shift)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Option<IpAddr> {
        Some(s.parse().unwrap())
    }

    #[test]
    fn parses_every_operand_form() {
        assert_eq!(HostEntry::parse("ALL"), HostEntry::All);
        assert_eq!(
            HostEntry::parse("10.1.2.3"),
            HostEntry::Net {
                addr: "10.1.2.3".parse().unwrap(),
                prefix: 32
            }
        );
        assert_eq!(
            HostEntry::parse("10.1.0.0/16"),
            HostEntry::Net {
                addr: "10.1.0.0".parse().unwrap(),
                prefix: 16
            }
        );
        assert_eq!(
            HostEntry::parse("10.1.0.0/255.255.0.0"),
            HostEntry::Net {
                addr: "10.1.0.0".parse().unwrap(),
                prefix: 16
            }
        );
        assert_eq!(
            HostEntry::parse("10.1"),
            HostEntry::Net {
                addr: "10.1.0.0".parse().unwrap(),
                prefix: 16
            }
        );
        assert_eq!(
            HostEntry::parse("2001:db8::/32"),
            HostEntry::Net {
                addr: "2001:db8::".parse().unwrap(),
                prefix: 32
            }
        );
        assert_eq!(
            HostEntry::parse("env=bad_bot"),
            HostEntry::Env {
                name: "bad_bot".into(),
                negate: false
            }
        );
        assert_eq!(
            HostEntry::parse("env=!good"),
            HostEntry::Env {
                name: "good".into(),
                negate: true
            }
        );
        assert!(HostEntry::parse(".example.com").is_unevaluable());
        assert!(HostEntry::parse("10.1.0.0/255.0.255.0").is_unevaluable());
        assert!(HostEntry::parse("10.1.0.0/33").is_unevaluable());
        assert!(HostEntry::parse("300.1").is_unevaluable());
    }

    #[test]
    fn partial_ipv4_with_trailing_dot_is_a_prefix() {
        // (#893) Apache's documented `Allow from 10.1.` spelling.
        assert_eq!(
            HostEntry::parse("10.1."),
            HostEntry::Net {
                addr: "10.1.0.0".parse().unwrap(),
                prefix: 16
            }
        );
        assert_eq!(
            HostEntry::parse("192.168.1."),
            HostEntry::Net {
                addr: "192.168.1.0".parse().unwrap(),
                prefix: 24
            }
        );
        assert!(HostEntry::parse("10..").is_unevaluable());
        assert!(HostEntry::parse(".").is_unevaluable());
        let ha = HostAccess {
            order: AccessOrder::parse("Deny,Allow"),
            deny: vec![HostEntry::parse("10.1.")],
            ..Default::default()
        };
        assert!(!ha.permits(&AccessSubject {
            client_ip: ip("10.1.2.3"),
            env_set: None
        }));
        assert!(ha.permits(&AccessSubject {
            client_ip: ip("10.2.0.1"),
            env_set: None
        }));
    }

    #[test]
    fn order_allow_deny_denies_by_default() {
        let ha = HostAccess {
            order: AccessOrder::parse("Allow,Deny"),
            allow: vec![HostEntry::parse("203.0.113.0/24")],
            deny: vec![],
            ..Default::default()
        };
        assert!(ha.permits(&AccessSubject {
            client_ip: ip("203.0.113.9"),
            env_set: None
        }));
        assert!(!ha.permits(&AccessSubject {
            client_ip: ip("198.51.100.1"),
            env_set: None
        }));
        // Unknown client IP: the allow cannot be proven -> denied.
        assert!(!ha.permits(&AccessSubject::default()));
        // IPv4-mapped IPv6 peers canonicalize.
        assert!(ha.permits(&AccessSubject {
            client_ip: ip("::ffff:203.0.113.9"),
            env_set: None
        }));
    }

    #[test]
    fn order_deny_allow_allows_by_default_and_allow_overrides_deny() {
        let ha = HostAccess {
            order: AccessOrder::DenyAllow,
            allow: vec![HostEntry::parse("198.51.100.7")],
            deny: vec![HostEntry::parse("198.51.100.0/24")],
            ..Default::default()
        };
        assert!(ha.permits(&AccessSubject {
            client_ip: ip("192.0.2.1"),
            env_set: None
        }));
        assert!(!ha.permits(&AccessSubject {
            client_ip: ip("198.51.100.8"),
            env_set: None
        }));
        assert!(ha.permits(&AccessSubject {
            client_ip: ip("198.51.100.7"),
            env_set: None
        }));
    }

    #[test]
    fn env_entries_read_the_request_env() {
        let ha = HostAccess {
            order: AccessOrder::AllowDeny,
            allow: vec![HostEntry::All],
            deny: vec![HostEntry::parse("env=bad_bot")],
            ..Default::default()
        };
        let set = |n: &str| n == "bad_bot";
        let unset = |_: &str| false;
        assert!(!ha.permits(&AccessSubject {
            client_ip: ip("192.0.2.1"),
            env_set: Some(&set)
        }));
        assert!(ha.permits(&AccessSubject {
            client_ip: ip("192.0.2.1"),
            env_set: Some(&unset)
        }));
        // No env context at all: a deny entry fails closed.
        assert!(!ha.permits(&AccessSubject {
            client_ip: ip("192.0.2.1"),
            env_set: None
        }));
    }

    #[test]
    fn hostname_entries_fail_closed() {
        let allow_host = HostAccess {
            order: AccessOrder::AllowDeny,
            allow: vec![HostEntry::parse(".example.com")],
            deny: vec![],
            ..Default::default()
        };
        assert!(!allow_host.permits(&AccessSubject {
            client_ip: ip("192.0.2.1"),
            env_set: None
        }));
        let deny_host = HostAccess {
            order: AccessOrder::DenyAllow,
            allow: vec![],
            deny: vec![HostEntry::parse("evil.example")],
            ..Default::default()
        };
        assert!(!deny_host.permits(&AccessSubject {
            client_ip: ip("192.0.2.1"),
            env_set: None
        }));
    }

    #[test]
    fn from_all_forms_keep_their_legacy_meaning() {
        let deny_all = HostAccess {
            order: AccessOrder::DenyAllow,
            allow: vec![],
            deny: vec![HostEntry::All],
            ..Default::default()
        };
        assert!(!deny_all.permits(&AccessSubject::default()));
        let allow_all = HostAccess {
            order: AccessOrder::AllowDeny,
            allow: vec![HostEntry::All],
            deny: vec![],
            ..Default::default()
        };
        assert!(allow_all.permits(&AccessSubject::default()));
        // Apache: with allow,deny a matching Deny beats a matching Allow.
        let both = HostAccess {
            order: AccessOrder::AllowDeny,
            allow: vec![HostEntry::All],
            deny: vec![HostEntry::All],
            ..Default::default()
        };
        assert!(!both.permits(&AccessSubject::default()));
    }

    #[test]
    fn missing_from_keyword_is_rejected() {
        assert!(parse_host_entries("all").is_none());
        assert_eq!(
            parse_host_entries("from all 10.0.0.0/8"),
            Some(vec![HostEntry::All, HostEntry::parse("10.0.0.0/8")])
        );
    }

    #[test]
    fn ipv4_mapped_v6_operands_fold_to_v4_prefix_width() {
        assert_eq!(
            HostEntry::parse("::ffff:10.1.2.3"),
            HostEntry::Net {
                addr: "10.1.2.3".parse().unwrap(),
                prefix: 32
            }
        );
        assert_eq!(
            HostEntry::parse("::ffff:10.1.0.0/112"),
            HostEntry::Net {
                addr: "10.1.0.0".parse().unwrap(),
                prefix: 16
            }
        );
        assert!(HostEntry::parse("::ffff:10.1.0.0/95").is_unevaluable());

        let deny = HostAccess {
            order: AccessOrder::DenyAllow,
            allow: vec![],
            deny: vec![HostEntry::parse("::ffff:10.1.2.3")],
            ..Default::default()
        };
        let subject = |s| AccessSubject {
            client_ip: ip(s),
            env_set: None,
        };
        assert!(deny.permits(&subject("8.8.8.8")));
        assert!(!deny.permits(&subject("10.1.2.3")));
        assert!(!deny.permits(&subject("::ffff:10.1.2.3")));

        let allow = HostAccess {
            order: AccessOrder::parse("Allow,Deny"),
            allow: vec![HostEntry::parse("::ffff:10.1.0.0/112")],
            deny: vec![],
            ..Default::default()
        };
        assert!(allow.permits(&subject("10.1.200.7")));
        assert!(!allow.permits(&subject("8.8.8.8")));
    }
}
