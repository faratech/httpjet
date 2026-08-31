//! GeoIP/ASN address sources for the ACL layer.
//!
//! A [`CidrList`] maps country labels (ISO-3166-1 alpha-2) and ASN numbers to
//! sets of network prefixes, loaded from a plain text file the operator
//! regenerates offline (e.g. from a MaxMind country/ASN dump by cron — httpjet
//! never fetches at runtime, so behavior is deterministic and offline). The
//! ACL resolves its configured labels against this source ONCE at state build
//! (see `hj_acl::GeoRules`), so the per-request hot path is a binary search
//! over merged intervals, never a database lookup.
//!
//! File format (whitespace-separated, `#` comments):
//!
//! ```text
//! country US 203.0.113.0/24 198.51.100.0/24
//! country DE 2001:db8::/32
//! asn 13335 203.0.113.0/24
//! ```

use std::collections::HashMap;
use std::net::IpAddr;

use ipnet::IpNet;

/// A source of label → prefix mappings (country ISO codes and ASN numbers).
/// Implemented by [`CidrList`]; a MaxMind mmdb backend can slot in behind the
/// same trait later.
pub trait GeoSource {
    /// Prefixes for an ISO-3166-1 alpha-2 country code (case-insensitive);
    /// `None` when the label is unknown to this source.
    fn country_prefixes(&self, iso: &str) -> Option<Vec<IpNet>>;
    /// Prefixes for an autonomous system number; `None` when unknown.
    fn asn_prefixes(&self, asn: u32) -> Option<Vec<IpNet>>;
}

/// Sorted, disjoint, inclusive address intervals with binary-search membership.
/// Built from prefixes: v4 and v6 are kept in separate arrays (an IPv4-mapped
/// IPv6 address canonically belongs to the v4 space — `IpNet::contains` makes
/// the same split).
#[derive(Debug, Default, Clone)]
pub struct IntervalSet {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl IntervalSet {
    /// Normalize prefixes into sorted, merged, inclusive intervals. Overlapping
    /// input prefixes (a country list routinely nests /20s inside /16s) collapse
    /// here, once, instead of being re-scanned per request.
    pub fn from_prefixes<'a>(prefixes: impl IntoIterator<Item = &'a IpNet>) -> Self {
        let mut v4: Vec<(u32, u32)> = Vec::new();
        let mut v6: Vec<(u128, u128)> = Vec::new();
        for p in prefixes {
            // Prefixes are canonical (host bits zeroed by the IpNet parse), so the
            // last address is network | !mask.
            match (p.network(), p.netmask()) {
                (IpAddr::V4(n), IpAddr::V4(m)) => {
                    let first = u32::from(n);
                    v4.push((first, first | !u32::from(m)));
                }
                (IpAddr::V6(n), IpAddr::V6(m)) => {
                    let first = u128::from(n);
                    v6.push((first, first | !u128::from(m)));
                }
                _ => {}
            }
        }
        let merge = |mut iv: Vec<(u128, u128)>| {
            iv.sort_unstable();
            let mut out: Vec<(u128, u128)> = Vec::with_capacity(iv.len());
            for (start, end) in iv {
                match out.last_mut() {
                    // Overlapping or adjacent intervals merge (adjacency keeps the
                    // array canonical so membership needs only one probe).
                    Some(last) if start <= last.1.saturating_add(1) => {
                        last.1 = last.1.max(end);
                    }
                    _ => out.push((start, end)),
                }
            }
            out
        };
        IntervalSet {
            v4: merge(
                v4.into_iter()
                    .map(|(a, b)| (a as u128, b as u128))
                    .collect(),
            )
            .into_iter()
            .map(|(a, b)| (a as u32, b as u32))
            .collect(),
            v6: merge(v6),
        }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => contains_u32(&self.v4, u32::from(v4)),
            IpAddr::V6(v6) => {
                // ::ffff:a.b.c.d is canonically v4 — judge it by its v4 address so
                // an ACL entry written as a v4 CIDR matches a v4-mapped peer.
                if let Some(m) = v6.to_ipv4_mapped() {
                    contains_u32(&self.v4, u32::from(m))
                } else {
                    contains_u128(&self.v6, u128::from(v6))
                }
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }
}

fn contains_u32(intervals: &[(u32, u32)], n: u32) -> bool {
    let idx = intervals.partition_point(|&(start, _)| start <= n);
    idx > 0 && intervals[idx - 1].1 >= n
}

fn contains_u128(intervals: &[(u128, u128)], n: u128) -> bool {
    let idx = intervals.partition_point(|&(start, _)| start <= n);
    idx > 0 && intervals[idx - 1].1 >= n
}

/// A parsed `country`/`asn` label → prefixes text file (see the module docs).
#[derive(Debug, Default, Clone)]
pub struct CidrList {
    countries: HashMap<String, Vec<IpNet>>,
    asns: HashMap<u32, Vec<IpNet>>,
}

impl CidrList {
    /// Parse the whole file. Unknown labels or malformed prefixes are ERRORS
    /// naming the line — a silently-partial geo ACL would deny or allow the
    /// wrong visitors, so this fails the state build instead.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut list = CidrList::default();
        for (idx, raw) in text.lines().enumerate() {
            let line_no = idx + 1;
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.split_whitespace();
            match parts.next() {
                Some("country") => {
                    let label = parts.next().ok_or_else(|| {
                        format!("geo line {line_no}: `country` needs a label and prefixes")
                    })?;
                    if label.len() != 2 || !label.bytes().all(|b| b.is_ascii_alphabetic()) {
                        return Err(format!(
                            "geo line {line_no}: country label {label:?} is not ISO-3166 alpha-2"
                        ));
                    }
                    let key = label.to_ascii_uppercase();
                    let entry = list.countries.entry(key).or_default();
                    push_prefixes(entry, parts, line_no)?;
                }
                Some("asn") => {
                    let asn = parts
                        .next()
                        .ok_or_else(|| {
                            format!("geo line {line_no}: `asn` needs a number and prefixes")
                        })
                        .and_then(|a| {
                            a.trim_start_matches("AS")
                                .parse::<u32>()
                                .map_err(|e| format!("geo line {line_no}: bad ASN {a:?}: {e}"))
                        })?;
                    let entry = list.asns.entry(asn).or_default();
                    push_prefixes(entry, parts, line_no)?;
                }
                other => {
                    return Err(format!(
                        "geo line {line_no}: expected `country` or `asn`, got {other:?}"
                    ));
                }
            }
        }
        Ok(list)
    }

    /// Country labels known to this list (uppercase).
    pub fn countries(&self) -> impl Iterator<Item = &str> {
        self.countries.keys().map(String::as_str)
    }
}

fn push_prefixes<'a>(
    entry: &mut Vec<IpNet>,
    prefixes: impl Iterator<Item = &'a str>,
    line_no: usize,
) -> Result<(), String> {
    let mut any = false;
    for p in prefixes {
        let net: IpNet = p
            .parse()
            .map_err(|e| format!("geo line {line_no}: bad prefix {p:?}: {e}"))?;
        entry.push(net);
        any = true;
    }
    if !any {
        return Err(format!(
            "geo line {line_no}: at least one prefix is required"
        ));
    }
    Ok(())
}

impl GeoSource for CidrList {
    fn country_prefixes(&self, iso: &str) -> Option<Vec<IpNet>> {
        self.countries.get(&iso.to_ascii_uppercase()).cloned()
    }

    fn asn_prefixes(&self, asn: u32) -> Option<Vec<IpNet>> {
        self.asns.get(&asn).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(specs: &[&str]) -> IntervalSet {
        let prefixes: Vec<IpNet> = specs.iter().map(|s| s.parse().unwrap()).collect();
        IntervalSet::from_prefixes(&prefixes)
    }

    #[test]
    fn membership_and_merging() {
        let s = set(&["10.0.0.0/8", "10.128.0.0/9", "192.168.1.0/24"]);
        assert!(s.contains("10.1.2.3".parse().unwrap()));
        assert!(s.contains("10.200.0.1".parse().unwrap()));
        assert!(s.contains("192.168.1.255".parse().unwrap()));
        assert!(!s.contains("192.168.2.1".parse().unwrap()));
        assert!(!s.contains("11.0.0.1".parse().unwrap()));
    }

    #[test]
    fn v4_mapped_v6_resolves_to_v4_space() {
        let s = set(&["203.0.113.0/24"]);
        let mapped: IpAddr = "::ffff:203.0.113.9".parse().unwrap();
        assert!(s.contains(mapped));
        assert!(!s.contains("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn adjacency_stays_canonical() {
        let s = set(&["203.0.113.0/25", "203.0.113.128/25"]);
        assert!(s.contains("203.0.113.0".parse().unwrap()));
        assert!(s.contains("203.0.113.255".parse().unwrap()));
        // Merged into exactly one interval.
        assert_eq!(s.v4.len(), 1);
    }

    #[test]
    fn cidr_list_parses_countries_and_asns() {
        let list = CidrList::parse(
            "# comment\n\ncountry US 203.0.113.0/24 198.51.100.0/24\ncountry de 2001:db8::/32\nasn 13335 203.0.114.0/24\nasn AS64512 10.0.0.0/8\n",
        )
        .unwrap();
        assert!(list.country_prefixes("us").is_some());
        assert!(list.country_prefixes("US").is_some());
        assert_eq!(list.country_prefixes("GB"), None);
        assert!(list.asn_prefixes(13335).is_some());
        assert!(list.asn_prefixes(64512).is_some());
        assert_eq!(list.asn_prefixes(1), None);
        assert_eq!(list.countries().count(), 2);
    }

    #[test]
    fn cidr_list_rejects_malformed_lines() {
        assert!(CidrList::parse("bogus US 1.2.3.0/24").is_err());
        assert!(CidrList::parse("country USA 1.2.3.0/24").is_err());
        assert!(CidrList::parse("country US not-a-prefix").is_err());
        assert!(CidrList::parse("asn banana 1.2.3.0/24").is_err());
        assert!(CidrList::parse("country US").is_err());
        // Errors name the line.
        let e = CidrList::parse("country US 1.2.3.0/24\ncountry DE nope").unwrap_err();
        assert!(e.contains("line 2"), "{e}");
    }
}
