//! Network-peer trust helpers shared across transports (TCP TLS and QUIC/HTTP3).

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::OnceLock;

/// The explicit allow-list of peer IPs (beyond loopback) that are exempt from the
/// origin-pull mTLS requirement. Installed once at startup from the resolved
/// `--cache-peer` addresses (the active-active sibling node). `None` until
/// installed (and in unit tests) ⇒ ONLY loopback/unspecified is exempt.
static EXEMPT_PEERS: OnceLock<HashSet<IpAddr>> = OnceLock::new();

/// Install the mTLS-exempt peer allow-list (the resolved `--cache-peer` IPs). Call
/// ONCE, before any listener accepts. Addresses are canonicalized so an
/// IPv4-mapped IPv6 form matches its IPv4. Idempotent-ish: a second call is a no-op
/// (the first install wins) — `--cache-peer` is a fixed CLI arg for the process.
pub fn set_exempt_peers(peers: impl IntoIterator<Item = IpAddr>) {
    let set: HashSet<IpAddr> = peers.into_iter().map(|ip| ip.to_canonical()).collect();
    let _ = EXEMPT_PEERS.set(set);
}

/// Is `ip` a loopback or explicitly-allow-listed peer that is exempt from the
/// mandatory Cloudflare origin-pull client-cert requirement (`clientVerify=2`)?
///
/// The origin-pull mTLS exists to keep *external* clients from reaching the origin
/// directly (only Cloudflare carries the client cert). Two classes of caller
/// legitimately reach the origin without it: (1) on-box services, because
/// `/etc/hosts` maps the public vhosts to `127.0.0.1` so a fetch of
/// `https://forum.example/...` hits the listener over loopback; and (2) an
/// explicitly configured peer (purge fan-out / health). Everyone else —
/// **including arbitrary RFC1918/LAN hosts** — must present a valid cert.
///
/// History: this used to exempt the WHOLE RFC1918/ULA/link-local space (range
/// based), which let any private-LAN host bypass Cloudflare AOP (security audit
/// 2026-06-19, MEDIUM). It is now narrowed to loopback/unspecified + the explicit
/// `--cache-peer` allow-list installed via [`set_exempt_peers`].
/// IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is unwrapped and judged as its IPv4 form.
pub fn is_trusted_internal_peer(ip: IpAddr) -> bool {
    match EXEMPT_PEERS.get() {
        Some(set) => peer_is_exempt(ip, set),
        None => peer_is_exempt(ip, &HashSet::new()),
    }
}

/// Pure core of [`is_trusted_internal_peer`] (testable without the process global):
/// loopback/unspecified are ALWAYS exempt; otherwise the canonicalized IP must be
/// in `extra`.
fn peer_is_exempt(ip: IpAddr, extra: &HashSet<IpAddr>) -> bool {
    let ip = ip.to_canonical();
    match ip {
        IpAddr::V4(v4) if v4.is_loopback() || v4.is_unspecified() => return true,
        IpAddr::V6(v6) if v6.is_loopback() || v6.is_unspecified() => return true,
        _ => {}
    }
    extra.contains(&ip)
}

/// Extract the host from a `Host` / `:authority` value, dropping any `:port` and
/// the brackets around an IPv6 literal, lowercased and with a trailing root dot
/// removed (`example.com.` → `example.com`).
///
/// Handles `example.com`, `example.com:443`, `[::1]`, and `[::1]:8443`. A plain
/// `split(':')` mangles the bracketed-IPv6 forms; this is the single host
/// normalizer shared by vhost routing, the mTLS HTTP→HTTPS redirect, and the
/// page-cache key host.
pub fn host_without_port(authority: &str) -> String {
    let a = authority.trim();
    let host = if let Some(rest) = a.strip_prefix('[') {
        // `[ipv6]` or `[ipv6]:port` — take up to the closing bracket.
        rest.split(']').next().unwrap_or(rest)
    } else if a.matches(':').count() > 1 {
        // Unbracketed multi-colon: a bare IPv6 literal (malformed in a Host header
        // per RFC 7230, but don't mangle it) — there is no port to strip.
        a
    } else {
        a.split(':').next().unwrap_or(a)
    };
    host.trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::{host_without_port, is_trusted_internal_peer, peer_is_exempt};
    use std::collections::HashSet;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("parse ip")
    }

    fn allow(addrs: &[&str]) -> HashSet<IpAddr> {
        addrs.iter().map(|s| ip(s).to_canonical()).collect()
    }

    #[test]
    fn loopback_is_always_exempt() {
        // Loopback and the unspecified address are exempt even with NO peer
        // allow-list configured.
        let empty = HashSet::new();
        assert!(peer_is_exempt(ip("127.0.0.1"), &empty));
        assert!(peer_is_exempt(ip("127.0.0.53"), &empty));
        assert!(peer_is_exempt(ip("::1"), &empty));
        assert!(peer_is_exempt(ip("0.0.0.0"), &empty));
        // IPv4-mapped IPv6 of loopback is unwrapped.
        assert!(peer_is_exempt(ip("::ffff:127.0.0.1"), &empty));
    }

    #[test]
    fn only_configured_peers_are_exempt_not_the_whole_lan() {
        // A documentation-range peer explicitly allow-listed via --cache-peer.
        let allowed = allow(&["192.0.2.3"]);
        assert!(peer_is_exempt(ip("192.0.2.3"), &allowed));
        // IPv4-mapped IPv6 of the configured peer still matches.
        assert!(peer_is_exempt(ip("::ffff:192.0.2.3"), &allowed));
        // But an arbitrary RFC1918 / LAN host that is NOT a configured peer is no
        // longer trusted — this is the audit-2026-06-19 narrowing (a cert-less
        // private-LAN host must not bypass Cloudflare AOP).
        assert!(!peer_is_exempt(ip("10.0.0.1"), &allowed));
        assert!(!peer_is_exempt(ip("172.16.5.4"), &allowed));
        assert!(!peer_is_exempt(ip("192.168.1.10"), &allowed));
        assert!(!peer_is_exempt(ip("169.254.1.1"), &allowed));
        assert!(!peer_is_exempt(ip("fd00::1"), &allowed));
        assert!(!peer_is_exempt(ip("fe80::1"), &allowed));
    }

    #[test]
    fn public_peers_are_not_trusted() {
        // Cloudflare edge / arbitrary public IPs must still present a client cert,
        // even if they were somehow allow-listed-adjacent. With no global installed,
        // is_trusted_internal_peer falls back to loopback-only.
        assert!(!is_trusted_internal_peer(ip("173.245.48.1"))); // a Cloudflare range
        assert!(!is_trusted_internal_peer(ip("8.8.8.8")));
        assert!(!is_trusted_internal_peer(ip("1.1.1.1")));
        assert!(!is_trusted_internal_peer(ip("203.0.113.7")));
        assert!(!is_trusted_internal_peer(ip("2606:4700:4700::1111")));
        // IPv4-mapped IPv6 of a public address is still public.
        assert!(!is_trusted_internal_peer(ip("::ffff:8.8.8.8")));
        // ...and loopback stays exempt through the public entry point.
        assert!(is_trusted_internal_peer(ip("127.0.0.1")));
        assert!(is_trusted_internal_peer(ip("::1")));
    }

    #[test]
    fn host_without_port_handles_ports_and_ipv6() {
        assert_eq!(host_without_port("example.com"), "example.com");
        assert_eq!(host_without_port("Example.COM:443"), "example.com");
        assert_eq!(host_without_port("forum.example."), "forum.example");
        assert_eq!(host_without_port("[::1]"), "::1");
        assert_eq!(host_without_port("[::1]:8443"), "::1");
        assert_eq!(
            host_without_port("[2606:4700::1111]:443"),
            "2606:4700::1111"
        );
        // Bare unbracketed IPv6 (malformed) is passed through, not truncated.
        assert_eq!(host_without_port("::1"), "::1");
    }
}
