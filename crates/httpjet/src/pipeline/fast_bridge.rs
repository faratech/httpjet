//! Why an on-core `fast_serve` request bridged to the tokio pipeline.
//!
//! A bridge is not an error: `dispatch()` serves the request. The counters say which gate
//! sent it there, which is what decides whether on-core prefix work was wasted (it all runs
//! again in `dispatch()`) and why a vhost never memoizes. Exported as
//! `httpjet_fast_bridge_total{reason="…"}`.

use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum FastBridge {
    /// WAF sidecar, trusted pre-handler, or a Range request.
    PreHandler,
    Acme,
    Method,
    RequestBody,
    UrlTooLong,
    NoHost,
    NoVhost,
    /// Peer/client ACL or GeoIP refusal (dispatch renders the 403).
    Acl,
    /// Over the per-IP rate (dispatch renders the 429).
    Throttle,
    MtlsRedirect,
    MalformedPath,
    /// An auth-protected chain or target (dispatch runs the challenge).
    Auth,
    SetEnv,
    AccessDenied,
    /// Rules outside the loaded chain ran, or a hop's access phase is not implied.
    RewriteCrossDir,
    /// Redirect / status / forbidden / gone / failed / invalid target.
    RewriteTerminal,
    /// A rewrite into a non-ancestor directory (dispatch reloads the destination chain).
    RewriteNewDir,
    /// A `<context>` refusal or slash redirect.
    Context,
    PostRewrite,
    HostForeign,
    /// The rewrite changed the path (e.g. a front controller) — the static branch needs a no-op.
    Rewritten,
    ProxyContext,
    Script,
    StaticStatus,
    StaticDenied,
    /// The static body could not be promoted to memory on-core (large or ranged).
    StaticUnbuffered,
    PurgeHeader,
    /// A cookied request whose unrewritten path names no file: only dispatch() can serve it.
    CookiedNoTarget,
    /// A cookied request for a script-suffixed path: scripts never serve on-core.
    CookiedScript,
    /// A disabled or suspended vhost (the full pipeline renders the 403).
    VhostDisabled,
}

impl FastBridge {
    pub(crate) const ALL: [FastBridge; 30] = [
        FastBridge::PreHandler,
        FastBridge::Acme,
        FastBridge::Method,
        FastBridge::RequestBody,
        FastBridge::UrlTooLong,
        FastBridge::NoHost,
        FastBridge::NoVhost,
        FastBridge::Acl,
        FastBridge::Throttle,
        FastBridge::MtlsRedirect,
        FastBridge::MalformedPath,
        FastBridge::Auth,
        FastBridge::SetEnv,
        FastBridge::AccessDenied,
        FastBridge::RewriteCrossDir,
        FastBridge::RewriteTerminal,
        FastBridge::RewriteNewDir,
        FastBridge::Context,
        FastBridge::PostRewrite,
        FastBridge::HostForeign,
        FastBridge::Rewritten,
        FastBridge::ProxyContext,
        FastBridge::Script,
        FastBridge::StaticStatus,
        FastBridge::StaticDenied,
        FastBridge::StaticUnbuffered,
        FastBridge::PurgeHeader,
        FastBridge::CookiedNoTarget,
        FastBridge::CookiedScript,
        FastBridge::VhostDisabled,
    ];

    pub(crate) fn label(self) -> &'static str {
        match self {
            FastBridge::PreHandler => "pre_handler",
            FastBridge::Acme => "acme",
            FastBridge::Method => "method",
            FastBridge::RequestBody => "request_body",
            FastBridge::UrlTooLong => "url_too_long",
            FastBridge::NoHost => "no_host",
            FastBridge::NoVhost => "no_vhost",
            FastBridge::Acl => "acl",
            FastBridge::Throttle => "throttle",
            FastBridge::MtlsRedirect => "mtls_redirect",
            FastBridge::MalformedPath => "malformed_path",
            FastBridge::Auth => "auth",
            FastBridge::SetEnv => "setenv",
            FastBridge::AccessDenied => "access_denied",
            FastBridge::RewriteCrossDir => "rewrite_cross_dir",
            FastBridge::RewriteTerminal => "rewrite_terminal",
            FastBridge::RewriteNewDir => "rewrite_new_dir",
            FastBridge::Context => "context",
            FastBridge::PostRewrite => "post_rewrite",
            FastBridge::HostForeign => "host_foreign",
            FastBridge::Rewritten => "rewritten",
            FastBridge::ProxyContext => "proxy_context",
            FastBridge::Script => "script",
            FastBridge::StaticStatus => "static_status",
            FastBridge::StaticDenied => "static_denied",
            FastBridge::StaticUnbuffered => "static_unbuffered",
            FastBridge::PurgeHeader => "purge_header",
            FastBridge::CookiedNoTarget => "cookied_no_target",
            FastBridge::CookiedScript => "cookied_script",
            FastBridge::VhostDisabled => "vhost_disabled",
        }
    }
}

#[derive(Default)]
pub struct FastBridgeCounters([AtomicU64; FastBridge::ALL.len()]);

impl FastBridgeCounters {
    pub(crate) fn bump(&self, why: FastBridge) {
        if let Some(counter) = self.0.get(why as usize) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn snapshot(&self) -> impl Iterator<Item = (&'static str, u64)> + '_ {
        FastBridge::ALL.iter().map(|&r| {
            let n = self
                .0
                .get(r as usize)
                .map_or(0, |c| c.load(Ordering::Relaxed));
            (r.label(), n)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_lists_every_variant_in_discriminant_order() {
        for (i, r) in FastBridge::ALL.iter().enumerate() {
            assert_eq!(*r as usize, i, "{r:?} out of order");
        }
        assert_eq!(
            FastBridge::VhostDisabled as usize + 1,
            FastBridge::ALL.len()
        );
    }

    #[test]
    fn labels_are_unique_prometheus_values() {
        let mut seen = std::collections::HashSet::new();
        for r in FastBridge::ALL {
            let l = r.label();
            assert!(
                l.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "{l}"
            );
            assert!(seen.insert(l), "duplicate label {l}");
        }
    }

    #[test]
    fn bump_counts_per_reason() {
        let c = FastBridgeCounters::default();
        c.bump(FastBridge::Rewritten);
        c.bump(FastBridge::Rewritten);
        c.bump(FastBridge::Script);
        let snap: std::collections::HashMap<_, _> = c.snapshot().collect();
        assert_eq!(snap["rewritten"], 2);
        assert_eq!(snap["script"], 1);
        assert_eq!(snap["acl"], 0);
    }
}
