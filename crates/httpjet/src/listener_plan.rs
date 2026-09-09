//! Pure TCP topology planning under immutable operator launch policy.
//! Descriptor acquisition and systemd ownership checks happen separately.
use crate::uring::worker_group::TcpListenerId;
use hj_core::config::{Listener, ServerConfig};
use std::net::SocketAddr;

#[derive(Clone, Copy)]
pub(crate) struct TcpLaunchPolicy {
    pub(crate) http: SocketAddr,
    pub(crate) https: Option<SocketAddr>,
}

#[derive(Clone)]
pub(crate) struct UdsLaunchPolicy {
    pub(crate) path: std::path::PathBuf,
}

pub(crate) struct TcpTarget<'a> {
    pub(crate) identity: TcpListenerId,
    pub(crate) address: SocketAddr,
    pub(crate) listener: Option<&'a Listener>,
}

pub(crate) struct TcpPlan<'a> {
    pub(crate) http: TcpTarget<'a>,
    pub(crate) https: Option<TcpTarget<'a>>,
    // Retain configured TLS metadata even when serving TLS is disabled; ACME
    // startup validation already distinguishes configured and enabled TLS.
    pub(crate) secure_listener: Option<&'a Listener>,
}

/// All existing TCP endpoints acquired for one plan. Partial acquisition rolls
/// back by dropping duplicates; active descriptors remain worker-owned.
pub(crate) struct AcquiredTcpPlan {
    pub(crate) http: crate::uring::worker_group::PreparedTcpHandoff,
    pub(crate) https: Option<crate::uring::worker_group::PreparedTcpHandoff>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TcpTransition {
    Handoff {
        source: TcpListenerId,
        target: TcpListenerId,
        address: SocketAddr,
    },
    Add {
        target: TcpListenerId,
        address: SocketAddr,
    },
    Remove {
        source: TcpListenerId,
        address: SocketAddr,
    },
}

impl TcpPlan<'_> {
    pub(crate) fn transitions_from(&self, previous: &TcpPlan<'_>) -> Vec<TcpTransition> {
        fn compare(
            old: Option<&TcpTarget<'_>>,
            new: Option<&TcpTarget<'_>>,
            out: &mut Vec<TcpTransition>,
        ) {
            match (old, new) {
                (Some(old), Some(new)) if old.address == new.address => {
                    out.push(TcpTransition::Handoff {
                        source: old.identity.clone(),
                        target: new.identity.clone(),
                        address: new.address,
                    });
                }
                (old, new) => {
                    if let Some(old) = old {
                        out.push(TcpTransition::Remove {
                            source: old.identity.clone(),
                            address: old.address,
                        });
                    }
                    if let Some(new) = new {
                        out.push(TcpTransition::Add {
                            target: new.identity.clone(),
                            address: new.address,
                        });
                    }
                }
            }
        }
        let mut changes = Vec::with_capacity(4);
        compare(Some(&previous.http), Some(&self.http), &mut changes);
        compare(previous.https.as_ref(), self.https.as_ref(), &mut changes);
        changes
    }
}

impl TcpLaunchPolicy {
    /// Preserve the existing startup selection rules, including the historical
    /// plain-HTTP fallback to the first configured listener. XML addresses are
    /// not bind authority in this launch mode. A plan creates no sockets and
    /// does not authorize replacing inherited descriptors or QUIC endpoints.
    pub(crate) fn plan(self, config: &ServerConfig) -> TcpPlan<'_> {
        let http = config
            .listeners
            .iter()
            .find(|l| !l.secure)
            .or_else(|| config.listeners.first());
        let secure = config.listeners.iter().find(|l| l.secure);
        fn target(listener: Option<&Listener>, address: SocketAddr, tls: bool) -> TcpTarget<'_> {
            TcpTarget {
                identity: TcpListenerId {
                    name: listener.map_or("Default", |l| l.name.as_str()).into(),
                    tls,
                },
                address,
                listener,
            }
        }
        TcpPlan {
            secure_listener: secure,
            http: target(http, self.http, false),
            https: self
                .https
                .zip(secure)
                .map(|(addr, listener)| target(Some(listener), addr, true)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn listener(name: &str, secure: bool) -> Listener {
        Listener {
            name: name.into(),
            secure,
            address: "0.0.0.0:1".into(),
            vhost_map: Vec::new(),
            tls: None,
            uds_path: None,
            proxy_protocol: false,
        }
    }
    fn policy() -> TcpLaunchPolicy {
        TcpLaunchPolicy {
            http: "127.0.0.1:18080".parse().unwrap(),
            https: Some("127.0.0.1:18443".parse().unwrap()),
        }
    }
    #[test]
    fn transitions_distinguish_rename_add_remove_and_address_move() {
        let old = ServerConfig {
            listeners: vec![listener("http", false), listener("tls", true)],
            ..Default::default()
        };
        let mut renamed = old.clone();
        renamed.listeners[0].name = "new-http".into();
        renamed.listeners[1].name = "new-tls".into();
        let launch = policy();
        let changes = launch.plan(&renamed).transitions_from(&launch.plan(&old));
        assert_eq!(changes.len(), 2);
        assert!(
            matches!(&changes[0], TcpTransition::Handoff { source, target, address }
            if source.name.as_ref() == "http" && target.name.as_ref() == "new-http" && *address == launch.http)
        );
        assert!(
            matches!(&changes[1], TcpTransition::Handoff { source, target, .. }
            if source.name.as_ref() == "tls" && target.name.as_ref() == "new-tls" && source.tls && target.tls)
        );
        let mut plain = old.clone();
        plain.listeners.pop();
        let removed = launch.plan(&plain).transitions_from(&launch.plan(&old));
        assert!(matches!(&removed[1], TcpTransition::Remove { source, .. } if source.tls));
        let added = launch.plan(&old).transitions_from(&launch.plan(&plain));
        assert!(matches!(&added[1], TcpTransition::Add { target, .. } if target.tls));
        let moved = TcpLaunchPolicy {
            http: "127.0.0.1:18081".parse().unwrap(),
            ..launch
        };
        let changes = moved.plan(&old).transitions_from(&launch.plan(&old));
        assert!(matches!(&changes[0], TcpTransition::Remove { source, .. } if !source.tls));
        assert!(matches!(&changes[1], TcpTransition::Add { target, .. } if !target.tls));
        assert_eq!(changes.len(), 3);
    }

    #[test]
    fn xml_cannot_override_launch_bind_addresses_or_enable_disabled_tls() {
        let cfg = ServerConfig {
            listeners: vec![listener("secure", true), listener("plain", false)],
            ..Default::default()
        };
        let plan = policy().plan(&cfg);
        assert_eq!(plan.http.identity.name.as_ref(), "plain");
        assert!(!plan.http.identity.tls);
        assert_eq!(plan.http.address, policy().http);
        let tls = plan.https.unwrap();
        assert_eq!(tls.identity.name.as_ref(), "secure");
        assert!(tls.identity.tls);
        assert_eq!(Some(tls.address), policy().https);
        assert!(
            TcpLaunchPolicy {
                https: None,
                ..policy()
            }
            .plan(&cfg)
            .https
            .is_none()
        );
    }
    #[test]
    fn empty_and_secure_only_configs_preserve_startup_fallback() {
        let cfg = ServerConfig::default();
        let plan = policy().plan(&cfg);
        assert_eq!(plan.http.identity.name.as_ref(), "Default");
        assert!(plan.http.listener.is_none());
        assert!(plan.https.is_none());
        let cfg = ServerConfig {
            listeners: vec![listener("secure", true)],
            ..Default::default()
        };
        let plan = policy().plan(&cfg);
        assert_eq!(plan.http.identity.name.as_ref(), "secure");
        assert!(std::ptr::eq(plan.http.listener.unwrap(), &cfg.listeners[0]));
        assert_ne!(plan.http.identity, plan.https.unwrap().identity);
    }
    #[test]
    fn candidate_plan_reads_candidate_policy_without_mutating_launch_policy() {
        let launch = policy();
        let mut cfg = ServerConfig {
            listeners: vec![listener("old", false)],
            ..Default::default()
        };
        assert_eq!(launch.plan(&cfg).http.identity.name.as_ref(), "old");
        cfg.listeners = vec![listener("tls", true), listener("new", false)];
        cfg.listeners[1].proxy_protocol = true;
        let plan = launch.plan(&cfg);
        assert_eq!(plan.http.identity.name.as_ref(), "new");
        assert!(plan.http.listener.unwrap().proxy_protocol);
        assert_eq!(plan.http.address, launch.http);
        assert!(plan.https.is_some());
    }
}
