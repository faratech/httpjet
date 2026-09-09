//! Connection/request views over compatible application generations.
use crate::state::ServerState;
use arc_swap::{ArcSwap, Guard};
use std::sync::Arc;

/// A resource generation's view is pinned again when accepting a connection.
/// Compatible application reloads remain visible. An incompatible trust epoch
/// cannot replace the connection's original application/trust combination.
#[derive(Clone)]
pub(crate) struct ServingView {
    live: Arc<ArcSwap<ServerState>>,
    pinned: Arc<ServerState>,
}

impl ServingView {
    pub(crate) fn new(live: Arc<ArcSwap<ServerState>>) -> Self {
        Self {
            pinned: live.load_full(),
            live,
        }
    }

    /// Prepare against a candidate without publishing it. A fresh trust epoch
    /// keeps this view on the candidate until the live holder publishes it.
    pub(crate) fn candidate(live: Arc<ArcSwap<ServerState>>, pinned: Arc<ServerState>) -> Self {
        Self { live, pinned }
    }

    pub(crate) fn trust_epoch(&self) -> Arc<()> {
        self.pinned.trust_epoch.clone()
    }

    /// True only while this view's accept-time trust policy matches the
    /// published generation. QUIC uses this to reject, rather than admit under
    /// a stale policy, during the brief cross-core ArcSwap propagation window.
    pub(crate) fn is_current_trust_epoch(&self) -> bool {
        Arc::ptr_eq(&self.live.load().trust_epoch, &self.pinned.trust_epoch)
    }

    pub(crate) fn load(&self) -> Guard<Arc<ServerState>> {
        let current = self.live.load();
        if Arc::ptr_eq(&current.trust_epoch, &self.pinned.trust_epoch) {
            current
        } else {
            Guard::from_inner(self.pinned.clone())
        }
    }

    pub(crate) fn load_full(&self) -> Arc<ServerState> {
        Guard::into_inner(self.load())
    }

    pub(crate) fn pin_connection(&self) -> Self {
        Self {
            live: self.live.clone(),
            pinned: self.load_full(),
        }
    }
}

impl From<Arc<ArcSwap<ServerState>>> for ServingView {
    fn from(live: Arc<ArcSwap<ServerState>>) -> Self {
        Self::new(live)
    }
}

/// Selected once before dispatch and carried through a fast-path miss into the
/// Tokio bridge. Remote request headers cannot manufacture this extension.
#[derive(Clone)]
pub(crate) struct RequestGeneration(pub(crate) Arc<ServerState>);
