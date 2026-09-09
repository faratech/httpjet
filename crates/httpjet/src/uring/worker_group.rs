//! Ownership of transport threads, including partial-startup rollback.

use std::{io, thread};
use tokio_util::sync::CancellationToken;

const MAX_RACED_ACCEPTS: usize = 1024;

/// Logical lookup key within a resource generation. This does not establish
/// socket ownership or policy compatibility: handoff still verifies SO_COOKIE
/// sets and the coordinator verifies the owning trust epoch.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct TcpListenerId {
    pub(crate) name: std::sync::Arc<str>,
    pub(crate) tls: bool,
}

/// Linux assigns a socket cookie to the kernel socket, not its descriptor or
/// address. Duplicated descriptors compare equal; separately bound reuseport
/// sockets do not. Query while the factory still owns the listening descriptor.
fn listener_cookie(listener: &std::net::TcpListener) -> io::Result<u64> {
    use std::os::fd::AsRawFd;
    let mut accepting: libc::c_int = 0;
    let mut length = std::mem::size_of_val(&accepting) as libc::socklen_t;
    // SAFETY: both option buffers and their lengths match the kernel option ABI.
    let result = unsafe {
        libc::getsockopt(
            listener.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ACCEPTCONN,
            (&mut accepting as *mut libc::c_int).cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if accepting != 1 || length as usize != std::mem::size_of_val(&accepting) {
        return Err(io::Error::other("TCP resource is not a listening socket"));
    }
    let mut cookie: u64 = 0;
    let mut length = std::mem::size_of_val(&cookie) as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            listener.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_COOKIE,
            (&mut cookie as *mut u64).cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if length as usize != std::mem::size_of_val(&cookie) {
        return Err(io::Error::other("invalid listening socket identity"));
    }
    Ok(cookie)
}

/// Retain this owner while serving. Dropping it signals every worker before
/// joining any worker. Cancellation flows from the process to this group, never
/// from a failed candidate back to the process or another listener group.
///
/// Joining is synchronous: workers must implement cancellation and their own
/// drain deadline. This does not bound an uninterruptible kernel operation.
#[must_use = "dropping the group stops and joins its listener workers"]
pub(crate) struct WorkerGroup {
    shutdown: CancellationToken,
    activation: CancellationToken,
    trust_epoch: Option<std::sync::Arc<()>>,
    tcp_identity: Option<TcpListenerId>,
    uds_identity: Option<std::path::PathBuf>,
    accept_stopped: Vec<CancellationToken>,
    listener_sockets: std::collections::BTreeSet<u64>,
    listener_owners: Vec<std::sync::Weak<std::net::TcpListener>>,
    topology_frozen: std::sync::atomic::AtomicBool,
    predecessors: std::sync::Arc<std::sync::OnceLock<AcceptHandoff>>,
    uds_predecessor: std::sync::Arc<std::sync::OnceLock<CancellationToken>>,
    uds_listener: Option<std::sync::Weak<std::os::unix::net::UnixListener>>,
    uds_stop_ack: Option<CancellationToken>,
    uds_path_owner: Option<std::sync::Arc<super::unix_path::OwnedUnixPath>>,
    raced: Option<(
        flume::Sender<std::net::TcpStream>,
        flume::Receiver<std::net::TcpStream>,
    )>,
    threads: Vec<thread::JoinHandle<()>>,
}

/// A one-way readiness-to-serving barrier. Cancellation wins when both signals
/// are already present. Only the group owner can release this barrier.
#[derive(Clone)]
pub(crate) struct ActivationGate {
    shutdown: CancellationToken,
    activation: CancellationToken,
    predecessors: std::sync::Arc<std::sync::OnceLock<AcceptHandoff>>,
    uds_predecessor: std::sync::Arc<std::sync::OnceLock<CancellationToken>>,
}

/// Opaque predecessor acknowledgments; only TCP worker factories register them.
#[derive(Clone)]
pub(crate) struct AcceptHandoff {
    stopped: Vec<CancellationToken>,
    listener_sockets: std::collections::BTreeSet<u64>,
    raced: flume::Receiver<std::net::TcpStream>,
}

pub(crate) struct AcceptRetirement {
    stopped: CancellationToken,
    raced: flume::Sender<std::net::TcpStream>,
    listener: Option<std::sync::Arc<std::net::TcpListener>>,
}

impl AcceptRetirement {
    pub(crate) fn cancel(&mut self) {
        self.listener.take();
        self.stopped.cancel();
    }

    pub(crate) fn transfer(&self, stream: std::net::TcpStream) {
        // One receiver is retained by the old owner solely for future candidate
        // registration. Ordinary shutdown has no successor and closes the fd.
        if self.raced.receiver_count() > 1 && self.raced.try_send(stream).is_err() {
            tracing::warn!("TCP handoff queue full or successor gone; rejecting raced connection");
        }
    }
}

/// Pin active socket ownership briefly under the coordinator lock, then duplicate
/// descriptors outside it. Dropping the source or prepared candidate closes only
/// these extra owners, never the active workers' descriptors.
pub(crate) struct TcpHandoffSource {
    listeners: Vec<std::sync::Arc<std::net::TcpListener>>,
    predecessor: AcceptHandoff,
}

pub(crate) struct PreparedTcpHandoff {
    pub(crate) listeners: Vec<std::net::TcpListener>,
    pub(crate) predecessor: AcceptHandoff,
}

/// A duplicated AF_UNIX listener plus shared pathname ownership. The shared
/// owner prevents retirement of the predecessor from unlinking the live
/// successor's pathname.
pub(crate) struct PreparedUdsHandoff {
    pub(crate) listener: std::os::unix::net::UnixListener,
    predecessor: CancellationToken,
    path_owner: Option<std::sync::Arc<super::unix_path::OwnedUnixPath>>,
}

pub(crate) struct UdsHandoffSource {
    identity: std::path::PathBuf,
    listener: std::sync::Arc<std::os::unix::net::UnixListener>,
    predecessor: CancellationToken,
    path_owner: Option<std::sync::Arc<super::unix_path::OwnedUnixPath>>,
}

pub(crate) struct UdsAcceptRetirement {
    stopped: CancellationToken,
    listener: Option<std::sync::Arc<std::os::unix::net::UnixListener>>,
}

impl UdsAcceptRetirement {
    pub(crate) fn cancel(&mut self) {
        self.listener.take();
        self.stopped.cancel();
    }
}

impl Drop for UdsAcceptRetirement {
    fn drop(&mut self) {
        self.cancel();
    }
}

impl UdsHandoffSource {
    pub(crate) fn prepare(self, expected_path: &std::path::Path) -> io::Result<PreparedUdsHandoff> {
        if self.identity != expected_path {
            return Err(io::Error::other(
                "UDS handoff endpoint differs from planned path",
            ));
        }
        Ok(PreparedUdsHandoff {
            listener: self.listener.try_clone()?,
            predecessor: self.predecessor,
            path_owner: self.path_owner,
        })
    }
}

impl PreparedUdsHandoff {
    pub(crate) fn into_parts(
        self,
    ) -> (
        std::os::unix::net::UnixListener,
        CancellationToken,
        Option<std::sync::Arc<super::unix_path::OwnedUnixPath>>,
    ) {
        (self.listener, self.predecessor, self.path_owner)
    }
}

impl TcpHandoffSource {
    pub(crate) fn prepare(
        self,
        expected_address: std::net::SocketAddr,
    ) -> io::Result<PreparedTcpHandoff> {
        // Check every inherited/reuseport descriptor before cloning any. Name
        // selection alone does not prove that this is the requested endpoint.
        if self.listeners.is_empty() || expected_address.port() == 0 {
            return Err(io::Error::other("TCP handoff requires a resolved endpoint"));
        }
        for socket in &self.listeners {
            if socket.local_addr()? != expected_address {
                return Err(io::Error::other(
                    "TCP handoff endpoint differs from planned address",
                ));
            }
        }
        let listeners = self
            .listeners
            .iter()
            .map(|socket| socket.try_clone())
            .collect::<io::Result<_>>()?;
        Ok(PreparedTcpHandoff {
            listeners,
            predecessor: self.predecessor,
        })
    }
}

impl ActivationGate {
    pub(crate) async fn wait(&self) -> bool {
        let activated = tokio::select! {
            biased;
            _ = self.shutdown.cancelled() => false,
            _ = self.activation.cancelled() => !self.shutdown.is_cancelled(),
        };
        if !activated {
            return false;
        }
        if let Some(predecessors) = self.predecessors.get() {
            for stopped in &predecessors.stopped {
                tokio::select! {
                    biased;
                    _ = self.shutdown.cancelled() => return false,
                    _ = stopped.cancelled() => {},
                }
            }
        }
        if let Some(stopped) = self.uds_predecessor.get() {
            tokio::select! {
                biased;
                _ = self.shutdown.cancelled() => return false,
                _ = stopped.cancelled() => {},
            }
        }
        !self.shutdown.is_cancelled()
    }

    pub(crate) fn raced_connections(&self) -> Option<flume::Receiver<std::net::TcpStream>> {
        self.predecessors.get().map(|old| old.raced.clone())
    }
}

impl WorkerGroup {
    pub(crate) fn new(parent: &CancellationToken) -> Self {
        Self {
            shutdown: parent.child_token(),
            activation: CancellationToken::new(),
            trust_epoch: None,
            tcp_identity: None,
            uds_identity: None,
            accept_stopped: Vec::new(),
            listener_sockets: Default::default(),
            listener_owners: Vec::new(),
            topology_frozen: std::sync::atomic::AtomicBool::new(false),
            predecessors: Default::default(),
            uds_predecessor: Default::default(),
            uds_listener: None,
            uds_stop_ack: None,
            uds_path_owner: None,
            raced: None,
            threads: Vec::new(),
        }
    }

    pub(crate) fn for_epoch(parent: &CancellationToken, epoch: std::sync::Arc<()>) -> Self {
        let mut group = Self::new(parent);
        group.trust_epoch = Some(epoch);
        group
    }

    pub(crate) fn for_tcp_epoch(
        parent: &CancellationToken,
        epoch: std::sync::Arc<()>,
        identity: TcpListenerId,
    ) -> Self {
        let mut group = Self::for_epoch(parent, epoch);
        group.tcp_identity = Some(identity);
        group
    }

    pub(crate) fn for_uds_epoch(
        parent: &CancellationToken,
        epoch: std::sync::Arc<()>,
        path: std::path::PathBuf,
    ) -> Self {
        let mut group = Self::for_epoch(parent, epoch);
        group.uds_identity = Some(path);
        group
    }

    pub(crate) fn tcp_identity(&self) -> Option<&TcpListenerId> {
        self.tcp_identity.as_ref()
    }

    pub(crate) fn uds_identity(&self) -> Option<&std::path::Path> {
        self.uds_identity.as_deref()
    }

    pub(crate) fn is_prepared_for(&self, epoch: &std::sync::Arc<()>) -> bool {
        let uds_shape = match (
            self.uds_identity.as_ref(),
            self.uds_listener.as_ref(),
            self.uds_stop_ack.as_ref(),
        ) {
            (None, None, None) => true,
            (Some(_), Some(listener), Some(_)) => listener.upgrade().is_some(),
            _ => false,
        };
        self.trust_epoch
            .as_ref()
            .is_some_and(|owned| std::sync::Arc::ptr_eq(owned, epoch))
            && !(self.tcp_identity.is_some() && self.uds_identity.is_some())
            && uds_shape
            && !self.activation.is_cancelled()
            && !self.shutdown.is_cancelled()
            && self.threads.iter().all(|thread| !thread.is_finished())
    }

    pub(crate) fn activation_gate(&self) -> ActivationGate {
        ActivationGate {
            shutdown: self.shutdown.clone(),
            activation: self.activation.clone(),
            predecessors: self.predecessors.clone(),
            uds_predecessor: self.uds_predecessor.clone(),
        }
    }

    pub(crate) fn register_uds_acceptor(
        &mut self,
        listener: std::sync::Arc<std::os::unix::net::UnixListener>,
        path_owner: Option<std::sync::Arc<super::unix_path::OwnedUnixPath>>,
    ) -> io::Result<UdsAcceptRetirement> {
        let expected = self
            .uds_identity
            .as_deref()
            .ok_or_else(|| io::Error::other("group has no UDS identity"))?;
        let identity_matches = path_owner.as_ref().map_or_else(
            || {
                listener
                    .local_addr()
                    .is_ok_and(|addr| addr.as_pathname() == Some(expected))
            },
            |owner| owner.matches_requested_path(expected),
        );
        if self.activation.is_cancelled()
            || self.tcp_identity.is_some()
            || self.uds_listener.is_some()
            || self.uds_predecessor.get().is_some()
            || !identity_matches
        {
            return Err(io::Error::other("invalid UDS acceptor registration"));
        }
        let stopped = CancellationToken::new();
        self.uds_listener = Some(std::sync::Arc::downgrade(&listener));
        self.uds_stop_ack = Some(stopped.clone());
        self.uds_path_owner = path_owner;
        Ok(UdsAcceptRetirement {
            stopped: stopped.clone(),
            listener: Some(listener),
        })
    }

    pub(crate) fn uds_handoff_source(&self) -> io::Result<UdsHandoffSource> {
        if !self.activation.is_cancelled()
            || self.shutdown.is_cancelled()
            || self.threads.iter().any(|worker| worker.is_finished())
        {
            return Err(io::Error::other("UDS listener is not active"));
        }
        let listener = self
            .uds_listener
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
            .ok_or_else(|| io::Error::other("not a UDS group"))?;
        let predecessor = self
            .uds_accept_stopped()
            .ok_or_else(|| io::Error::other("UDS acceptor is missing"))?;
        Ok(UdsHandoffSource {
            identity: self
                .uds_identity
                .clone()
                .expect("registered UDS listener has an identity"),
            listener,
            predecessor,
            path_owner: self.uds_path_owner.clone(),
        })
    }

    fn uds_accept_stopped(&self) -> Option<CancellationToken> {
        // The worker-owned retirement handle holds the only other clone and
        // cancels it after its accept loop has stopped.
        self.uds_stop_ack.clone()
    }

    pub(crate) fn register_acceptor(
        &mut self,
        listener: &std::net::TcpListener,
    ) -> io::Result<AcceptRetirement> {
        if self.activation.is_cancelled()
            || self.predecessors.get().is_some()
            || self
                .topology_frozen
                .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(io::Error::other("acceptor topology is already frozen"));
        }
        let cookie = listener_cookie(listener)?;
        let listener = std::sync::Arc::new(listener.try_clone()?);
        self.listener_sockets.insert(cookie);
        self.listener_owners
            .push(std::sync::Arc::downgrade(&listener));
        let stopped = CancellationToken::new();
        self.accept_stopped.push(stopped.clone());
        let (sender, _) = self
            .raced
            .get_or_insert_with(|| flume::bounded(MAX_RACED_ACCEPTS));
        Ok(AcceptRetirement {
            stopped,
            raced: sender.clone(),
            listener: Some(listener),
        })
    }

    pub(crate) fn tcp_handoff_source(&self) -> io::Result<TcpHandoffSource> {
        if !self.activation.is_cancelled()
            || self.shutdown.is_cancelled()
            || self.threads.iter().any(|worker| worker.is_finished())
        {
            return Err(io::Error::other("TCP listener is not active"));
        }
        let predecessor = self
            .accept_handoff()
            .ok_or_else(|| io::Error::other("not a TCP group"))?;
        let listeners = self
            .listener_owners
            .iter()
            .map(|owner| {
                owner
                    .upgrade()
                    .ok_or_else(|| io::Error::other("TCP listener is retiring"))
            })
            .collect::<io::Result<Vec<_>>>()?;
        Ok(TcpHandoffSource {
            listeners,
            predecessor,
        })
    }

    pub(crate) fn accept_handoff(&self) -> Option<AcceptHandoff> {
        self.topology_frozen
            .store(true, std::sync::atomic::Ordering::Release);
        self.raced.as_ref().map(|(_, receiver)| AcceptHandoff {
            stopped: self.accept_stopped.clone(),
            listener_sockets: self.listener_sockets.clone(),
            raced: receiver.clone(),
        })
    }

    /// Bind a prepared TCP successor to the old workers' explicit kernel-accept
    /// completion acknowledgments. This does not stop the predecessor itself.
    #[allow(dead_code)] // Resource topology acquisition wires this before publication.
    pub(crate) fn follow_acceptors(&self, predecessor: AcceptHandoff) -> io::Result<()> {
        if self.activation.is_cancelled()
            || self.shutdown.is_cancelled()
            || self.accept_stopped.is_empty()
            || self.listener_sockets != predecessor.listener_sockets
        {
            return Err(io::Error::other("invalid acceptor handoff"));
        }
        self.predecessors
            .set(predecessor)
            .map_err(|_| io::Error::other("acceptor handoff already assigned"))
    }

    /// Wait for the predecessor's AF_UNIX accept loop to stop before the
    /// duplicated listener begins accepting. The kernel accept queue remains
    /// attached to the shared socket inode throughout the handoff.
    pub(crate) fn follow_uds_acceptor(&self, predecessor: CancellationToken) -> io::Result<()> {
        if self.activation.is_cancelled()
            || self.shutdown.is_cancelled()
            || self.uds_listener.is_none()
            || predecessor.is_cancelled()
        {
            return Err(io::Error::other("invalid UDS acceptor handoff"));
        }
        self.uds_predecessor
            .set(predecessor)
            .map_err(|_| io::Error::other("UDS acceptor handoff already assigned"))
    }

    /// Release prepared workers. No allocation, bind or worker spawn occurs here.
    /// The caller must establish the publication/close boundary before activating.
    pub(crate) fn activate(&self) {
        self.activation.cancel();
    }

    pub(crate) fn stop(&self) {
        self.shutdown.cancel();
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.threads.iter().all(thread::JoinHandle::is_finished)
    }

    pub(crate) fn spawn(
        &mut self,
        builder: thread::Builder,
        run: impl FnOnce(CancellationToken) + Send + 'static,
    ) -> io::Result<()> {
        let shutdown = self.shutdown.clone();
        self.threads.push(builder.spawn(move || run(shutdown))?);
        Ok(())
    }
}

impl Drop for WorkerGroup {
    fn drop(&mut self) {
        self.shutdown.cancel();
        for handle in self.threads.drain(..) {
            // A panicking worker still must not prevent joining its siblings.
            if handle.join().is_err() {
                tracing::error!("transport worker panicked during retirement");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    struct UdsFixture(std::path::PathBuf);

    impl UdsFixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "hj-uds-handoff-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn socket(&self) -> std::path::PathBuf {
            self.0.join("http.sock")
        }
    }

    impl Drop for UdsFixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[tokio::test]
    async fn uds_handoff_preserves_path_owner_and_waits_for_predecessor() {
        let fixture = UdsFixture::new();
        let path = fixture.socket();
        let (listener, owner) = super::super::unix_path::OwnedUnixPath::bind(&path).unwrap();
        let parent = CancellationToken::new();
        let old_epoch = Arc::new(());
        let mut old = WorkerGroup::for_uds_epoch(&parent, old_epoch, path.clone());
        let mut old_retirement = old
            .register_uds_acceptor(Arc::new(listener), Some(Arc::new(owner)))
            .unwrap();
        old.activate();

        assert!(
            old.uds_handoff_source()
                .unwrap()
                .prepare(&fixture.0.join("wrong.sock"))
                .is_err()
        );
        let prepared = old.uds_handoff_source().unwrap().prepare(&path).unwrap();
        let (listener, predecessor, owner) = prepared.into_parts();
        let new_epoch = Arc::new(());
        let mut next = WorkerGroup::for_uds_epoch(&parent, new_epoch, path.clone());
        let mut next_retirement = next
            .register_uds_acceptor(Arc::new(listener), owner)
            .unwrap();
        next.follow_uds_acceptor(predecessor).unwrap();
        let gate = next.activation_gate();
        next.activate();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), gate.wait())
                .await
                .is_err(),
            "successor must not accept beside its predecessor"
        );

        old_retirement.cancel();
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), gate.wait())
                .await
                .unwrap()
        );
        drop(old);
        assert!(path.exists(), "successor retains pathname ownership");

        next_retirement.cancel();
        drop(next);
        assert!(!path.exists(), "last generation removes its owned pathname");
        assert!(!parent.is_cancelled());
    }

    fn waiting_worker(token: CancellationToken, exited: Arc<AtomicUsize>) {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(token.cancelled());
        exited.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn tcp_acquisition_rejects_mixed_endpoints_without_changing_active_ownership() {
        let first = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let second = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = first.local_addr().unwrap();
        let other = second.local_addr().unwrap();
        let parent = CancellationToken::new();
        let mut group = WorkerGroup::new(&parent);
        let mut first_owner = group.register_acceptor(&first).unwrap();
        let mut second_owner = group.register_acceptor(&second).unwrap();
        group.activate();
        for expected in [address, other, "127.0.0.1:0".parse().unwrap()] {
            assert!(
                group
                    .tcp_handoff_source()
                    .unwrap()
                    .prepare(expected)
                    .is_err()
            );
        }
        // A rejected candidate must not stop either acceptor or steal its fd.
        let one = std::net::TcpStream::connect(address).unwrap();
        let two = std::net::TcpStream::connect(other).unwrap();
        drop(first.accept().unwrap());
        drop(second.accept().unwrap());
        drop((one, two));
        group.stop();
        first_owner.cancel();
        second_owner.cancel();
        drop((first, second, group));
        assert!(!parent.is_cancelled());
    }

    #[test]
    fn tcp_source_acquisition_preserves_identity_and_releases_rollback_owners() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let identity = listener_cookie(&listener).unwrap();
        let parent = CancellationToken::new();
        let mut group = WorkerGroup::new(&parent);
        let mut retirement = group.register_acceptor(&listener).unwrap();
        assert!(
            group.tcp_handoff_source().is_err(),
            "prepared is not active"
        );
        group.activate();
        let candidate = group
            .tcp_handoff_source()
            .unwrap()
            .prepare(address)
            .unwrap();
        assert_eq!(candidate.listeners.len(), 1);
        assert_eq!(listener_cookie(&candidate.listeners[0]).unwrap(), identity);
        drop(candidate);
        // Rollback did not steal active ownership: another acquisition works.
        let source = group.tcp_handoff_source().unwrap();
        drop(source);
        drop(listener);
        group.stop();
        assert!(
            group.tcp_handoff_source().is_err(),
            "retiring is not active"
        );
        retirement.cancel();
        let rebound = std::net::TcpListener::bind(address).unwrap();
        drop(rebound);
        assert!(!parent.is_cancelled());
    }

    #[test]
    fn handoff_requires_identical_kernel_socket_set_not_matching_addresses() {
        let first = super::super::reuseport_std_listener("127.0.0.1:0".parse().unwrap()).unwrap();
        let duplicate = first.try_clone().unwrap();
        let separate = super::super::reuseport_std_listener(first.local_addr().unwrap()).unwrap();
        assert_eq!(
            listener_cookie(&first).unwrap(),
            listener_cookie(&duplicate).unwrap()
        );
        assert_ne!(
            listener_cookie(&first).unwrap(),
            listener_cookie(&separate).unwrap()
        );
        let parent = CancellationToken::new();
        let mut old = WorkerGroup::new(&parent);
        old.register_acceptor(&first).unwrap();
        let mut wrong = WorkerGroup::new(&parent);
        wrong.register_acceptor(&separate).unwrap();
        assert!(
            wrong
                .follow_acceptors(old.accept_handoff().unwrap())
                .is_err()
        );

        let mut same = WorkerGroup::new(&parent);
        same.register_acceptor(&duplicate).unwrap();
        same.follow_acceptors(old.accept_handoff().unwrap())
            .unwrap();
        assert!(
            same.register_acceptor(&separate).is_err(),
            "identity set is frozen after handoff assignment"
        );

        // An inherited reuseport set can contain several distinct kernel queues.
        // Keeping only one queue would strand the rest, despite matching ports.
        assert!(
            old.register_acceptor(&separate).is_err(),
            "exported predecessor topology is frozen"
        );
        let mut old_set = WorkerGroup::new(&parent);
        old_set.register_acceptor(&first).unwrap();
        old_set.register_acceptor(&separate).unwrap();
        let mut incomplete = WorkerGroup::new(&parent);
        incomplete.register_acceptor(&duplicate).unwrap();
        assert!(
            incomplete
                .follow_acceptors(old_set.accept_handoff().unwrap())
                .is_err()
        );
        let mut complete = WorkerGroup::new(&parent);
        complete.register_acceptor(&duplicate).unwrap();
        complete
            .register_acceptor(&separate.try_clone().unwrap())
            .unwrap();
        complete
            .follow_acceptors(old_set.accept_handoff().unwrap())
            .unwrap();
        assert!(!parent.is_cancelled());
    }

    #[test]
    fn non_listening_descriptor_cannot_register_tcp_handoff() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let fd: std::os::fd::OwnedFd = socket.into();
        let listener = std::net::TcpListener::from(fd);
        let mut group = WorkerGroup::new(&CancellationToken::new());
        assert!(group.register_acceptor(&listener).is_err());
        assert!(group.accept_handoff().is_none());
    }

    #[test]
    fn raced_accept_queue_is_bounded_and_shutdown_without_successor_closes() {
        use std::io::Read;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let (stream, _) = listener.accept().unwrap();
        let parent = CancellationToken::new();
        let mut group = WorkerGroup::new(&parent);
        let retirement = group.register_acceptor(&listener).unwrap();
        retirement.transfer(stream.try_clone().unwrap());
        assert_eq!(
            group.raced.as_ref().unwrap().1.len(),
            0,
            "no successor means no queueing"
        );
        let successor = group.accept_handoff().unwrap();
        for _ in 0..MAX_RACED_ACCEPTS + 1 {
            retirement.transfer(stream.try_clone().unwrap());
        }
        assert_eq!(successor.raced.len(), MAX_RACED_ACCEPTS);
        drop(stream);
        drop(successor);
        drop(retirement);
        drop(group);
        assert_eq!(
            client.read(&mut [0u8; 1]).unwrap(),
            0,
            "all queued fd owners must close"
        );
        assert!(!parent.is_cancelled());
    }

    #[tokio::test]
    async fn successor_waits_for_every_acceptor_and_remains_cancellable() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let parent = CancellationToken::new();
        let mut old = WorkerGroup::new(&parent);
        let mut first = old.register_acceptor(&listener).unwrap();
        let mut second = old.register_acceptor(&listener).unwrap();
        let mut next = WorkerGroup::new(&parent);
        next.register_acceptor(&listener).unwrap();
        let gate = next.activation_gate();
        next.follow_acceptors(old.accept_handoff().unwrap())
            .unwrap();
        assert!(
            next.follow_acceptors(old.accept_handoff().unwrap())
                .is_err()
        );
        next.activate();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), gate.wait())
                .await
                .is_err()
        );
        first.cancel();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), gate.wait())
                .await
                .is_err()
        );
        second.cancel();
        assert!(gate.wait().await);
        assert!(!parent.is_cancelled());

        let mut pending = WorkerGroup::new(&parent);
        pending.register_acceptor(&listener).unwrap();
        let mut cancelled = WorkerGroup::new(&parent);
        cancelled.register_acceptor(&listener).unwrap();
        cancelled
            .follow_acceptors(pending.accept_handoff().unwrap())
            .unwrap();
        let gate = cancelled.activation_gate();
        cancelled.activate();
        cancelled.stop();
        assert!(!gate.wait().await);
        assert!(!parent.is_cancelled());
    }

    #[tokio::test]
    async fn activation_is_explicit_and_cancellation_takes_precedence() {
        let parent = CancellationToken::new();
        let group = WorkerGroup::new(&parent);
        let gate = group.activation_gate();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), gate.wait())
                .await
                .is_err()
        );
        group.activate();
        assert!(gate.wait().await);
        assert!(
            gate.wait().await,
            "activation is retained, not a one-shot wake"
        );
        parent.cancel();
        group.activate();
        assert!(
            !gate.wait().await,
            "activation cannot revive a cancelled group"
        );
    }

    #[test]
    fn dropping_prepared_group_releases_waiters_without_activation() {
        let parent = CancellationToken::new();
        let mut group = WorkerGroup::new(&parent);
        let exited = Arc::new(AtomicUsize::new(0));
        for _ in 0..3 {
            let gate = group.activation_gate();
            let exited = exited.clone();
            group
                .spawn(thread::Builder::new(), move |_| {
                    let active = tokio::runtime::Builder::new_current_thread()
                        .build()
                        .unwrap()
                        .block_on(gate.wait());
                    assert!(!active, "rollback must not activate a prepared worker");
                    exited.fetch_add(1, Ordering::SeqCst);
                })
                .unwrap();
        }
        drop(group);
        assert_eq!(exited.load(Ordering::SeqCst), 3);
        assert!(!parent.is_cancelled());
    }

    #[test]
    fn dropping_group_joins_all_workers_without_cancelling_siblings() {
        let parent = CancellationToken::new();
        let sibling = parent.child_token();
        let exited = Arc::new(AtomicUsize::new(0));
        let mut group = WorkerGroup::new(&parent);
        for _ in 0..3 {
            let exited = exited.clone();
            group
                .spawn(thread::Builder::new(), move |token| {
                    waiting_worker(token, exited)
                })
                .unwrap();
        }
        drop(group);
        assert_eq!(exited.load(Ordering::SeqCst), 3);
        assert!(!parent.is_cancelled());
        assert!(!sibling.is_cancelled());
    }

    #[test]
    fn process_cancellation_reaches_owned_workers() {
        let parent = CancellationToken::new();
        let exited = Arc::new(AtomicUsize::new(0));
        let mut group = WorkerGroup::new(&parent);
        let done = exited.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        group
            .spawn(thread::Builder::new(), move |token| {
                waiting_worker(token, done);
                tx.send(()).unwrap();
            })
            .unwrap();
        parent.cancel();
        rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        assert_eq!(exited.load(Ordering::SeqCst), 1);
        drop(group);
    }

    #[test]
    fn failed_spawn_rolls_back_previously_started_workers() {
        let parent = CancellationToken::new();
        let exited = Arc::new(AtomicUsize::new(0));
        let start = || -> io::Result<WorkerGroup> {
            let mut group = WorkerGroup::new(&parent);
            let done = exited.clone();
            group.spawn(thread::Builder::new(), move |token| {
                waiting_worker(token, done)
            })?;
            // Impossible stack allocation gives a deterministic OS spawn error.
            group.spawn(thread::Builder::new().stack_size(usize::MAX), |_| {})?;
            Ok(group)
        };
        assert!(start().is_err());
        assert_eq!(exited.load(Ordering::SeqCst), 1);
        assert!(!parent.is_cancelled());
    }

    #[test]
    fn retirement_wakes_io_uring_accept_and_releases_listener() {
        let parent = CancellationToken::new();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut group = WorkerGroup::new(&parent);
        let (tx, rx) = std::sync::mpsc::channel();
        group
            .spawn(thread::Builder::new(), move |shutdown| {
                let mut runtime = super::super::build_core_runtime().unwrap();
                runtime.block_on(async move {
                let listener = monoio::net::TcpListener::from_std(listener).unwrap();
                tx.send(()).unwrap();
                monoio::select! {
                    _ = shutdown.cancelled() => {},
                    _ = listener.accept() => panic!("unexpected connection to isolated listener"),
                }
            });
            })
            .unwrap();
        rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        drop(group);
        assert!(!parent.is_cancelled());
        // No detached runtime or descriptor keeps this address occupied.
        let replacement = std::net::TcpListener::bind(address).unwrap();
        drop(replacement);
    }

    #[test]
    fn quic_driver_setup_failure_rejects_prepared_group() {
        use super::super::{bridge, h3};
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let bridge = runtime.block_on(async {
            bridge::spawn_on_current(2, |_, _| async {
                http::Response::new(hj_core::Body::Empty)
            })
        });
        // A real but incompatible datagram descriptor reaches driver probing:
        // adopting a descriptor alone must not acknowledge QUIC readiness.
        let (socket, peer) = std::os::unix::net::UnixDatagram::pair().unwrap();
        let fd: std::os::fd::OwnedFd = socket.into();
        let socket = std::net::UdpSocket::from(fd);
        let valid = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = valid.local_addr().unwrap();
        let parent = CancellationToken::new();
        let result = h3::serve_h3_pipeline(
            address,
            2,
            h3::self_signed_config().unwrap(),
            bridge,
            false,
            h3::H3RuntimeConfig::new(
                || (h3::H3RequestLimits::new(16_384, 1024), 2),
                Arc::new(std::sync::atomic::AtomicU64::new(0)),
                Arc::new(hj_core::budget::BodyBufferBudget::new(4096)),
            ),
            Some(vec![valid, socket]),
            parent.clone(),
        );
        assert!(result.is_err(), "driver setup must fail before readiness");
        assert!(!parent.is_cancelled());
        assert!(peer.send(b"closed candidate").is_err());
        // The valid sibling is joined too, even when it reached readiness first.
        let replacement = std::net::UdpSocket::bind(address).unwrap();
        drop(replacement);
    }

    #[test]
    fn quic_group_retirement_releases_udp_socket_without_process_shutdown() {
        use super::super::{bridge, h3};
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let bridge = runtime.block_on(async {
            bridge::spawn_on_current(2, |_, _| async {
                http::Response::new(hj_core::Body::Empty)
            })
        });
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        let parent = CancellationToken::new();
        let (group, _policy) = h3::serve_h3_pipeline(
            address,
            1,
            h3::self_signed_config().unwrap(),
            bridge,
            false,
            h3::H3RuntimeConfig::new(
                || (h3::H3RequestLimits::new(16_384, 1024), 2),
                Arc::new(std::sync::atomic::AtomicU64::new(0)),
                Arc::new(hj_core::budget::BodyBufferBudget::new(4096)),
            ),
            Some(vec![socket]),
            parent.clone(),
        )
        .unwrap();
        group.activate();
        drop(group);
        assert!(!parent.is_cancelled());
        let replacement = std::net::UdpSocket::bind(address).unwrap();
        drop(replacement);
    }

    #[test]
    fn prepared_http_waits_for_activation_before_serving() {
        tcp_activation(false);
    }

    #[test]
    fn prepared_tls_waits_for_activation_before_handshake() {
        tcp_activation(true);
    }

    fn tcp_activation(tls: bool) {
        use super::super::{
            ListenerBinding, h3, pipeline_admission, spawn_uring_http, spawn_uring_https,
        };
        use std::io::{Read, Write};
        let root = std::env::temp_dir().join(format!(
            "hj-activation-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("index.html"), b"activated response").unwrap();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let state = runtime.block_on(async { crate::pipeline::e2e::build_state(root.clone()) });
        let server_root = state.server.server_root.clone();
        let shutdown = state.shutdown.clone();
        let active = state.metrics.active_conns.clone();
        let holder = Arc::new(arc_swap::ArcSwap::from(state));
        let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let address = socket.local_addr().unwrap();
        let group = runtime.block_on(async {
            let admission = pipeline_admission(holder.clone());
            if tls {
                spawn_uring_https(
                    holder,
                    "http".into(),
                    address,
                    1,
                    h3::self_signed_config().unwrap(),
                    false,
                    None,
                    Some(vec![socket]),
                    admission,
                    ListenerBinding::default(),
                )
            } else {
                spawn_uring_http(
                    holder,
                    "http".into(),
                    address,
                    1,
                    Some(vec![socket]),
                    admission,
                    ListenerBinding::default(),
                )
            }
            .unwrap()
        });
        let mut client = std::net::TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(std::time::Duration::from_millis(100)))
            .unwrap();
        if tls {
            let config = rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth();
            let mut handshake =
                rustls::ClientConnection::new(Arc::new(config), "localhost".try_into().unwrap())
                    .unwrap();
            handshake.write_tls(&mut client).unwrap();
        } else {
            client
                .write_all(
                    b"GET /index.html HTTP/1.1\r\nHost: canon.test\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
        }
        let mut response = [0u8; 4096];
        let error = client
            .read(&mut response)
            .expect_err("prepared transport must remain silent");
        assert!(matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ));
        assert_eq!(
            active.load(Ordering::SeqCst),
            0,
            "prepared listener must not even accept"
        );
        group.activate();
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let received = client.read(&mut response).unwrap();
        assert!(received > 0);
        if !tls {
            assert!(response[..received].starts_with(b"HTTP/1.1 200"));
        }
        drop(client);
        drop(group);
        assert!(!shutdown.is_cancelled());
        drop(runtime);
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(server_root).unwrap();
    }
}
