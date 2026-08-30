//! Bounded pool of persistent Unix-domain-socket connections to an lsphp worker
//! pool. Connections are pooled FIFO; idle ones can be reused for keep-alive.
//!
//! LSAPI runs one request per connection round-trip but the *connection* can be
//! reused (lsphp's PC keep-alive). We therefore hand out a [`PooledConn`] guard
//! that returns the socket to the pool on drop unless it was poisoned.
//!
//! ## Generation epoch (resilience layer)
//! The pool carries a monotonic *generation* counter. Every idle entry is
//! stamped with the generation that was current when it was pooled, plus the
//! `Instant` it became idle. When the supervisor restarts the lsphp master, the
//! [`crate::monitor::Monitor`] calls [`LsapiPool::bump_generation`] with the
//! supervisor's new generation; any socket pooled against the OLD generation
//! belongs to a now-dead worker and MUST NOT be handed out. [`acquire`] discards
//! such stale entries (wrong generation OR older than the idle TTL), looping to a
//! fresh dial. Re-pool paths ([`PooledConn`] drop and [`ReturnGuard`] drop)
//! stamp the generation that was current at acquire time and REFUSE to re-pool a
//! socket if the generation has advanced since — that socket spans a restart and
//! is presumed dead.

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use memmap2::{Mmap, MmapMut, MmapOptions};
use parking_lot::Mutex;
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::Semaphore;

/// Errors acquiring or using a pooled connection.
#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    #[error("lsapi connect timeout after {0:?}")]
    Timeout(Duration),
    #[error("lsapi pool closed")]
    Closed,
    #[error("lsapi connect: {0}")]
    Connect(#[source] io::Error),
    #[error("lsapi circuit breaker open")]
    CircuitOpen,
}

/// Monotonic operational counters for one LSAPI connection pool.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PoolStats {
    pub generation_advances: u64,
    pub stale_idle_drops: u64,
    pub stale_checked_out_drops: u64,
    pub stale_worker_retire_signals: u64,
    pub stale_worker_retire_failures: u64,
    pub worker_attribution_failures: u64,
    pub eagain_retries: u64,
    pub eagain_terminal_exhaustions: u64,
}

#[derive(Default)]
struct PoolCounters {
    generation_advances: AtomicU64,
    stale_idle_drops: AtomicU64,
    stale_checked_out_drops: AtomicU64,
    stale_worker_retire_signals: AtomicU64,
    stale_worker_retire_failures: AtomicU64,
    worker_attribution_failures: AtomicU64,
    /// Consecutive capture failures since the last success or generation
    /// advance. Not exported: it only gates the attribution backoff.
    attribution_consecutive_failures: AtomicU64,
    eagain_retries: AtomicU64,
    eagain_terminal_exhaustions: AtomicU64,
}

impl PoolCounters {
    fn snapshot(&self) -> PoolStats {
        PoolStats {
            generation_advances: self.generation_advances.load(Ordering::Relaxed),
            stale_idle_drops: self.stale_idle_drops.load(Ordering::Relaxed),
            stale_checked_out_drops: self.stale_checked_out_drops.load(Ordering::Relaxed),
            stale_worker_retire_signals: self.stale_worker_retire_signals.load(Ordering::Relaxed),
            stale_worker_retire_failures: self.stale_worker_retire_failures.load(Ordering::Relaxed),
            worker_attribution_failures: self.worker_attribution_failures.load(Ordering::Relaxed),
            eagain_retries: self.eagain_retries.load(Ordering::Relaxed),
            eagain_terminal_exhaustions: self.eagain_terminal_exhaustions.load(Ordering::Relaxed),
        }
    }
}

/// Shared generation counter published by the standalone lsphp service.
pub const DEFAULT_EXTERNAL_GENERATION_PATH: &str = "/run/httpjet/lsphp.generation";

const EXTERNAL_GENERATION_FIELDS: usize = 2;
const EXTERNAL_GENERATION_BYTES: u64 = (size_of::<AtomicU64>() * EXTERNAL_GENERATION_FIELDS) as u64;
const EXTERNAL_GENERATION_STATE_OFFSET: usize = 0;
const EXTERNAL_GENERATION_MARKER_OFFSET: usize = size_of::<AtomicU64>();

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ExternalGenerationSnapshot {
    epoch: u64,
    marker_fingerprint: u64,
}

/// The generation state is a trust anchor (epoch + promoted-family marker):
/// in a group/other-writable directory any local user could pre-create or swap
/// the file and force spurious pool-invalidation churn. Same stance as
/// `validate_chroot_target` (0o022 = group-write | other-write); the default
/// sibling-of-socket path would otherwise land beside a /tmp socket.
fn validate_generation_dir(path: &Path) -> io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let md = std::fs::metadata(dir).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("lsphp generation dir {} stat failed: {e}", dir.display()),
        )
    })?;
    if !md.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("lsphp generation dir {} is not a directory", dir.display()),
        ));
    }
    if md.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "lsphp generation dir {} is group/other-writable (mode {:o}); a local user could forge the generation state — move the file to a root-owned directory (e.g. {DEFAULT_EXTERNAL_GENERATION_PATH})",
                dir.display(),
                md.mode() & 0o7777
            ),
        ));
    }
    Ok(())
}

/// Read-only view of the process-independent lsphp generation counter.
///
/// The file is exactly one native-endian [`AtomicU64`] in a shared mapping.
/// Mapping it once keeps generation checks on the request and re-pool paths to
/// an Acquire atomic load, with no per-request filesystem operation.
pub struct ExternalGeneration {
    map: Mmap,
}

impl ExternalGeneration {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        validate_generation_dir(path.as_ref())?;
        let file = File::open(path)?;
        validate_generation_file(&file)?;
        // SAFETY: the file length and alignment are validated; an mmap starts at
        // page alignment, which is stricter than AtomicU64's alignment. Writers
        // retain the fixed 16-byte file size for the lifetime of every mapping.
        let map = unsafe {
            MmapOptions::new()
                .len(EXTERNAL_GENERATION_BYTES as usize)
                .map(&file)?
        };
        Ok(Self { map })
    }

    pub fn load(&self) -> u64 {
        self.snapshot().epoch
    }

    fn snapshot(&self) -> ExternalGenerationSnapshot {
        read_generation_snapshot(&self.map)
    }
}

/// Writable owner of the shared lsphp generation counter.
///
/// `open_or_create` initializes a new empty file but refuses to resize a
/// non-empty malformed file: truncating a file while another process has it
/// mapped could make that reader fault.
pub struct ExternalGenerationWriter {
    map: MmapMut,
}

impl ExternalGenerationWriter {
    pub fn open_or_create(path: impl AsRef<Path>) -> io::Result<Self> {
        validate_generation_dir(path.as_ref())?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o644)
            .open(path)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o644))?;
        let len = file.metadata()?.len();
        if len == 0 {
            file.set_len(EXTERNAL_GENERATION_BYTES)?;
        } else if len != EXTERNAL_GENERATION_BYTES {
            return Err(invalid_generation_len(len));
        }
        // SAFETY: as in ExternalGeneration::open; this owner never resizes the
        // file after mapping it.
        let map = unsafe {
            MmapOptions::new()
                .len(EXTERNAL_GENERATION_BYTES as usize)
                .map_mut(&file)?
        };
        let writer = Self { map };
        let state = mapped_atomic(&writer.map, EXTERNAL_GENERATION_STATE_OFFSET);
        let observed = state.load(Ordering::Acquire);
        if observed & 1 != 0 {
            // A killed prior single writer may leave the publication busy bit
            // set. The encoded epoch is the last committed epoch, so clear only
            // the bit; the next promotion replaces the marker before advancing.
            state.store(observed & !1, Ordering::Release);
        }
        Ok(writer)
    }

    pub fn load(&self) -> u64 {
        self.snapshot().epoch
    }

    /// Publish an exact generation after the candidate pool is ready.
    ///
    /// Epoch-only: the stored family fingerprint is left untouched, so this
    /// must NEVER announce a worker-family replacement — readers would compare
    /// the new family's workers against the stale fingerprint and retire them
    /// after every response. Promotions go through [`Self::advance_with_marker`].
    pub fn publish(&self, generation: u64) {
        self.update(generation, None);
    }

    /// Advance monotonically across standalone-supervisor process restarts.
    /// Returns the generation that was published.
    ///
    /// Epoch-only, like [`Self::publish`]: never use this to announce a
    /// worker-family replacement — that is [`Self::advance_with_marker`].
    pub fn advance(&self, core_generation: u64) -> u64 {
        let current = self.snapshot().epoch;
        let next = current.saturating_add(1).max(core_generation);
        self.update(next, None);
        next
    }

    /// Publish the exact promoted worker-family marker and advance the epoch as
    /// one seqlock snapshot. Readers can therefore distinguish an old worker
    /// from a candidate that accepted just before publication.
    pub fn advance_with_marker(&self, core_generation: u64, marker: &str) -> u64 {
        let current = self.snapshot().epoch;
        let next = current.saturating_add(1).max(core_generation);
        self.update(next, Some(generation_marker_fingerprint(marker)));
        next
    }

    fn snapshot(&self) -> ExternalGenerationSnapshot {
        read_generation_snapshot(&self.map)
    }

    fn update(&self, generation: u64, marker_fingerprint: Option<u64>) {
        let state = mapped_atomic(&self.map, EXTERNAL_GENERATION_STATE_OFFSET);
        let current = state.load(Ordering::Acquire) >> 1;
        state.store((current << 1) | 1, Ordering::Release);
        if let Some(marker_fingerprint) = marker_fingerprint {
            mapped_atomic(&self.map, EXTERNAL_GENERATION_MARKER_OFFSET)
                .store(marker_fingerprint, Ordering::Release);
        }
        state.store(generation << 1, Ordering::Release);
    }
}

fn validate_generation_file(file: &File) -> io::Result<()> {
    let len = file.metadata()?.len();
    if len == EXTERNAL_GENERATION_BYTES {
        Ok(())
    } else {
        Err(invalid_generation_len(len))
    }
}

fn invalid_generation_len(len: u64) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "lsphp generation file must be exactly {EXTERNAL_GENERATION_BYTES} bytes, got {len}"
        ),
    )
}

fn mapped_atomic(map: &[u8], offset: usize) -> &AtomicU64 {
    // SAFETY: callers pass the start of a live, fixed-size shared mmap validated
    // above. mmap base addresses are page-aligned, and the mapping has room for
    // exactly one AtomicU64. The returned reference never outlives its owning map
    // in actual use; it is consumed immediately for one atomic operation.
    debug_assert_eq!(map.len(), EXTERNAL_GENERATION_BYTES as usize);
    debug_assert_eq!(offset % std::mem::align_of::<AtomicU64>(), 0);
    debug_assert!(offset + size_of::<AtomicU64>() <= map.len());
    unsafe { &*map.as_ptr().add(offset).cast::<AtomicU64>() }
}

fn read_generation_snapshot(map: &[u8]) -> ExternalGenerationSnapshot {
    loop {
        let state = mapped_atomic(map, EXTERNAL_GENERATION_STATE_OFFSET).load(Ordering::Acquire);
        let epoch = state >> 1;
        if state & 1 != 0 {
            return ExternalGenerationSnapshot {
                epoch,
                marker_fingerprint: 0,
            };
        }
        let marker_fingerprint =
            mapped_atomic(map, EXTERNAL_GENERATION_MARKER_OFFSET).load(Ordering::Acquire);
        let confirmed =
            mapped_atomic(map, EXTERNAL_GENERATION_STATE_OFFSET).load(Ordering::Acquire);
        if state == confirmed {
            return ExternalGenerationSnapshot {
                epoch,
                marker_fingerprint,
            };
        }
    }
}

fn generation_marker_fingerprint(marker: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in marker.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash.max(1)
}

#[derive(Debug)]
struct WorkerRetirement {
    pid: u32,
    start_time: u64,
    marker_fingerprint: u64,
    pidfd: OwnedFd,
}

impl WorkerRetirement {
    fn capture_for_stream(stream: &UnixStream, hint: Option<u32>) -> io::Result<Self> {
        let peer_inode = unix_diag_peer_inode(stream.as_raw_fd())?;
        if let Some(pid) = hint
            && process_holds_socket_inode(pid, peer_inode)?
        {
            return Self::capture(pid, peer_inode);
        }
        for entry in std::fs::read_dir("/proc")? {
            let entry = entry?;
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
            else {
                continue;
            };
            if process_is_lsphp(pid).unwrap_or(false)
                && process_holds_socket_inode(pid, peer_inode).unwrap_or(false)
            {
                return Self::capture(pid, peer_inode);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no lsphp worker holds UNIX peer inode {peer_inode}"),
        ))
    }

    fn capture(pid: u32, peer_inode: u64) -> io::Result<Self> {
        if !process_is_lsphp(pid)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("LSAPI PID frame named non-lsphp process {pid}"),
            ));
        }
        let start_time = process_start_time(pid)?;
        let marker = process_generation_marker(pid)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("LSAPI worker {pid} has no httpjet generation marker"),
            )
        })?;
        // SAFETY: pidfd_open returns a new owned descriptor on success.
        let raw =
            unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) } as libc::c_int;
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a fresh descriptor returned by pidfd_open.
        let pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
        if process_start_time(pid)? != start_time
            || !process_is_lsphp(pid)?
            || process_generation_marker(pid)?.as_deref() != Some(marker.as_str())
            || !process_holds_socket_inode(pid, peer_inode)?
        {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("LSAPI worker {pid} changed while pinning its pidfd"),
            ));
        }
        Ok(Self {
            pid,
            start_time,
            marker_fingerprint: generation_marker_fingerprint(&marker),
            pidfd,
        })
    }

    fn retire_if_stale(&self, current: ExternalGenerationSnapshot, counters: &PoolCounters) {
        if current.marker_fingerprint == 0 || self.marker_fingerprint == current.marker_fingerprint
        {
            return;
        }
        let rc = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                libc::SIGUSR1,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        if rc == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            counters
                .stale_worker_retire_signals
                .fetch_add(1, Ordering::Relaxed);
        } else {
            let error = io::Error::last_os_error();
            counters
                .stale_worker_retire_failures
                .fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                worker_pid = self.pid,
                worker_start_time = self.start_time,
                %error,
                "could not retire response-complete old-generation lsphp worker"
            );
        }
    }
}

fn unix_diag_peer_inode(socket_fd: libc::c_int) -> io::Result<u64> {
    const NETLINK_SOCK_DIAG: libc::c_int = 4;
    const SOCK_DIAG_BY_FAMILY: u16 = 20;
    const NLM_F_REQUEST: u16 = 1;
    const UDIAG_SHOW_PEER: u32 = 4;
    const UNIX_DIAG_PEER: u16 = 2;
    const NLMSG_ERROR: u16 = 2;
    const NLMSG_DONE: u16 = 3;
    const HEADER_LEN: usize = 16;
    const DIAG_MSG_LEN: usize = 16;

    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `stat` points to writable storage and `socket_fd` remains open.
    if unsafe { libc::fstat(socket_fd, stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstat succeeded and initialized the structure.
    let socket_inode = unsafe { stat.assume_init() }.st_ino;
    let socket_inode = u32::try_from(socket_inode).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("UNIX socket inode {socket_inode} exceeds sock_diag width"),
        )
    })?;

    // SAFETY: socket returns a fresh descriptor on success.
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            NETLINK_SOCK_DIAG,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is the fresh netlink descriptor above.
    let netlink = unsafe { OwnedFd::from_raw_fd(raw) };
    let timeout = libc::timeval {
        tv_sec: 0,
        tv_usec: 200_000,
    };
    // SAFETY: arguments point to a live timeval of the advertised size.
    if unsafe {
        libc::setsockopt(
            netlink.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&timeout as *const libc::timeval).cast(),
            size_of::<libc::timeval>() as libc::socklen_t,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }

    // nlmsghdr (16 bytes) followed by unix_diag_req (24 bytes), all native-endian.
    let mut request = [0u8; 40];
    let request_len = request.len() as u32;
    request[0..4].copy_from_slice(&request_len.to_ne_bytes());
    request[4..6].copy_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    request[6..8].copy_from_slice(&NLM_F_REQUEST.to_ne_bytes());
    static NEXT_SEQUENCE: AtomicU64 = AtomicU64::new(1);
    let sequence = NEXT_SEQUENCE.fetch_add(1, Ordering::Relaxed) as u32;
    request[8..12].copy_from_slice(&sequence.to_ne_bytes());
    request[16] = libc::AF_UNIX as u8;
    request[20..24].copy_from_slice(&u32::MAX.to_ne_bytes());
    request[24..28].copy_from_slice(&socket_inode.to_ne_bytes());
    request[28..32].copy_from_slice(&UDIAG_SHOW_PEER.to_ne_bytes());
    request[32..36].copy_from_slice(&u32::MAX.to_ne_bytes());
    request[36..40].copy_from_slice(&u32::MAX.to_ne_bytes());

    // SAFETY: zero is the kernel netlink endpoint; the request buffer is valid.
    let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    let sent = unsafe {
        libc::sendto(
            netlink.as_raw_fd(),
            request.as_ptr().cast(),
            request.len(),
            0,
            (&kernel as *const libc::sockaddr_nl).cast(),
            size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut response = [0u8; 512];
    loop {
        // SAFETY: response is writable for its entire advertised length.
        let received = unsafe {
            libc::recv(
                netlink.as_raw_fd(),
                response.as_mut_ptr().cast(),
                response.len(),
                0,
            )
        };
        if received < 0 {
            return Err(io::Error::last_os_error());
        }
        let received = received as usize;
        let mut offset = 0usize;
        while offset + HEADER_LEN <= received {
            let message_len = u32::from_ne_bytes(
                response[offset..offset + 4]
                    .try_into()
                    .expect("four-byte netlink length"),
            ) as usize;
            if message_len < HEADER_LEN || offset + message_len > received {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated UNIX_DIAG response",
                ));
            }
            let message_type = u16::from_ne_bytes(
                response[offset + 4..offset + 6]
                    .try_into()
                    .expect("two-byte netlink type"),
            );
            let message_sequence = u32::from_ne_bytes(
                response[offset + 8..offset + 12]
                    .try_into()
                    .expect("four-byte netlink sequence"),
            );
            if message_sequence == sequence {
                if message_type == NLMSG_ERROR {
                    let errno = if message_len >= HEADER_LEN + 4 {
                        i32::from_ne_bytes(
                            response[offset + HEADER_LEN..offset + HEADER_LEN + 4]
                                .try_into()
                                .expect("four-byte netlink error"),
                        )
                    } else {
                        -libc::EINVAL
                    };
                    return Err(io::Error::from_raw_os_error(-errno));
                }
                if message_type == NLMSG_DONE {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "UNIX_DIAG response contained no peer inode",
                    ));
                }
                if message_type == SOCK_DIAG_BY_FAMILY && message_len >= HEADER_LEN + DIAG_MSG_LEN {
                    let returned_inode = u32::from_ne_bytes(
                        response[offset + 20..offset + 24]
                            .try_into()
                            .expect("four-byte diag inode"),
                    );
                    if returned_inode != socket_inode {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "UNIX_DIAG returned the wrong socket",
                        ));
                    }
                    let mut attribute = offset + HEADER_LEN + DIAG_MSG_LEN;
                    while attribute + 4 <= offset + message_len {
                        let attribute_len = u16::from_ne_bytes(
                            response[attribute..attribute + 2]
                                .try_into()
                                .expect("two-byte diag attribute length"),
                        ) as usize;
                        let attribute_type = u16::from_ne_bytes(
                            response[attribute + 2..attribute + 4]
                                .try_into()
                                .expect("two-byte diag attribute type"),
                        );
                        if attribute_len < 4 || attribute + attribute_len > offset + message_len {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "invalid UNIX_DIAG attribute",
                            ));
                        }
                        if attribute_type == UNIX_DIAG_PEER && attribute_len >= 8 {
                            return Ok(u32::from_ne_bytes(
                                response[attribute + 4..attribute + 8]
                                    .try_into()
                                    .expect("four-byte peer inode"),
                            ) as u64);
                        }
                        attribute += (attribute_len + 3) & !3;
                    }
                }
            }
            offset += (message_len + 3) & !3;
        }
    }
}

fn process_holds_socket_inode(pid: u32, inode: u64) -> io::Result<bool> {
    let expected = std::ffi::OsString::from(format!("socket:[{inode}]"));
    for entry in std::fs::read_dir(format!("/proc/{pid}/fd"))? {
        let entry = entry?;
        match std::fs::read_link(entry.path()) {
            Ok(target) if target.as_os_str() == expected => return Ok(true),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}

fn process_is_lsphp(pid: u32) -> io::Result<bool> {
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))?;
    if comm.trim_end() != "lsphp" {
        return Ok(false);
    }
    let executable = std::fs::read_link(format!("/proc/{pid}/exe"))?;
    Ok(executable
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "lsphp" || name.starts_with("lsphp-")))
}

fn process_start_time(pid: u32) -> io::Result<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let after_comm = stat
        .rsplit_once(") ")
        .map(|(_, rest)| rest)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid /proc/{pid}/stat"),
            )
        })?;
    after_comm
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing process start time"))?
        .parse()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn process_generation_marker(pid: u32) -> io::Result<Option<String>> {
    const PREFIX: &[u8] = b"LSAPI_Z_HTTPJET_GENERATION_MARKER=";
    let environ = std::fs::read(format!("/proc/{pid}/environ"))?;
    environ
        .split(|byte| *byte == 0)
        .find_map(|entry| entry.strip_prefix(PREFIX))
        .map(|value| {
            std::str::from_utf8(value)
                .map(str::to_owned)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
        })
        .transpose()
}

/// Time-windowed circuit breaker for EXTERNAL mode (no supervisor of our own).
/// Fed exclusively by real fresh-dial outcomes from `acquire()` — NEVER by a
/// synthetic probe: a bare connect+close makes lsphp's accept loop exit the
/// worker (`readReq`/`LSAPI_Accept_r` in vendor/lsapilib.c treat an immediate
/// EOF as a fatal read and break out), so recovery detection rides on a real,
/// throttled ("half-open") request instead.
struct DialBreaker {
    /// Current continuous-failure episode. `None` while healthy. A gap longer than
    /// `BREAKER_EPISODE_GAP` between failures starts a fresh episode, so a stale
    /// failure left over from an old (since-recovered) outage cannot make an
    /// unrelated later blip trip the breaker instantly (#128).
    episode: Mutex<Option<FailEpisode>>,
    /// Whether the breaker is currently open.
    open: AtomicBool,
    /// Wall-clock instant when the next half-open trial is permitted.
    next_trial_at: Mutex<Instant>,
    /// Whether a half-open trial currently holds the single trial slot. Set by
    /// `admit`'s CAS; released ONLY by dropping the [`TrialGuard`] it hands back —
    /// so every trial exit path (dial failure, connect/semaphore timeout, idle
    /// reuse, or a cancelled request future) frees the slot and recovery can be
    /// re-probed. Without this the slot leaks on any non-success exit and the
    /// breaker wedges open forever (#125).
    trial_in_flight: AtomicBool,
}

/// One continuous-failure episode: `first` = when it started, `last` = most recent
/// failure. Used to enforce that the trip window measures *continuous* failure.
#[derive(Clone, Copy)]
struct FailEpisode {
    first: Instant,
    last: Instant,
}

/// RAII release of the breaker's single half-open trial slot. The request admitted
/// as the trial holds this for the whole dispatch; on drop (success, failure,
/// timeout, or cancellation) it clears `trial_in_flight` so the next cooldown can
/// admit a fresh trial. This is what prevents the permanent-wedge (#125).
pub struct TrialGuard {
    breaker: Arc<DialBreaker>,
}

impl Drop for TrialGuard {
    fn drop(&mut self) {
        self.breaker.trial_in_flight.store(false, Ordering::Release);
    }
}

/// Outcome of a circuit-breaker admission check.
pub enum DialAdmission {
    /// Breaker closed (or absent): proceed with no trial accounting.
    Proceed,
    /// Breaker open; this request won the single half-open trial slot. Hold the
    /// guard across the whole dispatch so the slot is released on every exit path.
    Trial(TrialGuard),
    /// Breaker open and no trial slot available: fail fast (503).
    Reject,
}

/// Constants for the DialBreaker debounce/recovery behavior.
const BREAKER_TRIAL_COOLDOWN: Duration = Duration::from_secs(1);
/// Total continuous-failure duration before the breaker trips open. Sized above the
/// per-request retry budget (`min(init_timeout, RETRY_DEFAULT_FLOOR)`) so it never
/// trips before the ride-out would already have given up.
const BREAKER_TRIP_AFTER: Duration = Duration::from_secs(8);
/// A continuous-failure episode is considered broken once no failure has been
/// recorded for this long; the next failure then starts a fresh episode. Larger
/// than the ~40ms within-request retry spacing and the 1s trial cooldown, smaller
/// than the multi-second per-request ride-out, so back-to-back failing requests keep
/// a single episode alive while the 8s trip window still means "8s of *continuous*
/// failure" rather than "8s since one stale failure long ago" (#128).
const BREAKER_EPISODE_GAP: Duration = Duration::from_secs(2);

impl DialBreaker {
    fn new() -> Self {
        DialBreaker {
            episode: Mutex::new(None),
            open: AtomicBool::new(false),
            next_trial_at: Mutex::new(Instant::now()),
            trial_in_flight: AtomicBool::new(false),
        }
    }

    /// Side-effecting gate; call ONCE per request before dialing. When the breaker
    /// is open it admits at most one half-open trial per `BREAKER_TRIAL_COOLDOWN`,
    /// handing back a [`TrialGuard`] the caller MUST hold until the dial outcome is
    /// known (its Drop releases the slot).
    fn admit(breaker: &Arc<DialBreaker>, now: Instant) -> DialAdmission {
        if !breaker.open.load(Ordering::Acquire) {
            return DialAdmission::Proceed;
        }
        // Breaker is open. Allow exactly one "half-open" trial every cooldown.
        let mut next = breaker.next_trial_at.lock();
        if now >= *next
            && breaker
                .trial_in_flight
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            *next = now + BREAKER_TRIAL_COOLDOWN;
            return DialAdmission::Trial(TrialGuard {
                breaker: breaker.clone(),
            });
        }
        DialAdmission::Reject
    }

    /// Pure read; returns whether the breaker is currently open.
    fn is_open(&self) -> bool {
        self.open.load(Ordering::Acquire)
    }

    /// Record the outcome of a fresh-dial attempt (or a successful idle reuse while
    /// open). Never touches `trial_in_flight` — the slot is owned by [`TrialGuard`].
    fn record(&self, success: bool, now: Instant) {
        if success {
            // Reachable backend: clear the episode and close the breaker.
            *self.episode.lock() = None;
            self.open.store(false, Ordering::Release);
            return;
        }
        // Transient failure (ECONNREFUSED/ENOENT). Extend the current continuous
        // episode, or start a fresh one if the previous failure is stale (#128).
        let mut ep = self.episode.lock();
        let first = match *ep {
            Some(e) if now.saturating_duration_since(e.last) <= BREAKER_EPISODE_GAP => e.first,
            _ => now,
        };
        *ep = Some(FailEpisode { first, last: now });
        if now.saturating_duration_since(first) >= BREAKER_TRIP_AFTER {
            self.open.store(true, Ordering::Release);
        }
    }
}

/// One idle, re-poolable connection: the socket, when it became idle, and the
/// pool generation it was pooled against.
struct IdleEntry {
    stream: UnixStream,
    worker: Option<WorkerRetirement>,
    worker_pid_hint: Option<u32>,
    since: Instant,
    generation: u64,
}

/// A bounded pool of UDS connections to a single lsphp socket path.
///
/// `max_conns` caps the number of *concurrent* outstanding connections (matching
/// LiteSpeed's `maxConns`). `acquire()` waits up to `init_timeout` for a slot and
/// a usable socket.
pub struct LsapiPool {
    path: PathBuf,
    sem: Arc<Semaphore>,
    idle: Arc<Mutex<VecDeque<IdleEntry>>>,
    init_timeout: Duration,
    max_conns: usize,
    /// Max time an idle socket may sit in the pool before it is discarded on the
    /// next acquire (lsphp PC keep-alive timeout; default 30s).
    idle_ttl: Duration,
    /// Monotonic generation; advanced by [`bump_generation`] on a master restart.
    generation: Arc<AtomicU64>,
    /// Cross-process generation source used by external-mode web pools. The
    /// standalone supervisor publishes only after candidate promotion; every
    /// acquire/re-pool observes it without a syscall.
    external_generation: Option<Arc<ExternalGeneration>>,
    counters: Arc<PoolCounters>,
    /// Budget for retrying a refused/missing-socket FRESH dial before surfacing a
    /// 502 — the lsphp restart window (LiteSpeed `retryTimeout`). 0 ⇒ a bounded
    /// built-in floor (see [`LsapiPool::acquire`]).
    retry_timeout: Duration,
    /// Optional circuit breaker for external-mode pools (no supervisor of our own).
    /// When active, rapid connection failures trigger an open state that fast-fails
    /// new requests until recovery is detected. Attached via `with_circuit_breaker()`.
    breaker: Option<Arc<DialBreaker>>,
}

/// Default idle TTL when the config carries no `pc_keep_alive_timeout`.
const DEFAULT_IDLE_TTL: Duration = Duration::from_secs(30);

/// Backoff between refused-dial retries; an lsphp restart window is ~seconds.
const RETRY_BACKOFF: Duration = Duration::from_millis(40);
/// Retry-budget floor used when `retry_timeout == 0` (prod has no `<retryTimeout>`):
/// the effective budget is `min(init_timeout, this)`. 5s comfortably covers a
/// `RestartSec=2` restart + lsphp readiness while staying far under Cloudflare's
/// ~100s origin timeout.
const RETRY_DEFAULT_FLOOR: Duration = Duration::from_secs(5);
/// Absolute cap even if an operator sets a huge `<retryTimeout>`, so a truly-down
/// backend can't pin a request near Cloudflare's origin timeout.
const RETRY_HARD_CAP: Duration = Duration::from_secs(15);
/// External mode owns no supervisor and must ride out a complete standalone
/// pool replacement independently of LiteSpeed's application retry value.
const EXTERNAL_RETRY_WINDOW: Duration = Duration::from_secs(30);

impl LsapiPool {
    /// Create a pool for `socket_path` with at most `max_conns` connections and
    /// the given connect/init timeout. The idle TTL defaults to 30s; override
    /// with [`LsapiPool::idle_ttl`].
    pub fn new(socket_path: impl Into<PathBuf>, max_conns: u32, init_timeout: Duration) -> Self {
        let max_conns = max_conns.max(1) as usize;
        LsapiPool {
            path: socket_path.into(),
            sem: Arc::new(Semaphore::new(max_conns)),
            idle: Arc::new(Mutex::new(VecDeque::new())),
            init_timeout,
            max_conns,
            idle_ttl: DEFAULT_IDLE_TTL,
            generation: Arc::new(AtomicU64::new(0)),
            external_generation: None,
            counters: Arc::new(PoolCounters::default()),
            retry_timeout: Duration::ZERO,
            breaker: None,
        }
    }

    /// Build a pool from a `PhpConfig`-style descriptor.
    pub fn from_uds(
        socket_path: impl Into<PathBuf>,
        max_conns: u32,
        init_timeout: Duration,
    ) -> Self {
        Self::new(socket_path, max_conns, init_timeout)
    }

    /// Set the idle TTL (source: `PhpConfig::pc_keep_alive_timeout`). A zero TTL
    /// is treated as "expire immediately" — idle sockets are never reused.
    pub fn idle_ttl(mut self, ttl: Duration) -> Self {
        self.idle_ttl = ttl;
        self
    }

    /// Set the refused/missing-socket dial retry budget (source: `PhpConfig::retry_timeout`,
    /// LiteSpeed `retryTimeout`). 0 keeps the bounded built-in floor (see [`Self::acquire`]).
    pub fn retry_timeout(mut self, t: Duration) -> Self {
        self.retry_timeout = t;
        self
    }

    /// Observe a process-independent generation counter published by the
    /// standalone lsphp service.
    pub fn external_generation(mut self, source: Arc<ExternalGeneration>) -> Self {
        self.external_generation = Some(source);
        self.refresh_external_generation();
        self
    }

    /// Open and attach a process-independent generation counter.
    pub fn external_generation_file(self, path: impl AsRef<Path>) -> io::Result<Self> {
        let source = Arc::new(ExternalGeneration::open(path)?);
        Ok(self.external_generation(source))
    }

    /// Attach a circuit breaker to this pool (for external-mode pools with no
    /// supervisor of their own). Only call once at construction.
    pub fn with_circuit_breaker(mut self) -> Self {
        self.breaker = Some(Arc::new(DialBreaker::new()));
        self
    }

    /// Check whether the circuit breaker (if attached) permits a new dial attempt.
    /// The returned [`DialAdmission`] carries the half-open trial guard (if this
    /// request is the trial); the caller MUST hold it across the whole dispatch.
    pub fn admit_dial(&self) -> DialAdmission {
        match &self.breaker {
            Some(b) => DialBreaker::admit(b, Instant::now()),
            None => DialAdmission::Proceed,
        }
    }

    /// Check whether the circuit breaker (if attached) is currently open.
    pub fn is_circuit_open(&self) -> bool {
        self.breaker.as_ref().map(|b| b.is_open()).unwrap_or(false)
    }

    /// Check whether this pool has a circuit breaker attached.
    pub fn has_circuit_breaker(&self) -> bool {
        self.breaker.is_some()
    }

    pub fn max_conns(&self) -> usize {
        self.max_conns
    }

    /// Number of currently-idle pooled connections (does not prune).
    pub fn idle_count(&self) -> usize {
        self.idle.lock().len()
    }

    pub fn stats(&self) -> PoolStats {
        self.counters.snapshot()
    }

    /// The pool's current generation.
    pub fn generation(&self) -> u64 {
        self.refresh_external_generation()
    }

    /// Advance the pool to a new generation (called by the monitor after the
    /// supervisor successfully restarts the master). Idle sockets pooled against
    /// the prior generation are dropped immediately; in-flight re-pool paths will
    /// observe the new generation and refuse to re-pool.
    ///
    /// `g` is the supervisor's generation counter. The pool generation only ever
    /// moves FORWARD: passing a stale or equal value is a no-op (it does NOT
    /// clear the idle set), so a debounced restart that was skipped cannot
    /// wrongly evict healthy keep-alive sockets. To force a fresh epoch without a
    /// supervisor bump, use [`LsapiPool::clear`].
    pub fn bump_generation(&self, g: u64) {
        // `fetch_max` prevents a slower prior restart callback from overwriting a
        // newer generation after it observed an old value.
        let cur = self.generation.fetch_max(g, Ordering::AcqRel);
        if g > cur {
            // Any socket pooled before the bump belongs to a dead worker.
            let stale = {
                let mut idle = self.idle.lock();
                idle.drain(..).collect::<Vec<_>>()
            };
            let dropped = stale.len();
            discard_stale_entries(stale, self.external_generation.as_deref(), &self.counters);
            self.counters
                .generation_advances
                .fetch_add(1, Ordering::Relaxed);
            self.counters
                .stale_idle_drops
                .fetch_add(dropped as u64, Ordering::Relaxed);
            // A new epoch is a new world: retry attribution even if the prior
            // family's environment made it fail persistently.
            self.counters
                .attribution_consecutive_failures
                .store(0, Ordering::Relaxed);
        }
        // g <= cur: no real restart happened; leave the idle set intact.
    }

    fn refresh_external_generation(&self) -> u64 {
        refresh_generation(
            &self.idle,
            &self.generation,
            self.external_generation.as_deref(),
            &self.counters,
        )
    }

    /// Drop every idle connection right now (e.g. the worker died / is being
    /// restarted). Outstanding `PooledConn`/`ReturnGuard`s are untouched but will
    /// refuse to re-pool once the generation advances.
    pub fn clear(&self) {
        self.idle.lock().clear();
    }

    /// Discard idle entries older than `ttl` or stamped against a stale
    /// generation. Called periodically by the monitor and inline on acquire.
    pub fn prune_idle(&self, ttl: Duration) {
        let cur = self.refresh_external_generation();
        let now = Instant::now();
        let mut stale = Vec::new();
        let mut idle = self.idle.lock();
        let mut retained = VecDeque::with_capacity(idle.len());
        while let Some(entry) = idle.pop_front() {
            if entry.generation != cur {
                stale.push(entry);
            } else if now.duration_since(entry.since) < ttl {
                retained.push_back(entry);
            }
        }
        *idle = retained;
        drop(idle);
        self.counters
            .stale_idle_drops
            .fetch_add(stale.len() as u64, Ordering::Relaxed);
        discard_stale_entries(stale, self.external_generation.as_deref(), &self.counters);
    }

    /// Acquire a connection, reusing a still-fresh idle one or dialing a new
    /// socket. Waits up to `init_timeout` for a free slot and for the connect to
    /// complete. Idle entries older than the idle TTL or stamped against a stale
    /// generation are discarded (looping to a fresh dial).
    pub async fn acquire(&self) -> Result<PooledConn, PoolError> {
        self.acquire_probed(true).await
    }

    /// (#315) `acquire` with the per-reuse health probe SKIPPED. For bodyless
    /// idempotent requests (GET/HEAD) the handler's IdempotentReset replay already
    /// covers a dead reuse with a fresh dial, so the probe's nonblocking recv is a
    /// pure extra syscall on the hottest PHP path. The stale-TTL and
    /// wrong-generation filters below are NOT skipped — only the recv probe.
    pub async fn acquire_unprobed(&self) -> Result<PooledConn, PoolError> {
        self.acquire_probed(false).await
    }

    async fn acquire_probed(&self, probe_reuse: bool) -> Result<PooledConn, PoolError> {
        let permit =
            match tokio::time::timeout(self.init_timeout, self.sem.clone().acquire_owned()).await {
                Ok(Ok(p)) => p,
                Ok(Err(_)) => return Err(PoolError::Closed),
                Err(_) => return Err(PoolError::Timeout(self.init_timeout)),
            };

        // Snapshot the generation we acquire against; the conn we hand out is
        // stamped with this on re-pool, and refused if the generation advanced.
        let acquire_gen = self.refresh_external_generation();
        let ttl = self.idle_ttl;
        let now = Instant::now();

        // Try to reuse a still-valid idle connection. Pop the next candidate that
        // is fresh AND of the current generation, then HEALTH-CHECK it before
        // handing it out: lsphp recycles workers by design (LSAPI_MAX_REQS / idle
        // pruning), which closes the kept-alive socket on its end. A half-closed
        // socket passes the generation+TTL test yet fails on the next read with
        // ECONNRESET *before any response byte*, surfacing to the client as a 502
        // — a benign recycle turned into a user-visible error. A cheap non-blocking
        // probe (`is_socket_healthy`) discards those dead sockets here so we fall
        // through to a fresh dial. This shrinks but cannot fully close the race: a
        // socket lsphp closes in the window between the probe and the handler's
        // write/read still resets — that residual is exactly what the handler's
        // IdempotentReset replay covers (shipped; bodyless-idempotent acquires now
        // even skip this probe entirely, see acquire_unprobed).
        // Wrong-generation entries are only collected here: their teardown
        // (UNIX_DIAG attribution + pidfd retirement) does blocking syscalls, so
        // it runs after the idle lock is released, like refresh/prune do.
        let mut wrong_generation = Vec::new();
        let reused = loop {
            let candidate = {
                let mut idle = self.idle.lock();
                loop {
                    match idle.pop_front() {
                        Some(entry) => {
                            if entry.generation != acquire_gen {
                                wrong_generation.push(entry);
                            } else if now.duration_since(entry.since) < ttl {
                                break Some(entry);
                            }
                            // Stale (wrong gen or too old): drop and keep looking.
                        }
                        None => break None,
                    }
                }
            };
            match candidate {
                Some(entry) if !probe_reuse || is_socket_healthy(&entry.stream) => {
                    break Some(entry);
                }
                // Half-closed or protocol-desynced: discard and try the next idle entry.
                Some(_dead) => continue,
                None => break None,
            }
        };
        self.counters
            .stale_idle_drops
            .fetch_add(wrong_generation.len() as u64, Ordering::Relaxed);
        discard_stale_entries(
            wrong_generation,
            self.external_generation.as_deref(),
            &self.counters,
        );
        if let Some(entry) = reused {
            if self.refresh_external_generation() != acquire_gen {
                self.counters
                    .stale_idle_drops
                    .fetch_add(1, Ordering::Relaxed);
                discard_stale_entry(entry, self.external_generation.as_deref(), &self.counters);
            } else {
                // A healthy reused socket proves the backend is reachable. If the breaker
                // is open (this request is its half-open trial), that closes it — the
                // trial can recover via reuse, not only via a fresh dial. Gated on
                // `is_open()` so the common (breaker-closed) keep-alive path stays lock-free.
                if let Some(b) = &self.breaker {
                    if b.is_open() {
                        b.record(true, Instant::now());
                    }
                }
                return Ok(PooledConn {
                    stream: Some(entry.stream),
                    worker: entry.worker,
                    worker_pid_hint: entry.worker_pid_hint,
                    idle: self.idle.clone(),
                    generation: self.generation.clone(),
                    external_generation: self.external_generation.clone(),
                    counters: self.counters.clone(),
                    acquire_gen,
                    _permit: Some(permit),
                    reusable: true,
                    reused: true,
                });
            }
        }

        // Dial a fresh connection. A refused/missing socket (ECONNREFUSED/ENOENT) is the
        // lsphp restart window — the master briefly isn't accepting (or the socket file is
        // momentarily gone). Rather than 502 immediately, retry within a bounded budget so a
        // request issued during a restart rides it out. External mode uses its own fixed window,
        // independent of LiteSpeed's application retry value. Each connect is bounded by both
        // init_timeout and the remaining whole-loop budget, so a down backend still fails well
        // under CF's origin timeout. Non-transient errors (e.g. EACCES) fail fast as before.
        let retry_budget = self.dial_retry_budget();
        let dial_deadline = Instant::now() + retry_budget;
        let mut last_was_eagain = false;
        let stream = loop {
            let remaining = dial_deadline.saturating_duration_since(Instant::now());
            let attempt_timeout = self.init_timeout.min(remaining);
            if attempt_timeout.is_zero() {
                if last_was_eagain {
                    self.record_eagain_outcome(false);
                }
                return Err(PoolError::Timeout(retry_budget));
            }
            match tokio::time::timeout(attempt_timeout, UnixStream::connect(&self.path)).await {
                Ok(Ok(s)) => {
                    if let Some(b) = &self.breaker {
                        b.record(true, Instant::now());
                    }
                    break s;
                }
                Ok(Err(e)) => {
                    let class = classify_dial_error(&e);
                    let transient = class != DialErrorClass::Fatal;
                    self.record_dial_failure(class);
                    let remaining = dial_deadline.saturating_duration_since(Instant::now());
                    if transient && !remaining.is_zero() {
                        if class == DialErrorClass::BacklogFull {
                            self.record_eagain_outcome(true);
                            last_was_eagain = true;
                        } else {
                            last_was_eagain = false;
                        }
                        tokio::time::sleep(RETRY_BACKOFF.min(remaining)).await;
                        continue;
                    }
                    if class == DialErrorClass::BacklogFull {
                        self.record_eagain_outcome(false);
                    }
                    return Err(PoolError::Connect(e));
                }
                Err(_) => return Err(PoolError::Timeout(attempt_timeout)),
            }
        };

        // Re-snapshot the generation AFTER the successful fresh connect: this fd belongs to
        // whatever worker is current NOW, not the epoch at acquire entry. A restart that bumped
        // the generation during the dial window (the new worker is connectable BEFORE do_restart
        // bumps the pool epoch) stamped the worker we actually connected to, so this healthy
        // socket survives that bump on re-pool instead of being needlessly dropped (#38). Reused
        // idle sockets keep `acquire_gen` — they were validated against it at pop time.
        let dial_gen = self.refresh_external_generation();

        Ok(PooledConn {
            stream: Some(stream),
            worker: None,
            worker_pid_hint: None,
            idle: self.idle.clone(),
            generation: self.generation.clone(),
            external_generation: self.external_generation.clone(),
            counters: self.counters.clone(),
            acquire_gen: dial_gen,
            _permit: Some(permit),
            reusable: true,
            reused: false,
        })
    }

    fn dial_retry_budget(&self) -> Duration {
        if self.breaker.is_some() {
            EXTERNAL_RETRY_WINDOW
        } else if self.retry_timeout.is_zero() {
            self.init_timeout.min(RETRY_DEFAULT_FLOOR)
        } else {
            self.retry_timeout.min(RETRY_HARD_CAP)
        }
    }

    fn record_dial_failure(&self, class: DialErrorClass) {
        if class != DialErrorClass::BacklogFull
            && let Some(b) = &self.breaker
        {
            b.record(false, Instant::now());
        }
    }

    fn record_eagain_outcome(&self, retrying: bool) {
        let counter = if retrying {
            &self.counters.eagain_retries
        } else {
            &self.counters.eagain_terminal_exhaustions
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DialErrorClass {
    RestartWindow,
    BacklogFull,
    Fatal,
}

fn classify_dial_error(error: &io::Error) -> DialErrorClass {
    if error.kind() == io::ErrorKind::WouldBlock || error.raw_os_error() == Some(libc::EAGAIN) {
        DialErrorClass::BacklogFull
    } else if matches!(
        error.kind(),
        io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
    ) {
        DialErrorClass::RestartWindow
    } else {
        DialErrorClass::Fatal
    }
}

/// Non-blocking liveness probe for an idle pooled socket, run before reuse.
///
/// A healthy idle LSAPI keep-alive socket has NO data pending — lsphp sends
/// nothing between requests — and is not at EOF. We attempt a single
/// non-blocking 1-byte read:
/// - `WouldBlock` (nothing to read) is the HEALTHY case → reuse the socket.
/// - `Ok(0)` (EOF / clean close) or an IO error (e.g. `ECONNRESET`) means lsphp
///   closed its end (worker recycled / idle-pruned) → unusable.
/// - `Ok(n > 0)` means unexpected bytes on an idle connection (protocol desync)
///   → also unusable.
///
/// The probe is non-destructive in the healthy case (no bytes are consumed and
/// the socket stays registered with the reactor for the handler's later async
/// reads); the only read that consumes a byte is on a socket we are discarding.
fn is_socket_healthy(stream: &UnixStream) -> bool {
    let mut probe = [0u8; 1];
    matches!(stream.try_read(&mut probe), Err(e) if e.kind() == io::ErrorKind::WouldBlock)
}

fn refresh_generation(
    idle: &Arc<Mutex<VecDeque<IdleEntry>>>,
    generation: &Arc<AtomicU64>,
    external: Option<&ExternalGeneration>,
    counters: &PoolCounters,
) -> u64 {
    let Some(external) = external else {
        return generation.load(Ordering::Acquire);
    };
    let observed = external.load();
    let mut current = generation.load(Ordering::Acquire);
    while observed > current {
        match generation.compare_exchange_weak(
            current,
            observed,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                let stale = {
                    let mut idle = idle.lock();
                    idle.drain(..).collect::<Vec<_>>()
                };
                let dropped = stale.len();
                counters
                    .attribution_consecutive_failures
                    .store(0, Ordering::Relaxed);
                discard_stale_entries(stale, Some(external), counters);
                counters.generation_advances.fetch_add(1, Ordering::Relaxed);
                counters
                    .stale_idle_drops
                    .fetch_add(dropped as u64, Ordering::Relaxed);
                return observed;
            }
            Err(actual) => current = actual,
        }
    }
    current
}

/// Consecutive attribution failures tolerated before capture attempts stop.
/// A persistent failure (e.g. sock_diag unavailable) would otherwise re-pay a
/// full /proc scan on every re-pool; the backoff holds until a success or the
/// next generation advance, when retirement matters again.
const ATTRIBUTION_BACKOFF_LIMIT: u64 = 8;

fn attempt_worker_attribution(
    stream: &UnixStream,
    hint: Option<u32>,
    counters: &PoolCounters,
) -> Option<WorkerRetirement> {
    if counters
        .attribution_consecutive_failures
        .load(Ordering::Relaxed)
        >= ATTRIBUTION_BACKOFF_LIMIT
    {
        return None;
    }
    match WorkerRetirement::capture_for_stream(stream, hint) {
        Ok(worker) => {
            counters
                .attribution_consecutive_failures
                .store(0, Ordering::Relaxed);
            Some(worker)
        }
        Err(error) => {
            counters
                .attribution_consecutive_failures
                .fetch_add(1, Ordering::Relaxed);
            counters
                .worker_attribution_failures
                .fetch_add(1, Ordering::Relaxed);
            tracing::debug!(%error, "could not attribute LSAPI UNIX peer");
            None
        }
    }
}

/// Push a recovered socket back into the idle set IFF the pool generation has not
/// advanced since it was acquired. A socket that spans a restart belongs to a
/// dead worker, so we drop it instead of re-pooling.
fn repool_if_current(
    idle: &Arc<Mutex<VecDeque<IdleEntry>>>,
    generation: &Arc<AtomicU64>,
    external_generation: Option<&ExternalGeneration>,
    counters: &Arc<PoolCounters>,
    acquire_gen: u64,
    stream: UnixStream,
    mut worker: Option<WorkerRetirement>,
    worker_pid_hint: Option<u32>,
) {
    if worker.is_none() && external_generation.is_some() {
        worker = attempt_worker_attribution(&stream, worker_pid_hint, counters);
    }
    if refresh_generation(idle, generation, external_generation, counters) == acquire_gen {
        idle.lock().push_back(IdleEntry {
            stream,
            worker,
            worker_pid_hint,
            since: Instant::now(),
            generation: acquire_gen,
        });
    } else {
        counters
            .stale_checked_out_drops
            .fetch_add(1, Ordering::Relaxed);
        if let (Some(external), Some(worker)) = (external_generation, worker.as_ref()) {
            worker.retire_if_stale(external.snapshot(), counters);
        }
    }
    // else: generation advanced (worker restarted) -> drop the socket.
}

/// A connection borrowed from the pool. Returns to the idle set on drop unless
/// [`PooledConn::poison`] was called (e.g. on a protocol or IO error) or the
/// pool generation advanced while it was checked out.
pub struct PooledConn {
    stream: Option<UnixStream>,
    worker: Option<WorkerRetirement>,
    worker_pid_hint: Option<u32>,
    idle: Arc<Mutex<VecDeque<IdleEntry>>>,
    generation: Arc<AtomicU64>,
    external_generation: Option<Arc<ExternalGeneration>>,
    counters: Arc<PoolCounters>,
    /// Generation snapshotted at acquire; re-pool is refused if it advances.
    acquire_gen: u64,
    // `Option` so [`PooledConn::into_split`] can move the permit into the
    // [`ReturnGuard`]; it is otherwise released when this `PooledConn` drops.
    _permit: Option<tokio::sync::OwnedSemaphorePermit>,
    reusable: bool,
    /// True if this socket came from idle reuse (lsphp PC keep-alive), false if it
    /// was freshly dialed. The handler uses this to decide whether a pre-response
    /// reset is the stale-keep-alive race (safe to retry on a fresh dial) vs a
    /// fresh connection that failed (a real backend problem, not retried).
    reused: bool,
}

impl PooledConn {
    /// True if this connection was reused from the idle pool (vs freshly dialed).
    pub fn is_reused(&self) -> bool {
        self.reused
    }

    /// Mutable access to the underlying stream.
    pub fn stream_mut(&mut self) -> &mut UnixStream {
        self.stream.as_mut().expect("stream present until drop")
    }

    /// Take ownership of the stream (it will NOT be returned to the pool).
    pub fn into_stream(mut self) -> UnixStream {
        self.reusable = false;
        self.stream.take().expect("stream present until drop")
    }

    /// Mark this connection unusable; it will be dropped, not pooled, on release.
    pub fn poison(&mut self) {
        self.reusable = false;
    }

    /// Split this connection into owned read/write halves for full-duplex use,
    /// plus a [`ReturnGuard`] that re-pools the socket once BOTH halves have been
    /// handed back cleanly.
    ///
    /// This is the streaming path: the body writer drives [`OwnedWriteHalf`] while
    /// the response reader drives [`OwnedReadHalf`] concurrently (they MUST run in
    /// separate tasks — see the handler's deadlock rule). When each side finishes
    /// cleanly it deposits its half into the guard via
    /// [`ReturnGuard::deposit_read`] / [`ReturnGuard::deposit_write`]; on the
    /// guard's drop the two halves are `reunite`d and the recovered `UnixStream`
    /// is returned to the idle pool — but ONLY if the guard was not [`poison`]ed,
    /// both halves were deposited, AND the pool generation has not advanced since
    /// acquire (a restart invalidates the socket).
    ///
    /// [`poison`]: ReturnGuard::poison
    pub fn into_split(mut self) -> (OwnedReadHalf, OwnedWriteHalf, ReturnGuard) {
        // Take ownership out of the guard's Drop so it doesn't double-handle the
        // stream; the ReturnGuard owns re-pooling from here on.
        let stream = self.stream.take().expect("stream present until drop");
        self.reusable = false; // PooledConn::drop must NOT re-pool this socket.
        let permit = self
            ._permit
            .take()
            .expect("permit present until into_split/drop");
        let (read, write) = stream.into_split();
        let guard = ReturnGuard {
            slot: Mutex::new(ReturnSlot {
                read: None,
                write: None,
                worker: self.worker.take(),
                worker_pid_hint: self.worker_pid_hint.take(),
                poisoned: false,
            }),
            idle: self.idle.clone(),
            generation: self.generation.clone(),
            external_generation: self.external_generation.clone(),
            counters: self.counters.clone(),
            acquire_gen: self.acquire_gen,
            _permit: Some(permit),
        };
        (read, write, guard)
    }
}

impl Drop for PooledConn {
    fn drop(&mut self) {
        if let Some(stream) = self.stream.take() {
            if self.reusable {
                repool_if_current(
                    &self.idle,
                    &self.generation,
                    self.external_generation.as_deref(),
                    &self.counters,
                    self.acquire_gen,
                    stream,
                    self.worker.take(),
                    self.worker_pid_hint.take(),
                );
            }
            // else: dropping `stream` closes the fd; the permit drop frees the slot.
        }
    }
}

/// Halves deposited back for re-pooling, plus the poison flag.
struct ReturnSlot {
    read: Option<OwnedReadHalf>,
    write: Option<OwnedWriteHalf>,
    worker: Option<WorkerRetirement>,
    worker_pid_hint: Option<u32>,
    poisoned: bool,
}

/// Re-pools a split connection once both halves are returned cleanly.
///
/// Produced by [`PooledConn::into_split`]. On drop it reunites the deposited
/// read/write halves and pushes the recovered socket back to the idle pool —
/// unless [`poison`](Self::poison) was called, either half is missing (a half
/// is missing if its task ended without depositing it, e.g. on IO error or an
/// early return), OR the pool generation advanced since acquire (the worker was
/// restarted under us). The semaphore permit is always released on drop, freeing
/// the slot whether or not the socket is reusable.
pub struct ReturnGuard {
    slot: Mutex<ReturnSlot>,
    idle: Arc<Mutex<VecDeque<IdleEntry>>>,
    generation: Arc<AtomicU64>,
    external_generation: Option<Arc<ExternalGeneration>>,
    counters: Arc<PoolCounters>,
    /// Generation snapshotted at acquire; re-pool is refused if it advances.
    acquire_gen: u64,
    // `Option` so we can move the permit out in Drop (it is released by drop).
    _permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl ReturnGuard {
    /// Record the worker identity carried by lsphp's kernel-generated PID frame.
    /// Capture is best-effort; retirement remains the supervisor's responsibility
    /// when procfs or pidfd access is unavailable.
    pub fn record_worker_pid(&self, pid: u32) {
        let mut slot = self.slot.lock();
        if slot.worker.as_ref().is_some_and(|worker| worker.pid == pid)
            || slot.worker_pid_hint == Some(pid)
        {
            return;
        }
        if slot.worker.is_some() || slot.worker_pid_hint.is_some() {
            slot.poisoned = true;
            tracing::warn!(
                worker_pid = pid,
                "LSAPI keep-alive connection changed worker hint"
            );
        } else {
            slot.worker_pid_hint = Some(pid);
        }
    }

    /// Deposit the read half after the response was fully and cleanly read.
    pub fn deposit_read(&self, read: OwnedReadHalf) {
        self.slot.lock().read = Some(read);
    }

    /// Deposit the write half after the request body was fully and cleanly
    /// written (do NOT shut the half down first — that would close the write
    /// direction and make the socket unusable for keep-alive).
    pub fn deposit_write(&self, write: OwnedWriteHalf) {
        self.slot.lock().write = Some(write);
    }

    /// Mark the connection unusable; it will be dropped, not pooled, on release.
    pub fn poison(&self) {
        self.slot.lock().poisoned = true;
    }
}

impl Drop for ReturnGuard {
    fn drop(&mut self) {
        let halves = {
            let mut slot = self.slot.lock();
            if slot.poisoned {
                return;
            }
            (
                slot.read.take(),
                slot.write.take(),
                slot.worker.take(),
                slot.worker_pid_hint.take(),
            )
        };

        // A missing half means that side did not finish cleanly; we then drop both.
        if let (Some(read), Some(write), worker, worker_pid_hint) = halves {
            // Both directions completed cleanly: re-pool the recovered socket IFF
            // the generation has not advanced (worker not restarted). Halves not
            // from the same socket (reunite Err) should be impossible here.
            if let Ok(stream) = read.reunite(write) {
                repool_if_current(
                    &self.idle,
                    &self.generation,
                    self.external_generation.as_deref(),
                    &self.counters,
                    self.acquire_gen,
                    stream,
                    worker,
                    worker_pid_hint,
                )
            }
        }
    }
}

fn discard_stale_entries(
    entries: Vec<IdleEntry>,
    external_generation: Option<&ExternalGeneration>,
    counters: &PoolCounters,
) {
    for entry in entries {
        discard_stale_entry(entry, external_generation, counters);
    }
}

fn discard_stale_entry(
    mut entry: IdleEntry,
    external_generation: Option<&ExternalGeneration>,
    counters: &PoolCounters,
) {
    if entry.worker.is_none() && external_generation.is_some() {
        entry.worker = attempt_worker_attribution(&entry.stream, entry.worker_pid_hint, counters);
    }
    if let (Some(external), Some(worker)) = (external_generation, entry.worker.as_ref()) {
        worker.retire_if_stale(external.snapshot(), counters);
    }
    drop(entry);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    fn tmp_sock(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "hj-lsapi-test-{}-{}.sock",
            std::process::id(),
            name
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn tmp_generation(name: &str) -> PathBuf {
        // The generation file refuses a group/other-writable parent
        // (validate_generation_dir), so stage it in a private directory rather
        // than directly in the shared temp dir.
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "hj-lsapi-generation-test-{}-{}.d",
            std::process::id(),
            name
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        dir.join("lsphp.generation")
    }

    #[test]
    fn generation_file_in_world_writable_dir_is_refused() {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "hj-lsapi-generation-world-writable-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        let path = dir.join("lsphp.generation");

        let err = match ExternalGenerationWriter::open_or_create(&path) {
            Err(e) => e,
            Ok(_) => panic!("a world-writable parent must refuse open_or_create"),
        };
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        let err = match ExternalGeneration::open(&path) {
            Err(e) => e,
            Ok(_) => panic!("a world-writable parent must refuse open"),
        };
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);

        // Tightening the directory heals it without code changes.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        ExternalGenerationWriter::open_or_create(&path).expect("private dir is accepted");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn shared_generation_is_monotonic_and_visible_across_mappings() {
        let path = tmp_generation("shared");
        let writer = ExternalGenerationWriter::open_or_create(&path).unwrap();
        let reader = ExternalGeneration::open(&path).unwrap();
        assert_eq!(reader.load(), 0);

        writer.publish(7);
        assert_eq!(reader.load(), 7);
        assert_eq!(writer.advance(3), 8);
        assert_eq!(reader.load(), 8);
        assert_eq!(writer.advance(20), 20);
        assert_eq!(reader.load(), 20);
        assert_eq!(writer.advance_with_marker(20, "candidate-21"), 21);
        assert_eq!(
            reader.snapshot(),
            ExternalGenerationSnapshot {
                epoch: 21,
                marker_fingerprint: generation_marker_fingerprint("candidate-21"),
            }
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn shared_generation_recovers_a_killed_writer_busy_bit() {
        let path = tmp_generation("busy-recovery");
        let writer = ExternalGenerationWriter::open_or_create(&path).unwrap();
        writer.publish(7);
        mapped_atomic(&writer.map, EXTERNAL_GENERATION_STATE_OFFSET)
            .store((7 << 1) | 1, Ordering::Release);
        let reader = ExternalGeneration::open(&path).unwrap();
        assert_eq!(reader.load(), 7, "busy publication exposes the prior epoch");
        drop(writer);

        let recovered = ExternalGenerationWriter::open_or_create(&path).unwrap();
        assert_eq!(recovered.load(), 7);
        assert_eq!(
            mapped_atomic(&recovered.map, EXTERNAL_GENERATION_STATE_OFFSET).load(Ordering::Acquire)
                & 1,
            0
        );
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn unix_diag_resolves_the_exact_accepted_peer_inode() {
        let path = tmp_sock("unix-diag-peer");
        let listener = UnixListener::bind(&path).unwrap();
        let client = UnixStream::connect(&path).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();

        let peer_inode = unix_diag_peer_inode(client.as_raw_fd()).unwrap();
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        assert_eq!(
            unsafe { libc::fstat(server.as_raw_fd(), stat.as_mut_ptr()) },
            0
        );
        let server_inode = unsafe { stat.assume_init() }.st_ino;
        assert_eq!(peer_inode, server_inode);
        assert!(process_holds_socket_inode(std::process::id(), peer_inode).unwrap());

        drop(client);
        drop(server);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn malformed_generation_file_is_rejected_without_resizing() {
        let path = tmp_generation("malformed");
        std::fs::write(&path, [0u8; 3]).unwrap();
        let err = match ExternalGenerationWriter::open_or_create(&path) {
            Ok(_) => panic!("malformed generation file must be rejected"),
            Err(err) => err,
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 3);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn external_mode_uses_fixed_retry_window_and_eagain_does_not_feed_breaker() {
        let pool = LsapiPool::new("/tmp/unused-lsapi.sock", 1, Duration::from_secs(60))
            .retry_timeout(Duration::from_secs(1))
            .with_circuit_breaker();
        assert_eq!(pool.dial_retry_budget(), Duration::from_secs(30));

        let would_block = io::Error::from(io::ErrorKind::WouldBlock);
        let class = classify_dial_error(&would_block);
        assert_eq!(class, DialErrorClass::BacklogFull);
        pool.record_dial_failure(class);
        let breaker = pool.breaker.as_ref().unwrap();
        assert!(breaker.episode.lock().is_none());
        assert!(!breaker.is_open());
        pool.record_eagain_outcome(true);
        pool.record_eagain_outcome(false);
        let stats = pool.stats();
        assert_eq!(stats.eagain_retries, 1);
        assert_eq!(stats.eagain_terminal_exhaustions, 1);
    }

    #[tokio::test]
    async fn external_generation_invalidates_idle_and_checked_out_connections() {
        let socket_path = tmp_sock("external-generation");
        let generation_path = tmp_generation("pool");
        let writer = ExternalGenerationWriter::open_or_create(&generation_path).unwrap();
        writer.publish(1);

        let listener = UnixListener::bind(&socket_path).unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    drop(stream);
                });
            }
        });
        let pool = LsapiPool::new(&socket_path, 2, Duration::from_secs(2))
            .external_generation_file(&generation_path)
            .unwrap();
        assert_eq!(pool.generation(), 1);

        let idle = pool.acquire().await.unwrap();
        drop(idle);
        assert_eq!(pool.idle_count(), 1);
        writer.advance(1);
        assert_eq!(pool.generation(), 2);
        assert_eq!(
            pool.idle_count(),
            0,
            "promotion must drop old-generation idle connections"
        );

        let checked_out = pool.acquire().await.unwrap();
        writer.advance(2);
        drop(checked_out);
        assert_eq!(
            pool.idle_count(),
            0,
            "a connection spanning external promotion must not be re-pooled"
        );
        assert_eq!(pool.generation(), 3);
        let stats = pool.stats();
        assert_eq!(stats.generation_advances, 3);
        assert_eq!(stats.stale_idle_drops, 1);
        assert_eq!(stats.stale_checked_out_drops, 1);

        let _ = server.await;
        let _ = std::fs::remove_file(socket_path);
        let _ = std::fs::remove_file(generation_path);
    }

    #[tokio::test]
    async fn attribution_backoff_caps_consecutive_capture_failures() {
        let socket_path = tmp_sock("attribution-backoff");
        let generation_path = tmp_generation("attribution-backoff");
        let writer = ExternalGenerationWriter::open_or_create(&generation_path).unwrap();
        writer.publish(1);

        // The accepting peer is this test process, not an lsphp worker, so
        // every capture attempt fails with NotFound.
        let listener = UnixListener::bind(&socket_path).unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(stream);
        });
        let pool = LsapiPool::new(&socket_path, 1, Duration::from_secs(2))
            .external_generation_file(&generation_path)
            .unwrap();

        for _ in 0..(ATTRIBUTION_BACKOFF_LIMIT + 4) {
            let conn = pool.acquire().await.unwrap();
            drop(conn);
        }
        assert_eq!(pool.idle_count(), 1);
        assert_eq!(
            pool.stats().worker_attribution_failures,
            ATTRIBUTION_BACKOFF_LIMIT,
            "attribution attempts must stop at the backoff limit"
        );

        // A generation advance re-arms attribution: teardown of the now-stale
        // idle entry attempts one more capture.
        writer.advance(1);
        assert_eq!(pool.generation(), 2);
        assert_eq!(
            pool.stats().worker_attribution_failures,
            ATTRIBUTION_BACKOFF_LIMIT + 1,
            "a new epoch must re-arm worker attribution"
        );

        server.abort();
        let _ = server.await;
        let _ = std::fs::remove_file(socket_path);
        let _ = std::fs::remove_file(generation_path);
    }

    #[tokio::test]
    async fn acquire_connects_and_roundtrips() {
        let path = tmp_sock("echo");
        let listener = UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            s.read_exact(&mut buf).await.unwrap();
            s.write_all(&buf).await.unwrap();
        });

        let pool = LsapiPool::new(&path, 4, Duration::from_secs(2));
        let mut conn = pool.acquire().await.unwrap();
        conn.stream_mut().write_all(b"ping").await.unwrap();
        let mut back = [0u8; 4];
        conn.stream_mut().read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"ping");
        server.await.unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn retry_rides_out_a_late_binding_socket() {
        // The lsphp restart window: the socket is momentarily absent (ENOENT) /refused. With
        // a retry budget, acquire() rides it out and connects once the master (re)binds,
        // instead of surfacing an immediate Connect error → 502. Without the retry this would
        // fail on the first dial.
        let path = tmp_sock("retry-late");
        let p2 = path.clone();
        let server = tokio::spawn(async move {
            // Socket absent for ~150ms (the "restart" gap), then it appears and echoes once.
            tokio::time::sleep(Duration::from_millis(150)).await;
            let listener = UnixListener::bind(&p2).unwrap();
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            s.read_exact(&mut buf).await.unwrap();
            s.write_all(&buf).await.unwrap();
        });

        let pool =
            LsapiPool::new(&path, 2, Duration::from_secs(2)).retry_timeout(Duration::from_secs(2));
        let mut conn = pool
            .acquire()
            .await
            .expect("retry should connect once the socket appears");
        conn.stream_mut().write_all(b"ping").await.unwrap();
        let mut back = [0u8; 4];
        conn.stream_mut().read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"ping");
        server.await.unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn fresh_dial_straddling_bump_is_retained() {
        // #38: a socket dialed during the lsphp restart window connects to the freshly-restarted
        // (healthy) worker, so it must NOT be dropped on re-pool merely because the pool generation
        // bumped between acquire-entry and the dial completing. The server binds only after a delay
        // so acquire() retries across the window, and we bump the generation mid-retry. Pre-fix the
        // conn carried the pre-bump (old) gen and repool_if_current dropped it (idle_count==0);
        // post-fix it carries the post-bump gen (re-snapshotted after connect) and is retained.
        let path = tmp_sock("gen-straddle");
        let p2 = path.clone();
        let server = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(120)).await; // late bind = the new worker
            let listener = UnixListener::bind(&p2).unwrap();
            let (s, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
            drop(s);
        });

        let pool = Arc::new(
            LsapiPool::new(&path, 2, Duration::from_secs(2)).retry_timeout(Duration::from_secs(2)),
        );
        let p = pool.clone();
        let acq = tokio::spawn(async move { p.acquire().await });
        tokio::time::sleep(Duration::from_millis(40)).await; // acquire is retrying the unbound socket
        pool.bump_generation(pool.generation() + 1);
        let conn = acq
            .await
            .unwrap()
            .expect("dial should ride out the late bind");
        drop(conn);
        assert_eq!(
            pool.idle_count(),
            1,
            "#38: a socket dialed to the new worker must survive a bump that landed during the dial"
        );
        let _ = server.await;
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn retry_budget_bounds_a_down_backend() {
        // A genuinely-absent backend must still FAIL within the retry budget — never hang.
        let path = tmp_sock("retry-down"); // never bound
        let pool = LsapiPool::new(&path, 1, Duration::from_millis(100))
            .retry_timeout(Duration::from_millis(300));
        let t0 = Instant::now();
        let r = pool.acquire().await;
        let elapsed = t0.elapsed();
        assert!(
            matches!(r, Err(PoolError::Connect(_)) | Err(PoolError::Timeout(_))),
            "a down backend must error with Connect/Timeout"
        );
        assert!(
            elapsed >= Duration::from_millis(250),
            "should retry ~the budget, took {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "must not hang past the budget, took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn returns_to_idle_on_drop_and_reuses() {
        let path = tmp_sock("idle");
        let listener = UnixListener::bind(&path).unwrap();
        // Accept exactly one connection and keep it open.
        let server = tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            // hold it open
            tokio::time::sleep(Duration::from_millis(200)).await;
            drop(s);
        });

        let pool = LsapiPool::new(&path, 2, Duration::from_secs(2));
        {
            let _c = pool.acquire().await.unwrap();
            // dropped here -> returned to idle
        }
        assert_eq!(pool.idle_count(), 1);
        let _c2 = pool.acquire().await.unwrap(); // reuses idle
        assert_eq!(pool.idle_count(), 0);
        let _ = server.await;
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn dead_idle_socket_is_probed_and_redials() {
        // Regression: an idle pooled socket that lsphp closed on its end (worker
        // recycle / idle prune) must be detected at acquire() and discarded, with
        // the pool dialing fresh — instead of handing out a half-closed socket
        // that resets mid-request and surfaces as a 502.
        let path = tmp_sock("deadidle");
        let listener = UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            // Connection #1: close immediately (simulates the lsphp recycle that
            // shuts the kept-alive socket).
            let (first, _) = listener.accept().await.unwrap();
            drop(first);
            // Connection #2: a live echo, proving a fresh dial happened and works.
            let (mut second, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            second.read_exact(&mut buf).await.unwrap();
            second.write_all(&buf).await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
        });

        let pool = LsapiPool::new(&path, 2, Duration::from_secs(2));
        {
            let _c = pool.acquire().await.unwrap(); // dials conn #1
            // dropped here -> returned to idle (still, regardless of health)
        }
        assert_eq!(pool.idle_count(), 1);
        // Let the FIN from the server's close reach our pooled socket.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // acquire() must probe the dead idle socket, drop it, and dial fresh — the
        // echo roundtrip below only succeeds on a live (freshly-dialed) connection.
        let mut c2 = pool.acquire().await.unwrap();
        c2.stream_mut().write_all(b"pong").await.unwrap();
        let mut back = [0u8; 4];
        c2.stream_mut().read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"pong");
        assert_eq!(pool.idle_count(), 0);
        let _ = server.await;
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn healthy_idle_socket_is_reused_after_probe() {
        // The probe must NOT consume bytes or break a live idle socket: a healthy
        // pooled connection is reused (no spurious redial) and still roundtrips.
        let path = tmp_sock("liveidle");
        let listener = UnixListener::bind(&path).unwrap();
        // Accept exactly ONE connection and echo a frame on it — if the probe
        // wrongly redialed, this single accept wouldn't serve the second acquire.
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            s.read_exact(&mut buf).await.unwrap();
            s.write_all(&buf).await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
        });
        let pool = LsapiPool::new(&path, 2, Duration::from_secs(2));
        {
            let _c = pool.acquire().await.unwrap(); // dial; idle on drop
        }
        assert_eq!(pool.idle_count(), 1);
        let mut c2 = pool.acquire().await.unwrap(); // probe says healthy -> reuse
        assert_eq!(pool.idle_count(), 0);
        c2.stream_mut().write_all(b"ping").await.unwrap();
        let mut back = [0u8; 4];
        c2.stream_mut().read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"ping"); // reused socket is fully usable after the probe
        let _ = server.await;
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn poisoned_conn_is_not_pooled() {
        let path = tmp_sock("poison");
        let listener = UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
            drop(s);
        });
        let pool = LsapiPool::new(&path, 2, Duration::from_secs(2));
        {
            let mut c = pool.acquire().await.unwrap();
            c.poison();
        }
        assert_eq!(pool.idle_count(), 0);
        let _ = server.await;
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn acquire_times_out_when_no_listener() {
        let path = tmp_sock("noconn");
        // no listener bound
        let pool = LsapiPool::new(&path, 1, Duration::from_millis(150));
        match pool.acquire().await {
            Err(PoolError::Connect(_)) | Err(PoolError::Timeout(_)) => {}
            Err(other) => panic!("unexpected error: {other:?}"),
            Ok(_) => panic!("expected connect failure with no listener"),
        }
    }

    #[tokio::test]
    async fn split_repools_when_both_halves_deposited_cleanly() {
        let path = tmp_sock("split-clean");
        let listener = UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
            drop(s);
        });

        let pool = LsapiPool::new(&path, 1, Duration::from_secs(2));
        {
            let conn = pool.acquire().await.unwrap();
            let (read, write, guard) = conn.into_split();
            // Both directions finished cleanly: deposit both halves.
            guard.deposit_read(read);
            guard.deposit_write(write);
            drop(guard); // reunite + re-pool happens here
        }
        assert_eq!(pool.idle_count(), 1, "clean split re-pools the socket");
        // The permit was released: a fresh acquire reuses the idle socket.
        let c2 = pool.acquire().await.unwrap();
        assert_eq!(pool.idle_count(), 0);
        drop(c2);
        let _ = server.await;
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn split_does_not_repool_when_poisoned() {
        let path = tmp_sock("split-poison");
        let listener = UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_millis(150)).await;
            drop(s);
        });

        let pool = LsapiPool::new(&path, 1, Duration::from_secs(2));
        {
            let conn = pool.acquire().await.unwrap();
            let (read, write, guard) = conn.into_split();
            guard.deposit_read(read);
            guard.deposit_write(write);
            guard.poison(); // poisoned wins over deposited halves
            drop(guard);
        }
        assert_eq!(pool.idle_count(), 0, "poisoned split is not re-pooled");
        // Slot freed even though the socket was dropped: acquire dials a new one.
        let _ = server.await;
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn split_does_not_repool_with_missing_half() {
        let path = tmp_sock("split-missing");
        let listener = UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_millis(150)).await;
            drop(s);
        });

        let pool = LsapiPool::new(&path, 1, Duration::from_secs(2));
        {
            let conn = pool.acquire().await.unwrap();
            let (read, write, guard) = conn.into_split();
            // Only the read half is deposited (writer never finished); the missing
            // write half must prevent re-pooling.
            guard.deposit_read(read);
            drop(write); // shuts down the write direction
            drop(guard);
        }
        assert_eq!(pool.idle_count(), 0, "a missing half prevents re-pooling");
        let _ = server.await;
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn bump_generation_drops_idle_and_refuses_stale_repool() {
        let path = tmp_sock("gen-drop");
        let listener = UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            // Accept two connections (one reused into the pool, one fresh).
            for _ in 0..2 {
                let (s, _) = listener.accept().await.unwrap();
                tokio::time::sleep(Duration::from_millis(300)).await;
                drop(s);
            }
        });

        let pool = LsapiPool::new(&path, 2, Duration::from_secs(5));
        // Pool one idle connection.
        {
            let _c = pool.acquire().await.unwrap();
        }
        assert_eq!(pool.idle_count(), 1);
        // A restart bumps the generation: the idle socket is dropped immediately.
        pool.bump_generation(pool.generation() + 1);
        assert_eq!(pool.idle_count(), 0, "bump clears the idle set");

        // A conn acquired BEFORE a later bump must refuse to re-pool after it.
        let conn = pool.acquire().await.unwrap();
        pool.bump_generation(pool.generation() + 1);
        drop(conn); // acquire_gen < current -> refused
        assert_eq!(
            pool.idle_count(),
            0,
            "stale-generation conn is not re-pooled"
        );
        let _ = server.await;
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn concurrent_generation_bumps_never_regress() {
        let pool = Arc::new(LsapiPool::new(
            "/tmp/httpjet-unused-generation-test.sock",
            1,
            Duration::from_secs(1),
        ));
        let mut threads = Vec::new();
        for offset in 0..8u64 {
            let pool = pool.clone();
            threads.push(std::thread::spawn(move || {
                for generation in (1..=512u64).rev() {
                    pool.bump_generation(generation + offset * 512);
                }
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(pool.generation(), 4096);
    }

    #[tokio::test]
    async fn prune_idle_discards_expired_entries() {
        let path = tmp_sock("prune");
        let listener = UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
            drop(s);
        });
        let pool = LsapiPool::new(&path, 2, Duration::from_secs(2));
        {
            let _c = pool.acquire().await.unwrap();
        }
        assert_eq!(pool.idle_count(), 1);
        // A zero TTL prunes everything (the entry is "older than" 0).
        pool.prune_idle(Duration::from_secs(0));
        assert_eq!(pool.idle_count(), 0);
        let _ = server.await;
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn acquire_discards_expired_idle_then_dials_fresh() {
        let path = tmp_sock("ttl-expire");
        let listener = UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            // First conn is pooled then expires; second is a fresh dial.
            for _ in 0..2 {
                let (s, _) = listener.accept().await.unwrap();
                tokio::time::sleep(Duration::from_millis(200)).await;
                drop(s);
            }
        });
        // Tiny TTL so the pooled socket is stale by the next acquire.
        let pool =
            LsapiPool::new(&path, 2, Duration::from_secs(2)).idle_ttl(Duration::from_millis(10));
        {
            let _c = pool.acquire().await.unwrap();
        }
        assert_eq!(pool.idle_count(), 1);
        tokio::time::sleep(Duration::from_millis(30)).await;
        // The idle entry is now older than the TTL: acquire discards it and dials.
        let c2 = pool.acquire().await.unwrap();
        assert_eq!(
            pool.idle_count(),
            0,
            "expired idle entry discarded on acquire"
        );
        drop(c2);
        let _ = server.await;
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn clear_drops_idle_without_advancing_generation() {
        let path = tmp_sock("clear");
        let listener = UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
            drop(s);
        });
        let pool = LsapiPool::new(&path, 2, Duration::from_secs(2));
        {
            let _c = pool.acquire().await.unwrap();
        }
        assert_eq!(pool.idle_count(), 1);
        let g = pool.generation();
        pool.clear();
        assert_eq!(pool.idle_count(), 0);
        assert_eq!(
            pool.generation(),
            g,
            "clear does not advance the generation"
        );
        let _ = server.await;
        let _ = std::fs::remove_file(&path);
    }

    // ── DialBreaker state-machine tests (#125 permanent-wedge, #128 stale episode) ──

    /// Drive a continuous failure episode (records spaced within the episode gap, as
    /// a real crashloop's ~40ms-spaced dial failures are) from `base` for `span`.
    fn fail_continuously(b: &Arc<DialBreaker>, base: Instant, span: Duration) {
        let step = BREAKER_EPISODE_GAP;
        let end = base + span;
        let mut t = base;
        while t < end {
            b.record(false, t);
            t += step;
        }
        b.record(false, end);
    }

    fn tripped_breaker(base: Instant) -> Arc<DialBreaker> {
        let b = Arc::new(DialBreaker::new());
        fail_continuously(&b, base, BREAKER_TRIP_AFTER);
        assert!(b.is_open(), "breaker should trip after continuous failure");
        b
    }

    #[test]
    fn breaker_trips_only_after_continuous_failures() {
        let b = Arc::new(DialBreaker::new());
        let t0 = Instant::now();
        b.record(false, t0);
        assert!(!b.is_open(), "a single failure must not trip");
        fail_continuously(&b, t0, BREAKER_TRIP_AFTER - Duration::from_secs(1));
        assert!(!b.is_open(), "<8s of continuous failure must not trip");
        fail_continuously(&b, t0, BREAKER_TRIP_AFTER);
        assert!(b.is_open(), "8s of continuous failure trips");
    }

    #[test]
    fn breaker_episode_resets_after_gap() {
        // #128: a stale failure from an old, since-recovered outage must not make an
        // unrelated later blip trip instantly.
        let b = Arc::new(DialBreaker::new());
        let t0 = Instant::now();
        b.record(false, t0);
        let later = t0 + Duration::from_secs(60);
        b.record(false, later);
        assert!(
            !b.is_open(),
            "a failure long after the last one starts a fresh episode"
        );
        // It now needs a fresh full window of continuous failure from `later`.
        fail_continuously(&b, later, BREAKER_TRIP_AFTER - Duration::from_secs(1));
        assert!(!b.is_open());
        fail_continuously(&b, later, BREAKER_TRIP_AFTER);
        assert!(b.is_open());
    }

    #[test]
    fn breaker_recovers_after_a_failed_trial() {
        // #125: the permanent-wedge regression. After the single half-open trial
        // FAILS, the slot must be released so the next cooldown admits a new trial,
        // and a subsequent success must close the breaker.
        let t0 = Instant::now();
        let b = tripped_breaker(t0);
        let t1 = t0 + BREAKER_TRIP_AFTER + Duration::from_secs(1);

        let g = match DialBreaker::admit(&b, t1) {
            DialAdmission::Trial(g) => g,
            _ => panic!("first request after trip must win the trial slot"),
        };
        // No second trial while the first is in flight.
        assert!(matches!(
            DialBreaker::admit(&b, t1 + BREAKER_TRIAL_COOLDOWN + Duration::from_millis(1)),
            DialAdmission::Reject
        ));
        // The trial fails and drops its guard (lsphp still down).
        b.record(false, t1);
        drop(g);

        // A NEW trial IS admitted after the cooldown — NOT wedged.
        let t2 = t1 + BREAKER_TRIAL_COOLDOWN + Duration::from_millis(1);
        let g2 = match DialBreaker::admit(&b, t2) {
            DialAdmission::Trial(g) => g,
            _ => panic!("breaker wedged: no trial admitted after a failed trial (#125)"),
        };
        // This trial succeeds; the breaker closes and admits everything.
        b.record(true, t2);
        drop(g2);
        assert!(!b.is_open());
        assert!(matches!(DialBreaker::admit(&b, t2), DialAdmission::Proceed));
    }

    #[test]
    fn breaker_trial_slot_released_on_guard_drop_without_record() {
        // #125: the trial exits WITHOUT calling record() (semaphore timeout / idle
        // reuse / cancelled future) — only the guard drops. The slot must still free.
        let t0 = Instant::now();
        let b = tripped_breaker(t0);
        let t1 = t0 + BREAKER_TRIP_AFTER + Duration::from_secs(1);
        match DialBreaker::admit(&b, t1) {
            DialAdmission::Trial(g) => drop(g),
            _ => panic!("expected a trial slot"),
        }
        let t2 = t1 + BREAKER_TRIAL_COOLDOWN + Duration::from_millis(1);
        assert!(
            matches!(DialBreaker::admit(&b, t2), DialAdmission::Trial(_)),
            "trial slot leaked when the guard dropped without record() (#125)"
        );
    }

    #[test]
    fn breaker_closed_admits_without_a_trial() {
        let b = Arc::new(DialBreaker::new());
        assert!(matches!(
            DialBreaker::admit(&b, Instant::now()),
            DialAdmission::Proceed
        ));
    }
}
