//! Privilege/isolation jail for lsphp workers (suEXEC + Linux namespaces).
//!
//! This is the security-critical cluster the [`crate::supervisor`] consumes: it
//! resolves and validates the worker's credentials, chroot target, and namespace
//! flags **in the parent** so the `pre_exec` child consumes only `Copy` /
//! [`CString`] values (no heap allocation, locks, or name lookups in the forked
//! child). It evolves independently of the supervisor lifecycle machinery.

use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use hj_core::config::{ChrootMode, NamespacePolicy, SuExecPolicy, VHostIsolation};

use crate::limits::ResourceLimits;

/// A fully-resolved privilege/isolation jail for an lsphp worker.
///
/// # Contract
/// Everything here is resolved and validated in the **parent** process. The
/// `pre_exec` closure consumes only `Copy` / [`CString`] values out of this
/// struct: no heap allocation, no locks, no filesystem I/O, no name lookups
/// happen inside the forked child. All `chroot`/`chdir` targets are pre-encoded
/// as NUL-terminated [`CString`]s so the child needs no `PathBuf` allocation.
///
/// # Dev-safety / fail-closed
/// The feature is **config-gated** ([`SuExecPolicy::enable`], default `false`)
/// **and** root-gated (only meaningful when `getuid()==0`). When OFF or
/// non-root, [`JailConfig::resolve`] returns an all-`None` jail and behavior is
/// byte-for-byte today's: one pool on the existing socket, server user/group,
/// no chroot. The security invariants below are *fail-closed*: any violation is
/// an `Err`, which the caller (the registry, Phase 4) turns into "PHP disabled
/// for this vhost" — the worker is **never** silently run as root and **never**
/// falls back to an unjailed run.
#[derive(Debug, Clone, Default)]
pub struct JailConfig {
    /// uid/gid to drop to. `None` = no drop (run as the current/server user, as
    /// today). When `Some`, the credentials have already passed the
    /// uid==0/gid==0 and `uid_min`/`gid_min` floor checks.
    pub credentials: Option<Credentials>,
    /// Linux namespaces to `unshare(2)` the worker into before the privilege
    /// drop (Phase 5a). Empty (the [`Default`]) = today's behavior: the worker
    /// shares the server's namespaces. Populated by [`JailConfig::resolve`] only
    /// when the effective [`NamespacePolicy`] is enabled **and** we are root.
    pub namespaces: NamespaceFlags,
    /// `chroot(2)` target, pre-encoded as a `CString`. `None` = no chroot.
    pub chroot: Option<CString>,
    /// Directory to `chdir(2)` into. After a chroot this is always `"/"` (the
    /// new root); without a chroot it may be unset. Pre-encoded as a `CString`.
    pub chdir: Option<CString>,
    /// Resource limits to install (split across the privilege drop by the
    /// supervisor: NPROC before setuid, AS/CPU after).
    pub rlimits: ResourceLimits,
    /// Minimum acceptable uid (carried for diagnostics / re-validation).
    pub uid_min: u32,
    /// Minimum acceptable gid.
    pub gid_min: u32,
}

/// Which Linux namespaces an lsphp worker is `unshare(2)`d into before its
/// privilege drop (Phase 5a). `Copy` and captured pre-fork so the `pre_exec`
/// child consumes it without any allocation (async-signal-safe).
///
/// The [`Default`] is **all-false** (no namespaces) = today's behavior. This is
/// only ever populated by [`JailConfig::resolve`] when the effective
/// [`NamespacePolicy`] has `enable == true` AND the supervisor runs as root —
/// `unshare(2)` of these namespaces needs `CAP_SYS_ADMIN`, which only root has,
/// and the unshare runs while still privileged (before setuid).
///
/// See [`NamespacePolicy`] for the per-namespace semantics (notably: `net`
/// gives loopback-only and breaks outbound PHP; `pid` is **not honored** in the
/// current unshare-then-exec model and is stripped fail-safe — see
/// [`NamespaceFlags::pid`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct NamespaceFlags {
    /// `CLONE_NEWNS` — private mount namespace (no mount choreography in 5a).
    pub mount: bool,
    /// `CLONE_NEWPID` — requested new PID namespace. **Currently NOT honored.**
    ///
    /// In the unshare-then-exec model used by [`LsphpSupervisor`], the process
    /// that execs the lsphp master only *unshares* the PID namespace: per
    /// `unshare(2)`, the caller stays in the old PID namespace and only its
    /// children enter the new one. The lsphp master is a long-lived prefork
    /// accept-distributor (vendor/lsapilib.c), so the FIRST request-handler it
    /// forks becomes PID 1 (init) of the new namespace. lsphp recycles those
    /// workers by design (exit after `LSAPI_MAX_REQS`, idle/max-idle pruning) —
    /// and when PID 1 dies the kernel SIGKILLs every other process in the
    /// namespace, tearing down the entire worker pool mid-request.
    ///
    /// To honor this safely the supervisor would have to `fork()` after the
    /// unshare so the lsphp master itself becomes a stable PID-1 reaper, which is
    /// incompatible with the current single-syscall, `Command`-tracked exec path.
    /// Until that lands, the flag is stripped fail-safe in
    /// [`NamespaceFlags::from_policy`] and [`NamespaceFlags::to_unshare_flags`],
    /// so no `CLONE_NEWPID` is ever actually unshared. The field is retained so a
    /// future fork-based implementation can honor it and so the registry jail key
    /// stays stable.
    pub pid: bool,
    /// `CLONE_NEWNET` — new network namespace (loopback-only; breaks egress).
    pub net: bool,
    /// `CLONE_NEWUTS` — private hostname/NIS domain.
    pub uts: bool,
    /// `CLONE_NEWIPC` — private SysV/POSIX IPC namespace.
    pub ipc: bool,
}

impl NamespaceFlags {
    /// True when no namespace is selected (the [`Default`]). When this holds,
    /// `pre_exec` performs **no** `unshare(2)` call at all — byte-for-byte
    /// today's behavior.
    pub fn is_empty(&self) -> bool {
        !(self.mount || self.pid || self.net || self.uts || self.ipc)
    }

    /// Map an *effective* [`NamespacePolicy`] (already chosen: vhost override
    /// else server policy) into flags. Returns the empty set when the policy's
    /// master `enable` is off, so a disabled policy never unshares anything.
    ///
    /// `CLONE_NEWPID` is **intentionally not honored** here: see the comment on
    /// [`NamespaceFlags::pid`]. The unshare-then-exec topology this supervisor
    /// uses cannot make the lsphp *master* PID 1 of the new namespace (only its
    /// children enter it, and the first-forked worker becomes PID 1 — its
    /// routine recycling would then SIGKILL the whole pool). Until a fork-based
    /// init can host the PID namespace, a requested `pid` is dropped fail-safe so
    /// no dangerous topology is ever created.
    fn from_policy(policy: &NamespacePolicy) -> Self {
        if !policy.enable {
            return NamespaceFlags::default();
        }
        NamespaceFlags {
            mount: policy.mount,
            // pid is deliberately NOT propagated — see doc comment above.
            pid: false,
            net: policy.net,
            uts: policy.uts,
            ipc: policy.ipc,
        }
    }

    /// Build the `rustix` [`UnshareFlags`](rustix::thread::UnshareFlags)
    /// corresponding to the selected namespaces. Computed in the **parent**
    /// (this returns a plain `Copy` bitflags value) so the child only issues the
    /// single `unshare_unsafe` syscall.
    ///
    /// `CLONE_NEWPID` is **never** emitted, regardless of `self.pid`. This is the
    /// authoritative enforcement point for the rule in [`NamespaceFlags::pid`]:
    /// the unshare-then-exec model used by [`LsphpSupervisor`] would leave the
    /// lsphp master in the parent PID namespace and make the first-forked worker
    /// PID 1 of the new one, so that worker's by-design recycling
    /// (`LSAPI_MAX_REQS` / idle pruning) would SIGKILL the entire sibling pool.
    /// `from_policy` already strips `pid`; this guard also covers any flags built
    /// by hand (e.g. the registry key path) so no caller can resurrect the
    /// dangerous topology.
    pub(crate) fn to_unshare_flags(self) -> rustix::thread::UnshareFlags {
        use rustix::thread::UnshareFlags;
        let mut f = UnshareFlags::empty();
        if self.mount {
            f |= UnshareFlags::NEWNS;
        }
        // self.pid is intentionally ignored — see doc comment above.
        if self.net {
            f |= UnshareFlags::NEWNET;
        }
        if self.uts {
            f |= UnshareFlags::NEWUTS;
        }
        if self.ipc {
            f |= UnshareFlags::NEWIPC;
        }
        f
    }
}

impl JailConfig {
    /// Resolve a fully-validated jail in the **parent** from per-vhost isolation
    /// intent + the server policy.
    ///
    /// `is_root` should be `getuid()==0`. `doc_root`/`vh_root` are the already
    /// `$VAR`-expanded paths for the vhost.
    ///
    /// # Dev-safety gates (checked first)
    /// - If `!policy.enable` **or** `!is_root` → returns the all-`None` jail
    ///   (today's behavior: server user/group, no chroot). `iso` is ignored.
    /// - If `iso` is `None` (vhost declares no override) → also the all-`None`
    ///   jail.
    ///
    /// # Security invariants (fail-closed; each is an `Err`)
    /// 1. Resolved worker `uid != 0` and `gid != 0` (never run as root).
    /// 2. `uid >= policy.uid_min` and `gid >= policy.gid_min` (default 100/100;
    ///    mirrors OLS `getUidMin`/`getGidMin`, localworker.cpp:447-456).
    /// 3. A chroot target must **exist**, be a **directory**, be **root-owned**
    ///    (uid 0), and **not be writable by the worker uid** (no group/other
    ///    write, and not owned-writable by a non-root owner — here owner is
    ///    root, so we reject any group/other write bit).
    /// 4. After a chroot we **always** `chdir("/")` (the new root). With no
    ///    chroot, no chdir is forced (today's behavior).
    ///
    /// # Namespaces (Phase 5a)
    /// The effective [`NamespacePolicy`] is the per-vhost override
    /// (`iso.namespaces`) when present, else the server policy
    /// (`policy.namespaces`). It is mapped to [`NamespaceFlags`] via
    /// [`NamespaceFlags::from_policy`] — which is empty unless the effective
    /// policy's master `enable` is on. Because the namespace branch is only
    /// reached after the `policy.enable && is_root` gate above, the flags are
    /// non-empty **only** when suEXEC is enabled, we are root, and the effective
    /// namespace policy is itself enabled. Otherwise they stay empty (today's
    /// behavior), and `pre_exec` issues no `unshare(2)`.
    pub fn resolve(
        iso: Option<&VHostIsolation>,
        doc_root: &Path,
        vh_root: &Path,
        policy: &SuExecPolicy,
        is_root: bool,
    ) -> io::Result<JailConfig> {
        // --- Dev-safety: config-gate + root-gate + per-vhost opt-in ---
        if !policy.enable || !is_root {
            return Ok(JailConfig::default());
        }
        let iso = match iso {
            Some(iso) => iso,
            None => return Ok(JailConfig::default()),
        };

        // --- Resolve credentials in the PARENT ---
        let cred = if iso.from_docroot_owner {
            // UID_DOCROOT: take the doc-root's owner uid/gid.
            let md = std::fs::metadata(doc_root).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!(
                        "suexec: cannot stat doc_root {} for owner: {e}",
                        doc_root.display()
                    ),
                )
            })?;
            Credentials {
                uid: md.uid(),
                gid: md.gid(),
            }
        } else {
            resolve_credentials(&iso.user, &iso.group)?
        };

        // --- Invariant 1 & 2: never root; honor the uid/gid floors ---
        if cred.uid == 0 || cred.gid == 0 {
            return Err(invalid(
                "suexec: refusing to run worker as root (uid==0 or gid==0)",
            ));
        }
        if cred.uid < policy.uid_min || cred.gid < policy.gid_min {
            return Err(invalid(
                "suexec: worker uid/gid below configured uidMin/gidMin floor",
            ));
        }

        // --- Resolve + validate the chroot target in the PARENT ---
        let chroot_path: Option<PathBuf> = match &iso.chroot {
            ChrootMode::None => None,
            ChrootMode::VhRoot => Some(vh_root.to_path_buf()),
            ChrootMode::Path(p) => Some(p.clone()),
        };

        let (chroot, chdir) = match chroot_path {
            Some(path) => {
                validate_chroot_target(&path, cred.uid)?;
                // Invariant 4: after chroot we always chdir into the new root.
                let c = path_to_cstring(&path)?;
                (Some(c), Some(cstring_root()))
            }
            None => (None, None),
        };

        // --- Effective namespace policy: per-vhost override else server. ---
        // We are past the `policy.enable && is_root` gate, so the only remaining
        // condition for non-empty flags is the *effective* policy's own master
        // `enable` (handled by NamespaceFlags::from_policy).
        let effective_ns = iso.namespaces.as_ref().unwrap_or(&policy.namespaces);
        let namespaces = NamespaceFlags::from_policy(effective_ns);

        Ok(JailConfig {
            credentials: Some(cred),
            namespaces,
            chroot,
            chdir,
            // rlimits are layered in by the supervisor from its own config; the
            // jail itself carries none by default. Phase 3's limits live on
            // SupervisorConfig and are merged at spawn time.
            rlimits: ResourceLimits::default(),
            uid_min: policy.uid_min,
            gid_min: policy.gid_min,
        })
    }
}

/// Validate a chroot target in the parent: must exist, be a directory, be
/// root-owned, and not be writable by the worker uid. Fail-closed.
fn validate_chroot_target(path: &Path, _worker_uid: u32) -> io::Result<()> {
    let md = std::fs::metadata(path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "suexec: chroot target {} does not exist/stat failed: {e}",
                path.display()
            ),
        )
    })?;
    if !md.is_dir() {
        return Err(invalid(&format!(
            "suexec: chroot target {} is not a directory",
            path.display()
        )));
    }
    // Must be owned by root (uid 0). A non-root-owned chroot root would let the
    // owner replace it / pivot the jail.
    if md.uid() != 0 {
        return Err(invalid(&format!(
            "suexec: chroot target {} must be owned by root (is uid {})",
            path.display(),
            md.uid()
        )));
    }
    // Must NOT be writable by the worker. Owner is root (checked above), so the
    // worker can only gain write via the group or other bits — reject either.
    // (0o022 = group-write | other-write.)
    if md.mode() & 0o022 != 0 {
        return Err(invalid(&format!(
            "suexec: chroot target {} is group/other-writable (mode {:o}); worker could escape jail",
            path.display(),
            md.mode() & 0o7777
        )));
    }
    Ok(())
}

/// Encode a path as a NUL-terminated `CString` (parent-side, so the child needs
/// no allocation). Errors if the path contains an interior NUL.
fn path_to_cstring(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| invalid("suexec: path contains interior NUL byte"))
}

/// `CString` for `"/"` (the post-chroot working directory).
fn cstring_root() -> CString {
    // "/" has no NUL, so this never fails.
    CString::new("/").expect("\"/\" is a valid CString")
}

/// Resolved POSIX credentials to drop to. Resolved entirely in the **parent**
/// (name → numeric uid/gid) so the `pre_exec` child only ever consumes `Copy`
/// values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Credentials {
    pub uid: u32,
    pub gid: u32,
}

/// Resolve a user (and optional group) name to uid/gid by reading `/etc/passwd`
/// and `/etc/group`. Numeric inputs are accepted directly. Avoids a libc/nss dep.
pub(crate) fn resolve_credentials(user: &str, group: &str) -> io::Result<Credentials> {
    let (uid, primary_gid) = lookup_user(user)?;
    let gid = if group.is_empty() {
        primary_gid
    } else {
        lookup_group(group)?
    };
    Ok(Credentials { uid, gid })
}

fn lookup_user(user: &str) -> io::Result<(u32, u32)> {
    let numeric_uid = user.parse::<u32>().ok();
    let passwd = std::fs::read_to_string("/etc/passwd")?;
    for line in passwd.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 4 {
            continue;
        }
        let row_uid: Option<u32> = f[2].parse().ok();
        if f[0] == user || (numeric_uid.is_some() && row_uid == numeric_uid) {
            let uid = f[2]
                .parse()
                .map_err(|_| invalid("bad uid in /etc/passwd"))?;
            let gid = f[3]
                .parse()
                .map_err(|_| invalid("bad gid in /etc/passwd"))?;
            return Ok((uid, gid));
        }
    }
    // A numeric uid with no matching passwd row: gid defaults to the same number
    // (the historical behavior; suEXEC is off by default so this is rarely hit).
    if let Some(uid) = numeric_uid {
        return Ok((uid, uid));
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("user '{user}' not found"),
    ))
}

fn lookup_group(group: &str) -> io::Result<u32> {
    if let Ok(gid) = group.parse::<u32>() {
        return Ok(gid);
    }
    let groups = std::fs::read_to_string("/etc/group")?;
    for line in groups.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() >= 3 && f[0] == group {
            return f[2].parse().map_err(|_| invalid("bad gid in /etc/group"));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("group '{group}' not found"),
    ))
}

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_numeric_credentials() {
        let c = resolve_credentials("1000", "1000").unwrap();
        assert_eq!(c.uid, 1000);
        assert_eq!(c.gid, 1000);
    }

    #[test]
    fn lookup_root_from_passwd() {
        // root is uid 0 on any Linux box.
        let (uid, gid) = lookup_user("root").unwrap();
        assert_eq!(uid, 0);
        assert_eq!(gid, 0);
    }

    #[test]
    fn missing_user_errors() {
        let err = lookup_user("definitely-not-a-real-user-xyz").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    // ----- JailConfig::resolve -----

    fn enabled_policy() -> SuExecPolicy {
        SuExecPolicy {
            enable: true,
            uid_min: 100,
            gid_min: 100,
            ..Default::default()
        }
    }

    fn iso_user(user: &str, group: &str) -> VHostIsolation {
        VHostIsolation {
            user: user.into(),
            group: group.into(),
            chroot: ChrootMode::None,
            from_docroot_owner: false,
            namespaces: None,
        }
    }

    #[test]
    fn resolve_off_when_policy_disabled() {
        // Feature OFF (default policy) -> all-None jail even if we are "root"
        // and the vhost declares isolation. Byte-for-byte today's behavior.
        let policy = SuExecPolicy::default(); // enable=false
        let iso = iso_user("1000", "1000");
        let jail = JailConfig::resolve(
            Some(&iso),
            Path::new("/tmp"),
            Path::new("/tmp"),
            &policy,
            /* is_root */ true,
        )
        .unwrap();
        assert!(jail.credentials.is_none());
        assert!(jail.chroot.is_none());
        assert!(jail.chdir.is_none());
    }

    #[test]
    fn resolve_off_when_not_root() {
        // Even with the feature ON, a non-root supervisor never drops/chroots.
        let policy = enabled_policy();
        let iso = iso_user("1000", "1000");
        let jail = JailConfig::resolve(
            Some(&iso),
            Path::new("/tmp"),
            Path::new("/tmp"),
            &policy,
            /* is_root */ false,
        )
        .unwrap();
        assert!(jail.credentials.is_none());
        assert!(jail.chroot.is_none());
        assert!(jail.chdir.is_none());
    }

    #[test]
    fn resolve_none_isolation_is_all_none() {
        // Vhost opts out (no per-vhost isolation) -> all-None jail.
        let policy = enabled_policy();
        let jail =
            JailConfig::resolve(None, Path::new("/tmp"), Path::new("/tmp"), &policy, true).unwrap();
        assert!(jail.credentials.is_none());
        assert!(jail.chroot.is_none());
    }

    #[test]
    fn resolve_rejects_root_uid() {
        // uid 0 must be rejected (never run a worker as root).
        let policy = enabled_policy();
        let iso = iso_user("0", "0");
        let err = JailConfig::resolve(
            Some(&iso),
            Path::new("/tmp"),
            Path::new("/tmp"),
            &policy,
            true,
        )
        .unwrap_err();
        assert!(err.to_string().contains("root"), "got: {err}");
    }

    #[test]
    fn resolve_rejects_root_gid_only() {
        // A non-root uid but gid 0 is still rejected.
        let policy = enabled_policy();
        let iso = iso_user("1000", "0");
        let err = JailConfig::resolve(
            Some(&iso),
            Path::new("/tmp"),
            Path::new("/tmp"),
            &policy,
            true,
        )
        .unwrap_err();
        assert!(err.to_string().contains("root"), "got: {err}");
    }

    #[test]
    fn resolve_rejects_below_uid_min() {
        // uid below the configured floor (default 100) is rejected.
        let policy = enabled_policy();
        let iso = iso_user("50", "50");
        let err = JailConfig::resolve(
            Some(&iso),
            Path::new("/tmp"),
            Path::new("/tmp"),
            &policy,
            true,
        )
        .unwrap_err();
        assert!(err.to_string().contains("floor"), "got: {err}");
    }

    #[test]
    fn resolve_rejects_below_gid_min() {
        // uid ok, gid below the floor -> rejected.
        let policy = enabled_policy();
        let iso = iso_user("1000", "50");
        let err = JailConfig::resolve(
            Some(&iso),
            Path::new("/tmp"),
            Path::new("/tmp"),
            &policy,
            true,
        )
        .unwrap_err();
        assert!(err.to_string().contains("floor"), "got: {err}");
    }

    #[test]
    fn resolve_accepts_valid_uid_no_chroot() {
        // Valid non-root uid/gid above the floor, no chroot -> credentials set,
        // chroot/chdir stay None.
        let policy = enabled_policy();
        let iso = iso_user("1000", "1000");
        let jail = JailConfig::resolve(
            Some(&iso),
            Path::new("/tmp"),
            Path::new("/tmp"),
            &policy,
            true,
        )
        .unwrap();
        assert_eq!(
            jail.credentials,
            Some(Credentials {
                uid: 1000,
                gid: 1000
            })
        );
        assert!(jail.chroot.is_none());
        assert!(jail.chdir.is_none());
        assert_eq!(jail.uid_min, 100);
        assert_eq!(jail.gid_min, 100);
    }

    // ----- Phase 5a: NamespaceFlags mapping + resolve() gating -----

    #[test]
    fn namespace_flags_default_is_empty() {
        // Regression gate: the default jail carries no namespaces (today's
        // behavior — pre_exec issues no unshare).
        let jail = JailConfig::default();
        assert!(jail.namespaces.is_empty());
        assert_eq!(jail.namespaces, NamespaceFlags::default());
    }

    #[test]
    fn namespace_flags_from_disabled_policy_is_empty() {
        // A policy with enable=false maps to empty flags even if per-flags set.
        let policy = NamespacePolicy {
            enable: false,
            mount: true,
            pid: true,
            net: true,
            uts: true,
            ipc: true,
        };
        assert!(NamespaceFlags::from_policy(&policy).is_empty());
    }

    #[test]
    fn namespace_flags_from_enabled_policy_maps_each_flag() {
        let policy = NamespacePolicy {
            enable: true,
            mount: true,
            pid: false,
            net: true,
            uts: false,
            ipc: true,
        };
        let f = NamespaceFlags::from_policy(&policy);
        assert!(f.mount && f.net && f.ipc);
        assert!(!f.pid && !f.uts);
        assert!(!f.is_empty());
    }

    #[test]
    fn namespace_flags_from_policy_strips_pid() {
        // `pid` is fail-safe stripped: the unshare-then-exec model would make the
        // first-forked lsphp worker PID 1, whose recycling SIGKILLs the pool.
        let policy = NamespacePolicy {
            enable: true,
            pid: true,
            mount: true,
            ..Default::default()
        };
        let f = NamespaceFlags::from_policy(&policy);
        assert!(!f.pid, "pid must be dropped by from_policy");
        assert!(f.mount, "other namespaces still propagate");
    }

    #[test]
    fn resolve_namespaces_empty_when_suexec_disabled() {
        // suEXEC OFF => no namespaces regardless of any per-vhost ns override.
        let policy = SuExecPolicy::default(); // enable=false
        let mut iso = iso_user("1000", "1000");
        iso.namespaces = Some(NamespacePolicy {
            enable: true,
            net: true,
            ..Default::default()
        });
        let jail = JailConfig::resolve(
            Some(&iso),
            Path::new("/tmp"),
            Path::new("/tmp"),
            &policy,
            true,
        )
        .unwrap();
        assert!(jail.namespaces.is_empty());
    }

    #[test]
    fn resolve_namespaces_empty_when_not_root() {
        // Feature ON + ns policy ON, but non-root => still empty (unshare needs
        // CAP_SYS_ADMIN; we never attempt it off-root).
        let mut policy = enabled_policy();
        policy.namespaces = NamespacePolicy {
            enable: true,
            net: true,
            ..Default::default()
        };
        let iso = iso_user("1000", "1000");
        let jail = JailConfig::resolve(
            Some(&iso),
            Path::new("/tmp"),
            Path::new("/tmp"),
            &policy,
            false,
        )
        .unwrap();
        assert!(jail.namespaces.is_empty());
        // Non-root also means the all-None jail (no credential drop).
        assert!(jail.credentials.is_none());
    }

    #[test]
    fn resolve_namespaces_empty_when_policy_disabled_but_suexec_on() {
        // suEXEC ON + root, but the namespace policy itself is disabled => empty.
        let policy = enabled_policy(); // namespaces default = disabled
        let iso = iso_user("1000", "1000");
        let jail = JailConfig::resolve(
            Some(&iso),
            Path::new("/tmp"),
            Path::new("/tmp"),
            &policy,
            true,
        )
        .unwrap();
        assert!(jail.namespaces.is_empty());
        // Credentials still resolve (suEXEC is on); only namespaces are empty.
        assert_eq!(
            jail.credentials,
            Some(Credentials {
                uid: 1000,
                gid: 1000
            })
        );
    }

    #[test]
    fn resolve_namespaces_from_server_policy_when_root() {
        // suEXEC ON + root + server ns policy ON, vhost inherits (None) => flags
        // come from the server policy.
        let mut policy = enabled_policy();
        policy.namespaces = NamespacePolicy {
            enable: true,
            mount: true,
            pid: true,
            ..Default::default()
        };
        let iso = iso_user("1000", "1000"); // namespaces: None => inherit
        let jail = JailConfig::resolve(
            Some(&iso),
            Path::new("/tmp"),
            Path::new("/tmp"),
            &policy,
            true,
        )
        .unwrap();
        // `pid` is stripped fail-safe (see NamespaceFlags::pid); `mount` survives.
        assert_eq!(
            jail.namespaces,
            NamespaceFlags {
                mount: true,
                pid: false,
                ..Default::default()
            }
        );
    }

    #[test]
    fn resolve_vhost_namespace_override_wins_over_server() {
        // Per-vhost override (Some) replaces the server policy wholesale.
        let mut policy = enabled_policy();
        policy.namespaces = NamespacePolicy {
            enable: true,
            net: true,
            ..Default::default()
        };
        let mut iso = iso_user("1000", "1000");
        // Override: enable only uts, no net.
        iso.namespaces = Some(NamespacePolicy {
            enable: true,
            uts: true,
            ..Default::default()
        });
        let jail = JailConfig::resolve(
            Some(&iso),
            Path::new("/tmp"),
            Path::new("/tmp"),
            &policy,
            true,
        )
        .unwrap();
        assert_eq!(
            jail.namespaces,
            NamespaceFlags {
                uts: true,
                ..Default::default()
            }
        );
        assert!(
            !jail.namespaces.net,
            "server net flag must not leak through override"
        );
    }

    #[test]
    fn unshare_flags_round_trip() {
        use rustix::thread::UnshareFlags;
        let f = NamespaceFlags {
            mount: true,
            pid: true,
            net: true,
            uts: true,
            ipc: true,
        }
        .to_unshare_flags();
        assert!(f.contains(UnshareFlags::NEWNS));
        // NEWPID is never emitted even when `pid` is set on the struct — the
        // authoritative fail-safe guard against the PID-1-recycling cascade.
        assert!(!f.contains(UnshareFlags::NEWPID));
        assert!(f.contains(UnshareFlags::NEWNET));
        assert!(f.contains(UnshareFlags::NEWUTS));
        assert!(f.contains(UnshareFlags::NEWIPC));
        assert!(NamespaceFlags::default().to_unshare_flags().is_empty());
    }

    #[test]
    fn unshare_flags_never_contains_newpid() {
        use rustix::thread::UnshareFlags;
        // Even a pid-only request resolves to an empty unshare set: nothing is
        // unshared, so no PID namespace is ever created by this exec model.
        let f = NamespaceFlags {
            pid: true,
            ..Default::default()
        }
        .to_unshare_flags();
        assert!(!f.contains(UnshareFlags::NEWPID));
        assert!(f.is_empty());
    }

    // Root-requiring: actually unsharing namespaces needs CAP_SYS_ADMIN and a
    // forked child. Kept ignored so the default test run never tries to unshare.
    #[test]
    #[ignore = "requires root + CAP_SYS_ADMIN to actually unshare(2) namespaces"]
    fn unshare_uts_namespace_root_only() {
        // A minimal smoke test: unshare a UTS namespace in-thread. Only valid
        // when run as root; the harness ignores it by default.
        let flags = NamespaceFlags {
            uts: true,
            ..Default::default()
        }
        .to_unshare_flags();
        // SAFETY: only NEWUTS is passed (no FILES); this thread does not rely on
        // a shared hostname afterwards.
        unsafe { rustix::thread::unshare_unsafe(flags) }.expect("unshare NEWUTS as root");
    }

    #[test]
    fn validate_chroot_rejects_nonexistent() {
        let err = validate_chroot_target(Path::new("/tmp/definitely-not-here-xyz-123"), 1000)
            .unwrap_err();
        // Either a stat error or our wrapped message; just assert it's an Err.
        let _ = err;
    }

    #[test]
    fn validate_chroot_rejects_non_dir() {
        // A regular file is not a valid chroot target.
        let p = std::env::temp_dir().join(format!("hj-jail-file-{}", std::process::id()));
        std::fs::write(&p, b"x").unwrap();
        let err = validate_chroot_target(&p, 1000).unwrap_err();
        assert!(err.to_string().contains("not a directory"), "got: {err}");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn path_to_cstring_rejects_interior_nul() {
        use std::os::unix::ffi::OsStrExt;
        let p = Path::new(std::ffi::OsStr::from_bytes(b"/a\0b"));
        assert!(path_to_cstring(p).is_err());
    }

    #[test]
    fn cstring_root_is_slash() {
        assert_eq!(cstring_root().to_bytes(), b"/");
    }

    // Root-gated chroot validation: requires running as root with a controlled
    // root-owned directory tree, so it's ignored by default.
    #[test]
    #[ignore = "requires root + a root-owned, non-writable chroot dir"]
    fn resolve_chroot_vhroot_root_only() {
        let policy = enabled_policy();
        let iso = VHostIsolation {
            user: "1000".into(),
            group: "1000".into(),
            chroot: ChrootMode::VhRoot,
            from_docroot_owner: false,
            namespaces: None,
        };
        // /tmp is world-writable so this would be rejected; a real run needs a
        // root-owned 0755 dir. Kept ignored.
        let jail =
            JailConfig::resolve(Some(&iso), Path::new("/"), Path::new("/"), &policy, true).unwrap();
        assert!(jail.chroot.is_some());
        assert_eq!(jail.chdir.as_ref().unwrap().to_bytes(), b"/");
    }
}
