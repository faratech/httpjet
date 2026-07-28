//! Per-worker resource limits (`setrlimit`) applied in the forked child before
//! `exec`, mirroring LiteSpeed's `memSoftLimit`/`memHardLimit`/`procSoftLimit`/
//! `procHardLimit`/CPU caps on its local (lsphp) workers.
//!
//! # Async-signal-safety
//! [`ResourceLimits::apply`] is invoked from inside the `pre_exec` closure of a
//! freshly-forked, single-threaded child. It must therefore touch nothing but
//! async-signal-safe syscalls: it makes only `getrlimit`/`setrlimit`
//! (`prlimit64`) calls
//! via `rustix`'s `linux_raw` backend — no heap allocation, no locks, no libc
//! global state. Rustix lowers both operations directly to syscalls, so they are
//! safe in this context.
//!
//! # RLIMIT_AS / opcache & JIT caveat
//! [`mem_hard`]/[`mem_soft`] are applied to **both** `RLIMIT_DATA` and
//! `RLIMIT_AS` (total address space). `RLIMIT_AS` also counts mmap'd regions:
//! PHP's opcache SHM segment and, especially, the JIT's executable buffer are
//! `mmap`-backed and *do* count against `RLIMIT_AS`. Setting `mem_hard` too low
//! with opcache+JIT enabled can make `mmap` fail at startup (often a silent
//! opcache disable, or an outright fatal). LiteSpeed itself notes this; the
//! safe move is to size `mem_hard` well above the configured
//! `opcache.memory_consumption` + `opcache.jit_buffer_size`, or to leave
//! `mem_hard` `None` and rely on `RLIMIT_DATA` (`mem_soft`) only. All fields
//! default to `None` (no limit), preserving today's behavior.

use std::io;

use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};

/// Resource limits to install in the child before `exec`. Every field is
/// `None` by default, meaning "do not call setrlimit for this resource" — i.e.
/// inherit the parent's limit (today's behavior).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResourceLimits {
    /// Soft data-segment limit (bytes) → `RLIMIT_DATA.current`. From
    /// `PhpConfig::mem_soft_limit`.
    pub mem_soft: Option<u64>,
    /// Hard address-space limit (bytes) → `RLIMIT_AS.maximum` (and current).
    /// From `PhpConfig::mem_hard_limit`. See the opcache/JIT caveat above.
    pub mem_hard: Option<u64>,
    /// CPU soft limit (seconds) → `RLIMIT_CPU.current`.
    pub cpu_soft_secs: Option<u64>,
    /// CPU hard limit (seconds) → `RLIMIT_CPU.maximum`.
    pub cpu_hard_secs: Option<u64>,
    /// Process-count soft limit → `RLIMIT_NPROC.current`.
    pub nproc_soft: Option<u64>,
    /// Process-count hard limit → `RLIMIT_NPROC.maximum`.
    pub nproc_hard: Option<u64>,
}

impl ResourceLimits {
    /// `true` if every field is `None` (nothing to do).
    pub fn is_empty(&self) -> bool {
        self.mem_soft.is_none()
            && self.mem_hard.is_none()
            && self.cpu_soft_secs.is_none()
            && self.cpu_hard_secs.is_none()
            && self.nproc_soft.is_none()
            && self.nproc_hard.is_none()
    }

    /// Install **all** configured limits via `setrlimit`, in one shot.
    ///
    /// Prefer the split [`apply_pre_setuid`](Self::apply_pre_setuid) /
    /// [`apply_post_setuid`](Self::apply_post_setuid) pair when a privilege drop
    /// is involved (see those docs for the ordering rationale). This combined
    /// method is kept for the no-drop / legacy path and is equivalent to calling
    /// the pre-setuid half followed by the post-setuid half.
    ///
    /// # Async-signal-safety
    /// Only issues `getrlimit`/`setrlimit` syscalls — no allocation, no
    /// locks. Safe to call inside a `pre_exec` closure (see module docs).
    ///
    /// Resources whose field is `None` are left untouched. On the first failing
    /// `setrlimit` the error is returned (which, in `pre_exec`, aborts the
    /// child spawn).
    pub fn apply(&self) -> io::Result<()> {
        self.apply_pre_setuid()?;
        self.apply_post_setuid()?;
        Ok(())
    }

    /// Limits that MUST be installed **before** the `setuid` drop.
    ///
    /// `RLIMIT_NPROC` is checked by the kernel at the *next* `fork`/`clone`
    /// against the process's **real uid** at that time; but more importantly the
    /// limit value should be established while we still have the privilege to
    /// raise it if needed. We install it before the drop so it is in force the
    /// instant the worker (and any children it forks) runs under its real uid.
    /// This mirrors OLS `apply_rlimits_uid_chroot_stderr` (lscgid.cpp:381-390),
    /// which sets `RLIMIT_NPROC` ahead of `set_uid_chroot`.
    ///
    /// # Async-signal-safety
    /// Only `getrlimit`/`setrlimit` syscalls. Safe inside `pre_exec`.
    pub fn apply_pre_setuid(&self) -> io::Result<()> {
        // RLIMIT_NPROC: caps the number of processes for the worker's uid.
        if self.nproc_soft.is_some() || self.nproc_hard.is_some() {
            set_pair(Resource::Nproc, self.nproc_soft, self.nproc_hard)?;
        }
        Ok(())
    }

    /// Limits installed **after** the `setuid` drop: address space / data
    /// segment / CPU. These are not uid-relative and OLS installs `RLIMIT_AS`
    /// after the uid/chroot change (lscgid.cpp:395-406), so we match that order.
    ///
    /// # Async-signal-safety
    /// Only `getrlimit`/`setrlimit` syscalls. Safe inside `pre_exec`.
    pub fn apply_post_setuid(&self) -> io::Result<()> {
        // RLIMIT_DATA from the soft memory limit. We set current == maximum so
        // the worker cannot raise it back up; this matches LiteSpeed treating
        // memSoftLimit as the effective brk/sbrk ceiling.
        if let Some(bytes) = self.mem_soft {
            set_exact(Resource::Data, bytes)?;
        }
        // RLIMIT_AS from the hard memory limit (total address space, mmap
        // included). See the opcache/JIT caveat in the module docs.
        if let Some(bytes) = self.mem_hard {
            set_exact(Resource::As, bytes)?;
        }
        // RLIMIT_CPU (seconds of CPU time). On soft-limit hit the kernel sends
        // SIGXCPU; on the hard limit, SIGKILL.
        if self.cpu_soft_secs.is_some() || self.cpu_hard_secs.is_some() {
            set_pair(Resource::Cpu, self.cpu_soft_secs, self.cpu_hard_secs)?;
        }
        Ok(())
    }
}

/// Set a resource's soft and hard limit to the same value.
#[inline]
fn set_exact(resource: Resource, value: u64) -> io::Result<()> {
    setrlimit(
        resource,
        Rlimit {
            current: Some(value),
            maximum: Some(value),
        },
    )
    .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))
}

#[inline]
fn set_pair(resource: Resource, soft: Option<u64>, hard: Option<u64>) -> io::Result<()> {
    let next = merge_limit_pair(getrlimit(resource), soft, hard);
    setrlimit(resource, next).map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))
}

fn merge_limit_pair(inherited: Rlimit, soft: Option<u64>, hard: Option<u64>) -> Rlimit {
    let maximum = hard.or(inherited.maximum);
    let current = match soft {
        Some(value) => Some(value),
        None => match hard {
            Some(maximum) => Some(
                inherited
                    .current
                    .map_or(maximum, |value| value.min(maximum)),
            ),
            None => inherited.current,
        },
    };
    Rlimit { current, maximum }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_empty() {
        assert!(ResourceLimits::default().is_empty());
    }

    #[test]
    fn nonempty_when_any_set() {
        let l = ResourceLimits {
            cpu_soft_secs: Some(10),
            ..Default::default()
        };
        assert!(!l.is_empty());
    }

    #[test]
    fn apply_empty_is_ok() {
        // No fields set → no syscalls → Ok.
        assert!(ResourceLimits::default().apply().is_ok());
    }

    #[test]
    fn apply_cpu_limit_succeeds() {
        // Setting a generous CPU limit on the test process should succeed and
        // never trip during the test run. We only assert it doesn't error.
        let l = ResourceLimits {
            cpu_soft_secs: Some(3600),
            ..Default::default()
        };
        l.apply().expect("setrlimit(RLIMIT_CPU) should succeed");
    }

    #[test]
    fn configured_soft_and_hard_are_preserved_independently() {
        let inherited = Rlimit {
            current: None,
            maximum: None,
        };
        assert_eq!(
            merge_limit_pair(inherited, Some(300), Some(600)),
            Rlimit {
                current: Some(300),
                maximum: Some(600),
            }
        );
    }

    #[test]
    fn unspecified_limit_side_keeps_inherited_semantics() {
        let inherited = Rlimit {
            current: Some(400),
            maximum: Some(800),
        };
        assert_eq!(
            merge_limit_pair(inherited, Some(300), None),
            Rlimit {
                current: Some(300),
                maximum: Some(800),
            }
        );
        assert_eq!(
            merge_limit_pair(inherited, None, Some(350)),
            Rlimit {
                current: Some(350),
                maximum: Some(350),
            }
        );
    }
}
