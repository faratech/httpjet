//! The background writer task: owns the open file, appends lines, and performs
//! size-based rolling with optional gzip archiving and age-based pruning.
//!
//! All disk work happens here, off the request path. The task drains an
//! unbounded channel; the senders ([`crate::AccessLogger`] / [`crate::ErrorLogger`])
//! only ever do a non-blocking `send`.

use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use flate2::Compression;
use flate2::write::GzEncoder;
use tokio::fs::{self, File, OpenOptions};
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::mpsc;

use crate::Msg;
use crate::fmt;

/// Rolling/pruning policy for one log file.
#[derive(Debug, Clone)]
pub struct RollConfig {
    /// Live log file path.
    pub path: PathBuf,
    /// Roll once the file exceeds this size in bytes. `0` disables rolling.
    pub rolling_size: u64,
    /// Prune rolled files older than this many days. `0` disables pruning.
    pub keep_days: u64,
    /// gzip rolled files (`.gz` suffix) instead of leaving them plain.
    pub compress_archive: bool,
}

struct Writer {
    cfg: RollConfig,
    file: BufWriter<File>,
    /// Bytes written to the current file (tracked to avoid stat per line).
    size: u64,
}

impl Writer {
    async fn open(cfg: RollConfig) -> io::Result<Self> {
        if let Some(parent) = cfg.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).await?;
            }
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&cfg.path)
            .await?;
        let size = file.metadata().await.map(|m| m.len()).unwrap_or(0);
        Ok(Writer {
            cfg,
            file: BufWriter::new(file),
            size,
        })
    }

    async fn write_line(&mut self, line: &str) -> io::Result<()> {
        self.file.write_all(line.as_bytes()).await?;
        self.file.write_all(b"\n").await?;
        self.size += line.len() as u64 + 1;
        if self.cfg.rolling_size > 0 && self.size >= self.cfg.rolling_size {
            if let Err(e) = self.roll().await {
                // (#7) The roll's rename failed (logrotate moved the live path, a
                // cross-device or read-only log dir, ...). roll() leaves self.size
                // >= rolling_size on failure, so WITHOUT this every subsequent line
                // would re-attempt the failing roll — a per-line flush+stat+rename
                // syscall storm for the process lifetime. Recover by reopening the
                // live path (recreates it after a logrotate move), and reset size so
                // the threshold isn't re-tripped until another full rolling_size of
                // output accumulates regardless of why the roll failed.
                let _ = self.reopen().await;
                self.size = 0;
                return Err(e);
            }
        }
        Ok(())
    }

    /// Re-open the live path (used after the file was renamed away, e.g. by
    /// `logrotate`, or on an explicit [`Msg::Reopen`]).
    async fn reopen(&mut self) -> io::Result<()> {
        self.file.flush().await?;
        let next = Writer::open(self.cfg.clone()).await?;
        self.file = next.file;
        self.size = next.size;
        Ok(())
    }

    /// Rename the live file to a timestamped sibling, optionally gzip it, then
    /// open a fresh empty live file and prune old archives.
    async fn roll(&mut self) -> io::Result<()> {
        self.file.flush().await?;

        let rolled = unique_rolled_path(&self.cfg.path, SystemTime::now()).await;
        // Move the current file aside, then immediately reopen a fresh live file
        // so concurrent appenders (and our next line) hit the new file.
        fs::rename(&self.cfg.path, &rolled).await?;

        let fresh = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.cfg.path)
            .await?;
        self.file = BufWriter::new(fresh);
        self.size = 0;

        if self.cfg.compress_archive {
            // Compression is CPU/IO heavy; run it on a blocking thread so the
            // writer task stays responsive to the channel.
            let src = rolled.clone();
            tokio::task::spawn_blocking(move || gzip_file(&src))
                .await
                .map_err(|e| io::Error::other(e.to_string()))??;
        }

        if self.cfg.keep_days > 0 {
            let cfg = self.cfg.clone();
            // Pruning is best-effort; failures are logged, not fatal.
            if let Err(e) = prune_old(&cfg).await {
                tracing::warn!(target: "hj_log", error = %e, "log prune failed");
            }
        }
        Ok(())
    }

    async fn flush(&mut self) -> io::Result<()> {
        self.file.flush().await
    }
}

/// Build a rolled-file path `<stem>.<stamp><ext>` that does not yet exist,
/// disambiguating with a counter when several rolls land in the same second.
async fn unique_rolled_path(path: &Path, ts: SystemTime) -> PathBuf {
    let stamp = fmt::roll_stamp(ts);
    let base = format!("{}.{}", path.display(), stamp);
    let mut candidate = PathBuf::from(&base);
    let mut n = 0u32;
    loop {
        let plain = candidate.clone();
        let gz = with_gz(&candidate);
        let plain_exists = fs::metadata(&plain).await.is_ok();
        let gz_exists = fs::metadata(&gz).await.is_ok();
        if !plain_exists && !gz_exists {
            return candidate;
        }
        n += 1;
        candidate = PathBuf::from(format!("{}.{}", base, n));
    }
}

fn with_gz(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".gz");
    PathBuf::from(s)
}

/// gzip `src` to `src.gz` and remove the original. Synchronous (run on a
/// blocking thread by the caller).
fn gzip_file(src: &Path) -> io::Result<()> {
    use std::fs::File as StdFile;
    use std::io::copy;

    let dst = with_gz(src);
    let mut input = StdFile::open(src)?;
    let out = StdFile::create(&dst)?;
    let mut encoder = GzEncoder::new(out, Compression::default());
    copy(&mut input, &mut encoder)?;
    encoder.finish()?;
    std::fs::remove_file(src)?;
    Ok(())
}

/// Remove rolled files (siblings of the live path that start with
/// `<filename>.`) whose mtime is older than `keep_days`.
async fn prune_old(cfg: &RollConfig) -> io::Result<()> {
    let dir = match cfg.path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let live_name = match cfg.path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n.to_string(),
        None => return Ok(()),
    };
    let prefix = format!("{}.", live_name);
    let cutoff = SystemTime::now() - Duration::from_secs(cfg.keep_days * 86_400);

    let mut entries = fs::read_dir(&dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name();
        let name = match name.to_str() {
            Some(n) => n,
            None => continue,
        };
        // Only touch our own rolled archives, never the live file itself.
        if name == live_name || !name.starts_with(&prefix) {
            continue;
        }
        let meta = match entry.metadata().await {
            Ok(m) => m,
            Err(_) => continue,
        };
        if !meta.is_file() {
            continue;
        }
        let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        if modified < cutoff {
            let _ = fs::remove_file(entry.path()).await;
        }
    }
    Ok(())
}

/// Drain `rx` until all senders drop or a [`Msg::Shutdown`] arrives.
///
/// If the file cannot be opened initially we still consume the channel (logging
/// must never wedge the request path); lines are dropped and the failure is
/// reported via `tracing`.
pub async fn run(cfg: RollConfig, mut rx: mpsc::UnboundedReceiver<Msg>, state: crate::LoggerState) {
    let depth = &state.depth;
    let mut writer = match Writer::open(cfg.clone()).await {
        Ok(w) => Some(w),
        Err(e) => {
            tracing::error!(target: "hj_log", path = %cfg.path.display(), error = %e, "failed to open log file");
            None
        }
    };
    // Rate-limit the write-failure log: a full/erroring disk would otherwise emit
    // one `tracing::error!` per dropped line. Those are `target:"hj_log"`, so the
    // ErrorLogLayer drops them from the error file (recursion guard) — but they
    // still reach stdout via the fmt layer, which would flood. Cap to 1 per 5 s.
    let mut last_write_err: Option<std::time::Instant> = None;

    while let Some(first) = rx.recv().await {
        // Process this message plus any already-queued ones (a burst), then
        // flush ONCE. This keeps the per-line durability of a flush-after-write
        // without paying a write/flush syscall per request under load — the
        // BufWriter coalesces the burst into one write.
        let mut wrote_line = false;
        let mut msg = Some(first);
        loop {
            // Resolve the message to an optional line to write. Both line-bearing
            // variants ((pre-rendered) `Line` and `Record`, rendered here on the
            // writer task so the request path never pays for it) uncount the queue
            // depth (#8) and then share the single write path below.
            let to_write: Option<String> = match msg.take() {
                Some(Msg::Line(line)) => {
                    depth.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    Some(line)
                }
                Some(Msg::Record(record, format)) => {
                    depth.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    Some(record.render(format))
                }
                Some(Msg::Reopen) => {
                    if let Some(w) = writer.as_mut() {
                        if let Err(e) = w.reopen().await {
                            tracing::error!(target: "hj_log", error = %e, "log reopen failed");
                        }
                    } else {
                        let opened = Writer::open(cfg.clone()).await;
                        if let Ok(w) = opened {
                            writer = Some(w);
                        }
                    }
                    None
                }
                Some(Msg::Shutdown(ack)) => {
                    if let Some(w) = writer.as_mut() {
                        let _ = w.flush().await;
                    }
                    let _ = ack.send(());
                    return;
                }
                None => None,
            };
            if let Some(line) = to_write {
                if let Some(w) = writer.as_mut() {
                    match w.write_line(&line).await {
                        Ok(()) => wrote_line = true,
                        Err(e) => {
                            let now = std::time::Instant::now();
                            if last_write_err.is_none_or(|t| {
                                now.duration_since(t) >= std::time::Duration::from_secs(5)
                            }) {
                                tracing::error!(target: "hj_log", error = %e, "log write failed (rate-limited to 1/5s)");
                                last_write_err = Some(now);
                            }
                            // A write error may leave a partial line buffered in
                            // the BufWriter; reopen so the next write starts on a
                            // clean line and does not append after corrupt output.
                            let reopen_cfg = w.cfg.clone();
                            if let Ok(fresh) = Writer::open(reopen_cfg).await {
                                *w = fresh;
                            }
                        }
                    }
                }
            }
            // Drain any messages already waiting; stop when the queue is empty.
            match rx.try_recv() {
                Ok(m) => msg = Some(m),
                Err(_) => break,
            }
        }
        if wrote_line {
            if let Some(w) = writer.as_mut() {
                let _ = w.flush().await;
            }
        }
    }

    // All senders dropped: flush whatever is buffered before exiting.
    if let Some(w) = writer.as_mut() {
        let _ = w.flush().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64};
    use tokio::sync::oneshot;

    /// Build a temp dir under the OS temp root (no extra deps), unique per test.
    fn temp_dir(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let uniq = format!(
            "hj-log-{}-{}-{}",
            tag,
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        p.push(uniq);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    async fn send_line(tx: &mpsc::UnboundedSender<Msg>, s: &str) {
        tx.send(Msg::Line(s.to_string())).unwrap();
    }

    fn logger_state() -> crate::LoggerState {
        Arc::new(crate::LoggerStateInner {
            depth: AtomicU64::new(0),
            gone: AtomicBool::new(false),
            dropped: AtomicU64::new(0),
        })
    }

    async fn shutdown(tx: &mpsc::UnboundedSender<Msg>) {
        let (a, b) = oneshot::channel();
        tx.send(Msg::Shutdown(a)).unwrap();
        b.await.unwrap();
    }

    #[tokio::test]
    async fn writes_lines() {
        let dir = temp_dir("write");
        let path = dir.join("access.log");
        let cfg = RollConfig {
            path: path.clone(),
            rolling_size: 0,
            keep_days: 0,
            compress_archive: false,
        };
        let (tx, rx) = mpsc::unbounded_channel();
        let h = tokio::spawn(run(cfg, rx, logger_state()));

        send_line(&tx, "line one").await;
        send_line(&tx, "line two").await;
        shutdown(&tx).await;
        h.await.unwrap();

        let body = std::fs::read_to_string(&path).unwrap();
        assert_eq!(body, "line one\nline two\n");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn renders_record_on_writer_task() {
        use crate::{AccessRecord, LogFormat};
        use std::time::{Duration, UNIX_EPOCH};

        let dir = temp_dir("record");
        let path = dir.join("access.log");
        let cfg = RollConfig {
            path: path.clone(),
            rolling_size: 0,
            keep_days: 0,
            compress_archive: false,
        };
        let (tx, rx) = mpsc::unbounded_channel();
        let h = tokio::spawn(run(cfg, rx, logger_state()));

        let record = AccessRecord {
            client_ip: "203.0.113.7".parse().unwrap(),
            ts: UNIX_EPOCH + Duration::from_secs(971_186_136), // 2000-10-10T13:55:36Z
            method: "GET".into(),
            uri: "/index.html?x=1".into(),
            protocol: "HTTP/2".into(),
            status: 200,
            bytes: 2326,
            referer: Some("https://example.com/start".into()),
            user_agent: Some("Mozilla/5.0".into()),
            host: Some("example.com".into()),
            remote_user: None,
            request_id: None,
        };
        // The line is rendered by the writer task from the structured record.
        tx.send(Msg::Record(Box::new(record), LogFormat::Combined))
            .unwrap();
        shutdown(&tx).await;
        h.await.unwrap();

        let body = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            body,
            "203.0.113.7 - - [10/Oct/2000:13:55:36 +0000] \"GET /index.html?x=1 HTTP/2\" 200 2326 \"https://example.com/start\" \"Mozilla/5.0\"\n"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn rolls_and_gzips_when_size_exceeded() {
        let dir = temp_dir("roll");
        let path = dir.join("access.log");
        let cfg = RollConfig {
            path: path.clone(),
            rolling_size: 32, // tiny: roll quickly
            keep_days: 0,
            compress_archive: true,
        };
        let (tx, rx) = mpsc::unbounded_channel();
        let h = tokio::spawn(run(cfg, rx, logger_state()));

        // Each line is ~20 bytes; a few lines blow past 32 and force a roll.
        for i in 0..10 {
            send_line(&tx, &format!("event number {:04}", i)).await;
        }
        shutdown(&tx).await;
        h.await.unwrap();

        // A rolled .gz archive must exist alongside the live file.
        let mut gz_count = 0;
        let mut live_exists = false;
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().into_string().unwrap();
            if name == "access.log" {
                live_exists = true;
            } else if name.starts_with("access.log.") && name.ends_with(".gz") {
                gz_count += 1;
            }
        }
        assert!(live_exists, "live log should be reopened after roll");
        assert!(
            gz_count >= 1,
            "expected at least one rolled .gz, found {gz_count}"
        );

        // Verify the gz decompresses to readable content.
        let gz_path = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .find(|p| p.extension().map(|x| x == "gz").unwrap_or(false))
            .unwrap();
        let raw = std::fs::read(&gz_path).unwrap();
        let mut dec = flate2::read::GzDecoder::new(&raw[..]);
        let mut text = String::new();
        std::io::Read::read_to_string(&mut dec, &mut text).unwrap();
        assert!(text.contains("event number"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn prunes_old_archives() {
        let dir = temp_dir("prune");
        let path = dir.join("access.log");

        // Plant an "old" archive and a "fresh" one.
        let old = dir.join("access.log.1999_01_01_000000");
        let fresh = dir.join("access.log.2999_01_01_000000");
        std::fs::write(&old, b"old").unwrap();
        std::fs::write(&fresh, b"fresh").unwrap();
        // Backdate the old file's mtime to ~100 days ago.
        let hundred_days_ago = SystemTime::now() - Duration::from_secs(100 * 86_400);
        filetime_set(&old, hundred_days_ago);

        let cfg = RollConfig {
            path: path.clone(),
            rolling_size: 0,
            keep_days: 30,
            compress_archive: false,
        };
        prune_old(&cfg).await.unwrap();

        assert!(!old.exists(), "old archive should be pruned");
        assert!(fresh.exists(), "recent archive should be kept");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn reopen_creates_new_file_after_external_rename() {
        let dir = temp_dir("reopen");
        let path = dir.join("error.log");
        let cfg = RollConfig {
            path: path.clone(),
            rolling_size: 0,
            keep_days: 0,
            compress_archive: false,
        };
        let (tx, rx) = mpsc::unbounded_channel();
        let h = tokio::spawn(run(cfg, rx, logger_state()));

        send_line(&tx, "before").await;
        // Simulate logrotate moving the live file aside.
        // Give the writer a moment to actually create+write the file.
        for _ in 0..50 {
            if path.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        let moved = dir.join("error.log.rotated");
        std::fs::rename(&path, &moved).unwrap();

        tx.send(Msg::Reopen).unwrap();
        send_line(&tx, "after").await;
        shutdown(&tx).await;
        h.await.unwrap();

        let live = std::fs::read_to_string(&path).unwrap();
        assert!(
            live.contains("after"),
            "post-reopen line should be in new file"
        );
        let rotated = std::fs::read_to_string(&moved).unwrap();
        assert!(
            rotated.contains("before"),
            "pre-reopen line stays in rotated file"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Set a file's mtime using libc's `utimensat` via std — but std has no such
    /// API, so use a tiny portable shim through `filetime`-free approach: open,
    /// then use SystemTime through `set_modified` (stable since Rust 1.75).
    fn filetime_set(path: &Path, t: SystemTime) {
        let f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        f.set_modified(t).unwrap();
    }
}
