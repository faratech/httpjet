//! tmpfs-file persistence for the page store (`--page-cache-store-path`, e.g.
//! `/dev/shm/jetcache`) — the same method LiteSpeed Enterprise uses for
//! `/dev/shm/lscache`, clean-room.
//!
//! One **immutable file per body version**: a re-store writes a NEW file (unique
//! `-<seq>` suffix) and the predecessor is unlinked, so a published file's bytes
//! can never change under a reader — an in-flight hit either reads exactly the
//! bytes its resident metadata describes or gets a clean `Err` (fail-closed
//! miss). Publish is `.tmp` + `rename` (atomic on one
//! filesystem); no fsync — tmpfs has no durability to buy, and the cache is
//! disposable on a host reboot anyway.
//!
//! Each file is fully self-describing (versioned header + the complete key +
//! tags + response headers + body), so a boot-time scan can rebuild the in-RAM
//! index from nothing — that is what makes the cache survive
//! `systemctl restart httpjet`.
//!
//! Layout: `root/<h0>/<h1>/<h2>/<16-hex-fnv64>-<seq>.pc` — three single-hex-char
//! levels (4096 leaf dirs, ~35 files/dir at prod's ~140K entries), LSWS-style.
//! Correctness never depends on the filename: the real key is parsed from the
//! meta block (the index is exact-Eq) and the filename is only a locator.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::{HeaderName, HeaderValue};
use parking_lot::Mutex;

use crate::key::PageCacheKey;
use crate::store::{CachedResponse, FileId, PageScope};

const MAGIC: [u8; 4] = *b"HJPC";
const VERSION: u16 = 2;
/// Boot-scan walker thread cap: tmpfs metadata reads parallelize well but the
/// win flattens past a few cores, and prod boxes share cores with live serving.
const SCAN_MAX_THREADS: usize = 8;
/// Fixed header: magic, version, flags, meta_len, body_len, status, reserved,
/// dict_gen, stored_unix_ms, ttl_ms, swr_ms, sie_ms, private_owner.
/// ALL containers (page AND static) carry an 80-byte header: the historical 64
/// bytes PLUS a 16-byte integrity tag (security #260): HMAC-SHA256(key,
/// header-fields || meta), truncated. The tag authenticates the identity-bearing
/// metadata so a same-uid writer cannot forge or relocate entries; body bytes are
/// bound by the authenticated lengths plus the serve-time identity guard. A
/// UNIFORM layout keeps every reader/writer/streaming-offset on one constant.
const HEADER_LEN: u64 = 80;
const TAG_LEN: usize = 16;
const FLAG_PRIVATE: u16 = 1 << 0;
const FLAG_STATIC: u16 = 1 << 1;
/// Parse-time sanity bounds (the real caps are the store's max_obj_bytes; these
/// only stop a corrupt length prefix from driving a huge allocation).
const MAX_META_LEN: u32 = 4 << 20;
const MAX_BODY_LEN: u32 = 256 << 20;
const STAMP_NAME: &str = ".purge_all_stamp";
const TAG_STAMP_NAME: &str = ".tag_purge_stamps";
pub(crate) const TAG_PURGE_FLOOR_RECORD_BYTES: u64 = 19;
pub(crate) const TAG_PURGE_STAMP_RECORD_BYTES: u64 = 36;

/// Why a file was rejected.
#[derive(Debug)]
pub enum ReadError {
    Io(io::Error),
    /// Failed validation (bad magic/version/lengths/encoding) — unlink it.
    Corrupt(&'static str),
}

impl From<io::Error> for ReadError {
    fn from(e: io::Error) -> Self {
        ReadError::Io(e)
    }
}

/// Everything `read_meta` recovers from a file — the caller (the store's boot
/// scan) decides keep-vs-unlink and rebuilds `PageCacheKey`/`CachedResponse`.
/// `variants` are deliberately not persisted: they exist only for hit-proven
/// entries and the PC2-lazy fill recreates them on the first post-restart hit.
pub struct ScannedEntry {
    pub key: PageCacheKey,
    pub status: u16,
    pub identity: String,
    pub headers: Vec<(HeaderName, HeaderValue)>,
    pub dict_gen: u32,
    pub tags: Vec<Arc<str>>,
    pub vary_cookie_name: String,
    pub vary_value: String,
    pub scope: PageScope,
    pub stored_unix_ms: u64,
    pub ttl: Duration,
    pub swr: Duration,
    pub sie: Duration,
    pub body_len: u32,
    pub meta_len: u32,
    pub disk_total: u32,
    pub version_seq: u64,
    pub path: PathBuf,
}

pub struct ScannedStaticEntry {
    pub vhost_id: u32,
    pub cache_path: String,
    pub source_path: PathBuf,
    pub file_id: FileId,
    pub content_type: Arc<str>,
    pub etag: String,
    pub last_modified: String,
    pub body_len: u32,
    pub meta_len: u32,
    pub disk_total: u32,
    pub path: PathBuf,
}

#[derive(Default)]
pub(crate) struct TagPurgeState {
    pub floor_ms: u64,
    pub stamps: HashMap<u64, u64>,
    pub record_count: u64,
    pub stamp_record_count: u64,
    pub byte_len: u64,
    pub corrupt: bool,
    /// One floor record plus one record per retained exact stamp, with no
    /// duplicates or already-subsumed stamps. Record order is immaterial.
    pub canonical: bool,
}

#[derive(Debug)]
pub struct StoredBodyFile {
    pub path: PathBuf,
    pub file: fs::File,
    pub file_len: u64,
    pub body_start: u64,
    pub body_len: u32,
}

pub(crate) struct PreparedEntry {
    tmp_path: PathBuf,
    dir: PathBuf,
    hex: String,
    first_seq: u64,
    logical_total: u64,
}

impl Drop for PreparedEntry {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.tmp_path);
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ScanSummary {
    pub loaded: u64,
    pub rejected: u64,
    pub corrupt_removed: u64,
    pub tmp_removed: u64,
}

pub struct DiskStore {
    root: PathBuf,
    /// Final files published by this process while its boot scan is pending. Publication
    /// and scan membership checks share this mutex, so the scanner can never mistake a
    /// just-linked live file for inherited state and reject/unlink it.
    live_files: Mutex<HashSet<PathBuf>>,
    boot_scan_pending: AtomicBool,
    /// Uniquifies the per-version filename. Re-seeded to max(seen)+1 by `scan`
    /// so a restart can never reuse a live file's name.
    seq: AtomicU64,
}

impl DiskStore {
    /// Open (creating if needed) the store root. Cheap — the leaf fanout is
    /// created on demand by writes and the boot scan handles `.tmp` cleanup.
    pub fn open(root: &Path) -> io::Result<DiskStore> {
        fs::create_dir_all(root)?;
        // Seed the per-version filename counter PAST any prior run's ids, so a store that races
        // the concurrent boot warm-scan window can't reuse — and `rename`-clobber — a persisted
        // file left by a previous process (the counter used to restart at 1 each boot and was
        // only reseeded at the END of the seconds-long scan, while serving begins immediately).
        // A wall-clock nanosecond base is monotonic across restarts (a process cannot emit >1e9
        // versions/sec), so a new run's `-<seq>` suffixes never alias an old run's; the scan still
        // fetch_max()es past the on-disk max as a backstop, and `write_entry` additionally refuses
        // to overwrite an existing file. Falls back to 1 only if the clock predates the epoch.
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(1)
            .max(1);
        Ok(DiskStore {
            root: root.to_path_buf(),
            live_files: Mutex::new(HashSet::new()),
            boot_scan_pending: AtomicBool::new(true),
            seq: AtomicU64::new(seed),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Persist one entry (metadata from `entry`/`key`, the stored-form body and
    /// its `dict_gen` passed explicitly — the caller may have just compressed
    /// it). Returns the published path. `.tmp` is cleaned up on any error.
    pub fn write_entry(
        &self,
        key: &PageCacheKey,
        entry: &CachedResponse,
        dict_gen: u32,
        body: &[u8],
        stored_unix_ms: u64,
    ) -> io::Result<(PathBuf, u32)> {
        let prepared = self.prepare_entry(key, entry, dict_gen, body, stored_unix_ms)?;
        self.publish_entry(prepared)
    }

    /// Write an entry's complete container under a temporary name without
    /// publishing a boot-scannable final file. The page store uses this split
    /// form so its final purge check and tag membership are established before
    /// publication.
    pub(crate) fn prepare_entry(
        &self,
        key: &PageCacheKey,
        entry: &CachedResponse,
        dict_gen: u32,
        body: &[u8],
        stored_unix_ms: u64,
    ) -> io::Result<PreparedEntry> {
        if body.len() as u64 > MAX_BODY_LEN as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "body over format bound",
            ));
        }
        let meta = encode_meta(key, entry)?;

        let hash = key_hash(key);
        let hex = format!("{hash:016x}");
        let dir = self.root.join(&hex[0..1]).join(&hex[1..2]).join(&hex[2..3]);
        fs::create_dir_all(&dir)?;
        let first_seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let tmp_path = dir.join(format!("{hex}-{first_seq}.pc.tmp"));

        let mut header = [0u8; HEADER_LEN as usize];
        header[0..4].copy_from_slice(&MAGIC);
        header[4..6].copy_from_slice(&VERSION.to_le_bytes());
        let flags = match entry.scope {
            PageScope::Public => 0u16,
            PageScope::Private { .. } => FLAG_PRIVATE,
        };
        header[6..8].copy_from_slice(&flags.to_le_bytes());
        header[8..12].copy_from_slice(&(meta.len() as u32).to_le_bytes());
        header[12..16].copy_from_slice(&(body.len() as u32).to_le_bytes());
        header[16..18].copy_from_slice(&entry.status.to_le_bytes());
        // 18..20 reserved = 0
        header[20..24].copy_from_slice(&dict_gen.to_le_bytes());
        header[24..32].copy_from_slice(&stored_unix_ms.to_le_bytes());
        header[32..40].copy_from_slice(&ms_u64(entry.ttl).to_le_bytes());
        header[40..48].copy_from_slice(&ms_u64(entry.swr).to_le_bytes());
        header[48..56].copy_from_slice(&ms_u64(entry.sie).to_le_bytes());
        header[56..64].copy_from_slice(&key.private_owner.to_le_bytes());
        // (security #260) Integrity tag over the identity-bearing fields + meta.
        let tag = integrity_tag(&header[..64], &meta);
        header[64..80].copy_from_slice(&tag);

        let write = (|| -> io::Result<()> {
            let mut f = fs::File::create(&tmp_path)?;
            f.write_all(&header)?;
            f.write_all(&meta)?;
            f.write_all(body)?;
            Ok(())
        })();
        if let Err(e) = write {
            let _ = fs::remove_file(&tmp_path);
            return Err(e);
        }
        let logical_total = HEADER_LEN + meta.len() as u64 + body.len() as u64;
        Ok(PreparedEntry {
            tmp_path,
            dir,
            hex,
            first_seq,
            logical_total,
        })
    }

    /// Atomically publish a prepared entry. A dropped/unpublished preparation
    /// removes only its private temp file.
    pub(crate) fn publish_entry(&self, prepared: PreparedEntry) -> io::Result<(PathBuf, u32)> {
        // Publish by HARD-LINKING the tmp into its final name, which FAILS if that name already
        // exists — so a published version file is never silently overwritten (the warm-window bug;
        // plain `rename` clobbers). Then drop the tmp name. `seq` is seeded past any prior run at
        // open(), so a collision (hence a retry) is effectively never hit; the loop is a backstop.
        let mut seq = prepared.first_seq;
        loop {
            let final_path = prepared.dir.join(format!("{}-{seq}.pc", prepared.hex));
            let mut live_files = self.live_files.lock();
            match fs::hard_link(&prepared.tmp_path, &final_path) {
                Ok(()) => {
                    let disk_total = match allocated_file_bytes(&final_path, prepared.logical_total)
                    {
                        Ok(n) => n,
                        Err(e) => {
                            let _ = fs::remove_file(&final_path);
                            return Err(e);
                        }
                    };
                    if self.boot_scan_pending.load(Ordering::Acquire) {
                        live_files.insert(final_path.clone());
                    }
                    drop(live_files);
                    let _ = fs::remove_file(&prepared.tmp_path);
                    return Ok((final_path, disk_total));
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    seq = self.seq.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Adopt a PEER-FETCHED entry: persist its already-encoded HJPC bytes verbatim
    /// under a filename derived from `key_hash` (the cross-node-deterministic hash).
    /// The container shape is validated so a corrupt/garbage transfer can never be
    /// published; the caller then `read_meta()`s the published file and indexes it
    /// via the same path the boot scan uses. Mirrors `write_entry`'s tmp+hard-link
    /// publish (no silent overwrite) but takes pre-encoded bytes.
    pub fn write_raw(&self, key_hash: u64, bytes: &[u8]) -> io::Result<(PathBuf, u32)> {
        let prepared = self.prepare_raw(key_hash, bytes)?;
        self.publish_entry(prepared)
    }

    pub(crate) fn prepare_raw(&self, key_hash: u64, bytes: &[u8]) -> io::Result<PreparedEntry> {
        let corrupt = |m: &'static str| io::Error::new(io::ErrorKind::InvalidData, m);
        if (bytes.len() as u64) < HEADER_LEN {
            return Err(corrupt("short HJPC blob"));
        }
        if bytes[0..4] != MAGIC {
            return Err(corrupt("bad HJPC magic"));
        }
        if u16::from_le_bytes([bytes[4], bytes[5]]) != VERSION {
            return Err(corrupt("HJPC version mismatch"));
        }
        let flags = u16::from_le_bytes([bytes[6], bytes[7]]);
        if flags & FLAG_STATIC != 0 {
            return Err(corrupt("static record is not page-adoptable"));
        }
        let meta_len = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let body_len = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        if meta_len > MAX_META_LEN || body_len > MAX_BODY_LEN {
            return Err(corrupt("HJPC length over bound"));
        }
        if HEADER_LEN + meta_len as u64 + body_len as u64 != bytes.len() as u64 {
            return Err(corrupt("HJPC length mismatch"));
        }
        // (security #260) Adopted blobs must carry a valid integrity tag over their
        // identity-bearing header fields + meta.
        if !verify_integrity(
            &bytes[64..80],
            &bytes[..64],
            &bytes[HEADER_LEN as usize..HEADER_LEN as usize + meta_len as usize],
        ) {
            return Err(corrupt("HJPC integrity tag mismatch"));
        }

        let hex = format!("{key_hash:016x}");
        let dir = self.root.join(&hex[0..1]).join(&hex[1..2]).join(&hex[2..3]);
        fs::create_dir_all(&dir)?;
        let first_seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let tmp_path = dir.join(format!("{hex}-{first_seq}.pc.tmp"));
        if let Err(e) = (|| -> io::Result<()> {
            let mut f = fs::File::create(&tmp_path)?;
            f.write_all(bytes)?;
            Ok(())
        })() {
            let _ = fs::remove_file(&tmp_path);
            return Err(e);
        }
        Ok(PreparedEntry {
            tmp_path,
            dir,
            hex,
            first_seq,
            logical_total: bytes.len() as u64,
        })
    }

    pub(crate) fn read_prepared_entry(
        &self,
        prepared: &PreparedEntry,
    ) -> Result<ScannedEntry, ReadError> {
        read_meta(&prepared.tmp_path)
    }

    /// Persist one static-file cache entry. Static records use the same immutable
    /// HJPC container and body reader, but carry static metadata and a `.sc`
    /// extension so the page boot scan never treats them as LSCache pages.
    pub fn write_static_entry(
        &self,
        vhost_id: u32,
        cache_path: &str,
        source_path: &Path,
        file_id: FileId,
        content_type: &str,
        etag: &str,
        last_modified: &str,
        body: &[u8],
    ) -> io::Result<(PathBuf, u32)> {
        if body.len() as u64 > MAX_BODY_LEN as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "body over format bound",
            ));
        }
        let meta = encode_static_meta(
            vhost_id,
            cache_path,
            source_path,
            file_id,
            content_type,
            etag,
            last_modified,
        )?;

        let hash = static_key_hash(vhost_id, cache_path);
        let hex = format!("{hash:016x}");
        let dir = self.root.join(&hex[0..1]).join(&hex[1..2]).join(&hex[2..3]);
        fs::create_dir_all(&dir)?;
        let first_seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let tmp_path = dir.join(format!("{hex}-{first_seq}.sc.tmp"));

        let mut header = [0u8; HEADER_LEN as usize];
        header[0..4].copy_from_slice(&MAGIC);
        header[4..6].copy_from_slice(&VERSION.to_le_bytes());
        header[6..8].copy_from_slice(&FLAG_STATIC.to_le_bytes());
        header[8..12].copy_from_slice(&(meta.len() as u32).to_le_bytes());
        header[12..16].copy_from_slice(&(body.len() as u32).to_le_bytes());
        // (security #260) Same integrity treatment + uniform tag slot as pages.
        let tag = integrity_tag(&header[..64], &meta);
        header[64..80].copy_from_slice(&tag);

        let write = (|| -> io::Result<()> {
            let mut f = fs::File::create(&tmp_path)?;
            f.write_all(&header)?;
            f.write_all(&meta)?;
            f.write_all(body)?;
            Ok(())
        })();
        if let Err(e) = write {
            let _ = fs::remove_file(&tmp_path);
            return Err(e);
        }

        let logical_total = HEADER_LEN + meta.len() as u64 + body.len() as u64;
        let mut seq = first_seq;
        loop {
            let final_path = dir.join(format!("{hex}-{seq}.sc"));
            let mut live_files = self.live_files.lock();
            match fs::hard_link(&tmp_path, &final_path) {
                Ok(()) => {
                    let disk_total = match allocated_file_bytes(&final_path, logical_total) {
                        Ok(n) => n,
                        Err(e) => {
                            let _ = fs::remove_file(&final_path);
                            let _ = fs::remove_file(&tmp_path);
                            return Err(e);
                        }
                    };
                    if self.boot_scan_pending.load(Ordering::Acquire) {
                        live_files.insert(final_path.clone());
                    }
                    drop(live_files);
                    let _ = fs::remove_file(&tmp_path);
                    return Ok((final_path, disk_total));
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    seq = self.seq.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => {
                    let _ = fs::remove_file(&tmp_path);
                    return Err(e);
                }
            }
        }
    }

    /// Read the body bytes back. Re-validates the header (magic/version/length
    /// invariant) so a truncated, replaced, or foreign file yields an error —
    /// never partial bytes. `expected_len` is the length the index recorded at
    /// persist time; any disagreement is corruption.
    pub fn read_body(path: &Path, expected_len: u32) -> Result<Bytes, ReadError> {
        let mut f = fs::File::open(path)?;
        let file_len = f.metadata()?.len();
        let mut header = [0u8; HEADER_LEN as usize];
        f.read_exact(&mut header)?;
        let (meta_len, body_len) = validate_header(&header, HEADER_LEN, file_len)?;
        if body_len != expected_len {
            return Err(ReadError::Corrupt("body length disagrees with index"));
        }
        f.seek(SeekFrom::Start(HEADER_LEN + meta_len as u64))?;
        let mut body = vec![0u8; body_len as usize];
        f.read_exact(&mut body)?;
        Ok(Bytes::from(body))
    }

    /// Resolve the immutable cache file and byte range that contains the body
    /// without allocating or reading the body itself. The transport can stream
    /// this range directly from tmpfs, matching the same header validation used
    /// by [`read_body`].
    pub fn body_file(path: &Path, expected_len: u32) -> Result<StoredBodyFile, ReadError> {
        let mut f = fs::File::open(path)?;
        let file_len = f.metadata()?.len();
        let mut header = [0u8; HEADER_LEN as usize];
        f.read_exact(&mut header)?;
        let (meta_len, body_len) = validate_header(&header, HEADER_LEN, file_len)?;
        if body_len != expected_len {
            return Err(ReadError::Corrupt("body length disagrees with index"));
        }
        Ok(StoredBodyFile {
            path: path.to_path_buf(),
            file: f,
            file_len,
            body_start: HEADER_LEN + meta_len as u64,
            body_len,
        })
    }

    /// Walk the fanout and yield every parseable entry to `keep`; a `false`
    /// return (or any validation failure) unlinks the file. Also removes stray
    /// `.tmp` files and re-seeds the filename sequence past everything seen.
    /// The walk fans out across scoped threads (one work unit per second-level
    /// fanout dir), so `keep` runs concurrently and observes entries in no
    /// particular order — safe because same-key duplicate resolution in the
    /// index compares stored version stamps, never arrival order.
    pub fn scan(&self, keep: impl Fn(ScannedEntry) -> bool + Send + Sync) -> ScanSummary {
        let scan_start = SystemTime::now();
        self.walk_parallel(|file, sum, max_seq| {
            let name = file.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.ends_with(".tmp") {
                // Only reap crash debris (mtime before this scan began); a
                // newer `.tmp` may be an in-flight `write_entry` whose hard_link
                // hasn't landed yet — unlinking it would ENOENT that write.
                if !modified_at_or_after(file, scan_start) {
                    let _ = fs::remove_file(file);
                    sum.tmp_removed += 1;
                }
                return;
            }
            if !name.ends_with(".pc") {
                return;
            }
            if self.live_files.lock().contains(file) {
                return;
            }
            if let Some(seq) = parse_seq(name) {
                *max_seq = (*max_seq).max(seq.saturating_add(1));
            }
            match read_meta(file) {
                Ok(entry) => {
                    if keep(entry) {
                        sum.loaded += 1;
                    } else {
                        let _ = fs::remove_file(file);
                        sum.rejected += 1;
                    }
                }
                Err(_) => {
                    let _ = fs::remove_file(file);
                    sum.corrupt_removed += 1;
                }
            }
        })
    }

    pub fn scan_static(
        &self,
        keep: impl Fn(ScannedStaticEntry) -> bool + Send + Sync,
    ) -> ScanSummary {
        let scan_start = SystemTime::now();
        self.walk_parallel(|file, sum, max_seq| {
            let name = file.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.ends_with(".sc.tmp") {
                // See `scan`: spare in-flight writes, reap only crash debris.
                if !modified_at_or_after(file, scan_start) {
                    let _ = fs::remove_file(file);
                    sum.tmp_removed += 1;
                }
                return;
            }
            if !name.ends_with(".sc") {
                return;
            }
            if self.live_files.lock().contains(file) {
                return;
            }
            if let Some(seq) = parse_seq_ext(name, ".sc") {
                *max_seq = (*max_seq).max(seq.saturating_add(1));
            }
            match read_static_meta(file) {
                Ok(entry) => {
                    if keep(entry) {
                        sum.loaded += 1;
                    } else {
                        let _ = fs::remove_file(file);
                        sum.rejected += 1;
                    }
                }
                Err(_) => {
                    let _ = fs::remove_file(file);
                    sum.corrupt_removed += 1;
                }
            }
        })
    }

    /// Shared boot-scan driver: enumerate the (up to 256) second-level fanout
    /// dirs as work units and drain them from a shared cursor across scoped
    /// threads. Each thread accumulates a private `ScanSummary` + max-seq
    /// (merged at the end), so `per_file` needs no shared mutable state.
    fn walk_parallel(
        &self,
        per_file: impl Fn(&Path, &mut ScanSummary, &mut u64) + Send + Sync,
    ) -> ScanSummary {
        let mut units: Vec<PathBuf> = Vec::new();
        for d0 in read_dir_sorted(&self.root) {
            if d0.is_dir() {
                // (non-dirs at the root: the purge stamp — never a work unit)
                units.extend(read_dir_sorted(&d0).into_iter().filter(|p| p.is_dir()));
            }
        }
        let walk_unit = |unit: &Path, sum: &mut ScanSummary, max_seq: &mut u64| {
            for d2 in read_dir_sorted(unit) {
                for file in read_dir_sorted(&d2) {
                    per_file(&file, sum, max_seq);
                }
            }
        };
        let mut sum = ScanSummary::default();
        let mut max_seq = self.seq.load(Ordering::Relaxed);
        let threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .min(SCAN_MAX_THREADS)
            .min(units.len().max(1));
        if threads <= 1 {
            for unit in &units {
                walk_unit(unit, &mut sum, &mut max_seq);
            }
        } else {
            let next = std::sync::atomic::AtomicUsize::new(0);
            std::thread::scope(|s| {
                let workers: Vec<_> = (0..threads)
                    .map(|_| {
                        s.spawn(|| {
                            let mut sum = ScanSummary::default();
                            let mut max_seq = 0u64;
                            loop {
                                let i = next.fetch_add(1, Ordering::Relaxed);
                                let Some(unit) = units.get(i) else { break };
                                walk_unit(unit, &mut sum, &mut max_seq);
                            }
                            (sum, max_seq)
                        })
                    })
                    .collect();
                for w in workers {
                    // A panicked walker propagates: the boot scan has no partial-result
                    // semantics (failing loudly beats silently under-loading the index).
                    let (s, m) = w.join().expect("boot-scan walker panicked");
                    sum.loaded += s.loaded;
                    sum.rejected += s.rejected;
                    sum.corrupt_removed += s.corrupt_removed;
                    sum.tmp_removed += s.tmp_removed;
                    max_seq = max_seq.max(m);
                }
            });
        }
        self.seq.fetch_max(max_seq, Ordering::Relaxed);
        sum
    }

    /// Drop the transient current-process publication set after both boot scans finish.
    /// No scanner runs again in this process, so later writes need no tracking.
    pub fn finish_boot_scan(&self) {
        let mut live_files = self.live_files.lock();
        self.boot_scan_pending.store(false, Ordering::Release);
        live_files.clear();
    }

    /// Unlink published versions of `key` through `max_version_seq`. A newer
    /// final file may belong to a render that started after the purge epoch and
    /// has not acquired the index shard yet, so it must survive. In-flight temp
    /// files are likewise owned by their writers; rejected writers clean them,
    /// while a crash leaves debris for the next boot scan.
    pub fn remove_key_versions_through(&self, key: &PageCacheKey, max_version_seq: u64) {
        let hash = key_hash(key);
        let hex = format!("{hash:016x}");
        let dir = self.root.join(&hex[0..1]).join(&hex[1..2]).join(&hex[2..3]);
        let prefix = format!("{hex}-");
        for file in read_dir_sorted(&dir) {
            let Some(name) = file.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !name.starts_with(&prefix) {
                continue;
            }
            if name.ends_with(".pc")
                && read_meta(&file).is_ok_and(|e| &e.key == key && e.version_seq <= max_version_seq)
            {
                Self::remove(&file);
            }
        }
    }

    /// Record a durable `purge_all` watermark: entries stored at-or-before this
    /// wall time must never be loaded by a later boot scan.
    pub fn write_purge_stamp(&self, wall_ms: u64) -> io::Result<()> {
        let tmp = self.root.join(format!("{STAMP_NAME}.tmp"));
        let fin = self.root.join(STAMP_NAME);
        fs::write(&tmp, wall_ms.to_string())?;
        fs::rename(&tmp, &fin)
    }

    pub fn read_purge_stamp(&self) -> Option<u64> {
        let s = fs::read_to_string(self.root.join(STAMP_NAME)).ok()?;
        s.trim().parse().ok()
    }

    /// Append one tag-purge watermark. Fixed-size fields make a torn record detectable; boot
    /// recovery converts any malformed/truncated journal into a conservative restart-time floor.
    pub fn append_tag_purge_stamp(&self, tag_hash: u64, wall_ms: u64) -> io::Result<()> {
        use std::fs::OpenOptions;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.root.join(TAG_STAMP_NAME))?;
        writeln!(file, "T {tag_hash:016x} {wall_ms:016x}")
    }

    /// Atomically compact the tag-purge journal. `floor_ms` safely subsumes every removed
    /// exact tag stamp: peer entries at-or-before it are rejected regardless of tag.
    pub fn write_tag_purge_state(&self, floor_ms: u64, stamps: &[(u64, u64)]) -> io::Result<()> {
        let tmp = self.root.join(format!("{TAG_STAMP_NAME}.tmp"));
        let fin = self.root.join(TAG_STAMP_NAME);
        let mut file = fs::File::create(&tmp)?;
        writeln!(file, "F {floor_ms:016x}")?;
        for &(tag_hash, wall_ms) in stamps {
            writeln!(file, "T {tag_hash:016x} {wall_ms:016x}")?;
        }
        drop(file);
        fs::rename(tmp, fin)
    }

    /// Recover the compact floor and latest wall stamp for each stable tag hash. Hash
    /// collisions can only cause a conservative peer-fill miss, never stale adoption.
    pub(crate) fn read_tag_purge_state(&self) -> TagPurgeState {
        let Ok(file) = fs::File::open(self.root.join(TAG_STAMP_NAME)) else {
            return TagPurgeState::default();
        };
        let byte_len = file.metadata().map(|metadata| metadata.len()).unwrap_or(0);
        let empty_file = byte_len == 0;
        let mut floor_ms = 0u64;
        let mut stamps = HashMap::<u64, u64>::new();
        let mut corrupt = empty_file;
        let mut record_count = 0u64;
        let mut stamp_record_count = 0u64;
        let mut floor_record_count = 0u64;
        for line in BufReader::new(file).lines() {
            let line = match line {
                Ok(line) => line,
                Err(_) => {
                    corrupt = true;
                    break;
                }
            };
            record_count = record_count.saturating_add(1);
            let mut fields = line.split_whitespace();
            match (fields.next(), fields.next(), fields.next(), fields.next()) {
                (Some("F"), Some(wall), None, None) if wall.len() == 16 => {
                    if let Ok(wall) = u64::from_str_radix(wall, 16) {
                        floor_record_count = floor_record_count.saturating_add(1);
                        floor_ms = floor_ms.max(wall);
                    } else {
                        corrupt = true;
                    }
                }
                (Some("T"), Some(hash), Some(wall), None)
                    if hash.len() == 16 && wall.len() == 16 =>
                {
                    if let (Ok(hash), Ok(wall)) =
                        (u64::from_str_radix(hash, 16), u64::from_str_radix(wall, 16))
                    {
                        stamp_record_count = stamp_record_count.saturating_add(1);
                        stamps
                            .entry(hash)
                            .and_modify(|old| *old = (*old).max(wall))
                            .or_insert(wall);
                    } else {
                        corrupt = true;
                    }
                }
                _ => corrupt = true,
            }
        }
        if corrupt {
            floor_ms = floor_ms.max(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
            );
        }
        stamps.retain(|_, wall| *wall > floor_ms);
        let canonical =
            !corrupt && floor_record_count == 1 && stamp_record_count == stamps.len() as u64;
        TagPurgeState {
            floor_ms,
            stamps,
            record_count,
            stamp_record_count,
            byte_len,
            corrupt,
            canonical,
        }
    }

    /// Unlink a published entry file; ENOENT is fine (purge and eviction may
    /// both reach the same file).
    pub fn remove(path: &Path) {
        if let Err(e) = fs::remove_file(path) {
            if e.kind() != io::ErrorKind::NotFound {
                tracing::warn!(path = %path.display(), error = %e, "jetcache: unlink failed");
            }
        }
    }
}

/// Header-only load: parse + validate everything except the body bytes (the
/// body stays cold in tmpfs — the whole point of the boot scan being cheap).
pub fn read_meta(path: &Path) -> Result<ScannedEntry, ReadError> {
    let mut f = fs::File::open(path)?;
    let md = f.metadata()?;
    let file_len = md.len();
    let mut header = [0u8; HEADER_LEN as usize];
    f.read_exact(&mut header)?;
    let (meta_len, body_len) = validate_header(&header, HEADER_LEN, file_len)?;
    let disk_total = allocated_bytes_from_metadata(&md, file_len);
    let flags = u16::from_le_bytes([header[6], header[7]]);
    let status = u16::from_le_bytes([header[16], header[17]]);
    let dict_gen = u32::from_le_bytes(header[20..24].try_into().unwrap());
    let stored_unix_ms = u64::from_le_bytes(header[24..32].try_into().unwrap());
    let ttl = Duration::from_millis(u64::from_le_bytes(header[32..40].try_into().unwrap()));
    let swr = Duration::from_millis(u64::from_le_bytes(header[40..48].try_into().unwrap()));
    let sie = Duration::from_millis(u64::from_le_bytes(header[48..56].try_into().unwrap()));
    let private_owner = u64::from_le_bytes(header[56..64].try_into().unwrap());

    let mut meta = vec![0u8; meta_len as usize];
    f.read_exact(&mut meta)?;
    // (security #260) The identity-bearing meta block must carry a valid integrity
    // tag; an adopted/forged container without one is corrupt and gets removed.
    if !verify_integrity(&header[64..80], &header[..64], &meta) {
        return Err(ReadError::Corrupt("integrity tag mismatch"));
    }
    let mut c = Cursor { buf: &meta, pos: 0 };

    let vhost_id = c.u32()?;
    let secure = c.u8()? != 0;
    let host = c.string()?;
    let path_field = c.string()?;
    let normalized_query = c.string()?;
    let key_vary_value = c.string()?;
    let identity = c.string()?;
    let vary_cookie_name = c.string()?;
    let vary_value = c.string()?;
    let tag_count = c.u16()?;
    let mut tags = Vec::with_capacity(tag_count as usize);
    for _ in 0..tag_count {
        tags.push(Arc::<str>::from(c.string()?));
    }
    let header_count = c.u16()?;
    let mut headers = Vec::with_capacity(header_count as usize);
    for _ in 0..header_count {
        let name =
            HeaderName::from_bytes(c.lp()?).map_err(|_| ReadError::Corrupt("bad header name"))?;
        let value =
            HeaderValue::from_bytes(c.lp()?).map_err(|_| ReadError::Corrupt("bad header value"))?;
        headers.push((name, value));
    }
    if c.pos != meta.len() {
        return Err(ReadError::Corrupt("trailing bytes in meta block"));
    }

    let scope = if flags & FLAG_PRIVATE != 0 {
        PageScope::Private {
            owner_hash: private_owner,
        }
    } else {
        PageScope::Public
    };
    let key = PageCacheKey {
        vhost_id,
        secure,
        host,
        path: path_field,
        normalized_query,
        vary_value: key_vary_value,
        private_owner,
    };
    Ok(ScannedEntry {
        key,
        status,
        identity,
        headers,
        dict_gen,
        tags,
        vary_cookie_name,
        vary_value,
        scope,
        stored_unix_ms,
        ttl,
        swr,
        sie,
        body_len,
        meta_len,
        disk_total,
        version_seq: page_file_seq(path).unwrap_or(0),
        path: path.to_path_buf(),
    })
}

pub fn read_static_meta(path: &Path) -> Result<ScannedStaticEntry, ReadError> {
    let mut f = fs::File::open(path)?;
    let md = f.metadata()?;
    let file_len = md.len();
    let mut header = [0u8; HEADER_LEN as usize];
    f.read_exact(&mut header)?;
    let (meta_len, body_len) = validate_header(&header, HEADER_LEN, file_len)?;
    let disk_total = allocated_bytes_from_metadata(&md, file_len);
    let flags = u16::from_le_bytes([header[6], header[7]]);
    if flags & FLAG_STATIC == 0 {
        return Err(ReadError::Corrupt("not a static entry"));
    }

    let mut meta = vec![0u8; meta_len as usize];
    f.read_exact(&mut meta)?;
    // (security #260) Uniform tag location: header[64..80] over [0..64] || meta.
    if !verify_integrity(&header[64..80], &header[..64], &meta) {
        return Err(ReadError::Corrupt("integrity tag mismatch"));
    }
    let mut c = Cursor { buf: &meta, pos: 0 };

    let vhost_id = c.u32()?;
    let cache_path = c.string()?;
    let source_path = PathBuf::from(c.string()?);
    let file_id = FileId {
        size: c.u64()?,
        mtime_secs: c.u64()?,
        mtime_nanos: c.u32()?,
        inode: c.u64()?,
    };
    let content_type = Arc::<str>::from(c.string()?);
    let etag = c.string()?;
    let last_modified = c.string()?;
    if c.pos != meta.len() {
        return Err(ReadError::Corrupt("trailing bytes in static meta block"));
    }

    Ok(ScannedStaticEntry {
        vhost_id,
        cache_path,
        source_path,
        file_id,
        content_type,
        etag,
        last_modified,
        body_len,
        meta_len,
        disk_total,
        path: path.to_path_buf(),
    })
}

/// FNV-1a-64 over the canonical key fields (house style — same family as
/// `vhost_id_hash` and the private-owner hashes). Only a storage locator; the
/// exact key in the meta block is what the index trusts.
pub fn key_hash(key: &PageCacheKey) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut eat = |bytes: &[u8]| {
        for &b in bytes {
            h ^= b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01B3);
        }
        // Field separator so ("ab","c") never hashes like ("a","bc").
        h ^= 0xFF;
        h = h.wrapping_mul(0x0000_0100_0000_01B3);
    };
    eat(&key.vhost_id.to_le_bytes());
    eat(&[key.secure as u8]);
    eat(key.host.as_bytes());
    eat(key.path.as_bytes());
    eat(key.normalized_query.as_bytes());
    eat(key.vary_value.as_bytes());
    eat(&key.private_owner.to_le_bytes());
    // NIL-sentinel guard: the store uses `CacheKeyId(u64::MAX)` as its intrusive-LRU list
    // terminator, so a real key must never hash to that bit pattern. Collapse the one
    // colliding value into bucket 0 (a one-in-2⁶⁴ reassignment; the identity guard makes any
    // resulting collision a clean miss, never wrong content).
    if h == u64::MAX {
        h = 0;
    }
    h
}

pub fn static_key_hash(vhost_id: u32, path: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut eat = |bytes: &[u8]| {
        for &b in bytes {
            h ^= b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01B3);
        }
        h ^= 0xFF;
        h = h.wrapping_mul(0x0000_0100_0000_01B3);
    };
    eat(&vhost_id.to_le_bytes());
    eat(path.as_bytes());
    if h == u64::MAX {
        h = 0;
    }
    h
}

fn encode_meta(key: &PageCacheKey, entry: &CachedResponse) -> io::Result<Vec<u8>> {
    if entry.tags.len() > u16::MAX as usize || entry.headers.len() > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tag/header count over format bound",
        ));
    }
    let mut m = Vec::with_capacity(512);
    m.extend_from_slice(&key.vhost_id.to_le_bytes());
    m.push(key.secure as u8);
    push_lp(&mut m, key.host.as_bytes());
    push_lp(&mut m, key.path.as_bytes());
    push_lp(&mut m, key.normalized_query.as_bytes());
    push_lp(&mut m, key.vary_value.as_bytes());
    push_lp(&mut m, entry.identity.as_bytes());
    push_lp(&mut m, entry.vary_cookie_name.as_bytes());
    push_lp(&mut m, entry.vary_value.as_bytes());
    m.extend_from_slice(&(entry.tags.len() as u16).to_le_bytes());
    for t in &entry.tags {
        push_lp(&mut m, t.as_bytes());
    }
    m.extend_from_slice(&(entry.headers.len() as u16).to_le_bytes());
    for (n, v) in &entry.headers {
        push_lp(&mut m, n.as_str().as_bytes());
        push_lp(&mut m, v.as_bytes());
    }
    if m.len() as u64 > MAX_META_LEN as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "meta block over format bound",
        ));
    }
    Ok(m)
}

fn encode_static_meta(
    vhost_id: u32,
    cache_path: &str,
    source_path: &Path,
    file_id: FileId,
    content_type: &str,
    etag: &str,
    last_modified: &str,
) -> io::Result<Vec<u8>> {
    let mut m = Vec::with_capacity(256);
    m.extend_from_slice(&vhost_id.to_le_bytes());
    push_lp(&mut m, cache_path.as_bytes());
    push_lp(&mut m, source_path.to_string_lossy().as_bytes());
    m.extend_from_slice(&file_id.size.to_le_bytes());
    m.extend_from_slice(&file_id.mtime_secs.to_le_bytes());
    m.extend_from_slice(&file_id.mtime_nanos.to_le_bytes());
    m.extend_from_slice(&file_id.inode.to_le_bytes());
    push_lp(&mut m, content_type.as_bytes());
    push_lp(&mut m, etag.as_bytes());
    push_lp(&mut m, last_modified.as_bytes());
    if m.len() as u64 > MAX_META_LEN as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "static meta block over format bound",
        ));
    }
    Ok(m)
}

/// The validation invariant: magic + version + `file size == 64 + meta + body`.
fn validate_header(header: &[u8], hlen: u64, file_len: u64) -> Result<(u32, u32), ReadError> {
    if header[0..4] != MAGIC {
        return Err(ReadError::Corrupt("bad magic"));
    }
    if u16::from_le_bytes([header[4], header[5]]) != VERSION {
        return Err(ReadError::Corrupt("unknown version"));
    }
    let meta_len = u32::from_le_bytes(header[8..12].try_into().unwrap());
    let body_len = u32::from_le_bytes(header[12..16].try_into().unwrap());
    if meta_len > MAX_META_LEN || body_len > MAX_BODY_LEN {
        return Err(ReadError::Corrupt("length over format bound"));
    }
    if file_len != hlen + meta_len as u64 + body_len as u64 {
        return Err(ReadError::Corrupt("file size disagrees with header"));
    }
    Ok((meta_len, body_len))
}

/// Process-lifetime integrity key (security #260). Installed once at startup from
/// a 0600 keyfile; when absent (tests / opt-out) tags are written as ZEROS and
/// verification is skipped, preserving the old behavior for ephemeral test stores.
static INTEGRITY_KEY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();

/// Create-or-load the 32-byte jetcache integrity key at `path` (created 0600 from
/// /dev/urandom). Best-effort: on failure the store runs WITHOUT integrity tags
/// (zeros) and this returns Err for the caller to log.
pub fn init_integrity_key(path: &std::path::Path) -> std::io::Result<()> {
    use std::io::Read;
    let mut key = [0u8; 32];
    match std::fs::File::open(path) {
        Ok(mut f) => f.read_exact(&mut key)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut ur = std::fs::File::open("/dev/urandom")?;
            ur.read_exact(&mut key)?;
            // Create with a tight mode regardless of umask; the dir may not exist yet.
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            std::fs::write(path, key)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
            }
        }
        Err(e) => return Err(e),
    }
    let _ = INTEGRITY_KEY.set(key);
    Ok(())
}

/// Truncated HMAC-SHA256 over (header_fields || meta). Zeros when no key installed.
fn integrity_tag(prefix: &[u8], meta: &[u8]) -> [u8; TAG_LEN] {
    let Some(key) = INTEGRITY_KEY.get() else {
        return [0u8; TAG_LEN];
    };
    use hmac::{Mac, SimpleHmac};
    type HmacSha256 = SimpleHmac<sha2::Sha256>;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac accepts any key len");
    mac.update(prefix);
    mac.update(meta);
    let out = mac.finalize().into_bytes();
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&out[..TAG_LEN]);
    tag
}

fn verify_integrity(tag: &[u8], prefix: &[u8], meta: &[u8]) -> bool {
    // No key installed: accept anything (test / ephemeral stores).
    if INTEGRITY_KEY.get().is_none() {
        return true;
    }
    let expect = integrity_tag(prefix, meta);
    tag.len() == TAG_LEN
        && tag
            .iter()
            .zip(expect.iter())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

fn push_lp(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(bytes);
}

fn ms_u64(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

fn parse_seq(name: &str) -> Option<u64> {
    parse_seq_ext(name, ".pc")
}

pub fn page_file_seq(path: &Path) -> Option<u64> {
    parse_seq(path.file_name()?.to_str()?)
}

fn parse_seq_ext(name: &str, suffix: &str) -> Option<u64> {
    name.strip_suffix(suffix)?.split_once('-')?.1.parse().ok()
}

fn read_dir_sorted(dir: &Path) -> Vec<PathBuf> {
    let Ok(rd) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = rd.filter_map(|e| e.ok().map(|e| e.path())).collect();
    paths.sort_unstable();
    paths
}

/// True if `file`'s mtime is at or after `since`. The boot scan uses this to leave
/// a `.tmp` that may be an in-flight write (created during/after the scan) in place,
/// reaping only older crash debris. An unreadable mtime is treated as NOT in-flight
/// (false) so genuinely orphaned files are still eventually cleaned.
fn modified_at_or_after(file: &Path, since: SystemTime) -> bool {
    fs::metadata(file)
        .and_then(|m| m.modified())
        .map(|m| m >= since)
        .unwrap_or(false)
}

fn allocated_file_bytes(path: &Path, fallback: u64) -> io::Result<u32> {
    let md = fs::metadata(path)?;
    Ok(allocated_bytes_from_metadata(&md, fallback))
}

fn allocated_bytes_from_metadata(md: &fs::Metadata, fallback: u64) -> u32 {
    let bytes = allocated_blocks_bytes(md).max(fallback);
    bytes.min(u32::MAX as u64) as u32
}

#[cfg(unix)]
fn allocated_blocks_bytes(md: &fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    md.blocks().saturating_mul(512)
}

#[cfg(not(unix))]
fn allocated_blocks_bytes(_md: &fs::Metadata) -> u64 {
    0
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ReadError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(ReadError::Corrupt("length overflow"))?;
        if end > self.buf.len() {
            return Err(ReadError::Corrupt("field past end of meta block"));
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, ReadError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, ReadError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, ReadError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, ReadError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn lp(&mut self) -> Result<&'a [u8], ReadError> {
        let len = self.u32()? as usize;
        self.take(len)
    }
    fn string(&mut self) -> Result<String, ReadError> {
        std::str::from_utf8(self.lp()?)
            .map(str::to_owned)
            .map_err(|_| ReadError::Corrupt("non-utf8 string field"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn key() -> PageCacheKey {
        PageCacheKey {
            vhost_id: 7,
            secure: true,
            host: "forum.example".into(),
            path: "/threads/example.1/".into(),
            normalized_query: "page=2".into(),
            vary_value: "xf_style_id=3".into(),
            private_owner: 0,
        }
    }

    fn entry(scope: PageScope) -> CachedResponse {
        CachedResponse {
            status: 200,
            identity: "https\nforum.example\n/threads/example.1/".into(),
            headers: vec![
                (
                    http::header::CONTENT_TYPE,
                    HeaderValue::from_static("text/html; charset=utf-8"),
                ),
                (
                    HeaderName::from_static("x-frame-options"),
                    HeaderValue::from_static("SAMEORIGIN"),
                ),
            ],
            body: crate::store::PageBody::InMem(Bytes::new()),
            variants: vec![("br".into(), Bytes::from_static(b"ignored-not-persisted"))],
            variants_filled: true,
            dict_gen: 0,
            tags: vec![Arc::from("T123"), Arc::from("forum")],
            vary_cookie_name: "xf_style_id".into(),
            vary_value: "xf_style_id=3".into(),
            scope,
            stored_at: Instant::now(),
            ttl: Duration::from_secs(900),
            swr: Duration::from_secs(60),
            sie: Duration::from_secs(3600),
        }
    }

    fn store() -> (tempfile::TempDir, DiskStore) {
        let td = tempfile::tempdir().unwrap();
        let ds = DiskStore::open(td.path()).unwrap();
        (td, ds)
    }

    fn store_with_seq(root: &Path, _runtime_seq_floor: u64, next_seq: u64) -> DiskStore {
        fs::create_dir_all(root).unwrap();
        DiskStore {
            root: root.to_path_buf(),
            live_files: Mutex::new(HashSet::new()),
            boot_scan_pending: AtomicBool::new(true),
            seq: AtomicU64::new(next_seq),
        }
    }

    #[test]
    fn read_dir_sorted_returns_lexical_paths() {
        let td = tempfile::tempdir().unwrap();
        for name in ["c.pc", "a.pc", "b.pc"] {
            fs::write(td.path().join(name), b"x").unwrap();
        }
        let names: Vec<String> = read_dir_sorted(td.path())
            .into_iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["a.pc", "b.pc", "c.pc"]);
    }

    #[test]
    fn scan_tolerates_max_seq_filename() {
        // A crafted filename with seq == u64::MAX must not overflow `seq + 1` (a debug-build
        // panic in the boot scan) — saturating_add keeps it safe. tmpfs is shared, so a stray
        // filename is conceivable.
        let (_td, ds) = store();
        let dir = ds.root.join("0").join("0").join("0");
        fs::create_dir_all(&dir).unwrap();
        let name = format!("0000000000000000-{}.pc", u64::MAX);
        fs::write(dir.join(name), b"not valid meta").unwrap();
        // Must return without panicking; the unreadable file is reaped as corrupt.
        let sum = ds.scan(|_| true);
        assert_eq!(sum.corrupt_removed, 1);
    }

    #[test]
    fn round_trips_public_entry() {
        let (_td, ds) = store();
        let k = key();
        let e = entry(PageScope::Public);
        let body = b"dict-compressed page bytes";
        let (path, _disk_total) = ds.write_entry(&k, &e, 42, body, 1_750_000_000_123).unwrap();

        let got = read_meta(&path).expect("read_meta");
        assert_eq!(got.key, k);
        assert_eq!(got.status, 200);
        assert_eq!(got.identity, e.identity);
        assert_eq!(got.headers, e.headers);
        assert_eq!(got.dict_gen, 42);
        assert_eq!(got.tags, e.tags);
        assert_eq!(got.vary_cookie_name, "xf_style_id");
        assert_eq!(got.scope, PageScope::Public);
        assert_eq!(got.stored_unix_ms, 1_750_000_000_123);
        assert_eq!(got.ttl, Duration::from_secs(900));
        assert_eq!(got.swr, Duration::from_secs(60));
        assert_eq!(got.sie, Duration::from_secs(3600));
        assert_eq!(got.body_len as usize, body.len());

        let bytes = DiskStore::read_body(&path, body.len() as u32).expect("read_body");
        assert_eq!(&bytes[..], body);
    }

    #[test]
    fn body_file_returns_validated_payload_range_without_reading_body() {
        let (_td, ds) = store();
        let k = key();
        let e = entry(PageScope::Public);
        let body = b"plain identity page bytes";
        let (path, _disk_total) = ds.write_entry(&k, &e, 0, body, 1_750_000_000_123).unwrap();

        let f = DiskStore::body_file(&path, body.len() as u32).expect("body_file");
        assert_eq!(f.path, path);
        assert_eq!(f.body_len as usize, body.len());
        assert_eq!(f.file_len, fs::metadata(&f.path).unwrap().len());

        let raw = fs::read(&f.path).unwrap();
        let start = f.body_start as usize;
        let end = start + f.body_len as usize;
        assert_eq!(&raw[start..end], body);
    }

    #[test]
    fn never_overwrites_a_published_version_file() {
        // Regression (#2): a write whose filename seq aliases an already-published file — the
        // warm-scan-window race where a fresh boot's counter restarts low — must NOT clobber the
        // existing bytes. write_entry hard-links into the final name (refusing an existing one) and
        // routes the colliding write to a fresh path.
        let (_td, ds) = store();
        let k = key();
        let e = entry(PageScope::Public);

        ds.seq.store(100, Ordering::Relaxed);
        let (p1, _) = ds.write_entry(&k, &e, 0, b"OLD", 1).unwrap();
        assert!(
            p1.to_string_lossy().ends_with("-100.pc"),
            "first write uses the pinned seq"
        );

        // Rewind the counter so the next write WOULD reuse `-100.pc`.
        ds.seq.store(100, Ordering::Relaxed);
        let (p2, _) = ds.write_entry(&k, &e, 0, b"NEW", 2).unwrap();
        assert_ne!(
            p1, p2,
            "the colliding write must land on a fresh path, not overwrite"
        );

        // Both files exist with their own bytes — the published version was never clobbered.
        assert_eq!(&DiskStore::read_body(&p1, 3).unwrap()[..], b"OLD");
        assert_eq!(&DiskStore::read_body(&p2, 3).unwrap()[..], b"NEW");
    }

    #[test]
    fn uncommitted_prepared_entry_cannot_resurrect_after_restart() {
        let (td, ds) = store();
        let prepared = ds
            .prepare_entry(
                &key(),
                &entry(PageScope::Public),
                0,
                b"pre-purge-render",
                100,
            )
            .unwrap();
        let tmp = prepared.tmp_path.clone();
        assert!(tmp.exists());
        assert_eq!(
            read_dir_sorted(tmp.parent().unwrap())
                .iter()
                .filter(|p| p.extension().is_some_and(|e| e == "pc"))
                .count(),
            0,
            "prepare must not expose a boot-scannable final file"
        );

        // Model a process crash before the store reaches its final purge veto: Drop does not run,
        // so only the private temp file remains. The next process treats it as crash debris.
        std::mem::forget(prepared);
        drop(ds);
        let restarted = DiskStore::open(td.path()).unwrap();
        let sum = restarted.scan(|_| true);
        assert_eq!(sum.loaded, 0);
        assert_eq!(sum.tmp_removed, 1);
        assert!(!tmp.exists());
    }

    #[test]
    fn round_trips_private_scope_and_owner() {
        let (_td, ds) = store();
        let mut k = key();
        k.private_owner = 0xDEAD_BEEF_CAFE_F00D;
        k.vary_value = "s=ab12".into();
        let e = entry(PageScope::Private {
            owner_hash: 0xDEAD_BEEF_CAFE_F00D,
        });
        let (path, _) = ds.write_entry(&k, &e, 0, b"private body", 1).unwrap();
        let got = read_meta(&path).unwrap();
        assert_eq!(
            got.scope,
            PageScope::Private {
                owner_hash: 0xDEAD_BEEF_CAFE_F00D
            }
        );
        assert_eq!(got.key.private_owner, 0xDEAD_BEEF_CAFE_F00D);
    }

    #[test]
    fn rejects_every_corruption_class() {
        let (_td, ds) = store();
        let (path, _) = ds
            .write_entry(&key(), &entry(PageScope::Public), 0, b"abcdef", 5)
            .unwrap();
        let pristine = fs::read(&path).unwrap();

        // bad magic
        let mut bad = pristine.clone();
        bad[0] = b'X';
        fs::write(&path, &bad).unwrap();
        assert!(matches!(read_meta(&path), Err(ReadError::Corrupt(_))));

        // unknown version
        let mut bad = pristine.clone();
        bad[4] = 99;
        fs::write(&path, &bad).unwrap();
        assert!(matches!(read_meta(&path), Err(ReadError::Corrupt(_))));

        // truncated body (size invariant)
        let mut bad = pristine.clone();
        bad.truncate(bad.len() - 3);
        fs::write(&path, &bad).unwrap();
        assert!(matches!(read_meta(&path), Err(ReadError::Corrupt(_))));
        assert!(matches!(
            DiskStore::read_body(&path, 6),
            Err(ReadError::Corrupt(_))
        ));

        // appended garbage (size invariant, the other direction)
        let mut bad = pristine.clone();
        bad.extend_from_slice(b"zz");
        fs::write(&path, &bad).unwrap();
        assert!(matches!(read_meta(&path), Err(ReadError::Corrupt(_))));

        // length prefix pointing past the meta block
        let mut bad = pristine.clone();
        // first lp is host at meta offset 5 (after vhost_id + secure); blow up its length
        let off = HEADER_LEN as usize + 5;
        bad[off..off + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        fs::write(&path, &bad).unwrap();
        assert!(matches!(read_meta(&path), Err(ReadError::Corrupt(_))));

        // body length disagreeing with the index's expectation
        fs::write(&path, &pristine).unwrap();
        assert!(matches!(
            DiskStore::read_body(&path, 7),
            Err(ReadError::Corrupt(_))
        ));

        // missing file is Io, not Corrupt (fail-closed miss either way)
        fs::remove_file(&path).unwrap();
        assert!(matches!(
            DiskStore::read_body(&path, 6),
            Err(ReadError::Io(_))
        ));
    }

    #[test]
    fn scan_yields_keeps_unlinks_rejects_and_reseeds_seq() {
        let (td, ds) = store();
        let k1 = key();
        let mut k2 = key();
        k2.path = "/whats-new/".into();
        let (p1, _) = ds
            .write_entry(&k1, &entry(PageScope::Public), 0, b"one", 100)
            .unwrap();
        let (p2, _) = ds
            .write_entry(&k2, &entry(PageScope::Public), 0, b"two", 200)
            .unwrap();
        // a stray tmp + a corrupt file
        let tmp = p1.with_extension("pc.tmp");
        fs::write(&tmp, b"partial").unwrap();
        let corrupt = p1.parent().unwrap().join("ffffffffffffffff-9.pc");
        fs::write(&corrupt, b"not a cache file").unwrap();

        // a fresh DiskStore (simulated restart) must reseed seq past existing files
        let ds2 = DiskStore::open(td.path()).unwrap();
        let seen = Mutex::new(Vec::new());
        let sum = ds2.scan(|e| {
            let keep = e.key == k1;
            seen.lock().push((e.key.clone(), e.stored_unix_ms));
            keep
        });
        assert_eq!(sum.loaded, 1);
        assert_eq!(sum.rejected, 1);
        assert_eq!(sum.corrupt_removed, 1);
        assert_eq!(sum.tmp_removed, 1);
        assert_eq!(seen.lock().len(), 2);
        assert!(p1.exists(), "kept entry file must remain");
        assert!(!p2.exists(), "rejected entry file must be unlinked");
        assert!(!tmp.exists());
        assert!(!corrupt.exists());

        // next write must not collide with the surviving file's name
        let (p3, _) = ds2
            .write_entry(&k1, &entry(PageScope::Public), 0, b"three", 300)
            .unwrap();
        assert_ne!(p3, p1);
        assert!(p3.exists() && p1.exists());
    }

    #[test]
    fn boot_scans_ignore_final_files_published_by_the_current_process() {
        let td = tempfile::tempdir().unwrap();
        let inherited = store_with_seq(td.path(), 1, 10);
        let inherited_key = key();
        let (old_page, _) = inherited
            .write_entry(
                &inherited_key,
                &entry(PageScope::Public),
                0,
                b"old-page",
                100,
            )
            .unwrap();
        let old_source = td.path().join("old-static-source");
        fs::write(&old_source, b"old-static").unwrap();
        let (old_static, _) = inherited
            .write_static_entry(
                1,
                "/old.css",
                &old_source,
                FileId::stat(&old_source).unwrap(),
                "text/css",
                "old-etag",
                "old-date",
                b"old-static",
            )
            .unwrap();

        let current = store_with_seq(td.path(), 100, 100);
        let mut live_key = key();
        live_key.path = "/live/".into();
        let (live_page, _) = current
            .write_entry(&live_key, &entry(PageScope::Public), 0, b"live-page", 200)
            .unwrap();
        let live_source = td.path().join("live-static-source");
        fs::write(&live_source, b"live-static").unwrap();
        let (live_static, _) = current
            .write_static_entry(
                1,
                "/live.css",
                &live_source,
                FileId::stat(&live_source).unwrap(),
                "text/css",
                "live-etag",
                "live-date",
                b"live-static",
            )
            .unwrap();

        let page_keys = Mutex::new(Vec::new());
        let page_sum = current.scan(|e| {
            page_keys.lock().push(e.key.clone());
            true
        });
        assert_eq!(page_sum.loaded, 1);
        assert_eq!(*page_keys.lock(), vec![inherited_key]);

        let static_paths = Mutex::new(Vec::new());
        let static_sum = current.scan_static(|e| {
            static_paths.lock().push(e.cache_path.clone());
            true
        });
        assert_eq!(static_sum.loaded, 1);
        assert_eq!(*static_paths.lock(), vec!["/old.css"]);

        assert!(old_page.exists() && old_static.exists());
        assert!(live_page.exists() && live_static.exists());
    }

    #[test]
    fn purge_stamp_round_trip_and_absence() {
        let (_td, ds) = store();
        assert_eq!(ds.read_purge_stamp(), None);
        ds.write_purge_stamp(1_750_000_999_000).unwrap();
        assert_eq!(ds.read_purge_stamp(), Some(1_750_000_999_000));
        // the stamp at the root must not confuse the scan
        let sum = ds.scan(|_| true);
        assert_eq!(sum.loaded + sum.rejected + sum.corrupt_removed, 0);
    }

    #[test]
    fn tag_purge_journal_round_trip_and_compaction() {
        let (_td, ds) = store();
        let state = ds.read_tag_purge_state();
        assert_eq!(state.floor_ms, 0);
        assert!(state.stamps.is_empty());
        assert_eq!(state.record_count, 0);
        assert_eq!(state.stamp_record_count, 0);
        assert_eq!(state.byte_len, 0);
        assert!(!state.corrupt);
        assert!(!state.canonical);
        ds.append_tag_purge_stamp(0x11, 100).unwrap();
        ds.append_tag_purge_stamp(0x11, 120).unwrap();
        ds.append_tag_purge_stamp(0x22, 110).unwrap();
        let state = ds.read_tag_purge_state();
        assert_eq!(state.floor_ms, 0);
        assert_eq!(state.stamps.get(&0x11), Some(&120));
        assert_eq!(state.stamps.get(&0x22), Some(&110));
        assert_eq!(state.record_count, 3);
        assert_eq!(state.stamp_record_count, 3);
        assert_eq!(state.byte_len, 3 * TAG_PURGE_STAMP_RECORD_BYTES);
        assert!(!state.canonical, "append-only state has no floor record");

        ds.write_tag_purge_state(115, &[(0x11, 120)]).unwrap();
        let state = ds.read_tag_purge_state();
        assert_eq!(state.floor_ms, 115);
        assert_eq!(state.stamps, HashMap::from([(0x11, 120)]));
        assert_eq!(state.record_count, 2);
        assert_eq!(state.stamp_record_count, 1);
        assert_eq!(
            state.byte_len,
            TAG_PURGE_FLOOR_RECORD_BYTES + TAG_PURGE_STAMP_RECORD_BYTES
        );
        assert!(state.canonical);

        let record = format!("T {:016x} {:016x}\n", 0x33u64, 175_000u64);
        let complete_without_newline = record.len() - 1;
        for cut in 0..complete_without_newline {
            fs::write(ds.root.join(TAG_STAMP_NAME), &record.as_bytes()[..cut]).unwrap();
            let state = ds.read_tag_purge_state();
            assert!(state.floor_ms > 0, "truncated record prefix {cut}");
            assert!(state.stamps.is_empty(), "truncated record prefix {cut}");
            assert!(state.corrupt, "truncated record prefix {cut}");
        }
        fs::write(
            ds.root.join(TAG_STAMP_NAME),
            &record.as_bytes()[..complete_without_newline],
        )
        .unwrap();
        let state = ds.read_tag_purge_state();
        assert_eq!(state.stamps, HashMap::from([(0x33, 175_000)]));
        assert_eq!(state.stamp_record_count, 1);
        assert!(!state.corrupt);
    }

    #[test]
    fn same_key_distinct_versions_coexist_until_resolved() {
        let (td, ds) = store();
        let k = key();
        let (pa, _) = ds
            .write_entry(&k, &entry(PageScope::Public), 0, b"old", 100)
            .unwrap();
        let (pb, _) = ds
            .write_entry(&k, &entry(PageScope::Public), 0, b"new", 200)
            .unwrap();
        assert_ne!(pa, pb);
        assert_eq!(
            pa.parent(),
            pb.parent(),
            "same key hashes to the same leaf dir"
        );
        // the scan callback sees both; the store's loader keeps the newest
        drop(ds);
        let restarted = DiskStore::open(td.path()).unwrap();
        let stamps = Mutex::new(Vec::new());
        restarted.scan(|e| {
            stamps.lock().push(e.stored_unix_ms);
            true
        });
        let mut stamps = stamps.into_inner();
        stamps.sort_unstable();
        assert_eq!(stamps, vec![100, 200]);
    }

    #[test]
    fn purge_version_sweep_spares_newer_final_and_inflight_tmp_files() {
        let (_td, ds) = store();
        let k = key();
        ds.seq.store(10, Ordering::Relaxed);
        let (old, _) = ds
            .write_entry(&k, &entry(PageScope::Public), 0, b"old", 100)
            .unwrap();
        let (fresh, _) = ds
            .write_entry(&k, &entry(PageScope::Public), 0, b"fresh", 200)
            .unwrap();
        let inflight = fresh.with_extension("pc.tmp");
        fs::write(&inflight, b"in-flight").unwrap();
        let old_seq = read_meta(&old).unwrap().version_seq;

        ds.remove_key_versions_through(&k, old_seq);

        assert!(!old.exists(), "the purged indexed version is removed");
        assert!(fresh.exists(), "a newer published version must survive");
        assert!(
            inflight.exists(),
            "purge never owns another writer's tmp file"
        );
    }

    #[test]
    fn remove_is_idempotent() {
        let (_td, ds) = store();
        let (p, _) = ds
            .write_entry(&key(), &entry(PageScope::Public), 0, b"x", 1)
            .unwrap();
        DiskStore::remove(&p);
        assert!(!p.exists());
        DiskStore::remove(&p); // ENOENT swallowed
    }

    #[test]
    fn key_hash_is_field_separated_and_stable() {
        let a = key();
        let mut b = key();
        b.host = "forum.invalid".into();
        b.path = format!("m{}", b.path);
        assert_ne!(key_hash(&a), key_hash(&b), "field boundaries must matter");
        assert_eq!(
            key_hash(&a),
            key_hash(&key()),
            "stable across constructions"
        );
    }
}
