//! HPACK (RFC 7541) codec for httpjet's native h2 stack — zero-allocation encode into a caller buffer.
//!
//! The [`Encoder`] writes header fields directly into a caller-supplied buffer with
//! no per-call heap allocation: a header whose `(name, value)` is in the static table
//! (e.g. `:status: 200`) becomes a single indexed byte; a known name (e.g. `etag`,
//! `content-type`) becomes an indexed-name literal; everything else a literal with a
//! literal name. The static table is pre-tuned to httpjet's actual response headers
//! (see [`static_table`]), so a typical static/cached response encodes to a few bytes.
//!
//! The [`Decoder`] parses a peer's header block (indexed, literal with/without/never
//! indexing, dynamic-table size updates) maintaining the dynamic table per RFC 7541.
//!
//! String literals use Huffman (§5.2) whenever it is strictly smaller than the raw
//! octets, on both encode and decode. Values are treated as raw octet strings
//! end-to-end (HPACK strings are not text); only DECODED header fields are
//! UTF-8-validated, because httpjet's request contract surfaces them as `str`.

#![forbid(unsafe_op_in_unsafe_fn)]

use std::borrow::Cow;
use std::collections::{HashMap, VecDeque};

pub mod huffman; // QPACK (RFC 9204) reuses the RFC 7541 Huffman table — exposed for hj-http3/uring
mod integer;
pub(crate) mod static_table;

/// HPACK decode error.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Truncated input / malformed varint.
    Truncated,
    /// An index referenced an entry outside the static+dynamic table.
    BadIndex,
    /// A string literal was not valid UTF-8 / not valid Huffman (header values are
    /// byte strings, but httpjet's contract uses `str`; non-UTF-8 is rejected here).
    BadString,
    /// A dynamic table size update was illegal: either it exceeded the protocol limit
    /// (SETTINGS_HEADER_TABLE_SIZE, RFC 7541 §6.3) or it did not appear at the very start
    /// of the header block (§4.2). Both are HPACK decoding errors → COMPRESSION_ERROR.
    InvalidSizeUpdate,
    /// The decoded header list exceeded `SETTINGS_MAX_HEADER_LIST_SIZE` (RFC 7540 §6.5.2),
    /// accounted per field as `name.len() + value.len() + 32` (RFC 7541 §4.1). This is the
    /// "HTTP/2 Bomb" guard: a block of near-empty indexed entries amplifies 1 wire byte into
    /// a full header field, so the wire-size cap never fires — this trips on the decoded size
    /// instead. The decoder is connection-scoped/stateful, so aborting mid-block desyncs the
    /// shared HPACK context → treat as connection-fatal (COMPRESSION_ERROR), like a bad decode.
    HeaderListTooLarge,
}

// ── String literals (RFC 7541 §5.2) ──────────────────────────────────────────

fn encode_string(out: &mut Vec<u8>, s: &str) {
    encode_string_bytes(out, s.as_bytes())
}

fn encode_string_bytes(out: &mut Vec<u8>, raw: &[u8]) {
    // Huffman-encode when it is strictly smaller than the raw literal (what
    // compliant encoders do); otherwise emit the raw bytes. The H bit is the top bit
    // of the 7-bit length prefix.
    let hlen = huffman::encoded_len(raw);
    if hlen < raw.len() {
        integer::encode(out, hlen as u64, 7, 0x80); // H=1
        huffman::encode(out, raw);
    } else {
        integer::encode(out, raw.len() as u64, 7, 0x00); // H=0
        out.extend_from_slice(raw);
    }
}

fn decode_string<'a>(buf: &'a [u8], pos: &mut usize) -> Result<Cow<'a, str>, Error> {
    let huff = buf.get(*pos).ok_or(Error::Truncated)? & 0x80 != 0;
    let len = integer::decode(buf, pos, 7).ok_or(Error::Truncated)? as usize;
    let end = pos.checked_add(len).ok_or(Error::Truncated)?;
    let bytes = buf.get(*pos..end).ok_or(Error::Truncated)?;
    *pos = end;
    if huff {
        let decoded = huffman::decode(bytes).ok_or(Error::BadString)?;
        let s = String::from_utf8(decoded).map_err(|_| Error::BadString)?;
        Ok(Cow::Owned(s))
    } else {
        std::str::from_utf8(bytes)
            .map(Cow::Borrowed)
            .map_err(|_| Error::BadString)
    }
}

/// Like [`decode_string`] but a Huffman literal decodes into the caller's reused `scratch` instead
/// of a fresh `String` — for TRANSIENT fields (a literal-without/never-indexing header that is
/// emitted and never stored), so a per-request-varying Huffman header (Cookie, `:path`) costs no
/// per-field allocation. Returns a borrow of `buf` (non-Huffman, zero-copy) or `scratch` (Huffman);
/// both outlive the single emit call. NOT for the incremental-indexing arm, where the field must be
/// owned into the dynamic table.
fn decode_string_into<'s>(
    buf: &'s [u8],
    pos: &mut usize,
    scratch: &'s mut Vec<u8>,
) -> Result<&'s str, Error> {
    let huff = buf.get(*pos).ok_or(Error::Truncated)? & 0x80 != 0;
    let len = integer::decode(buf, pos, 7).ok_or(Error::Truncated)? as usize;
    let end = pos.checked_add(len).ok_or(Error::Truncated)?;
    let bytes = buf.get(*pos..end).ok_or(Error::Truncated)?;
    *pos = end;
    if huff {
        huffman::decode_into(scratch, bytes).ok_or(Error::BadString)?;
        std::str::from_utf8(scratch).map_err(|_| Error::BadString)
    } else {
        std::str::from_utf8(bytes).map_err(|_| Error::BadString)
    }
}

std::thread_local! {
    /// Reused (name, value) scratch for decoding TRANSIENT (literal-without/never-indexing) header
    /// fields — the decode loop emits straight from these instead of allocating a `String` per
    /// Huffman field. A decoded value is consumed by the `emit` closure (copied into the
    /// HeaderName/HeaderValue) before the next field reuses the buffer; decode is not re-entrant.
    static DECODE_SCRATCH: std::cell::RefCell<(Vec<u8>, Vec<u8>)> =
        std::cell::RefCell::new((Vec::new(), Vec::new()));
}

// ── Encoder ──────────────────────────────────────────────────────────────────

const ENTRY_OVERHEAD: usize = 32; // RFC 7541 §4.1
const STATIC_LEN: usize = 61; // static_table::TABLE.len()

/// HPACK encoder with a connection-scoped dynamic table (incremental indexing), like
/// lshpack's history mode: headers that repeat across requests on a connection collapse
/// to a single index byte after their first appearance. Per-request-varying headers
/// (`date`, `set-cookie`, oversized values) are intentionally NOT indexed so they don't
/// churn the table.
pub struct Encoder {
    /// Values are raw octets: HPACK string literals are byte strings (RFC 7541 §5.2),
    /// and `http::HeaderValue` already guarantees no NUL/CR/LF — so the encoder never
    /// needs the per-byte `to_str` text validation a `str` value type would force on
    /// every response header.
    dynamic: VecDeque<(Box<str>, Box<[u8]>)>,
    /// Seqno of each `dynamic` entry, parallel to `dynamic` (front = newest). The
    /// monotonic seqno lets the lookup maps compute an entry's current 1-based index
    /// (`hpack_index`) without rescanning, even though every insert/evict shifts
    /// position-from-front. See [`Self::hpack_index`].
    seqnos: VecDeque<u64>,
    /// Total inserts ever; the next entry's seqno. The front (newest) live entry has
    /// seqno `ins_count - 1`.
    ins_count: u64,
    /// O(1) lookup replacing the per-header linear scan of `dynamic`: header name →
    /// its LIVE `(value, seqno)` entries in ascending-seqno order (oldest first). The
    /// `Box<str>` key borrow-looks-up from `&str` with no allocation; the per-name list
    /// is ~1 entry for distinct-name responses (the heavy-vhost case). Kept exactly in
    /// sync with `dynamic` by eager delete in [`Self::evict_back`] (so a stale entry can
    /// never yield a wrong index → no header corruption). `find_dynamic`/`find_dynamic_name`
    /// are proven equal to the retained linear oracle by a property test.
    name_index: HashMap<Box<str>, Vec<(Box<[u8]>, u64)>>,
    size: usize,
    /// The dynamic-table size currently in effect — kept in lock-step with the peer's
    /// decoder (it only changes when a size-update instruction is actually emitted).
    max_size: usize,
    /// The largest table size this encoder will ever use, regardless of how high the
    /// peer raises SETTINGS_HEADER_TABLE_SIZE — its construction value (4096 default).
    /// Caps growth so a generous peer can't make us hold a huge table.
    preferred_max: usize,
    /// RFC 7541 §4.2: if the peer changes SETTINGS_HEADER_TABLE_SIZE multiple times
    /// between our blocks, we must signal the minimum value seen in that interval before
    /// the final value. `pending_min_size` records that minimum; `pending_size_update`
    /// records the final (most-recent) target. Both are relative to the *currently active*
    /// `max_size` — we only emit a size-update instruction when the target differs from it.
    pending_size_update: Option<usize>,
    /// The minimum table size seen across all `set_peer_max_size` calls since the last
    /// header block was emitted. Must be signaled before `pending_size_update` when it
    /// is below the currently active `max_size` (RFC 7541 §4.2 intermediate-minimum rule).
    pending_min_size: Option<usize>,
}

impl Default for Encoder {
    fn default() -> Self {
        // 4096 is the HPACK default SETTINGS_HEADER_TABLE_SIZE most peers advertise.
        Encoder {
            dynamic: VecDeque::new(),
            seqnos: VecDeque::new(),
            ins_count: 0,
            name_index: HashMap::new(),
            size: 0,
            max_size: 4096,
            preferred_max: 4096,
            pending_size_update: None,
            pending_min_size: None,
        }
    }
}

impl Encoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply the peer's advertised SETTINGS_HEADER_TABLE_SIZE (RFC 7541 §6.3, RFC 7540
    /// §6.5.2) — the maximum dynamic-table size the peer's DECODER will maintain. We adopt
    /// `min(preferred, peer_max)` and, if that differs from the size currently in effect,
    /// queue a size-update instruction to lead the next header block; the table is resized
    /// (and any over-cap entries evicted) at emit time in [`Self::encode_header`], so the
    /// encoder and the peer's decoder always evict to the SAME final size and never desync —
    /// even if the peer changes the setting several times before we send a block.
    ///
    /// RFC 7541 §4.2: if the peer changes SETTINGS_HEADER_TABLE_SIZE multiple times between
    /// our blocks and the minimum observed is less than the final target, we must signal the
    /// minimum first (so the peer's decoder evicts to it) then the final. `pending_min_size`
    /// tracks that minimum; it is only relevant when we have a real pending change.
    pub(crate) fn set_peer_max_size(&mut self, peer_max: usize) {
        let target = peer_max.min(self.preferred_max);
        if target != self.max_size {
            // Track the lowest target seen — needed to produce the §4.2 intermediate signal.
            self.pending_min_size = Some(
                self.pending_min_size
                    .map_or(target, |prev| prev.min(target)),
            );
            self.pending_size_update = Some(target);
        } else {
            // Net no-op: the target equals the currently active size, so no update is needed
            // and any earlier intermediate-minimum is moot (no change will be emitted).
            self.pending_size_update = None;
            self.pending_min_size = None;
        }
    }

    /// 1-based HPACK index of a live entry from its insertion seqno. The front
    /// (newest, seqno = `ins_count - 1`) is `STATIC_LEN + 1`; an entry's position
    /// from the front is `ins_count - 1 - seqno` (every newer entry is still live,
    /// since eviction is strictly oldest-first), so the index is exactly what the old
    /// `position()`-from-front scan returned.
    fn hpack_index(&self, seqno: u64) -> usize {
        debug_assert!(seqno < self.ins_count);
        STATIC_LEN + 1 + (self.ins_count - 1 - seqno) as usize
    }

    /// 1-based HPACK index of an exact dynamic-table `(name, value)` match — the
    /// front-most (newest) such entry, matching the old front-to-back `position()`.
    /// O(1) name lookup + a scan of the (usually 1-element) per-name list, newest-first.
    fn find_dynamic(&self, name: &str, value: &[u8]) -> Option<usize> {
        let list = self.name_index.get(name)?;
        // Ascending seqno order, so reverse = newest-first = front-most.
        for (v, seqno) in list.iter().rev() {
            if v.as_ref() == value {
                return Some(self.hpack_index(*seqno));
            }
        }
        None
    }

    /// 1-based HPACK index of the front-most (newest) dynamic-table entry with `name`.
    fn find_dynamic_name(&self, name: &str) -> Option<usize> {
        let (_, seqno) = self.name_index.get(name)?.last()?;
        Some(self.hpack_index(*seqno))
    }

    /// Evict the oldest (back) dynamic entry, keeping `seqnos` and `name_index` in
    /// lock-step with `dynamic`. Returns `false` when the table is already empty.
    /// The evicted entry is the global oldest = the smallest seqno in its name's list
    /// (its front), so an evicted *older* duplicate never removes the key still holding
    /// the newer copy — the per-name list holds every live copy, keyed by exact seqno.
    fn evict_back(&mut self) -> bool {
        let (Some((n, v)), Some(seqno)) = (self.dynamic.pop_back(), self.seqnos.pop_back()) else {
            return false;
        };
        self.size -= n.len() + v.len() + ENTRY_OVERHEAD;
        if let Some(list) = self.name_index.get_mut(&n) {
            if let Some(pos) = list.iter().position(|(_, s)| *s == seqno) {
                list.remove(pos);
            }
            if list.is_empty() {
                self.name_index.remove(&n);
            }
        }
        true
    }

    /// Insert `(name, value)` at the front of the dynamic table, evicting from the back
    /// to stay within `max_size` (RFC 7541 §4.4).
    fn insert(&mut self, name: &str, value: &[u8]) {
        let entry_size = name.len() + value.len() + ENTRY_OVERHEAD;
        while self.size + entry_size > self.max_size {
            if !self.evict_back() {
                break;
            }
        }
        if entry_size <= self.max_size {
            self.size += entry_size;
            let seqno = self.ins_count;
            self.ins_count += 1;
            self.dynamic.push_front((name.into(), value.into()));
            self.seqnos.push_front(seqno);
            // Borrow-lookup first so an existing name doesn't allocate a throwaway key.
            match self.name_index.get_mut(name) {
                Some(list) => list.push((value.into(), seqno)),
                None => {
                    self.name_index
                        .insert(name.into(), vec![(value.into(), seqno)]);
                }
            }
        }
    }

    /// Whether a header is worth adding to the dynamic table. Excludes values that
    /// change per request (would evict useful entries) and very large values.
    fn indexable(name: &str, value: &[u8]) -> bool {
        !matches!(name, "date" | "set-cookie") && value.len() <= 256
    }

    /// Encode one header field into `out`. `name` must be lowercase (HTTP/2 invariant).
    /// `value` is raw octets — pass `HeaderValue::as_bytes()` straight through; HPACK
    /// string literals are byte strings, so no text validation pass is needed (or done).
    pub fn encode_header(&mut self, out: &mut Vec<u8>, name: &str, value: impl AsRef<[u8]>) {
        self.encode_header_inner(out, name, value.as_ref());
    }

    /// The non-generic body, so the `impl AsRef<[u8]>` convenience above never
    /// duplicates this (large) function per value type.
    fn encode_header_inner(&mut self, out: &mut Vec<u8>, name: &str, value: &[u8]) {
        // 0. §4.2/§6.3: a pending dynamic-table size update MUST lead the first header
        //    block after the change. `encode_header` is always the first call when building
        //    a block, so emit it here, adopt the new size, and evict to fit BEFORE the
        //    indexing logic below runs under the new limit.
        //
        //    RFC 7541 §4.2 intermediate-minimum rule: if the peer's SETTINGS lowered the
        //    limit at any point between blocks and then raised it to a different final value,
        //    we MUST first signal the minimum (so the peer's decoder evicts entries we already
        //    dropped) and then the final value. Only emit the intermediate when it is strictly
        //    less than the final target — if they are equal, one update suffices.
        if let Some(new_max) = self.pending_size_update.take() {
            let min_size = self.pending_min_size.take().unwrap_or(new_max);
            if min_size < new_max {
                // Intermediate shrink: peer's decoder must evict to min_size first.
                integer::encode(out, min_size as u64, 5, 0x20);
                self.max_size = min_size;
                while self.size > self.max_size {
                    if !self.evict_back() {
                        break;
                    }
                }
            } else {
                self.pending_min_size = None; // clear any stale min that is >= new_max
            }
            // Final (or only) size-update instruction.
            integer::encode(out, new_max as u64, 5, 0x20);
            self.max_size = new_max;
            while self.size > self.max_size {
                if !self.evict_back() {
                    break;
                }
            }
        } else {
            self.pending_min_size = None; // no pending change, discard any stale min
        }
        // 1. Exact (name,value) already in the static or dynamic table -> 1 indexed ref.
        if let Some(idx) =
            static_table::find_name_value(name, value).or_else(|| self.find_dynamic(name, value))
        {
            integer::encode(out, idx as u64, 7, 0x80);
            return;
        }
        // 2. Indexable -> literal WITH incremental indexing (6-bit name prefix), then add
        //    it so the next occurrence on this connection is a single index byte.
        if Self::indexable(name, value) {
            match static_table::find_name(name).or_else(|| self.find_dynamic_name(name)) {
                Some(i) => integer::encode(out, i as u64, 6, 0x40),
                None => {
                    out.push(0x40);
                    encode_string(out, name);
                }
            }
            encode_string_bytes(out, value);
            self.insert(name, value);
            return;
        }
        // 3. Not worth indexing -> literal WITHOUT indexing (indexed name if known).
        match static_table::find_name(name).or_else(|| self.find_dynamic_name(name)) {
            Some(i) => integer::encode(out, i as u64, 4, 0x00),
            None => {
                out.push(0x00);
                encode_string(out, name);
            }
        }
        encode_string_bytes(out, value);
    }
}

// ── Decoder (with dynamic table) ─────────────────────────────────────────────

/// HPACK decoder maintaining the dynamic table per RFC 7541 §2.3.2 / §4.
pub struct Decoder {
    dynamic: VecDeque<(String, String)>,
    size: usize,
    /// Current dynamic-table size limit (mutated by §6.3 size updates).
    max_size: usize,
    /// Hard protocol limit = the SETTINGS_HEADER_TABLE_SIZE we advertise. A size update
    /// may shrink `max_size` anywhere in `0..=hard_max`, but never above it (§6.3).
    hard_max: usize,
    /// SETTINGS_MAX_HEADER_LIST_SIZE we advertise (RFC 7540 §6.5.2): the maximum decoded
    /// header-list size, summed per field as `name.len() + value.len() + 32`. Bounds the
    /// "HTTP/2 Bomb" amplification; a block exceeding it fails with `HeaderListTooLarge`.
    max_list_size: usize,
}

impl Decoder {
    /// `max_size` is the SETTINGS_HEADER_TABLE_SIZE we advertise (default 4096); `max_list_size`
    /// is the SETTINGS_MAX_HEADER_LIST_SIZE bound on the *decoded* header list (anti-DoS).
    pub fn new(max_size: usize, max_list_size: usize) -> Self {
        Decoder {
            dynamic: VecDeque::new(),
            size: 0,
            max_size,
            hard_max: max_size,
            max_list_size,
        }
    }

    /// Borrow a table entry's `(name, value)` — static (`'static`) or dynamic (borrowing
    /// `self.dynamic`). Returning refs lets the decode loop emit indexed/named headers with
    /// ZERO per-header `String` allocation (the `emit` closure builds the HeaderName/Value),
    /// instead of materializing a throwaway owned tuple per header on every request decode.
    fn entry_ref(&self, index: usize) -> Option<(&str, &str)> {
        if let Some((n, v)) = static_table::get(index) {
            return Some((n, v));
        }
        let dyn_idx = index.checked_sub(static_table::TABLE.len() + 1)?;
        self.dynamic
            .get(dyn_idx)
            .map(|(n, v)| (n.as_str(), v.as_str()))
    }

    fn insert(&mut self, name: String, value: String) {
        let entry_size = name.len() + value.len() + ENTRY_OVERHEAD;
        self.evict_to(self.max_size.saturating_sub(entry_size));
        if entry_size <= self.max_size {
            self.size += entry_size;
            self.dynamic.push_front((name, value));
        }
        // If a single entry exceeds max_size, the table ends up empty (RFC §4.4).
    }

    fn evict_to(&mut self, target: usize) {
        while self.size > target {
            match self.dynamic.pop_back() {
                Some((n, v)) => self.size -= n.len() + v.len() + ENTRY_OVERHEAD,
                None => break,
            }
        }
    }

    fn set_max_size(&mut self, new_max: usize) -> Result<(), Error> {
        // §6.3: the new maximum size MUST be ≤ the limit determined by the protocol
        // (the SETTINGS_HEADER_TABLE_SIZE we advertised). Exceeding it is a decode error.
        if new_max > self.hard_max {
            return Err(Error::InvalidSizeUpdate);
        }
        self.max_size = new_max;
        self.evict_to(new_max);
        Ok(())
    }

    /// Decode a complete header block, invoking `emit(name, value)` for each field in
    /// order. Returns `Err` on malformed input.
    pub fn decode<F>(&mut self, buf: &[u8], mut emit: F) -> Result<(), Error>
    where
        F: FnMut(&str, &str),
    {
        let mut pos = 0;
        // §4.2: a dynamic table size update MUST occur at the beginning of a header block,
        // before any header field representation. Once we've emitted a field, a later size
        // update is a decoding error.
        let mut seen_field = false;
        // RFC 7540 §6.5.2 / RFC 7541 §4.1: account each emitted field as name+value+32 and
        // refuse the block once the running total exceeds the advertised MAX_HEADER_LIST_SIZE.
        // This bounds the "HTTP/2 Bomb" — a block of near-empty indexed entries that costs ~1
        // wire byte each but appends a full field — which the wire-size cap alone cannot catch.
        let list_limit = self.max_list_size;
        let mut listed = 0usize;
        let mut emit_checked = |n: &str, v: &str| -> Result<(), Error> {
            listed = listed.saturating_add(n.len() + v.len() + ENTRY_OVERHEAD);
            if listed > list_limit {
                return Err(Error::HeaderListTooLarge);
            }
            emit(n, v);
            Ok(())
        };
        while pos < buf.len() {
            let b = buf[pos];
            if b & 0x80 != 0 {
                // §6.1 Indexed Header Field.
                let idx = integer::decode(buf, &mut pos, 7).ok_or(Error::Truncated)? as usize;
                let (n, v) = self.entry_ref(idx).ok_or(Error::BadIndex)?;
                seen_field = true;
                emit_checked(n, v)?;
            } else if b & 0x40 != 0 {
                // §6.2.1 Literal with incremental indexing (6-bit name index prefix).
                let (n, v) = self.read_literal(buf, &mut pos, 6)?;
                seen_field = true;
                emit_checked(&n, &v)?;
                // Own the entry before inserting: the table must outlive the block, AND owning in a
                // separate statement first releases the shared `self`/`buf` borrow the `Cow` held,
                // so the insert can reborrow `&mut self`. (The non-indexing arm below never owns —
                // that is the allocation the `Cow` return type saves.)
                let (n, v) = (n.into_owned(), v.into_owned());
                self.insert(n, v);
            } else if b & 0x20 != 0 {
                // §6.3 Dynamic table size update (5-bit prefix).
                if seen_field {
                    return Err(Error::InvalidSizeUpdate); // §4.2: not at block start
                }
                let new_max = integer::decode(buf, &mut pos, 5).ok_or(Error::Truncated)? as usize;
                self.set_max_size(new_max)?;
            } else {
                // §6.2.2 without indexing / §6.2.3 never indexed (4-bit name prefix). The field is
                // emitted and NEVER stored, so its name+value are TRANSIENT — decode them into the
                // reused thread-local scratch and emit straight from the borrow, so a per-request
                // Huffman field (Cookie, `:path`) costs no per-field `String` allocation. (The
                // incremental-indexing arm above still owns, as that entry outlives the block.)
                let name_idx = integer::decode(buf, &mut pos, 4).ok_or(Error::Truncated)? as usize;
                seen_field = true;
                DECODE_SCRATCH.with(|cell| -> Result<(), Error> {
                    let mut guard = cell.borrow_mut();
                    let (nb, vb) = &mut *guard;
                    let name: &str = if name_idx == 0 {
                        decode_string_into(buf, &mut pos, nb)?
                    } else {
                        self.entry_ref(name_idx).ok_or(Error::BadIndex)?.0
                    };
                    let value: &str = decode_string_into(buf, &mut pos, vb)?;
                    emit_checked(name, value)
                })?;
            }
        }
        Ok(())
    }

    /// Read a literal header field whose name is either an index (`prefix_bits`-wide,
    /// nonzero) or a following string literal (index 0).
    fn read_literal<'a>(
        &'a self,
        buf: &'a [u8],
        pos: &mut usize,
        prefix_bits: u8,
    ) -> Result<(Cow<'a, str>, Cow<'a, str>), Error> {
        let name_idx = integer::decode(buf, pos, prefix_bits).ok_or(Error::Truncated)? as usize;
        // Borrow rather than own: an indexed name borrows the table, a non-Huffman literal
        // borrows the wire buffer (`decode_string` already returns a `Cow`). The caller owns
        // (`into_owned`) ONLY on the incremental-indexing arm, where the entry must outlive the
        // block — the without/never-indexing arms emit straight from the borrow, which is the
        // per-header allocate-then-drop this avoids for un-indexed (per-request-varying) fields.
        let name = if name_idx == 0 {
            decode_string(buf, pos)?
        } else {
            Cow::Borrowed(self.entry_ref(name_idx).ok_or(Error::BadIndex)?.0)
        };
        let value = decode_string(buf, pos)?;
        Ok((name, value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Stage-2 safety net: the pre-optimization linear scans, kept as oracles so the
    //    O(1) `name_index` lookups are provably byte-identical (a wrong dynamic index =
    //    silent header corruption / GOAWAY, so this equivalence is load-bearing). ──
    fn fd_linear(enc: &Encoder, name: &str, value: &[u8]) -> Option<usize> {
        enc.dynamic
            .iter()
            .position(|(n, v)| &**n == name && &**v == value)
            .map(|p| STATIC_LEN + 1 + p)
    }
    fn fdn_linear(enc: &Encoder, name: &str) -> Option<usize> {
        enc.dynamic
            .iter()
            .position(|(n, _)| &**n == name)
            .map(|p| STATIC_LEN + 1 + p)
    }

    /// Deterministic xorshift64 PRNG — the workspace has no `rand`/`proptest`.
    struct Rng(u64);
    impl Rng {
        fn next_u64(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next_u64() % n as u64) as usize
        }
    }

    #[test]
    fn dynamic_hash_matches_linear_oracle_under_random_ops() {
        // Random insert / size-shrink / encode streams over a tiny alphabet (forces
        // duplicates + same-name/different-value collisions + eviction), asserting the
        // hash lookups equal the linear oracle and the three table views stay in sync
        // after EVERY op.
        let big = "v".repeat(300); // >256 ⇒ not indexable via encode_header
        let names = ["x-a", "x-b", "content-type", "vary", "x-c", "date"];
        let values = [
            "1",
            "2",
            "application/octet-stream",
            "Accept",
            "",
            big.as_str(),
        ];
        let sizes = [0usize, 64, 200, 4096];

        let mut enc = Encoder::new();
        let mut rng = Rng(0x9E3779B97F4A7C15);
        let mut out = Vec::new();

        for _ in 0..6000 {
            match rng.below(4) {
                0 => {
                    out.clear();
                    enc.encode_header(
                        &mut out,
                        names[rng.below(names.len())],
                        values[rng.below(values.len())],
                    );
                }
                1 => enc.insert(
                    names[rng.below(names.len())],
                    values[rng.below(values.len())].as_bytes(),
                ),
                2 => enc.set_peer_max_size(sizes[rng.below(sizes.len())]),
                _ => {
                    out.clear();
                    enc.encode_header(&mut out, "x-flush", "z"); // applies any pending size update
                }
            }

            // The three views of the dynamic table must agree in size.
            assert_eq!(enc.seqnos.len(), enc.dynamic.len(), "seqnos vs dynamic len");
            let idx_total: usize = enc.name_index.values().map(|l| l.len()).sum();
            assert_eq!(
                idx_total,
                enc.dynamic.len(),
                "name_index total vs dynamic len"
            );

            // Byte-identical lookup vs the oracle for every query (incl. misses).
            for &n in names.iter().chain(["x-flush", "x-missing"].iter()) {
                assert_eq!(
                    enc.find_dynamic_name(n),
                    fdn_linear(&enc, n),
                    "find_dynamic_name({n:?})"
                );
                for &v in &values {
                    assert_eq!(
                        enc.find_dynamic(n, v.as_bytes()),
                        fd_linear(&enc, n, v.as_bytes()),
                        "find_dynamic({n:?},{v:?})"
                    );
                }
            }
        }
    }

    #[test]
    fn duplicate_and_same_name_lookup_semantics() {
        // (x,A) then (x,B) then (x,A) again: find_dynamic must return the FRONT-MOST
        // (newest) match, exactly like the old position()-from-front scan.
        let mut enc = Encoder::new();
        enc.insert("x", b"A"); // seqno 0
        enc.insert("x", b"B"); // seqno 1 (same name, different value)
        enc.insert("x", b"A"); // seqno 2 (duplicate of #0, now newest)
        assert_eq!(enc.find_dynamic_name("x"), Some(STATIC_LEN + 1)); // newest = front = 62
        assert_eq!(enc.find_dynamic("x", b"A"), Some(STATIC_LEN + 1)); // newest A (#2) = 62
        assert_eq!(enc.find_dynamic("x", b"B"), Some(STATIC_LEN + 2)); // #1 = 63
        assert_eq!(enc.find_dynamic("x", b"A"), fd_linear(&enc, "x", b"A"));
        assert_eq!(enc.find_dynamic("x", b"B"), fd_linear(&enc, "x", b"B"));
    }

    #[test]
    fn indexed_status_200_is_one_byte() {
        let mut enc = Encoder::new();
        let mut out = Vec::new();
        enc.encode_header(&mut out, ":status", "200");
        assert_eq!(out, vec![0x88]); // index 8, §6.1
    }

    #[test]
    fn indexed_name_literal_value() {
        // content-type with a literal value. With incremental indexing the encoder uses
        // the 6-bit-prefix "literal with indexing" form (representation byte 0x40|31);
        // verify it decodes back exactly (the byte form is an encoder choice).
        let mut enc = Encoder::new();
        let mut out = Vec::new();
        enc.encode_header(&mut out, "content-type", "text/html");
        let mut dec = Decoder::new(4096, 1 << 20);
        let mut got = Vec::new();
        dec.decode(&out, |n, v| got.push((n.to_owned(), v.to_owned())))
            .unwrap();
        assert_eq!(got, vec![("content-type".into(), "text/html".into())]);
    }

    #[test]
    fn new_name_literal() {
        let mut enc = Encoder::new();
        let mut out = Vec::new();
        enc.encode_header(&mut out, "x-custom", "yes");
        let mut dec = Decoder::new(4096, 1 << 20);
        let mut got = Vec::new();
        dec.decode(&out, |n, v| got.push((n.to_owned(), v.to_owned())))
            .unwrap();
        assert_eq!(got, vec![("x-custom".into(), "yes".into())]);
    }

    #[test]
    fn obs_text_value_encodes_as_octets_and_indexes() {
        // HPACK strings are octet strings: a value with obs-text (0x80+) — which a
        // `to_str()`-validating encoder would have dropped — must encode as a raw
        // literal and participate in dynamic-table indexing like any other value.
        let mut enc = Encoder::new();
        let mut first = Vec::new();
        enc.encode_header(&mut first, "x-o", &[0x61u8, 0xE9][..]);
        // Huffman inflates the 2-byte value (0xE9 is a long code), so the value must be
        // the H=0 raw literal at the block's tail.
        assert!(first.ends_with(&[0x02, 0x61, 0xE9]), "got {first:x?}");
        let mut second = Vec::new();
        enc.encode_header(&mut second, "x-o", &[0x61u8, 0xE9][..]);
        assert_eq!(
            second.len(),
            1,
            "repeat must collapse to one dynamic-table index byte"
        );
        assert_ne!(
            second[0] & 0x80,
            0,
            "repeat must be an indexed-field representation"
        );
    }

    #[test]
    fn dynamic_table_collapses_repeated_header_to_one_byte() {
        // A repeated header on the same encoder must encode to a single index byte the
        // second time (the connection-scoped dynamic-table win), and a single decoder
        // fed the concatenated stream reconstructs both occurrences.
        let mut enc = Encoder::new();
        let mut first = Vec::new();
        enc.encode_header(&mut first, "content-type", "application/octet-stream");
        let mut second = Vec::new();
        enc.encode_header(&mut second, "content-type", "application/octet-stream");
        assert_eq!(
            second.len(),
            1,
            "repeat should be one indexed byte, got {second:?}"
        );
        assert_ne!(
            second[0] & 0x80,
            0,
            "repeat should be an indexed-field representation"
        );

        let mut combined = first.clone();
        combined.extend_from_slice(&second);
        let mut dec = Decoder::new(4096, 1 << 20);
        let mut got = Vec::new();
        dec.decode(&combined, |n, v| got.push((n.to_owned(), v.to_owned())))
            .unwrap();
        assert_eq!(
            got,
            vec![
                ("content-type".into(), "application/octet-stream".into()),
                ("content-type".into(), "application/octet-stream".into()),
            ]
        );
    }

    #[test]
    fn date_is_not_indexed() {
        // `date` changes per second, so it must NOT enter the dynamic table (no churn).
        let mut enc = Encoder::new();
        let mut a = Vec::new();
        enc.encode_header(&mut a, "date", "Wed, 03 Jun 2026 09:49:05 GMT");
        assert!(enc.dynamic.is_empty(), "date must not be indexed");
        // A different date second still encodes as a literal (no false dynamic hit).
        let mut b = Vec::new();
        enc.encode_header(&mut b, "date", "Wed, 03 Jun 2026 09:49:06 GMT");
        assert!(b.len() > 1);
    }

    #[test]
    fn roundtrip_typical_static_response() {
        let headers = vec![
            (":status", "200"),
            ("content-type", "application/octet-stream"),
            ("content-length", "1024"),
            ("last-modified", "Mon, 01 Jun 2026 01:33:55 GMT"),
            ("accept-ranges", "bytes"),
            ("etag", "\"400-6a1ce183-3e6b8b;;;\""),
            ("vary", "Accept"),
            ("cache-control", "public, max-age=300"),
            ("date", "Wed, 03 Jun 2026 09:49:05 GMT"),
            ("x-litespeed-cache", "hit"),
        ];
        let mut enc = Encoder::new();
        let mut buf = Vec::new();
        for (n, v) in headers.iter().copied() {
            enc.encode_header(&mut buf, n, v);
        }

        let mut dec = Decoder::new(4096, 1 << 20);
        let mut got = Vec::new();
        dec.decode(&buf, |n, v| got.push((n.to_owned(), v.to_owned())))
            .unwrap();

        let want: Vec<(String, String)> = headers
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect();
        assert_eq!(got, want);
    }

    #[test]
    fn decoder_handles_incremental_indexing_and_dynamic_refs() {
        // Hand-build: literal w/ incremental indexing, new name "x-a: 1", then an
        // indexed reference to it (first dynamic entry = index 62).
        let mut buf = Vec::new();
        buf.push(0x40); // literal w/ incremental indexing, new name
        super::encode_string(&mut buf, "x-a");
        super::encode_string(&mut buf, "1");
        integer::encode(&mut buf, 62, 7, 0x80); // indexed: first dynamic entry

        let mut dec = Decoder::new(4096, 1 << 20);
        let mut got = Vec::new();
        dec.decode(&buf, |n, v| got.push((n.to_owned(), v.to_owned())))
            .unwrap();
        assert_eq!(
            got,
            vec![("x-a".into(), "1".into()), ("x-a".into(), "1".into())]
        );
    }

    #[test]
    fn decoder_literal_without_and_never_indexed_do_not_index() {
        // §6.2.2 (without indexing) and §6.2.3 (never indexed) MUST emit the field but leave the
        // dynamic table untouched. Exercises the Cow-borrowed `read_literal` path (an indexed name
        // borrows the static table; a non-Huffman value borrows the wire) that replaced the
        // throwaway per-header `String` these representations used to allocate-then-drop.
        let mut buf = Vec::new();
        // §6.2.2 without indexing, NEW name (4-bit name index 0): raw "x-test" / raw "v".
        buf.push(0x00);
        buf.push(6);
        buf.extend_from_slice(b"x-test");
        buf.push(1);
        buf.extend_from_slice(b"v");
        // §6.2.3 never indexed, INDEXED name (static index 1 = ":authority"): raw value "ex.com".
        buf.push(0x10 | 1);
        buf.push(6);
        buf.extend_from_slice(b"ex.com");

        let mut dec = Decoder::new(4096, 1 << 20);
        let mut got = Vec::new();
        dec.decode(&buf, |n, v| got.push((n.to_owned(), v.to_owned())))
            .unwrap();
        assert_eq!(
            got,
            vec![
                ("x-test".into(), "v".into()),
                (":authority".into(), "ex.com".into())
            ]
        );
        // Neither representation indexes — the table stays empty (the now-borrowing arm must not
        // leave a spurious entry behind).
        assert_eq!(
            dec.size, 0,
            "without/never-indexed literals must not grow the dynamic table"
        );
        assert!(dec.dynamic.is_empty());
    }

    #[test]
    fn size_update_larger_than_protocol_max_is_error() {
        // §6.3: a size update above the advertised SETTINGS_HEADER_TABLE_SIZE (here 4096)
        // is a decode error. 0x3f,0xe1,0x1f = dynamic-table-size-update of 4097.
        let mut dec = Decoder::new(4096, 1 << 20);
        let mut buf = Vec::new();
        integer::encode(&mut buf, 4097, 5, 0x20);
        assert_eq!(dec.decode(&buf, |_, _| {}), Err(Error::InvalidSizeUpdate));
    }

    #[test]
    fn size_update_not_at_block_start_is_error() {
        // §4.2: a size update after a header field representation is illegal.
        let mut buf = Vec::new();
        buf.push(0x88); // indexed field :status 200
        integer::encode(&mut buf, 0, 5, 0x20); // size update to 0, but mid-block
        let mut dec = Decoder::new(4096, 1 << 20);
        assert_eq!(dec.decode(&buf, |_, _| {}), Err(Error::InvalidSizeUpdate));
    }

    #[test]
    fn size_update_at_block_start_is_ok() {
        // A size update IS allowed at the very start, before any field.
        let mut buf = Vec::new();
        integer::encode(&mut buf, 0, 5, 0x20); // shrink table to 0
        buf.push(0x88); // then :status 200
        let mut dec = Decoder::new(4096, 1 << 20);
        let mut got = Vec::new();
        dec.decode(&buf, |n, v| got.push((n.to_owned(), v.to_owned())))
            .unwrap();
        assert_eq!(got, vec![(":status".into(), "200".into())]);
    }

    #[test]
    fn encoder_uses_huffman_when_smaller_and_roundtrips() {
        // A long compressible value should be Huffman-encoded (H bit set) and smaller
        // than raw, and still decode back exactly.
        let value = "Mozilla/5.0 (compatible; example) text/html application/json";
        let mut enc = Encoder::new();
        let mut out = Vec::new();
        enc.encode_header(&mut out, "user-agent", value);
        // Whole encoding (1-byte name index + Huffman value) is strictly smaller than a
        // raw literal would be (representation byte + raw value), proving Huffman applied.
        assert!(
            out.len() < 1 + value.len(),
            "value should be Huffman-coded (smaller)"
        );

        let mut dec = Decoder::new(4096, 1 << 20);
        let mut got = Vec::new();
        dec.decode(&out, |n, v| got.push((n.to_owned(), v.to_owned())))
            .unwrap();
        assert_eq!(got, vec![("user-agent".into(), value.to_owned())]);
    }

    #[test]
    fn rejects_indexed_header_bomb() {
        // The "HTTP/2 Bomb": a 64 KiB block of single-byte indexed references to static
        // index 32 (`cookie: ""`). Each byte costs ~nothing on the wire but appends a full
        // header field, so the 64 KiB *wire* cap never fires — a naive decoder expands this
        // to ~65 000 fields (~6.5 MB resident). The decoded-list cap (name+value+32 per
        // field, RFC 7541 §4.1) must trip it long before that.
        const COOKIE_INDEXED: u8 = 0x80 | 32; // §6.1 indexed header field, static index 32
        let bomb = vec![COOKIE_INDEXED; 64 * 1024];
        let mut dec = Decoder::new(4096, 128 * 1024);
        let mut emitted = 0usize;
        let res = dec.decode(&bomb, |n, v| {
            assert_eq!((n, v), ("cookie", ""));
            emitted += 1;
        });
        assert_eq!(res, Err(Error::HeaderListTooLarge));
        // 128 KiB / (6 + 0 + 32) ≈ 3449 entries trips the cap — far below the 65 536 on the wire.
        assert!(emitted > 0, "should decode some fields before tripping");
        assert!(
            emitted < 4096,
            "cap should trip early, but emitted {emitted} fields"
        );
    }

    #[test]
    fn realistic_block_stays_under_list_cap() {
        // A normal small request (a handful of indexed fields) decodes without tripping.
        const COOKIE_INDEXED: u8 = 0x80 | 32;
        let small = vec![COOKIE_INDEXED; 16];
        let mut dec = Decoder::new(4096, 128 * 1024);
        let mut got = 0usize;
        dec.decode(&small, |_, _| got += 1).unwrap();
        assert_eq!(got, 16);
    }

    #[test]
    fn peer_table_size_zero_emits_size_update_and_roundtrips() {
        // Peer advertises SETTINGS_HEADER_TABLE_SIZE=0 (disable the dynamic table). The next
        // block must lead with a §6.3 size update of 0, and a decoder must still read it back.
        let mut enc = Encoder::new();
        enc.set_peer_max_size(0);
        let mut out = Vec::new();
        enc.encode_header(&mut out, "x-custom", "value");
        assert_eq!(
            out[0], 0x20,
            "a size update of 0 (0b001 prefix) must lead the block"
        );

        let mut dec = Decoder::new(4096, 1 << 16);
        let mut got = Vec::new();
        dec.decode(&out, |n, v| got.push((n.to_string(), v.to_string())))
            .unwrap();
        assert_eq!(got, vec![("x-custom".to_string(), "value".to_string())]);

        // The change is signaled exactly once — a later block carries no size update.
        let mut out2 = Vec::new();
        enc.encode_header(&mut out2, "x-custom", "value");
        assert_ne!(
            out2[0], 0x20,
            "size update must not repeat on subsequent blocks"
        );
    }

    #[test]
    fn peer_table_size_at_or_above_default_emits_no_update() {
        // At/above our 4096 preferred max we keep using 4096 — no size update needed.
        for peer in [4096usize, 8192] {
            let mut enc = Encoder::new();
            enc.set_peer_max_size(peer);
            let mut out = Vec::new();
            enc.encode_header(&mut out, ":status", "200");
            assert_ne!(
                out[0], 0x20,
                "no size update when staying at the default (peer={peer})"
            );
        }
    }

    #[test]
    fn shrinking_peer_table_evicts_indexed_entries() {
        let mut enc = Encoder::new();
        let mut b1 = Vec::new();
        enc.encode_header(&mut b1, "x-a", "1");
        let mut b2 = Vec::new();
        enc.encode_header(&mut b2, "x-a", "1");
        assert_eq!(b2.len(), 1, "a repeated header collapses to one index byte");

        // Peer shrinks to 0: the next block leads with update(0) and the entry is evicted,
        // so the header is re-sent as a literal rather than the (now-invalid) index.
        enc.set_peer_max_size(0);
        let mut b3 = Vec::new();
        enc.encode_header(&mut b3, "x-a", "1");
        assert_eq!(b3[0], 0x20, "size update leads the block after a shrink");
        assert!(b3.len() > 2, "the evicted entry is re-encoded as a literal");
    }

    #[test]
    fn transient_table_size_change_before_block_is_coalesced() {
        // Peer lowers then restores the table size before we emit any block. Since eviction is
        // deferred to emit time, the net effect is no change → no size update, table intact.
        let mut enc = Encoder::new();
        let mut b1 = Vec::new();
        enc.encode_header(&mut b1, "x-a", "1"); // index it
        enc.set_peer_max_size(0);
        enc.set_peer_max_size(4096);
        let mut b2 = Vec::new();
        enc.encode_header(&mut b2, "x-a", "1");
        assert_ne!(
            b2[0], 0x20,
            "a transient change that nets to no-op emits nothing"
        );
        assert_eq!(
            b2.len(),
            1,
            "the dynamic entry survived (never actually evicted)"
        );
    }
}
