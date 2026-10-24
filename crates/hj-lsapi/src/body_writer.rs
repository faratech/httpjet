//! Request-body writer for bodies PHP may leave partly unread.
//!
//! lsphp parses an unread body tail as its next BEGIN_REQUEST. This writer scans
//! every body offset with [`classify_begin_request`] and stops before writing the
//! bytes that would complete a request lsphp could accept.
//!
//! The scan alone assumes lsphp reads the tail contiguously. `readReq` reads the
//! packet header into the start of its buffer on every pass (vendor/lsapilib.c),
//! so when its first read returns fewer than 8 bytes, the next read lands on top
//! of them and the request starts at whatever byte began that next write. The
//! writer therefore never begins a write with bytes that could open a request
//! unless the write also carries the whole 44-byte fixed header (which the scan
//! has judged), and it keeps the final 44 bytes for the last write. Writes are
//! capped well below the kernel's unix-socket skb size, so each one reaches
//! lsphp's receive queue whole.

use std::io::{self, IoSlice};

use bytes::{Buf, Bytes, BytesMut};
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::proto::{BeginVerdict, REQ_HEADER_LEN, classify_begin_request, magic_offsets};

const MAX_WRITE: usize = 16 * 1024;

/// Bytes before a chunk whose request-start windows reach into it.
const CARRY: usize = REQ_HEADER_LEN - 1;

#[derive(Debug)]
pub(crate) enum BodyWriteError {
    /// The body holds bytes lsphp could run as a new request; nothing from the
    /// offending chunk was written.
    EmbeddedBegin,
    Io(io::Error),
}

pub(crate) struct ScannedBodyWriter {
    body_len: u64,
    received: u64,
    written: u64,
    /// Received but not yet written: body bytes `written..received`.
    held: BytesMut,
    /// The last bytes received before the next chunk.
    carry: [u8; CARRY],
    carry_len: usize,
}

impl ScannedBodyWriter {
    pub(crate) fn new(body_len: u64) -> Self {
        Self {
            body_len,
            received: 0,
            written: 0,
            held: BytesMut::new(),
            carry: [0; CARRY],
            carry_len: 0,
        }
    }

    /// Scan `chunk`, then write as much of the body received so far as is safe.
    pub(crate) async fn push<W: AsyncWrite + Unpin>(
        &mut self,
        out: &mut W,
        chunk: Bytes,
    ) -> Result<(), BodyWriteError> {
        if self.scan(&chunk) {
            return Err(BodyWriteError::EmbeddedBegin);
        }
        self.received += chunk.len() as u64;
        let complete = self.received >= self.body_len;
        let limit = if complete {
            self.received
        } else {
            self.received
                .min(self.body_len.saturating_sub(REQ_HEADER_LEN as u64))
        };
        let len = limit.saturating_sub(self.written) as usize;
        if len == 0 || (!complete && len < REQ_HEADER_LEN && self.opens_request(&chunk, len)) {
            self.held.extend_from_slice(&chunk);
            return Ok(());
        }
        let (held_now, _) = split(&self.held, len);
        let (chunk_now, chunk_later) = split(&chunk, len - held_now.len());
        write_split(out, held_now, chunk_now)
            .await
            .map_err(BodyWriteError::Io)?;
        self.written = limit;
        let written_from_held = held_now.len();
        self.held.advance(written_from_held);
        self.held.extend_from_slice(chunk_later);
        Ok(())
    }

    /// Whether `chunk`, with the bytes before it, completes a request lsphp
    /// could accept. A window cut short by the end of the body is harmless:
    /// lsphp would wait for bytes that never come.
    fn scan(&mut self, chunk: &[u8]) -> bool {
        let carried = self.carry.get(..self.carry_len).unwrap_or_default();
        let mut seam = [0u8; CARRY + REQ_HEADER_LEN];
        let seam = gather(
            &mut seam,
            carried.iter().chain(chunk.iter().take(REQ_HEADER_LEN)),
        );
        let frame_at = |bytes: &[u8], at: usize| {
            bytes
                .get(at..)
                .is_some_and(|window| classify_begin_request(window) == BeginVerdict::Frame)
        };
        let found = (0..carried.len()).any(|at| frame_at(seam, at))
            || magic_offsets(chunk).any(|at| frame_at(chunk, at));
        let tail: &[u8] = if chunk.len() >= CARRY { chunk } else { seam };
        let mut carry = [0u8; CARRY];
        let kept = gather(
            &mut carry,
            tail.iter().skip(tail.len().saturating_sub(CARRY)),
        )
        .len();
        self.carry = carry;
        self.carry_len = kept;
        found
    }

    /// Whether the next `len` unwritten bytes (`held` then `chunk`), written on
    /// their own, could open a request.
    fn opens_request(&self, chunk: &[u8], len: usize) -> bool {
        let mut window = [0u8; REQ_HEADER_LEN];
        let window = gather(&mut window, self.held.iter().chain(chunk).take(len));
        classify_begin_request(window) != BeginVerdict::Clean
    }
}

/// Copy `bytes` into `buf` (as many as fit) and return the filled prefix.
fn gather<'a, 'b>(buf: &'a mut [u8], bytes: impl Iterator<Item = &'b u8>) -> &'a [u8] {
    let mut filled = 0;
    for (slot, &byte) in buf.iter_mut().zip(bytes) {
        *slot = byte;
        filled += 1;
    }
    buf.get(..filled).unwrap_or_default()
}

/// `bytes` split at `at`, or whole when `at` is past its end.
fn split(bytes: &[u8], at: usize) -> (&[u8], &[u8]) {
    bytes.split_at_checked(at).unwrap_or((bytes, &[]))
}

/// Write `head` then `tail` in writes of at most `MAX_WRITE` bytes, folding a
/// remainder shorter than the request header into the write before it.
async fn write_split<W: AsyncWrite + Unpin>(
    out: &mut W,
    mut head: &[u8],
    mut tail: &[u8],
) -> io::Result<()> {
    while !head.is_empty() || !tail.is_empty() {
        let total = head.len() + tail.len();
        let mut piece = total.min(MAX_WRITE);
        if total - piece < REQ_HEADER_LEN {
            piece = total;
        }
        let (head_now, head_later) = split(head, piece);
        let (tail_now, tail_later) = split(tail, piece - head_now.len());
        write_whole(out, head_now, tail_now).await?;
        head = head_later;
        tail = tail_later;
    }
    Ok(())
}

async fn write_whole<W: AsyncWrite + Unpin>(
    out: &mut W,
    mut head: &[u8],
    mut tail: &[u8],
) -> io::Result<()> {
    while !head.is_empty() || !tail.is_empty() {
        let n = if head.is_empty() {
            out.write(tail).await?
        } else {
            out.write_vectored(&[IoSlice::new(head), IoSlice::new(tail)])
                .await?
        };
        if n == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        let from_head = n.min(head.len());
        head = split(head, from_head).1;
        tail = split(tail, n - from_head).1;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::build_begin_request_framed;

    /// Records every write so the tests can check what reached the socket and
    /// where each write started.
    #[derive(Default)]
    struct Recorder {
        bytes: Vec<u8>,
        writes: Vec<std::ops::Range<usize>>,
    }

    impl AsyncWrite for Recorder {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            let start = self.bytes.len();
            self.bytes.extend_from_slice(buf);
            self.writes.push(start..start + buf.len());
            std::task::Poll::Ready(Ok(buf.len()))
        }

        fn poll_write_vectored(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            bufs: &[IoSlice<'_>],
        ) -> std::task::Poll<io::Result<usize>> {
            let start = self.bytes.len();
            for buf in bufs {
                self.bytes.extend_from_slice(buf);
            }
            let end = self.bytes.len();
            self.writes.push(start..end);
            std::task::Poll::Ready(Ok(end - start))
        }

        fn is_write_vectored(&self) -> bool {
            true
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    fn forged() -> Bytes {
        let env = [("SCRIPT_FILENAME", "/tmp/x.php"), ("REQUEST_METHOD", "GET")];
        build_begin_request_framed::<_, _, (&str, &str)>(&env, &[], &[], 0)
    }

    async fn feed(body: &[u8], cuts: &[usize]) -> (Result<(), BodyWriteError>, Recorder) {
        let mut writer = ScannedBodyWriter::new(body.len() as u64);
        let mut out = Recorder::default();
        let mut at = 0;
        for &cut in cuts.iter().chain([&body.len()]) {
            if cut <= at {
                continue;
            }
            let chunk = Bytes::copy_from_slice(&body[at..cut]);
            at = cut;
            if let Err(e) = writer.push(&mut out, chunk).await {
                return (Err(e), out);
            }
        }
        (Ok(()), out)
    }

    fn assert_no_request_start(out: &Recorder, body_len: usize) {
        for write in &out.writes {
            let start = &out.bytes[write.clone()];
            let window = &start[..start.len().min(REQ_HEADER_LEN)];
            assert!(
                write.len() >= REQ_HEADER_LEN
                    || classify_begin_request(window) == BeginVerdict::Clean
                    || write.end == body_len,
                "write {write:?} could open a request: {window:?}"
            );
            assert!(write.len() <= MAX_WRITE + REQ_HEADER_LEN, "{write:?}");
        }
    }

    #[tokio::test]
    async fn forged_frame_never_reaches_the_writer() {
        let frame = forged();
        for at in [0, 1, 3072, 8191, 8192, 24576, 40_000] {
            let mut body = vec![b'A'; at];
            body.extend_from_slice(&frame);
            body.extend_from_slice(&[b'z'; 100]);
            let frame_end = at + frame.len();
            let mut cut_sets: Vec<Vec<usize>> = vec![vec![], vec![at], vec![at + 1]];
            for split in [3, 7, 8, 20, 43, 44, 45] {
                cut_sets.push(vec![at + split]);
                cut_sets.push(vec![at.saturating_sub(5), at + split]);
            }
            cut_sets.push((0..body.len()).collect());
            cut_sets.push((0..body.len()).step_by(16 * 1024 + 7).collect());
            for cuts in cut_sets {
                let (result, out) = feed(&body, &cuts).await;
                assert!(
                    matches!(result, Err(BodyWriteError::EmbeddedBegin)),
                    "at {at} cuts {:?}: {result:?}",
                    &cuts[..cuts.len().min(4)]
                );
                // lsphp needs the frame's header (and all of a short packet) to
                // accept it; never deliver that much of it.
                assert!(
                    out.bytes.len() < at + REQ_HEADER_LEN.min(frame.len()),
                    "at {at}: {} bytes written, frame at {at}..{frame_end}",
                    out.bytes.len()
                );
                assert_eq!(&out.bytes[..], &body[..out.bytes.len()]);
                assert_no_request_start(&out, body.len());
            }
        }
    }

    #[tokio::test]
    async fn clean_bodies_arrive_whole_in_safe_writes() {
        let mut state = 0x2545_f491_4f6c_dd1d_u64;
        let mut random = vec![0u8; 300_000];
        for byte in random.iter_mut() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = state as u8;
        }
        // Plant request-looking prefixes that lsphp would refuse.
        for at in (1000..random.len() - 100).step_by(9973) {
            random[at..at + 3].copy_from_slice(b"LS\x01");
        }
        let lengths = [0, 1, 7, 43, 44, 45, 87, 88, 1000, 16 * 1024, 70_000];
        for len in lengths {
            let body = &random[..len];
            let cut_sets: Vec<Vec<usize>> = vec![
                vec![],
                (0..len).collect(),
                (0..len).step_by(5).collect(),
                (0..len).step_by(4096).collect(),
                vec![len.saturating_sub(1)],
                vec![len.saturating_sub(44)],
            ];
            for cuts in cut_sets {
                let (result, out) = feed(body, &cuts).await;
                result.unwrap();
                assert_eq!(&out.bytes[..], body, "len {len}");
                assert_no_request_start(&out, len);
            }
        }
    }

    #[tokio::test]
    async fn a_lone_request_prefix_waits_for_more_bytes() {
        let mut body = vec![b'A'; 100];
        body.extend_from_slice(b"L");
        body.extend_from_slice(&[b'B'; 100]);
        let mut writer = ScannedBodyWriter::new(body.len() as u64);
        let mut out = Recorder::default();
        writer
            .push(&mut out, Bytes::copy_from_slice(&body[..100]))
            .await
            .unwrap();
        writer
            .push(&mut out, Bytes::copy_from_slice(&body[100..101]))
            .await
            .unwrap();
        assert_eq!(out.bytes.len(), 100, "a write starting with L must wait");
        writer
            .push(&mut out, Bytes::copy_from_slice(&body[101..]))
            .await
            .unwrap();
        assert_eq!(&out.bytes[..], &body[..]);
        assert_eq!(out.writes[1].start, 100);
        assert!(out.writes[1].len() >= REQ_HEADER_LEN);
    }
}
