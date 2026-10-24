//! A streaming compression body: wraps an upstream [`StreamBody`] and emits a
//! compressed stream incrementally, frame by frame, without buffering the whole
//! body.
//!
//! Each codec drives a `std::io::Write` encoder whose sink is an internal
//! `Vec<u8>`. Upstream data frames are accumulated into a small input buffer
//! and written into the encoder + flushed once the buffer reaches
//! [`FLUSH_THRESHOLD`] (#326) — closing a compression block per upstream frame
//! wrecked the ratio and burned encoder CPU on small frames (a 4 KiB-framed
//! render compressed ~30-80% larger than one flushed in 32 KiB batches). SSE
//! (`text/event-stream`) is never compressed (`Compress::plan` refuses it). A
//! proxied feed a client may read as it arrives (`hj_core::ProxiedBody`) also
//! flushes whenever its upstream stalls ([`CompressStream::flush_when_idle`]);
//! local renders batch with no interactivity cost. On upstream
//! end-of-stream any buffered input is written and the encoder is *finished*
//! (its trailer/epilogue emitted). The concatenation of all emitted chunks is
//! a single, complete stream in the chosen coding.

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use flate2::Compression;
use flate2::write::GzEncoder;
use hj_core::{BoxError, StreamBody};
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt;

use std::io::{self, Write};

use std::sync::{Mutex, PoisonError};

use brotli::CompressorWriter as BrotliCompressor;
use zstd::stream::raw::{Encoder as RawZstdEncoder, Operation};
use zstd::stream::zio::Writer as ZioWriter;

use crate::encoding::{Encoding, Levels, zstd_window_log};

/// (#326) Accumulate this many bytes of upstream input before writing them into
/// the encoder and flushing a block. Bounds both the compression-block size
/// (ratio) and the worst-case latency added while a slow upstream fills the
/// buffer; the terminal `finish()` always flushes whatever remains.
const FLUSH_THRESHOLD: usize = 32 * 1024;

thread_local! {
    static STREAM_OUT_LOCAL: std::cell::RefCell<Vec<Vec<u8>>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Encoder sinks and input batches. Every streamed response used to grow fresh
/// ones per block; pooled, they stay resident and each emitted block returns its
/// buffer once the client side has written it.
static STREAM_OUT: hj_core::TieredPool<Vec<u8>> =
    hj_core::TieredPool::new(&STREAM_OUT_LOCAL, 8, 32);

/// Largest pooled sink or batch buffer; a block that grew past it frees it.
const STREAM_OUT_KEEP: usize = 64 * 1024;

/// Initial room for the next encoder sink (compressed output of one batch).
const SINK_ROOM: usize = 16 * 1024;

fn next_sink(input_len: usize) -> Vec<u8> {
    STREAM_OUT.take_buf(input_len.min(SINK_ROOM), SINK_ROOM)
}

fn block_bytes(buf: Vec<u8>) -> Bytes {
    STREAM_OUT.freeze(buf, STREAM_OUT_KEEP)
}
/// Always-ready empty DATA frames make no compression or wire progress. Return
/// `Pending` after this many so a faulty producer cannot monopolize one runtime
/// thread inside a single [`Body::poll_frame`] call.
const READY_EMPTY_YIELD_INTERVAL: usize = 64;

/// A codec-agnostic incremental encoder over a `Vec<u8>` sink. Each call to
/// [`BlockEncoder::write_block`] compresses + flushes a chunk and returns the
/// bytes produced so far; [`BlockEncoder::finish`] consumes the encoder and
/// returns the final trailer/epilogue bytes (mandatory — skipping it truncates
/// the stream).
pub(crate) trait BlockEncoder: Send + Sync {
    /// Compress `buf`, flush, and return any bytes the encoder produced.
    fn write_block(&mut self, buf: &[u8]) -> io::Result<Vec<u8>>;
    /// Finalize the stream, returning the trailing bytes.
    fn finish(self: Box<Self>) -> io::Result<Vec<u8>>;
}

struct GzipEnc(GzEncoder<Vec<u8>>);
impl BlockEncoder for GzipEnc {
    fn write_block(&mut self, buf: &[u8]) -> io::Result<Vec<u8>> {
        self.0.write_all(buf)?;
        self.0.flush()?;
        Ok(std::mem::replace(self.0.get_mut(), next_sink(buf.len())))
    }
    fn finish(self: Box<Self>) -> io::Result<Vec<u8>> {
        let GzipEnc(enc) = *self;
        enc.finish()
    }
}

/// zstd contexts reused across streamed responses. A fresh streaming context at the egress
/// level allocates a multi-MiB window buffer and zeroes its match tables, and under the
/// prod allocator settings those pages are decommitted on free and faulted back in for the
/// next response. Global (not per-thread) and small: streamed responses are a few per second,
/// and a per-thread pool would keep a multi-MiB context resident on every runtime thread.
static ZSTD_STREAM_POOL: Mutex<Vec<(i32, RawZstdEncoder<'static>)>> = Mutex::new(Vec::new());
const ZSTD_STREAM_POOL_CAP: usize = 4;

fn take_zstd_stream_encoder(level: i32) -> io::Result<RawZstdEncoder<'static>> {
    let pooled = {
        let mut pool = ZSTD_STREAM_POOL
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        pool.iter()
            .position(|(l, _)| *l == level)
            .map(|i| pool.swap_remove(i).1)
    };
    if let Some(enc) = pooled {
        return Ok(enc);
    }
    let mut enc = RawZstdEncoder::new(level)?;
    // Pooled per level and kept across `reinit`, so the cap is set once here.
    if let Some(window_log) = zstd_window_log(level) {
        enc.set_parameter(zstd::zstd_safe::CParameter::WindowLog(window_log))?;
    }
    Ok(enc)
}

/// Return a context whose frame finished cleanly; `reinit` resets the session and keeps the
/// level. One dropped mid-stream (client gone) is simply freed.
fn return_zstd_stream_encoder(level: i32, mut enc: RawZstdEncoder<'static>) {
    if enc.reinit().is_err() {
        return;
    }
    let mut pool = ZSTD_STREAM_POOL
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if pool.len() < ZSTD_STREAM_POOL_CAP {
        pool.push((level, enc));
    }
}

/// `zio::Writer` over a pooled raw encoder: the same pairing `zstd::stream::write::Encoder`
/// wraps, so the frames are identical, but `into_inner` hands the context back at the end.
struct ZstdEnc {
    writer: Option<ZioWriter<Vec<u8>, RawZstdEncoder<'static>>>,
    level: i32,
}
impl BlockEncoder for ZstdEnc {
    fn write_block(&mut self, buf: &[u8]) -> io::Result<Vec<u8>> {
        let w = self
            .writer
            .as_mut()
            .expect("zstd stream writer is present until finish");
        w.write_all(buf)?;
        w.flush()?;
        Ok(std::mem::replace(w.writer_mut(), next_sink(buf.len())))
    }
    fn finish(mut self: Box<Self>) -> io::Result<Vec<u8>> {
        let mut w = self
            .writer
            .take()
            .expect("zstd stream writer is present until finish");
        w.finish()?;
        let (sink, enc) = w.into_inner();
        return_zstd_stream_encoder(self.level, enc);
        Ok(sink)
    }
}

struct BrotliEnc(BrotliCompressor<Vec<u8>>);
impl BlockEncoder for BrotliEnc {
    fn write_block(&mut self, buf: &[u8]) -> io::Result<Vec<u8>> {
        self.0.write_all(buf)?;
        self.0.flush()?;
        Ok(std::mem::replace(self.0.get_mut(), next_sink(buf.len())))
    }
    fn finish(self: Box<Self>) -> io::Result<Vec<u8>> {
        // `into_inner` performs the brotli FINISH operation before returning.
        let BrotliEnc(w) = *self;
        Ok(w.into_inner())
    }
}

/// State of the encoder driving an upstream body.
enum EncState {
    /// Actively reading upstream frames and compressing them.
    Active(Box<dyn BlockEncoder>),
    /// Upstream yielded a trailers (non-data) frame while the codec was still active. The codec
    /// has been finished and its epilogue emitted; this frame must be sent NEXT (before EOF) so
    /// the order is [compressed data] → [codec epilogue] → [trailers], never the reverse (a
    /// truncated compressed body + an illegal DATA-after-trailers frame — RFC 7540/9114).
    PendingTrailers(Frame<Bytes>),
    /// Everything has been emitted.
    Done,
}

/// `http_body::Body` adapter that compresses an inner [`StreamBody`] with a
/// chosen [`Encoding`].
pub struct CompressStream {
    inner: StreamBody,
    state: EncState,
    /// (#326) Upstream bytes accumulated but not yet written to the encoder;
    /// flushed as one block once it reaches [`FLUSH_THRESHOLD`] or at EOF.
    pending_in: Vec<u8>,
    /// Emit the first block as soon as the upstream stalls instead of waiting for a
    /// full batch (see [`CompressStream::flush_first_when_idle`]).
    flush_first_when_idle: bool,
    /// Emit the pending block every time the upstream stalls (see
    /// [`CompressStream::flush_when_idle`]).
    flush_when_idle: bool,
    /// Consecutive always-ready empty DATA frames skipped since real payload.
    skipped_empty_frames: usize,
}

impl CompressStream {
    /// Wrap `inner` with an incremental encoder for `enc` at the given `levels`.
    pub fn new(inner: StreamBody, enc: Encoding, levels: &Levels) -> Self {
        let encoder: Box<dyn BlockEncoder> = match enc {
            Encoding::Gzip => Box::new(GzipEnc(GzEncoder::new(
                next_sink(SINK_ROOM),
                Compression::new(levels.gzip),
            ))),
            Encoding::Zstd => Box::new(ZstdEnc {
                writer: Some(ZioWriter::new(
                    next_sink(SINK_ROOM),
                    take_zstd_stream_encoder(levels.zstd)
                        .expect("zstd encoder init is infallible for a valid level"),
                )),
                level: levels.zstd,
            }),
            Encoding::Brotli => Box::new(BrotliEnc(BrotliCompressor::new(
                next_sink(SINK_ROOM),
                4096,
                levels.brotli_q,
                levels.brotli_lgwin,
            ))),
        };
        CompressStream {
            inner,
            state: EncState::Active(encoder),
            pending_in: STREAM_OUT.take_buf(FLUSH_THRESHOLD, FLUSH_THRESHOLD),
            flush_first_when_idle: false,
            flush_when_idle: false,
            skipped_empty_frames: 0,
        }
    }

    /// For a body the backend is still producing (`crate::ProgressiveBody`): its first
    /// bytes usually carry the page head, which a browser acts on before the rest arrives,
    /// so they go out when the upstream first stalls. Later blocks keep the batching.
    pub fn flush_first_when_idle(mut self) -> Self {
        self.flush_first_when_idle = true;
        self
    }

    /// For a proxied feed (`hj_core::ProxiedBody`): a client may be consuming it as it
    /// arrives, so whatever is pending goes out whenever the upstream stalls. A fast
    /// upstream still batches, since nothing is pending-and-idle between its frames.
    pub fn flush_when_idle(mut self) -> Self {
        self.flush_when_idle = true;
        self
    }

    /// Box this into the workspace [`StreamBody`] type.
    pub fn boxed_stream(self) -> StreamBody {
        BodyExt::boxed(self)
    }
}

impl Drop for CompressStream {
    fn drop(&mut self) {
        STREAM_OUT.give_buf(std::mem::take(&mut self.pending_in), STREAM_OUT_KEEP);
    }
}

impl Body for CompressStream {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        loop {
            match &mut self.state {
                EncState::Active(_) => {
                    // Pull the next upstream frame.
                    match Pin::new(&mut self.inner).poll_frame(cx) {
                        Poll::Pending => {
                            if !(self.flush_first_when_idle || self.flush_when_idle)
                                || self.pending_in.is_empty()
                            {
                                return Poll::Pending;
                            }
                            let this = &mut *self;
                            this.flush_first_when_idle = false;
                            let EncState::Active(enc) = &mut this.state else {
                                unreachable!("state is Active in this arm");
                            };
                            let written = enc.write_block(&this.pending_in);
                            this.pending_in.clear();
                            // The upstream registered the waker, so an empty write can wait.
                            return match written {
                                Ok(buf) if buf.is_empty() => Poll::Pending,
                                Ok(buf) => Poll::Ready(Some(Ok(Frame::data(block_bytes(buf))))),
                                Err(e) => Poll::Ready(Some(Err(Box::new(e) as BoxError))),
                            };
                        }
                        Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
                        Poll::Ready(Some(Ok(frame))) => {
                            let data = match frame.into_data() {
                                Ok(d) => d,
                                Err(non_data) => {
                                    // A trailers (non-data) frame. The codec epilogue MUST be
                                    // emitted BEFORE the trailers (and no DATA may follow a
                                    // trailers frame — RFC 7540/9114). Finish the codec now, send
                                    // its epilogue, and stash the trailers for the next poll —
                                    // never forward them with the encoder still open (which would
                                    // truncate the body and emit an illegal post-trailers DATA).
                                    let EncState::Active(mut enc) =
                                        std::mem::replace(&mut self.state, EncState::Done)
                                    else {
                                        unreachable!("state is Active in this arm");
                                    };
                                    // (#326) Drain any buffered input into the encoder, then
                                    // finish; concatenate both outputs into the single terminal
                                    // chunk ([final block][epilogue]) before the trailers.
                                    let pending = std::mem::take(&mut self.pending_in);
                                    let written = if pending.is_empty() {
                                        Ok(Vec::new())
                                    } else {
                                        enc.write_block(&pending)
                                    };
                                    STREAM_OUT.give_buf(pending, STREAM_OUT_KEEP);
                                    let mut out = match written {
                                        Ok(b) => b,
                                        Err(e) => {
                                            return Poll::Ready(Some(Err(Box::new(e) as BoxError)));
                                        }
                                    };
                                    match enc.finish() {
                                        Ok(buf) => {
                                            out.extend_from_slice(&buf);
                                            if out.is_empty() {
                                                // Nothing to emit ⇒ send the trailers now, then EOF.
                                                return Poll::Ready(Some(Ok(non_data)));
                                            }
                                            self.state = EncState::PendingTrailers(non_data);
                                            return Poll::Ready(Some(Ok(Frame::data(
                                                block_bytes(out),
                                            ))));
                                        }
                                        Err(e) => {
                                            return Poll::Ready(Some(Err(Box::new(e) as BoxError)));
                                        }
                                    }
                                }
                            };
                            if data.is_empty() {
                                self.skipped_empty_frames += 1;
                                if self.skipped_empty_frames == READY_EMPTY_YIELD_INTERVAL {
                                    self.skipped_empty_frames = 0;
                                    cx.waker().wake_by_ref();
                                    return Poll::Pending;
                                }
                                continue;
                            }
                            self.skipped_empty_frames = 0;
                            // (#326) Accumulate upstream frames; only compress + flush a block
                            // once FLUSH_THRESHOLD is reached, the upstream stalls on a
                            // `flush_when_idle` feed, or at EOF/trailers. SSE is never routed here.
                            self.pending_in.extend_from_slice(&data);
                            if self.pending_in.len() < FLUSH_THRESHOLD {
                                continue;
                            }
                            let this = &mut *self;
                            this.flush_first_when_idle = false;
                            let EncState::Active(enc) = &mut this.state else {
                                unreachable!("state is Active in this arm");
                            };
                            // Compress in place and keep the batch buffer's capacity: the
                            // next batch refills it instead of regrowing from zero.
                            let written = enc.write_block(&this.pending_in);
                            this.pending_in.clear();
                            match written {
                                Ok(buf) if buf.is_empty() => continue, // encoder buffering
                                Ok(buf) => {
                                    return Poll::Ready(Some(Ok(Frame::data(block_bytes(buf)))));
                                }
                                Err(e) => return Poll::Ready(Some(Err(Box::new(e) as BoxError))),
                            }
                        }
                        Poll::Ready(None) => {
                            // Upstream done: drain buffered input, then finish the compressed
                            // stream; the terminal chunk is [final block][epilogue] concatenated.
                            if let EncState::Active(mut enc) =
                                std::mem::replace(&mut self.state, EncState::Done)
                            {
                                let pending = std::mem::take(&mut self.pending_in);
                                let written = if pending.is_empty() {
                                    Ok(Vec::new())
                                } else {
                                    enc.write_block(&pending)
                                };
                                STREAM_OUT.give_buf(pending, STREAM_OUT_KEEP);
                                let mut out = match written {
                                    Ok(b) => b,
                                    Err(e) => {
                                        return Poll::Ready(Some(Err(Box::new(e) as BoxError)));
                                    }
                                };
                                match enc.finish() {
                                    Ok(buf) => {
                                        out.extend_from_slice(&buf);
                                        if out.is_empty() {
                                            return Poll::Ready(None);
                                        }
                                        return Poll::Ready(Some(Ok(Frame::data(block_bytes(
                                            out,
                                        )))));
                                    }
                                    Err(e) => {
                                        return Poll::Ready(Some(Err(Box::new(e) as BoxError)));
                                    }
                                }
                            }
                            return Poll::Ready(None);
                        }
                    }
                }
                EncState::PendingTrailers(_) => {
                    // The epilogue was already emitted; deliver the stashed trailers, then EOF.
                    if let EncState::PendingTrailers(frame) =
                        std::mem::replace(&mut self.state, EncState::Done)
                    {
                        return Poll::Ready(Some(Ok(frame)));
                    }
                    return Poll::Ready(None);
                }
                EncState::Done => return Poll::Ready(None),
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        matches!(self.state, EncState::Done)
    }

    fn size_hint(&self) -> SizeHint {
        // Compressed length is unknown up front.
        SizeHint::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::read::GzDecoder;
    use http_body_util::{BodyExt, Full};
    use std::io::Read;

    fn gunzip(data: &[u8]) -> Vec<u8> {
        let mut d = GzDecoder::new(data);
        let mut out = Vec::new();
        d.read_to_end(&mut out).unwrap();
        out
    }

    fn unzstd(data: &[u8]) -> Vec<u8> {
        zstd::decode_all(data).unwrap()
    }

    fn unbrotli(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        brotli::Decompressor::new(data, 4096)
            .read_to_end(&mut out)
            .unwrap();
        out
    }

    fn decode(enc: Encoding, data: &[u8]) -> Vec<u8> {
        match enc {
            Encoding::Gzip => gunzip(data),
            Encoding::Zstd => unzstd(data),
            Encoding::Brotli => unbrotli(data),
        }
    }

    fn into_stream_body<B>(b: B) -> StreamBody
    where
        B: Body<Data = Bytes> + Send + Sync + 'static,
        B::Error: std::error::Error + Send + Sync + 'static,
    {
        b.map_err(|e| Box::new(e) as BoxError).boxed()
    }

    async fn compress(enc: Encoding, inner: StreamBody) -> Vec<u8> {
        CompressStream::new(inner, enc, &Levels::default())
            .boxed_stream()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec()
    }

    async fn single_frame(enc: Encoding) {
        let payload = b"hello streaming world ".repeat(50);
        let inner = into_stream_body(Full::new(Bytes::from(payload.clone())));
        let comp = compress(enc, inner).await;
        assert_eq!(decode(enc, &comp), payload, "single-frame {enc:?}");
    }

    async fn multi_frame(enc: Encoding) {
        use futures_like::iter_body;
        let chunks: Vec<Bytes> = (0..10)
            .map(|i| Bytes::from(format!("chunk-{i}-").repeat(40)))
            .collect();
        let expected: Vec<u8> = chunks.iter().flat_map(|c| c.to_vec()).collect();

        let inner = into_stream_body(iter_body(chunks));
        let comp = compress(enc, inner).await;
        assert_eq!(decode(enc, &comp), expected, "multi-frame {enc:?}");
    }

    #[tokio::test]
    async fn ready_empty_frames_yield_before_payload() {
        use futures_like::iter_body;
        use std::task::Waker;

        for enc in [Encoding::Gzip, Encoding::Zstd, Encoding::Brotli] {
            let payload = Bytes::from_static(b"payload after ready empty frames");
            let mut frames = vec![Bytes::new(); READY_EMPTY_YIELD_INTERVAL + 1];
            frames.push(payload.clone());
            let inner = into_stream_body(iter_body(frames));
            let mut body = CompressStream::new(inner, enc, &Levels::default()).boxed_stream();
            let mut cx = Context::from_waker(Waker::noop());

            assert!(
                matches!(Pin::new(&mut body).poll_frame(&mut cx), Poll::Pending),
                "{enc:?}: a long ready empty run must yield before its payload"
            );
            let compressed = body.collect().await.unwrap().to_bytes();
            assert_eq!(decode(enc, &compressed), payload, "{enc:?}");
        }
    }

    #[tokio::test]
    async fn many_ready_empty_frames_reach_clean_eof() {
        use futures_like::iter_body;

        for enc in [Encoding::Gzip, Encoding::Zstd, Encoding::Brotli] {
            let inner = into_stream_body(iter_body(vec![Bytes::new(); 10_000]));
            let compressed =
                tokio::time::timeout(std::time::Duration::from_secs(2), compress(enc, inner))
                    .await
                    .expect("finite empty stream must reach EOF");
            assert!(decode(enc, &compressed).is_empty(), "{enc:?}");
        }
    }

    #[tokio::test]
    async fn gzip_single_frame_round_trips() {
        single_frame(Encoding::Gzip).await;
    }
    #[tokio::test]
    async fn gzip_multi_frame_round_trips() {
        multi_frame(Encoding::Gzip).await;
    }
    #[tokio::test]
    async fn zstd_single_frame_round_trips() {
        single_frame(Encoding::Zstd).await;
    }
    #[tokio::test]
    async fn zstd_multi_frame_round_trips() {
        multi_frame(Encoding::Zstd).await;
    }
    #[tokio::test]
    async fn brotli_single_frame_round_trips() {
        single_frame(Encoding::Brotli).await;
    }
    #[tokio::test]
    async fn brotli_multi_frame_round_trips() {
        multi_frame(Encoding::Brotli).await;
    }

    /// (#497) Streamed zstd responses reuse pooled contexts. A reused context must start a clean
    /// frame: back-to-back responses with the same input produce identical, decodable output
    /// (and match a fresh `zstd::stream::write::Encoder`), and the pool stays capped.
    #[tokio::test]
    async fn pooled_zstd_stream_contexts_start_clean_frames() {
        use futures_like::iter_body;
        let chunks: Vec<Bytes> = (0..40)
            .map(|i| Bytes::from(format!("<div class=\"row-{i}\">stream</div>").repeat(60)))
            .collect();
        let expected: Vec<u8> = chunks.iter().flat_map(|c| c.to_vec()).collect();
        let first = compress(Encoding::Zstd, into_stream_body(iter_body(chunks.clone()))).await;
        let second = compress(Encoding::Zstd, into_stream_body(iter_body(chunks.clone()))).await;
        assert_eq!(unzstd(&first), expected);
        assert_eq!(
            first, second,
            "a reused context must not carry state between frames"
        );
        assert!(ZSTD_STREAM_POOL.lock().unwrap().len() <= ZSTD_STREAM_POOL_CAP);
    }

    async fn compress_zstd_at(level: i32, payload: &[u8]) -> Vec<u8> {
        let levels = Levels {
            zstd: level,
            ..Levels::default()
        };
        let inner = into_stream_body(Full::new(Bytes::copy_from_slice(payload)));
        CompressStream::new(inner, Encoding::Zstd, &levels)
            .boxed_stream()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec()
    }

    /// Regression (#1020): a streamed frame has no content size, so levels 20-22
    /// declared their full 32-128 MiB window, past RFC 9659's 8 MiB decoder limit.
    #[tokio::test]
    async fn ultra_zstd_stream_fits_the_http_window() {
        let payload = b"<p>ultra level stream</p>".repeat(400);
        for level in [20, 22, 22] {
            let frame = compress_zstd_at(level, &payload).await;
            let mut dec = zstd::stream::read::Decoder::new(&frame[..]).unwrap();
            dec.window_log_max(23).unwrap();
            let mut out = Vec::new();
            dec.read_to_end(&mut out)
                .expect("frame fits an 8 MiB window");
            assert_eq!(out, payload, "level {level}");
        }
    }

    /// Through level 19 the streamed frame keeps zstd's own parameters: it is the
    /// frame a fresh `zstd::stream::write::Encoder` writes for the same
    /// write/flush/finish sequence.
    #[tokio::test]
    async fn zstd_stream_bytes_unchanged_through_level_19() {
        use std::io::Write;
        let payload = b"<div class=\"row\">unchanged frame</div>".repeat(300);
        for level in [1, 3, 9, 19] {
            let mut reference = zstd::stream::write::Encoder::new(Vec::new(), level).unwrap();
            reference.write_all(&payload).unwrap();
            reference.flush().unwrap();
            let want = reference.finish().unwrap();
            assert_eq!(
                compress_zstd_at(level, &payload).await,
                want,
                "level {level}"
            );
        }
    }

    /// (#326) Many small upstream frames must (a) still round-trip exactly, and
    /// (b) compress better than the old per-frame-flush shape did, because the
    /// input is now batched into >=FLUSH_THRESHOLD blocks before a flush.
    #[tokio::test]
    async fn small_frames_are_batched_before_flush() {
        use futures_like::iter_body;
        // ~256 KiB of compressible HTML delivered in 1 KiB frames — the shape
        // (small LSAPI DATA frames) that made per-frame flush expensive.
        let unit = b"<div class=\"message\"><a href=\"/t/x.1/\">reply</a> user time</div>\n";
        let mut whole = Vec::new();
        while whole.len() < 256 * 1024 {
            whole.extend_from_slice(unit);
        }
        let chunks: Vec<Bytes> = whole.chunks(1024).map(Bytes::copy_from_slice).collect();
        let frame_count = chunks.len();

        for enc in [Encoding::Gzip, Encoding::Zstd, Encoding::Brotli] {
            let inner = into_stream_body(iter_body(chunks.clone()));
            let comp = compress(enc, inner).await;
            assert_eq!(decode(enc, &comp), whole, "batched round-trip {enc:?}");

            // Reference: the pre-#326 per-frame-flush encoding of the same frames.
            let mut per_frame: Box<dyn BlockEncoder> = match enc {
                Encoding::Gzip => {
                    Box::new(GzipEnc(GzEncoder::new(Vec::new(), Compression::new(6))))
                }
                Encoding::Zstd => Box::new(ZstdEnc {
                    writer: Some(ZioWriter::new(Vec::new(), RawZstdEncoder::new(3).unwrap())),
                    level: 3,
                }),
                Encoding::Brotli => {
                    Box::new(BrotliEnc(BrotliCompressor::new(Vec::new(), 4096, 5, 19)))
                }
            };
            let mut ref_len = 0usize;
            for c in &chunks {
                ref_len += per_frame.write_block(c).unwrap().len();
            }
            ref_len += per_frame.finish().unwrap().len();

            assert!(
                comp.len() < ref_len,
                "{enc:?}: batched {} B should beat per-frame {} B over {} frames",
                comp.len(),
                ref_len,
                frame_count
            );
        }
    }

    #[derive(Debug)]
    enum Ev {
        Data(Bytes),
        Trailers(http::HeaderMap),
    }

    /// Drive a body to EOF synchronously (our test bodies are always Ready), recording the
    /// ORDERED sequence of frames so we can assert no DATA follows a trailers frame.
    fn drive(mut body: StreamBody) -> Vec<Ev> {
        use std::task::{Context, Poll, Waker};
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut out = Vec::new();
        loop {
            match Pin::new(&mut body).poll_frame(&mut cx) {
                Poll::Ready(Some(Ok(f))) => {
                    if let Some(d) = f.data_ref() {
                        out.push(Ev::Data(d.clone()));
                    } else if let Some(t) = f.trailers_ref() {
                        out.push(Ev::Trailers(t.clone()));
                    }
                }
                Poll::Ready(Some(Err(e))) => panic!("unexpected stream error: {e}"),
                Poll::Ready(None) => break,
                Poll::Pending => panic!("test bodies are always ready"),
            }
        }
        out
    }

    struct DataThenTrailers {
        chunks: std::collections::VecDeque<Bytes>,
        trailers: Option<http::HeaderMap>,
    }
    impl Body for DataThenTrailers {
        type Data = Bytes;
        type Error = std::convert::Infallible;
        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            if let Some(b) = self.chunks.pop_front() {
                return Poll::Ready(Some(Ok(Frame::data(b))));
            }
            if let Some(t) = self.trailers.take() {
                return Poll::Ready(Some(Ok(Frame::trailers(t))));
            }
            Poll::Ready(None)
        }
    }

    #[test]
    fn trailers_emitted_after_codec_epilogue() {
        // Regression (#89): when the upstream carries HTTP trailers, the codec epilogue MUST be
        // emitted BEFORE the trailers and no DATA may follow them — otherwise the compressed body
        // is truncated (epilogue stranded behind the trailers) and a DATA-after-trailers frame is
        // illegal (RFC 7540/9114). Assert for every codec: trailers are the LAST frame, and the
        // concatenated DATA still round-trips (proving the epilogue was emitted, not stranded).
        for enc in [Encoding::Gzip, Encoding::Zstd, Encoding::Brotli] {
            let payload = b"compress me then a trailer ".repeat(40);
            let mut tr = http::HeaderMap::new();
            tr.insert("x-checksum", http::HeaderValue::from_static("abc123"));
            let inner = into_stream_body(DataThenTrailers {
                chunks: std::iter::once(Bytes::from(payload.clone())).collect(),
                trailers: Some(tr),
            });
            let evs = drive(CompressStream::new(inner, enc, &Levels::default()).boxed_stream());

            let tpos = evs
                .iter()
                .position(|e| matches!(e, Ev::Trailers(_)))
                .unwrap_or_else(|| panic!("{enc:?}: trailers must be preserved"));
            assert_eq!(
                tpos,
                evs.len() - 1,
                "{enc:?}: no frame may follow the trailers"
            );
            assert_eq!(
                evs.iter().filter(|e| matches!(e, Ev::Trailers(_))).count(),
                1,
                "{enc:?}: exactly one trailers frame"
            );

            let data: Vec<u8> = evs
                .iter()
                .filter_map(|e| {
                    if let Ev::Data(b) = e {
                        Some(b.to_vec())
                    } else {
                        None
                    }
                })
                .flatten()
                .collect();
            assert_eq!(
                decode(enc, &data),
                payload,
                "{enc:?}: body must round-trip (epilogue not stranded behind trailers)"
            );
            if let Ev::Trailers(t) = &evs[tpos] {
                assert_eq!(
                    t.get("x-checksum").unwrap(),
                    "abc123",
                    "{enc:?}: trailer preserved"
                );
            }
        }
    }

    /// Yields `first`, stalls once, then yields `rest` and ends.
    struct StallAfterFirst {
        step: u8,
        first: Bytes,
        rest: Bytes,
    }
    impl Body for StallAfterFirst {
        type Data = Bytes;
        type Error = std::convert::Infallible;
        fn poll_frame(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            self.step += 1;
            match self.step {
                1 => Poll::Ready(Some(Ok(Frame::data(self.first.clone())))),
                2 => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                3 => Poll::Ready(Some(Ok(Frame::data(self.rest.clone())))),
                _ => Poll::Ready(None),
            }
        }
    }

    #[test]
    fn progressive_body_emits_its_first_block_when_the_upstream_stalls() {
        use std::task::Waker;
        let first = Bytes::from(b"<head>early</head>".repeat(100));
        let rest = Bytes::from(b"<p>late body</p>".repeat(3000));
        for (idle_flush, expect_early) in [(true, true), (false, false)] {
            let inner = into_stream_body(StallAfterFirst {
                step: 0,
                first: first.clone(),
                rest: rest.clone(),
            });
            let stream = CompressStream::new(inner, Encoding::Zstd, &Levels::default());
            let mut body = if idle_flush {
                stream.flush_first_when_idle()
            } else {
                stream
            }
            .boxed_stream();
            let mut cx = Context::from_waker(Waker::noop());
            let first_poll = Pin::new(&mut body).poll_frame(&mut cx);
            assert_eq!(
                matches!(first_poll, Poll::Ready(Some(Ok(_)))),
                expect_early,
                "idle_flush={idle_flush}: first block before the stall ends"
            );
            let mut out = match first_poll {
                Poll::Ready(Some(Ok(f))) => f.into_data().unwrap().to_vec(),
                _ => Vec::new(),
            };
            loop {
                match Pin::new(&mut body).poll_frame(&mut cx) {
                    Poll::Ready(Some(Ok(f))) => out.extend_from_slice(&f.into_data().unwrap()),
                    Poll::Ready(None) => break,
                    Poll::Ready(Some(Err(e))) => panic!("stream error: {e}"),
                    Poll::Pending => panic!("only the first poll stalls"),
                }
            }
            let expected: Vec<u8> = [first.as_ref(), rest.as_ref()].concat();
            assert_eq!(unzstd(&out), expected, "idle_flush={idle_flush}");
        }
    }

    /// An upstream that stalls between each of its frames.
    struct StallBetween {
        frames: Vec<Bytes>,
        stalled: bool,
    }

    impl Body for StallBetween {
        type Data = Bytes;
        type Error = std::convert::Infallible;
        fn poll_frame(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            if self.frames.is_empty() {
                return Poll::Ready(None);
            }
            if !self.stalled {
                self.stalled = true;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            self.stalled = false;
            Poll::Ready(Some(Ok(Frame::data(self.frames.remove(0)))))
        }
    }

    /// Regression (#889): a proxied feed's small bursts each reach the client when
    /// the upstream stalls, not batched until EOF.
    #[test]
    fn proxied_feed_flushes_every_burst_when_the_upstream_stalls() {
        use std::task::Waker;
        let lines: Vec<Bytes> = (0..3)
            .map(|i| Bytes::from(format!("token line {i}\n")))
            .collect();
        let inner = into_stream_body(StallBetween {
            frames: lines.clone(),
            stalled: true,
        });
        let mut body = CompressStream::new(inner, Encoding::Gzip, &Levels::default())
            .flush_when_idle()
            .boxed_stream();
        let mut cx = Context::from_waker(Waker::noop());
        let mut out = Vec::new();
        let mut early_blocks = 0;
        loop {
            match Pin::new(&mut body).poll_frame(&mut cx) {
                Poll::Ready(Some(Ok(f))) => {
                    out.extend_from_slice(&f.into_data().unwrap());
                    early_blocks += 1;
                }
                Poll::Ready(None) => break,
                Poll::Ready(Some(Err(e))) => panic!("stream error: {e}"),
                Poll::Pending => {}
            }
        }
        assert!(early_blocks >= 3, "each burst flushed: {early_blocks}");
        let mut plain = Vec::new();
        flate2::read::GzDecoder::new(out.as_slice())
            .read_to_end(&mut plain)
            .unwrap();
        assert_eq!(plain, lines.concat());
    }

    /// Minimal frame-stream helper to avoid pulling in `futures` as a dep.
    mod futures_like {
        use super::*;
        use std::collections::VecDeque;

        pub fn iter_body(chunks: Vec<Bytes>) -> IterBody {
            IterBody {
                chunks: chunks.into(),
            }
        }

        pub struct IterBody {
            chunks: VecDeque<Bytes>,
        }

        impl Body for IterBody {
            type Data = Bytes;
            type Error = std::convert::Infallible;

            fn poll_frame(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
                match self.chunks.pop_front() {
                    Some(b) => Poll::Ready(Some(Ok(Frame::data(b)))),
                    None => Poll::Ready(None),
                }
            }
        }
    }
}
