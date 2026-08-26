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
//! (`text/event-stream`) is never compressed (`Compress::plan` refuses it), so
//! this streaming encoder only ever handles bodies — large HTML/JSON renders,
//! proxied downloads — that no client consumes block-by-block, making the
//! bounded batching a pure win with no interactivity regression. On upstream
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

use brotli::CompressorWriter as BrotliCompressor;
use zstd::stream::write::Encoder as ZstdEncoder;

use crate::encoding::{Encoding, Levels};

/// (#326) Accumulate this many bytes of upstream input before writing them into
/// the encoder and flushing a block. Bounds both the compression-block size
/// (ratio) and the worst-case latency added while a slow upstream fills the
/// buffer; the terminal `finish()` always flushes whatever remains.
const FLUSH_THRESHOLD: usize = 32 * 1024;

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
        let out = std::mem::take(self.0.get_mut());
        // `take` left the encoder's sink at zero capacity; pre-grow it so the NEXT
        // streamed frame doesn't reallocate from scratch (each PHP DATA frame would
        // otherwise force a fresh Vec). Capped at 16 KiB to bound over-allocation.
        self.0.get_mut().reserve(buf.len().min(16 * 1024));
        Ok(out)
    }
    fn finish(self: Box<Self>) -> io::Result<Vec<u8>> {
        let GzipEnc(enc) = *self;
        enc.finish()
    }
}

struct ZstdEnc(ZstdEncoder<'static, Vec<u8>>);
impl BlockEncoder for ZstdEnc {
    fn write_block(&mut self, buf: &[u8]) -> io::Result<Vec<u8>> {
        self.0.write_all(buf)?;
        self.0.flush()?;
        let out = std::mem::take(self.0.get_mut());
        // `take` left the encoder's sink at zero capacity; pre-grow it so the NEXT
        // streamed frame doesn't reallocate from scratch (each PHP DATA frame would
        // otherwise force a fresh Vec). Capped at 16 KiB to bound over-allocation.
        self.0.get_mut().reserve(buf.len().min(16 * 1024));
        Ok(out)
    }
    fn finish(self: Box<Self>) -> io::Result<Vec<u8>> {
        let ZstdEnc(enc) = *self;
        enc.finish()
    }
}

struct BrotliEnc(BrotliCompressor<Vec<u8>>);
impl BlockEncoder for BrotliEnc {
    fn write_block(&mut self, buf: &[u8]) -> io::Result<Vec<u8>> {
        self.0.write_all(buf)?;
        self.0.flush()?;
        let out = std::mem::take(self.0.get_mut());
        // `take` left the encoder's sink at zero capacity; pre-grow it so the NEXT
        // streamed frame doesn't reallocate from scratch (each PHP DATA frame would
        // otherwise force a fresh Vec). Capped at 16 KiB to bound over-allocation.
        self.0.get_mut().reserve(buf.len().min(16 * 1024));
        Ok(out)
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
}

impl CompressStream {
    /// Wrap `inner` with an incremental encoder for `enc` at the given `levels`.
    pub fn new(inner: StreamBody, enc: Encoding, levels: &Levels) -> Self {
        let encoder: Box<dyn BlockEncoder> = match enc {
            Encoding::Gzip => Box::new(GzipEnc(GzEncoder::new(
                Vec::new(),
                Compression::new(levels.gzip),
            ))),
            Encoding::Zstd => Box::new(ZstdEnc(
                ZstdEncoder::new(Vec::new(), levels.zstd)
                    .expect("zstd encoder init over a Vec sink is infallible for a valid level"),
            )),
            Encoding::Brotli => Box::new(BrotliEnc(BrotliCompressor::new(
                Vec::new(),
                4096,
                levels.brotli_q,
                levels.brotli_lgwin,
            ))),
        };
        CompressStream {
            inner,
            state: EncState::Active(encoder),
            pending_in: Vec::new(),
        }
    }

    /// Box this into the workspace [`StreamBody`] type.
    pub fn boxed_stream(self) -> StreamBody {
        BodyExt::boxed(self)
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
                        Poll::Pending => return Poll::Pending,
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
                                    let mut out = if pending.is_empty() {
                                        Vec::new()
                                    } else {
                                        match enc.write_block(&pending) {
                                            Ok(b) => b,
                                            Err(e) => {
                                                return Poll::Ready(Some(Err(
                                                    Box::new(e) as BoxError
                                                )));
                                            }
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
                                                Bytes::from(out),
                                            ))));
                                        }
                                        Err(e) => {
                                            return Poll::Ready(Some(Err(Box::new(e) as BoxError)));
                                        }
                                    }
                                }
                            };
                            if data.is_empty() {
                                continue;
                            }
                            // (#326) Accumulate upstream frames; only compress + flush a block
                            // once FLUSH_THRESHOLD is reached (or at EOF/trailers). SSE is never
                            // routed here, so no client is waiting on a sub-threshold frame.
                            self.pending_in.extend_from_slice(&data);
                            if self.pending_in.len() < FLUSH_THRESHOLD {
                                continue;
                            }
                            let batch = std::mem::take(&mut self.pending_in);
                            let EncState::Active(enc) = &mut self.state else {
                                unreachable!("state is Active in this arm");
                            };
                            match enc.write_block(&batch) {
                                Ok(buf) if buf.is_empty() => continue, // encoder buffering
                                Ok(buf) => {
                                    return Poll::Ready(Some(Ok(Frame::data(Bytes::from(buf)))));
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
                                let mut out = if pending.is_empty() {
                                    Vec::new()
                                } else {
                                    match enc.write_block(&pending) {
                                        Ok(b) => b,
                                        Err(e) => {
                                            return Poll::Ready(Some(Err(Box::new(e) as BoxError)));
                                        }
                                    }
                                };
                                match enc.finish() {
                                    Ok(buf) => {
                                        out.extend_from_slice(&buf);
                                        if out.is_empty() {
                                            return Poll::Ready(None);
                                        }
                                        return Poll::Ready(Some(Ok(Frame::data(Bytes::from(
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
                Encoding::Zstd => Box::new(ZstdEnc(ZstdEncoder::new(Vec::new(), 3).unwrap())),
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
