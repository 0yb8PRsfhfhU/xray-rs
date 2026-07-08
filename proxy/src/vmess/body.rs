//! VMess AEAD chunk-body codec: per-direction framing with optional SHAKE128
//! length masking and global padding. Pure framing logic over `AsyncRead`/
//! `AsyncWrite`; the handler only constructs a `Body` and relays through it.

use std::io;

use bytes::{Bytes, BytesMut};
use shake::digest::{ExtendableOutput, Update as _, XofReader};
use shake::{Shake128, Shake128Reader};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use kernel::ConnectionPolicy;

use crate::SharedDialer;
use crate::crypto::{Aead, AeadKind};
use crate::io::{ChunkRead, ChunkWrite};

struct ShakeParser {
    reader: Shake128Reader,
}

impl ShakeParser {
    fn new(iv: &[u8]) -> ShakeParser {
        let mut shake = Shake128::default();
        shake.update(iv);
        ShakeParser {
            reader: shake.finalize_xof(),
        }
    }
    fn next_u16(&mut self) -> u16 {
        let mut b = [0u8; 2];
        self.reader.read(&mut b);
        u16::from_be_bytes(b)
    }
}

/// AEAD chunk body state for one direction.
pub(crate) struct Body {
    aead: Option<Aead>,
    iv: [u8; 16],
    count: u16,
    shake: Option<ShakeParser>,
    global_padding: bool,
}

impl Body {
    /// Build a per-direction codec. `masking` enables SHAKE128 length masking
    /// (and is the prerequisite for global padding); the stream is seeded by `iv`.
    pub(crate) fn new(
        aead: Option<Aead>,
        iv: [u8; 16],
        masking: bool,
        global_padding: bool,
    ) -> Body {
        Body {
            aead,
            iv,
            count: 0,
            shake: masking.then(|| ShakeParser::new(&iv)),
            global_padding,
        }
    }

    fn overhead(&self) -> usize {
        if self.aead.is_some() {
            AeadKind::TAG
        } else {
            0
        }
    }

    fn chunk_nonce(&self) -> [u8; 12] {
        let mut n = [0u8; 12];
        let cb = self.count.to_be_bytes();
        if let Some(dst) = n.get_mut(..2) {
            dst.copy_from_slice(&cb);
        }
        if let (Some(dst), Some(src)) = (n.get_mut(2..12), self.iv.get(2..12)) {
            dst.copy_from_slice(src);
        }
        n
    }

    /// Random padding length for the next frame. Global-padding mode draws it
    /// from the SHAKE stream, so it is zero whenever masking (the stream) is off.
    fn next_padding(&mut self) -> usize {
        if self.global_padding {
            self.shake
                .as_mut()
                .map_or(0, |s| usize::from(s.next_u16() % 64))
        } else {
            0
        }
    }

    /// SHAKE length masking. XOR is symmetric, so this both masks (write) and
    /// unmasks (read) a frame size; a no-op when masking is disabled.
    fn mask_size(&mut self, size: u16) -> u16 {
        match self.shake.as_mut() {
            Some(s) => s.next_u16() ^ size,
            None => size,
        }
    }

    /// Seal one outbound body piece (or pass it through when security=none),
    /// then advance the per-direction chunk counter.
    fn seal_piece(&mut self, piece: &[u8]) -> io::Result<Vec<u8>> {
        let ct = match &self.aead {
            Some(aead) => {
                let nonce = self.chunk_nonce();
                aead.seal(&nonce, piece).map_err(io::Error::other)?
            }
            None => piece.to_vec(),
        };
        self.count = self.count.wrapping_add(1);
        Ok(ct)
    }

    /// Open one inbound body piece (or pass it through when security=none),
    /// then advance the per-direction chunk counter.
    fn open_piece(&mut self, ct: &[u8]) -> io::Result<Vec<u8>> {
        let plain = match &self.aead {
            Some(aead) => {
                let nonce = self.chunk_nonce();
                aead.open(&nonce, ct)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
            }
            None => ct.to_vec(),
        };
        self.count = self.count.wrapping_add(1);
        Ok(plain)
    }

    /// Frame a sealed piece on the wire: masked length prefix, ciphertext, then
    /// random padding. `padding` must come from a preceding `next_padding()` so
    /// the SHAKE stream stays ordered as (padding, length) per frame.
    fn encode_frame(&mut self, ct: &[u8], padding: usize) -> BytesMut {
        let size = ct.len().saturating_add(padding);
        let masked = self.mask_size(u16::try_from(size).unwrap_or(u16::MAX));
        let mut out = BytesMut::with_capacity(size.saturating_add(2));
        out.extend_from_slice(&masked.to_be_bytes());
        out.extend_from_slice(ct);
        if padding > 0 {
            let mut pad = vec![0u8; padding];
            rand::fill(&mut pad);
            out.extend_from_slice(&pad);
        }
        out
    }
}

pub(crate) async fn read_chunk<R>(r: &mut R, body: &mut Body) -> io::Result<Option<Bytes>>
where
    R: AsyncRead + Unpin,
{
    let mut size_buf = [0u8; 2];
    match r.read_exact(&mut size_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    // SHAKE order per frame is (padding, length); keep these two calls in order.
    let padding = body.next_padding();
    let size = usize::from(body.mask_size(u16::from_be_bytes(size_buf)));
    let floor = body.overhead().saturating_add(padding);
    if size == floor {
        return Ok(None); // terminal empty chunk
    }
    if size < floor {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "vmess chunk size",
        ));
    }
    let mut chunk = vec![0u8; size];
    r.read_exact(&mut chunk).await?;
    let ct_len = size.saturating_sub(padding);
    let ct = chunk.get(..ct_len).unwrap_or(&[]);
    Ok(Some(Bytes::from(body.open_piece(ct)?)))
}

pub(crate) async fn write_chunk<W>(w: &mut W, body: &mut Body, data: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let max = 8192usize
        .saturating_sub(body.overhead())
        .saturating_sub(64)
        .max(1);
    for piece in data.chunks(max) {
        // SHAKE order per frame is (padding, length): next_padding() then
        // encode_frame()'s mask_size(). seal_piece() consumes no SHAKE bytes.
        let padding = body.next_padding();
        let ct = body.seal_piece(piece)?;
        let frame = body.encode_frame(&ct, padding);
        w.write_all(&frame).await?;
    }
    Ok(())
}

pub(crate) async fn write_terminal<W>(w: &mut W, body: &mut Body) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    // The terminal marker is just an empty-payload frame (sealed to a bare tag
    // under AEAD), framed identically to any other chunk.
    let padding = body.next_padding();
    let ct = body.seal_piece(&[])?;
    let frame = body.encode_frame(&ct, padding);
    w.write_all(&frame).await
}

impl ChunkRead for Body {
    async fn read_chunk<R>(&mut self, r: &mut R) -> io::Result<Option<Bytes>>
    where
        R: AsyncRead + Unpin + Send,
    {
        read_chunk(r, self).await
    }
}

impl ChunkWrite for Body {
    async fn write_chunk<W>(&mut self, w: &mut W, data: &[u8]) -> io::Result<()>
    where
        W: AsyncWrite + Unpin + Send,
    {
        write_chunk(w, self, data).await
    }

    async fn finish<W>(&mut self, w: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin + Send,
    {
        write_terminal(w, self).await
    }
}

/// Bridge the AEAD chunk body to a plaintext duplex and run the mux demuxer
/// (XUDP / mux.cool) over it, aborting the bridge when the session ends. VMess
/// mux rides inside the encrypted body, so the codecs decrypt/encrypt one side
/// of a `tokio::io::duplex` and hand the plaintext other side to `mux::serve`;
/// each sub-flow egresses DIRECT through `dialer` (the tower tree cannot route
/// one carrier fanning out to many sub-sessions).
pub(crate) async fn serve_mux<S>(
    conn: S,
    mut up: Body,
    mut down: Body,
    dialer: SharedDialer,
    policy: ConnectionPolicy,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mine, theirs) = tokio::io::duplex(65536);
    let (mut r, mut w) = tokio::io::split(conn);
    let (mut mr, mut mw) = tokio::io::split(mine);
    let bridge = tokio::spawn(async move {
        let up_dir = async move {
            while let Ok(Some(c)) = read_chunk(&mut r, &mut up).await {
                if !c.is_empty() && mw.write_all(&c).await.is_err() {
                    break;
                }
            }
        };
        let down_dir = async move {
            let mut buf = vec![0u8; 16384];
            loop {
                match mr.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if write_chunk(&mut w, &mut down, buf.get(..n).unwrap_or(&[]))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }
            let _ = write_terminal(&mut w, &mut down).await;
        };
        tokio::join!(up_dir, down_dir);
    });
    let res = crate::mux::serve(theirs, Bytes::new(), dialer, policy).await;
    bridge.abort();
    res
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    fn codec_body(aead: bool, masking: bool, padding: bool, key: &[u8; 16], iv: &[u8; 16]) -> Body {
        let aead = aead.then(|| Aead::new(AeadKind::Aes128Gcm, key).expect("aead"));
        Body::new(aead, *iv, masking, padding)
    }

    async fn codec_roundtrip(aead: bool, masking: bool, padding: bool, payloads: &[Vec<u8>]) {
        let key = [7u8; 16];
        let iv = [9u8; 16];
        let mut writer = codec_body(aead, masking, padding, &key, &iv);
        let mut reader = codec_body(aead, masking, padding, &key, &iv);

        let mut wire: Vec<u8> = Vec::new();
        for p in payloads {
            write_chunk(&mut wire, &mut writer, p).await.expect("write");
        }
        write_terminal(&mut wire, &mut writer)
            .await
            .expect("terminal");

        let mut src: &[u8] = &wire;
        let mut out = Vec::new();
        while let Some(chunk) = read_chunk(&mut src, &mut reader).await.expect("read") {
            out.extend_from_slice(&chunk);
        }
        let expected: Vec<u8> = payloads.iter().flatten().copied().collect();
        assert_eq!(
            out, expected,
            "roundtrip mismatch aead={aead} masking={masking} padding={padding}"
        );
        // NOTE: read_chunk reports the terminal chunk by returning None as soon as
        // it decodes the length prefix; it deliberately does not drain the terminal
        // frame's body (tag + padding). The stream ends there, so leftover bytes are
        // expected. The contract under test is plaintext round-trip fidelity.
    }

    #[tokio::test]
    async fn vmess_body_codec_roundtrip_matrix() {
        // Includes a >8 KiB payload to exercise the multi-piece write loop.
        let payloads = vec![
            b"hello vmess".to_vec(),
            vec![0xABu8; 20_000],
            b"trailing chunk".to_vec(),
        ];
        for &aead in &[false, true] {
            for &masking in &[false, true] {
                for &padding in &[false, true] {
                    codec_roundtrip(aead, masking, padding, &payloads).await;
                }
            }
        }
    }
}
