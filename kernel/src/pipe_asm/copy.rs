//! Copy loops between a transport connection and a [`Link`] (SPEC §2a).
//!
//! Each chunk resets the idle [`Timer`]. Uplink EOF drops the link sender so the
//! outbound observes a clean close; first error wins via `try_join!`.

use std::io;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::pipe_asm::pipe::Link;
use crate::pipe_asm::timer::Timer;
use crate::stats::Counter;

/// Read window size handed to a single `read` (SPEC §2a, 8–64 KiB band).
pub const READ_BUF: usize = 16384;

fn idle_err() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "connection idle timeout")
}

/// Pump `reader` → link `tx`, freezing each read into [`Bytes`] (SPEC §P3).
/// Returns `Ok(())` on EOF; `tx` is dropped here, signalling EOF downstream.
pub async fn conn_to_link<R>(
    mut reader: R,
    tx: mpsc::Sender<Bytes>,
    timer: &Timer,
    counter: Option<&Counter>,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    let token = timer.token();
    loop {
        let mut buf = BytesMut::with_capacity(READ_BUF);
        let n = tokio::select! {
            biased;
            _ = token.cancelled() => return Err(idle_err()),
            r = reader.read_buf(&mut buf) => r?,
        };
        if n == 0 {
            return Ok(());
        }
        timer.update();
        if let Some(c) = counter {
            c.add_up(n as u64);
        }
        if tx.send(buf.freeze()).await.is_err() {
            return Ok(());
        }
    }
}

/// Pump link `rx` → `writer`. Returns `Ok(())` when the sender is dropped (EOF).
pub async fn link_to_conn<W>(
    mut rx: mpsc::Receiver<Bytes>,
    mut writer: W,
    timer: &Timer,
    counter: Option<&Counter>,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let token = timer.token();
    loop {
        let chunk = tokio::select! {
            biased;
            _ = token.cancelled() => return Err(idle_err()),
            c = rx.recv() => c,
        };
        match chunk {
            Some(b) => {
                timer.update();
                if let Some(c) = counter {
                    c.add_down(b.len() as u64);
                }
                writer.write_all(&b).await?;
            }
            None => {
                let _ = writer.flush().await;
                return Ok(());
            }
        }
    }
}

/// Run both copy directions over a split connection until both finish or one
/// errors (SPEC §1 lifecycle step 5).
pub async fn splice<S>(conn: S, link: Link, timer: &Timer) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (r, w) = tokio::io::split(conn);
    let Link { reader, writer } = link;
    tokio::try_join!(
        conn_to_link(r, writer, timer, None),
        link_to_conn(reader, w, timer, None)
    )?;
    Ok(())
}

/// Write side that accepts owned [`Bytes`] chunks without an intermediate copy
/// (SPEC §P3). Transports whose wire write takes an owned buffer (WebSocket
/// binary frames, h2 `DATA`) implement this so the downlink hands the original
/// `Bytes` straight through. `+ Send` is explicit because the relay future is
/// spawned.
pub trait BytesSink: Send {
    /// Write one chunk, taking ownership.
    fn send(&mut self, buf: Bytes) -> impl core::future::Future<Output = io::Result<()>> + Send;
    /// Flush any buffered bytes to the peer.
    fn flush(&mut self) -> impl core::future::Future<Output = io::Result<()>> + Send;
}

/// Pump link `rx` → sink `w`, moving each [`Bytes`] chunk through [`BytesSink`]
/// (downlink counterpart to [`link_to_conn`]). Empty chunks are dropped so a
/// frame-oriented sink never emits an empty frame. `Ok(())` on sender drop (EOF).
pub async fn link_to_sink<W>(
    mut rx: mpsc::Receiver<Bytes>,
    mut w: W,
    timer: &Timer,
    counter: Option<&Counter>,
) -> io::Result<()>
where
    W: BytesSink,
{
    let token = timer.token();
    loop {
        let chunk = tokio::select! {
            biased;
            _ = token.cancelled() => return Err(idle_err()),
            c = rx.recv() => c,
        };
        match chunk {
            Some(b) => {
                if b.is_empty() {
                    continue;
                }
                timer.update();
                let len = b.len();
                w.send(b).await?;
                if let Some(c) = counter {
                    c.add_down(len as u64);
                }
            }
            None => {
                let _ = w.flush().await;
                return Ok(());
            }
        }
    }
}

/// Run both copy directions over a split connection whose write half is a
/// [`BytesSink`] (zero-copy downlink counterpart to [`splice`]). `counter`, when
/// present, accumulates inbound per-user upload/download bytes.
pub async fn splice_sink<R, W>(
    r: R,
    w: W,
    link: Link,
    timer: &Timer,
    counter: Option<&Counter>,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: BytesSink,
{
    let Link { reader, writer } = link;
    tokio::try_join!(
        conn_to_link(r, writer, timer, counter),
        link_to_sink(reader, w, timer, counter)
    )?;
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use crate::pipe_asm::pipe::pipe;
    use std::time::Duration;

    /// Test sink: forwards each event over an unbounded channel so the test can
    /// inspect order / flush after the sink is consumed by the copy loop.
    enum Event {
        Chunk(Bytes),
        Flush,
    }

    struct CollectSink {
        tx: mpsc::UnboundedSender<Event>,
    }

    impl BytesSink for CollectSink {
        async fn send(&mut self, buf: Bytes) -> io::Result<()> {
            let _ = self.tx.send(Event::Chunk(buf));
            Ok(())
        }
        async fn flush(&mut self) -> io::Result<()> {
            let _ = self.tx.send(Event::Flush);
            Ok(())
        }
    }

    #[tokio::test]
    async fn link_to_sink_orders_drops_empty_and_flushes_on_eof() {
        let timer = Timer::new(Duration::from_secs(60));
        let (link_tx, link_rx) = mpsc::channel::<Bytes>(8);
        let (ev_tx, mut ev_rx) = mpsc::unbounded_channel::<Event>();

        link_tx.send(Bytes::from_static(b"alpha")).await.unwrap();
        link_tx.send(Bytes::new()).await.unwrap(); // empty must be dropped
        link_tx.send(Bytes::from_static(b"beta")).await.unwrap();
        drop(link_tx); // EOF

        link_to_sink(link_rx, CollectSink { tx: ev_tx }, &timer, None)
            .await
            .unwrap();

        let mut chunks = Vec::new();
        let mut flushed = false;
        while let Ok(ev) = ev_rx.try_recv() {
            match ev {
                Event::Chunk(b) => chunks.push(b),
                Event::Flush => flushed = true,
            }
        }
        assert_eq!(chunks.len(), 2, "empty chunk must be dropped");
        assert_eq!(&chunks[0][..], b"alpha");
        assert_eq!(&chunks[1][..], b"beta");
        assert!(flushed, "EOF must trigger flush");
    }

    #[tokio::test]
    async fn splice_sink_pumps_both_directions() {
        let timer = Timer::new(Duration::from_secs(60));
        let (inbound, outbound) = pipe(8);
        let Link {
            reader: mut out_reader,
            writer: out_writer,
        } = outbound;

        // Downlink: outbound side writes two chunks then closes.
        out_writer.send(Bytes::from_static(b"down1")).await.unwrap();
        out_writer.send(Bytes::from_static(b"down2")).await.unwrap();
        drop(out_writer);

        let (ev_tx, mut ev_rx) = mpsc::unbounded_channel::<Event>();
        let uplink: &[u8] = b"up-bytes";
        splice_sink(uplink, CollectSink { tx: ev_tx }, inbound, &timer, None)
            .await
            .unwrap();

        // Downlink reached the sink in order.
        let mut down = Vec::new();
        while let Ok(ev) = ev_rx.try_recv() {
            if let Event::Chunk(b) = ev {
                down.extend_from_slice(&b);
            }
        }
        assert_eq!(&down[..], b"down1down2");

        // Uplink reached the outbound reader.
        let mut up = Vec::new();
        while let Ok(b) = out_reader.try_recv() {
            up.extend_from_slice(&b);
        }
        assert_eq!(&up[..], b"up-bytes");
    }

    #[tokio::test]
    async fn splice_sink_accounts_traffic() {
        let timer = Timer::new(Duration::from_secs(60));
        let (inbound, outbound) = pipe(8);
        let Link {
            reader: mut out_reader,
            writer: out_writer,
        } = outbound;

        // Downlink: 5 + 5 = 10 bytes; uplink: 8 bytes.
        out_writer.send(Bytes::from_static(b"down1")).await.unwrap();
        out_writer.send(Bytes::from_static(b"down2")).await.unwrap();
        drop(out_writer);

        let counter = Counter::default();
        let (ev_tx, _ev_rx) = mpsc::unbounded_channel::<Event>();
        let uplink: &[u8] = b"up-bytes";
        splice_sink(
            uplink,
            CollectSink { tx: ev_tx },
            inbound,
            &timer,
            Some(&counter),
        )
        .await
        .unwrap();
        while out_reader.try_recv().is_ok() {}

        assert_eq!(counter.up(), 8, "uplink bytes counted");
        assert_eq!(counter.down(), 10, "downlink bytes counted");
        let (up, down) = counter.take();
        assert_eq!((up, down), (8, 10));
        assert_eq!((counter.up(), counter.down()), (0, 0), "take resets");
    }
}
