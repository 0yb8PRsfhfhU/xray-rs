//! Copy loops between a transport connection and a [`Link`] (SPEC §2a).
//!
//! Each chunk resets the idle [`Timer`]. Uplink EOF drops the link sender so the
//! outbound observes a clean close; first error wins via `try_join!`.

use std::io;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::pipe::Link;
use crate::timer::Timer;

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
        conn_to_link(r, writer, timer),
        link_to_conn(reader, w, timer)
    )?;
    Ok(())
}
