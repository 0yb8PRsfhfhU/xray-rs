//! HTTP-Upgrade transport: read one HTTP/1.1 upgrade request, reply `101`, then
//! pass bytes through unchanged (SPEC §2c). Header bytes are read one at a time
//! so no payload is consumed past the `CRLFCRLF` terminator.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Server httpupgrade settings.
#[derive(Debug, Clone, Default)]
pub struct HttpUpgradeConfig {
    pub path: String,
    pub host: Option<String>,
}

const MAX_HEAD: usize = 16384;
const RESPONSE: &[u8] =
    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";

/// Perform the server httpupgrade handshake, returning the same stream for
/// raw passthrough.
pub async fn accept<S>(mut s: S, cfg: &HttpUpgradeConfig) -> io::Result<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let head = read_head(&mut s).await?;
    let text = std::str::from_utf8(&head)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-utf8 request"))?;
    let mut lines = text.split("\r\n");

    let request_line = lines.next().unwrap_or("");
    let path = request_line.split(' ').nth(1).unwrap_or("");
    if !cfg.path.is_empty() && path != cfg.path {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad path"));
    }

    let (mut connection, mut upgrade, mut host) = (String::new(), String::new(), String::new());
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim();
            match key.as_str() {
                "connection" => connection = val.to_ascii_lowercase(),
                "upgrade" => upgrade = val.to_ascii_lowercase(),
                "host" => host = val.to_string(),
                _ => {}
            }
        }
    }

    if let Some(want) = &cfg.host {
        let got = host.split(':').next().unwrap_or(&host);
        if !got.eq_ignore_ascii_case(want) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad host"));
        }
    }
    if connection != "upgrade" || upgrade != "websocket" {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "unrecognized request"));
    }

    s.write_all(RESPONSE).await?;
    s.flush().await?;
    Ok(s)
}

async fn read_head<S>(s: &mut S) -> io::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        let n = s.read(&mut byte).await?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof in request"));
        }
        buf.extend_from_slice(&byte);
        if buf.ends_with(b"\r\n\r\n") {
            return Ok(buf);
        }
        if buf.len() > MAX_HEAD {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "request head too large"));
        }
    }
}
