//! HTTP/1.x proxy inbound (SPEC §2e). Reference: `Xray-core/proxy/http/server.go`.
//!
//! Reads one request head (bounded, terminated by CRLFCRLF). `CONNECT` opens a
//! raw tunnel after a `200 Connection Established` reply. Other methods are
//! proxied: the absolute-form request target is rewritten to origin-form and the
//! rewritten head (plus any already-read body) is relayed to the origin.
//!
//! v1 scope: one proxied request per connection. The forwarded request carries
//! `Connection: close`, so the origin closes after responding and the client
//! does not attempt to reuse the (proxy-addressed) connection for a second
//! plain request. `CONNECT` tunnels are unaffected.

use std::io;

use base64::Engine;
use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use kernel::{
    Address, Ctx, Destination, Error, LINK_CAPACITY, Network, Proxy, ProxyDecision, Timer, pipe,
};

use crate::ProxyContext;
use crate::io::{
    noop_decision, read_header, relay_stream, sniff_override, user_counter, user_hash,
};

/// Maximum request-head size we will buffer before giving up (~16 KiB).
const MAX_HEAD: usize = 16384;

/// HTTP is TCP-only (no UDP association).
const NETWORKS: &[Network] = &[Network::Tcp];

/// A single HTTP proxy account for Basic `Proxy-Authorization`.
#[derive(Debug, Clone)]
pub struct HttpAccount {
    pub username: String,
    pub password: String,
}

/// HTTP proxy inbound handler. Empty `accounts` means no authentication.
pub struct Http {
    accounts: Vec<HttpAccount>,
    cx: ProxyContext,
}

impl Http {
    pub fn new(accounts: Vec<HttpAccount>, cx: ProxyContext) -> Http {
        Http { accounts, cx }
    }

    pub fn networks(&self) -> &'static [Network] {
        NETWORKS
    }

    /// Validate Basic `Proxy-Authorization` against the configured accounts.
    /// Returns the matched account username (borrowed from the table) so the
    /// session can be attributed, or `None` when the header is absent/invalid or
    /// no account matches.
    fn check_auth(&self, headers: &[&str]) -> Option<&str> {
        let value = header_value(headers, "proxy-authorization")?;
        // Auth scheme name is case-insensitive: "Basic <base64(user:pass)>".
        let encoded = if value.len() >= 6
            && value.get(..6).map(|p| p.eq_ignore_ascii_case("Basic ")) == Some(true)
        {
            value.get(6..).unwrap_or("").trim()
        } else {
            return None;
        };
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .ok()?;
        let creds = std::str::from_utf8(&decoded).ok()?;
        let (user, pass) = creds.split_once(':')?;
        self.accounts
            .iter()
            .find(|a| a.username == user && a.password == pass)
            .map(|a| a.username.as_str())
    }
}

impl Proxy for Http {
    type Auth = ();

    fn networks(&self) -> &[Network] {
        NETWORKS
    }

    async fn decode<S>(&self, ctx: Ctx, mut stream: S) -> io::Result<ProxyDecision>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (head, body) = read_header(
            &mut stream,
            self.cx.policy.handshake_timeout,
            MAX_HEAD,
            parse_head,
        )
        .await?;

        let text = std::str::from_utf8(&head).map_err(|_| invalid("http: non-utf8 head"))?;
        let mut lines = text.split("\r\n");
        let request_line = lines.next().ok_or_else(|| invalid("http: empty request"))?;
        let mut parts = request_line.splitn(3, ' ');
        let method = parts
            .next()
            .ok_or_else(|| invalid("http: missing method"))?;
        let target = parts
            .next()
            .ok_or_else(|| invalid("http: missing target"))?;
        let version = parts
            .next()
            .ok_or_else(|| invalid("http: missing version"))?;

        let mut headers: Vec<&str> = Vec::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            headers.push(line);
        }

        // Authenticate (Basic). Attribute the session only when an account
        // matches; an inbound with no accounts is open and passes the session
        // through unattributed. A required-but-failed auth answers 407 and drops
        // the connection (the tree treats the no-op decision as freedom's drop).
        let ctx = if self.accounts.is_empty() {
            ctx
        } else {
            match self.check_auth(&headers) {
                Some(user) => {
                    let hash = user_hash(user.as_bytes());
                    ctx.with_user(user, hash)
                }
                None => {
                    stream
                        .write_all(
                            b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                              Proxy-Authenticate: Basic realm=\"proxy\"\r\n\
                              Connection: close\r\n\r\n",
                        )
                        .await?;
                    return Ok(noop_decision(ctx));
                }
            }
        };

        let timer = Timer::new(self.cx.policy.idle_timeout);

        if method.eq_ignore_ascii_case("CONNECT") {
            // authority-form target: host:port (port defaults to 443).
            let (address, port) = parse_authority(target, 443)?;
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            // `body` holds the first already-read bytes of the tunneled stream;
            // it seeds the uplink before live client bytes flow.
            let target = sniff_override(Destination::tcp(address, port), &body);
            let (inbound, outbound) = pipe(LINK_CAPACITY);
            let counter = user_counter(&ctx, self.cx.stats.as_ref()).await;
            tokio::spawn(relay_stream(stream, inbound, timer, counter, body));
            return Ok(ProxyDecision {
                target,
                ctx,
                link: outbound,
            });
        }

        // Plain proxied request: derive the destination + the origin-form line.
        let (address, port, new_req_line, inject_host): (Address, u16, String, Option<String>) =
            if let Some((authority, path, dport)) = split_absolute(target) {
                let (a, p) = parse_authority(authority, dport)?;
                (
                    a,
                    p,
                    format!("{method} {path} {version}"),
                    Some(authority.to_string()),
                )
            } else {
                // Not absolute-form; fall back to the Host header (transparent).
                let host =
                    header_value(&headers, "host").ok_or_else(|| invalid("http: missing host"))?;
                let (a, p) = parse_authority(host, 80)?;
                (a, p, request_line.to_string(), None)
            };

        let mut out = BytesMut::with_capacity(head.len().saturating_add(body.len()));
        out.put_slice(new_req_line.as_bytes());
        out.put_slice(b"\r\n");

        let mut host_seen = false;
        for line in &headers {
            let name = line.split(':').next().unwrap_or("").trim();
            // Drop hop-by-hop / proxy-specific headers; force-close below.
            if name.eq_ignore_ascii_case("proxy-connection")
                || name.eq_ignore_ascii_case("proxy-authorization")
                || name.eq_ignore_ascii_case("connection")
            {
                continue;
            }
            if name.eq_ignore_ascii_case("host") {
                host_seen = true;
            }
            out.put_slice(line.as_bytes());
            out.put_slice(b"\r\n");
        }
        if let Some(authority) = &inject_host
            && !host_seen
        {
            out.put_slice(b"Host: ");
            out.put_slice(authority.as_bytes());
            out.put_slice(b"\r\n");
        }
        out.put_slice(b"Connection: close\r\n");
        out.put_slice(b"\r\n");
        out.put_slice(&body);

        // The rewritten origin-form request head (+ any already-read body) is the
        // uplink `leftover`: `relay_stream` forwards it before pumping live bytes.
        let leftover = out.freeze();
        let target = Destination::tcp(address, port);
        let (inbound, outbound) = pipe(LINK_CAPACITY);
        let counter = user_counter(&ctx, self.cx.stats.as_ref()).await;
        tokio::spawn(relay_stream(stream, inbound, timer, counter, leftover));
        Ok(ProxyDecision {
            target,
            ctx,
            link: outbound,
        })
    }
}

/// Header-read codec for [`read_header`]: succeed once CRLFCRLF is present,
/// returning the head (including the terminator); the remainder is the body.
fn parse_head(b: &mut Bytes) -> Result<Bytes, Error> {
    match find_crlfcrlf(b.as_ref()) {
        Some(idx) => {
            let end = idx.checked_add(4).ok_or(Error::Overflow)?;
            Ok(b.split_to(end))
        }
        None => Err(Error::Truncated {
            needed: 1,
            had: b.len(),
        }),
    }
}

/// First index of the `\r\n\r\n` head terminator, if present.
fn find_crlfcrlf(hay: &[u8]) -> Option<usize> {
    hay.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Find a header value (trimmed) by case-insensitive name.
fn header_value<'a>(headers: &[&'a str], name: &str) -> Option<&'a str> {
    headers.iter().find_map(|line| {
        let (k, v) = line.split_once(':')?;
        if k.trim().eq_ignore_ascii_case(name) {
            Some(v.trim())
        } else {
            None
        }
    })
}

/// Split an absolute-form URI `http(s)://authority/path?query` into
/// `(authority, origin-path, default-port)`. Returns `None` for non-absolute
/// targets (origin-form or authority-form).
fn split_absolute(target: &str) -> Option<(&str, &str, u16)> {
    let (rest, default_port) = if target.len() >= 7
        && target.get(..7).map(|p| p.eq_ignore_ascii_case("http://")) == Some(true)
    {
        (target.get(7..)?, 80u16)
    } else if target.len() >= 8
        && target.get(..8).map(|p| p.eq_ignore_ascii_case("https://")) == Some(true)
    {
        (target.get(8..)?, 443u16)
    } else {
        return None;
    };
    let idx = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = rest.get(..idx)?;
    let path = match rest.get(idx..) {
        Some(p) if !p.is_empty() => p,
        _ => "/",
    };
    Some((authority, path, default_port))
}

/// Parse an authority `host`, `host:port`, `[v6]`, or `[v6]:port` into an
/// [`Address`] and port, applying `default_port` when none is present.
fn parse_authority(s: &str, default_port: u16) -> io::Result<(Address, u16)> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| invalid("http: malformed ipv6 authority"))?;
        let host = rest
            .get(..end)
            .ok_or_else(|| invalid("http: malformed ipv6 authority"))?;
        let after = rest.get(end.saturating_add(1)..).unwrap_or("");
        let port = match after.strip_prefix(':') {
            Some(p) if !p.is_empty() => p.parse::<u16>().map_err(|_| invalid("http: bad port"))?,
            _ => default_port,
        };
        return Ok((Address::parse(host), port));
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit()) => {
            let port = p.parse::<u16>().map_err(|_| invalid("http: bad port"))?;
            Ok((Address::parse(h), port))
        }
        _ => Ok((Address::parse(s), default_port)),
    }
}

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}
