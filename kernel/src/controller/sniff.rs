//! Traffic sniffers (SPEC §2f).
//!
//! When an inbound hands the router a connection whose destination is a bare IP
//! address, the router can still apply domain rules by peeking at the first
//! bytes of the client stream. [`sniff`] inspects that prefix and, when it can
//! recognise the protocol, returns the domain the client is really asking for:
//! the SNI of a TLS `ClientHello`, or the `Host` header of an HTTP/1.x request.
//!
//! Every length field parsed here is attacker-controlled, so each is validated
//! against the bytes that actually remain before any slice is taken. On the
//! slightest shortfall the parser yields `None` instead of panicking — this
//! crate denies unchecked indexing, unchecked arithmetic and panics (SPEC §P7).
//!
//! Ported from `Xray-core/common/protocol/tls/sniff.go` and
//! `Xray-core/common/protocol/http/sniff.go`.

use compact_str::CompactString;

/// Application protocol recognised by [`sniff`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SniffedProtocol {
    /// TLS — the domain is the `server_name` (SNI) extension.
    Tls,
    /// HTTP/1.x — the domain is the `Host` header.
    Http,
}

impl SniffedProtocol {
    /// The routing-rule protocol token, matching Xray's sniffer names.
    pub fn as_str(self) -> &'static str {
        match self {
            SniffedProtocol::Tls => "tls",
            SniffedProtocol::Http => "http",
        }
    }
}

/// Sniff a connection prefix, trying TLS first and then HTTP.
///
/// Returns the recognised protocol together with the domain the client is
/// addressing, or `None` when `payload` matches neither.
pub fn sniff(payload: &[u8]) -> Option<(SniffedProtocol, CompactString)> {
    if let Some(domain) = sniff_tls(payload) {
        return Some((SniffedProtocol::Tls, domain));
    }
    if let Some(domain) = sniff_http(payload) {
        return Some((SniffedProtocol::Http, domain));
    }
    None
}

/// Read a big-endian `u16` from the first two bytes of `s`, if present.
fn read_u16(s: &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes([*s.first()?, *s.get(1)?]))
}

/// Parse a TLS record carrying a `ClientHello` and return its SNI `host_name`.
///
/// `payload` must start at the TLS record header. Returns `None` for anything
/// that is not a well-formed handshake record advertising a server name.
pub fn sniff_tls(payload: &[u8]) -> Option<CompactString> {
    // Record header: type(1) | version(2) | length(2).
    if payload.len() < 5 {
        return None;
    }
    if *payload.first()? != 0x16 {
        // Not a TLS handshake record.
        return None;
    }
    // A valid TLS version has major == 3 (SSL3 / TLS1.x); the minor is ignored.
    if *payload.get(1)? != 3 {
        return None;
    }
    let record_len = usize::from(read_u16(payload.get(3..)?)?);
    let end = 5usize.checked_add(record_len)?;
    if end > payload.len() {
        // Record claims more bytes than we have; need more data.
        return None;
    }
    read_client_hello(payload.get(5..end)?)
}

/// Walk a `ClientHello` handshake message and extract the SNI `host_name`.
///
/// `data` starts at the handshake message (type byte). The layout skipped here
/// is: handshake header(4) | version(2) | random(32) | session id | cipher
/// suites | compression methods | extensions, after which the `server_name`
/// extension (type `0x0000`) is located and its first `host_name` returned.
fn read_client_hello(data: &[u8]) -> Option<CompactString> {
    // type(1)+len(3)+version(2)+random(32)+session-id-len(1) lands the session
    // id length byte at offset 38; require enough bytes to reach past it.
    if data.len() < 42 {
        return None;
    }
    let session_id_len = usize::from(*data.get(38)?);
    if session_id_len > 32 {
        return None;
    }
    // Skip fixed header + session id.
    let mut data = data.get(39usize.checked_add(session_id_len)?..)?;

    // Cipher suites: u16 count of bytes, must be even.
    let cipher_suite_len = usize::from(read_u16(data)?);
    if cipher_suite_len & 1 == 1 {
        return None;
    }
    data = data.get(2usize.checked_add(cipher_suite_len)?..)?;

    // Compression methods: u8 length prefix.
    let compression_len = usize::from(*data.first()?);
    data = data.get(1usize.checked_add(compression_len)?..)?;

    // Extensions: u16 total length, which must match the bytes that remain.
    let extensions_len = usize::from(read_u16(data)?);
    data = data.get(2..)?;
    if extensions_len != data.len() {
        return None;
    }

    while !data.is_empty() {
        // Extension header: type(2) | length(2).
        let extension = read_u16(data)?;
        let length = usize::from(read_u16(data.get(2..)?)?);
        data = data.get(4..)?;
        let body = data.get(..length)?;

        if extension == 0x0000 {
            // server_name extension; the first host_name entry wins.
            if let Some(name) = read_server_name(body) {
                return Some(name);
            }
        }

        data = data.get(length..)?;
    }

    None
}

/// Parse the body of a `server_name` extension and return its `host_name`.
///
/// Returns `None` if the list is malformed, the name is incomplete (a control
/// byte or space, which for QUIC would mean the SNI spans packets), or the name
/// carries an illegal trailing dot.
fn read_server_name(body: &[u8]) -> Option<CompactString> {
    // ServerNameList: u16 length of the entries that follow.
    let names_len = usize::from(read_u16(body)?);
    let mut d = body.get(2..)?;
    if d.len() != names_len {
        return None;
    }

    while !d.is_empty() {
        // ServerName: type(1) | length(2) | name.
        let name_type = *d.first()?;
        let name_len = usize::from(read_u16(d.get(1..)?)?);
        d = d.get(3..)?;
        let name = d.get(..name_len)?;

        if name_type == 0 {
            // host_name. A control byte or space means the value is truncated
            // (relevant when sniffing QUIC across packets); a trailing dot is
            // illegal per RFC 6066 §3.
            let mut last = 0u8;
            for &c in name {
                if c <= b' ' {
                    return None;
                }
                last = c;
            }
            if last == b'.' {
                return None;
            }
            return Some(CompactString::new(core::str::from_utf8(name).ok()?));
        }

        d = d.get(name_len..)?;
    }

    None
}

/// HTTP request methods accepted as evidence of an HTTP/1.x request, lowercased.
const HTTP_METHODS: [&str; 7] = ["get", "post", "head", "put", "delete", "options", "connect"];

/// Does `b` begin with a recognised HTTP method (case-insensitive)?
///
/// Mirrors the reference loop: a method matches when its full token is present;
/// a buffer shorter than the method currently under test is treated as "no
/// clue" and rejected, so callers never act on a half-arrived request line.
fn begins_with_http_method(b: &[u8]) -> bool {
    for m in HTTP_METHODS {
        let m = m.as_bytes();
        if b.len() >= m.len() && b.get(..m.len()).is_some_and(|p| p.eq_ignore_ascii_case(m)) {
            return true;
        }
        if b.len() < m.len() {
            return false;
        }
    }
    false
}

/// Parse an HTTP/1.x request prefix and return its `Host` header (port removed).
///
/// Headers after the blank line that terminates the header block are ignored,
/// matching the reference sniffer. Returns `None` when the prefix is not an
/// HTTP request or carries no usable `Host`.
pub fn sniff_http(payload: &[u8]) -> Option<CompactString> {
    if !begins_with_http_method(payload) {
        return None;
    }

    let mut host: Option<CompactString> = None;
    let mut lines = payload.split(|&c| c == b'\n');
    // Discard the request line; only header lines carry the Host.
    let _request_line = lines.next();

    for line in lines {
        // The blank line ends the header block.
        if line.is_empty() {
            break;
        }
        // Split on the first colon; lines without one are not headers.
        let Some(colon) = line.iter().position(|&c| c == b':') else {
            continue;
        };
        let key = line.get(..colon)?;
        let value = line.get(colon.checked_add(1)?..)?;
        if key.eq_ignore_ascii_case(b"host") {
            let raw = core::str::from_utf8(value.trim_ascii()).ok()?;
            host = strip_port(&raw.to_ascii_lowercase());
        }
    }

    match host {
        Some(h) if !h.is_empty() => Some(h),
        _ => None,
    }
}

/// Strip a trailing `:port` from a host string, leaving the bare host.
///
/// Bracketed IPv6 literals keep their address (without brackets); an
/// unbracketed value carrying more than one colon (a bare IPv6 literal) cannot
/// be split unambiguously and yields `None`, matching `net.SplitHostPort`.
fn strip_port(host: &str) -> Option<CompactString> {
    if let Some(rest) = host.strip_prefix('[') {
        let (addr, after) = rest.split_once(']')?;
        if after.is_empty() || after.starts_with(':') {
            return Some(CompactString::new(addr));
        }
        return None;
    }
    match host.bytes().filter(|&c| c == b':').count() {
        0 => Some(CompactString::new(host)),
        1 => host
            .rsplit_once(':')
            .map(|(h, _port)| CompactString::new(h)),
        _ => None,
    }
}
