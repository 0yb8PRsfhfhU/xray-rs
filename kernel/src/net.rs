//! Core network value types and the shared SOCKS-style address codec.
//!
//! The codec (SPEC §2b) is implemented once and parameterised by family + port
//! order so all six protocols share it instead of forking near-identical copies.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use compact_str::CompactString;

use crate::error::{Error, Result};

/// Transport network. Discriminants match the Go protobuf enum (no value `1`).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    Unknown = 0,
    Tcp = 2,
    Udp = 3,
    Unix = 4,
}

impl Network {
    /// Lower-case wire name (`"tcp"`, `"udp"`, …).
    pub fn as_str(self) -> &'static str {
        match self {
            Network::Tcp => "tcp",
            Network::Udp => "udp",
            Network::Unix => "unix",
            Network::Unknown => "unknown",
        }
    }
}

/// A network address: either a resolved IP or an unresolved domain name.
///
/// `Domain` is a [`CompactString`] (inline ≤24 bytes, cheap clone/compare) per
/// SPEC §P4, never a bare `String`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Address {
    Ip(IpAddr),
    Domain(CompactString),
}

impl Address {
    /// Build an [`Address`] from a raw IP byte slice (4 or 16 bytes),
    /// collapsing v4-mapped v6 to v4 exactly like Go's `net.IPAddress`.
    pub fn from_ip_bytes(ip: &[u8]) -> Result<Address> {
        match ip.len() {
            4 => {
                let mut a = [0u8; 4];
                a.copy_from_slice(ip);
                Ok(Address::Ip(IpAddr::V4(Ipv4Addr::from(a))))
            }
            16 => {
                let mut a = [0u8; 16];
                a.copy_from_slice(ip);
                let v6 = Ipv6Addr::from(a);
                match v6.to_ipv4_mapped() {
                    Some(v4) => Ok(Address::Ip(IpAddr::V4(v4))),
                    None => Ok(Address::Ip(IpAddr::V6(v6))),
                }
            }
            _ => Err(Error::Protocol("invalid IP length")),
        }
    }

    /// Parse a string as an IP, falling back to a domain (like `net.ParseAddress`).
    pub fn parse(s: &str) -> Address {
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Address::Ip(ip);
        }
        // Strip brackets from `[::1]`-style inputs before the second attempt.
        let trimmed = s.strip_prefix('[').and_then(|t| t.strip_suffix(']'));
        if let Some(inner) = trimmed {
            if let Ok(ip) = inner.parse::<IpAddr>() {
                return Address::Ip(ip);
            }
        }
        Address::Domain(CompactString::new(s))
    }

    pub fn is_ip(&self) -> bool {
        matches!(self, Address::Ip(_))
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Address::Ip(ip) => write!(f, "{ip}"),
            Address::Domain(d) => write!(f, "{d}"),
        }
    }
}

/// A full destination: network + address + port.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Destination {
    pub network: Network,
    pub address: Address,
    pub port: u16,
}

impl Destination {
    pub fn tcp(address: Address, port: u16) -> Destination {
        Destination { network: Network::Tcp, address, port }
    }

    pub fn udp(address: Address, port: u16) -> Destination {
        Destination { network: Network::Udp, address, port }
    }

    pub fn is_valid(&self) -> bool {
        self.network != Network::Unknown
    }

    /// `host:port` form suitable for `connect`. IPv6 hosts are bracketed.
    pub fn net_addr(&self) -> String {
        match &self.address {
            Address::Ip(IpAddr::V6(ip)) => format!("[{ip}]:{}", self.port),
            other => format!("{other}:{}", self.port),
        }
    }
}

impl fmt::Display for Destination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.network.as_str(), self.address, self.port)
    }
}

// ---------------------------------------------------------------------------
// Shared address codec (SPEC §2b)
// ---------------------------------------------------------------------------

/// Which address-type byte map to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// VLESS / VMess: `1=IPv4, 2=Domain, 3=IPv6`.
    VlessVmess,
    /// Trojan / Shadowsocks / SOCKS: `1=IPv4, 3=Domain, 4=IPv6`.
    Standard,
}

/// Field order on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortOrder {
    /// Port precedes the address (VLESS / VMess).
    PortFirst,
    /// Address precedes the port (Trojan / SS / SOCKS).
    PortLast,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Ipv4,
    Ipv6,
    Domain,
}

impl Family {
    /// Map a raw address-type byte to its kind, or `None` if unknown.
    fn kind(self, b: u8) -> Option<Kind> {
        match self {
            Family::VlessVmess => match b {
                1 => Some(Kind::Ipv4),
                2 => Some(Kind::Domain),
                3 => Some(Kind::Ipv6),
                _ => None,
            },
            Family::Standard => match b {
                1 => Some(Kind::Ipv4),
                3 => Some(Kind::Domain),
                4 => Some(Kind::Ipv6),
                _ => None,
            },
        }
    }

    /// The type byte to emit for a given address.
    fn byte_for(self, addr: &Address) -> u8 {
        match self {
            Family::VlessVmess => match addr {
                Address::Ip(IpAddr::V4(_)) => 1,
                Address::Domain(_) => 2,
                Address::Ip(IpAddr::V6(_)) => 3,
            },
            Family::Standard => match addr {
                Address::Ip(IpAddr::V4(_)) => 1,
                Address::Domain(_) => 3,
                Address::Ip(IpAddr::V6(_)) => 4,
            },
        }
    }
}

/// Configuration for one address-codec call site.
#[derive(Debug, Clone, Copy)]
pub struct AddrCodec {
    pub family: Family,
    pub order: PortOrder,
    /// Mask the type byte with `& 0x0F` before lookup (Shadowsocks).
    pub mask: bool,
}

impl AddrCodec {
    pub const VLESS: AddrCodec =
        AddrCodec { family: Family::VlessVmess, order: PortOrder::PortFirst, mask: false };
    pub const VMESS: AddrCodec = AddrCodec::VLESS;
    pub const TROJAN: AddrCodec =
        AddrCodec { family: Family::Standard, order: PortOrder::PortLast, mask: false };
    pub const SOCKS: AddrCodec = AddrCodec::TROJAN;
    pub const SHADOWSOCKS: AddrCodec =
        AddrCodec { family: Family::Standard, order: PortOrder::PortLast, mask: true };

    /// Decode an `(address, port)` pair from `buf`, advancing it.
    pub fn read(&self, buf: &mut Bytes) -> Result<(Address, u16)> {
        match self.order {
            PortOrder::PortFirst => {
                let port = read_port(buf)?;
                let addr = self.read_address(buf)?;
                Ok((addr, port))
            }
            PortOrder::PortLast => {
                let addr = self.read_address(buf)?;
                let port = read_port(buf)?;
                Ok((addr, port))
            }
        }
    }

    /// Encode an `(address, port)` pair into `buf`.
    pub fn write(&self, buf: &mut BytesMut, addr: &Address, port: u16) -> Result<()> {
        match self.order {
            PortOrder::PortFirst => {
                buf.put_u16(port);
                self.write_address(buf, addr)
            }
            PortOrder::PortLast => {
                self.write_address(buf, addr)?;
                buf.put_u16(port);
                Ok(())
            }
        }
    }

    fn read_address(&self, buf: &mut Bytes) -> Result<Address> {
        let mut t = take_u8(buf)?;
        if self.mask {
            t &= 0x0F;
        }
        let kind = self.family.kind(t).ok_or(Error::BadAddressType(t))?;
        match kind {
            Kind::Ipv4 => {
                let b = take(buf, 4)?;
                Address::from_ip_bytes(&b)
            }
            Kind::Ipv6 => {
                let b = take(buf, 16)?;
                Address::from_ip_bytes(&b)
            }
            Kind::Domain => {
                let len = take_u8(buf)? as usize;
                if len == 0 {
                    return Err(Error::BadDomain);
                }
                let b = take(buf, len)?;
                let domain = std::str::from_utf8(&b).map_err(|_| Error::BadDomain)?;
                // First char looks like an IP? Try to parse it as one (Go parity).
                if let Some(first) = domain.as_bytes().first() {
                    if *first == b'[' || first.is_ascii_digit() {
                        let parsed = Address::parse(domain);
                        if parsed.is_ip() {
                            return Ok(parsed);
                        }
                    }
                }
                if !is_valid_domain(domain) {
                    return Err(Error::BadDomain);
                }
                Ok(Address::Domain(CompactString::new(domain)))
            }
        }
    }

    fn write_address(&self, buf: &mut BytesMut, addr: &Address) -> Result<()> {
        buf.put_u8(self.family.byte_for(addr));
        match addr {
            Address::Ip(IpAddr::V4(ip)) => buf.put_slice(&ip.octets()),
            Address::Ip(IpAddr::V6(ip)) => buf.put_slice(&ip.octets()),
            Address::Domain(d) => {
                let bytes = d.as_bytes();
                let len = u8::try_from(bytes.len()).map_err(|_| Error::BadDomain)?;
                buf.put_u8(len);
                buf.put_slice(bytes);
            }
        }
        Ok(())
    }
}

pub fn read_port(buf: &mut Bytes) -> Result<u16> {
    if buf.remaining() < 2 {
        return Err(Error::Truncated { needed: 2, had: buf.remaining() });
    }
    Ok(buf.get_u16())
}

/// Take one byte without panicking.
pub fn take_u8(buf: &mut Bytes) -> Result<u8> {
    if buf.remaining() < 1 {
        return Err(Error::Truncated { needed: 1, had: buf.remaining() });
    }
    Ok(buf.get_u8())
}

/// Split off exactly `n` bytes or error.
pub fn take(buf: &mut Bytes, n: usize) -> Result<Bytes> {
    if buf.remaining() < n {
        return Err(Error::Truncated { needed: n, had: buf.remaining() });
    }
    Ok(buf.split_to(n))
}

fn is_valid_domain(d: &str) -> bool {
    !d.is_empty()
        && d.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'.' || c == b'_')
}
