pub mod dialer;
pub mod dns;
pub mod user;

use crate::Error;
use compact_str::CompactString;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
    pub fn from_ip_bytes(ip: &[u8]) -> Result<Address, Error> {
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
        if let Some(inner) = trimmed
            && let Ok(ip) = inner.parse::<IpAddr>()
        {
            return Address::Ip(ip);
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
        Destination {
            network: Network::Tcp,
            address,
            port,
        }
    }

    pub fn udp(address: Address, port: u16) -> Destination {
        Destination {
            network: Network::Udp,
            address,
            port,
        }
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
        write!(
            f,
            "{}:{}:{}",
            self.network.as_str(),
            self.address,
            self.port
        )
    }
}
