//! Rule-based router: map a routing context to an outbound tag (SPEC §2f).
//!
//! Supports domain (full/suffix/keyword), IP/source CIDR, port ranges, network,
//! inbound-tag and sniffed-protocol matchers. GeoIP/GeoSite files are out of
//! scope; rules carry explicit lists.

use std::net::IpAddr;

use compact_str::CompactString;

use crate::net::{Address, Destination, Network};

/// Context evaluated against routing rules for one flow.
pub struct RouteCtx<'a> {
    pub network: Network,
    pub target: &'a Destination,
    pub inbound_tag: &'a str,
    pub source: Option<IpAddr>,
    pub sniffed_domain: Option<&'a str>,
    pub protocol: Option<&'a str>,
}

/// Domain match modes.
#[derive(Debug, Clone)]
pub enum DomainMatcher {
    Full(CompactString),
    Suffix(CompactString),
    Keyword(CompactString),
}

impl DomainMatcher {
    fn matches(&self, domain: &str) -> bool {
        match self {
            DomainMatcher::Full(d) => domain.eq_ignore_ascii_case(d),
            DomainMatcher::Keyword(k) => domain.contains(k.as_str()),
            DomainMatcher::Suffix(s) => {
                if domain.eq_ignore_ascii_case(s) {
                    return true;
                }
                match domain.len().checked_sub(s.len()) {
                    Some(i) if i >= 1 => {
                        domain.as_bytes().get(i.wrapping_sub(1)) == Some(&b'.')
                            && domain
                                .get(i..)
                                .is_some_and(|tail| tail.eq_ignore_ascii_case(s))
                    }
                    _ => false,
                }
            }
        }
    }
}

/// A CIDR block for IPv4 or IPv6.
#[derive(Debug, Clone)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Parse `a.b.c.d/n` or `addr/n`. A bare IP becomes a /32 or /128.
    pub fn parse(s: &str) -> Option<Cidr> {
        let (ip_str, pfx_str) = match s.split_once('/') {
            Some((a, b)) => (a, Some(b)),
            None => (s, None),
        };
        let addr: IpAddr = ip_str.parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match pfx_str {
            Some(p) => p.parse::<u8>().ok().filter(|p| *p <= max)?,
            None => max,
        };
        Some(Cidr { addr, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                prefix_match(&net.octets(), &ip.octets(), self.prefix)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                prefix_match(&net.octets(), &ip.octets(), self.prefix)
            }
            _ => false,
        }
    }
}

fn prefix_match(net: &[u8], ip: &[u8], prefix: u8) -> bool {
    let mut bits = prefix as usize;
    for (a, b) in net.iter().zip(ip.iter()) {
        if bits == 0 {
            break;
        }
        if bits >= 8 {
            if a != b {
                return false;
            }
            bits = bits.saturating_sub(8);
        } else {
            let shift = 8u32.saturating_sub(bits as u32);
            let mask = 0xffu8.wrapping_shl(shift);
            if (a & mask) != (b & mask) {
                return false;
            }
            bits = 0;
        }
    }
    true
}

/// One routing rule. Empty lists mean "unconstrained on this dimension". A flow
/// matches when every constrained dimension matches (AND across dimensions, OR
/// within each list).
#[derive(Debug, Clone, Default)]
pub struct Rule {
    pub outbound_tag: CompactString,
    pub networks: Vec<Network>,
    pub domains: Vec<DomainMatcher>,
    pub ips: Vec<Cidr>,
    pub source_ips: Vec<Cidr>,
    pub ports: Vec<(u16, u16)>,
    pub inbound_tags: Vec<CompactString>,
    pub protocols: Vec<CompactString>,
}

impl Rule {
    fn matches(&self, rc: &RouteCtx<'_>) -> bool {
        if !self.networks.is_empty() && !self.networks.contains(&rc.network) {
            return false;
        }
        if !self.inbound_tags.is_empty() && !self.inbound_tags.iter().any(|t| t == rc.inbound_tag) {
            return false;
        }
        if !self.ports.is_empty()
            && !self
                .ports
                .iter()
                .any(|(lo, hi)| rc.target.port >= *lo && rc.target.port <= *hi)
        {
            return false;
        }
        if !self.protocols.is_empty() {
            match rc.protocol {
                Some(p) if self.protocols.iter().any(|x| x == p) => {}
                _ => return false,
            }
        }
        if !self.source_ips.is_empty() {
            match rc.source {
                Some(ip) if self.source_ips.iter().any(|c| c.contains(ip)) => {}
                _ => return false,
            }
        }
        if !self.domains.is_empty() {
            let domain = match (&rc.target.address, rc.sniffed_domain) {
                (Address::Domain(d), _) => Some(d.as_str()),
                (_, Some(d)) => Some(d),
                _ => None,
            };
            match domain {
                Some(d) if self.domains.iter().any(|m| m.matches(d)) => {}
                _ => return false,
            }
        }
        if !self.ips.is_empty() {
            match &rc.target.address {
                Address::Ip(ip) if self.ips.iter().any(|c| c.contains(*ip)) => {}
                _ => return false,
            }
        }
        true
    }
}

/// An ordered list of rules. First match wins.
#[derive(Debug, Clone, Default)]
pub struct Router {
    rules: Vec<Rule>,
}

impl Router {
    pub fn new(rules: Vec<Rule>) -> Router {
        Router { rules }
    }

    /// Return the outbound tag for `rc`, or `None` to fall through to default.
    pub fn pick(&self, rc: &RouteCtx<'_>) -> Option<&str> {
        self.rules
            .iter()
            .find(|r| r.matches(rc))
            .map(|r| r.outbound_tag.as_str())
    }
}
