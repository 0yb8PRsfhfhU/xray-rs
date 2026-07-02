//! The routing engine (objective requirement 5).
//!
//! Config is a *bigraph*: many match rules pointing at overlapping outbound tag
//! sets. The runtime renders it as an ordered [`RouteTable`] — a first-match
//! list of [`MatchRule`]s plus a mandatory default branch. Each rule is an array
//! of [`Condition`]s combined with OR (**any** condition matching selects the
//! rule); rules are tried in config order (first rule first). Every rule carries
//! its `outs` tag list and its own [`LoadBalancer`]; an empty `outs` routes to
//! [`RouteDecision::Blackhole`], and if no rule matches, the default branch
//! decides — defaulting to [`RouteDecision::Freedom`] when the config omits one.
//!
//! `geosite:`/`geoip:` membership is delegated to a [`GeoMatcher`] so the engine
//! stays free of embedded geodata and fully unit-testable with an in-memory map.

use std::net::IpAddr;

use compact_str::CompactString;

use crate::net::{Address, Destination, Network};
use crate::route::balance::{BalanceMode, LoadBalancer};

/// Abstract geo membership oracle (objective requirement 5: `geosite`/`geoip`).
///
/// Kept a trait so the routing engine never embeds a geodata file: production
/// wires an xray `geosite.dat`/`geoip.dat`-backed impl, tests wire a map. Never
/// a trait object on the hot path — the table is generic over `G` (SPEC §P1).
pub trait GeoMatcher: Send + Sync {
    /// Is `domain` a member of geosite category `tag` (e.g. `"openai"`)?
    fn site_contains(&self, tag: &str, domain: &str) -> bool;
    /// Is `ip` a member of geoip country `tag` (e.g. `"ca"`)?
    fn ip_contains(&self, tag: &str, ip: IpAddr) -> bool;
}

/// A [`GeoMatcher`] that knows nothing — every geo lookup misses. The default
/// when no geodata is configured; geo rules simply never match.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoGeo;

impl GeoMatcher for NoGeo {
    fn site_contains(&self, _tag: &str, _domain: &str) -> bool {
        false
    }
    fn ip_contains(&self, _tag: &str, _ip: IpAddr) -> bool {
        false
    }
}

/// A CIDR block for IPv4 or IPv6 (`ip:1.2.3.4/24`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Parse `a.b.c.d/n` or a bare address (→ `/32` or `/128`).
    pub fn parse(s: &str) -> Option<Cidr> {
        let (ip_str, pfx_str) = match s.split_once('/') {
            Some((a, b)) => (a, Some(b)),
            None => (s, None),
        };
        let addr: IpAddr = ip_str.trim().parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match pfx_str {
            Some(p) => p.trim().parse::<u8>().ok().filter(|p| *p <= max)?,
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

/// One match condition. A [`MatchRule`] holds several and ORs them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Condition {
    /// `geosite:openai` — domain is in a geosite category.
    GeoSite(CompactString),
    /// `domain:google.com` — domain-suffix match (also matches the apex).
    DomainSuffix(CompactString),
    /// `geoip:ca` — resolved IP is in a geoip country.
    GeoIp(CompactString),
    /// `ip:1.2.3.4/24` — target IP in a CIDR block.
    Ip(Cidr),
    /// `port:1000-2000` (or `port:53`) — target port in an inclusive range.
    Port { lo: u16, hi: u16 },
    /// `*` — matches anything (the catch-all / default marker).
    Any,
}

impl Condition {
    /// Parse one `type:value` token (or the bare `*`). Returns `None` on an
    /// unknown type or malformed value.
    pub fn parse(token: &str) -> Option<Condition> {
        let token = token.trim();
        if token == "*" {
            return Some(Condition::Any);
        }
        let (kind, value) = token.split_once(':')?;
        let value = value.trim();
        match kind.trim().to_ascii_lowercase().as_str() {
            "geosite" => (!value.is_empty()).then(|| Condition::GeoSite(value.into())),
            "domain" => (!value.is_empty())
                .then(|| Condition::DomainSuffix(value.to_ascii_lowercase().into())),
            "geoip" => (!value.is_empty()).then(|| Condition::GeoIp(value.into())),
            "ip" => Cidr::parse(value).map(Condition::Ip),
            "port" => parse_port_range(value).map(|(lo, hi)| Condition::Port { lo, hi }),
            _ => None,
        }
    }

    fn matches<G: GeoMatcher>(&self, q: &RouteQuery<'_>, geo: &G) -> bool {
        match self {
            Condition::Any => true,
            Condition::Port { lo, hi } => q.target.port >= *lo && q.target.port <= *hi,
            Condition::DomainSuffix(suffix) => {
                q.domain().is_some_and(|d| domain_suffix_match(&d, suffix))
            }
            Condition::GeoSite(tag) => q.domain().is_some_and(|d| geo.site_contains(tag, &d)),
            Condition::Ip(cidr) => match &q.target.address {
                Address::Ip(ip) => cidr.contains(*ip),
                Address::Domain(_) => false,
            },
            Condition::GeoIp(tag) => match &q.target.address {
                Address::Ip(ip) => geo.ip_contains(tag, *ip),
                Address::Domain(_) => false,
            },
        }
    }
}

/// Parse `"1000-2000"` or `"53"` into an inclusive `(lo, hi)` range.
fn parse_port_range(s: &str) -> Option<(u16, u16)> {
    match s.split_once('-') {
        Some((lo, hi)) => {
            let lo = lo.trim().parse().ok()?;
            let hi = hi.trim().parse().ok()?;
            if lo <= hi { Some((lo, hi)) } else { None }
        }
        None => {
            let p = s.trim().parse().ok()?;
            Some((p, p))
        }
    }
}

/// Case-insensitive domain-suffix match: `d == suffix`, or `d` ends in
/// `.suffix` at a label boundary.
fn domain_suffix_match(d: &str, suffix: &str) -> bool {
    if d.eq_ignore_ascii_case(suffix) {
        return true;
    }
    match d.len().checked_sub(suffix.len()) {
        Some(i) if i >= 1 => {
            d.as_bytes().get(i.wrapping_sub(1)) == Some(&b'.')
                && d.get(i..)
                    .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
        }
        _ => false,
    }
}

/// The flow being routed: its target plus recovered context (a sniffed domain,
/// the client source, the authenticated user's balance hash).
#[derive(Debug, Clone)]
pub struct RouteQuery<'a> {
    pub target: &'a Destination,
    pub network: Network,
    pub source: Option<IpAddr>,
    /// Domain recovered by a sniffer when `target` is a bare IP (SPEC §2f).
    pub sniffed_domain: Option<&'a str>,
    /// Authenticated user's stable hash, for `user_auth_hash` balancing.
    pub auth_hash: Option<u64>,
}

impl RouteQuery<'_> {
    /// The domain to match against: the target host if it is a domain, else the
    /// sniffed domain (lower-cased for case-insensitive matching).
    fn domain(&self) -> Option<CompactString> {
        match &self.target.address {
            Address::Domain(d) => Some(d.to_ascii_lowercase()),
            Address::Ip(_) => self.sniffed_domain.map(|d| d.to_ascii_lowercase().into()),
        }
    }
}

/// Where a flow should go once routing resolves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteDecision {
    /// Send to the outbound with this readable tag.
    Outbound(CompactString),
    /// No rule matched and the default is "direct" (objective requirement 5:
    /// absent default ⇒ freedom).
    Freedom,
    /// A matched rule had no `outs` (objective requirement 5 ⇒ blackhole).
    Blackhole,
}

/// One routing rule: OR-combined conditions plus the outbound tags to balance
/// across when it matches.
#[derive(Debug)]
pub struct MatchRule {
    conditions: Vec<Condition>,
    outs: Vec<CompactString>,
    balancer: LoadBalancer,
}

impl MatchRule {
    /// Build a rule from conditions, an `outs` tag list, and a balance mode
    /// (only consulted when `outs` has more than one tag).
    pub fn new(
        conditions: Vec<Condition>,
        outs: Vec<CompactString>,
        mode: BalanceMode,
    ) -> MatchRule {
        MatchRule {
            conditions,
            outs,
            balancer: LoadBalancer::new(mode),
        }
    }

    /// Does any condition match this flow?
    fn matches<G: GeoMatcher>(&self, q: &RouteQuery<'_>, geo: &G) -> bool {
        self.conditions.iter().any(|c| c.matches(q, geo))
    }

    /// Resolve this rule's `outs` to a decision, balancing when needed.
    fn decide(&self, q: &RouteQuery<'_>) -> RouteDecision {
        match self.outs.len() {
            0 => RouteDecision::Blackhole,
            1 => self
                .outs
                .first()
                .map(|t| RouteDecision::Outbound(t.clone()))
                .unwrap_or(RouteDecision::Blackhole),
            n => match self
                .balancer
                .pick(n, q.auth_hash)
                .and_then(|i| self.outs.get(i))
            {
                Some(t) => RouteDecision::Outbound(t.clone()),
                None => RouteDecision::Blackhole,
            },
        }
    }
}

/// An ordered, first-match rule table with a mandatory default branch.
#[derive(Debug)]
pub struct RouteTable {
    rules: Vec<MatchRule>,
    default: RouteDecision,
}

impl RouteTable {
    /// Build a table. `default` is the branch taken when no rule matches; pass
    /// `None` to get the objective's fallback ([`RouteDecision::Freedom`]).
    pub fn new(rules: Vec<MatchRule>, default: Option<RouteDecision>) -> RouteTable {
        RouteTable {
            rules,
            default: default.unwrap_or(RouteDecision::Freedom),
        }
    }

    /// The default branch decision.
    pub fn default_decision(&self) -> &RouteDecision {
        &self.default
    }

    /// Resolve a flow to a [`RouteDecision`]: first matching rule wins; if none
    /// match, the default branch decides (objective requirement 5).
    pub fn route<G: GeoMatcher>(&self, q: &RouteQuery<'_>, geo: &G) -> RouteDecision {
        for rule in &self.rules {
            if rule.matches(q, geo) {
                return rule.decide(q);
            }
        }
        self.default.clone()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// In-memory geo oracle for tests.
    #[derive(Default)]
    struct MapGeo {
        sites: HashMap<String, Vec<String>>,
        ips: HashMap<String, Vec<Cidr>>,
    }
    impl GeoMatcher for MapGeo {
        fn site_contains(&self, tag: &str, domain: &str) -> bool {
            self.sites
                .get(tag)
                .is_some_and(|ds| ds.iter().any(|d| domain_suffix_match(domain, d)))
        }
        fn ip_contains(&self, tag: &str, ip: IpAddr) -> bool {
            self.ips
                .get(tag)
                .is_some_and(|cs| cs.iter().any(|c| c.contains(ip)))
        }
    }

    fn tcp_dom(host: &str, port: u16) -> Destination {
        Destination::tcp(Address::parse(host), port)
    }

    fn query<'a>(target: &'a Destination) -> RouteQuery<'a> {
        RouteQuery {
            target,
            network: Network::Tcp,
            source: None,
            sniffed_domain: None,
            auth_hash: None,
        }
    }

    #[test]
    fn parse_all_condition_kinds() {
        assert_eq!(Condition::parse("*"), Some(Condition::Any));
        assert_eq!(
            Condition::parse("geosite:openai"),
            Some(Condition::GeoSite("openai".into()))
        );
        assert_eq!(
            Condition::parse("domain:Google.com"),
            Some(Condition::DomainSuffix("google.com".into()))
        );
        assert_eq!(
            Condition::parse("geoip:ca"),
            Some(Condition::GeoIp("ca".into()))
        );
        assert!(matches!(
            Condition::parse("ip:1.2.3.4/24"),
            Some(Condition::Ip(_))
        ));
        assert_eq!(
            Condition::parse("port:1000-2000"),
            Some(Condition::Port { lo: 1000, hi: 2000 })
        );
        assert_eq!(
            Condition::parse("port:53"),
            Some(Condition::Port { lo: 53, hi: 53 })
        );
        assert_eq!(Condition::parse("bogus:x"), None);
        assert_eq!(Condition::parse("port:9-1"), None); // reversed range
    }

    #[test]
    fn domain_suffix_boundaries() {
        assert!(domain_suffix_match("google.com", "google.com"));
        assert!(domain_suffix_match("www.google.com", "google.com"));
        assert!(!domain_suffix_match("notgoogle.com", "google.com"));
        assert!(!domain_suffix_match("google.com.evil.com", "google.com"));
    }

    #[test]
    fn first_match_wins_in_config_order() {
        let d = tcp_dom("8.8.8.8", 443);
        let table = RouteTable::new(
            vec![
                MatchRule::new(
                    vec![Condition::parse("port:443").unwrap()],
                    vec!["a".into()],
                    BalanceMode::Random,
                ),
                MatchRule::new(vec![Condition::Any], vec!["b".into()], BalanceMode::Random),
            ],
            None,
        );
        assert_eq!(
            table.route(&query(&d), &NoGeo),
            RouteDecision::Outbound("a".into())
        );
    }

    #[test]
    fn absent_default_is_freedom() {
        let d = tcp_dom("example.com", 80);
        let table = RouteTable::new(
            vec![MatchRule::new(
                vec![Condition::parse("port:443").unwrap()],
                vec!["tls".into()],
                BalanceMode::Random,
            )],
            None,
        );
        assert_eq!(table.route(&query(&d), &NoGeo), RouteDecision::Freedom);
    }

    #[test]
    fn empty_outs_is_blackhole() {
        let d = tcp_dom("ads.example.com", 80);
        let table = RouteTable::new(
            vec![MatchRule::new(
                vec![Condition::parse("domain:example.com").unwrap()],
                vec![],
                BalanceMode::Random,
            )],
            None,
        );
        assert_eq!(table.route(&query(&d), &NoGeo), RouteDecision::Blackhole);
    }

    #[test]
    fn any_condition_matches_rule() {
        // Rule with two conditions; only the second matches -> rule matches (OR).
        let d = tcp_dom("1.2.3.4", 9000);
        let table = RouteTable::new(
            vec![MatchRule::new(
                vec![
                    Condition::parse("port:1-100").unwrap(),
                    Condition::parse("ip:1.2.3.0/24").unwrap(),
                ],
                vec!["hit".into()],
                BalanceMode::Random,
            )],
            None,
        );
        assert_eq!(
            table.route(&query(&d), &NoGeo),
            RouteDecision::Outbound("hit".into())
        );
    }

    #[test]
    fn geosite_and_geoip_via_matcher() {
        let mut geo = MapGeo::default();
        geo.sites.insert("openai".into(), vec!["openai.com".into()]);
        geo.ips
            .insert("ca".into(), vec![Cidr::parse("99.0.0.0/8").unwrap()]);

        let table = RouteTable::new(
            vec![
                MatchRule::new(
                    vec![Condition::parse("geosite:openai").unwrap()],
                    vec!["ai".into()],
                    BalanceMode::Random,
                ),
                MatchRule::new(
                    vec![Condition::parse("geoip:ca").unwrap()],
                    vec!["canada".into()],
                    BalanceMode::Random,
                ),
            ],
            None,
        );

        let site = tcp_dom("chat.openai.com", 443);
        assert_eq!(
            table.route(&query(&site), &geo),
            RouteDecision::Outbound("ai".into())
        );

        let ip = tcp_dom("99.1.2.3", 443);
        assert_eq!(
            table.route(&query(&ip), &geo),
            RouteDecision::Outbound("canada".into())
        );

        // Same rules, NoGeo -> geo conditions never match -> default freedom.
        assert_eq!(table.route(&query(&site), &NoGeo), RouteDecision::Freedom);
    }

    #[test]
    fn multi_outs_load_balances() {
        let d = tcp_dom("example.com", 443);
        let table = RouteTable::new(
            vec![MatchRule::new(
                vec![Condition::Any],
                vec!["o1".into(), "o2".into(), "o3".into()],
                BalanceMode::RoundRobin,
            )],
            None,
        );
        let picks: Vec<_> = (0..3).map(|_| table.route(&query(&d), &NoGeo)).collect();
        assert_eq!(
            picks,
            vec![
                RouteDecision::Outbound("o1".into()),
                RouteDecision::Outbound("o2".into()),
                RouteDecision::Outbound("o3".into()),
            ]
        );
    }

    #[test]
    fn sniffed_domain_used_for_bare_ip() {
        let d = tcp_dom("1.2.3.4", 443);
        let mut q = query(&d);
        q.sniffed_domain = Some("blocked.example.com");
        let table = RouteTable::new(
            vec![MatchRule::new(
                vec![Condition::parse("domain:example.com").unwrap()],
                vec![],
                BalanceMode::Random,
            )],
            None,
        );
        assert_eq!(table.route(&q, &NoGeo), RouteDecision::Blackhole);
    }
}
