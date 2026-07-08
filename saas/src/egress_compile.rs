//! Compile the small egress TOML DSL into kernel routing objects: a tag-keyed
//! outbound set plus a first-match [`RouteTable`]. The default branch resolves
//! to freedom (the `default-direct` outbound).

use std::sync::Arc;

use anyhow::{Result, anyhow, bail};
use compact_str::CompactString;

use kernel::{Address, BalanceMode, Condition, MatchRule, RouteTable};
use proxy::{Outbound, SocksOutbound, SsOutbound};

use crate::egress_config::{EgressConfig, OutSpec};

/// Normalized route config independent of TOML spelling.
#[derive(Debug, Clone)]
pub struct NormalizedEgress {
    pub default_tag: CompactString,
    pub routes: Vec<NormalizedRoute>,
    pub outbounds: Vec<NamedOutbound>,
}

/// A normalized route and its generated outbound tag.
#[derive(Debug, Clone)]
pub struct NormalizedRoute {
    pub tag: CompactString,
    pub rules: Vec<RuleExpr>,
}

/// A named outbound spec.
#[derive(Debug, Clone)]
pub struct NamedOutbound {
    pub tag: CompactString,
    pub spec: OutSpec,
}

/// Normalized matcher expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleExpr {
    DomainSuffix(CompactString),
    DomainFull(CompactString),
    DomainKeyword(CompactString),
    GeoSite(CompactString),
    GeoIp(CompactString),
    CatchAll,
}

/// Compiled runtime egress objects: the tag-keyed outbound set (for an
/// `OutboundList`), the first-match route table, and the tag that services the
/// default/"direct" branch.
pub struct CompiledEgress {
    pub freedom_tag: Option<CompactString>,
    pub route_table: RouteTable,
    pub outbounds: Vec<(CompactString, Outbound)>,
}

/// Normalize raw TOML into a stable IR. Routes with only comment labels are
/// ignored, so a `rules = ["#SG"]` block does not become a catch-all.
pub fn normalize(cfg: &EgressConfig) -> Result<NormalizedEgress> {
    let default_tag = CompactString::new("default-direct");
    let mut routes = Vec::new();
    let mut outbounds = Vec::new();

    for (idx, route) in cfg.routes.iter().enumerate() {
        let tag = CompactString::from(format!("route-{idx:03}"));
        let rules = route
            .rules
            .iter()
            .filter_map(|raw| parse_rule_expr(raw))
            .collect::<Vec<_>>();

        if rules.is_empty() {
            tracing::debug!(
                route = %tag,
                "egress route has no effective matchers; skipping"
            );
            continue;
        }
        if route.outs.len() != 1 {
            bail!(
                "egress route {tag} must have exactly one [[routes.Outs]] entry; got {}",
                route.outs.len()
            );
        }
        let spec = route
            .outs
            .first()
            .ok_or_else(|| anyhow!("egress route {tag} has no outbound"))?
            .clone();
        routes.push(NormalizedRoute {
            tag: tag.clone(),
            rules,
        });
        outbounds.push(NamedOutbound { tag, spec });
    }

    outbounds.push(NamedOutbound {
        tag: default_tag.clone(),
        spec: OutSpec::Direct,
    });

    Ok(NormalizedEgress {
        default_tag,
        routes,
        outbounds,
    })
}

/// Compile raw config into a kernel outbound set + route table.
pub fn compile(cfg: &EgressConfig) -> Result<CompiledEgress> {
    if !cfg.enable {
        let default_tag = CompactString::new("default-direct");
        return Ok(CompiledEgress {
            freedom_tag: Some(default_tag.clone()),
            route_table: RouteTable::new(Vec::new(), None),
            outbounds: vec![(default_tag, Outbound::Freedom)],
        });
    }
    let normalized = normalize(cfg)?;
    compile_normalized(&normalized)
}

/// Compile already-normalized egress IR.
pub fn compile_normalized(normalized: &NormalizedEgress) -> Result<CompiledEgress> {
    let mut outbounds = Vec::with_capacity(normalized.outbounds.len());
    for named in &normalized.outbounds {
        outbounds.push((named.tag.clone(), compile_outbound(&named.spec)?));
    }

    let mut rules = Vec::new();
    for route in &normalized.routes {
        let conds = rule_conditions(&route.rules);
        if conds.is_empty() {
            continue;
        }
        rules.push(MatchRule::new(
            conds,
            vec![route.tag.clone()],
            BalanceMode::Random,
        ));
    }
    // Absent default branch => Freedom (the default-direct outbound).
    let route_table = RouteTable::new(rules, None);

    Ok(CompiledEgress {
        freedom_tag: Some(normalized.default_tag.clone()),
        route_table,
        outbounds,
    })
}

fn parse_rule_expr(raw: &str) -> Option<RuleExpr> {
    let s = raw.trim();
    if s.is_empty() || s.starts_with('#') {
        return None;
    }
    if s == "*" {
        return Some(RuleExpr::CatchAll);
    }
    if let Some(rest) = s.strip_prefix("domain:") {
        return nonempty(rest).map(RuleExpr::DomainSuffix);
    }
    if let Some(rest) = s.strip_prefix("suffix:") {
        return nonempty(rest).map(RuleExpr::DomainSuffix);
    }
    if let Some(rest) = s.strip_prefix("full:") {
        return nonempty(rest).map(RuleExpr::DomainFull);
    }
    if let Some(rest) = s.strip_prefix("keyword:") {
        return nonempty(rest).map(RuleExpr::DomainKeyword);
    }
    if let Some(rest) = s.strip_prefix("geosite:") {
        return nonempty(rest).map(RuleExpr::GeoSite);
    }
    if let Some(rest) = s.strip_prefix("geoip:") {
        return nonempty(rest).map(RuleExpr::GeoIp);
    }
    nonempty(s).map(RuleExpr::DomainSuffix)
}

fn nonempty(s: &str) -> Option<CompactString> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(CompactString::new(trimmed))
    }
}

fn compile_outbound(spec: &OutSpec) -> Result<Outbound> {
    match spec {
        OutSpec::Direct => Ok(Outbound::Freedom),
        OutSpec::Block => Ok(Outbound::Blackhole),
        OutSpec::Shadowsocks {
            server,
            port,
            password,
            cipher,
            ..
        } => {
            let ob = SsOutbound::new(Address::parse(server), *port, password, cipher)
                .map_err(|e| anyhow!("shadowsocks outbound: {e}"))?;
            Ok(Outbound::Shadowsocks(Arc::new(ob)))
        }
        OutSpec::Socks {
            server,
            port,
            username,
            password,
            ..
        } => Ok(Outbound::Socks(Arc::new(SocksOutbound::new(
            Address::parse(server),
            *port,
            username.clone(),
            password.clone(),
        )))),
    }
}

/// Translate a route's matcher expressions into kernel [`Condition`]s, OR-combined
/// in the resulting [`MatchRule`]. `full:` collapses to a suffix match (no exact
/// match in the kernel router); `keyword:` has no kernel equivalent and is
/// dropped; `geosite:`/`geoip:` become geo conditions (matched only when a geo
/// resolver is wired — otherwise they never match).
fn rule_conditions(exprs: &[RuleExpr]) -> Vec<Condition> {
    let mut conds = Vec::new();
    for expr in exprs {
        match expr {
            RuleExpr::DomainSuffix(s) | RuleExpr::DomainFull(s) => {
                conds.push(Condition::DomainSuffix(s.to_ascii_lowercase()));
            }
            RuleExpr::DomainKeyword(name) => {
                tracing::warn!(keyword = %name, "keyword domain rule skipped: unsupported by kernel router");
            }
            RuleExpr::GeoSite(name) => conds.push(Condition::GeoSite(name.clone())),
            RuleExpr::GeoIp(name) => conds.push(Condition::GeoIp(name.clone())),
            RuleExpr::CatchAll => conds.push(Condition::Any),
        }
    }
    conds
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress_config::EgressConfig;
    use kernel::{Address, Destination, Network, NoGeo, RouteDecision, RouteQuery};

    #[test]
    fn normalize_skips_comments_and_keeps_catchall() {
        let cfg = EgressConfig::parse(
            r##"
            [[routes]]
            rules = ["#Only a label"]
              [[routes.Outs]]
              type = "direct"

            [[routes]]
            rules = ["domain:netflix.com", "full:api.example.com", "keyword:openai", "*"]
              [[routes.Outs]]
              type = "block"
            "##,
        )
        .expect("parse");

        let normalized = normalize(&cfg).expect("normalize");
        assert_eq!(normalized.routes.len(), 1);
        assert_eq!(normalized.routes[0].rules.len(), 4);
        assert!(matches!(
            normalized.routes[0].rules.last(),
            Some(RuleExpr::CatchAll)
        ));
    }

    #[test]
    fn compiles_and_routes_domain_before_default() {
        let cfg = EgressConfig::parse(
            r##"
            [[routes]]
            rules = ["domain:netflix.com"]
              [[routes.Outs]]
              type = "block"
            "##,
        )
        .expect("parse");

        let compiled = compile(&cfg).expect("compile");
        let dest = Destination::tcp(Address::parse("www.netflix.com"), 443);
        let q = RouteQuery {
            target: &dest,
            network: Network::Tcp,
            source: None,
            sniffed_domain: None,
            auth_hash: None,
        };
        assert_eq!(
            compiled.route_table.route(&q, &NoGeo),
            RouteDecision::Outbound("route-000".into())
        );
        assert!(
            compiled
                .outbounds
                .iter()
                .any(|(t, _)| t == "default-direct")
        );
    }

    #[test]
    fn disabled_config_is_plain_direct() {
        let cfg = EgressConfig::parse("enable = false").expect("parse");
        let compiled = compile(&cfg).expect("compile");
        assert_eq!(compiled.freedom_tag.as_deref(), Some("default-direct"));
        assert!(matches!(
            compiled.outbounds.first(),
            Some((_, Outbound::Freedom))
        ));
    }
}
