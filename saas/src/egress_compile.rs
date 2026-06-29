//! Compile the small egress TOML DSL into kernel routing objects.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Result, anyhow, bail};
use compact_str::CompactString;
use kernel::controller::router::{Cidr, DomainMatcher, Router, Rule};
use kernel::egress::outbound::{SocksOutbound, SsOutbound};
use kernel::{Address, Outbound};

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

/// Compiled runtime egress objects.
pub struct CompiledEgress {
    pub default_tag: CompactString,
    pub router: Option<Router>,
    pub outbounds: HashMap<CompactString, Outbound>,
}

/// Resolver hook for future geosite/geoip data. The default resolver skips
/// geodata while keeping explicit domain/IP rules active.
pub trait GeoResolver {
    fn geosite(&self, name: &str) -> Vec<DomainMatcher>;
    fn geoip(&self, name: &str) -> Vec<Cidr>;
}

/// No-op geodata resolver. `geosite:*` and `geoip:*` are warned and skipped.
pub struct NoopGeoResolver;

impl GeoResolver for NoopGeoResolver {
    fn geosite(&self, _name: &str) -> Vec<DomainMatcher> {
        Vec::new()
    }

    fn geoip(&self, _name: &str) -> Vec<Cidr> {
        Vec::new()
    }
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

/// Compile using [`NoopGeoResolver`].
pub fn compile(cfg: &EgressConfig) -> Result<CompiledEgress> {
    compile_with_geo(cfg, &NoopGeoResolver)
}

/// Compile raw config into kernel outbounds and router.
pub fn compile_with_geo(cfg: &EgressConfig, geo: &impl GeoResolver) -> Result<CompiledEgress> {
    if !cfg.enable {
        let default_tag = CompactString::new("default-direct");
        let mut outbounds = HashMap::new();
        outbounds.insert(default_tag.clone(), Outbound::Freedom);
        return Ok(CompiledEgress {
            default_tag,
            router: None,
            outbounds,
        });
    }

    let normalized = normalize(cfg)?;
    compile_normalized(&normalized, geo)
}

/// Compile already-normalized egress IR.
pub fn compile_normalized(
    normalized: &NormalizedEgress,
    geo: &impl GeoResolver,
) -> Result<CompiledEgress> {
    let mut outbounds = HashMap::new();
    for named in &normalized.outbounds {
        outbounds.insert(named.tag.clone(), compile_outbound(&named.spec)?);
    }

    let mut rules = Vec::new();
    for route in &normalized.routes {
        for expr in &route.rules {
            compile_rule_expr(expr, &route.tag, geo, &mut rules);
        }
    }

    let router = if rules.is_empty() {
        None
    } else {
        Some(Router::new(rules))
    };

    Ok(CompiledEgress {
        default_tag: normalized.default_tag.clone(),
        router,
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

fn compile_rule_expr(
    expr: &RuleExpr,
    tag: &CompactString,
    geo: &impl GeoResolver,
    out: &mut Vec<Rule>,
) {
    match expr {
        RuleExpr::DomainSuffix(s) => out.push(domain_rule(tag, DomainMatcher::Suffix(s.clone()))),
        RuleExpr::DomainFull(s) => out.push(domain_rule(tag, DomainMatcher::Full(s.clone()))),
        RuleExpr::DomainKeyword(s) => {
            out.push(domain_rule(tag, DomainMatcher::Keyword(s.clone())));
        }
        RuleExpr::GeoSite(name) => {
            let domains = geo.geosite(name);
            if domains.is_empty() {
                tracing::warn!(geosite = %name, "geosite rule skipped: no geodata resolver");
            } else {
                let mut rule = Rule {
                    outbound_tag: tag.clone(),
                    ..Rule::default()
                };
                rule.domains.extend(domains);
                out.push(rule);
            }
        }
        RuleExpr::GeoIp(name) => {
            let ips = geo.geoip(name);
            if ips.is_empty() {
                tracing::warn!(geoip = %name, "geoip rule skipped: no geodata resolver");
            } else {
                let mut rule = Rule {
                    outbound_tag: tag.clone(),
                    ..Rule::default()
                };
                rule.ips.extend(ips);
                out.push(rule);
            }
        }
        RuleExpr::CatchAll => out.push(Rule {
            outbound_tag: tag.clone(),
            ..Rule::default()
        }),
    }
}

fn domain_rule(tag: &CompactString, matcher: DomainMatcher) -> Rule {
    let mut rule = Rule {
        outbound_tag: tag.clone(),
        ..Rule::default()
    };
    rule.domains.push(matcher);
    rule
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress_config::EgressConfig;
    use kernel::{Destination, Network, RouteCtx};

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
        let router = compiled.router.as_ref().expect("router");
        let dest = Destination::tcp(Address::parse("www.netflix.com"), 443);
        let rc = RouteCtx {
            network: Network::Tcp,
            target: &dest,
            inbound_tag: "in",
            source: None,
            sniffed_domain: None,
            protocol: None,
        };

        assert_eq!(router.pick(&rc), Some("route-000"));
        assert!(compiled.outbounds.contains_key("default-direct"));
    }

    #[test]
    fn disabled_config_is_plain_direct() {
        let cfg = EgressConfig::parse("enable = false").expect("parse");
        let compiled = compile(&cfg).expect("compile");
        assert!(compiled.router.is_none());
        assert_eq!(compiled.default_tag, "default-direct");
        assert!(matches!(
            compiled.outbounds.get("default-direct"),
            Some(Outbound::Freedom)
        ));
    }
}
