//! TOML configuration schema and the build step that turns it into runtime
//! objects. The legacy xray JSON format is intentionally not used (objective).

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use compact_str::CompactString;
use serde::Deserialize;

use kernel::router::{Cidr, DomainMatcher, Router, Rule};
use kernel::{Dispatcher, Network, Outbound, Resolver, SystemDialer};
use proxy::{Inbound, Trojan, TrojanUsers, Vless, VlessUsers};
use transport::{
    HttpUpgradeConfig, Security, StreamConfig, TlsServer, TransportKind, WsConfig,
};

#[derive(Debug, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub log: LogCfg,
    #[serde(default, rename = "inbound")]
    pub inbounds: Vec<InboundCfg>,
    #[serde(default, rename = "outbound")]
    pub outbounds: Vec<OutboundCfg>,
    #[serde(default, rename = "route")]
    pub routes: Vec<RouteCfg>,
}

#[derive(Debug, Deserialize, Default)]
pub struct LogCfg {
    pub level: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct InboundCfg {
    pub tag: Option<String>,
    #[serde(default = "default_listen")]
    pub listen: String,
    pub port: u16,
    pub protocol: String,
    #[serde(default)]
    pub users: Vec<UserCfg>,
    pub tls: Option<TlsCfg>,
    pub transport: Option<TransportCfg>,
}

fn default_listen() -> String {
    "0.0.0.0".to_string()
}

#[derive(Debug, Deserialize)]
pub struct UserCfg {
    pub uuid: Option<String>,
    pub password: Option<String>,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub level: u32,
}

#[derive(Debug, Deserialize)]
pub struct TlsCfg {
    pub cert: String,
    pub key: String,
    pub alpn: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct TransportCfg {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub path: String,
    pub host: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OutboundCfg {
    pub tag: Option<String>,
    pub protocol: String,
}

#[derive(Debug, Deserialize)]
pub struct RouteCfg {
    pub outbound: String,
    #[serde(default)]
    pub domain: Vec<String>,
    #[serde(default)]
    pub ip: Vec<String>,
    #[serde(default)]
    pub source: Vec<String>,
    #[serde(default)]
    pub port: Vec<String>,
    #[serde(default)]
    pub network: Vec<String>,
    #[serde(default, rename = "inbound")]
    pub inbound_tag: Vec<String>,
    #[serde(default)]
    pub protocol: Vec<String>,
}

/// A fully built inbound: where to listen, how to wrap the stream, and the
/// handler that decodes it.
pub struct InboundInstance {
    pub tag: CompactString,
    pub listen: String,
    pub port: u16,
    pub stream: StreamConfig,
    pub handler: Arc<Inbound>,
}

/// Everything the runtime needs after parsing config.
pub struct Built {
    pub dispatcher: Arc<Dispatcher>,
    pub inbounds: Vec<InboundInstance>,
}

impl Config {
    pub fn parse(text: &str) -> Result<Config> {
        toml::from_str(text).context("parsing TOML config")
    }

    /// Build runtime objects (dispatcher, inbounds) from the parsed config.
    pub fn build(self) -> Result<Built> {
        let resolver = Arc::new(Resolver::system());
        let dialer = SystemDialer::new(resolver);

        let mut outbounds: HashMap<CompactString, Outbound> = HashMap::new();
        let mut default_tag: Option<CompactString> = None;
        for ob in &self.outbounds {
            let tag = CompactString::new(ob.tag.as_deref().unwrap_or(&ob.protocol));
            let outbound = match ob.protocol.as_str() {
                "freedom" | "direct" => Outbound::freedom(),
                "blackhole" | "block" => Outbound::blackhole(),
                other => bail!("unknown outbound protocol: {other}"),
            };
            if default_tag.is_none() {
                default_tag = Some(tag.clone());
            }
            outbounds.insert(tag, outbound);
        }
        if outbounds.is_empty() {
            outbounds.insert(CompactString::new("freedom"), Outbound::freedom());
            default_tag = Some(CompactString::new("freedom"));
        }
        let default_tag = default_tag.unwrap_or_else(|| CompactString::new("freedom"));

        let router = if self.routes.is_empty() {
            None
        } else {
            let mut rules = Vec::new();
            for r in &self.routes {
                rules.push(build_rule(r)?);
            }
            Some(Router::new(rules))
        };

        let dispatcher = Arc::new(Dispatcher::new(dialer, outbounds, default_tag, router));

        let mut inbounds = Vec::new();
        for ib in self.inbounds {
            inbounds.push(build_inbound(ib)?);
        }

        Ok(Built { dispatcher, inbounds })
    }
}

fn build_rule(r: &RouteCfg) -> Result<Rule> {
    let mut rule = Rule { outbound_tag: CompactString::new(&r.outbound), ..Rule::default() };
    for n in &r.network {
        match n.as_str() {
            "tcp" => rule.networks.push(Network::Tcp),
            "udp" => rule.networks.push(Network::Udp),
            other => bail!("bad route network: {other}"),
        }
    }
    for d in &r.domain {
        rule.domains.push(parse_domain_matcher(d));
    }
    for ip in &r.ip {
        rule.ips.push(Cidr::parse(ip).ok_or_else(|| anyhow!("bad ip cidr: {ip}"))?);
    }
    for s in &r.source {
        rule.source_ips.push(Cidr::parse(s).ok_or_else(|| anyhow!("bad source cidr: {s}"))?);
    }
    for p in &r.port {
        rule.ports.push(parse_port_range(p)?);
    }
    for t in &r.inbound_tag {
        rule.inbound_tags.push(CompactString::new(t));
    }
    for p in &r.protocol {
        rule.protocols.push(CompactString::new(p));
    }
    Ok(rule)
}

fn parse_domain_matcher(s: &str) -> DomainMatcher {
    if let Some(rest) = s.strip_prefix("full:") {
        DomainMatcher::Full(CompactString::new(rest))
    } else if let Some(rest) = s.strip_prefix("keyword:") {
        DomainMatcher::Keyword(CompactString::new(rest))
    } else if let Some(rest) = s.strip_prefix("suffix:") {
        DomainMatcher::Suffix(CompactString::new(rest))
    } else if let Some(rest) = s.strip_prefix("domain:") {
        DomainMatcher::Suffix(CompactString::new(rest))
    } else {
        DomainMatcher::Suffix(CompactString::new(s))
    }
}

fn parse_port_range(s: &str) -> Result<(u16, u16)> {
    match s.split_once('-') {
        Some((a, b)) => {
            let lo: u16 = a.trim().parse().context("port range low")?;
            let hi: u16 = b.trim().parse().context("port range high")?;
            Ok((lo.min(hi), lo.max(hi)))
        }
        None => {
            let p: u16 = s.trim().parse().context("port")?;
            Ok((p, p))
        }
    }
}

fn build_inbound(ib: InboundCfg) -> Result<InboundInstance> {
    let tag = CompactString::new(ib.tag.clone().unwrap_or_else(|| ib.protocol.clone()));

    let handler = match ib.protocol.as_str() {
        "vless" => {
            let mut users = Vec::new();
            for u in &ib.users {
                let uuid = u
                    .uuid
                    .as_deref()
                    .ok_or_else(|| anyhow!("vless user missing uuid"))?;
                let id = kernel::Uuid::parse_str(uuid).map_err(|e| anyhow!("bad uuid: {e}"))?;
                users.push((id, CompactString::new(&u.email), u.level));
            }
            Inbound::Vless(Vless::new(Arc::new(VlessUsers::new(users))))
        }
        "trojan" => {
            let mut users = Vec::new();
            for u in &ib.users {
                let pw = u
                    .password
                    .clone()
                    .ok_or_else(|| anyhow!("trojan user missing password"))?;
                users.push((pw, CompactString::new(&u.email), u.level));
            }
            Inbound::Trojan(Trojan::new(Arc::new(TrojanUsers::new(users))))
        }
        other => bail!("unknown/unsupported inbound protocol: {other}"),
    };

    let stream = build_stream(&ib)?;

    Ok(InboundInstance {
        tag,
        listen: ib.listen,
        port: ib.port,
        stream,
        handler: Arc::new(handler),
    })
}

fn build_stream(ib: &InboundCfg) -> Result<StreamConfig> {
    let security = match &ib.tls {
        None => Security::None,
        Some(tls) => {
            let cert = std::fs::read(&tls.cert).with_context(|| format!("reading {}", tls.cert))?;
            let key = std::fs::read(&tls.key).with_context(|| format!("reading {}", tls.key))?;
            let alpn = tls
                .alpn
                .clone()
                .unwrap_or_else(|| vec!["h2".to_string(), "http/1.1".to_string()]);
            let server = TlsServer::from_pem(&cert, &key, &alpn)
                .map_err(|e| anyhow!("tls setup: {e}"))?;
            Security::Tls(Arc::new(server))
        }
    };

    let transport = match &ib.transport {
        None => TransportKind::Raw,
        Some(t) => match t.kind.as_str() {
            "tcp" | "raw" => TransportKind::Raw,
            "ws" | "websocket" => TransportKind::Ws(Arc::new(WsConfig {
                path: t.path.clone(),
                host: t.host.clone(),
            })),
            "httpupgrade" => TransportKind::HttpUpgrade(Arc::new(HttpUpgradeConfig {
                path: t.path.clone(),
                host: t.host.clone(),
            })),
            other => bail!("unknown transport: {other}"),
        },
    };

    Ok(StreamConfig { security, transport })
}
