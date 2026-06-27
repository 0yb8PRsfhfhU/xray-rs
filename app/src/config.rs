//! TOML configuration schema and the build step that turns it into runtime
//! objects. The legacy xray JSON format is intentionally not used (objective).

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use compact_str::CompactString;
use serde::Deserialize;

use kernel::controller::router::{Cidr, DomainMatcher, Router, Rule};
use kernel::{CachedResolver, Dispatcher, Network, Outbound, SystemDialer};
use proxy::{
    Dokodemo, Http, HttpAccount, Inbound, Shadowsocks, Socks, SocksAccount, Trojan, TrojanUsers,
    Vless, VlessUsers, Vmess, VmessUsers,
};
use transport::{
    GrpcConfig, HttpUpgradeConfig, Security, StreamConfig, TlsServer, TransportKind, WsConfig,
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
    #[serde(flatten)]
    pub protocol: InboundProtocolCfg,
    pub tls: Option<TlsCfg>,
    pub transport: Option<TransportCfg>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "protocol")]
pub enum InboundProtocolCfg {
    #[serde(rename = "vless")]
    Vless {
        #[serde(default)]
        users: Vec<IdUserCfg>,
    },
    #[serde(rename = "vmess")]
    Vmess {
        #[serde(default)]
        users: Vec<IdUserCfg>,
    },
    #[serde(rename = "trojan")]
    Trojan {
        #[serde(default)]
        users: Vec<PasswordUserCfg>,
    },
    #[serde(rename = "shadowsocks", alias = "ss")]
    Shadowsocks {
        method: String,
        #[serde(default)]
        users: Vec<PasswordUserCfg>,
    },
    #[serde(rename = "socks", alias = "socks5")]
    Socks {
        #[serde(default)]
        users: Vec<AccountUserCfg>,
    },
    #[serde(rename = "http")]
    Http {
        #[serde(default)]
        users: Vec<AccountUserCfg>,
    },
    #[serde(rename = "dokodemo", alias = "dokodemo-door")]
    Dokodemo {
        /// dokodemo-door fixed relay target (host/domain). `port` is the LISTEN port.
        target_address: String,
        target_port: u16,
    },
}

impl InboundProtocolCfg {
    fn default_tag(&self) -> &'static str {
        match self {
            Self::Vless { .. } => "vless",
            Self::Vmess { .. } => "vmess",
            Self::Trojan { .. } => "trojan",
            Self::Shadowsocks { .. } => "shadowsocks",
            Self::Socks { .. } => "socks",
            Self::Http { .. } => "http",
            Self::Dokodemo { .. } => "dokodemo",
        }
    }
}

fn default_listen() -> String {
    "0.0.0.0".to_string()
}

#[derive(Debug, Deserialize)]
pub struct IdUserCfg {
    pub uuid: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub level: u32,
}

#[derive(Debug, Deserialize)]
pub struct PasswordUserCfg {
    pub password: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub level: u32,
}

#[derive(Debug, Deserialize)]
pub struct AccountUserCfg {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct TlsCfg {
    pub cert: String,
    pub key: String,
    pub alpn: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum TransportCfg {
    #[serde(rename = "tcp", alias = "raw")]
    Raw,
    #[serde(rename = "ws", alias = "websocket")]
    Ws {
        #[serde(default)]
        path: String,
        host: Option<String>,
    },
    #[serde(rename = "httpupgrade")]
    HttpUpgrade {
        #[serde(default)]
        path: String,
        host: Option<String>,
    },
    #[serde(rename = "grpc", alias = "gun")]
    Grpc {
        #[serde(default)]
        service_name: String,
    },
}

#[derive(Debug, Deserialize)]
pub struct OutboundCfg {
    pub tag: Option<String>,
    #[serde(flatten)]
    pub protocol: OutboundProtocolCfg,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "protocol")]
pub enum OutboundProtocolCfg {
    #[serde(rename = "freedom", alias = "direct")]
    Freedom,
    #[serde(rename = "blackhole", alias = "block")]
    Blackhole,
}

impl OutboundProtocolCfg {
    fn default_tag(&self) -> &'static str {
        match self {
            Self::Freedom => "freedom",
            Self::Blackhole => "blackhole",
        }
    }
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
        let resolver = Arc::new(CachedResolver::system()?);
        let dialer = SystemDialer::new(resolver);

        let mut outbounds: HashMap<CompactString, Outbound> = HashMap::new();
        let mut default_tag: Option<CompactString> = None;
        for ob in &self.outbounds {
            let tag = CompactString::new(ob.tag.as_deref().unwrap_or(ob.protocol.default_tag()));
            let outbound = match ob.protocol {
                OutboundProtocolCfg::Freedom => Outbound::Freedom,
                OutboundProtocolCfg::Blackhole => Outbound::Blackhole,
            };
            if default_tag.is_none() {
                default_tag = Some(tag.clone());
            }
            outbounds.insert(tag, outbound);
        }
        if outbounds.is_empty() {
            outbounds.insert(CompactString::new("freedom"), Outbound::Freedom);
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

        Ok(Built {
            dispatcher,
            inbounds,
        })
    }
}

fn build_rule(r: &RouteCfg) -> Result<Rule> {
    let mut rule = Rule {
        outbound_tag: CompactString::new(&r.outbound),
        ..Rule::default()
    };
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
        rule.ips
            .push(Cidr::parse(ip).ok_or_else(|| anyhow!("bad ip cidr: {ip}"))?);
    }
    for s in &r.source {
        rule.source_ips
            .push(Cidr::parse(s).ok_or_else(|| anyhow!("bad source cidr: {s}"))?);
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
    let InboundCfg {
        tag,
        listen,
        port,
        protocol,
        tls,
        transport,
    } = ib;

    let tag = CompactString::new(tag.unwrap_or_else(|| protocol.default_tag().to_string()));

    let handler = match protocol {
        InboundProtocolCfg::Vless { users } => {
            let mut built_users = Vec::new();
            for user in users {
                let id =
                    kernel::Uuid::parse_str(&user.uuid).map_err(|e| anyhow!("bad uuid: {e}"))?;
                built_users.push((id, CompactString::new(&user.email), user.level));
            }
            Inbound::Vless(Vless::new(Arc::new(VlessUsers::new(built_users))))
        }
        InboundProtocolCfg::Vmess { users } => {
            let mut built_users = Vec::new();
            for user in users {
                let id =
                    kernel::Uuid::parse_str(&user.uuid).map_err(|e| anyhow!("bad uuid: {e}"))?;
                built_users.push((id, CompactString::new(&user.email), user.level));
            }
            let table = VmessUsers::new(built_users).map_err(|e| anyhow!("vmess users: {e}"))?;
            Inbound::Vmess(Vmess::new(Arc::new(table)))
        }
        InboundProtocolCfg::Trojan { users } => {
            let mut built_users = Vec::new();
            for user in users {
                built_users.push((user.password, CompactString::new(&user.email), user.level));
            }
            Inbound::Trojan(Trojan::new(Arc::new(TrojanUsers::new(built_users))))
        }
        InboundProtocolCfg::Shadowsocks { method, users } => {
            let kind = proxy::shadowsocks::method_kind(&method)
                .ok_or_else(|| anyhow!("unsupported shadowsocks method: {method}"))?;
            let mut built_users = Vec::new();
            for user in users {
                built_users.push((user.password, CompactString::new(&user.email), user.level));
            }
            Inbound::Shadowsocks(Shadowsocks::new(kind, built_users))
        }
        InboundProtocolCfg::Socks { users } => {
            let mut accounts = Vec::new();
            for user in users {
                accounts.push(SocksAccount {
                    username: user.username,
                    password: user.password,
                });
            }
            Inbound::Socks(Socks::new(accounts))
        }
        InboundProtocolCfg::Http { users } => {
            let mut accounts = Vec::new();
            for user in users {
                accounts.push(HttpAccount {
                    username: user.username,
                    password: user.password,
                });
            }
            Inbound::Http(Http::new(accounts))
        }
        InboundProtocolCfg::Dokodemo {
            target_address,
            target_port,
        } => Inbound::Dokodemo(Dokodemo::new(
            kernel::Address::parse(&target_address),
            target_port,
        )),
    };

    let stream = build_stream(tls, transport)?;

    Ok(InboundInstance {
        tag,
        listen,
        port,
        stream,
        handler: Arc::new(handler),
    })
}

fn build_stream(tls: Option<TlsCfg>, transport: Option<TransportCfg>) -> Result<StreamConfig> {
    let security = match tls {
        None => Security::None,
        Some(tls) => {
            let cert = std::fs::read(&tls.cert).with_context(|| format!("reading {}", tls.cert))?;
            let key = std::fs::read(&tls.key).with_context(|| format!("reading {}", tls.key))?;
            let alpn = tls
                .alpn
                .unwrap_or_else(|| vec!["h2".to_string(), "http/1.1".to_string()]);
            let server =
                TlsServer::from_pem(&cert, &key, &alpn).map_err(|e| anyhow!("tls setup: {e}"))?;
            Security::Tls(Arc::new(server))
        }
    };

    let transport = match transport {
        None => TransportKind::Raw,
        Some(TransportCfg::Raw) => TransportKind::Raw,
        Some(TransportCfg::Ws { path, host }) => {
            TransportKind::Ws(Arc::new(WsConfig { path, host }))
        }
        Some(TransportCfg::HttpUpgrade { path, host }) => {
            TransportKind::HttpUpgrade(Arc::new(HttpUpgradeConfig { path, host }))
        }
        Some(TransportCfg::Grpc { service_name }) => {
            TransportKind::Grpc(Arc::new(GrpcConfig { service_name }))
        }
    };

    Ok(StreamConfig {
        security,
        transport,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_inbound_and_transport_aliases() {
        let text = r#"
            [[inbound]]
            port = 1080
            protocol = "socks5"
              [[inbound.users]]
              username = "alice"
              password = "secret"
              [inbound.transport]
              type = "websocket"
              path = "/ws"

            [[inbound]]
            port = 8388
            protocol = "ss"
            method = "aes-128-gcm"
              [[inbound.users]]
              password = "ss-secret"

            [[inbound]]
            port = 5300
            protocol = "dokodemo-door"
            target_address = "1.1.1.1"
            target_port = 53

            [[outbound]]
            protocol = "direct"
        "#;

        let cfg = Config::parse(text).expect("config parse should succeed");

        assert!(matches!(
            cfg.inbounds[0].protocol,
            InboundProtocolCfg::Socks { .. }
        ));
        assert!(matches!(
            cfg.inbounds[0].transport,
            Some(TransportCfg::Ws { .. })
        ));
        assert!(matches!(
            cfg.inbounds[1].protocol,
            InboundProtocolCfg::Shadowsocks { .. }
        ));
        assert!(matches!(
            cfg.inbounds[2].protocol,
            InboundProtocolCfg::Dokodemo { .. }
        ));
        assert!(matches!(
            cfg.outbounds[0].protocol,
            OutboundProtocolCfg::Freedom
        ));
    }

    #[test]
    fn parse_rejects_unknown_protocol() {
        let text = r#"
            [[inbound]]
            port = 1080
            protocol = "unknown-proto"
        "#;

        let err = Config::parse(text).expect_err("unknown protocol must fail");
        let msg = format!("{err:#}");
        assert!(msg.contains("unknown variant"));
    }
}
