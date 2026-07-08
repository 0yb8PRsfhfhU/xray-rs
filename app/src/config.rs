//! TOML configuration schema and the build step that turns it into runtime
//! objects. The legacy xray JSON format is intentionally not used (objective).

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use compact_str::CompactString;
use serde::Deserialize;

use kernel::{
    BalanceMode, CachedResolver, Condition, ConnectionPolicy, MatchRule, NoGeo, OutboundDispatch,
    OutboundList, ProxyService, RouteService, RouteTable, SystemDialer,
};
use proxy::{
    Dokodemo, Http, HttpAccount, Inbound, ProxyContext, Shadowsocks, Socks, SocksAccount, Trojan,
    TrojanUsers, Vless, VlessUsers, Vmess, VmessUsers,
};
use transport::{
    GrpcConfig, HttpUpgradeConfig, Security, StreamConfig, StreamTransport, TlsServer,
    TransportKind, WsConfig,
};

/// Concrete outbound sum used by both binaries (freedom / blackhole / ss / socks).
type Ob = proxy::Outbound;
/// The system dialer specialised on the shared cached resolver.
type Dial = SystemDialer<CachedResolver>;
/// The tower service tree for one inbound: transport → proxy → (route, outbound).
type RouteChild = RouteService<NoGeo>;
type ObChild = OutboundDispatch<Ob, Dial>;
type ProxySvc = ProxyService<Inbound, RouteChild, ObChild>;
pub type InboundTree = kernel::TransportService<StreamTransport, ProxySvc>;
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

/// A config route. `source`/`network`/`inbound`/`protocol` are parsed for
/// config compatibility but have no kernel-router equivalent, so they are
/// intentionally ignored (only `domain`/`ip`/`port` map to conditions).
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
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

/// A fully built inbound: its listen address, the tower service tree that
/// frames + decodes + routes it, and the handler (kept for the standalone UDP
/// listener path, which lives outside the tree).
pub struct InboundInstance {
    pub tag: CompactString,
    pub listen: SocketAddr,
    pub tree: InboundTree,
    pub handler: Arc<Inbound>,
}

/// Everything the runtime needs after parsing config.
pub struct Built {
    pub inbounds: Vec<InboundInstance>,
}

impl Config {
    pub fn parse(text: &str) -> Result<Config> {
        toml::from_str(text).context("parsing TOML config")
    }

    /// Build the runtime service tree from the parsed config: one shared route +
    /// outbound child, and one `TransportService` → `ProxyService` per inbound.
    pub fn build(self) -> Result<Built> {
        let resolver = Arc::new(CachedResolver::system()?);
        let dialer = Arc::new(SystemDialer::new(resolver));
        let policy = ConnectionPolicy::default();

        // Outbound set (tag-keyed). The first freedom-kind outbound services the
        // default/"direct" route branch.
        let mut items: Vec<(CompactString, Ob)> = Vec::new();
        let mut freedom_tag: Option<CompactString> = None;
        for ob in &self.outbounds {
            let tag = CompactString::new(ob.tag.as_deref().unwrap_or(ob.protocol.default_tag()));
            let outbound = match ob.protocol {
                OutboundProtocolCfg::Freedom => {
                    if freedom_tag.is_none() {
                        freedom_tag = Some(tag.clone());
                    }
                    Ob::Freedom
                }
                OutboundProtocolCfg::Blackhole => Ob::Blackhole,
            };
            items.push((tag, outbound));
        }
        if items.is_empty() {
            items.push((CompactString::new("freedom"), Ob::Freedom));
            freedom_tag = Some(CompactString::new("freedom"));
        }
        let freedom_tag = freedom_tag.or_else(|| items.first().map(|(t, _)| t.clone()));
        let outbounds = Arc::new(OutboundList::new(items));

        // Route table: first-match rules over what the kernel router can express
        // (domain / ip / port); the absent default branch resolves to freedom.
        let mut rules = Vec::new();
        for r in &self.routes {
            if let Some(rule) = build_match_rule(r)? {
                rules.push(rule);
            }
        }
        let route_table = Arc::new(RouteTable::new(rules, None));

        // Children shared by every inbound (cloned into each ProxyService).
        let route_svc = RouteService::new(route_table, Arc::new(NoGeo));
        let ob_dispatch = OutboundDispatch::new(outbounds, dialer.clone(), freedom_tag);
        let cx = ProxyContext::new(dialer, None, policy);

        let mut inbounds = Vec::new();
        for ib in self.inbounds {
            inbounds.push(build_inbound(ib, &cx, &route_svc, &ob_dispatch)?);
        }

        Ok(Built { inbounds })
    }
}

/// Translate one config route into a kernel [`MatchRule`], or `None` when it
/// carries no condition the kernel router can express. The kernel router models
/// domain / ip / port / geo conditions OR-combined; the config's `source`,
/// `network`, `inbound`, and `protocol` selectors have no kernel equivalent and
/// are ignored (a rule reduced to nothing is dropped).
fn build_match_rule(r: &RouteCfg) -> Result<Option<MatchRule>> {
    let mut conds: Vec<Condition> = Vec::new();
    for d in &r.domain {
        if let Some(c) = domain_condition(d) {
            conds.push(c);
        }
    }
    for ip in &r.ip {
        let c =
            Condition::parse(&format!("ip:{ip}")).ok_or_else(|| anyhow!("bad ip cidr: {ip}"))?;
        conds.push(c);
    }
    for p in &r.port {
        let c = Condition::parse(&format!("port:{p}")).ok_or_else(|| anyhow!("bad port: {p}"))?;
        conds.push(c);
    }
    if conds.is_empty() {
        return Ok(None);
    }
    let outs = vec![CompactString::new(&r.outbound)];
    Ok(Some(MatchRule::new(conds, outs, BalanceMode::Random)))
}

/// Map a config domain matcher token to a kernel [`Condition`]. `full:`/`suffix:`
/// collapse to a suffix match (the kernel has no exact-only match); `geosite:`
/// passes through; `keyword:` has no kernel equivalent and is dropped.
fn domain_condition(d: &str) -> Option<Condition> {
    let token = if let Some(x) = d.strip_prefix("full:") {
        format!("domain:{x}")
    } else if let Some(x) = d.strip_prefix("suffix:") {
        format!("domain:{x}")
    } else if d.starts_with("domain:") || d.starts_with("geosite:") {
        d.to_string()
    } else if d.strip_prefix("keyword:").is_some() {
        return None;
    } else {
        format!("domain:{d}")
    };
    Condition::parse(&token)
}

fn build_inbound(
    ib: InboundCfg,
    cx: &ProxyContext,
    route_svc: &RouteChild,
    ob_dispatch: &ObChild,
) -> Result<InboundInstance> {
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
            Inbound::Vless(Vless::new(
                Arc::new(VlessUsers::new(built_users)),
                cx.clone(),
            ))
        }
        InboundProtocolCfg::Vmess { users } => {
            let mut built_users = Vec::new();
            for user in users {
                let id =
                    kernel::Uuid::parse_str(&user.uuid).map_err(|e| anyhow!("bad uuid: {e}"))?;
                built_users.push((id, CompactString::new(&user.email), user.level));
            }
            let table = VmessUsers::new(built_users).map_err(|e| anyhow!("vmess users: {e}"))?;
            Inbound::Vmess(Vmess::new(Arc::new(table), cx.clone()))
        }
        InboundProtocolCfg::Trojan { users } => {
            let mut built_users = Vec::new();
            for user in users {
                built_users.push((user.password, CompactString::new(&user.email), user.level));
            }
            Inbound::Trojan(Trojan::new(
                Arc::new(TrojanUsers::new(built_users)),
                cx.clone(),
            ))
        }
        InboundProtocolCfg::Shadowsocks { method, users } => {
            let kind = proxy::shadowsocks::method_kind(&method)
                .ok_or_else(|| anyhow!("unsupported shadowsocks method: {method}"))?;
            let mut built_users = Vec::new();
            for user in users {
                built_users.push((user.password, CompactString::new(&user.email), user.level));
            }
            Inbound::Shadowsocks(Shadowsocks::new(kind, built_users, cx.clone()))
        }
        InboundProtocolCfg::Socks { users } => {
            let mut accounts = Vec::new();
            for user in users {
                accounts.push(SocksAccount {
                    username: user.username,
                    password: user.password,
                });
            }
            Inbound::Socks(Socks::new(accounts, cx.clone()))
        }
        InboundProtocolCfg::Http { users } => {
            let mut accounts = Vec::new();
            for user in users {
                accounts.push(HttpAccount {
                    username: user.username,
                    password: user.password,
                });
            }
            Inbound::Http(Http::new(accounts, cx.clone()))
        }
        InboundProtocolCfg::Dokodemo {
            target_address,
            target_port,
        } => Inbound::Dokodemo(Dokodemo::new(
            kernel::Address::parse(&target_address),
            target_port,
            cx.clone(),
        )),
    };

    let stream = build_stream(tls, transport)?;
    let addr: SocketAddr = format!("{listen}:{port}")
        .parse()
        .with_context(|| format!("invalid listen address {listen}:{port}"))?;

    let handler = Arc::new(handler);
    let transport_svc = StreamTransport::new(stream, addr);
    let proxy_svc = ProxyService::new(handler.clone(), route_svc.clone(), ob_dispatch.clone());
    let tree = kernel::TransportService::new(Arc::new(transport_svc), proxy_svc, tag.clone());

    Ok(InboundInstance {
        tag,
        listen: addr,
        tree,
        handler,
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
