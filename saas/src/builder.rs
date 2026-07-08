//! Build xray-rs inbound handlers and stream configs from a panel [`NodeInfo`]
//! plus its user list — the Rust analogue of XrayR's `service/controller`
//! `inboundbuilder.go` + `userbuilder.go`, restricted to the protocol/transport
//! intersection the xray-rs core actually supports.
//!
//! Supported node types: `V2ray` (→ VMess, or VLESS flow=none when
//! `EnableVless`), `Vmess`, `Vless`, `Trojan`, `Shadowsocks` (AEAD ciphers).
//! Out of scope and rejected with a clear error: `Shadowsocks-Plugin`
//! (needs Xray's mux.cool plugin machinery), XTLS flows, REALITY, XHTTP/
//! splithttp transports, and SS2022 ciphers.

use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use compact_str::CompactString;

use kernel::Uuid;
use proxy::shadowsocks::method_kind;
use proxy::{
    Inbound, ProxyContext, Shadowsocks, Trojan, TrojanUsers, Vless, VlessUsers, Vmess, VmessUsers,
};
use transport::{
    GrpcConfig, HttpUpgradeConfig, Security, StreamConfig, TlsServer, TransportKind, WsConfig,
};

use crate::api::{NodeInfo, NodeType, UserInfo};
use crate::config::CertConfig;

/// A fully built inbound ready to bind.
pub struct BuiltInbound {
    pub tag: CompactString,
    pub listen: String,
    pub port: u16,
    pub stream: StreamConfig,
    pub handler: Arc<Inbound>,
}

/// XrayR's `buildNodeTag`: `{NodeType}_{ListenIP}_{Port}`.
pub fn build_node_tag(node: &NodeInfo, listen_ip: &str) -> CompactString {
    CompactString::from(format!(
        "{}_{}_{}",
        node.node_type.as_str(),
        listen_ip,
        node.port
    ))
}

/// XrayR's `buildUserTag`: `{node_tag}|{email}|{uid}` — the per-user traffic key.
pub fn build_user_tag(node_tag: &str, user: &UserInfo) -> CompactString {
    CompactString::from(format!("{}|{}|{}", node_tag, user.email, user.uid))
}

/// Whether a node is served as VLESS (vs VMess) — mirrors XrayR's
/// `EnableVless || NodeType == Vless`.
fn is_vless(node: &NodeInfo) -> bool {
    node.enable_vless || node.node_type == NodeType::Vless
}

/// Resolve the Shadowsocks cipher: the node method if present, else the first
/// user's method (old SSPanel SS API carries it per-user).
fn ss_method<'a>(node: &'a NodeInfo, users: &'a [UserInfo]) -> Option<&'a str> {
    if !node.cypher_method.is_empty() {
        Some(node.cypher_method.as_str())
    } else {
        users.first().map(|u| u.method.as_str())
    }
}

fn build_vless_users(users: &[UserInfo], node_tag: &str) -> VlessUsers {
    let mut built = Vec::with_capacity(users.len());
    for u in users {
        match Uuid::parse_str(&u.uuid) {
            Ok(id) => built.push((id, build_user_tag(node_tag, u), 0u32)),
            Err(e) => tracing::warn!(uid = u.uid, error = %e, "skipping vless user: bad uuid"),
        }
    }
    VlessUsers::new(built)
}

fn build_vmess_users(users: &[UserInfo], node_tag: &str) -> Result<VmessUsers> {
    let mut built = Vec::with_capacity(users.len());
    for u in users {
        match Uuid::parse_str(&u.uuid) {
            Ok(id) => built.push((id, build_user_tag(node_tag, u), 0u32)),
            Err(e) => tracing::warn!(uid = u.uid, error = %e, "skipping vmess user: bad uuid"),
        }
    }
    VmessUsers::new(built).map_err(|e| anyhow!("vmess user table: {e}"))
}

fn build_trojan_users(users: &[UserInfo], node_tag: &str) -> TrojanUsers {
    // XrayR uses the user UUID as the trojan password.
    let built: Vec<(String, CompactString, u32)> = users
        .iter()
        .map(|u| (u.uuid.to_string(), build_user_tag(node_tag, u), 0u32))
        .collect();
    TrojanUsers::new(built)
}

fn build_ss_user_iter(users: &[UserInfo], node_tag: &str) -> Vec<(String, CompactString, u32)> {
    users
        .iter()
        .map(|u| (u.passwd.to_string(), build_user_tag(node_tag, u), 0u32))
        .collect()
}

/// Build the inbound handler for `node` with its initial user set.
pub fn build_inbound_handler(
    node: &NodeInfo,
    users: &[UserInfo],
    node_tag: &str,
    cx: &ProxyContext,
) -> Result<Inbound> {
    match node.node_type {
        NodeType::V2ray | NodeType::Vmess | NodeType::Vless => {
            if is_vless(node) {
                if !node.vless_flow.is_empty() {
                    bail!(
                        "VLESS flow {:?} (XTLS/Vision) is not supported; only flow=none",
                        node.vless_flow
                    );
                }
                Ok(Inbound::Vless(Vless::new(
                    Arc::new(build_vless_users(users, node_tag)),
                    cx.clone(),
                )))
            } else {
                Ok(Inbound::Vmess(Vmess::new(
                    Arc::new(build_vmess_users(users, node_tag)?),
                    cx.clone(),
                )))
            }
        }
        NodeType::Trojan => Ok(Inbound::Trojan(Trojan::new(
            Arc::new(build_trojan_users(users, node_tag)),
            cx.clone(),
        ))),
        NodeType::Shadowsocks => {
            let method = ss_method(node, users)
                .ok_or_else(|| anyhow!("shadowsocks node has no cipher method and no users"))?;
            let kind = method_kind(method).ok_or_else(|| {
                anyhow!("unsupported shadowsocks method {method:?} (SS2022 is out of scope)")
            })?;
            Ok(Inbound::Shadowsocks(Shadowsocks::new(
                kind,
                build_ss_user_iter(users, node_tag),
                cx.clone(),
            )))
        }
        NodeType::ShadowsocksPlugin => {
            bail!("Shadowsocks-Plugin is not supported by the xray-rs core")
        }
        NodeType::Dokodemo => bail!("dokodemo-door is not a panel-served node type"),
    }
}

/// Re-apply a fresh user set to a live inbound handler (live user sync).
/// Returns an error if the handler variant does not match `node`.
pub fn apply_users(
    inbound: &Inbound,
    node: &NodeInfo,
    users: &[UserInfo],
    node_tag: &str,
) -> Result<()> {
    match inbound {
        Inbound::Vless(h) => h.set_users(Arc::new(build_vless_users(users, node_tag))),
        Inbound::Vmess(h) => h.set_users(Arc::new(build_vmess_users(users, node_tag)?)),
        Inbound::Trojan(h) => h.set_users(Arc::new(build_trojan_users(users, node_tag))),
        Inbound::Shadowsocks(h) => h.set_users(build_ss_user_iter(users, node_tag)),
        other => bail!(
            "cannot sync users: inbound variant {:?} does not match node {:?}",
            std::mem::discriminant(other),
            node.node_type
        ),
    }
    Ok(())
}

/// Build the transport-security + stream config for `node`.
pub fn build_stream(node: &NodeInfo, cert: &CertConfig) -> Result<StreamConfig> {
    if node.enable_reality {
        bail!("REALITY is not supported (out of scope)");
    }

    let security = if node.enable_tls && cert.cert_mode != "none" {
        if cert.cert_file.is_empty() || cert.key_file.is_empty() {
            bail!(
                "node requires TLS but CertConfig has no CertFile/KeyFile (cert_mode={:?}); \
                 only file-provided certificates are supported",
                cert.cert_mode
            );
        }
        let cert_pem = std::fs::read(&cert.cert_file)
            .with_context(|| format!("reading {}", cert.cert_file))?;
        let key_pem =
            std::fs::read(&cert.key_file).with_context(|| format!("reading {}", cert.key_file))?;
        let alpn = ["h2".to_string(), "http/1.1".to_string()];
        let server = TlsServer::from_pem(&cert_pem, &key_pem, &alpn)
            .map_err(|e| anyhow!("TLS setup: {e}"))?;
        Security::Tls(Arc::new(server))
    } else {
        Security::None
    };

    let transport = match node.transport_protocol.as_str() {
        "tcp" | "raw" | "" => TransportKind::Raw,
        "ws" | "websocket" => TransportKind::Ws(Arc::new(WsConfig {
            path: node.path.to_string(),
            host: if node.host.is_empty() {
                None
            } else {
                Some(node.host.to_string())
            },
        })),
        "httpupgrade" => TransportKind::HttpUpgrade(Arc::new(HttpUpgradeConfig {
            path: node.path.to_string(),
            host: if node.host.is_empty() {
                None
            } else {
                Some(node.host.to_string())
            },
        })),
        "grpc" | "gun" => TransportKind::Grpc(Arc::new(GrpcConfig {
            service_name: node.service_name.to_string(),
        })),
        "splithttp" | "xhttp" => bail!("XHTTP/splithttp transport is not supported (out of scope)"),
        other => bail!("unsupported transport protocol: {other:?}"),
    };

    Ok(StreamConfig {
        security,
        transport,
    })
}

/// Build a complete inbound (handler + stream) bound to `listen_ip`.
pub fn build_inbound(
    node: &NodeInfo,
    users: &[UserInfo],
    listen_ip: &str,
    cert: &CertConfig,
    cx: &ProxyContext,
) -> Result<BuiltInbound> {
    let port: u16 = node
        .port
        .try_into()
        .map_err(|_| anyhow!("node port {} out of range", node.port))?;
    if port == 0 {
        bail!("node port must be > 0");
    }
    let tag = build_node_tag(node, listen_ip);
    let handler = build_inbound_handler(node, users, &tag, cx)?;
    let stream = build_stream(node, cert)?;
    Ok(BuiltInbound {
        tag,
        listen: listen_ip.to_string(),
        port,
        stream,
        handler: Arc::new(handler),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::NodeType;

    fn node(node_type: NodeType) -> NodeInfo {
        NodeInfo {
            node_type,
            node_id: 7,
            port: 443,
            speed_limit: 0,
            alter_id: 0,
            transport_protocol: CompactString::from("tcp"),
            host: CompactString::default(),
            path: CompactString::default(),
            enable_tls: false,
            enable_vless: false,
            vless_flow: CompactString::default(),
            cypher_method: CompactString::default(),
            server_key: CompactString::default(),
            service_name: CompactString::default(),
            authority: CompactString::default(),
            header: None,
            accept_proxy_protocol: false,
            enable_reality: false,
        }
    }

    fn user(uid: i32, uuid: &str, passwd: &str, method: &str) -> UserInfo {
        UserInfo {
            uid,
            email: CompactString::default(),
            uuid: CompactString::from(uuid),
            passwd: CompactString::from(passwd),
            port: 0,
            alter_id: 0,
            method: CompactString::from(method),
            speed_limit: 0,
            device_limit: 0,
        }
    }

    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
    const NO_CERT: CertConfig = CertConfig {
        cert_mode: String::new(),
        cert_domain: String::new(),
        cert_file: String::new(),
        key_file: String::new(),
    };

    fn no_cert() -> CertConfig {
        CertConfig {
            cert_mode: "none".to_string(),
            cert_domain: String::new(),
            cert_file: String::new(),
            key_file: String::new(),
        }
    }

    fn test_cx() -> ProxyContext {
        let resolver = Arc::new(kernel::CachedResolver::system().expect("resolver"));
        let dialer = Arc::new(kernel::SystemDialer::new(resolver));
        ProxyContext::new(dialer, None, kernel::ConnectionPolicy::default())
    }

    #[test]
    fn node_and_user_tags() {
        let n = node(NodeType::V2ray);
        assert_eq!(build_node_tag(&n, "0.0.0.0"), "V2ray_0.0.0.0_443");
        let mut u = user(42, UUID, "pw", "");
        u.email = CompactString::from("alice");
        assert_eq!(
            build_user_tag("V2ray_0.0.0.0_443", &u),
            "V2ray_0.0.0.0_443|alice|42"
        );
    }

    #[test]
    fn v2ray_builds_vmess_by_default_and_vless_when_enabled() {
        let cx = test_cx();
        let users = vec![user(1, UUID, "", "")];
        let n = node(NodeType::V2ray);
        assert!(matches!(
            build_inbound_handler(&n, &users, "t", &cx).unwrap(),
            Inbound::Vmess(_)
        ));
        let mut nv = node(NodeType::V2ray);
        nv.enable_vless = true;
        assert!(matches!(
            build_inbound_handler(&nv, &users, "t", &cx).unwrap(),
            Inbound::Vless(_)
        ));
    }

    #[test]
    fn vless_flow_is_rejected() {
        let users = vec![user(1, UUID, "", "")];
        let mut n = node(NodeType::Vless);
        n.vless_flow = CompactString::from("xtls-rprx-vision");
        assert!(build_inbound_handler(&n, &users, "t", &test_cx()).is_err());
    }

    #[test]
    fn trojan_and_shadowsocks_build() {
        let cx = test_cx();
        let users = vec![user(1, UUID, "secret", "aes-128-gcm")];
        assert!(matches!(
            build_inbound_handler(&node(NodeType::Trojan), &users, "t", &cx).unwrap(),
            Inbound::Trojan(_)
        ));
        let mut ss = node(NodeType::Shadowsocks);
        ss.cypher_method = CompactString::from("aes-128-gcm");
        assert!(matches!(
            build_inbound_handler(&ss, &users, "t", &cx).unwrap(),
            Inbound::Shadowsocks(_)
        ));
    }

    #[test]
    fn shadowsocks_method_from_user_when_node_empty() {
        // Old SSPanel SS API leaves node method empty; fall back to the user's.
        let users = vec![user(1, UUID, "pw", "chacha20-ietf-poly1305")];
        let ss = node(NodeType::Shadowsocks);
        assert!(build_inbound_handler(&ss, &users, "t", &test_cx()).is_ok());
    }

    #[test]
    fn ss2022_and_plugin_are_rejected() {
        let cx = test_cx();
        let users = vec![user(1, UUID, "pw", "2022-blake3-aes-128-gcm")];
        let ss = node(NodeType::Shadowsocks);
        assert!(build_inbound_handler(&ss, &users, "t", &cx).is_err());
        assert!(
            build_inbound_handler(&node(NodeType::ShadowsocksPlugin), &users, "t", &cx).is_err()
        );
    }

    #[test]
    fn build_stream_transports() {
        let cert = no_cert();
        let mut n = node(NodeType::V2ray);
        n.transport_protocol = CompactString::from("tcp");
        assert!(matches!(
            build_stream(&n, &cert).unwrap().transport,
            TransportKind::Raw
        ));

        n.transport_protocol = CompactString::from("ws");
        n.path = CompactString::from("/p");
        n.host = CompactString::from("h.com");
        assert!(matches!(
            build_stream(&n, &cert).unwrap().transport,
            TransportKind::Ws(_)
        ));

        n.transport_protocol = CompactString::from("grpc");
        n.service_name = CompactString::from("GunSvc");
        assert!(matches!(
            build_stream(&n, &cert).unwrap().transport,
            TransportKind::Grpc(_)
        ));

        n.transport_protocol = CompactString::from("httpupgrade");
        assert!(matches!(
            build_stream(&n, &cert).unwrap().transport,
            TransportKind::HttpUpgrade(_)
        ));
    }

    #[test]
    fn build_stream_rejects_xhttp_and_reality() {
        let cert = no_cert();
        let mut x = node(NodeType::V2ray);
        x.transport_protocol = CompactString::from("xhttp");
        assert!(build_stream(&x, &cert).is_err());

        let mut r = node(NodeType::Trojan);
        r.enable_reality = true;
        assert!(build_stream(&r, &cert).is_err());
    }

    #[test]
    fn tls_without_cert_files_errors() {
        let mut n = node(NodeType::Trojan);
        n.enable_tls = true;
        let cert = CertConfig {
            cert_mode: "file".to_string(),
            ..no_cert()
        };
        assert!(build_stream(&n, &cert).is_err());
        // also ensure NO_CERT const is referenced (cert_mode "" disables TLS path)
        let _ = &NO_CERT;
    }

    #[test]
    fn apply_users_swaps_matching_handler() {
        let users = vec![user(1, UUID, "", "")];
        let n = node(NodeType::V2ray);
        let handler = build_inbound_handler(&n, &users, "t", &test_cx()).unwrap();
        let more = vec![user(1, UUID, "", ""), user(2, UUID, "", "")];
        assert!(apply_users(&handler, &n, &more, "t").is_ok());
    }
}
