//! Panel-agnostic API value types — the Rust analogue of XrayR's
//! `api/apimodel.go`. These are the normalized types the controller consumes;
//! the SSPanel client (`crate::sspanel`) produces them from wire responses.

use compact_str::CompactString;
use regex::Regex;

/// Node protocol family, parsed from the panel's `NodeType` string.
///
/// Only the families supported by BOTH XrayR and the xray-rs core are modelled.
/// XTLS-only flows, REALITY, XHTTP and SS2022 are out of scope (objective) and
/// surface as build errors downstream rather than new variants here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NodeType {
    /// `V2ray` — built as VMess, or VLESS (flow=none) when `EnableVless`.
    V2ray,
    /// `Vmess` — always VMess.
    Vmess,
    /// `Vless` — always VLESS (flow=none).
    Vless,
    Trojan,
    Shadowsocks,
    /// `Shadowsocks-Plugin` — plain SS inbound plus a dokodemo streaming port.
    ShadowsocksPlugin,
    /// Internal node type used by the Shadowsocks-Plugin streaming inbound.
    Dokodemo,
}

impl NodeType {
    /// Parse the panel's node-type string (case-insensitive on the canonical
    /// spellings XrayR accepts).
    pub fn parse(s: &str) -> Option<NodeType> {
        match s {
            "V2ray" | "v2ray" | "V2Ray" => Some(NodeType::V2ray),
            "Vmess" | "vmess" | "VMess" => Some(NodeType::Vmess),
            "Vless" | "vless" | "VLESS" => Some(NodeType::Vless),
            "Trojan" | "trojan" => Some(NodeType::Trojan),
            "Shadowsocks" | "shadowsocks" => Some(NodeType::Shadowsocks),
            "Shadowsocks-Plugin" | "shadowsocks-plugin" => Some(NodeType::ShadowsocksPlugin),
            "dokodemo-door" | "dokodemo" => Some(NodeType::Dokodemo),
            _ => None,
        }
    }

    /// The canonical string XrayR uses (for tags and panel reporting).
    pub fn as_str(self) -> &'static str {
        match self {
            NodeType::V2ray => "V2ray",
            NodeType::Vmess => "Vmess",
            NodeType::Vless => "Vless",
            NodeType::Trojan => "Trojan",
            NodeType::Shadowsocks => "Shadowsocks",
            NodeType::ShadowsocksPlugin => "Shadowsocks-Plugin",
            NodeType::Dokodemo => "dokodemo-door",
        }
    }
}

/// Host system status reported to the panel (`api.NodeStatus`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct NodeStatus {
    pub cpu: f64,
    pub mem: f64,
    pub disk: f64,
    pub uptime: u64,
}

/// Normalized node configuration (`api.NodeInfo`), trimmed to the fields the
/// xray-rs core can act on. REALITY/XHTTP/XTLS fields are intentionally absent.
#[derive(Debug, Clone, PartialEq)]
pub struct NodeInfo {
    pub node_type: NodeType,
    pub node_id: i32,
    pub port: u32,
    /// Speed limit in bytes/sec (0 = unlimited). Carried for parity; the core
    /// does not yet enforce per-user speed limits.
    pub speed_limit: u64,
    pub alter_id: u16,
    /// Transport: `tcp`, `ws`/`websocket`, `grpc`, `httpupgrade`.
    pub transport_protocol: CompactString,
    pub host: CompactString,
    pub path: CompactString,
    pub enable_tls: bool,
    pub enable_vless: bool,
    pub vless_flow: CompactString,
    pub cypher_method: CompactString,
    /// Shadowsocks-2022 share key (unused by the core; SS2022 is out of scope).
    pub server_key: CompactString,
    pub service_name: CompactString,
    pub authority: CompactString,
    /// gRPC/TCP header type (e.g. `{"type":"http"}`), raw JSON, if any.
    pub header: Option<String>,
    pub accept_proxy_protocol: bool,
    /// True when the panel demands REALITY — the builder rejects it (out of scope).
    pub enable_reality: bool,
}

/// A single user as delivered by the panel (`api.UserInfo`).
///
/// `Eq`/`Hash` cover identity-bearing fields so the controller can diff old vs
/// new user sets (mirrors XrayR's `compareUserList`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UserInfo {
    pub uid: i32,
    pub email: CompactString,
    pub uuid: CompactString,
    pub passwd: CompactString,
    pub port: u32,
    pub alter_id: u16,
    pub method: CompactString,
    pub speed_limit: u64,
    pub device_limit: i32,
}

/// An online user IP report entry (`api.OnlineUser`).
#[derive(Debug, Clone, PartialEq)]
pub struct OnlineUser {
    pub uid: i32,
    pub ip: String,
}

/// Per-user traffic to report to the panel (`api.UserTraffic`).
#[derive(Debug, Clone, PartialEq)]
pub struct UserTraffic {
    pub uid: i32,
    pub email: CompactString,
    pub upload: i64,
    pub download: i64,
}

/// Self-description of an API client (`api.ClientInfo`).
#[derive(Debug, Clone, PartialEq)]
pub struct ClientInfo {
    pub api_host: String,
    pub node_id: i32,
    pub key: String,
    pub node_type: NodeType,
}

/// An audit rule (`api.DetectRule`): id plus a compiled regex.
#[derive(Debug, Clone)]
pub struct DetectRule {
    pub id: i32,
    pub pattern: Regex,
}

/// An audit hit to report (`api.DetectResult`).
#[derive(Debug, Clone, PartialEq)]
pub struct DetectResult {
    pub uid: i32,
    pub rule_id: i32,
}

/// API client configuration (`api.Config`), one per panel node.
#[derive(Debug, Clone)]
pub struct ApiConfig {
    pub api_host: String,
    pub node_id: i32,
    pub key: String,
    pub node_type: NodeType,
    pub enable_vless: bool,
    pub vless_flow: String,
    /// Request timeout in seconds (0 → default of 5).
    pub timeout: u32,
    /// Speed limit override in Mbps (0 = use panel value).
    pub speed_limit: f64,
    /// Device limit override (0 = use panel value).
    pub device_limit: i32,
    pub rule_list_path: String,
    pub disable_custom_config: bool,
}

/// Errors raised by the panel API client.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// The resource is unchanged since the last poll (HTTP 304 / ETag match).
    /// Not a failure — the controller reuses its cached value.
    #[error("resource not modified")]
    NotModified,
    /// Transport-level failure talking to the panel.
    #[error("request to {path} failed: {source}")]
    Request {
        path: String,
        #[source]
        source: reqwest::Error,
    },
    /// The panel returned a non-success HTTP status.
    #[error("request to {path} failed with status {status}: {body}")]
    Status {
        path: String,
        status: u16,
        body: String,
    },
    /// The panel returned `ret != 1` (application-level failure).
    #[error("panel returned ret={ret}")]
    Ret { ret: u64 },
    /// Failed to decode the panel's JSON.
    #[error("decoding {context} failed: {source}")]
    Decode {
        context: &'static str,
        #[source]
        source: serde_json::Error,
    },
    /// The node response could not be parsed into a [`NodeInfo`].
    #[error("parse node info failed: {0}")]
    ParseNode(String),
}

/// Convenience result alias for API operations.
pub type ApiResult<T> = Result<T, ApiError>;
