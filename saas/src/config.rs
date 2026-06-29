//! XrayR-compatible configuration — the Rust analogue of XrayR's
//! `panel/config.go` (plus the `ApiConfig`/`ControllerConfig` sub-trees from
//! `api/apimodel.go` and `service/controller/config.go`).
//!
//! The on-disk format is TOML rather than XrayR's YAML, but the *key names* are
//! preserved verbatim (PascalCase, `NodeID`, `DNSType`, …) via explicit
//! `#[serde(rename = "…")]` so an operator's mental model carries over. Defaults
//! mirror `panel/defaultConfig.go`. Unknown keys are tolerated and ignored:
//! real XrayR configs carry many fields for features out of scope here
//! (REALITY, fallback, limiter, custom DNS/inbound/outbound), and they must
//! parse cleanly without us modelling them.

use anyhow::Context;
use serde::Deserialize;

use crate::egress_config::EgressConfig;

/// Top-level config (`panel.Config`). Only `Nodes` is required; `Log` and
/// `ConnectionConfig` fall back to XrayR's documented defaults when omitted.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(rename = "Log", default)]
    pub log: LogConfig,
    #[serde(rename = "ConnectionConfig", default)]
    pub connection: ConnectionConfig,
    #[serde(rename = "Nodes")]
    pub nodes: Vec<NodeConfig>,
    /// Optional top-level egress routing DSL: `enable = true` + `[[routes]]`.
    #[serde(flatten)]
    pub egress: EgressConfig,
}

/// Logging configuration (`panel.LogConfig`).
#[derive(Debug, Clone, Deserialize)]
pub struct LogConfig {
    /// `none`, `error`, `warning`, `info`, `debug`. Defaults to `none`.
    #[serde(rename = "Level", default = "default_log_level")]
    pub level: String,
    #[serde(rename = "AccessPath", default)]
    pub access_path: String,
    #[serde(rename = "ErrorPath", default)]
    pub error_path: String,
}

/// Per-connection tuning (`panel.ConnectionConfig`). All fields default to the
/// values from `panel/defaultConfig.go`.
#[derive(Debug, Clone, Deserialize)]
pub struct ConnectionConfig {
    #[serde(rename = "Handshake", default = "default_handshake")]
    pub handshake: u32,
    #[serde(rename = "ConnIdle", default = "default_conn_idle")]
    pub conn_idle: u32,
    #[serde(rename = "UplinkOnly", default = "default_uplink_only")]
    pub uplink_only: u32,
    #[serde(rename = "DownlinkOnly", default = "default_downlink_only")]
    pub downlink_only: u32,
    /// Internal per-connection cache size, in kB.
    #[serde(rename = "BufferSize", default = "default_buffer_size")]
    pub buffer_size: i32,
}

/// One panel node (`panel.NodesConfig`): which panel, plus its API and
/// controller sub-configs.
#[derive(Debug, Clone, Deserialize)]
pub struct NodeConfig {
    /// `SSpanel`, `NewV2board`, … Only `SSpanel` is wired up by this crate.
    #[serde(rename = "PanelType", default)]
    pub panel_type: String,
    #[serde(rename = "ApiConfig", default)]
    pub api: ApiConfigCfg,
    #[serde(rename = "ControllerConfig", default)]
    pub controller: ControllerConfig,
}

/// Panel API client settings (`api.Config`). Distinct from the normalized
/// [`crate::api::ApiConfig`] this converts into via [`NodeConfig::api_config`].
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ApiConfigCfg {
    #[serde(rename = "ApiHost", default)]
    pub api_host: String,
    #[serde(rename = "NodeID", default)]
    pub node_id: i32,
    #[serde(rename = "ApiKey", default)]
    pub api_key: String,
    /// `V2ray`, `Vmess`, `Vless`, `Trojan`, `Shadowsocks`, `Shadowsocks-Plugin`.
    #[serde(rename = "NodeType", default)]
    pub node_type: String,
    #[serde(rename = "EnableVless", default)]
    pub enable_vless: bool,
    #[serde(rename = "VlessFlow", default)]
    pub vless_flow: String,
    /// Request timeout in seconds (0 = downstream default).
    #[serde(rename = "Timeout", default)]
    pub timeout: u32,
    /// Speed-limit override in Mbps (0 = use panel value).
    #[serde(rename = "SpeedLimit", default)]
    pub speed_limit: f64,
    /// Device-limit override (0 = use panel value).
    #[serde(rename = "DeviceLimit", default)]
    pub device_limit: i32,
    #[serde(rename = "RuleListPath", default)]
    pub rule_list_path: String,
    #[serde(rename = "DisableCustomConfig", default)]
    pub disable_custom_config: bool,
}

/// Controller settings (`service/controller.Config`), trimmed to the fields the
/// xray-rs core acts on. REALITY/fallback/limiter fields are intentionally
/// absent — they parse into nothing and are dropped.
#[derive(Debug, Clone, Deserialize)]
pub struct ControllerConfig {
    #[serde(rename = "ListenIP", default = "default_bind_ip")]
    pub listen_ip: String,
    #[serde(rename = "SendIP", default = "default_bind_ip")]
    pub send_ip: String,
    /// Node-info / user-list refresh interval, in seconds.
    #[serde(rename = "UpdatePeriodic", default = "default_update_periodic")]
    pub update_periodic: u32,
    #[serde(rename = "EnableProxyProtocol", default)]
    pub enable_proxy_protocol: bool,
    #[serde(rename = "DisableSniffing", default)]
    pub disable_sniffing: bool,
    #[serde(rename = "DisableUploadTraffic", default)]
    pub disable_upload_traffic: bool,
    #[serde(rename = "DisableGetRule", default)]
    pub disable_get_rule: bool,
    /// DNS strategy: `AsIs`, `UseIP`, `UseIPv4`, `UseIPv6`.
    #[serde(rename = "DNSType", default = "default_dns_type")]
    pub dns_type: String,
    #[serde(rename = "CertConfig", default)]
    pub cert: CertConfig,
    /// Catch-all for XrayR keys this core does not model (fallback, custom DNS,
    /// REALITY, custom inbound/outbound, routing, …). Captured only so they can
    /// be warned about at startup; never read otherwise.
    #[serde(flatten)]
    pub unknown: std::collections::BTreeMap<String, toml::Value>,
}

/// TLS certificate acquisition settings (`mylego.CertConfig`).
#[derive(Debug, Clone, Deserialize)]
pub struct CertConfig {
    /// `none`, `file`, `http`, `tls`, `dns`. `none` disables TLS.
    #[serde(rename = "CertMode", default = "default_cert_mode")]
    pub cert_mode: String,
    #[serde(rename = "CertDomain", default)]
    pub cert_domain: String,
    #[serde(rename = "CertFile", default)]
    pub cert_file: String,
    #[serde(rename = "KeyFile", default)]
    pub key_file: String,
}

impl Config {
    /// Parse an XrayR-style TOML config.
    pub fn parse(text: &str) -> anyhow::Result<Config> {
        toml::from_str(text).context("failed to parse XrayR TOML config")
    }
}

impl NodeConfig {
    /// Build the normalized [`crate::api::ApiConfig`] this crate's panel client
    /// consumes, resolving the textual `NodeType`. Returns an error when the
    /// node type is one the xray-rs core does not support.
    pub fn api_config(&self) -> anyhow::Result<crate::api::ApiConfig> {
        let node_type = crate::api::NodeType::parse(&self.api.node_type)
            .with_context(|| format!("unsupported NodeType: {:?}", self.api.node_type))?;
        Ok(crate::api::ApiConfig {
            api_host: self.api.api_host.clone(),
            node_id: self.api.node_id,
            key: self.api.api_key.clone(),
            node_type,
            enable_vless: self.api.enable_vless,
            vless_flow: self.api.vless_flow.clone(),
            timeout: self.api.timeout,
            speed_limit: self.api.speed_limit,
            device_limit: self.api.device_limit,
            rule_list_path: self.api.rule_list_path.clone(),
            disable_custom_config: self.api.disable_custom_config,
        })
    }
}

// --- Defaults (mirrors `panel/defaultConfig.go`) -----------------------------

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            access_path: String::new(),
            error_path: String::new(),
        }
    }
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            handshake: default_handshake(),
            conn_idle: default_conn_idle(),
            uplink_only: default_uplink_only(),
            downlink_only: default_downlink_only(),
            buffer_size: default_buffer_size(),
        }
    }
}

impl Default for ControllerConfig {
    fn default() -> Self {
        Self {
            listen_ip: default_bind_ip(),
            send_ip: default_bind_ip(),
            update_periodic: default_update_periodic(),
            enable_proxy_protocol: false,
            disable_sniffing: false,
            disable_upload_traffic: false,
            disable_get_rule: false,
            dns_type: default_dns_type(),
            cert: CertConfig::default(),
            unknown: std::collections::BTreeMap::new(),
        }
    }
}

impl Default for CertConfig {
    fn default() -> Self {
        Self {
            cert_mode: default_cert_mode(),
            cert_domain: String::new(),
            cert_file: String::new(),
            key_file: String::new(),
        }
    }
}

fn default_log_level() -> String {
    "none".to_string()
}

fn default_handshake() -> u32 {
    4
}

fn default_conn_idle() -> u32 {
    30
}

fn default_uplink_only() -> u32 {
    2
}

fn default_downlink_only() -> u32 {
    4
}

fn default_buffer_size() -> i32 {
    64
}

fn default_bind_ip() -> String {
    "0.0.0.0".to_string()
}

fn default_update_periodic() -> u32 {
    60
}

fn default_dns_type() -> String {
    "AsIs".to_string()
}

fn default_cert_mode() -> String {
    "none".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A faithful TOML translation of `release/config/config.yml.example`'s
    /// active node, with `UpdatePeriodic`/`ListenIP` deliberately omitted so the
    /// controller defaults are exercised.
    const REPRESENTATIVE: &str = r#"
[Log]
Level = "warning"
AccessPath = "/etc/XrayR/access.log"
ErrorPath = "/etc/XrayR/error.log"

[ConnectionConfig]
Handshake = 4
ConnIdle = 30
UplinkOnly = 2
DownlinkOnly = 4
BufferSize = 64

[[Nodes]]
PanelType = "SSpanel"

[Nodes.ApiConfig]
ApiHost = "http://127.0.0.1:667"
ApiKey = "123"
NodeID = 41
NodeType = "V2ray"
Timeout = 30
EnableVless = false
VlessFlow = "xtls-rprx-vision"
SpeedLimit = 0.0
DeviceLimit = 0
RuleListPath = ""
DisableCustomConfig = false

[Nodes.ControllerConfig]
SendIP = "0.0.0.0"
DNSType = "AsIs"
EnableProxyProtocol = false

[Nodes.ControllerConfig.CertConfig]
CertMode = "dns"
CertDomain = "node1.test.com"
CertFile = "/etc/XrayR/cert/node1.test.com.cert"
KeyFile = "/etc/XrayR/cert/node1.test.com.key"
"#;

    #[test]
    fn parses_representative_config() {
        let cfg = Config::parse(REPRESENTATIVE).expect("representative config should parse");

        assert_eq!(cfg.nodes.len(), 1);
        let node = &cfg.nodes[0];
        assert_eq!(node.panel_type, "SSpanel");

        assert_eq!(node.api.api_host, "http://127.0.0.1:667");
        assert_eq!(node.api.node_id, 41);
        assert_eq!(node.api.api_key, "123");
        assert_eq!(node.api.node_type, "V2ray");
        assert_eq!(node.api.timeout, 30);
        assert_eq!(node.api.vless_flow, "xtls-rprx-vision");

        // Omitted in the TOML -> XrayR defaults must apply.
        assert_eq!(node.controller.update_periodic, 60);
        assert_eq!(node.controller.listen_ip, "0.0.0.0");
        // Present values carry through.
        assert_eq!(node.controller.send_ip, "0.0.0.0");
        assert_eq!(node.controller.dns_type, "AsIs");
        assert_eq!(node.controller.cert.cert_mode, "dns");
        assert_eq!(node.controller.cert.cert_domain, "node1.test.com");

        assert_eq!(cfg.log.level, "warning");
        assert_eq!(cfg.connection.buffer_size, 64);
    }

    #[test]
    fn ignores_unknown_keys() {
        // Keys for out-of-scope features (REALITY) plus a whole unknown nested
        // table must parse and be dropped silently.
        const WITH_UNKNOWN: &str = r#"
[[Nodes]]
PanelType = "SSpanel"

[Nodes.ApiConfig]
ApiHost = "http://127.0.0.1:667"
ApiKey = "123"
NodeID = 41
NodeType = "V2ray"

[Nodes.ControllerConfig]
EnableProxyProtocol = false
EnableREALITY = true
DisableLocalREALITYConfig = false

[Nodes.ControllerConfig.REALITYConfigs]
Show = true
Dest = "www.amazon.com:443"
ServerNames = ["www.amazon.com"]

[Nodes.ControllerConfig.AutoSpeedLimitConfig]
Limit = 0
WarnTimes = 0
"#;

        let cfg = Config::parse(WITH_UNKNOWN).expect("unknown keys should be ignored");
        assert_eq!(cfg.nodes.len(), 1);
        assert_eq!(cfg.nodes[0].panel_type, "SSpanel");
        assert!(!cfg.nodes[0].controller.enable_proxy_protocol);
    }

    #[test]
    fn api_config_ok_for_supported_type() {
        let cfg = Config::parse(REPRESENTATIVE).expect("parse");
        let api = cfg.nodes[0]
            .api_config()
            .expect("V2ray must resolve to a supported NodeType");

        assert_eq!(api.node_type, crate::api::NodeType::V2ray);
        assert_eq!(api.api_host, "http://127.0.0.1:667");
        assert_eq!(api.node_id, 41);
        assert_eq!(api.key, "123");
        assert_eq!(api.timeout, 30);
        assert_eq!(api.vless_flow, "xtls-rprx-vision");
        assert!(!api.enable_vless);
    }

    #[test]
    fn api_config_err_for_unsupported_type() {
        const T: &str = r#"
[[Nodes]]
PanelType = "SSpanel"

[Nodes.ApiConfig]
ApiHost = "http://127.0.0.1:667"
ApiKey = "123"
NodeID = 1
NodeType = "VlessReality"
"#;
        let cfg = Config::parse(T).expect("parse");
        assert!(
            cfg.nodes[0].api_config().is_err(),
            "VlessReality is not a supported NodeType"
        );
    }

    #[test]
    fn applies_defaults_for_minimal_config() {
        // Only the required node fields; Log/ConnectionConfig/ControllerConfig
        // are absent entirely, so every default path must fire.
        const T: &str = r#"
[[Nodes]]
PanelType = "SSpanel"

[Nodes.ApiConfig]
ApiHost = "http://127.0.0.1:667"
ApiKey = "123"
NodeID = 1
NodeType = "V2ray"
"#;
        let cfg = Config::parse(T).expect("minimal config should parse");

        assert_eq!(cfg.log.level, "none");
        assert_eq!(cfg.connection.handshake, 4);
        assert_eq!(cfg.connection.conn_idle, 30);
        assert_eq!(cfg.connection.uplink_only, 2);
        assert_eq!(cfg.connection.downlink_only, 4);
        assert_eq!(cfg.connection.buffer_size, 64);

        let node = &cfg.nodes[0];
        assert_eq!(node.controller.update_periodic, 60);
        assert_eq!(node.controller.listen_ip, "0.0.0.0");
        assert_eq!(node.controller.send_ip, "0.0.0.0");
        assert_eq!(node.controller.dns_type, "AsIs");
        assert_eq!(node.controller.cert.cert_mode, "none");
    }
}
