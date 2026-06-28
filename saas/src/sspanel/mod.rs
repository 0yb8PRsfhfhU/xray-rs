//! SSPanel (XrayR variant) HTTP API client — a faithful port of
//! `XrayR/api/sspanel/sspanel.go`.
//!
//! The [`SspanelClient`] talks to an SSPanel `mod_mu` backend: it polls node
//! configuration and the user list, reports node status / online IPs / traffic,
//! and pulls and reports audit rules. Wire (de)serialization lives in
//! [`model`]; this module owns the transport, the ETag/version state, and the
//! pure node-string/custom-config parsers that produce [`crate::api`] types.
//!
//! The parser free functions ([`parse_v2ray_node_response`], etc.) are network
//! free and unit-tested directly. XTLS flows, REALITY, XHTTP and SS2022 are out
//! of scope: REALITY presence is surfaced via [`NodeInfo::enable_reality`] but
//! no REALITY config is built.

mod model;

use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::LazyLock;
use std::time::Duration;

use compact_str::CompactString;
use regex::Regex;
use reqwest::header::{ACCEPT, ETAG, IF_NONE_MATCH};
use serde::Serialize;
use serde_json::Value;

use crate::api::*;
use model::{
    CustomConfig, IllegalItem, NodeInfoResponse, OnlineUserWire, PostData, Response, RuleItem,
    SystemLoad, UserResponse, UserTrafficWire,
};

/// Trojan node-string regexes, mirroring the package-level `regexp.MustCompile`
/// vars in `sspanel.go`. The `(?m)` flag matches the Go originals (inert here,
/// the patterns use no anchors).
static FIRST_PORT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)port=(\d+)#?").expect("valid first-port regex"));
static SECOND_PORT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)port=\d+#(\d+)").expect("valid second-port regex"));
static HOST_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)host=([\w.]+)\|?").expect("valid host regex"));

/// Inputs the pure parsers need from the client, decoupling them from the live
/// HTTP client so they can be unit-tested without a network.
pub struct ParseParams {
    pub node_type: NodeType,
    pub node_id: i32,
    pub enable_vless: bool,
    pub vless_flow: String,
    pub speed_limit: f64,
    pub device_limit: i32,
}

/// An SSPanel `mod_mu` API client (`sspanel.APIClient`).
pub struct SspanelClient {
    client: reqwest::Client,
    api_host: String,
    node_id: i32,
    key: String,
    node_type: NodeType,
    enable_vless: bool,
    vless_flow: String,
    speed_limit: f64,
    device_limit: i32,
    disable_custom_config: bool,
    /// ETag cache keyed by endpoint (`"node"`, `"users"`, `"rules"`).
    etags: Mutex<HashMap<&'static str, String>>,
    /// Panel version learned from the last `get_node_info`, gating which API
    /// flavour and which reports are used.
    version: Mutex<String>,
}

impl SspanelClient {
    /// Build a client from an [`ApiConfig`] (`sspanel.New`). The request timeout
    /// falls back to 5s when unset.
    pub fn new(cfg: &ApiConfig) -> SspanelClient {
        let timeout = if cfg.timeout > 0 {
            cfg.timeout as u64
        } else {
            5
        };
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout))
            .build()
            // A TLS-backend init failure is environmental and unrecoverable
            // here; degrade to a default client rather than panic.
            .unwrap_or_else(|_| reqwest::Client::new());

        SspanelClient {
            client,
            api_host: cfg.api_host.clone(),
            node_id: cfg.node_id,
            key: cfg.key.clone(),
            node_type: cfg.node_type,
            enable_vless: cfg.enable_vless,
            vless_flow: cfg.vless_flow.clone(),
            speed_limit: cfg.speed_limit,
            device_limit: cfg.device_limit,
            disable_custom_config: cfg.disable_custom_config,
            etags: Mutex::new(HashMap::new()),
            version: Mutex::new(String::new()),
        }
    }

    /// Describe this client (`APIClient.Describe`).
    pub fn describe(&self) -> ClientInfo {
        ClientInfo {
            api_host: self.api_host.clone(),
            node_id: self.node_id,
            key: self.key.clone(),
            node_type: self.node_type,
        }
    }

    /// Pull and parse node configuration (`APIClient.GetNodeInfo`).
    ///
    /// Returns [`ApiError::NotModified`] when the panel reports HTTP 304.
    pub async fn get_node_info(&self) -> ApiResult<NodeInfo> {
        let path = format!("/mod_mu/nodes/{}/info", self.node_id);
        let data = self.get_json(&path, "node", false).await?;
        let node_resp: NodeInfoResponse =
            serde_json::from_value(data).map_err(|e| ApiError::Decode {
                context: "node info",
                source: e,
            })?;
        self.set_version(&node_resp.version);

        let params = self.parse_params();
        // Old API when custom config is disabled or the panel predates 2021.11.
        let expired = compare_version(&node_resp.version, "2021.11") == -1;
        if self.disable_custom_config || expired {
            if expired {
                tracing::warn!(
                    version = %node_resp.version,
                    "SSPanel version is expired; an update is recommended"
                );
            }
            match self.node_type {
                NodeType::V2ray => parse_v2ray_node_response(&params, &node_resp),
                NodeType::Trojan => parse_trojan_node_response(&params, &node_resp),
                NodeType::Shadowsocks => {
                    // Old SS API carries no port in the node string; learn it
                    // from the first user (mirrors ParseSSNodeResponse).
                    let first_port = self.fetch_first_user_port().await?;
                    parse_ss_node_response(&params, &node_resp, first_port)
                }
                NodeType::ShadowsocksPlugin => parse_ss_plugin_node_response(&params, &node_resp),
                other => Err(ApiError::ParseNode(format!(
                    "unsupported node type: {}",
                    other.as_str()
                ))),
            }
        } else {
            parse_sspanel_node_info(&params, &node_resp)
        }
    }

    /// Pull and parse the user list (`APIClient.GetUserList`).
    pub async fn get_user_list(&self) -> ApiResult<Vec<UserInfo>> {
        let data = self.get_json("/mod_mu/users", "users", true).await?;
        let users: Vec<UserResponse> =
            serde_json::from_value(data).map_err(|e| ApiError::Decode {
                context: "user list",
                source: e,
            })?;
        parse_user_list_response(&self.parse_params(), &users)
    }

    /// Report host status (`APIClient.ReportNodeStatus`). No-op on panels
    /// >= 2023.2, which compute load server-side.
    pub async fn report_node_status(&self, status: &NodeStatus) -> ApiResult<()> {
        if compare_version(&self.get_version(), "2023.2") == -1 {
            let path = format!("/mod_mu/nodes/{}/info", self.node_id);
            let body = SystemLoad {
                uptime: status.uptime.to_string(),
                load: format!(
                    "{:.2} {:.2} {:.2}",
                    status.cpu / 100.0,
                    status.mem / 100.0,
                    status.disk / 100.0
                ),
            };
            self.post_json(&path, false, &body).await?;
        }
        Ok(())
    }

    /// Report online user IPs (`APIClient.ReportNodeOnlineUsers`).
    pub async fn report_node_online_users(&self, users: &[OnlineUser]) -> ApiResult<()> {
        let data: Vec<OnlineUserWire> = users
            .iter()
            .map(|u| OnlineUserWire {
                user_id: u.uid,
                ip: u.ip.clone(),
            })
            .collect();
        self.post_json("/mod_mu/users/aliveip", true, &PostData { data })
            .await
    }

    /// Report per-user traffic (`APIClient.ReportUserTraffic`).
    pub async fn report_user_traffic(&self, traffic: &[UserTraffic]) -> ApiResult<()> {
        let data: Vec<UserTrafficWire> = traffic
            .iter()
            .map(|t| UserTrafficWire {
                user_id: t.uid,
                u: t.upload,
                d: t.download,
            })
            .collect();
        self.post_json("/mod_mu/users/traffic", true, &PostData { data })
            .await
    }

    /// Pull audit rules (`APIClient.GetNodeRule`). Rules whose regex fails to
    /// compile are skipped with a warning rather than failing the whole pull.
    pub async fn get_node_rule(&self) -> ApiResult<Vec<DetectRule>> {
        let data = self
            .get_json("/mod_mu/func/detect_rules", "rules", false)
            .await?;
        let items: Vec<RuleItem> = serde_json::from_value(data).map_err(|e| ApiError::Decode {
            context: "node rule",
            source: e,
        })?;
        let mut rules = Vec::with_capacity(items.len());
        for item in items {
            match Regex::new(&item.regex) {
                Ok(pattern) => rules.push(DetectRule {
                    id: item.id,
                    pattern,
                }),
                Err(e) => tracing::warn!(
                    rule_id = item.id,
                    error = %e,
                    "skipping audit rule with invalid regex"
                ),
            }
        }
        Ok(rules)
    }

    /// Report audit hits (`APIClient.ReportIllegal`).
    pub async fn report_illegal(&self, results: &[DetectResult]) -> ApiResult<()> {
        let data: Vec<IllegalItem> = results
            .iter()
            .map(|r| IllegalItem {
                list_id: r.rule_id,
                user_id: r.uid,
            })
            .collect();
        self.post_json("/mod_mu/users/detectlog", true, &PostData { data })
            .await
    }

    // ---- internal helpers -------------------------------------------------

    fn parse_params(&self) -> ParseParams {
        ParseParams {
            node_type: self.node_type,
            node_id: self.node_id,
            enable_vless: self.enable_vless,
            vless_flow: self.vless_flow.clone(),
            speed_limit: self.speed_limit,
            device_limit: self.device_limit,
        }
    }

    /// Build a request carrying the always-present query params (`key`/`muKey`)
    /// and `Accept: application/json` (mirrors resty's base config + forced
    /// content type).
    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let url = format!("{}{}", self.api_host, path);
        self.client
            .request(method, url)
            .query(&[("key", self.key.as_str()), ("muKey", self.key.as_str())])
            .header(ACCEPT, "application/json")
    }

    /// GET an endpoint with conditional-request (ETag) handling and decode the
    /// envelope, returning the inner `data` value.
    async fn get_json(
        &self,
        path: &str,
        etag_key: &'static str,
        node_id_query: bool,
    ) -> ApiResult<Value> {
        let etag = self.get_etag(etag_key);
        let mut req = self
            .request(reqwest::Method::GET, path)
            .header(IF_NONE_MATCH, etag);
        if node_id_query {
            req = req.query(&[("node_id", self.node_id.to_string())]);
        }

        let resp = self.send_with_retry(req, path).await?;
        if resp.status().as_u16() == 304 {
            return Err(ApiError::NotModified);
        }
        let etag_val = resp
            .headers()
            .get(ETAG)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        self.set_etag(etag_key, &etag_val);

        self.parse_response(path, resp).await
    }

    /// POST a JSON body and validate the envelope.
    async fn post_json<B: Serialize>(
        &self,
        path: &str,
        node_id_query: bool,
        body: &B,
    ) -> ApiResult<()> {
        let mut req = self.request(reqwest::Method::POST, path);
        if node_id_query {
            req = req.query(&[("node_id", self.node_id.to_string())]);
        }
        let req = req.json(body);
        let resp = self.send_with_retry(req, path).await?;
        self.parse_response(path, resp).await?;
        Ok(())
    }

    /// Fetch the first user's port for the old Shadowsocks node API. Unlike the
    /// public pulls, this issues no conditional request (matching Go).
    async fn fetch_first_user_port(&self) -> ApiResult<u32> {
        let path = "/mod_mu/users";
        let req = self
            .request(reqwest::Method::GET, path)
            .query(&[("node_id", self.node_id.to_string())]);
        let resp = self.send_with_retry(req, path).await?;
        let data = self.parse_response(path, resp).await?;
        let users: Vec<UserResponse> =
            serde_json::from_value(data).map_err(|e| ApiError::Decode {
                context: "user list",
                source: e,
            })?;
        Ok(users.first().map(|u| u.port).unwrap_or(0))
    }

    /// Validate an HTTP response and return the envelope's `data` field
    /// (`APIClient.parseResponse`): HTTP status > 400 → [`ApiError::Status`],
    /// `ret != 1` → [`ApiError::Ret`].
    async fn parse_response(&self, path: &str, resp: reqwest::Response) -> ApiResult<Value> {
        let status = resp.status().as_u16();
        let body = resp.text().await.map_err(|e| ApiError::Request {
            path: path.to_string(),
            source: e,
        })?;
        if status > 400 {
            return Err(ApiError::Status {
                path: path.to_string(),
                status,
                body,
            });
        }
        let response: Response = serde_json::from_str(&body).map_err(|e| ApiError::Decode {
            context: "response envelope",
            source: e,
        })?;
        if response.ret != 1 {
            return Err(ApiError::Ret { ret: response.ret });
        }
        Ok(response.data)
    }

    /// Send a request, retrying transport failures up to 3 attempts total.
    /// HTTP responses (including 304 / 4xx / 5xx) are returned as-is — only
    /// connection-level errors retry.
    async fn send_with_retry(
        &self,
        builder: reqwest::RequestBuilder,
        path: &str,
    ) -> ApiResult<reqwest::Response> {
        // Up to two clone-and-retry passes, then a final consuming send that
        // surfaces the real error. If the body is not cloneable, fall straight
        // through to the single consuming send.
        for _ in 0..2 {
            let Some(attempt) = builder.try_clone() else {
                break;
            };
            if let Ok(resp) = attempt.send().await {
                return Ok(resp);
            }
        }
        builder.send().await.map_err(|e| ApiError::Request {
            path: path.to_string(),
            source: e,
        })
    }

    fn get_etag(&self, key: &'static str) -> String {
        self.etags.lock().get(key).cloned().unwrap_or_default()
    }

    fn set_etag(&self, key: &'static str, value: &str) {
        if value.is_empty() {
            return;
        }
        let mut m = self.etags.lock();
        let differs = m.get(key).map(|cur| cur != value).unwrap_or(true);
        if differs {
            m.insert(key, value.to_string());
        }
    }

    fn get_version(&self) -> String {
        self.version.lock().clone()
    }

    fn set_version(&self, value: &str) {
        *self.version.lock() = value.to_string();
    }
}

// ---- pure parsers (network-free, unit-tested) -----------------------------

/// Speed limit in bytes/sec: the per-client override (Mbps) when positive, else
/// the panel value (`(mbps * 1_000_000) / 8`, truncated like Go's `uint64`).
fn speed_limit_bytes(override_mbps: f64, panel_mbps: f64) -> u64 {
    let mbps = if override_mbps > 0.0 {
        override_mbps
    } else {
        panel_mbps
    };
    ((mbps * 1_000_000.0) / 8.0) as u64
}

/// Parse a port like Go's `ParseInt(s, 10, 32)` followed by a `uint32` cast.
fn parse_port_i32(s: &str) -> ApiResult<u32> {
    s.parse::<i32>()
        .map(|v| v as u32)
        .map_err(|e| ApiError::ParseNode(format!("invalid port {s:?}: {e}")))
}

/// Parse an alterId like Go's `ParseInt(s, 10, 16)` followed by a `uint16` cast.
fn parse_alter_id(s: &str) -> ApiResult<u16> {
    s.parse::<i16>()
        .map(|v| v as u16)
        .map_err(|e| ApiError::ParseNode(format!("invalid alterId {s:?}: {e}")))
}

/// Port of `ParseV2rayNodeResponse`. Node string layout:
/// `addr;port;alterId;<flag>;<transport>;key=value|key=value|...`.
fn parse_v2ray_node_response(p: &ParseParams, resp: &NodeInfoResponse) -> ApiResult<NodeInfo> {
    if resp.server.is_empty() {
        return Err(ApiError::ParseNode("no server info in response".into()));
    }
    let server_conf: Vec<&str> = resp.server.split(';').collect();
    if server_conf.len() < 6 {
        return Err(ApiError::ParseNode(format!(
            "malformed v2ray server string: {:?}",
            resp.server
        )));
    }

    let port = parse_port_i32(server_conf[1])?;
    let alter_id = parse_alter_id(server_conf[2])?;

    let mut enable_tls = false;
    let mut transport_protocol = String::new();
    for &value in &server_conf[3..5] {
        match value {
            "tls" => enable_tls = true,
            "" => {}
            other => transport_protocol = other.to_string(),
        }
    }

    let mut path = String::new();
    let mut host = String::new();
    let mut service_name = String::new();
    let mut header_type = String::new();
    for item in server_conf[5].split('|') {
        let parts: Vec<&str> = item.split('=').collect();
        let key = parts[0];
        if key.is_empty() {
            continue;
        }
        let value = parts.get(1).copied().unwrap_or("");
        match key {
            // Rejoin in case the path itself contains '='.
            "path" => path = parts[1..].join("="),
            "host" => host = value.to_string(),
            "servicename" => service_name = value.to_string(),
            "headerType" => header_type = value.to_string(),
            _ => {}
        }
    }

    let speed_limit = speed_limit_bytes(p.speed_limit, resp.node_speedlimit);
    let header = if header_type.is_empty() {
        None
    } else {
        Some(serde_json::json!({ "type": header_type }).to_string())
    };

    Ok(NodeInfo {
        node_type: p.node_type,
        node_id: p.node_id,
        port,
        speed_limit,
        alter_id,
        transport_protocol: transport_protocol.into(),
        host: host.into(),
        path: path.into(),
        enable_tls,
        enable_vless: p.enable_vless,
        vless_flow: CompactString::new(&p.vless_flow),
        cypher_method: CompactString::default(),
        server_key: CompactString::default(),
        service_name: service_name.into(),
        authority: CompactString::default(),
        header,
        accept_proxy_protocol: false,
        enable_reality: false,
    })
}

/// Port of `ParseSSNodeResponse`. The old SS API carries no port in the node
/// string; the caller supplies the first user's port.
fn parse_ss_node_response(
    p: &ParseParams,
    resp: &NodeInfoResponse,
    first_user_port: u32,
) -> ApiResult<NodeInfo> {
    let speed_limit = speed_limit_bytes(p.speed_limit, resp.node_speedlimit);
    Ok(NodeInfo {
        node_type: p.node_type,
        node_id: p.node_id,
        port: first_user_port,
        speed_limit,
        alter_id: 0,
        transport_protocol: "tcp".into(),
        host: CompactString::default(),
        path: CompactString::default(),
        enable_tls: false,
        enable_vless: false,
        vless_flow: CompactString::default(),
        // Go leaves the method empty here; it is supplied per-user.
        cypher_method: CompactString::default(),
        server_key: CompactString::default(),
        service_name: CompactString::default(),
        authority: CompactString::default(),
        header: None,
        accept_proxy_protocol: false,
        enable_reality: false,
    })
}

/// Port of `ParseSSPluginNodeResponse`. Shadowsocks-Plugin uses two ports; the
/// streaming port is the node port minus one.
fn parse_ss_plugin_node_response(p: &ParseParams, resp: &NodeInfoResponse) -> ApiResult<NodeInfo> {
    let server_conf: Vec<&str> = resp.server.split(';').collect();
    if server_conf.len() < 6 {
        return Err(ApiError::ParseNode(format!(
            "malformed shadowsocks-plugin server string: {:?}",
            resp.server
        )));
    }

    // Matches Go's `uint32(port) - 1` with its wraparound semantics: only a
    // resulting port of 0 (i.e. a node port of 1) is rejected.
    let port = parse_port_i32(server_conf[1])?.wrapping_sub(1);
    if port == 0 {
        return Err(ApiError::ParseNode(
            "Shadowsocks-Plugin listen port must bigger than 1".into(),
        ));
    }

    let mut enable_tls = false;
    let mut transport_protocol = String::new();
    for &value in &server_conf[3..5] {
        match value {
            "tls" => enable_tls = true,
            "ws" => transport_protocol = "ws".to_string(),
            "obfs" => transport_protocol = "tcp".to_string(),
            _ => {}
        }
    }

    let mut path = String::new();
    let mut host = String::new();
    for item in server_conf[5].split('|') {
        let parts: Vec<&str> = item.split('=').collect();
        let key = parts[0];
        if key.is_empty() {
            continue;
        }
        let value = parts.get(1).copied().unwrap_or("");
        match key {
            "path" => path = parts[1..].join("="),
            "host" => host = value.to_string(),
            _ => {}
        }
    }

    let speed_limit = speed_limit_bytes(p.speed_limit, resp.node_speedlimit);
    Ok(NodeInfo {
        node_type: p.node_type,
        node_id: p.node_id,
        port,
        speed_limit,
        alter_id: 0,
        transport_protocol: transport_protocol.into(),
        host: host.into(),
        path: path.into(),
        enable_tls,
        enable_vless: false,
        vless_flow: CompactString::default(),
        cypher_method: CompactString::default(),
        server_key: CompactString::default(),
        service_name: CompactString::default(),
        authority: CompactString::default(),
        header: None,
        accept_proxy_protocol: false,
        enable_reality: false,
    })
}

/// Port of `ParseTrojanNodeResponse`. Node string layout:
/// `addr;port=<outside>#<inside>|host=<host>|key=value...`. The inside port is
/// preferred when present.
fn parse_trojan_node_response(p: &ParseParams, resp: &NodeInfoResponse) -> ApiResult<NodeInfo> {
    if resp.server.is_empty() {
        return Err(ApiError::ParseNode("no server info in response".into()));
    }

    let outside_port = capture(&FIRST_PORT_RE, &resp.server);
    let inside_port = capture(&SECOND_PORT_RE, &resp.server);
    let host = capture(&HOST_RE, &resp.server);

    let port_str = if !inside_port.is_empty() {
        inside_port
    } else {
        outside_port
    };
    let port = parse_port_i32(&port_str)?;

    let server_conf: Vec<&str> = resp.server.split(';').collect();
    let extra = server_conf.get(1).copied().unwrap_or("");
    let mut transport_protocol = String::from("tcp");
    let mut service_name = String::new();
    for item in extra.split('|') {
        let parts: Vec<&str> = item.split('=').collect();
        let key = parts[0];
        if key.is_empty() {
            continue;
        }
        let value = parts.get(1).copied().unwrap_or("");
        match key {
            "grpc" => transport_protocol = "grpc".to_string(),
            "servicename" => service_name = value.to_string(),
            _ => {}
        }
    }

    let speed_limit = speed_limit_bytes(p.speed_limit, resp.node_speedlimit);
    Ok(NodeInfo {
        node_type: p.node_type,
        node_id: p.node_id,
        port,
        speed_limit,
        alter_id: 0,
        transport_protocol: transport_protocol.into(),
        host: host.into(),
        path: CompactString::default(),
        enable_tls: true,
        enable_vless: false,
        vless_flow: CompactString::default(),
        cypher_method: CompactString::default(),
        server_key: CompactString::default(),
        service_name: service_name.into(),
        authority: CompactString::default(),
        header: None,
        accept_proxy_protocol: false,
        enable_reality: false,
    })
}

/// First capture group of `re` against `text`, or empty (`FindStringSubmatch`
/// with `len > 1`).
fn capture(re: &Regex, text: &str) -> String {
    re.captures(text)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
        .unwrap_or_default()
}

/// Port of `ParseUserListResponse`. Applies the per-user / per-node device and
/// speed limits. `LastReportOnline` is treated as empty (lastOnline = 0), so a
/// user whose live IPs already meet the device limit is dropped.
fn parse_user_list_response(p: &ParseParams, users: &[UserResponse]) -> ApiResult<Vec<UserInfo>> {
    let mut out = Vec::with_capacity(users.len());
    for user in users {
        let mut device_limit = if p.device_limit > 0 {
            p.device_limit
        } else {
            user.node_iplimit
        };

        if device_limit > 0 && user.alive_ip > 0 {
            // lastOnline is always 0 here.
            let local_device_limit = device_limit - user.alive_ip;
            if local_device_limit > 0 {
                device_limit = local_device_limit;
            } else {
                continue;
            }
        }

        let speed_limit = speed_limit_bytes(p.speed_limit, user.node_speedlimit);
        out.push(UserInfo {
            uid: user.id,
            email: CompactString::default(),
            uuid: CompactString::new(&user.uuid),
            passwd: CompactString::new(&user.passwd),
            port: user.port,
            alter_id: 0,
            method: CompactString::new(&user.method),
            speed_limit,
            device_limit,
        });
    }
    Ok(out)
}

/// Port of `ParseSSPanelNodeInfo` (panels >= 2021.11), driven by the node's
/// `custom_config`. REALITY presence is recorded but no REALITY config is built.
fn parse_sspanel_node_info(p: &ParseParams, resp: &NodeInfoResponse) -> ApiResult<NodeInfo> {
    if resp.custom_config.is_null() {
        return Err(ApiError::ParseNode(
            "custom_config is empty, disable custom config".into(),
        ));
    }
    let cfg: CustomConfig = serde_json::from_value(resp.custom_config.clone())
        .map_err(|e| ApiError::ParseNode(format!("custom_config format error: {e}")))?;

    let speed_limit = speed_limit_bytes(p.speed_limit, resp.node_speedlimit);
    let port = parse_port_i32(&cfg.offset_port_node)?;

    let mut enable_tls = false;
    let mut enable_vless = false;
    let mut transport_protocol = String::new();
    match p.node_type {
        NodeType::Shadowsocks => transport_protocol = "tcp".to_string(),
        NodeType::V2ray => {
            transport_protocol = cfg.network.clone();
            if cfg.security == "tls" || cfg.security == "xtls" {
                enable_tls = true;
            }
            if cfg.enable_vless == "1" {
                enable_vless = true;
            }
        }
        NodeType::Trojan => {
            enable_tls = true;
            transport_protocol = "tcp".to_string();
            if !cfg.network.is_empty() {
                transport_protocol = cfg.network.clone();
            }
        }
        _ => {}
    }

    // Pass the raw header JSON through unchanged when present.
    let header = if cfg.header.is_null() {
        None
    } else {
        Some(cfg.header.to_string())
    };

    Ok(NodeInfo {
        node_type: p.node_type,
        node_id: p.node_id,
        port,
        speed_limit,
        alter_id: 0,
        transport_protocol: transport_protocol.into(),
        host: CompactString::new(&cfg.host),
        path: CompactString::new(&cfg.path),
        enable_tls,
        enable_vless,
        vless_flow: CompactString::new(&cfg.flow),
        cypher_method: CompactString::new(&cfg.method),
        server_key: CompactString::new(&cfg.server_key),
        service_name: CompactString::new(&cfg.servicename),
        authority: CompactString::default(),
        header,
        accept_proxy_protocol: false,
        enable_reality: cfg.enable_reality,
    })
}

/// Port of `compareVersion`: `1` if `v1 > v2`, `-1` if `v1 < v2`, `0` if equal.
/// Compares dot-separated numeric segments left to right.
pub fn compare_version(v1: &str, v2: &str) -> i32 {
    let a = v1.as_bytes();
    let b = v2.as_bytes();
    let (n, m) = (a.len(), b.len());
    let (mut i, mut j) = (0usize, 0usize);
    while i < n || j < m {
        let mut x: i64 = 0;
        while i < n && a[i] != b'.' {
            x = x * 10 + (a[i] as i64 - b'0' as i64);
            i += 1;
        }
        i += 1; // skip the dot

        let mut y: i64 = 0;
        while j < m && b[j] != b'.' {
            y = y * 10 + (b[j] as i64 - b'0' as i64);
            j += 1;
        }
        j += 1; // skip the dot

        if x > y {
            return 1;
        }
        if x < y {
            return -1;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::NodeType;

    fn params(node_type: NodeType) -> ParseParams {
        ParseParams {
            node_type,
            node_id: 1,
            enable_vless: false,
            vless_flow: String::new(),
            speed_limit: 0.0,
            device_limit: 0,
        }
    }

    fn node(server: &str) -> NodeInfoResponse {
        NodeInfoResponse {
            server: server.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn compare_version_orders_segments() {
        assert_eq!(compare_version("2021.11", "2021.10"), 1);
        assert_eq!(compare_version("2021.11", "2021.11"), 0);
        assert_eq!(compare_version("2020.1", "2021.11"), -1);
        assert_eq!(compare_version("", "2023.2"), -1);
        assert_eq!(compare_version("2023.2", "2023.2"), 0);
    }

    #[test]
    fn compare_version_numeric_not_lexicographic() {
        // 11 > 2 numerically (a naive string compare would say "11" < "2").
        assert_eq!(compare_version("2021.11", "2021.2"), 1);
    }

    #[test]
    fn parse_v2ray_ws_tls() {
        let p = params(NodeType::V2ray);
        let resp = node("1.1.1.1;443;2;tls;ws;path=/path|host=h.com");
        let n = parse_v2ray_node_response(&p, &resp).unwrap();
        assert_eq!(n.port, 443);
        assert_eq!(n.alter_id, 2);
        assert!(n.enable_tls);
        assert_eq!(n.transport_protocol.as_str(), "ws");
        assert_eq!(n.path.as_str(), "/path");
        assert_eq!(n.host.as_str(), "h.com");
        assert!(n.header.is_none());
    }

    #[test]
    fn parse_v2ray_header_type() {
        let p = params(NodeType::V2ray);
        let resp = node("1.1.1.1;443;2;;tcp;path=/p|host=h|headerType=http");
        let n = parse_v2ray_node_response(&p, &resp).unwrap();
        assert_eq!(n.transport_protocol.as_str(), "tcp");
        let header = n.header.expect("header should be set");
        assert!(
            header.contains("\"type\":\"http\""),
            "unexpected header json: {header}"
        );
    }

    #[test]
    fn parse_v2ray_path_with_equals() {
        // A '=' inside the path value must survive (Go rejoins on '=').
        let p = params(NodeType::V2ray);
        let resp = node("1.1.1.1;443;0;;ws;path=/a=b|host=h");
        let n = parse_v2ray_node_response(&p, &resp).unwrap();
        assert_eq!(n.path.as_str(), "/a=b");
    }

    #[test]
    fn parse_v2ray_speed_limit_override() {
        let mut p = params(NodeType::V2ray);
        p.speed_limit = 100.0; // 100 Mbps -> bytes/sec
        let resp = node("1.1.1.1;443;0;;tcp;path=/p|host=h");
        let n = parse_v2ray_node_response(&p, &resp).unwrap();
        assert_eq!(n.speed_limit, ((100.0 * 1_000_000.0) / 8.0) as u64);
    }

    #[test]
    fn parse_v2ray_rejects_short_string() {
        let p = params(NodeType::V2ray);
        assert!(parse_v2ray_node_response(&p, &node("a;443;0")).is_err());
        assert!(parse_v2ray_node_response(&p, &node("")).is_err());
    }

    #[test]
    fn parse_trojan_inside_port() {
        let p = params(NodeType::Trojan);
        let resp = node("gz.aaa.com;port=443#12345|host=hk.aaa.com");
        let n = parse_trojan_node_response(&p, &resp).unwrap();
        assert_eq!(n.port, 12345);
        assert_eq!(n.host.as_str(), "hk.aaa.com");
        assert!(n.enable_tls);
        assert_eq!(n.transport_protocol.as_str(), "tcp");
    }

    #[test]
    fn parse_trojan_outside_port_when_no_inside() {
        let p = params(NodeType::Trojan);
        let resp = node("gz.aaa.com;port=443|host=hk.aaa.com");
        let n = parse_trojan_node_response(&p, &resp).unwrap();
        assert_eq!(n.port, 443);
    }

    #[test]
    fn parse_trojan_grpc() {
        let p = params(NodeType::Trojan);
        let resp = node("x.com;port=443|grpc=1|servicename=GunService");
        let n = parse_trojan_node_response(&p, &resp).unwrap();
        assert_eq!(n.port, 443);
        assert_eq!(n.transport_protocol.as_str(), "grpc");
        assert_eq!(n.service_name.as_str(), "GunService");
        assert!(n.enable_tls);
    }

    #[test]
    fn parse_ss_plugin_port_minus_one() {
        let p = params(NodeType::ShadowsocksPlugin);
        let resp = node("1.1.1.1;1001;0;ws;;path=/p|host=h");
        let n = parse_ss_plugin_node_response(&p, &resp).unwrap();
        assert_eq!(n.port, 1000);
        assert_eq!(n.transport_protocol.as_str(), "ws");
        assert_eq!(n.path.as_str(), "/p");
        assert_eq!(n.host.as_str(), "h");
    }

    #[test]
    fn parse_ss_plugin_rejects_port_one() {
        let p = params(NodeType::ShadowsocksPlugin);
        // Node port 1 -> streaming port 0, which Go rejects.
        let resp = node("1.1.1.1;1;0;;;path=/p|host=h");
        assert!(parse_ss_plugin_node_response(&p, &resp).is_err());
    }

    #[test]
    fn parse_ss_node_uses_first_user_port() {
        let p = params(NodeType::Shadowsocks);
        let resp = node("");
        let n = parse_ss_node_response(&p, &resp, 8388).unwrap();
        assert_eq!(n.port, 8388);
        assert_eq!(n.transport_protocol.as_str(), "tcp");
        assert!(n.cypher_method.is_empty());
    }

    #[test]
    fn parse_sspanel_v2ray() {
        let p = params(NodeType::V2ray);
        let resp = NodeInfoResponse {
            custom_config: serde_json::json!({
                "offset_port_node": "443",
                "network": "ws",
                "security": "tls",
                "enable_vless": "1",
                "path": "/p",
                "host": "h"
            }),
            ..Default::default()
        };
        let n = parse_sspanel_node_info(&p, &resp).unwrap();
        assert_eq!(n.port, 443);
        assert_eq!(n.transport_protocol.as_str(), "ws");
        assert!(n.enable_tls);
        assert!(n.enable_vless);
        assert_eq!(n.host.as_str(), "h");
        assert_eq!(n.path.as_str(), "/p");
    }

    #[test]
    fn parse_sspanel_trojan() {
        let p = params(NodeType::Trojan);
        let resp = NodeInfoResponse {
            custom_config: serde_json::json!({ "offset_port_node": "443" }),
            ..Default::default()
        };
        let n = parse_sspanel_node_info(&p, &resp).unwrap();
        assert!(n.enable_tls);
        assert_eq!(n.transport_protocol.as_str(), "tcp");
    }

    #[test]
    fn parse_sspanel_shadowsocks() {
        let p = params(NodeType::Shadowsocks);
        let resp = NodeInfoResponse {
            custom_config: serde_json::json!({
                "offset_port_node": "443",
                "method": "aes-128-gcm"
            }),
            ..Default::default()
        };
        let n = parse_sspanel_node_info(&p, &resp).unwrap();
        assert_eq!(n.transport_protocol.as_str(), "tcp");
        assert_eq!(n.cypher_method.as_str(), "aes-128-gcm");
    }

    #[test]
    fn parse_sspanel_reality_flag_only() {
        let p = params(NodeType::V2ray);
        let resp = NodeInfoResponse {
            custom_config: serde_json::json!({
                "offset_port_node": "443",
                "network": "tcp",
                "security": "reality",
                "enable_reality": true,
                "reality-opts": { "dest": "example.com:443" }
            }),
            ..Default::default()
        };
        let n = parse_sspanel_node_info(&p, &resp).unwrap();
        assert!(n.enable_reality);
        // "reality" is not "tls"/"xtls", so TLS stays off.
        assert!(!n.enable_tls);
    }

    #[test]
    fn parse_sspanel_rejects_null_custom_config() {
        let p = params(NodeType::V2ray);
        let resp = NodeInfoResponse::default(); // custom_config is JSON null
        assert!(parse_sspanel_node_info(&p, &resp).is_err());
    }

    fn user(id: i32, node_iplimit: i32, alive_ip: i32, speed: f64) -> UserResponse {
        UserResponse {
            id,
            uuid: format!("uuid-{id}"),
            passwd: format!("pw-{id}"),
            port: 1000 + id as u32,
            method: "aes-128-gcm".to_string(),
            node_speedlimit: speed,
            node_iplimit,
            alive_ip,
        }
    }

    #[test]
    fn parse_user_list_speed_and_device_limit() {
        let p = params(NodeType::Shadowsocks);
        let users = vec![user(1, 5, 2, 100.0)];
        let out = parse_user_list_response(&p, &users).unwrap();
        assert_eq!(out.len(), 1);
        let u = &out[0];
        assert_eq!(u.uid, 1);
        assert_eq!(u.uuid.as_str(), "uuid-1");
        assert_eq!(u.port, 1001);
        // node speed limit 100 Mbps -> bytes/sec
        assert_eq!(u.speed_limit, ((100.0 * 1_000_000.0) / 8.0) as u64);
        // device limit 5 reduced by 2 live IPs -> 3
        assert_eq!(u.device_limit, 3);
    }

    #[test]
    fn parse_user_list_skips_when_ips_exceed_limit() {
        let p = params(NodeType::Shadowsocks);
        // alive_ip (10) >= node_iplimit (3): no device budget left -> dropped.
        let users = vec![user(2, 3, 10, 0.0)];
        let out = parse_user_list_response(&p, &users).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn parse_user_list_overrides_from_params() {
        let mut p = params(NodeType::Shadowsocks);
        p.device_limit = 10;
        p.speed_limit = 50.0;
        // alive_ip 0 -> device adjustment skipped, override device limit kept.
        let users = vec![user(7, 1, 0, 999.0)];
        let out = parse_user_list_response(&p, &users).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].device_limit, 10);
        assert_eq!(out[0].speed_limit, ((50.0 * 1_000_000.0) / 8.0) as u64);
    }
}
