//! SSPanel (XrayR variant) wire structs — the Rust analogue of
//! `XrayR/api/sspanel/model.go`. These mirror the panel's JSON response and
//! request bodies verbatim; field names match the Go `json:"..."` tags. The
//! `crate::sspanel` parsers translate them into the normalized `crate::api`
//! types.
//!
//! Many fields are carried only to round-trip the wire format faithfully and
//! are never read by the parsers, hence the module-wide `dead_code` allowance.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// `/mod_mu/nodes/{id}/info` payload (`sspanel.NodeInfoResponse`).
#[derive(Debug, Default, Deserialize)]
pub struct NodeInfoResponse {
    #[serde(default)]
    pub node_group: i64,
    #[serde(default)]
    pub node_class: i64,
    #[serde(default)]
    pub node_speedlimit: f64,
    #[serde(default)]
    pub traffic_rate: f64,
    #[serde(default)]
    pub sort: i64,
    #[serde(default)]
    pub server: String,
    #[serde(default, rename = "type")]
    pub r#type: String,
    #[serde(default)]
    pub custom_config: Value,
    #[serde(default)]
    pub version: String,
}

/// SSPanel custom node config (`sspanel.CustomConfig`), available on panels at
/// version 2021.11 and newer. `header`/`reality-opts` are kept as raw JSON so the
/// parsers can pass them through without modelling REALITY (out of scope).
#[derive(Debug, Default, Deserialize)]
pub struct CustomConfig {
    #[serde(default)]
    pub offset_port_node: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub server_key: String,
    #[serde(default)]
    pub tls: String,
    #[serde(default)]
    pub enable_vless: String,
    #[serde(default)]
    pub network: String,
    #[serde(default)]
    pub security: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub verify_cert: bool,
    #[serde(default)]
    pub obfs: String,
    #[serde(default)]
    pub header: Value,
    #[serde(default)]
    pub allow_insecure: String,
    #[serde(default)]
    pub servicename: String,
    #[serde(default)]
    pub enable_xtls: String,
    #[serde(default)]
    pub flow: String,
    #[serde(default)]
    pub enable_reality: bool,
    #[serde(default, rename = "reality-opts")]
    pub reality_opts: Value,
}

/// A single user from `/mod_mu/users` (`sspanel.UserResponse`).
#[derive(Debug, Default, Deserialize)]
pub struct UserResponse {
    #[serde(default)]
    pub id: i32,
    #[serde(default)]
    pub passwd: String,
    #[serde(default)]
    pub port: u32,
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub node_speedlimit: f64,
    #[serde(default)]
    pub node_iplimit: i32,
    #[serde(default)]
    pub uuid: String,
    #[serde(default)]
    pub alive_ip: i32,
}

/// The common envelope every SSPanel endpoint returns (`sspanel.Response`).
#[derive(Debug, Default, Deserialize)]
pub struct Response {
    #[serde(default)]
    pub ret: u64,
    #[serde(default)]
    pub data: Value,
}

/// POST body wrapper (`sspanel.PostData`): `{ "data": <payload> }`.
#[derive(Debug, Serialize)]
pub struct PostData<T> {
    pub data: T,
}

/// Node load report body (`sspanel.SystemLoad`).
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SystemLoad {
    #[serde(default)]
    pub uptime: String,
    #[serde(default)]
    pub load: String,
}

/// Online-user IP report entry (`sspanel.OnlineUser`).
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct OnlineUserWire {
    #[serde(default)]
    pub user_id: i32,
    #[serde(default)]
    pub ip: String,
}

/// Per-user traffic report entry (`sspanel.UserTraffic`).
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct UserTrafficWire {
    #[serde(default)]
    pub user_id: i32,
    #[serde(default)]
    pub u: i64,
    #[serde(default)]
    pub d: i64,
}

/// An audit rule from `/mod_mu/func/detect_rules` (`sspanel.RuleItem`).
#[derive(Debug, Default, Deserialize)]
pub struct RuleItem {
    #[serde(default)]
    pub id: i32,
    #[serde(default)]
    pub regex: String,
}

/// An audit hit report entry (`sspanel.IllegalItem`).
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct IllegalItem {
    #[serde(default)]
    pub list_id: i32,
    #[serde(default)]
    pub user_id: i32,
}
