//! Integration tests: a minimal in-process SSPanel `mod_mu` HTTP mock exercised
//! end to end by the real [`SspanelClient`] and the [`Controller`].
//!
//! End-to-end proxying through a bound inbound is out of scope (objective); we
//! verify the panel API surface, inbound binding, user sync, and that real
//! per-user traffic counts flow back to the panel's traffic endpoint.

use std::sync::Arc;

use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use saas::api::{ApiConfig, DetectResult, NodeStatus, NodeType, OnlineUser, UserTraffic};
use saas::config::ControllerConfig;
use saas::controller::Controller;
use saas::inbound_manager::InboundManager;
use saas::sspanel::SspanelClient;

use compact_str::CompactString;
use kernel::{CachedResolver, Dispatcher, Outbound, Policy, Stats, SystemDialer};

const NODE_ID: i32 = 3;
const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

/// Records every request the mock received: (method, path, body).
#[derive(Default)]
struct MockState {
    node_port: u32,
    requests: Mutex<Vec<(String, String, Vec<u8>)>>,
}

impl MockState {
    fn record(&self, method: &str, path: &str, body: &[u8]) {
        self.requests
            .lock()
            .push((method.to_string(), path.to_string(), body.to_vec()));
    }

    fn requests_to(&self, method: &str, path: &str) -> Vec<Vec<u8>> {
        self.requests
            .lock()
            .iter()
            .filter(|(m, p, _)| m == method && p == path)
            .map(|(_, _, b)| b.clone())
            .collect()
    }

    fn response(&self, method: &str, path: &str) -> String {
        match (method, path) {
            ("GET", "/mod_mu/nodes/3/info") => format!(
                r#"{{"ret":1,"data":{{"version":"2021.11","node_speedlimit":0,"custom_config":{{"offset_port_node":"{}","network":"ws","security":"","enable_vless":"0","path":"/ws","host":"example.com","method":""}}}}}}"#,
                self.node_port
            ),
            ("GET", "/mod_mu/users") => format!(
                r#"{{"ret":1,"data":[{{"id":1,"uuid":"{UUID}","passwd":"pw","port":0,"method":"","node_speedlimit":0,"node_iplimit":0,"alive_ip":0}}]}}"#
            ),
            ("GET", "/mod_mu/func/detect_rules") => {
                r#"{"ret":1,"data":[{"id":7,"regex":"badword"}]}"#.to_string()
            }
            ("POST", _) => r#"{"ret":1,"data":[]}"#.to_string(),
            _ => r#"{"ret":1,"data":null}"#.to_string(),
        }
    }
}

/// Start the mock SSPanel server; returns (`base_url`, state).
async fn start_mock(node_port: u32) -> (String, Arc<MockState>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = Arc::new(MockState {
        node_port,
        requests: Mutex::new(Vec::new()),
    });
    let srv_state = state.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let st = srv_state.clone();
            tokio::spawn(async move { handle_conn(stream, st).await });
        }
    });
    (format!("http://{addr}"), state)
}

async fn handle_conn(mut stream: tokio::net::TcpStream, state: Arc<MockState>) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    // Read request head.
    let (head_end, content_len) = loop {
        if let Some(pos) = find(&buf, b"\r\n\r\n") {
            let cl = content_length(&buf[..pos]);
            break (pos + 4, cl);
        }
        match stream.read(&mut tmp).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    };
    // Read body.
    while buf.len() < head_end + content_len {
        match stream.read(&mut tmp).await {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    }

    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let first = head.lines().next().unwrap_or("");
    let mut it = first.split_whitespace();
    let method = it.next().unwrap_or("").to_string();
    let target = it.next().unwrap_or("");
    let path = target.split('?').next().unwrap_or("").to_string();
    let body_end = (head_end + content_len).min(buf.len());
    let body = buf[head_end..body_end].to_vec();

    state.record(&method, &path, &body);
    let resp_body = state.response(&method, &path);
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        resp_body.len()
    );
    let _ = stream.write_all(resp.as_bytes()).await;
    let _ = stream.write_all(resp_body.as_bytes()).await;
    let _ = stream.flush().await;
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn content_length(head: &[u8]) -> usize {
    let head = String::from_utf8_lossy(head);
    for line in head.lines() {
        if let Some(v) = line.strip_prefix("Content-Length:") {
            return v.trim().parse().unwrap_or(0);
        }
        // case-insensitive fallback
        let lower = line.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("content-length:") {
            return v.trim().parse().unwrap_or(0);
        }
    }
    0
}

fn free_port() -> u32 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    u32::from(l.local_addr().unwrap().port())
}

fn api_config(host: &str) -> ApiConfig {
    ApiConfig {
        api_host: host.to_string(),
        node_id: NODE_ID,
        key: "testkey".to_string(),
        node_type: NodeType::V2ray,
        enable_vless: false,
        vless_flow: String::new(),
        timeout: 5,
        speed_limit: 0.0,
        device_limit: 0,
        rule_list_path: String::new(),
        disable_custom_config: false,
    }
}

#[tokio::test]
async fn sspanel_client_endpoints_round_trip() {
    let (host, state) = start_mock(50000).await;
    let client = SspanelClient::new(&api_config(&host));

    // Node info: SSPanel custom-config V2ray (vmess/ws/no-tls).
    let node = client.get_node_info().await.expect("get_node_info");
    assert_eq!(node.node_type, NodeType::V2ray);
    assert_eq!(node.port, 50000);
    assert_eq!(node.transport_protocol, "ws");
    assert!(!node.enable_tls);
    assert!(!node.enable_vless);
    assert_eq!(node.path, "/ws");
    assert_eq!(node.host, "example.com");

    // User list.
    let users = client.get_user_list().await.expect("get_user_list");
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].uid, 1);
    assert_eq!(users[0].uuid, UUID);

    // Reports.
    client
        .report_node_status(&NodeStatus {
            cpu: 10.0,
            mem: 20.0,
            disk: 30.0,
            uptime: 123,
        })
        .await
        .expect("report_node_status");

    client
        .report_user_traffic(&[UserTraffic {
            uid: 1,
            email: CompactString::default(),
            upload: 111,
            download: 222,
        }])
        .await
        .expect("report_user_traffic");

    client
        .report_node_online_users(&[OnlineUser {
            uid: 1,
            ip: "1.2.3.4".to_string(),
        }])
        .await
        .expect("report_node_online_users");

    let rules = client.get_node_rule().await.expect("get_node_rule");
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].id, 7);
    assert!(rules[0].pattern.is_match("this has a badword in it"));

    client
        .report_illegal(&[DetectResult { uid: 1, rule_id: 7 }])
        .await
        .expect("report_illegal");

    // The traffic report reached the panel with the right numbers.
    let bodies = state.requests_to("POST", "/mod_mu/users/traffic");
    assert_eq!(bodies.len(), 1);
    let v: serde_json::Value = serde_json::from_slice(&bodies[0]).unwrap();
    let entry = &v["data"][0];
    assert_eq!(entry["user_id"], 1);
    assert_eq!(entry["u"], 111);
    assert_eq!(entry["d"], 222);

    // Status report (panel < 2023.2) was sent as a POST to the node-info path.
    assert_eq!(state.requests_to("POST", "/mod_mu/nodes/3/info").len(), 1);
    // Online + illegal reached their endpoints.
    assert_eq!(state.requests_to("POST", "/mod_mu/users/aliveip").len(), 1);
    assert_eq!(
        state.requests_to("POST", "/mod_mu/users/detectlog").len(),
        1
    );
}

fn build_dispatcher(stats: Arc<Stats>) -> Arc<Dispatcher> {
    let resolver = Arc::new(CachedResolver::system().expect("resolver"));
    let dialer = SystemDialer::new(resolver);
    let mut outbounds = std::collections::HashMap::new();
    outbounds.insert(CompactString::new("freedom"), Outbound::Freedom);
    Arc::new(Dispatcher::new(dialer, outbounds, "freedom", None).with_stats(stats))
}

#[tokio::test]
async fn controller_binds_inbound_and_reports_counted_traffic() {
    let port = free_port();
    let (host, state) = start_mock(port).await;

    let stats = Arc::new(Stats::new());
    let dispatcher = build_dispatcher(stats.clone());
    let ibm = Arc::new(InboundManager::new(dispatcher, Policy::default()));

    let cfg = ControllerConfig {
        listen_ip: "127.0.0.1".to_string(),
        ..Default::default()
    };
    let client = SspanelClient::new(&api_config(&host));
    let mut controller = Controller::new(client, cfg, ibm.clone(), stats.clone());

    // Start: fetch node + users, build and bind the inbound.
    controller.start().await.expect("controller start");
    assert_eq!(ibm.len(), 1, "one inbound bound");
    let tag = controller.node_tag().to_string();
    assert_eq!(tag, format!("V2ray_127.0.0.1_{port}"));
    assert!(ibm.contains(&tag));

    // Simulate proxied traffic: bump the user's counter as the data plane would.
    let user_tag = format!("{tag}||1"); // {node_tag}|{email=""}|{uid=1}
    let counter = stats.counter(&user_tag);
    counter.add_up(1000);
    counter.add_down(2000);

    // One reporting cycle.
    controller.user_info_monitor().await;

    let bodies = state.requests_to("POST", "/mod_mu/users/traffic");
    assert_eq!(bodies.len(), 1, "exactly one traffic report");
    let v: serde_json::Value = serde_json::from_slice(&bodies[0]).unwrap();
    let entry = &v["data"][0];
    assert_eq!(entry["user_id"], 1);
    assert_eq!(entry["u"], 1000);
    assert_eq!(entry["d"], 2000);

    // Counter was reset after a successful report.
    assert_eq!(counter.up(), 0);
    assert_eq!(counter.down(), 0);

    // A no-change poll keeps the same inbound bound (304-free equality path).
    controller.node_info_monitor().await;
    assert_eq!(ibm.len(), 1);
    assert!(ibm.contains(&tag));

    ibm.remove(&tag);
    assert_eq!(ibm.len(), 0);
}

#[test]
fn example_config_parses_and_resolves() {
    let text = include_str!("../config.example.toml");
    let config = saas::config::Config::parse(text).expect("example config parses");
    assert_eq!(config.nodes.len(), 1);
    let node = &config.nodes[0];
    assert_eq!(node.panel_type, "SSpanel");
    assert_eq!(node.api.api_host, "http://127.0.0.1:667");
    assert_eq!(node.api.api_key, "123");
    assert_eq!(node.api.node_id, 41);
    assert_eq!(node.controller.update_periodic, 60);
    // NodeType resolves to a supported api::NodeType.
    let api_cfg = node.api_config().expect("api config resolves");
    assert_eq!(api_cfg.node_type, NodeType::V2ray);
}
