//! Small TOML DSL for egress routing.
//!
//! This intentionally does not model Xray JSON or XrayR custom-outbound merge
//! behaviour. It accepts the local `enable` + `[[routes]]` format and leaves
//! runtime objects to `egress_compile`.

use anyhow::Context;
use serde::Deserialize;

fn default_true() -> bool {
    true
}

/// Top-level egress routing config.
#[derive(Debug, Clone, Deserialize)]
pub struct EgressConfig {
    #[serde(default = "default_true")]
    pub enable: bool,
    #[serde(default)]
    pub routes: Vec<RouteBlock>,
}

impl Default for EgressConfig {
    fn default() -> Self {
        Self {
            enable: true,
            routes: Vec::new(),
        }
    }
}

impl EgressConfig {
    /// Parse a standalone egress-routing TOML file.
    pub fn parse(text: &str) -> anyhow::Result<EgressConfig> {
        toml::from_str(text).context("failed to parse egress TOML config")
    }
}

/// One route block: a list of matcher strings and exactly one outbound for now.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RouteBlock {
    #[serde(default)]
    pub rules: Vec<String>,
    #[serde(default, rename = "Outs")]
    pub outs: Vec<OutSpec>,
}

/// Outbound definitions embedded under a route block.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum OutSpec {
    #[serde(rename = "direct", alias = "freedom")]
    Direct,
    #[serde(rename = "block", alias = "blackhole")]
    Block,
    #[serde(rename = "ss", alias = "shadowsocks")]
    Shadowsocks {
        #[serde(default)]
        listen: String,
        server: String,
        port: u16,
        password: String,
        #[serde(alias = "method")]
        cipher: String,
    },
    #[serde(rename = "socks", alias = "socks5")]
    Socks {
        #[serde(default)]
        listen: String,
        server: String,
        port: u16,
        #[serde(default)]
        username: String,
        #[serde(default)]
        password: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_route_block_with_ss_socks_and_direct() {
        let cfg = EgressConfig::parse(
            r##"
            enable = true

            [[routes]]
            rules = ["#Netflix", "geosite:netflix", "domain:netflix.com"]
              [[routes.Outs]]
              type = "ss"
              server = "ss.example"
              port = 8388
              password = "pw"
              cipher = "aes-128-gcm"

            [[routes]]
            rules = ["keyword:openai"]
              [[routes.Outs]]
              type = "socks"
              server = "127.0.0.1"
              port = 1080
              username = "u"
              password = "p"

            [[routes]]
            rules = ["*"]
              [[routes.Outs]]
              type = "direct"
            "##,
        )
        .expect("egress config parses");

        assert!(cfg.enable);
        assert_eq!(cfg.routes.len(), 3);
        assert!(matches!(cfg.routes[0].outs.first(), Some(OutSpec::Shadowsocks { .. })));
        assert!(matches!(cfg.routes[1].outs.first(), Some(OutSpec::Socks { .. })));
        assert!(matches!(cfg.routes[2].outs.first(), Some(OutSpec::Direct)));
    }
}
