//! `saas` — an XrayR-compatible SaaS server front-end for the xray-rs core.
//!
//! Integrates a subscription panel (SSPanel, XrayR variant) with the xray-rs
//! data plane: it polls the panel for node configuration and the user list,
//! builds the matching inbound, syncs users into the live handler, and reports
//! per-user traffic back to the panel — preserving XrayR's polling behaviour.

pub mod api;
pub mod builder;
pub mod config;
pub mod controller;
pub mod egress_compile;
pub mod egress_config;
pub mod inbound_manager;
pub mod panel;
pub mod serverstatus;
pub mod sspanel;
