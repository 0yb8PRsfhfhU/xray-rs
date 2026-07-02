//! Runtime layer: abstract egress ([`dns`], [`dialer`]), user auth/authorization
//! ([`user`]), per-connection [`session`] context, the React-style
//! [`context`] propagation channel, and the `tower::Service` config↔service
//! tree ([`service`]).

pub mod context;
pub mod dialer;
pub mod dns;
pub mod service;
pub mod session;
pub mod tree;
pub mod user;
