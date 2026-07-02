//! Routing (objective requirement 5): a config-level bigraph of matches↦outbounds
//! rendered as a first-match [`RouteTable`](rule::RouteTable) that resolves a
//! flow to an outbound tag (or a builtin), a [`LoadBalancer`](balance) that
//! spreads a match across several tags, and traffic [`sniff`]ers that recover a
//! domain from a bare-IP flow.

pub mod balance;
pub mod rule;
pub mod sniff;
