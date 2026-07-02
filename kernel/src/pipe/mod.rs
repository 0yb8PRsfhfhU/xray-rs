//! The data plane and its trait seams.
//!
//! - [`pipe`]: the in-process duplex [`Link`](pipe::Link) (bounded `mpsc<Bytes>` pair).
//! - [`copy`]: the copy loops between a transport connection and a `Link`.
//! - [`timer`]: the idle-activity timer.
//! - [`translation`]: framed header read + chunk codec traits.
//! - [`transport`]: the abstract [`Transport`](transport::Transport) trait (listener seam).
//! - [`proxy_protocol`]: the abstract [`Proxy`](proxy_protocol::Proxy) trait (decode/auth seam).
//! - [`outbound`]: the abstract [`Outbound`](outbound::Outbound) trait (egress seam).

pub mod copy;
pub mod outbound;
#[allow(clippy::module_inception)]
pub mod pipe;
pub mod proxy_protocol;
pub mod timer;
pub mod translation;
pub mod transport;
