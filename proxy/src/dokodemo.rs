//! dokodemo-door inbound (SPEC §2e). Reference: `Xray-core/proxy/dokodemo/dokodemo.go`.
//!
//! Server-side TCP only: every accepted connection is relayed verbatim to a
//! single fixed target taken from config — there is no proxy header to parse
//! and no per-connection user (dokodemo is unauthenticated).
//!
//! Out of scope for now (intentionally not faked): UDP, transparent proxy /
//! TPROXY, and `followRedirect` (recovering the pre-redirect original
//! destination). Those require platform socket plumbing that does not exist on
//! the server side yet.

use std::io;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite};

use kernel::{
    Address, Ctx, Destination, LINK_CAPACITY, Network, Proxy, ProxyDecision, Timer, pipe,
};

use crate::ProxyContext;
use crate::io::{relay_stream, user_counter};

const NETWORKS: &[Network] = &[Network::Tcp];

/// dokodemo-door inbound: relay every connection to a fixed destination.
pub struct Dokodemo {
    address: Address,
    port: u16,
    cx: ProxyContext,
}

impl Dokodemo {
    pub fn new(address: Address, port: u16, cx: ProxyContext) -> Dokodemo {
        Dokodemo { address, port, cx }
    }

    pub fn networks(&self) -> &'static [Network] {
        NETWORKS
    }
}

impl Proxy for Dokodemo {
    type Auth = ();

    fn networks(&self) -> &[Network] {
        NETWORKS
    }

    async fn decode<S>(&self, ctx: Ctx, stream: S) -> io::Result<ProxyDecision>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // No header to parse and no user to authenticate: relay straight to the
        // fixed destination. There is no pre-read payload, so nothing to sniff.
        let dest = Destination::tcp(self.address.clone(), self.port);
        let timer = Timer::new(self.cx.policy.idle_timeout);
        let counter = user_counter(&ctx, self.cx.stats.as_ref()).await;
        let (inbound, outbound) = pipe(LINK_CAPACITY);
        tokio::spawn(relay_stream(stream, inbound, timer, counter, Bytes::new()));
        Ok(ProxyDecision {
            target: dest,
            ctx,
            link: outbound,
        })
    }
}
