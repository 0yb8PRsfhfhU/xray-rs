//! dokodemo-door inbound (SPEC §2e). Reference: `Xray-core/proxy/dokodemo/dokodemo.go`.
//!
//! Server-side TCP only: every accepted connection is relayed verbatim to a
//! single fixed target taken from config — there is no proxy header to parse.
//!
//! Out of scope for now (intentionally not faked): UDP, transparent proxy /
//! TPROXY, and `followRedirect` (recovering the pre-redirect original
//! destination). Those require platform socket plumbing that does not exist on
//! the server side yet.

use std::io;

use bytes::Bytes;

use kernel::{Address, Ctx, Destination, Dispatcher, Policy, Timer};
use transport::Stream;

use crate::io::relay_tcp;

/// dokodemo-door inbound: relay every connection to a fixed destination.
pub struct Dokodemo {
    address: Address,
    port: u16,
}

impl Dokodemo {
    pub fn new(address: Address, port: u16) -> Dokodemo {
        Dokodemo { address, port }
    }

    pub async fn process(
        &self,
        ctx: &Ctx,
        conn: Stream,
        disp: &Dispatcher,
        policy: &Policy,
    ) -> io::Result<()> {
        let dest = Destination::tcp(self.address.clone(), self.port);
        let timer = Timer::new(policy.idle);
        relay_tcp(conn, dest, Bytes::new(), ctx, disp, timer).await
    }
}
