//! VLESS inbound, `flow=none` only (XTLS/Vision excluded per objective).
//!
//! Request: `ver(0) + uuid(16) + addons(len+bytes) + cmd + addr(famA,port-first)`.
//! Response: `ver(0) + addons(len=0)`. TLS provides confidentiality.

use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use bytes::Bytes;
use compact_str::CompactString;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use kernel::net::{self, AddrCodec};
use kernel::{
    Ctx, Destination, Error, LINK_CAPACITY, Network, Proxy, ProxyDecision, Timer, Uuid, pipe,
};

use crate::ProxyContext;
use crate::io::{
    noop_decision, read_header, relay_stream, sniff_override, user_counter, user_hash,
};

const CMD_TCP: u8 = 1;
const CMD_UDP: u8 = 2;
const CMD_MUX: u8 = 3;
const NETWORKS: &[Network] = &[Network::Tcp, Network::Udp];

/// A VLESS user identity.
#[derive(Debug)]
pub struct VlessUser {
    pub id: Uuid,
    pub email: CompactString,
    pub level: u32,
}

/// Immutable VLESS user table keyed by the 16-byte UUID.
pub struct VlessUsers {
    by_id: HashMap<[u8; 16], Arc<VlessUser>>,
}

impl VlessUsers {
    pub fn new<I>(users: I) -> VlessUsers
    where
        I: IntoIterator<Item = (Uuid, CompactString, u32)>,
    {
        let mut by_id = HashMap::new();
        for (id, email, level) in users {
            by_id.insert(*id.as_bytes(), Arc::new(VlessUser { id, email, level }));
        }
        VlessUsers { by_id }
    }

    pub fn get(&self, id: &[u8]) -> Option<&Arc<VlessUser>> {
        let k: [u8; 16] = id.try_into().ok()?;
        self.by_id.get(&k)
    }
}

/// A decoded VLESS request: TCP/UDP target, or a mux.cool carrier.
enum VlessReq {
    Tcp(Destination),
    Udp(Destination),
    Mux,
}

fn parse(buf: &mut Bytes, users: &VlessUsers) -> Result<(VlessReq, CompactString), Error> {
    let ver = net::take_u8(buf)?;
    if ver != 0 {
        return Err(Error::Protocol("vless version"));
    }
    let id = net::take(buf, 16)?;
    let user = users.get(&id).ok_or(Error::Auth)?;
    let email = user.email.clone();
    let addon_len = net::take_u8(buf)? as usize;
    if addon_len > 0 {
        let _ = net::take(buf, addon_len)?;
    }
    let cmd = net::take_u8(buf)?;
    match cmd {
        CMD_TCP => {
            let (address, port) = AddrCodec::VLESS.read(buf)?;
            Ok((VlessReq::Tcp(Destination::tcp(address, port)), email))
        }
        CMD_UDP => {
            let (address, port) = AddrCodec::VLESS.read(buf)?;
            Ok((VlessReq::Udp(Destination::udp(address, port)), email))
        }
        CMD_MUX => Ok((VlessReq::Mux, email)),
        _ => Err(Error::Protocol("vless command")),
    }
}

/// VLESS inbound handler.
pub struct Vless {
    users: arc_swap::ArcSwap<VlessUsers>,
    cx: ProxyContext,
}

impl Vless {
    pub fn new(users: Arc<VlessUsers>, cx: ProxyContext) -> Vless {
        Vless {
            users: arc_swap::ArcSwap::from(users),
            cx,
        }
    }

    /// Swap in a new user table (live user sync, SPEC §P2).
    pub fn set_users(&self, users: Arc<VlessUsers>) {
        self.users.store(users);
    }

    pub fn networks(&self) -> &'static [Network] {
        NETWORKS
    }
}

impl Proxy for Vless {
    type Auth = ();

    fn networks(&self) -> &[Network] {
        NETWORKS
    }

    async fn decode<S>(&self, ctx: Ctx, mut stream: S) -> io::Result<ProxyDecision>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let users = self.users.load_full();
        let ((req, email), leftover) = read_header(
            &mut stream,
            self.cx.policy.handshake_timeout,
            16384,
            move |b| parse(b, &users),
        )
        .await?;
        // Response header: version 0, zero-length addons.
        stream.write_all(&[0u8, 0u8]).await?;
        let hash = user_hash(email.as_bytes());
        let ctx = ctx.with_user(email, hash);
        let timer = Timer::new(self.cx.policy.idle_timeout);
        let counter = user_counter(&ctx, self.cx.stats.as_ref()).await;
        match req {
            VlessReq::Tcp(dest) => {
                let target = sniff_override(dest, &leftover);
                let (inbound, outbound) = pipe(LINK_CAPACITY);
                tokio::spawn(relay_stream(stream, inbound, timer, counter, leftover));
                Ok(ProxyDecision {
                    target,
                    ctx,
                    link: outbound,
                })
            }
            VlessReq::Udp(dest) => {
                crate::udp::relay_vless_udp(
                    stream,
                    dest,
                    leftover,
                    self.cx.dialer.as_ref(),
                    timer,
                    counter,
                )
                .await?;
                Ok(noop_decision(ctx))
            }
            VlessReq::Mux => {
                crate::mux::serve(stream, leftover, self.cx.dialer.clone(), self.cx.policy).await?;
                Ok(noop_decision(ctx))
            }
        }
    }
}
