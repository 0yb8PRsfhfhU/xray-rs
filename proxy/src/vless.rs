//! VLESS inbound, `flow=none` only (XTLS/Vision excluded per objective).
//!
//! Request: `ver(0) + uuid(16) + addons(len+bytes) + cmd + addr(famA,port-first)`.
//! Response: `ver(0) + addons(len=0)`. TLS provides confidentiality.

use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use bytes::Bytes;
use compact_str::CompactString;
use tokio::io::AsyncWriteExt;

use kernel::types::error::Error;
use kernel::types::net::{self, AddrCodec};
use kernel::{Ctx, Destination, Dispatcher, Policy, Timer, Uuid};
use transport::Stream;

use crate::io::{read_header, relay_tcp};
use crate::udp::relay_vless_udp;

const CMD_TCP: u8 = 1;
const CMD_UDP: u8 = 2;
const CMD_MUX: u8 = 3;

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

fn parse(buf: &mut Bytes, users: &VlessUsers) -> Result<VlessReq, Error> {
    let ver = net::take_u8(buf)?;
    if ver != 0 {
        return Err(Error::Protocol("vless version"));
    }
    let id = net::take(buf, 16)?;
    if users.get(&id).is_none() {
        return Err(Error::Auth);
    }
    let addon_len = net::take_u8(buf)? as usize;
    if addon_len > 0 {
        let _ = net::take(buf, addon_len)?;
    }
    let cmd = net::take_u8(buf)?;
    match cmd {
        CMD_TCP => {
            let (address, port) = AddrCodec::VLESS.read(buf)?;
            Ok(VlessReq::Tcp(Destination::tcp(address, port)))
        }
        CMD_UDP => {
            let (address, port) = AddrCodec::VLESS.read(buf)?;
            Ok(VlessReq::Udp(Destination::udp(address, port)))
        }
        CMD_MUX => Ok(VlessReq::Mux),
        _ => Err(Error::Protocol("vless command")),
    }
}

/// VLESS inbound handler.
pub struct Vless {
    users: Arc<VlessUsers>,
}

impl Vless {
    pub fn new(users: Arc<VlessUsers>) -> Vless {
        Vless { users }
    }

    pub async fn process(
        &self,
        ctx: &Ctx,
        mut conn: Stream,
        disp: &Dispatcher,
        policy: &Policy,
    ) -> io::Result<()> {
        let users = self.users.clone();
        let (req, leftover) = read_header(&mut conn, policy.handshake, 16384, move |b| {
            parse(b, &users)
        })
        .await?;
        // Response header: version 0, zero-length addons.
        conn.write_all(&[0u8, 0u8]).await?;
        match req {
            VlessReq::Tcp(dest) => {
                let timer = Timer::new(policy.idle);
                relay_tcp(conn, dest, leftover, ctx, disp, timer).await
            }
            VlessReq::Udp(dest) => {
                let timer = Timer::new(policy.idle);
                relay_vless_udp(conn, dest, leftover, ctx, disp, timer).await
            }
            VlessReq::Mux => crate::mux::serve(conn, leftover, ctx, disp, policy).await,
        }
    }
}
