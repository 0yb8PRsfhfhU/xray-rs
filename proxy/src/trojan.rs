//! Trojan inbound (SPEC §2e): `56B hex(SHA224(pw)) + CRLF + cmd + addr + CRLF`.
//! Authentication is a constant-size map lookup; TLS provides confidentiality.

use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use bytes::Bytes;
use compact_str::CompactString;
use sha2::{Digest, Sha224};

use kernel::types::error::Error;
use kernel::types::net::{self, AddrCodec};
use kernel::{Ctx, Destination, Dispatcher, Network, Policy, Timer};
use transport::Stream;

use crate::io::{read_header, relay_tcp};

const CMD_UDP: u8 = 3;

/// A trojan user (the 56-byte key derives from the password).
#[derive(Debug)]
pub struct TrojanUser {
    pub email: CompactString,
    pub level: u32,
}

/// Immutable trojan user table keyed by the 56-byte hex(SHA224(password)).
pub struct TrojanUsers {
    by_key: HashMap<[u8; 56], Arc<TrojanUser>>,
}

/// Compute the 56-byte ASCII-hex key for a password.
pub fn trojan_key(password: &str) -> [u8; 56] {
    let mut h = Sha224::new();
    h.update(password.as_bytes());
    let digest = h.finalize();
    let mut out = [0u8; 56];
    let _ = hex::encode_to_slice(digest, &mut out);
    out
}

impl TrojanUsers {
    pub fn new<I>(users: I) -> TrojanUsers
    where
        I: IntoIterator<Item = (String, CompactString, u32)>,
    {
        let mut by_key = HashMap::new();
        for (password, email, level) in users {
            by_key.insert(trojan_key(&password), Arc::new(TrojanUser { email, level }));
        }
        TrojanUsers { by_key }
    }

    pub fn get(&self, key: &[u8]) -> Option<&Arc<TrojanUser>> {
        let k: [u8; 56] = key.try_into().ok()?;
        self.by_key.get(&k)
    }
}

/// Parse the trojan request header, authenticating the user.
fn parse(buf: &mut Bytes, users: &TrojanUsers) -> Result<Destination, Error> {
    let hash = net::take(buf, 56)?;
    if users.get(&hash).is_none() {
        return Err(Error::Auth);
    }
    let _crlf = net::take(buf, 2)?;
    let cmd = net::take_u8(buf)?;
    let (address, port) = AddrCodec::TROJAN.read(buf)?;
    let _crlf2 = net::take(buf, 2)?;
    let network = if cmd == CMD_UDP {
        Network::Udp
    } else {
        Network::Tcp
    };
    Ok(Destination {
        network,
        address,
        port,
    })
}

/// Trojan inbound handler.
pub struct Trojan {
    users: Arc<TrojanUsers>,
}

impl Trojan {
    pub fn new(users: Arc<TrojanUsers>) -> Trojan {
        Trojan { users }
    }

    pub async fn process(
        &self,
        ctx: &Ctx,
        mut conn: Stream,
        disp: &Dispatcher,
        policy: &Policy,
    ) -> io::Result<()> {
        let users = self.users.clone();
        let (dest, leftover) = read_header(&mut conn, policy.handshake, 16384, move |b| {
            parse(b, &users)
        })
        .await?;
        let timer = Timer::new(policy.idle);
        match dest.network {
            Network::Udp => {
                crate::udp::relay_trojan_udp(conn, dest, leftover, ctx, disp, timer).await
            }
            _ => relay_tcp(conn, dest, leftover, ctx, disp, timer).await,
        }
    }
}
