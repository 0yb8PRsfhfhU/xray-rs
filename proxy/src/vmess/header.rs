//! Pure VMess request-header parser: fixed fields, FNV1a authentication, and
//! the shared VMess address codec. No socket I/O lives here.

use bytes::Bytes;
use compact_str::CompactString;

use kernel::Error;
use kernel::net::{self, AddrCodec};
use kernel::{Destination, Network};

use super::crypto::fnv1a;

const CMD_TCP: u8 = 1;
const CMD_UDP: u8 = 2;
const CMD_MUX: u8 = 3;

/// Decoded VMess request header.
pub(crate) struct Request {
    pub(crate) dest: Destination,
    pub(crate) req_key: [u8; 16],
    pub(crate) req_iv: [u8; 16],
    pub(crate) resp_header: u8,
    pub(crate) option: u8,
    pub(crate) security: u8,
    pub(crate) mux: bool,
    pub(crate) email: CompactString,
}

pub(crate) fn parse_header(header: &[u8]) -> Result<Request, Error> {
    // version(1) iv(16) key(16) respHeader(1) option(1) padsec(1) reserved(1) cmd(1) = 38
    if header.len() < 38 {
        return Err(Error::Protocol("vmess header short"));
    }
    let fixed = header.get(..38).ok_or(Error::Protocol("vmess header"))?;
    let mut b = Bytes::copy_from_slice(header);
    // verify FNV1a over header[..len-4]
    let body_len = header
        .len()
        .checked_sub(4)
        .ok_or(Error::Protocol("vmess fnv"))?;
    let signed = header.get(..body_len).ok_or(Error::Protocol("vmess fnv"))?;
    let expect = header.get(body_len..).ok_or(Error::Protocol("vmess fnv"))?;
    let expect = u32::from_be_bytes([
        *expect.first().ok_or(Error::Protocol("fnv"))?,
        *expect.get(1).ok_or(Error::Protocol("fnv"))?,
        *expect.get(2).ok_or(Error::Protocol("fnv"))?,
        *expect.get(3).ok_or(Error::Protocol("fnv"))?,
    ]);
    if fnv1a(signed) != expect {
        return Err(Error::Auth);
    }

    let version = *fixed.first().ok_or(Error::Protocol("ver"))?;
    if version != 1 {
        return Err(Error::Protocol("vmess version"));
    }
    let mut req_iv = [0u8; 16];
    let mut req_key = [0u8; 16];
    req_iv.copy_from_slice(fixed.get(1..17).ok_or(Error::Protocol("iv"))?);
    req_key.copy_from_slice(fixed.get(17..33).ok_or(Error::Protocol("key"))?);
    let resp_header = *fixed.get(33).ok_or(Error::Protocol("resp"))?;
    let option = *fixed.get(34).ok_or(Error::Protocol("opt"))?;
    let padsec = *fixed.get(35).ok_or(Error::Protocol("padsec"))?;
    // padsec high nibble is the address-padding length; the decrypted header
    // already includes those bytes and the FNV1a check covers them, so the
    // address codec reads what it needs and the trailing padding is just left.
    let security = padsec & 0x0f;
    let cmd = *fixed.get(37).ok_or(Error::Protocol("cmd"))?;

    // Consume the 38 fixed bytes, then addr (unless Mux, which carries no addr).
    b.advance_fixed(38)?;
    if cmd == CMD_MUX {
        return Ok(Request {
            dest: Destination::tcp(kernel::Address::Ip(std::net::Ipv4Addr::LOCALHOST.into()), 0),
            req_key,
            req_iv,
            resp_header,
            option,
            security,
            mux: true,
            email: CompactString::default(),
        });
    }
    let network = match cmd {
        CMD_TCP => Network::Tcp,
        CMD_UDP => Network::Udp,
        _ => return Err(Error::Protocol("vmess command")),
    };
    let (address, port) = AddrCodec::VMESS.read(&mut b)?;

    Ok(Request {
        dest: Destination {
            network,
            address,
            port,
        },
        req_key,
        req_iv,
        resp_header,
        option,
        security,
        mux: false,
        email: CompactString::default(),
    })
}

trait AdvanceFixed {
    fn advance_fixed(&mut self, n: usize) -> Result<(), Error>;
}

impl AdvanceFixed for Bytes {
    fn advance_fixed(&mut self, n: usize) -> Result<(), Error> {
        let _ = net::take(self, n)?;
        Ok(())
    }
}
