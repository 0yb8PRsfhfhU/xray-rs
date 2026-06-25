//! Server-side TLS via OpenSSL (per objective: OpenSSL, not rustls).

use std::pin::Pin;

use openssl::pkey::PKey;
use openssl::ssl::{AlpnError, Ssl, SslAcceptor, SslMethod, select_next_proto};
use openssl::x509::X509;
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

use kernel::error::{Error, Result};

/// A reusable TLS server context built from a PEM cert chain + key.
pub struct TlsServer {
    acceptor: SslAcceptor,
}

fn cfg<T>(r: std::result::Result<T, openssl::error::ErrorStack>) -> Result<T> {
    r.map_err(|e| Error::Config(format!("openssl: {e}")))
}

/// Encode ALPN protocol names into OpenSSL wire format (`len ++ bytes`).
fn alpn_wire(alpn: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in alpn {
        if let Ok(len) = u8::try_from(p.len()) {
            out.push(len);
            out.extend_from_slice(p.as_bytes());
        }
    }
    out
}

impl TlsServer {
    /// Build from in-memory PEM bytes. `alpn` lists offered protocols
    /// (e.g. `["h2", "http/1.1"]`); empty disables ALPN negotiation.
    pub fn from_pem(cert_pem: &[u8], key_pem: &[u8], alpn: &[String]) -> Result<TlsServer> {
        let pkey = cfg(PKey::private_key_from_pem(key_pem))?;
        let mut chain = cfg(X509::stack_from_pem(cert_pem))?;
        let mut iter = chain.drain(..);
        let leaf = iter.next().ok_or_else(|| Error::Config("empty certificate".into()))?;

        let mut b = cfg(SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()))?;
        cfg(b.set_private_key(&pkey))?;
        cfg(b.set_certificate(&leaf))?;
        for extra in iter {
            cfg(b.add_extra_chain_cert(extra))?;
        }
        if !alpn.is_empty() {
            let wire: &'static [u8] = Box::leak(alpn_wire(alpn).into_boxed_slice());
            b.set_alpn_select_callback(move |_ssl, client| {
                select_next_proto(wire, client).ok_or(AlpnError::NOACK)
            });
        }
        Ok(TlsServer { acceptor: b.build() })
    }

    /// Perform the TLS handshake over an accepted TCP stream.
    pub async fn accept(&self, tcp: TcpStream) -> std::io::Result<SslStream<TcpStream>> {
        let ssl = Ssl::new(self.acceptor.context()).map_err(std::io::Error::other)?;
        let mut stream = SslStream::new(ssl, tcp).map_err(std::io::Error::other)?;
        Pin::new(&mut stream).accept().await.map_err(std::io::Error::other)?;
        Ok(stream)
    }
}
