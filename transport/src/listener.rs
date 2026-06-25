//! TCP listener binding with server sockopts (SPEC §2c).

use std::io;
use std::net::SocketAddr;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpListener;

/// Server socket options applied before bind.
#[derive(Debug, Clone, Default)]
pub struct SocketOpts {
    pub reuse_port: bool,
    pub mark: Option<u32>,
}

/// Bind a TCP listener with `SO_REUSEADDR` (+ optional `SO_REUSEPORT`/`SO_MARK`).
pub fn bind_tcp(addr: SocketAddr, opts: &SocketOpts) -> io::Result<TcpListener> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    if opts.reuse_port {
        let _ = socket.set_reuse_port(true);
    }
    #[cfg(target_os = "linux")]
    if let Some(mark) = opts.mark {
        let _ = socket.set_mark(mark);
    }
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    TcpListener::from_std(socket.into())
}
