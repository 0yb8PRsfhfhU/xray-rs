//! Outbound handlers: `freedom` (direct) and `blackhole` (drop). Summed into a
//! closed `enum` per SPEC §P1 — no trait objects.

use std::io;

use bytes::Bytes;

use crate::pipe_asm::copy::splice;
use crate::egress::dialer::SystemDialer;
use crate::types::net::{Address, Destination};
use crate::pipe_asm::pipe::{Link, UdpLink, UdpPacket};
use crate::pipe_asm::timer::Timer;

/// Closed sum of server outbounds.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Outbound {
    /// Direct outbound: dial the real target and forward bytes.
    Freedom,
    /// Drop everything (used to block routed traffic).
    Blackhole,
}

impl Outbound {
    /// Handle a TCP flow to `dest`, pumping bytes between the link and target.
    pub async fn handle_tcp(
        &self,
        dialer: &SystemDialer,
        dest: Destination,
        link: Link,
        timer: &Timer,
    ) -> io::Result<()> {
        match self {
            Outbound::Freedom => {
                let stream = dialer.dial_tcp(&dest).await?;
                splice(stream, link, timer).await
            }
            Outbound::Blackhole => {
                drop(link);
                Ok(())
            }
        }
    }

    /// Handle a UDP-associated flow: relay datagrams to their per-packet targets.
    pub async fn handle_udp(
        &self,
        dialer: &SystemDialer,
        link: UdpLink,
        timer: &Timer,
    ) -> io::Result<()> {
        match self {
            Outbound::Freedom => freedom_udp(dialer, link, timer).await,
            Outbound::Blackhole => {
                drop(link);
                Ok(())
            }
        }
    }
}

async fn freedom_udp(dialer: &SystemDialer, link: UdpLink, timer: &Timer) -> io::Result<()> {
    use std::sync::Arc;
    let UdpLink { mut reader, writer } = link;
    let sock = Arc::new(dialer.bind_udp().await?);
    let token = timer.token();

    let send_sock = sock.clone();
    let send = async move {
        while let Some(pkt) = reader.recv().await {
            timer.update();
            let addr = dialer.resolve_addr(&pkt.target).await?;
            send_sock.send_to(&pkt.data, addr).await?;
        }
        Ok(())
    };

    let recv = async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, from) = sock.recv_from(&mut buf).await?;
            timer.update();
            let slice = buf.get(..n).unwrap_or(&[]);
            let data = Bytes::copy_from_slice(slice);
            let target = Destination::udp(Address::Ip(from.ip()), from.port());
            if writer.send(UdpPacket { data, target }).await.is_err() {
                return Ok(());
            }
        }
    };

    tokio::select! {
        _ = token.cancelled() => Ok(()),
        r = send => r,
        r = recv => r,
    }
}
