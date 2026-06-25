//! In-process duplex pipe (`Link`) — the data-plane spine (SPEC §2a).
//!
//! A bounded `mpsc<Bytes>` pair *is* the backpressure. Dropping a sender yields
//! a clean EOF on the paired receiver; a [`CancellationToken`] aborts both ends.

use bytes::Bytes;
use tokio::sync::mpsc;

use crate::net::Destination;

/// Default number of in-flight chunks per direction (~backpressure window).
pub const LINK_CAPACITY: usize = 32;

/// A UDP datagram travelling through a [`UdpLink`], tagged with its target.
#[derive(Debug, Clone)]
pub struct UdpPacket {
    pub data: Bytes,
    pub target: Destination,
}

/// One half of a stream pipe: read downlink bytes, write uplink bytes.
pub struct Link {
    pub reader: mpsc::Receiver<Bytes>,
    pub writer: mpsc::Sender<Bytes>,
}

/// One half of a datagram pipe for UDP-associated flows.
pub struct UdpLink {
    pub reader: mpsc::Receiver<UdpPacket>,
    pub writer: mpsc::Sender<UdpPacket>,
}

/// Create a stream pipe. Returns `(inbound_half, outbound_half)`:
/// data the inbound writes flows to the outbound's reader, and vice versa.
pub fn pipe(capacity: usize) -> (Link, Link) {
    let (up_tx, up_rx) = mpsc::channel(capacity);
    let (down_tx, down_rx) = mpsc::channel(capacity);
    let inbound = Link { reader: down_rx, writer: up_tx };
    let outbound = Link { reader: up_rx, writer: down_tx };
    (inbound, outbound)
}

/// Create a datagram pipe, mirroring [`pipe`] for UDP packets.
pub fn udp_pipe(capacity: usize) -> (UdpLink, UdpLink) {
    let (up_tx, up_rx) = mpsc::channel(capacity);
    let (down_tx, down_rx) = mpsc::channel(capacity);
    let inbound = UdpLink { reader: down_rx, writer: up_tx };
    let outbound = UdpLink { reader: up_rx, writer: down_tx };
    (inbound, outbound)
}
