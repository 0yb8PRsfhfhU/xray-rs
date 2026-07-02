//! The concrete `tower::Service` tree (objective requirement 4).
//!
//! Four services compose into the isomorphic hierarchy — **transport is the
//! parent of proxy, whose children are route then outbound**:
//!
//! ```text
//! TransportService   accept a raw conn -> frame it into stream(s)
//!   └─ ProxyService   decode + auth the stream, learn the target
//!        ├─ RouteService     target -> RouteDecision (first-match table)
//!        └─ OutboundDispatch decision -> pick outbound, dial + relay
//! ```
//!
//! A parent delegates *part* of each request to a child by holding the child as
//! a `tower::Service` and driving it with [`ServiceExt::oneshot`]. Because the
//! child is reached through its own service value (typically a
//! [`SwappableService`](crate::runtime::service::SwappableService)), a swap of
//! that child is observed here as `oneshot` awaiting the child's `poll_ready` —
//! the accepted "not ready after update" window (objective requirement 4) is
//! propagated per-request, and the parent stays transparent to the child.
//!
//! `kernel` supplies [`RouteService`] and [`OutboundDispatch`] concretely (they
//! are pure framework), and [`ProxyService`]/[`TransportService`] as generic
//! compositions over the [`Proxy`]/[`Transport`]/[`Outbound`] trait impls that
//! live downstream.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::task::{Context, Poll};

use compact_str::CompactString;
use futures::future::{BoxFuture, Ready, ready};
use tower::{Service, ServiceExt};

use crate::net::{Destination, Network};
use crate::pipe::outbound::{Outbound, OutboundList};
use crate::pipe::pipe::Link;
use crate::pipe::proxy_protocol::{Proxy, ProxyDecision};
use crate::pipe::transport::{Accepted, Transport};
use crate::route::rule::{GeoMatcher, RouteDecision, RouteQuery, RouteTable};
use crate::runtime::dialer::Dialer;
use crate::runtime::session::Ctx;

// ---------------------------------------------------------------------------
// Request types flowing down the tree
// ---------------------------------------------------------------------------

/// A raw accepted connection entering [`TransportService`]. The listen loop
/// supplies the peer address (the transport owns the *local* address).
pub struct Incoming<C> {
    pub conn: C,
    pub source: Option<SocketAddr>,
}

/// A decoded stream entering [`ProxyService`].
pub struct ProxyRequest<S> {
    pub ctx: Ctx,
    pub stream: S,
}

/// A flow to be routed, entering [`RouteService`]. Owns its fields so the
/// service future is `'static`.
#[derive(Debug, Clone)]
pub struct RouteRequest {
    pub target: Destination,
    pub network: Network,
    pub source: Option<IpAddr>,
    pub sniffed_domain: Option<CompactString>,
    pub auth_hash: Option<u64>,
}

/// A routed flow entering [`OutboundDispatch`].
pub struct OutboundRequest {
    pub decision: RouteDecision,
    pub ctx: Ctx,
    pub target: Destination,
    pub link: Link,
}

// ---------------------------------------------------------------------------
// RouteService — target -> RouteDecision
// ---------------------------------------------------------------------------

/// Leaf service: resolve a [`RouteRequest`] through the [`RouteTable`] against a
/// [`GeoMatcher`]. Pure and synchronous (a table walk), so its future is
/// [`Ready`]. Generic over `G` — never a geo trait object (SPEC §P1).
pub struct RouteService<G> {
    table: Arc<RouteTable>,
    geo: Arc<G>,
}

impl<G> RouteService<G> {
    pub fn new(table: Arc<RouteTable>, geo: Arc<G>) -> Self {
        RouteService { table, geo }
    }
}

impl<G> Clone for RouteService<G> {
    fn clone(&self) -> Self {
        RouteService {
            table: Arc::clone(&self.table),
            geo: Arc::clone(&self.geo),
        }
    }
}

impl<G: GeoMatcher> Service<RouteRequest> for RouteService<G> {
    type Response = RouteDecision;
    type Error = crate::Error;
    type Future = Ready<Result<RouteDecision, crate::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: RouteRequest) -> Self::Future {
        let query = RouteQuery {
            target: &req.target,
            network: req.network,
            source: req.source,
            sniffed_domain: req.sniffed_domain.as_deref(),
            auth_hash: req.auth_hash,
        };
        let decision = self.table.route(&query, self.geo.as_ref());
        ready(Ok(decision))
    }
}

// ---------------------------------------------------------------------------
// OutboundDispatch — decision -> pick outbound -> dial + relay
// ---------------------------------------------------------------------------

/// Leaf service: turn a [`RouteDecision`] into egress. Resolves the decision's
/// tag against the tag-keyed [`OutboundList`] snapshot (SPEC §P2) and runs the
/// chosen [`Outbound`] over a generic [`Dialer`] (SPEC §P1). A
/// [`RouteDecision::Freedom`] resolves to the configured freedom tag;
/// [`RouteDecision::Blackhole`] (or a missing tag with no freedom) drops the
/// link by returning without dialing.
pub struct OutboundDispatch<O, D> {
    outbounds: Arc<OutboundList<O>>,
    dialer: Arc<D>,
    freedom_tag: Option<CompactString>,
}

impl<O, D> OutboundDispatch<O, D> {
    /// `freedom_tag` names the outbound that services [`RouteDecision::Freedom`]
    /// (the default "direct" branch, objective requirement 5).
    pub fn new(
        outbounds: Arc<OutboundList<O>>,
        dialer: Arc<D>,
        freedom_tag: Option<CompactString>,
    ) -> Self {
        OutboundDispatch {
            outbounds,
            dialer,
            freedom_tag,
        }
    }
}

impl<O, D> Clone for OutboundDispatch<O, D> {
    fn clone(&self) -> Self {
        OutboundDispatch {
            outbounds: Arc::clone(&self.outbounds),
            dialer: Arc::clone(&self.dialer),
            freedom_tag: self.freedom_tag.clone(),
        }
    }
}

impl<O: Outbound, D: Dialer + 'static> Service<OutboundRequest> for OutboundDispatch<O, D> {
    type Response = ();
    type Error = io::Error;
    type Future = BoxFuture<'static, io::Result<()>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: OutboundRequest) -> Self::Future {
        let outbounds = Arc::clone(&self.outbounds);
        let dialer = Arc::clone(&self.dialer);
        let freedom_tag = self.freedom_tag.clone();
        Box::pin(async move {
            let OutboundRequest {
                decision,
                ctx,
                target,
                link,
            } = req;
            let tag = match decision {
                RouteDecision::Outbound(t) => Some(t),
                RouteDecision::Freedom => freedom_tag,
                // Blackhole: drop the link (EOF both ways) and finish.
                RouteDecision::Blackhole => None,
            };
            let Some(tag) = tag else {
                return Ok(());
            };
            let Some(outbound) = outbounds.get(&tag) else {
                // Unknown tag: nothing to dial. Drop the link like a blackhole.
                return Ok(());
            };
            outbound.process(&ctx, target, link, dialer.as_ref()).await
        })
    }
}

// ---------------------------------------------------------------------------
// ProxyService — decode + auth, then delegate to route + outbound children
// ---------------------------------------------------------------------------

/// Parent service over a [`Proxy`], holding its two children (route, outbound)
/// as `tower::Service`s. On each stream it decodes/authenticates via the proxy,
/// asks the route child where to send the flow, then hands the [`Link`] to the
/// outbound child. The children are typically
/// [`SwappableService`](crate::runtime::service::SwappableService)s, so a reload
/// of either is observed here transparently through [`ServiceExt::oneshot`].
pub struct ProxyService<P, Rc, Oc> {
    proxy: Arc<P>,
    route: Rc,
    outbound: Oc,
}

impl<P, Rc, Oc> ProxyService<P, Rc, Oc> {
    pub fn new(proxy: Arc<P>, route: Rc, outbound: Oc) -> Self {
        ProxyService {
            proxy,
            route,
            outbound,
        }
    }
}

impl<P, Rc: Clone, Oc: Clone> Clone for ProxyService<P, Rc, Oc> {
    fn clone(&self) -> Self {
        ProxyService {
            proxy: Arc::clone(&self.proxy),
            route: self.route.clone(),
            outbound: self.outbound.clone(),
        }
    }
}

impl<P, Rc, Oc, S> Service<ProxyRequest<S>> for ProxyService<P, Rc, Oc>
where
    P: Proxy,
    Rc: Service<RouteRequest, Response = RouteDecision> + Clone + Send + 'static,
    Rc::Error: Into<io::Error>,
    Rc::Future: Send,
    Oc: Service<OutboundRequest, Response = ()> + Clone + Send + 'static,
    Oc::Error: Into<io::Error>,
    Oc::Future: Send,
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    type Response = ();
    type Error = io::Error;
    type Future = BoxFuture<'static, io::Result<()>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Children are readied per-request via `oneshot`; that is where the
        // not-ready-after-swap window is observed (objective requirement 4).
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: ProxyRequest<S>) -> Self::Future {
        let proxy = Arc::clone(&self.proxy);
        let route = self.route.clone();
        let outbound = self.outbound.clone();
        Box::pin(async move {
            let ProxyRequest { ctx, stream } = req;
            // 1. decode + authenticate + learn target (proxy owns the uplink pump).
            let ProxyDecision { target, ctx, link } = proxy.decode(ctx, stream).await?;
            // 2. delegate routing to the route child.
            let route_req = RouteRequest {
                target: target.clone(),
                network: target.network,
                source: ctx.source.map(|s| s.ip()),
                sniffed_domain: None,
                auth_hash: ctx.user_auth_hash,
            };
            let decision = route.oneshot(route_req).await.map_err(Into::into)?;
            // 3. delegate egress to the outbound child.
            let ob_req = OutboundRequest {
                decision,
                ctx,
                target,
                link,
            };
            outbound.oneshot(ob_req).await.map_err(Into::into)?;
            Ok(())
        })
    }
}

// ---------------------------------------------------------------------------
// TransportService — accept a raw conn, frame it, drive the proxy child
// ---------------------------------------------------------------------------

/// Root service over a [`Transport`], holding the proxy child. It frames one
/// accepted connection and drives the proxy child per resulting stream — one for
/// a [`Accepted::Single`] transport, many (spawned) for a
/// [`Accepted::Multiplexed`] carrier. The transport owns the *local* listen
/// address (objective requirement 3); the peer address arrives on [`Incoming`].
pub struct TransportService<T, Pc> {
    transport: Arc<T>,
    proxy: Pc,
    tag: CompactString,
}

impl<T, Pc> TransportService<T, Pc> {
    pub fn new(transport: Arc<T>, proxy: Pc, tag: impl Into<CompactString>) -> Self {
        TransportService {
            transport,
            proxy,
            tag: tag.into(),
        }
    }
}

impl<T, Pc: Clone> Clone for TransportService<T, Pc> {
    fn clone(&self) -> Self {
        TransportService {
            transport: Arc::clone(&self.transport),
            proxy: self.proxy.clone(),
            tag: self.tag.clone(),
        }
    }
}

impl<T, Pc> Service<Incoming<T::Conn>> for TransportService<T, Pc>
where
    T: Transport,
    Pc: Service<ProxyRequest<T::Stream>, Response = ()> + Clone + Send + 'static,
    Pc::Error: Into<io::Error>,
    Pc::Future: Send,
{
    type Response = ();
    type Error = io::Error;
    type Future = BoxFuture<'static, io::Result<()>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, incoming: Incoming<T::Conn>) -> Self::Future {
        let transport = Arc::clone(&self.transport);
        let proxy = self.proxy.clone();
        let tag = self.tag.clone();
        let local = transport.listen_addr();
        Box::pin(async move {
            let mk_ctx = |source: Option<SocketAddr>| {
                let mut ctx = Ctx::new(tag.clone(), source);
                ctx.local = Some(local);
                ctx
            };
            match transport.accept(incoming.conn).await? {
                Accepted::Single(stream) => {
                    let req = ProxyRequest {
                        ctx: mk_ctx(incoming.source),
                        stream,
                    };
                    proxy.oneshot(req).await.map_err(Into::into)?;
                }
                Accepted::Multiplexed(mut rx) => {
                    // Each demultiplexed stream is an independent flow; spawn so
                    // a slow flow never blocks the carrier.
                    while let Some(stream) = rx.recv().await {
                        let proxy = proxy.clone();
                        let ctx = mk_ctx(incoming.source);
                        tokio::spawn(async move {
                            let _ = proxy.oneshot(ProxyRequest { ctx, stream }).await;
                        });
                    }
                }
            }
            Ok(())
        })
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use crate::net::Address;
    use crate::pipe::pipe::{LINK_CAPACITY, pipe};
    use crate::route::balance::BalanceMode;
    use crate::route::rule::{Condition, MatchRule, NoGeo};
    use crate::runtime::service::{SwapHandle, UpdatePolicy};
    use parking_lot::Mutex;
    use tokio::io::DuplexStream;

    /// Records which outbound tag serviced each flow.
    type Log = Arc<Mutex<Vec<CompactString>>>;

    /// A dialer that is never actually called by the mock outbound.
    struct MockDialer;
    impl crate::runtime::dialer::TcpDialer for MockDialer {
        async fn dial_tcp(&self, _d: &Destination) -> io::Result<tokio::net::TcpStream> {
            Err(io::Error::other("mock"))
        }
    }
    impl crate::runtime::dialer::UdpDialer for MockDialer {
        async fn bind_udp(&self, _d: &Destination) -> io::Result<tokio::net::UdpSocket> {
            Err(io::Error::other("mock"))
        }
    }

    /// An outbound that records its tag and drains the link.
    struct MockOutbound {
        tag: CompactString,
        log: Log,
    }
    impl Outbound for MockOutbound {
        async fn process<D: Dialer>(
            &self,
            _ctx: &Ctx,
            _target: Destination,
            mut link: Link,
            _dialer: &D,
        ) -> io::Result<()> {
            self.log.lock().push(self.tag.clone());
            // Drain until EOF so the pipe closes cleanly.
            while link.reader.recv().await.is_some() {}
            Ok(())
        }
    }

    /// A proxy that yields a fixed target without reading the stream.
    struct MockProxy {
        target: Destination,
    }
    impl Proxy for MockProxy {
        type Auth = ();
        fn networks(&self) -> &[Network] {
            &[Network::Tcp]
        }
        async fn decode<S>(&self, ctx: Ctx, _stream: S) -> io::Result<ProxyDecision>
        where
            S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
        {
            // Build the pipe; keep the outbound half for the decision, drop the
            // inbound half so the link EOFs immediately (no real pumping here).
            let (_inbound, outbound) = pipe(LINK_CAPACITY);
            Ok(ProxyDecision {
                target: self.target.clone(),
                ctx,
                link: outbound,
            })
        }
    }

    /// A transport that yields one dummy stream per accepted connection.
    struct MockTransport;
    impl Transport for MockTransport {
        type Conn = DuplexStream;
        type Stream = DuplexStream;
        fn listen_addr(&self) -> SocketAddr {
            "127.0.0.1:0".parse().unwrap()
        }
        async fn accept(&self, _conn: Self::Conn) -> io::Result<Accepted<Self::Stream>> {
            let (a, _b) = tokio::io::duplex(64);
            Ok(Accepted::Single(a))
        }
    }

    /// Build the full tree and run one flow to `target`; return the tag that
    /// serviced it.
    async fn run_flow(target: Destination) -> Option<CompactString> {
        let log: Log = Arc::new(Mutex::new(Vec::new()));

        // Outbounds: "direct" (freedom) + "block".
        let outbounds = Arc::new(OutboundList::new([
            (
                CompactString::from("direct"),
                MockOutbound {
                    tag: "direct".into(),
                    log: log.clone(),
                },
            ),
            (
                CompactString::from("block"),
                MockOutbound {
                    tag: "block".into(),
                    log: log.clone(),
                },
            ),
        ]));

        // Route table: domain:blocked.com -> ["block"]; else default -> freedom.
        let table = Arc::new(RouteTable::new(
            vec![MatchRule::new(
                vec![Condition::parse("domain:blocked.com").unwrap()],
                vec!["block".into()],
                BalanceMode::Random,
            )],
            None, // absent default => Freedom
        ));

        // Children as swappable services (proves tree integrates with req. 4).
        let (_rh, route_child) = SwapHandle::new(
            RouteService::new(table, Arc::new(NoGeo)),
            UpdatePolicy::Drain,
        );
        let (_oh, ob_child) = SwapHandle::new(
            OutboundDispatch::new(outbounds, Arc::new(MockDialer), Some("direct".into())),
            UpdatePolicy::Drain,
        );

        let proxy_svc = ProxyService::new(Arc::new(MockProxy { target }), route_child, ob_child);
        let (_ph, proxy_child) = SwapHandle::new(proxy_svc, UpdatePolicy::Drain);

        let mut transport_svc = TransportService::new(Arc::new(MockTransport), proxy_child, "in");

        let (conn, _peer) = tokio::io::duplex(64);
        transport_svc
            .ready()
            .await
            .unwrap()
            .call(Incoming { conn, source: None })
            .await
            .unwrap();

        log.lock().first().cloned()
    }

    #[tokio::test]
    async fn blocked_domain_routes_to_block_outbound() {
        let target = Destination::tcp(Address::parse("blocked.com"), 443);
        assert_eq!(run_flow(target).await.as_deref(), Some("block"));
    }

    #[tokio::test]
    async fn default_flow_routes_to_freedom_outbound() {
        let target = Destination::tcp(Address::parse("allowed.com"), 443);
        assert_eq!(run_flow(target).await.as_deref(), Some("direct"));
    }
}
