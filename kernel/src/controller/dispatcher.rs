//! Dispatcher: build the pipe pair, pick an outbound, drive it (SPEC §1, §2f).

use std::collections::HashMap;

use compact_str::CompactString;

use crate::controller::router::{RouteCtx, Router};
use crate::controller::session::Ctx;
use crate::egress::dialer::SystemDialer;
use crate::egress::outbound::Outbound;
use crate::pipe_asm::pipe::{LINK_CAPACITY, Link, UdpLink, pipe, udp_pipe};
use crate::pipe_asm::timer::Timer;
use crate::types::net::Destination;

/// Owns the outbound set + router and wires inbound flows to outbounds.
pub struct Dispatcher {
    dialer: SystemDialer,
    outbounds: HashMap<CompactString, Outbound>,
    default_tag: CompactString,
    router: Option<Router>,
}

impl Dispatcher {
    pub fn new(
        dialer: SystemDialer,
        outbounds: HashMap<CompactString, Outbound>,
        default_tag: impl Into<CompactString>,
        router: Option<Router>,
    ) -> Dispatcher {
        Dispatcher {
            dialer,
            outbounds,
            default_tag: default_tag.into(),
            router,
        }
    }

    /// Convenience: a dispatcher with a single `freedom` outbound and no router.
    pub fn single_freedom(dialer: SystemDialer) -> Dispatcher {
        let mut outbounds = HashMap::new();
        outbounds.insert(CompactString::new("freedom"), Outbound::Freedom);
        Dispatcher::new(dialer, outbounds, "freedom", None)
    }

    pub fn dialer(&self) -> &SystemDialer {
        &self.dialer
    }

    fn select(&self, ctx: &Ctx, dest: &Destination, sniffed: Option<&str>) -> Outbound {
        if let Some(router) = &self.router {
            let rc = RouteCtx {
                network: dest.network,
                target: dest,
                inbound_tag: &ctx.inbound_tag,
                source: ctx.source.map(|s| s.ip()),
                sniffed_domain: sniffed,
                protocol: None,
            };
            if let Some(tag) = router.pick(&rc)
                && let Some(ob) = self.outbounds.get(tag)
            {
                return *ob;
            }
        }
        self.outbounds
            .get(self.default_tag.as_str())
            .cloned()
            .unwrap_or(Outbound::Freedom)
    }

    /// Dispatch a TCP flow to `dest`; returns the inbound half of the pipe.
    pub fn dispatch_tcp(&self, ctx: &Ctx, dest: Destination, timer: Timer) -> Link {
        self.dispatch_tcp_sniffed(ctx, dest, None, timer)
    }

    /// Dispatch a TCP flow with an optional sniffed domain used for routing.
    pub fn dispatch_tcp_sniffed(
        &self,
        ctx: &Ctx,
        dest: Destination,
        sniffed: Option<&str>,
        timer: Timer,
    ) -> Link {
        let (inbound, outbound_half) = pipe(LINK_CAPACITY);
        let ob = self.select(ctx, &dest, sniffed);
        let dialer = self.dialer.clone();
        let id = ctx.id;
        tokio::spawn(async move {
            if let Err(e) = ob.handle_tcp(&dialer, dest, outbound_half, &timer).await {
                tracing::debug!(session = id, error = %e, "outbound tcp ended");
            }
        });
        inbound
    }

    /// Dispatch a UDP-associated flow; returns the inbound half of the pipe.
    pub fn dispatch_udp(&self, ctx: &Ctx, timer: Timer) -> UdpLink {
        let (inbound, outbound_half) = udp_pipe(LINK_CAPACITY);
        let ob = self
            .outbounds
            .get(self.default_tag.as_str())
            .cloned()
            .unwrap_or(Outbound::Freedom);
        let dialer = self.dialer.clone();
        let id = ctx.id;
        tokio::spawn(async move {
            if let Err(e) = ob.handle_udp(&dialer, outbound_half, &timer).await {
                tracing::debug!(session = id, error = %e, "outbound udp ended");
            }
        });
        inbound
    }
}
