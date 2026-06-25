# xray-core → Rust: server-library spec

A spec summary of what to implement to rewrite the **library** portion of
[xray-core](https://github.com/XTLS/Xray-core) (Go reference in `Xray-core/`) as a
Rust **proxy server** (inbound side). Derived from reading the reference source.

## 0. Scope note (read first)

"Proxy server, not client" = you implement **inbound** proxy protocols (decode what
clients send) but skip the **outbound** proxy encoders (vmess/vless/trojan *client*
that dial an upstream xray). You still need **one outbound: `freedom`** (direct
`TcpStream::connect` to the real target) — a server with no outbound forwards nothing.

- ✅ Inbound protocol decoders (vless/trojan/shadowsocks/socks/http/vmess server)
- ✅ Inbound transports + server-side TLS
- ✅ Dispatcher + a `freedom` direct outbound
- ❌ Outbound proxy protocol encoders, client dialers, DNS-over-proxy client API,
  routing-to-other-servers — out of scope (noted only where the inbound *reuses* a
  shared codec).

**Compatibility, not transliteration.** The Go source is a *wire-format and behavior*
reference, not a structure to mirror line-for-line. Match the bytes on the wire and the
observable handshake/timeout/auth semantics; do **not** reproduce Go's package layout,
interface graph, reflection DI, or `MultiBuffer` plumbing. Where a Rust idiom is cleaner
(enums over interfaces, ownership over GC, `?` over `common.Must`), take it.

## 0.5 Rust implementation principles (read second)

These bind every section below. When the prose later says "a `Dialer`" or "the config",
it means the Rust shapes defined here.

### P1 — Static dispatch by default; sum variants with `enum`, never `dyn`

The set of proxies/transports/outbounds is **closed and known at compile time**, so the
type is always statically knowable. Prefer monomorphized generics `fn f<D: Dialer>(d: &D)`
over `&dyn Dialer`. When one value must hold *one of several* concrete types (e.g. the
dispatcher owns whichever outbound the config built), **sum them into an `enum` that
implements the trait by delegating** — this keeps static dispatch, no vtable, no heap
indirection, and lets the optimizer inline.

```rust
// trait stays object-safe-agnostic; we never make a trait object out of it
trait Dialer {
    async fn dial(&self, dest: &Destination) -> io::Result<Stream>;
}

// the "sum" — add a variant per impl; match delegates. This IS a `Dialer`.
enum AnyDialer { System(SystemDialer), /* tls/ws wrappers later */ }
impl Dialer for AnyDialer {
    async fn dial(&self, dest: &Destination) -> io::Result<Stream> {
        match self { AnyDialer::System(d) => d.dial(dest).await }
    }
}
```

Apply the same pattern to the three other open-ended sets:

- `enum Outbound { Freedom(Freedom), Blackhole(Blackhole) }` impl `OutboundHandler`.
- `enum Inbound { Trojan(..), Vless(..), Shadowsocks(..), Socks(..), Http(..), Vmess(..) }`
  impl `InboundHandler`.
- `enum Stream { Tcp(TcpStream), Tls(Box<TlsStream<TcpStream>>), Ws(WsStream), Hu(HuStream) }`
  impl `AsyncRead + AsyncWrite` by delegating each poll. **Box the large TLS variant** so
  the enum stays pointer-sized; otherwise every `Stream` is as big as the fattest variant.

`#[enum_dispatch]` (crate) can generate the delegating `match` arms if the boilerplate
grows; hand-written `match` is fine and clearer for ≤6 variants.

The only place a trait object is acceptable: a genuinely *open* plugin registry the binary
can't enumerate — we have none, so **no `Box<dyn>` / `&dyn` in the hot path**.

### P2 — Immutable shared state; swap-and-drain over locks

Reads on the connection path must never block on a writer. Model live config as
`Arc<Config>` (deeply immutable), **not** `Arc<RwLock<Config>>`:

- At `accept()` time a worker clones one `Arc<Config>` and holds it for the whole
  connection. No lock, no re-read, no torn view; a connection runs against a consistent
  snapshot for its entire life.
- Hot reload = **build a new `Instance` from a new `Arc<Config>`, start it, then drain the
  old**: stop accepting on old listeners, let in-flight connections finish (or cancel via
  their `CancellationToken`), drop the old `Arc` when refcount hits zero.
- Publish the live pointer with `arc_swap::ArcSwap<Config>` for lock-free atomic
  swap; new connections pick up the new snapshot, existing ones keep theirs.

Same rule for user tables: validators hold `Arc<UserTable>`; AddUser/RemoveUser rebuild
and swap rather than locking a shared mutable map on the auth path.

### P3 — `Bytes` for handoff, `BytesMut` only while filling

The copy loop owns a reusable `BytesMut` read window; after a read it does
`buf.split().freeze()` → `Bytes` and hands that to the `Link`. `Bytes` is cheap to clone
(refcount) and **read-only**, which is exactly the contract once bytes leave the reader:
we never mutate mid-chunk. Reach for `BytesMut` *only* where you actually rewrite bytes
in place (e.g. assembling a response header, AEAD in-place decrypt). If a chunk passes
through untouched, it stays `Bytes` end-to-end — zero copies.

### P4 — Cheap domain values; cache DNS

`Address::Domain` is compared, cloned, and used as a cache key constantly (routing,
sniffing, DNS lookup). Store it as a small, cheap-to-clone, cheap-to-compare type:

- `compact_str::CompactString` — inline ≤24 bytes (covers most hostnames) with no heap
  alloc, `O(1)` clone for inline, `Eq`/`Hash` like `String`. **Default choice.**
- `Arc<str>` — when the same domain is shared widely and you want refcounted `O(1)` clone
  regardless of length and pointer-cheap moves.

Either way, **not** bare `String` (allocates on every clone, full memcmp on compare).

When a proxy target is a **domain** (common — clients send hostnames), the `freedom`
outbound must resolve it before `connect`. Resolution is the slow path, so **cache it with
`moka`** (async, TTL + capacity bound, concurrent):

```rust
// resolver shared via Arc<Resolver>; key by the cheap domain type
type DnsCache = moka::future::Cache<CompactString, Arc<[IpAddr]>>;
```

Honor record TTLs (clamp to a sane min/max), cap entries, and dedupe in-flight lookups so
a burst of connections to one host triggers one resolution. This replaces Go's
`dialer.LookupForIP` + ad-hoc caching.

### P5 — Reach for a crate before hand-rolling a protocol

Mirror Go's *wire format*, not its hand-built machinery, when a mature Rust crate already
implements the lower layer:

- **QUIC / HTTP-3** (XHTTP h3, future) → **`quinn`** (+ `h3`), never a hand-rolled
  datagram state machine on raw `tokio::net::UdpSocket`.
- **TLS server** → `tokio-rustls`; **WebSocket** → `tokio-tungstenite`;
  **HTTP/1+2** (httpupgrade, grpc-over-h2, http inbound) → `hyper` / `h2`.
- **Crypto** → RustCrypto (`aes-gcm`, `chacha20poly1305`, `hkdf`, `sha1/2`, `md-5`,
  `hmac`, `crc32fast`), `uuid`, `x25519-dalek`.

Hand-roll only what has no crate or where the format *is* the product: the proxy header
codecs, the SS/VMess AEAD chunk framing, mkcp (reliable-UDP, no crate — keep deferred).

### P6 — Test protocols first, from the Go vectors (see §6)

Header/crypto codecs are pure functions over bytes and have golden vectors in the Go
`*_test.go` files. Port those vectors to `#[test]` **before** writing the decoder, then
make them pass. This is the highest-leverage correctness lever in the project.

### P7 — Never panic on the connection path

Inbound handlers parse **attacker-controlled bytes**; a panic there is a remote DoS (one
crafted header kills a worker task / aborts the process). Make malformed input return an
`Err`, never unwind:

- **No `unwrap`/`expect`/`panic!`/`unreachable!`/`todo!`** in library code. Enforce with
  lints at each crate root, so a slip is a build error, not a runtime crash:

  ```rust
  #![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic,
          clippy::unreachable, clippy::todo, clippy::unimplemented,
          clippy::indexing_slicing, clippy::arithmetic_side_effects)]
  ```
  (Tests may relax these locally with `#[allow(...)]`.) Propagate with `?` over a real
  error enum (`thiserror`); reserve `expect` for genuine start-up invariants only.
- **No unchecked indexing/slicing.** `buf[i]` and `buf[a..b]` panic out of bounds — and
  `b` is usually a length field the client chose. Use `buf.get(i)` / `buf.get(a..b)` /
  `split_at_checked` / `split_first` / `chunks` and handle the `None`. Validate every
  length prefix against remaining bytes *before* slicing.
- **No unchecked arithmetic on parsed values.** Length/offset/counter math on
  attacker-supplied numbers can overflow (debug panic) or wrap (silent corruption). Use
  `checked_add`/`checked_mul`/`checked_sub` (→ `Err` on overflow) or `saturating_*` where
  clamping is correct; division/modulo guard the zero divisor first.
- Prefer total APIs that can't panic: `try_into()` over `as`-truncation for sizes,
  `copy_from_slice` only after a length check, `bytes::Buf` getters (which the
  `BytesMut`/`Bytes` codecs already bounds-check) over manual indexing.

## 1. The runtime pipeline

Everything pivots on two traits and an in-memory duplex pipe (`Link`):

```mermaid
graph LR
  A[Transport Listener<br/>accept conn] --> B[Inbound.Process<br/>decode proto, auth user,<br/>learn target Destination]
  B -->|Dispatch dest -> Link| C[Dispatcher<br/>pipe pair + pick outbound]
  C --> D[Outbound.Process<br/>freedom: dial target]
  B -. copy conn<->Link.Writer/Reader .-> C
  D -. copy Link<->remote .-> C
```

**Two core traits** (`proxy/proxy.go` → Rust). Note the deltas from Go: the dispatcher is
**one concrete type** (pass `&Dispatcher`, no generic), and the dialer is a **generic
`D: Dialer`**, not `internet.Dialer` interface / `&dyn`:

```rust
trait InboundHandler {
    fn networks(&self) -> &[Network];
    async fn process(&self, ctx: &Ctx, net: Network, conn: Stream, disp: &Dispatcher)
        -> io::Result<()>;
}
trait OutboundHandler {
    async fn process<D: Dialer>(&self, ctx: &Ctx, link: Link, dialer: &D) -> io::Result<()>;
}
```

`Stream` and the `Inbound`/`Outbound`/`AnyDialer` sums are the enums from §P1.

**Per-connection lifecycle inside `process` (`InboundHandler`):**

1. set handshake read-deadline (default 60s, via `tokio::time::timeout` around the header
   read); read proxy header off `conn`
2. authenticate user via per-protocol validator → derive target `Destination`
   (validators hold an immutable `Arc<UserTable>`, §P2)
3. clear deadline; start idle timer (default 300s)
4. `link = dispatcher.dispatch(ctx, dest)` (async, returns immediately) **or** build the
   `Link` yourself and `dispatch_link(ctx, dest, link)` (blocks until outbound done)
5. run two copy loops — uplink `conn→link.writer`, downlink `link.reader→conn` — first
   error wins, close-writer-on-uplink-EOF (`tokio::try_join!` / `select!`).

The **Dispatcher** just makes a `pipe` pair (`Link{Reader,Writer}`), wires the inbound
half back to the caller, picks an outbound (default handler if no router), and calls
`Outbound::process`. The byte-pumping lives in the proxies, not the dispatcher.

## 2. Layer-by-layer: what to build

### 2a. Data plane (`kernel`) — MANDATORY, build first

| Go construct | Purpose | Rust equivalent |
|---|---|---|
| `buf.Buffer` (8 KiB pooled window) | recyclable byte chunk | `BytesMut` read window → `.split().freeze()` to `Bytes` for handoff (§P3) |
| `buf.Reader/Writer` (`ReadMultiBuffer`) | framed I/O spine | `tokio::io::AsyncRead/AsyncWrite` (collapse MultiBuffer → a single `Bytes` per chunk) |
| `buf.Copy` + `UpdateActivity` | the copy loop, resets idle timer per chunk, EOF→Ok | hand loop: `read → freeze → send`, `timer.reset()` per chunk |
| `transport.Link` + `transport/pipe` | in-proc duplex, backpressure, Close=EOF / Interrupt=abort | **bounded `tokio::sync::mpsc<Bytes>` pair**; drop sender = EOF; `CancellationToken` = interrupt |
| `signal.ActivityTimer` | idle timeout → cancel | `CancellationToken` + interval task, or `tokio::time::timeout` per read |
| `task.Run` / `OnSuccess` | run both directions, first-err-wins | `tokio::try_join!` / `select!` of two spawned copies |

**`Link` shape.** `struct Link { reader: mpsc::Receiver<Bytes>, writer: mpsc::Sender<Bytes> }`.
The bounded channel *is* the backpressure (Go's `pipe` limit = 512 KiB worth of buffers).
`Sender` dropped ⇒ `Receiver` yields `None` ⇒ clean EOF. Abort = `CancellationToken`
cancelled, raced via `select!` in both copy loops. No `RwLock`, no shared mutable state on
the data path (§P2).

Skip for v1: bytespool tiers, `readv`, the `splice(2)` zero-copy fast path +
`CanSpliceCopy` state machine (correct without it, just slower), `BufferedWriter`
coalescing.

### 2b. Core value types (`kernel`) — MANDATORY

```rust
struct Destination { addr: Address, port: u16, network: Network }
enum Address { Ip(IpAddr), Domain(CompactString) }   // §P4: not String
#[repr(u8)] enum Network { Unknown = 0, Tcp = 2, Udp = 3, Unix = 4 } // no value 1; matches proto
struct MemoryUser { account: Account, email: CompactString, level: u32 }
struct Uuid([u8; 16]);   // ParseString maps short (<=30-char) strings to a deterministic SHA1-derived UUID
```

- **The shared SOCKS-style address codec** (`common/protocol/address.go`) — implement
  once, parameterized; this single primitive covers all six protocols:
  - 1 type byte → IPv4 (4B) / IPv6 (16B) / Domain (1B len + N) ; port = 2B big-endian
  - **Family A (VLESS/VMess):** `1=IPv4, 2=Domain, 3=IPv6`, **port-first**
  - **Family B (Trojan/SS/SOCKS):** `1=IPv4, 3=Domain, 4=IPv6`, **addr-first** (SS masks type `&0x0F`)
  - Rust shape: `fn read_address(buf: &mut Bytes, fam: Family, order: Order) -> Result<(Address, u16)>`
    + the symmetric `write_address(buf: &mut BytesMut, ..)`. Parameterize family + order as
    small enums; **do not** fork six near-identical copies (§ compatibility note).
  - This is the first thing to test-drive: `address_test.go` is a table of
    `(options, input bytes, expected addr+port, error?)` — port it verbatim (§6).
- DNS: a shared `Arc<Resolver>` wrapping a `moka` cache (§P4) lives in `kernel`; `freedom`
  and any future router consume it. Resolver itself can wrap `hickory-resolver` (system +
  configured upstreams) — a crate, per §P5.

### 2c. Transports (`transport`) — registry + stacks

Registration model: a map `name → ListenFn` (or a `match` on the transport enum — §P1).
`ListenFn(addr, port, &StreamSettings, on_conn)` binds the socket, applies sockopts,
optionally wraps each accepted conn with TLS/REALITY at the **security seam**, then calls
`on_conn(conn)` where `conn: Stream`. `Stream` is the enum sum from §P1
(`AsyncRead + AsyncWrite + Unpin` + `local_addr`/`remote_addr`), **not** `Box<dyn Conn>`.

Priority for a first server:

| # | Transport | Effort | Notes |
|---|---|---|---|
| 1 | **`tcp`/raw** | trivial | default; raw bytes, optional header masquerade. **MANDATORY** |
| 2 | **`httpupgrade`** | cheap | read one HTTP/1.1 req → write `101` → raw passthrough (`hyper` for the parse) |
| 3 | **`websocket`** | medium | `tokio-tungstenite` frames, 1 binary msg/write; TLS at listener; early-data via `Sec-WebSocket-Protocol` |
| 4 | `grpc` / `mkcp` | high | grpc = full HTTP/2 bidi stream of `Hunk{bytes}` (`h2`/`tonic`); mkcp = reliable-UDP state machine (hand-rolled, no crate) |
| 5 | `splithttp`/XHTTP | highest | sessioned multi-request reassembly, h1/h2/h3 — defer; **h3 leg = `quinn` + `h3`, never hand-rolled QUIC** (§P5) |

Sockopts that matter server-side: `SO_REUSEADDR/REUSEPORT`, `IP_TRANSPARENT` (tproxy),
`TCP_FASTOPEN`, keepalive, `SO_MARK`, PROXY-protocol accept. Set them via `socket2` on the
raw fd before/after bind.

### 2d. Transport security (`transport`)

| Layer | Verdict | Rust |
|---|---|---|
| **Plain TLS server** | implement early | `tokio-rustls`: cert+key, ALPN (default `["h2","http/1.1"]`), min/max version. Skip client-verify paths. Wrapped conn becomes `Stream::Tls` (boxed, §P1). |
| **REALITY** | hard, defer | Not a TLS server — it's a MITM/steal proxy: dials the real `Dest`, mirrors ClientHello, hijacks only if SNI∈ServerNames + X25519/shortId/timestamp auth passes, else transparently relays. Needs a **custom TLS stack** (Go uses a `crypto/tls` fork); `rustls` alone can't do it. `x25519-dalek` for the key agreement. |
| **XTLS Vision** | optional, defer | proxy-layer wrapper over TLS (VLESS flow `xtls-rprx-vision`): sniffs inner TLS records, pads frames (cmd bytes `0x00/0x01/0x02`), switches to direct copy. Adds the `TrafficState` machinery (`proxy/proxy.go` `TrafficState`/`VisionReader`/`VisionWriter`). |

### 2e. Inbound protocols (`proxy`) — wire formats + priority

| # | Protocol | Crypto | Wire (request) |
|---|---|---|---|
| 1 | **Trojan** | none (TLS provides) | `56B hex(SHA224(pw))` + `CRLF` + `cmd(1)` + addr(famB) + `port(2)` + `CRLF` + payload. Auth = map lookup on the 56 bytes. UDP: `addr+port+len(2)+CRLF+payload`. |
| 2 | **VLESS** (`flow=none`) | none (TLS provides) | `ver(0)` + `uuid(16)` + `addons(1 len+bytes)` + `cmd(1)` + `port(2)`+`addrtype(1)`+addr (famA). Resp: `ver`+addons. UDP framed in-stream: 2B-len prefix per datagram. Auth = UUID map (bytes 6–7 zeroed = "vless route"). |
| 3 | **Shadowsocks** (AEAD) | self-contained | `salt(ivLen)` then AEAD chunk stream `[enc len][AEAD(payload)+tag]`. subkey=`HKDF-SHA1(master, salt, "ss-subkey")`; master=`EVP_BytesToKey(pw)`; nonce=LE counter from 0. First plaintext = addr(famB)+port. Ciphers: AES-128/256-GCM, (X)ChaCha20-Poly1305. Multi-user = trial-decrypt. |
| 4 | **SOCKS5** (+4/4a) | none | standard greeting/auth/CONNECT; UDP ASSOCIATE opens a UDP hub. Also speaks HTTP on the same port. |
| 5 | **HTTP** | none | CONNECT + plain-HTTP proxy, Basic auth, keep-alive (`hyper`). |
| 6 | **VMess** | full AEAD | **most complex, do last:** 16B authID → trial-decrypt to find user (crc + ±120s time window + replay DB), `OpenVMessAEADHeader` (KDF = nested HMAC-SHA256 over `cmdKey=MD5(uuid‖magic)`), 38B fixed header + addr + padding + FNV1a, then per-security body crypto + optional SHAKE128 chunk masking. UDP rides inside the AEAD stream. |
| — | **SS2022** | delegated | Go wraps sing-shadowsocks; treat as out-of-scope unless you reimplement the 2022 spec. |
| — | dokodemo | none | transparent/tproxy target; no proxy header — useful as a test sink. |

**Dispatch styles:** Trojan/SS/VMess use `Dispatch + two copy loops`;
VLESS/SOCKS-CONNECT/HTTP build the `Link` and use `DispatchLink`. UDP is either
framed-in-stream (VLESS/VMess) or per-packet codec via a UDP dispatcher (Trojan/SS/SOCKS).

Shared crypto building blocks to centralize (one module, reused across protocols):
AEAD chunked stream (SS + VMess body), `EVP_BytesToKey` + `HKDF-SHA1` (SS), VMess
`KDF`/`CreateAuthID`/cmdKey, FNV-1a. Each has Go test vectors — test-drive them (§6).

**Codec shape.** Per protocol, write a pure `Header` parse/encode pair operating on
`Bytes`/`BytesMut` with **no I/O** (mirror Go's `ConnReader.ParseHeader` /
`ConnWriter`), then a thin async wrapper that reads bytes off `Stream` into the parser.
The pure core is what the ported tests exercise.

### 2f. App glue (`kernel`)

- **Dispatcher** (MANDATORY): pipe pair, ensure session `Outbounds` chain + `Content`,
  optional sniffing, pick outbound (forced tag → router → default handler), call
  `outbound.process`. Holds `Arc<Config>` snapshot; selects from the `enum Outbound` set.
- **Inbound/Outbound managers + workers** (MANDATORY): a worker binds a TCP/UDP listener
  per port, clones the `Arc<Config>` snapshot (§P2), builds the session context, calls
  `inbound.process`. First outbound added = default.
- **Session context** (`Ctx`) carried through every connection (by `&` / `Arc`, immutable
  where possible): `Inbound{source,local,gateway,tag,user,timer}`,
  `Outbounds[]{target,...}`, `Content{protocol,attributes}`, session `ID`. Per-connection
  mutable bits (the timer's deadline) live behind their own cheap cell, not a global lock.
- **Router** (OPTIONAL — dispatcher tolerates `None` → everything to default outbound),
  **sniffer** (http/tls/quic detection, OPTIONAL — `tls/sniff`, `http/sniff`,
  `quic/sniff` have test vectors), **policy** (OPTIONAL — defaults: handshake 60s, idle
  300s, buffer 512 KiB), **stats** (OPTIONAL — `AtomicU64` counters, no lock).

## 3. Config & the DI registry → Rust

Go uses a 3-layer reflection DI: `TypedMessage{type:proto-FullName, value:bytes}` →
global proto registry → `reflect`-keyed creator map → lazy `RequireFeatures` callbacks.
**Collapse all of it** in Rust (this is exactly the "compatibility, not transliteration"
rule — none of the reflection machinery should survive):

- Decode config with **`prost`** (the `.proto` files are the source of truth) — or accept
  the JSON front-end (`infra/conf`, top-level
  `{log, routing, dns, inbounds, outbounds, policy}`) via `serde`.
- Replace the reflect map with **explicit `match` dispatch on the type-URL string**:
  `"xray.proxy.vless.inbound.Config" => decode + build Inbound::Vless(..)`. The result is
  one of the closed `enum Inbound` / `enum Outbound` variants (§P1) — no dynamic creator
  map, no `dyn`.
- Replace the dynamic `[]Feature` slice + lazy resolution with a **concrete typed runtime
  struct** wired explicitly, behind a single immutable `Arc<Config>` (§P2):

  ```rust
  struct Instance {
      config: Arc<Config>,          // immutable snapshot; swap to reload (§P2)
      dispatcher: Dispatcher,
      inbound_mgr: InboundManager,
      outbound_mgr: OutboundManager,
      dns: Arc<Resolver>,           // moka-cached (§P4)
      policy: Policy, stats: Stats,
  }
  ```
  Pass deps into constructors directly; no `RequireFeatures` callback graph.

- Keep a `trait Runnable { fn start(&self); fn close(&self); }` for lifecycle. Reload =
  build a fresh `Instance`, `start()` it, `close()`/drain the old (§P2 swap-and-drain).

`core.Config`:
`{ inbounds: [InboundHandlerConfig{tag, receiver_settings, proxy_settings}], outbounds: [...], app: [feature configs] }`.

## 4. Suggested crate layout (you have kernel/proxy/transport)

- **`kernel`** — data plane (`Bytes`/`Link`/pipe/copy), signal/timer, net value types +
  shared address codec, DNS resolver (`moka` cache), session ctx, `Instance`+config
  decode+`match` registry, dispatcher, inbound/outbound managers+workers, `freedom`
  outbound, (later) router/policy/stats.
- **`transport`** — listener registry, `Stream` enum + sockopts, tcp → httpupgrade →
  websocket → …, TLS (rustls), (later) REALITY, (later) QUIC via `quinn`.
- **`proxy`** — `InboundHandler` trait + `enum Inbound` + the shared crypto/codec helpers
  + per-protocol handlers.

**Rust deps:**

| Crate | Use |
|---|---|
| `tokio`, `tokio-util` | runtime, `CancellationToken`, codecs |
| `bytes` | `Bytes`/`BytesMut` (§P3) |
| `compact_str` | cheap `Address::Domain` (§P4) |
| `moka` | async DNS cache (§P4) |
| `arc-swap` | lock-free live `Arc<Config>` swap (§P2) |
| `tokio-rustls` / `rustls` | TLS server (§2d) |
| `prost` (+ `serde`/`serde_json`) | config decode (§3) |
| `aes-gcm`, `chacha20poly1305`, `hkdf`, `sha1`, `sha2`, `md-5`, `hmac`, `crc32fast` | protocol crypto (§2e) |
| `uuid` | VLESS/VMess IDs |
| `tokio-tungstenite` | websocket transport |
| `hyper` / `h2` | httpupgrade / grpc / http inbound |
| `hickory-resolver` | DNS lookups behind the cache |
| `socket2` | server sockopts (§2c) |
| `quinn` (+ `h3`) | QUIC/h3 for XHTTP (later, §P5) |
| `x25519-dalek` | REALITY (later) |
| `enum_dispatch` | optional, generate enum-sum delegation (§P1) |

## 5. Milestone path (each ships a working server)

1. **M1 — skeleton:** `kernel` data plane (`Bytes`/Link/copy/timer) + value types + session
   ctx + dispatcher + inbound/outbound managers + `freedom` outbound (with `moka` DNS
   cache) + raw `tcp` listener.
2. **M2 — first real proxy:** `socks` (and/or `dokodemo`) inbound over raw TCP — no
   crypto, end-to-end forwarding works. **Verify with `curl --socks5`.**
3. **M3 — TLS-fronted proxies:** rustls TLS listener + **Trojan** + **VLESS(none)**
   inbound. **Verify against a real xray client.**
4. **M4 — Shadowsocks** (AEAD chunk stack + key schedule) + UDP path.
5. **M5 — transports:** `websocket` + `httpupgrade`.
6. **M6+ — advanced (optional):** VMess, router+sniffer+policy, gRPC/XHTTP (h3 via
   `quinn`), REALITY, XTLS Vision, mux, splice fast path.

## 6. Testing strategy — port the Go vectors first (§P6)

The codec/crypto layer is pure and already has golden vectors in the reference. Port them
to Rust `#[test]` **before** implementing, then code to green. The Go tests double as a
spec: `writer → reader` round-trips plus exact byte tables.

| Rust target | Go source of truth | What it pins |
|---|---|---|
| shared address codec | `common/protocol/address_test.go` | family A/B byte order, port-first vs addr-first, error cases (the `(options, input, addr, port, error)` table) |
| `Uuid::parse_str` | `common/protocol/id_test.go` | 16-byte parse + SHA1 short-string derivation |
| time window | `common/protocol/time_test.go` | VMess ±120s timestamp gen/validate |
| Trojan header | `proxy/trojan/protocol_test.go` | `ConnWriter`→`ConnReader` TCP + `PacketWriter`/`PacketReader` UDP round-trip; 56B hash auth |
| VLESS encoding | `proxy/vless/encoding/encoding_test.go` | request/response header, addons, in-stream UDP framing |
| Shadowsocks | `proxy/shadowsocks/protocol_test.go`, `config_test.go` | AEAD chunk stream, salt/subkey schedule, multi-cipher |
| VMess AEAD | `proxy/vmess/aead/authid_test.go`, `aead/encrypt_test.go`, `encoding/encoding_test.go`, `validator_test.go` | authID create/match, AEAD header KDF, full header round-trip, user lookup/replay |
| sniffers | `common/protocol/tls/sniff_test.go`, `http/sniff_test.go`, `quic/sniff_test.go` | SNI/host/QUIC detection (when sniffer is built) |

**How to port (example — Trojan):** the Go test builds a `ConnWriter`, writes a payload to
an in-memory buffer, then reads it back with `ConnReader` and asserts `Target` and payload
match. In Rust this becomes a `BytesMut` round-trip with **no sockets**:

```rust
#[test]
fn trojan_tcp_roundtrip() {
    let user = MemoryUser::trojan("password");
    let dest = Destination::tcp(Address::Ip([127,0,0,1].into()), 1234);
    let mut buf = BytesMut::new();
    write_trojan_header(&mut buf, &user, &dest);
    buf.extend_from_slice(b"test string");

    let mut b = buf.freeze();                 // Bytes, read-only (§P3)
    let hdr = parse_trojan_header(&mut b, &user_table).unwrap();
    assert_eq!(hdr.dest, dest);
    assert_eq!(&b[..], b"test string");
}
```

Keep parse/encode **I/O-free** (operate on `Bytes`/`BytesMut`) so these tests stay pure
and fast; the async `Stream` wrapper is tested separately with an end-to-end loopback
(M2's `curl --socks5`, M3's real-client check). Add adversarial cases the Go table already
encodes — truncated input, wrong length byte, bad auth — and assert they error rather than
panic.

---

**Bottom line:** the minimum viable server is M1–M3: ~the data plane + dispatcher + one
direct outbound + a TLS listener + Trojan/VLESS-none (both are header-parse-only since TLS
carries the encryption). That's the smallest thing a real xray client can connect through.
Everything else (VMess crypto, REALITY, exotic transports, routing) is incremental and
independently shippable. Throughout: static enums over `dyn` (§P1), immutable `Arc`
snapshots over locks (§P2), `Bytes` over copies (§P3), cached cheap domains (§P4),
crates over hand-rolled lower layers (§P5), Go vectors as the test oracle (§P6), and
never a panic on attacker-controlled bytes (§P7).
