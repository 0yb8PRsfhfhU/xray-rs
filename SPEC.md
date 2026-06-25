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

---

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

**Two core traits** (`proxy/proxy.go`):

```
Inbound  { fn networks() -> &[Network];
           async fn process(ctx, net: Network, conn: Connection, disp: &Dispatcher) }
Outbound { async fn process(ctx, link: Link, dialer: &dyn Dialer) }
```

**Per-connection lifecycle inside `Inbound::process`:**

1. set handshake read-deadline (default 60s); read proxy header off `conn`
2. authenticate user via per-protocol validator → derive target `Destination`
3. clear deadline; start idle timer (default 300s)
4. `link = dispatcher.dispatch(ctx, dest)` (async, returns immediately) **or** build the
   `Link` yourself and `dispatch_link(ctx, dest, link)` (blocks until outbound done)
5. run two copy loops — uplink `conn→link.writer`, downlink `link.reader→conn` — first
   error wins, close-writer-on-uplink-EOF (`task.Run` + `OnSuccess`).

The **Dispatcher** just makes a `pipe` pair (`Link{Reader,Writer}`), wires the inbound
half back to the caller, picks an outbound (default handler if no router), and calls
`Outbound::process`. The byte-pumping lives in the proxies, not the dispatcher.

---

## 2. Layer-by-layer: what to build

### 2a. Data plane (`kernel`) — MANDATORY, build first

| Go construct | Purpose | Rust equivalent |
|---|---|---|
| `buf.Buffer` (8 KiB pooled window) | recyclable byte chunk | `bytes::BytesMut` / pooled `Vec<u8>` |
| `buf.Reader/Writer` (`ReadMultiBuffer`) | framed I/O spine | `tokio::io::AsyncRead/AsyncWrite` (collapse MultiBuffer → just `BytesMut`) |
| `buf.Copy` + `UpdateActivity` | the copy loop, resets idle timer per chunk, EOF→Ok | hand loop or `tokio::io::copy` + per-chunk `timer.reset()` |
| `transport.Link` + `transport/pipe` | in-proc duplex, backpressure, Close=EOF / Interrupt=abort | **`tokio::sync::mpsc` bounded pair**; drop sender = EOF; `CancellationToken` = interrupt |
| `signal.ActivityTimer` | idle timeout → cancel | `CancellationToken` + interval task, or `tokio::time::timeout` per read |
| `task.Run` / `OnSuccess` | run both directions, first-err-wins | `tokio::try_join!` / `select!` of two spawned copies |

Skip for v1: bytespool tiers, `readv`, the `splice(2)` zero-copy fast path +
`CanSpliceCopy` state machine (correct without it, just slower), `BufferedWriter`
coalescing.

### 2b. Core value types (`kernel`) — MANDATORY

- `Destination { addr: Address, port: u16, network: Network }`
- `Address = enum { Ip(IpAddr), Domain(String) }`
- `Network = enum { Unknown=0, TCP=2, UDP=3, UNIX=4 }` (note: no value 1; matches proto)
- `MemoryUser { account, email, level }`
- `UUID([u8;16])` — `ParseString` also maps short (<=30-char) strings to a deterministic
  SHA1-derived UUID.
- **The shared SOCKS-style address codec** (`common/protocol/address.go`) — implement
  once, parameterized:
  - 1 type byte → IPv4 (4B) / IPv6 (16B) / Domain (1B len + N) ; port = 2B big-endian
  - **Family A (VLESS/VMess):** `1=IPv4, 2=Domain, 3=IPv6`, **port-first**
  - **Family B (Trojan/SS/SOCKS):** `1=IPv4, 3=Domain, 4=IPv6`, **addr-first** (SS masks type `&0x0F`)
  - This single primitive covers all six protocols.

### 2c. Transports (`transport`) — registry + stacks

Registration model: a map `name → ListenFunc`. `ListenFunc(addr, port, &StreamSettings,
on_conn)` binds the socket, applies sockopts, optionally wraps each accepted conn with
TLS/REALITY at the **security seam**, then calls `on_conn(conn)`.
`Connection = AsyncRead + AsyncWrite + Unpin + {local_addr, remote_addr}`.

Priority for a first server:

| # | Transport | Effort | Notes |
|---|---|---|---|
| 1 | **`tcp`/raw** | trivial | default; raw bytes, optional header masquerade. **MANDATORY** |
| 2 | **`httpupgrade`** | cheap | read one HTTP/1.1 req → write `101` → raw passthrough |
| 3 | **`websocket`** | medium | gorilla-style frames, 1 binary msg/write; TLS at listener; early-data via `Sec-WebSocket-Protocol` |
| 4 | `grpc` / `mkcp` | high | grpc = full HTTP/2 bidi stream of `Hunk{bytes}`; mkcp = reliable-UDP state machine |
| 5 | `splithttp`/XHTTP | highest | sessioned multi-request reassembly, h1/h2/h3 — defer |

Sockopts that matter server-side: `SO_REUSEADDR/REUSEPORT`, `IP_TRANSPARENT` (tproxy),
`TCP_FASTOPEN`, keepalive, `SO_MARK`, PROXY-protocol accept.

### 2d. Transport security (`transport`)

| Layer | Verdict | Rust |
|---|---|---|
| **Plain TLS server** | implement early | `tokio-rustls`: cert+key, ALPN (default `["h2","http/1.1"]`), min/max version. Skip client-verify paths. |
| **REALITY** | hard, defer | Not a TLS server — it's a MITM/steal proxy: dials the real `Dest`, mirrors ClientHello, hijacks only if SNI∈ServerNames + X25519/shortId/timestamp auth passes, else transparently relays. Needs a **custom TLS stack** (Go uses a `crypto/tls` fork); `rustls` alone can't do it. |
| **XTLS Vision** | optional, defer | proxy-layer wrapper over TLS (VLESS flow `xtls-rprx-vision`): sniffs inner TLS records, pads frames (cmd bytes `0x00/0x01/0x02`), switches to direct copy. Adds the `TrafficState` machinery. |

### 2e. Inbound protocols (`proxy`) — wire formats + priority

| # | Protocol | Crypto | Wire (request) |
|---|---|---|---|
| 1 | **Trojan** | none (TLS provides) | `56B hex(SHA224(pw))` + `CRLF` + `cmd(1)` + addr(famB) + `port(2)` + `CRLF` + payload. Auth = map lookup on the 56 bytes. UDP: `addr+port+len(2)+CRLF+payload`. |
| 2 | **VLESS** (`flow=none`) | none (TLS provides) | `ver(0)` + `uuid(16)` + `addons(1 len+bytes)` + `cmd(1)` + `port(2)`+`addrtype(1)`+addr (famA). Resp: `ver`+addons. UDP framed in-stream: 2B-len prefix per datagram. Auth = UUID map (bytes 6–7 zeroed = "vless route"). |
| 3 | **Shadowsocks** (AEAD) | self-contained | `salt(ivLen)` then AEAD chunk stream `[enc len][AEAD(payload)+tag]`. subkey=`HKDF-SHA1(master, salt, "ss-subkey")`; master=`EVP_BytesToKey(pw)`; nonce=LE counter from 0. First plaintext = addr(famB)+port. Ciphers: AES-128/256-GCM, (X)ChaCha20-Poly1305. Multi-user = trial-decrypt. |
| 4 | **SOCKS5** (+4/4a) | none | standard greeting/auth/CONNECT; UDP ASSOCIATE opens a UDP hub. Also speaks HTTP on the same port. |
| 5 | **HTTP** | none | CONNECT + plain-HTTP proxy, Basic auth, keep-alive. |
| 6 | **VMess** | full AEAD | **most complex, do last:** 16B authID → trial-decrypt to find user (crc + ±120s time window + replay DB), `OpenVMessAEADHeader` (KDF = nested HMAC-SHA256 over `cmdKey=MD5(uuid‖magic)`), 38B fixed header + addr + padding + FNV1a, then per-security body crypto + optional SHAKE128 chunk masking. UDP rides inside the AEAD stream. |
| — | **SS2022** | delegated | Go wraps sing-shadowsocks; treat as out-of-scope unless you reimplement the 2022 spec. |
| — | dokodemo | none | transparent/tproxy target; no proxy header — useful as a test sink. |

**Dispatch styles:** Trojan/SS/VMess use `Dispatch + two copy loops`;
VLESS/SOCKS-CONNECT/HTTP build the `Link` and use `DispatchLink`. UDP is either
framed-in-stream (VLESS/VMess) or per-packet codec via a UDP dispatcher (Trojan/SS/SOCKS).

Shared crypto building blocks to centralize: AEAD chunked stream (SS + VMess body),
`EVP_BytesToKey` + `HKDF-SHA1` (SS), VMess `KDF`/`CreateAuthID`/cmdKey, FNV-1a.

### 2f. App glue (`kernel`)

- **Dispatcher** (MANDATORY): pipe pair, ensure session `Outbounds` chain + `Content`,
  optional sniffing, pick outbound (forced tag → router → default handler), call
  `outbound.dispatch`.
- **Inbound/Outbound managers + workers** (MANDATORY): a worker binds a TCP/UDP listener
  per port, builds the session context, calls `inbound.process`. First outbound added =
  default.
- **Session context** carried through every connection:
  `Inbound{source,local,gateway,tag,user,conn,timer}`, `Outbounds[]{target,...}`,
  `Content{protocol,attributes}`, session `ID`.
- **Router** (OPTIONAL — dispatcher tolerates `None` → everything to default outbound),
  **sniffer** (http/tls/quic detection, OPTIONAL), **policy** (OPTIONAL — defaults:
  handshake 60s, idle 300s, buffer 512 KiB), **stats** (OPTIONAL).

---

## 3. Config & the DI registry → Rust

Go uses a 3-layer reflection DI: `TypedMessage{type:proto-FullName, value:bytes}` →
global proto registry → `reflect`-keyed creator map → lazy `RequireFeatures` callbacks.
**Collapse all of it** in Rust:

- Decode config with **`prost`** (the `.proto` files are the source of truth) — or accept
  the JSON front-end (`infra/conf`, top-level
  `{log, routing, dns, inbounds, outbounds, policy}`) via `serde`.
- Replace the reflect map with **explicit enum/`match` dispatch on the type-URL string**:
  `"xray.proxy.vless.inbound.Config" => decode + build handler`.
- Replace the dynamic `[]Feature` slice + lazy resolution with a **concrete typed runtime
  struct** wired explicitly:

  ```
  struct Instance { dispatcher, inbound_mgr, outbound_mgr,
                    dns, policy, stats }  // pass deps into constructors directly
  ```

- Keep a `trait Runnable { start; close }` for lifecycle.

`core.Config`:
`{ inbounds: [InboundHandlerConfig{tag, receiver_settings, proxy_settings}], outbounds: [...], app: [feature configs] }`.

---

## 4. Suggested crate layout (you have kernel/proxy/transport)

- **`kernel`** — buf/Link/pipe/copy, signal/timer, net value types, session ctx,
  `Instance`+config decode+registry, dispatcher, inbound/outbound managers+workers,
  `freedom` outbound, (later) router/policy/stats.
- **`transport`** — listener registry, `Connection` trait, tcp → httpupgrade →
  websocket → …, TLS (rustls), (later) REALITY.
- **`proxy`** — `Inbound` trait + the shared address codec + per-protocol handlers,
  AEAD/KDF crypto helpers.

Rust deps: `tokio`, `bytes`, `tokio-rustls`/`rustls`, `prost` (+`serde`/`serde_json` for
JSON config), RustCrypto (`aes-gcm`, `chacha20poly1305`, `hkdf`, `sha1`, `sha2`, `md-5`,
`hmac`, `crc32fast`), `uuid`, `tokio-tungstenite` (ws), `hyper`/`h2` (grpc/xhttp),
`x25519-dalek` (later, REALITY).

---

## 5. Milestone path (each ships a working server)

1. **M1 — skeleton:** `kernel` data plane (buf/Link/copy/timer) + value types + session
   ctx + dispatcher + inbound/outbound managers + `freedom` outbound + raw `tcp` listener.
2. **M2 — first real proxy:** `socks` (and/or `dokodemo`) inbound over raw TCP — no
   crypto, end-to-end forwarding works. **Verify with `curl --socks5`.**
3. **M3 — TLS-fronted proxies:** rustls TLS listener + **Trojan** + **VLESS(none)**
   inbound. **Verify against a real xray client.**
4. **M4 — Shadowsocks** (AEAD chunk stack + key schedule) + UDP path.
5. **M5 — transports:** `websocket` + `httpupgrade`.
6. **M6+ — advanced (optional):** VMess, router+sniffer+policy, gRPC/XHTTP, REALITY,
   XTLS Vision, mux, splice fast path.

---

**Bottom line:** the minimum viable server is M1–M3: ~the data plane + dispatcher + one
direct outbound + a TLS listener + Trojan/VLESS-none (both are header-parse-only since TLS
carries the encryption). That's the smallest thing a real xray client can connect through.
Everything else (VMess crypto, REALITY, exotic transports, routing) is incremental and
independently shippable.
