# Active Proxy Egress — Operator Guide

This document describes the `active_proxy` feature introduced in the
`feature/active-proxy-egress` branch. It covers usage via the `docker compose`
CLI workflow, direct manipulation of the engine REST API, and the network
configuration required to support both egress paths.

---

## Background

Amass distinguishes between two categories of traffic:

- **Passive traffic** — queries to third-party OSINT sources (crt.sh, Censys,
  VirusTotal, RDAP, etc.). This traffic never touches target infrastructure
  directly and is not detectable by the target organisation.

- **Active traffic** — connections made directly to target assets (IP addresses
  or FQDNs). This includes HTTP service probes, JARM TLS fingerprinting, and
  PTR/reverse DNS lookups. This traffic **is** detectable by the target and
  will trigger honeypot alerts, IDS rules, and access logs.

The `active_proxy` feature routes all active traffic through an
operator-specified proxy, while leaving passive OSINT traffic on the engine's
default network path. This allows:

- Monitoring and logging of all detectable reconnaissance traffic at the proxy.
- Egress segregation in enterprise environments where active and passive traffic
  must exit through different network paths.
- Fail-closed enforcement: if no proxy is configured and active mode is
  requested, the engine refuses to start rather than silently leaking active
  traffic through the default network.

---

## Configuration Reference

| Parameter | CLI flag | YAML key | JSON field | Type | Default |
|---|---|---|---|---|---|
| Enable active mode | `-active` | `active: true` | `"active": true` | bool | false |
| Active proxy URL | `-active-proxy <url>` | `active_proxy: <url>` | `"active_proxy": "<url>"` | string | `""` |
| Fail-closed policy | `-active-strict=<bool>` | `active_strict: <bool>` | `"active_strict": <bool>` | bool | **true** |
| Active DNS resolver | *(YAML/JSON only)* | `active_dns_resolver: <host:port>` | `"active_dns_resolver": "<host:port>"` | string | `1.1.1.1:53` |

### Supported proxy schemes

| Scheme | Description |
|---|---|
| `http://` | HTTP proxy using CONNECT tunnelling for raw TCP, plain forwarding for HTTP |
| `https://` | HTTP proxy over TLS |
| `socks5://` | SOCKS5 proxy; hostname resolution performed by the client |
| `socks5h://` | SOCKS5 proxy; hostname resolution delegated to the proxy |

### `active_strict` behaviour

`active_strict` defaults to `true`. With this default in effect:

- Running with `-active` and no `-active-proxy` is a hard error — the engine
  refuses to start and prints an actionable error message.
- This applies whether the session is started via the CLI or the engine REST
  API. An API payload that omits `active_strict` is treated as if it sent
  `"active_strict": true`.

To allow active traffic to exit through the engine's default network (the
legacy behaviour, not recommended), explicitly pass `-active-strict=false` on
the CLI or `"active_strict": false` in the API payload.

---

## Usage: docker compose CLI workflow

This is the recommended way to run Amass in production. The `enum` container
parses CLI arguments, builds a session configuration, and posts it to the
`engine` container's REST API. The engine then performs all reconnaissance.

### Basic invocation

```bash
docker compose run --rm enum \
  -d example.com \
  -active \
  -active-proxy socks5h://proxy.internal:1080 \
  -p 80,443,8080,8443
```

All active traffic (HTTP probes on the specified ports, JARM fingerprinting,
reverse DNS) will exit through `socks5h://proxy.internal:1080`. Passive OSINT
traffic continues to use the engine container's default network.

### With proxy authentication

```bash
docker compose run --rm enum \
  -d example.com \
  -active \
  -active-proxy socks5h://user:password@proxy.internal:1080
```

### With a custom active DNS resolver

By default, active-derived DNS queries (PTR lookups for discovered IPs) go to
`1.1.1.1:53` over the active proxy. To use your own resolver instead — for
example, an internal resolver that is reachable through the proxy:

```yaml
# In your amass config YAML, under options:
options:
  active_proxy: "socks5h://proxy.internal:1080"
  active_dns_resolver: "10.10.0.53:53"
```

### Opting out of strict mode (not recommended)

If you explicitly want active traffic to exit the engine's default network
without a proxy:

```bash
docker compose run --rm enum \
  -d example.com \
  -active \
  -active-strict=false
```

This produces a warning and proceeds. Use only in controlled lab environments.

### Verifying proxy enforcement

To confirm active traffic is being routed correctly, you can observe the proxy
logs during a run. If the proxy receives no connections while `-active` is set
and targets are being probed, something is misconfigured. The engine log will
emit `WARN` messages for any active operation that was skipped due to a missing
or unreachable egress profile.

---

## Usage: direct engine REST API

Operators who run the engine as a long-lived service and post session
configurations directly to its API must include the active egress fields in
their JSON payload. The engine applies the same validation and fail-closed
enforcement as the CLI.

### Endpoint

```
POST /api/v1/sessions
Content-Type: application/json
```

### Full payload example

```json
{
  "seed": {},
  "scope": {
    "domains": ["example.com"],
    "ports": [80, 443, 8080, 8443]
  },
  "active": true,
  "active_proxy": "socks5h://proxy.internal:1080",
  "active_strict": true,
  "active_dns_resolver": "10.10.0.53:53"
}
```

A successful response returns HTTP `201 Created` with a session token:

```json
{ "sessionToken": "<uuid>" }
```

### Policy violation response

If `active` is `true`, `active_proxy` is absent or empty, and `active_strict`
is `true` (or omitted, since `true` is the default), the engine rejects the
request:

```
HTTP/1.1 400 Bad Request
Content-Type: application/json

{
  "error": "invalid configuration: active mode is enabled but no active_proxy
            is configured: set active_proxy in the payload, or pass
            active_strict: false to allow active traffic over the default
            egress (not recommended)"
}
```

### Explicitly disabling strict mode via API

```json
{
  "scope": { "domains": ["example.com"], "ports": [80, 443] },
  "active": true,
  "active_strict": false
}
```

**Important:** A payload that omits `active_strict` entirely is treated as
`true`, not `false`. You must explicitly send `"active_strict": false` to opt
out. This is intentional — it prevents a misconfigured or minimal payload from
silently weakening egress controls.

### What active egress covers

The following traffic types are routed through `active_proxy` when set:

| Traffic type | Routed through active proxy |
|---|---|
| HTTP/HTTPS service probes (all configured ports) | ✅ Yes |
| JARM TLS fingerprinting | ✅ Yes |
| PTR / reverse DNS lookups for discovered IPs | ✅ Yes |
| Passive OSINT (crt.sh, Censys, VirusTotal, etc.) | ❌ No — default egress |
| Forward DNS resolution | ❌ No — public resolvers, default egress |
| Zone transfers | ❌ No — goes to authoritative nameservers, default egress |

---

## Network Setup Requirements

This section describes the network architecture required for the engine
container to reach both egress paths correctly.

### Overview

The engine container requires **two independent network paths**:

```
                        ┌─────────────────────────────────┐
                        │         Engine Container         │
                        │                                  │
                        │  Passive OSINT clients ──────────┼──► Default gateway
                        │  (General, Crawl HTTP clients)   │    (Internet)
                        │                                  │
                        │  Active egress clients ──────────┼──► Active proxy
                        │  (HTTP probes, JARM, PTR DNS)    │    │
                        └─────────────────────────────────┘    │
                                                                ▼
                                                       Proxy server
                                                                │
                                                                ▼
                                                       Target infrastructure
                                                       (FQDNs, IPs being scanned)
```

### Requirement 1: Default Internet access

The engine container must be able to reach the public Internet for passive
OSINT queries. These are standard HTTPS connections to third-party APIs and
data sources. A typical Docker bridge network with NAT provides this.

Required outbound access:

- TCP 443 to arbitrary public IP addresses (OSINT APIs)
- TCP 53 / UDP 53 to public DNS resolvers (1.1.1.1, 8.8.8.8, etc.) for
  general name resolution

No special routing is required for this path — it is the engine container's
default network behaviour.

### Requirement 2: Active proxy reachability

The engine container must be able to reach the active proxy server. The proxy
URL specified in `-active-proxy` is dialled by the engine, not the enum
container. This means:

- The **engine container's network** must have a route to the proxy host and
  port.
- The **enum container** only passes the proxy URL string to the engine via the
  API — it does not itself use the proxy.

If the proxy is on a separate network segment (e.g. a dedicated egress VLAN),
the engine container must be attached to that network. The enum container does
not need to be.

### Requirement 3: Proxy server egress to target infrastructure

The proxy server itself must be able to reach the target FQDNs and IPs being
scanned. Configure the proxy's egress and firewall rules accordingly. The
engine's active clients will tunnel all target connections through the proxy
using CONNECT (for HTTP/HTTPS proxies) or SOCKS5 (for socks5/socks5h proxies).

### docker compose network configuration

A typical production setup uses two Docker networks:

```yaml
# docker-compose.yml (relevant excerpt)

networks:
  osint_net:
    # Standard bridge network with Internet access for passive OSINT.
    driver: bridge

  active_net:
    # Network that has a route to the active proxy.
    # Could be a macvlan, an overlay, or a bridge with specific routing rules.
    driver: bridge
    ipam:
      config:
        - subnet: 10.10.1.0/24

services:
  engine:
    networks:
      - osint_net    # passive OSINT traffic exits here
      - active_net   # route to the active proxy exits here

  enum:
    networks:
      - osint_net    # only needs to reach the engine API
    depends_on:
      - engine
```

The active proxy itself may be:

- A containerised proxy (e.g. Dante for SOCKS5, Squid for HTTP CONNECT) on
  `active_net`
- An external proxy reachable via a gateway on `active_net`
- A VPN exit node that the engine container connects to before dialling targets

### DNS for active traffic

Active-derived PTR lookups are sent over the active proxy as TCP DNS to the
resolver specified in `active_dns_resolver` (default `1.1.1.1:53`). This
resolver must be reachable **through the proxy**, not directly from the engine
container. If `1.1.1.1` is not reachable through your proxy, set
`active_dns_resolver` to a resolver that is — for example, an internal resolver
on the same network segment as the proxy's egress.

### Firewall / egress filtering recommendations

| Source | Destination | Protocol | Purpose | Allow? |
|---|---|---|---|---|
| Engine container | OSINT APIs (public Internet) | TCP 443 | Passive data sources | ✅ Yes |
| Engine container | Public DNS resolvers | TCP/UDP 53 | Forward name resolution | ✅ Yes |
| Engine container | Active proxy host:port | TCP | Active egress tunnel | ✅ Yes |
| Engine container | Target IPs/FQDNs directly | TCP any | Active probes (bypassing proxy) | ❌ Block |
| Active proxy | Target IPs/FQDNs | TCP 80/443/custom | Proxied active probes | ✅ Yes |

Blocking direct engine-to-target connections at the firewall level provides a
defence-in-depth guarantee: even if a bug caused an active operation to bypass
the proxy client, the connection would be dropped at the network layer.

---

## Troubleshooting

**Session creation fails with "active mode is enabled but no active_proxy is configured"**

You passed `-active` without `-active-proxy`. Either add `-active-proxy <url>`
or pass `-active-strict=false` to opt out of fail-closed enforcement.

**Active proxy URL rejected at startup**

The URL must include a scheme (`http://`, `https://`, `socks5://`, or
`socks5h://`) and a `host:port`. Bare addresses like `127.0.0.1:1080` are
rejected. Use `socks5://127.0.0.1:1080`.

**Engine log shows "skipping active IP sweep: no active egress configured"**

The session was created with `active_strict: false` and no proxy was provided.
Active sweep operations are being silently skipped. This is the documented
soft-default behaviour. Provide a proxy URL to enable full active enumeration.

**Engine log shows WARN messages but active probes are still running**

Active probes use `Clients().Active` — if this is non-nil (i.e. a proxy was
successfully configured) probes will run regardless of WARN messages from other
subsystems. Check that the proxy is reachable and examine its own logs to
confirm connections are arriving.

**Proxy is reachable from the enum container but not the engine container**

The proxy URL is used by the engine container, not the enum container. Verify
that the engine container's network has a route to the proxy host and port —
not just the enum container's network.
