# Direct Engine API: Active Egress Settings

Operators who run the Amass engine as a long-lived service (for example, in a
container separate from the `enum` CLI) interact with it directly over its HTTP
API. The session configuration that the CLI normally builds locally must be
posted as JSON to `POST /api/v1/sessions`. This document describes the active
egress fields that JSON payload may include.

Passive traffic (data-source clients, default DNS, general crawl) is not
affected by these fields and continues to use the engine's existing networking
behavior. The active egress settings only govern the traffic produced by
`-active` enumeration: HTTP probes, raw TLS/JARM dials and active-derived DNS.

## Fields

| Field                  | Type    | Default | Purpose                                                                                       |
|------------------------|---------|---------|-----------------------------------------------------------------------------------------------|
| `active`               | bool    | false   | Enables active enumeration in the session.                                                    |
| `active_proxy`         | string  | `""`    | Upstream proxy URL through which all active traffic must egress. Supported schemes: `http`, `https`, `socks5`, `socks5h`. |
| `active_strict`        | bool    | true    | Fail-closed policy. When true and `active=true`, session creation is refused if no `active_proxy` is configured. |
| `active_dns_resolver`  | string  | `""`    | `host:port` resolver used for active-derived DNS over the active egress. Empty = engine default. TCP only. |

### `active_strict` semantics for API callers

`active_strict` defaults to `true` to match the CLI's fail-closed posture.
A payload that omits the field is treated as if the caller sent
`"active_strict": true`. To allow active traffic to leave the default
network (legacy behavior), an API caller must explicitly send
`"active_strict": false`.

This default applies after `json.Unmarshal` via a custom unmarshaler so that
direct API operation does not silently weaken what enterprise egress
segregation policies expect from the CLI.

### Validation

Before a session is created, the engine API runs the same `CheckSettings`
validation the CLI uses:

- If `active=true` and `active_proxy` is set, the URL is validated for
  scheme/host correctness.
- If `active=true`, `active_proxy` is empty, and `active_strict=true`
  (the default), session creation is rejected with HTTP `400` and an error
  mentioning `active_proxy`.

## Minimal example payload fragment

```json
{
  "scope": {
    "domains": ["example.com"],
    "ports": [80, 443]
  },
  "active": true,
  "active_proxy": "socks5h://10.0.0.1:1080",
  "active_strict": true,
  "active_dns_resolver": "10.0.0.1:53"
}
```

POST this JSON to `/api/v1/sessions`. A `201 Created` response carries the new
session token:

```json
{ "sessionToken": "<uuid>" }
```

If the active egress policy is violated (for example, `active=true` with no
`active_proxy` and strict mode left at its default), the API responds:

```
HTTP/1.1 400 Bad Request
Content-Type: application/json

{ "error": "invalid configuration: active mode is enabled but no active_proxy is configured: ..." }
```

## Disabling strict mode explicitly

API callers who deliberately want the legacy behavior of routing active
traffic over the engine's default egress must opt in:

```json
{
  "active": true,
  "active_strict": false
}
```

Without this explicit override, the engine will refuse to create the
session.

## What this does NOT change

- Passive enumeration traffic, data-source HTTP clients and default DNS
  resolvers continue to use the engine's existing network behavior.
- The CLI flag and YAML form (`-active-proxy`, `active_proxy:` etc.) still
  work for CLI operators and are unchanged.
- The fields above accept the same values whether they reach the engine
  via YAML (CLI) or JSON (direct API).
