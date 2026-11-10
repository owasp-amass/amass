# MCP investigation tools

Both MCP servers (`amass ai mcp` over stdio and `amass-ai-mcp-http`) list two
tools next to the read-only graph tools. They let an MCP client, which is
itself the model, use the answer kinds and the evidence checks directly.

## investigate

Runs a structured question and returns the computed answer with numbered
evidence. Arguments:

| Field | Meaning |
| --- | --- |
| `subject` | The starting asset: an indexed selector (`{"type":"FQDN","field":"name","value":"example.com"}`) or an Organization name |
| `answer` | `hierarchy`, `controlled`, `third_party`, `table`, `route` or `paths` |
| `target_types` | Asset types to list; a table's single row type; a route's last hop type |
| `columns` | Table columns: `{"type":"IPAddress","role":""}`, `{"type":"Organization","role":"controller"}` |
| `hops` | Route hops: `{"direction","label","relation_type","destination_type"}`, up to 3 |
| `purpose` | `connected` (default) or `ultimate_parent` for paths |

The tool description, the answer enum and the controllable row types are
generated from the OAM catalog, the answer-kind registry and the semantics
table. `paths` needs a model configured on the Amass side; every other kind
runs without one.

The result holds `investigation_id`, the query description, the answer
kind, the computed answer, `evidence` (`E1: FQDN www.example.com
--dns_record--> IPAddress 192.0.2.1 (sources: ...)`, up to 200 items),
`incomplete`, and the structured vendors or table rows.

## verify_citations

`{"investigation_id": "...", "text": "..."}` checks the client's prose
against that investigation's evidence with the same rules as `-narrate`
(see `CITATIONS.md`) and returns `verified`, `problems` and the cited
items. The last 64 investigations are kept in memory.

## Example

```json
{"name": "investigate", "arguments": {
  "subject": {"type": "Organization", "name": "Colgate University"},
  "answer": "table", "target_types": ["URL"],
  "columns": [{"type": "IPAddress", "role": ""}, {"type": "Organization", "role": "controller"}]}}
```

The client writes its summary citing `[E#]` items and calls
`verify_citations` before presenting it.

## Transport

Both servers use the official MCP Go SDK
(`github.com/modelcontextprotocol/go-sdk`). The HTTP server keeps Amass's
own checks in front of the SDK's Streamable HTTP handler: a bearer token,
local browser origins only, a 1 MiB request limit, JSON responses (no
server-sent event stream), and idle-session expiry with a session cap.
Only sessions Amass admitted reach the SDK, and expired or evicted
sessions are closed in the SDK too. Session IDs are 192 random bits.
