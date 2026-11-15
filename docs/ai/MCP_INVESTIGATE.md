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
| `answer` | `hierarchy`, `controlled`, `third_party`, `table`, `ownership_gaps`, `family`, `org_group`, `services`, `network`, `dangling_dns`, `changes`, `certificates`, `domains`, `email`, `exposure`, `concentration`, `coverage`, `geography`, `group_vendors`, `route` or `paths` |
| `target_types` | Asset types to list; a table's single row type; a route's last hop type |
| `columns` | Table columns: `{"type":"IPAddress","role":""}`, `{"type":"Organization","role":"controller"}` |
| `hops` | Route hops: `{"direction","label","relation_type","destination_type"}`, up to 3 |
| `purpose` | `connected` (default) or `ultimate_parent` for paths |
| `max_assets` | Assets a lens may read (default 2,000, up to 50,000); a larger footprint is sampled across kinds of asset and the answer is marked incomplete |

The tool description, the answer enum and the controllable row types are
generated from the OAM catalog, the answer-kind registry and the semantics
table. `paths` needs a model configured on the Amass side; every other kind
runs without one.

The result holds `investigation_id`, the query description, the answer
kind, the computed answer, `evidence` (`E1: FQDN www.example.com
--dns_record--> IPAddress 192.0.2.1 (sources: ...)`, up to 200 items),
`incomplete`, and the structured vendors, family members, group members or table rows.

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

## Instructions and prompts

At connection both servers send instructions that tell the assistant what
the database holds, to prefer `investigate`, to cite evidence and verify its
prose, and that nothing is written or collected. With the catalog loaded
they also offer one prompt per answer kind answered from a subject alone
(`amass_exposure`, `amass_email`, `amass_family`, ...; generated from the
answer-kind registry, so a new subject lens gets a prompt), and
`amass_attack_surface_overview`, which asks for several kinds at once.
Each takes one `subject` argument, a domain or an organization's name, and
expands into the investigate calls to make. Clients that show MCP prompts
as commands (Claude Code, VS Code, Gemini CLI and others) list them by
name.

## visualize

`{"subject": "example.com"}` (or an organization's name) draws what the
subject controls, from the controlled-assets lens: a Mermaid diagram of
asset types with counts and the relations between them, every asset as
well when there are at most 40, and, from the HTTP server when
`AMASS_AI_MCP_PUBLIC_URL` is set, a link to an interactive D3 graph and a
GEXF file for Gephi (valid for an hour, served on localhost). Drawings
cover up to 3,000 assets.

## Operator mode

A server started with an operator configuration also offers tools that act:

| Tool | What it does |
| --- | --- |
| `plan_enumeration` | Shows what enumerating one exact target (domain, IP, CIDR or AS number) would do, passive or active: scope, methods, effects and the `plan_id`. Starts nothing. |
| `start_enumeration` | Starts the planned enumeration after the user approves it. |
| `enumeration_status` | Lists runs, or shows one with its progress and, once finished, what the changes lens finds since it started. |
| `stop_enumeration` | Ends a run and its engine session. |
| `list_proposals` | Lists ownership, merge, identity and person-named proposals. |
| `review_proposal` | Approves, rejects or retracts a proposal; approving and retracting write to the Asset Database after the user approves. |
| `data_sources` | Lists which data sources have credentials, never the credentials. |
| `data_source_key_link` | Gives the user a one-time local link (15 minutes, single use) to a form that writes a data source's credentials to the datasources file; the key never passes through the assistant. |

Over HTTP the operator tools are offered only to clients that present
`AMASS_AI_MCP_OPERATOR_TOKEN`, which must differ from the read-only token;
a session belongs to the token that opened it. Over stdio,
`amass ai -operator mcp` (or `amass-ai-mcp -operator`) enables them for
whoever can start the process. Operator sessions use event streams so the
server can ask for approval in the middle of a tool call.

Approval: `start_enumeration` and the writing `review_proposal` decisions
ask the user first, in order of preference:

1. the client's own dialog (MCP elicitation: an input-required result on
   protocol 2026-07-28, an `elicitation/create` request on earlier
   versions);
2. from the HTTP server with `AMASS_AI_MCP_PUBLIC_URL` set, a one-time local
   approval link (15 minutes) the assistant gives the user: the page shows
   the action and carries it out only when the user presses Approve, a form
   POST a model fetching the page cannot make;
3. otherwise (stdio) the client's own tool-call approval, helped by the
   tool annotations, unless `AMASS_AI_MCP_REQUIRE_CONFIRMATION=true`, which
   refuses instead.

These are safeguards against a model acting on its own; the operator token
is what authorizes a client. Each run and decision records who approved it
and how.

Enumerations (`internal/collect`) are confined to the approved scope with
no expansion. Active mode adds brute forcing, name alterations, zone
transfer attempts and certificate and service probes on the configured
ports, and covers at most a /16 IPv4 or /48 IPv6 range. Two runs may run
at once; a run ends when its work settles, after 30 minutes without
progress, or after 24 hours. Runs are recorded in
`AMASS_AI_MCP_RUN_JOURNAL` and resumed after a restart while the engine
still has them.

Connecting an assistant to the Compose environment is covered by
`scripts/ai-connect.sh` in amass-docker-compose (see its `AI.md`).

## Transport

Both servers use the official MCP Go SDK
(`github.com/modelcontextprotocol/go-sdk`). The HTTP server keeps Amass's
own checks in front of the SDK's Streamable HTTP handler: a bearer token,
local browser origins only, a 1 MiB request limit, JSON responses (no
server-sent event stream), and idle-session expiry with a session cap.
Only sessions Amass admitted reach the SDK, and expired or evicted
sessions are closed in the SDK too. Session IDs are 192 random bits.
