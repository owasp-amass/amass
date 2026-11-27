# MCP investigation tools

Both MCP servers (`amass ai mcp` over stdio and `amass-mcp-http`) list two
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
| `max_assets` | An optional limit on the assets a lens reads, for a quick, partial answer marked incomplete; by default a lens reads the whole footprint, bounded only by time |
| `owner_steps` | How many assets the search for an asset's owner visits before giving up (default 100); it stops at the nearest organization, so raise it only when assets are reported with no owner |
| `owner_depth` | How many levels the search for the subject's own owner climbs (default 8) |

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
  "subject": {"type": "Organization", "name": "OWASP Foundation"},
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
`AMASS_MCP_PUBLIC_URL` is set, a link to an interactive D3 graph and a
GEXF file for Gephi (valid for an hour, served on localhost). Drawings
cover up to 3,000 assets.

## Configuration

Two read-only tools let the assistant read and check the Amass
configuration. The server runs no model of its own, so the assistant is
the one that drafts a configuration from what these return; writing it
needs operator mode (`apply_config`, below).

| Tool | What it does |
| --- | --- |
| `describe_config` | Returns the configuration schema (sections, and every field with its type, default, description and an example), the current configuration with data source credentials masked, and a commented template to start a new file from. `section` narrows it to seed, scope, options, transformations, datasources or ai. |
| `validate_config` | Checks a complete configuration draft with the real Amass loader and shows how it differs from the current one (credentials masked), without changing anything. |

Data source credentials never pass through the assistant: they are masked
in what `describe_config` returns and in every diff, and `apply_config`
refuses a draft that sets any. Keys are entered by the operator through
`data_source_key_link`.

A terminal user gets the same help from the locally configured model with
`amass ai config -question "..." -config <file>`, which shows the proposed
configuration and a masked diff and writes it only on approval (at the
prompt, or ahead of time with `-approve-config`).

## Operator mode

A server started with an operator configuration also offers tools that act:

| Tool | What it does |
| --- | --- |
| `plan_enumeration` | Shows what enumerating a target (domain, IP, CIDR or AS number) would do, passive or active: scope, methods, effects and the `plan_id`. `also` adds up to 25 more targets to the same run (such as the organization's netblocks and AS, each held to the same rules), `expand` allows scope expansion as far as the configuration's expansion policy does (without it, the run is held to the given scope), and `interface` names the network interface on the engine's host for the run's traffic, as `amass enum -iface` does; the `plan_id` covers all three. `brute_force` and `alterations` turn on name guessing in active mode. Starts nothing. |
| `start_enumeration` | Starts the planned enumeration, with the same `target`, `mode`, `also`, `expand`, `brute_force`, `alterations` and `interface`, after the user approves it. When another engine on the database is enumerating the same scope, the engine's session joins that job (the run records `job` and `joined`, and the result tells the assistant to say so). |
| `enumeration_status` | Lists runs, or shows one with its progress (the whole job's, for a run that joined one), the job's workers while it runs (`GET /sessions/{token}/workers`: live, background work, items leased and done), and, once finished, what the changes lens finds since it started. |
| `stop_enumeration` | Ends a run and its engine session; other engines' workers on the same job carry on. |
| `watch_target` | Re-runs a planned enumeration every N hours (at least 6) after one approval, until stopped; a due run joins the scope's job when another engine is running it. |
| `list_watches` | Lists watches with their schedule, next run and what the last finished run found (the changes lens since it started). |
| `stop_watch` | Removes a watch. |
| `read_documents` | With the user's approval, has the document model named in `options.ai.documents` read a domain's or organization's documents in full (fetched again; the database keeps no copy) and stores the validated findings: assets, relations and field values in OAM terms (at most 10 documents per call, default 2; each version is read once). Returns counts unless `options.ai.documents.share_with_assistants` is set. |
| `contribute` | With the user's approval, writes up to 50 items an assistant found by other means into the Asset Database: assets, relations and properties, each checked against the OAM schema and carrying its evidence. A relation or property names an asset by an earlier item's index or by an exact type, field and value that matches one stored asset. Items are tagged with the source `amass-ai:<client>` and count like other stored data; new assets are also given to the running enumerations. |
| `list_proposals` | Lists ownership, merge, identity, person-named and name (person or organization) proposals, and assistants' contributions (`ctb-`). |
| `review_proposal` | Approves, rejects or retracts a proposal; approving and retracting write to the Asset Database after the user approves. Approving a name proposal (`nk-`) takes `as`: `person` or `organization`. A contribution can only be retracted. |
| `data_sources` | Lists which data sources have credentials and where they come from (the datasources file, the environment or the database's encrypted store), never the credentials. |
| `data_source_key_link` | Gives the user a one-time local link (15 minutes, single use) to a form that writes a data source's credentials to the database's encrypted store when the server has the secrets key (see [SECRETS.md](SECRETS.md)), otherwise to the datasources file; the key never passes through the assistant. |
| `apply_config` | Writes a complete configuration draft (see `describe_config` and `validate_config`) to the configuration file after the user approves it and sees the exact masked diff. Refuses a draft that sets data source credentials. |

Over HTTP the operator tools are offered only to clients that present
`AMASS_MCP_OPERATOR_TOKEN`, which must differ from the read-only token;
a session belongs to the token that opened it. Over stdio,
`amass ai -operator mcp` (or `amass-mcp -operator`) enables them for
whoever can start the process. Operator sessions use event streams so the
server can ask for approval in the middle of a tool call.

Approval: `start_enumeration`, `apply_config`, `contribute` and the
writing `review_proposal` decisions ask the user first, in order of
preference:

1. the client's own dialog (MCP elicitation: an input-required result on
   protocol 2026-07-28, an `elicitation/create` request on earlier
   versions);
2. from the HTTP server with `AMASS_MCP_PUBLIC_URL` set, a one-time local
   approval link (15 minutes) the assistant gives the user: the page shows
   the action and carries it out only when the user presses Approve, a form
   POST a model fetching the page cannot make;
3. otherwise (stdio) the client's own tool-call approval, helped by the
   tool annotations, unless `AMASS_MCP_REQUIRE_CONFIRMATION=true`, which
   refuses instead.

These are safeguards against a model acting on its own; the operator token
is what authorizes a client. Each run and decision records who approved it
and how.

Enumerations (`internal/collect`) are confined to the approved scope, and
expand only when the plan allows it. Active mode adds zone transfer
attempts and certificate and service probes on the configured ports, and
covers at most a /16 IPv4 or /48 IPv6 range; brute forcing and name
alterations run only when the plan asks for them. A plan's interface
replaces `options.interface` for that run, and the engine refuses to start
a run whose interface its host does not have. An active plan's
`active_route` (an interface or a proxy URL such as `socks5h://tor:9050`)
and `active_udp_route` replace `options.active_route` and
`options.active_udp_route`; a plan never carries a proxy password, and the
engine refuses to start a run whose proxy it cannot reach. Any number of
runs may run at once, each scope once; a run ends when its work settles,
after 30 minutes without progress, or after 24 hours. Runs are recorded in
`AMASS_MCP_RUN_JOURNAL` and resumed after a restart while the engine
still has them. Watches are kept in `AMASS_MCP_WATCHES` (at most 32); a
due run that cannot start because its scope is already being collected is
retried an hour later. When the Asset Database keeps a journal (PostgreSQL or SQLite),
runs and watches are kept in its `runs` and `watches` topics instead
(`internal/coord`), so MCP servers on one database list each other's runs
and share the watches; the files' records are moved into an empty topic
once. Leases in the database keep two servers from supervising one run or
starting one watch's due run twice.

Contributions (`internal/review/contributions.go`,
`internal/graph/oamrepo/contribute.go`) are journaled as kind
`contribution` with what was written: the entities, edges and properties,
and whether each property was there already. A write that fails part way,
or that cannot be journaled, is undone at once. Retracting one
(`review_proposal` or `amass review retract`) removes the properties it
added, then each edge with no source left and each entity with no source
and no edges left, so what a collector also observed stays.

Unless `options.ai.contributions.strong_evidence` is set, a strong signal
that rests on contributions counts as supporting
(`internal/lens/contributions.go`): it keeps its weight and corroborates,
but cannot be the strong signal. Each occurrence of a signal is one way its
evidence holds, and needs each of its links: every edge of a witness chain,
or, for a duplicate pair, the records of the shared value on both
organizations. A link whose records only `amass-ai:<client>` sources
recorded makes its way rest on contributions, and the signal rests on them
when every way does. So an assistant's website edge to a collected domain
cannot widen scope, while a value a collector also recorded keeps its
strength. The lens reads sources only for strong signals' evidence, once
per search. This applies to ownership gaps (`GapSignal.Contributed`),
related-domain and infrastructure scoring (`ContributedSignals`, which
scope admission follows) and duplicate merges (`AutoMergeable`);
`oamrepo.New` carries the setting on every configured adapter.

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
