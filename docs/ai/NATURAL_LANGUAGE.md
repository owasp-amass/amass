# Typed OAM query planning and entity resolution (experimental)

The AI planner accepts natural language and supports **all registered OAM asset types as query starting points**, obtaining valid relationship transitions from
`oam.AssetList`, `oam.GetAssetOutgoingRelations`, and `oam.GetTransformAssetTypes`,
and returns a bounded (1–3-hop) typed query plan. All transitions are checked
against the authoritative OAM taxonomy before read-only execution. No hardcoded
natural-language patterns are used.

## Entity resolution

OAM's existing `Organization` asset provides `unique_id`, `name`,
`legal_name`, `jurisdiction` and `registration_id`. The resolver
uses indexed, typed Asset Database filters over those fields. A plan's
`subject` includes `type: "Organization"` and exactly one of
`name`, `legal_name`, `unique_id`, or `registration_id`.
Registration identifiers require a jurisdiction; an optional jurisdiction
also disambiguates name-based queries.

For display names, the resolver searches both `name` and `legal_name`.
For names and legal names, only the final-period variant is additionally
considered. Arbitrary edit-distance matches, suffix stripping and unbounded
table scans are not used.

The `resolve_organization` tool returns a status of `matched`,
`ambiguous`, `not_found`, or `truncated`, with candidate OAM
entity IDs and match provenance. Multiple candidates never cause
automatic selection. A query with no matching organization is
`incomplete`; it cannot prove the absence of relationships.

### Explicitly sourced aliases

Trade names and historical names are loaded from an optional, local,
read-only JSON file using `-organization-aliases /path/to/aliases.json`:

```json
{
  "aliases": [
    {
      "alias": "Acme Group",
      "unique_id": "synthetic-acme-holdings",
      "jurisdiction": "US-NY",
      "source": "curated-registry-record-001"
    }
  ]
}
```

Replace the example values with identifiers and sources you have actually
verified. An alias maps to an existing Organization `unique_id`; it does
not create an OAM asset or relationship. The source is included in
the returned candidate's match provenance. Aliases must have an explicit
source and resolve to a matching existing entity. The JSON file is limited
to 1 MiB and 1000 aliases. No external lookup is performed.

The JSON schema is a configuration format for the AI resolver, not a
change to the OAM `Organization` asset schema.

### Example

```json
{
  "subject": {"type": "Organization", "name": "Acme Holdings Inc."},
  "hops": [
    {"direction": "out", "label": "subsidiary", "relation_type": "SimpleRelation", "destination_type": "Organization"},
    {"direction": "out", "label": "website", "relation_type": "SimpleRelation", "destination_type": "URL"}
  ]
}
```

The model generates a candidate plan; Go validates and executes it.
The agent never writes inferred relationships. Entity matches and graph
paths provide evidence of stored OAM records, not independent proof of
ownership or attribution.

### Current boundaries

The planner can begin at any registered OAM asset type. Graph traversal and candidate results are bounded. The explicit alias file is a local configuration mechanism;
a future design may integrate persistent alias evidence and automated
identity-candidate generation with analyst review.

For MCP clients, `describe_oam_schema` exposes valid OAM relationships,
`describe_asset_selectors` exposes indexed search fields for every registered
asset type, and `resolve_asset` performs bounded, type-checked lookup.
`resolve_organization` remains available for entity names and aliases.

## Starting from any OAM asset type

A plan can use `{"subject":{"type":"FQDN","field":"name","value":"tech.acme.example"}}`
or `{"subject":{"type":"URL","field":"url","value":"https://tech.acme.example/"}}`,
as well as `{"subject":{"type":"FQDN","entity_id":"42"}}` for an explicit
database entity ID supplied by the user. IDs must never be invented.

Example beginning with a domain:

```json
{
  "subject":{"type":"FQDN","field":"name","value":"tech.acme.example"},
  "hops":[
    {"direction":"in","label":"domain","relation_type":"SimpleRelation","destination_type":"URL"}
  ]
}
```

Indexable fields vary by OAM asset type. `ContactRecord` currently
requires an explicit `entity_id` because its available content filter,
`discovered_at`, is not an identity key. This also demonstrates why
domain names, URLs, IP addresses, ASN numbers, certificates, organizations,
and other OAM assets must not share a single untyped name resolver.
The content-filter selector catalog must stay aligned with the
Asset Database repository schema. Unsupported selectors fail closed.


## Typed planner correction and small-model compatibility

Smaller local models sometimes reuse the Organization-style `name` field
for FQDNs. If the selected OAM asset type explicitly supports an indexed
`name` field, the planner may normalize that **structured plan field** into
`{"field":"name","value":"..."}`. This does not rewrite the input question,
create aliases, or infer missing entity values. For all other incomplete
selectors, the model receives a targeted retry listing the indexed fields
for the selected asset type and an example of the required structure.

The planner permits up to three generation attempts. Plans are only executed
after strict OAM selector and relationship validation. A failed plan does
not imply an asset or relationship is absent from the Asset Database.

## Inference latency with local Ollama

The OpenAI-compatible HTTP client used to impose a fixed 90-second request
timeout, while the AI CLI had a two-minute total investigation deadline.
Local models can exceed these limits when processing larger schema catalogs.
The planner now groups identical OAM relationship transitions and sends a
compact source/label/relation-type/destination catalog, without relaxing the
authoritative validator's exact OAM checks.

You can increase both bounded durations for slower local inference:

```sh
amass ai -model qwen3:8b -model-timeout 4m -investigation-timeout 12m \
  -question "Which URL assets are related to tech.acme.example?" ask
```

Defaults are 3 minutes per model request and 8 minutes overall. The limits
accept 5s–15m and model-timeout–30m, respectively. Repeated model calls share
the overall investigation deadline; an expired inference request does not
establish that an OAM asset or relationship is absent.

### Native Ollama provider (recommended for local models)

`-provider ollama` calls Ollama's native `/api/chat` instead of its
OpenAI-compatible `/v1` endpoint. With the native API Amass can:

- turn off a reasoning model's thinking phase (`think: false`). Qwen3 thinks
  by default, which on a CPU-only host such as Docker Desktop on macOS can
  take minutes per request. Pass `-think` (or `ai.think: true`,
  `AMASS_AI_THINK=true`) to turn it back on;
- set the context window (`-context-tokens`, default 8192). The planner
  prompt for the full OAM catalog is about 3,500 tokens, and a smaller
  window silently truncates it;
- constrain the goal planner's reply to a JSON schema that enumerates the
  OAM asset types and each allowed relationship as one whole transition, so
  valid parts cannot be combined into a transition OAM does not have (if an
  Ollama build rejects the schema, the request is retried unconstrained);
- keep the model loaded for 30 minutes between CLI runs.

The endpoint is the Ollama base URL:

```sh
amass ai -provider ollama -endpoint http://127.0.0.1:11434 -model qwen3:8b \
  -trace -question "Which organizations are connected to tech.acme.example?" ask
```

Models that do not support thinking reject the `think` field; Amass retries
once without it and stops sending it. The Anthropic provider gets the same
schema-constrained planning through a forced tool call. The `compatible`
provider is unchanged and still relies on the prompt for JSON.

`-trace` prints one line per stage and the model usage to stderr, including
when an investigation fails (illustrative output):

```text
trace: goal_planning            21.4s  model_interpretation
trace: resolve_asset             0.0s  FQDN
...
trace: model calls=2 input_tokens=7410 output_tokens=388 model_time=34.9s
```

The JSON output carries the same totals in `model_usage`.

### Catalog slicing

The full planner prompt for the OAM catalog is about 17,000 characters.
The planner now shows only what the question mentions: relationships whose
labels it names, aliases for the asset types it names or implies (a URL,
IP address, CIDR, ASN or hostname implies its type), and their selectors.
For typical questions this is about a third of the full prompt, which
matters on CPU-only hosts where reading the prompt dominates latency. The
reply schema allows only the relationship labels that were shown. If the
first two attempts fail validation, the last attempt shows the full
catalog. Validation always uses the full catalog.

A word that names an asset type ("organization") does not count as asking
for the relationship of the same name. When a question asks for no
particular relationship, or asks for the highest parent without naming
relationships, any relationship constraints the model adds are dropped
rather than validated: they could only narrow the search.

## Relationship direction in answers

Answer paths render arrows using the stored edge endpoints, not the query
traversal order. For example, when starting at an FQDN and walking an
incoming `domain` relationship, the answer renders
`FQDN <--domain-- URL` because the stored OAM edge is directed
`URL --domain--> FQDN`. This prevents inverse traversal from being
mistaken for the direction of the asserted relationship.

## Empty intermediate hops and unresolved questions

A schema-valid multi-hop plan can still choose the wrong graph path.
If a proposed path has no edges at an intermediate hop, the remaining hops
cannot be executed. The CLI marks the investigation `incomplete: true`,
reports `plan_stopped_at_hop`, and explicitly warns that other OAM paths
may exist. A one-hop search with no matching edges is not automatically
classified as truncated. None of these outcomes proves the absence of an
asset elsewhere in the graph. Finding an ultimate parent organization
requires graph-aware alternative-path planning and recursive traversal of
corporate hierarchy relations; this is **not** implemented by the current
fixed-hop planner.
