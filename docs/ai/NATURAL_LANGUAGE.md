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

