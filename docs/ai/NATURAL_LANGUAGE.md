# Typed OAM query planning (experimental)

The `amass ai ask` command now uses an OAM-aware, provider-neutral
planning layer. There are no hardcoded natural-language question patterns
in the active CLI path.

1. The model receives a machine-readable taxonomy generated from
   `oam.AssetList`, `oam.GetAssetOutgoingRelations`, and
   `oam.GetTransformAssetTypes`.
2. The model returns a strictly validated typed plan containing an
   Organization name and 1–3 directed OAM relationship transitions.
3. Invalid labels, relation types, destinations, directions, or hop counts
   are rejected. The planner has one opportunity to correct an invalid plan.
4. Amass resolves the organization name, executes bounded graph queries,
   and generates answers deterministically from returned asset/edge IDs.
5. Empty, ambiguous, or truncated queries are explicitly qualified.

Example intermediate plan for a multi-hop investigation:

```json
{
  "subject": {"type":"Organization","name":"Acme Holdings Inc."},
  "hops": [
    {"direction":"out","label":"subsidiary","relation_type":"SimpleRelation","destination_type":"Organization"},
    {"direction":"out","label":"website","relation_type":"SimpleRelation","destination_type":"URL"}
  ]
}
```

This architecture reduces hallucinated relationship labels without claiming
that any given model will always produce a valid plan. The current planner
starts from Organization names only; other asset types can appear as
destination types. Entity-name lookup first tries the exact Organization name, then checks a
single terminal-period variant (e.g. `Inc` and `Inc.`) using bounded
repository queries. Multiple matching organization IDs remain ambiguous;
the resolver never silently chooses one. This does not constitute general
fuzzy matching or entity resolution across aliases and legal names.

Other source-name variations remain exact. A later increment can add
generalized typed entity resolution and explicit ambiguity handling.

For MCP clients, the read-only `describe_oam_schema` tool exposes
the same OAM taxonomy and can be scoped by `source_type`.

The previous regex-based direct-subsidiary path has been removed.
OAM relationships are never auto-written by the planner.

**Safety:** OAM records remain untrusted evidence. Schema validation
guarantees type/label consistency, not truth of ownership claims.
No database modifications are made by this capability.
