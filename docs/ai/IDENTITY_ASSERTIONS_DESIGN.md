# Persistent identity assertions — design proposal

**Status:** Design for review. No OAM schema or Asset Database migrations are introduced by this document.

## Principle: all OAM asset types can be investigation roots

Identity resolution, evidence association and provenance must be usable by
**any OAM asset type**, not only Organization. Domain-first ASM workflows begin
at FQDN, URL, IPAddress, Netblock, AutonomousSystem, TLSCertificate and Service
assets just as often as they begin with legal entities.

Do not conflate three different statements:

1. **Observation:** an external source reports an FQDN, certificate, registry record or company name.
2. **Identity assertion:** one observed identifier, alias or source record *may refer to* an existing OAM asset.
3. **Attribution assertion:** the asset *may be controlled by / associated with* a legal organization.

The first is a source fact, the second is entity-resolution evidence, and the
third is a higher-risk relationship requiring independent supporting evidence.

## Proposed read/write separation

- **Observation store:** immutable source snapshots and timestamps.
- **Assertion store:** append-only, independently identified candidate claims,
  provenance, status and temporal validity.
- **Review ledger:** independent review decisions referencing the assertion,
  reviewer, policy version, supporting evidence and time.
- **Graph projection:** only policy-approved assertions create or modify OAM
  graph links. Denied, proposed and superseded assertions do not appear as
  authoritative OAM relationships.
- **Query index:** read-only, bounded indexes by asset type and typed selector.
  Query responses disclose whether a match is exact, normalized, sourced alias
  or merely a proposed candidate.

The underlying OAM asset and relation schemas should not be changed until the
proposed assertion semantics and lifecycle are approved. SourceProperties
remain source evidence, not equivalent to independent legal ownership proof.

## Proposed persistent records

```json
{
  "assertion_id": "uuid",
  "subject": {"asset_type": "FQDN", "entity_id": "123"},
  "predicate": "alias_of",
  "object": {"asset_type": "FQDN", "entity_id": "456"},
  "supporting_evidence": [
    {"source_id": "registry-import-001", "record_id": "row-59",
     "observed_at": "2026-11-08T00:00:00Z", "content_hash": "sha256:..."}
  ],
  "status": "proposed",
  "confidence": null,
  "valid_from": null,
  "valid_until": null,
  "policy_version": "v1",
  "created_at": "2026-11-08T00:00:00Z"
}
```

Other predicates (such as `name_of`, `registered_to`, `controlled_by`,
`same_entity_as`, `operated_by`) should be defined and reviewed separately,
not reused as invented OAM graph relationship labels.

A review event references the assertion ID and sets `approved`,
`rejected`, `revoked` or `needs_review`. Events are append-only:
revoking a claim must not delete its historical evidence.

## Safety and correctness requirements

1. **Bounded search:** never scan the full OAM graph to compensate for an
   unsupported index; report incomplete/truncated result instead.
2. **Type-safe identity:** FQDN normalization differs from legal-name,
   IP-address, netblock, ASN, account and TLS certificate normalization.
3. **Ambiguity:** two plausible entities may not be silently merged or
   chosen by model confidence alone.
4. **Evidence independence:** repeated copies of the same underlying
   registry record are not independent corroborating sources.
5. **Temporal validity:** source observation time differs from the legal or
   operational period during which a statement was true.
6. **Analyst accountability:** reviewer, policy version, evidence IDs and
   reversal history are mandatory for promoting attribution claims.
7. **No implicit write:** an LLM proposal cannot write OAM graph relations.
8. **No destructive merges:** changing a canonical entity requires a
   reversible reviewable operation.

## Implementation sequence

- **Phase A (in progress):** universal read-only typed OAM root resolution
  with provenance and fail-closed ambiguity; FQDN/URL regression tests.
- **Phase B:** implement persistent assertion + review storage as a separate
  Asset Database migration with bounded indexed queries and a repository API.
- **Phase C:** expose reviewed assertions to AI investigation; include evidence
  and validity in responses; keep proposed claims non-authoritative.
- **Phase D:** add controlled graph projection and reconciliation logic, with
  rollback and audit tests.

Before Phase B, agree on the assertion vocabulary, storage backend semantics,
revision strategy, and whether any OAM asset/relation types are required.
**Any OAM model modification must include corresponding OAM docs updates,
examples, and tests in the same coordinated changeset.**
