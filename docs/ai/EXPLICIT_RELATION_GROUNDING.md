# Explicit OAM relationship goal grounding

## Symptom and cause

A small local model may repeatedly propose a valid-but-irrelevant schema
route (such as WHOIS/registration) when the user expressly asks for
`website` and `domain` relationships. It may also omit the required
`relation_type` field and produce an invalid goal after three retries.

The planner now treats explicitly named relation labels in phrases such
as "through website and domain relationships" as **hard user intent**.
It builds the shortest schema-compatible transition sequence with
exactly those labels and validated root/target types. If the schema
has zero or multiple possible transitions, it fails closed instead of
guessing or dropping the user's constraints.

For the following request, this is the unique OAM type sequence:

```text
Starting FQDN: tech.acme.example
FQDN <-domain-- URL <-website-- Organization
Stored schema:
URL --domain (SimpleRelation)--> FQDN
Organization --website (SimpleRelation)--> URL
Goal path_rule: all
```

If the user explicitly asks "via domain then website relationships in
that order", `path_rule` becomes `ordered` with the same stored OAM
edge orientations but the requested traversal order.

The planner still validates the model's root identifier, indexed
field, target types, direction, and purpose independently before
schema-grounding its relationship constraints. The database is
never updated. No Internet collection is performed.

## Pull and verify

```bash
cd /path/to/amass
git fetch origin feature/ai-investigation-inference
git merge --ff-only origin/feature/ai-investigation-inference
go mod edit -replace=github.com/owasp-amass/asset-db=../asset-db

go test ./internal/ai \
  -run 'TestExplicitRelationGrounding|TestNonExplicitQuestionDoesNotTriggerRelationRepair|TestAdaptiveGoalPlannerRepairsUnknownTaxonomyRelation' \
  -v -count=1

go test ./internal/ai/... -count=1
CGO_ENABLED=0 go build -o "$AI_TEST_ROOT/bin/amass" ./cmd/amass
```

## Retry with Qwen3 and the existing disposable semantic fixture

```bash
set -o pipefail

"$AI_TEST_ROOT/bin/amass" ai \
 -dir "$AI_SEMANTIC_ROOT" \
 -model qwen3:8b \
 -model-timeout 4m -investigation-timeout 12m \
 -question "Which organization is connected to tech.acme.example through website and domain relationships, and which witnessed route has better named source-tag coverage?" \
 -depth 8 -max-paths-per-asset 3 -format json ask |
 tee "$AI_SEMANTIC_ROOT/evidence-alternates.json"

jq '{
  goal,
  selected:[.matches[]|{
    path_id,target:(.nodes[-1].content.name // .nodes[-1].key),
    edge_labels:[.edges[].label]
  }],
  alternatives:.search.alternative_matches,
  evidence:[.evidence_dossier.paths[]|{
    path_id,status,
    edges:[.edges[]|{label,status,attributed_sources}]
  }],
  trace,
  incomplete
}' "$AI_SEMANTIC_ROOT/evidence-alternates.json"
```

Expected goal:
- `subject.type` = `FQDN`, `subject.value` =
  `tech.acme.example`, `target_types` = `["Organization"]`.
- `purpose` = `connected`, `direction` = `both`.
- `relationships` contains the exact `URL/domain/FQDN` and
  `Organization/website/URL` `SimpleRelation` records.
- `path_rule` = `all`.
- Two witnessed alternative routes should be present in
  `search.matches` if the semantic fixture was seeded and
  the search budgets permit them.

The model may choose more than one witnessed path or an empty
selection; inspect both the deterministic search and final selection.
The source-tag dossier compares named provenance coverage but
never claims independent verification of ownership.
