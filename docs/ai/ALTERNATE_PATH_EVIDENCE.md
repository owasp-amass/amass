# Alternate OAM paths: source-aware selection and execution tracing

This milestone builds on `SEMANTIC_EVIDENCE.md`. It does not modify the
Asset Database schema, issue Internet collection, or grant model tools
additional privileges. The prior `asset-db/testdata/ai/semantic` fixture
remains the recommended **disposable** end-to-end test dataset.

## Changes

- `adaptiveCandidate.edge_sources` now contains, for each witnessed OAM
  relationship edge: its exact edge ID, label, support status, and
  deduplicated source IDs.
- `adaptiveCandidate.source_tag_coverage` records the count of edges
  with attributable source tags, edges with multiple named source tags,
  edges lacking attributed source tags, and unassessed edges.
- When **two routes reach the same destination asset**, Qwen receives
  a deterministic display order that favors fewer unassessed edges,
  a higher *fraction* of edges with attributable source tags, more
  multiply-tagged edges, and then shorter routes.
- Paths to **different destination assets** are never ranked for
  relevance or truth based on tag counts.
- The original full witnessed path set remains available; display
  order neither filters graph results nor verifies any relationship.
- Investigation JSON now includes `trace[]` with bounded stage metrics
  and elapsed wall-clock milliseconds, including actual unique
  edge-evidence lookups and retrieved tag counts.
- Intermediate navigation model calls are also logged as
  `frontier_guidance` events, including failed or rejected advice.
  Small graphs may not need any intermediate model guidance.

These are transparent **source-tag coverage** comparisons. Different
source names can represent the SAME upstream feed, or a false claim.
No probability of correctness, legal ownership, or independence is
inferred from tag counts.

### Trace fields

Each trace event has `stage`, `duration_ms` and `incomplete`,
with additional fields as appropriate:

- `goal_planning`: model interpreted the user's typed OAM goal.
- `resolve_asset`: deterministic indexed/ID subject resolution.
- `guided_search`: output path count, visited nodes/edges,
  and expanded witnessed paths.
- `frontier_guidance`: optional model prioritization for large
  exploration frontiers; failed advice is not applied.
- `evidence_inspection`: input/output candidate path counts,
  **unique** edge-provenance reads and distinct edge tag records
  (shared edges are not double-counted).
- `path_selection`: how many semantically eligible witnessed
  candidates the model evaluated and selected.

`duration_ms` is elapsed stage time, not a throughput guarantee.
The top-level legacy `tool_calls` reports logical graph tool
operations rather than every internal repository lookup. Use
`trace[].edge_evidence_lookups` to inspect the latter.

## Update local repositories

Because you already have an intentionally modified `go.mod`
for the sibling Asset Database feature checkout, use fetch and
fast-forward merge rather than a pull that triggers rebase:

```bash
cd /path/to/asset-db
git switch feature/ai-investigation-inference
git fetch origin feature/ai-investigation-inference
git merge --ff-only origin/feature/ai-investigation-inference

cd ../amass
git switch feature/ai-investigation-inference
git fetch origin feature/ai-investigation-inference
git merge --ff-only origin/feature/ai-investigation-inference

go mod edit -replace=github.com/owasp-amass/asset-db=../asset-db

go test ./internal/ai/... -count=1
go test ./internal/ai \
  -run 'TestEvidenceAware|TestAdaptiveQuestionUsesGenericRelationshipGoalAndSourceDossier' \
  -v -count=1
go vet ./internal/ai/...
CGO_ENABLED=0 go build -o "$AI_TEST_ROOT/bin/amass" ./cmd/amass
```

Expected unit-test logging includes two alternate route path IDs,
a better documented two-edge route (2/2 tagged edges), and a
weaker route (1/2 tagged edges). This only tests the model-facing
candidate ordering; it does **not** establish independent
corroboration.

## User-facing end-to-end test, on the original Acme fixture

```bash
mkdir -p "$AI_TEST_ROOT/qa"
set -o pipefail

"$AI_TEST_ROOT/bin/amass" ai \
  -config "$AI_TEST_ROOT/config.yaml" \
  -model qwen3:8b \
  -model-timeout 4m -investigation-timeout 12m \
  -question "What is the highest parent organization associated with tech.acme.example?" \
  -depth 8 -max-paths-per-asset 3 \
  -format json ask |
  tee "$AI_TEST_ROOT/qa/traced-parent.json"

jq '{
  answer,
  selected:[.matches[]|{path_id,depth:(.edges|length),
    target:(.nodes[-1].content.name // .nodes[-1].key)}],
  trace,
  evidence_incomplete,
  dossier:[.evidence_dossier.paths[]|{path_id,status,
    edges:[.edges[]|{edge_id,label,status,attributed_sources}]}]
}' "$AI_TEST_ROOT/qa/traced-parent.json"
```

Expected: Acme Holdings Inc., depth 3, a provenance dossier
with edge 9 (domain) and edge 4 (website) unattributed,
and edge 1 (subsidiary) carrying two synthetic source tags.
`trace` should include all five basic investigation stages;
the `evidence_inspection` event should show exactly 3
unique edge lookups. `evidence_incomplete` should be true,
but graph `incomplete` should remain false.

## New fixture: alternate-route acceptance

Create a **NEW** isolated SQLite DB with the committed fixture.
Never seed or overwrite an existing Amass or customer DB.

```bash
cd /path/to/asset-db
AI_SEMANTIC_ROOT=$(mktemp -d /tmp/amass-ai-semantic.XXXXXX)
export AI_SEMANTIC_ROOT
go run ./cmd/ai-fixture-seed \
  -fixture ./testdata/ai/semantic \
  -sqlite "$AI_SEMANTIC_ROOT/semantic-fixture.db" \
  -confirm-disposable

cp "$AI_SEMANTIC_ROOT/semantic-fixture.db" \
   "$AI_SEMANTIC_ROOT/asset.db"

cd ../amass
"$AI_TEST_ROOT/bin/amass" ai \
  -dir "$AI_SEMANTIC_ROOT" \
  -model qwen3:8b -model-timeout 4m \
  -investigation-timeout 12m \
  -question "Which organization is connected to tech.acme.example through website and domain relationships, and which witnessed route has better named source-tag coverage?" \
  -depth 8 -max-paths-per-asset 3 \
  -format json ask |
  tee "$AI_SEMANTIC_ROOT/evidence-alternates.json"

jq '{
  goal,
  selected:[.matches[]|{path_id,depth:(.edges|length),
    target:(.nodes[-1].content.name // .nodes[-1].key),
    edge_ids:[.edges[].id]}],
  graph_alternates:.search.alternative_matches,
  evidence:[.evidence_dossier.paths[]|{
    path_id,status,
    edges:[.edges[]|{edge_id,label,status,attributed_sources}]}],
  trace
}' "$AI_SEMANTIC_ROOT/evidence-alternates.json"
```

Expected from the seeded database:

- Two witnessed routes to Acme Technologies Ltd., one through
  each synthetic URL; each route has a distinct `path_id`.
- One route has **two** named source tags on both its domain
  and website edge; the weaker route has only one source
  tag on each of those relationships.
- Source-tag coverage should influence the order in which
  the candidate routes are **presented to Qwen**, not prove
  either route is independently corroborated.
- The final selection can vary with the local model and
  question interpretation. Inspect `goal`, `search.matches`,
  `matches` and `trace` separately before drawing conclusions.

Qwen's private candidate prompt is not included in normal
`ask` JSON output; the Go regression test validates the
candidate ordering and exact evidence fields directly.

No Internet collection is launched by these commands.
