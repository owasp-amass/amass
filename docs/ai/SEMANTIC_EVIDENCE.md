# OAM relationship semantics and edge-level provenance (experimental)

This milestone extends `amass ai ask` with **taxonomy-valid relationship
constraints** and an explicit, bounded **source evidence dossier**. The
core navigator remains read-only and works across registered OAM asset and
relationship types.

## Goal contract

```json
{
  "subject":{"type":"FQDN","field":"name","value":"tech.acme.example"},
  "target_types":["Organization"],
  "direction":"both",
  "purpose":"connected",
  "relationships":[
    {"source_type":"URL","label":"domain","relation_type":"SimpleRelation","destination_type":"FQDN"},
    {"source_type":"Organization","label":"website","relation_type":"SimpleRelation","destination_type":"URL"},
    {"source_type":"Organization","label":"subsidiary","relation_type":"SimpleRelation","destination_type":"Organization"}
  ],
  "path_rule":"ordered"
}
```

`relationships` contains exact, **stored-direction** OAM taxonomy
transitions. `path_rule` can be:

- `""` with no constraints: open-ended exploration (previous behavior).
- `"any"`: at least one required transition exists in a path.
- `"all"`: every required transition exists, in any order.
- `"ordered"`: transitions appear in order **from the user's root**;
  unrelated intermediate edges are permitted.

When starting at an FQDN the example traverses the stored `domain`,
`website` and `subsidiary` edges in reverse. A made-up OAM relation
fails validation before traversal.

## Evidence contract

The investigation JSON now contains `evidence_dossier` and
`evidence_incomplete`. Each `evidence_dossier.paths[]` is linked by
`path_id` and lists the source-level support of each exact OAM edge.
It distinguishes `no_attributed_sources`, `single_source`, and
`multiple_source_tags`. Only typed `SourceProperty` records contribute
a source identity; generic tags cannot be counted as corroboration.

**Multiple source names are not proof of source independence, a true
relationship, or legal ownership.** Source records identify stored
provenance tags, not an independently verified fact. A path with one
weakly supported edge remains `limited_source_support` even when other
edges have many tags. `evidence_incomplete` is independent of graph
`incomplete`.

Edge ID and asset ID strings may overlap. The new
`EdgeEvidenceReader` and `get_edge_evidence` tool query the exact
edge namespace rather than using an ambiguous entity-first lookup.

The dossier limits itself to 40 edge lookups and 8 tags per edge.
The existing Asset Database tag reader may load additional records
before adapter-side limiting; adding a SQL-bounded tag reader is
future work.

## Update and automated tests

```bash
cd /path/to/asset-db
git switch feature/ai-investigation-inference
git fetch origin feature/ai-investigation-inference
git merge --ff-only origin/feature/ai-investigation-inference
go test ./internal/aitestfixture/... -count=1

cd ../amass
git switch feature/ai-investigation-inference
git fetch origin feature/ai-investigation-inference
git merge --ff-only origin/feature/ai-investigation-inference
go mod edit -replace=github.com/owasp-amass/asset-db=../asset-db

go test ./internal/ai/... -count=1
go test ./internal/ai -run \
 'TestGoalRelationships|TestGuidedGraphRespectsExactRelationshipGoal|TestPathEvidence|TestAdaptiveQuestionUsesGenericRelationshipGoal|TestGetEdgeEvidence' -v -count=1
go vet ./internal/ai/...
CGO_ENABLED=0 go build -o "$AI_TEST_ROOT/bin/amass" ./cmd/amass
```

## User-facing test 1: existing Acme database

```bash
mkdir -p "$AI_TEST_ROOT/qa"
set -o pipefail
"$AI_TEST_ROOT/bin/amass" ai \
  -config "$AI_TEST_ROOT/config.yaml" \
  -model qwen3:8b \
  -model-timeout 4m -investigation-timeout 12m \
  -question "What is the highest parent organization associated with tech.acme.example?" \
  -depth 8 -format json ask |
  tee "$AI_TEST_ROOT/qa/semantic-parent.json"

jq '{
 goal, answer,
 graph_incomplete:.incomplete,
 evidence_incomplete,
 evidence:[.evidence_dossier.paths[]|{
   path_id,status,weakest_link,verified_ownership,
   edges:[.edges[]|{edge_id,label,status,attributed_sources}]
 }]
}' "$AI_TEST_ROOT/qa/semantic-parent.json"
```

Expected: parent Acme Holdings Inc. The original fixture gives
its subsidiary edge two synthetic source tags but leaves the
website/domain edges unattributed. Therefore the path should be
`limited_source_support`, **not verified ownership**.

## User-facing test 2: richer disposable alternate-path fixture

The asset-db branch has a new `testdata/ai/semantic` fixture with two
URL routes to `tech.acme.example`, a parent/sibling hierarchy, an
unrelated Northwind organization, and deliberately unequal source
support across edges.

From the `asset-db` checkout, create a NEW, disposable directory:

```bash
AI_SEMANTIC_ROOT=$(mktemp -d /tmp/amass-ai-semantic.XXXXXX)
export AI_SEMANTIC_ROOT

go run ./cmd/ai-fixture-seed \
  -fixture ./testdata/ai/semantic \
  -sqlite "$AI_SEMANTIC_ROOT/semantic-fixture.db" \
  -confirm-disposable

# The Amass local backend expects asset.db. This copies into a NEW
# disposable directory, never an existing Amass installation.
cp "$AI_SEMANTIC_ROOT/semantic-fixture.db" "$AI_SEMANTIC_ROOT/asset.db"
printf 'Disposable test directory: %s\n' "$AI_SEMANTIC_ROOT"
```

Then, from the `amass` checkout, use `-dir` without `-config`.
Make sure neither `AMASS_CONFIG` nor external database environment
settings override this local-only configuration.

```bash
"$AI_TEST_ROOT/bin/amass" ai \
  -dir "$AI_SEMANTIC_ROOT" \
  -model qwen3:8b \
  -model-timeout 4m -investigation-timeout 12m \
  -question "Which organizations are connected to tech.acme.example by website and domain relationships?" \
  -depth 8 -max-paths-per-asset 3 -guidance-rounds 2 \
  -format json ask |
  tee "$AI_SEMANTIC_ROOT/semantic-alternates.json"

jq '{
 goal,
 tech_paths:[.search.matches[] |
   select(.nodes[-1].content.name=="Acme Technologies Ltd.") |
   {path_id,depth:(.edges|length),nodes:[.nodes[].key]}],
 alternative_matches:.search.alternative_matches,
 sources:[.evidence_dossier.paths[]|{
   path_id,status,weakest_link,
   edges:[.edges[]|{edge_id,label,status,attributed_sources}]
 }],
 graph_incomplete:.incomplete,
 evidence_incomplete
}' "$AI_SEMANTIC_ROOT/semantic-alternates.json"
```

Expected: two different `path_id` values that reach Acme
Technologies through different URLs. The alternate route has two
source tags on its domain and website edges; the original URL
route has only one on those edges. This is a controlled contrast
in **declared source tags**, not verified independent corroboration.

## User-facing test 3: relationship-specific ordered question

```bash
"$AI_TEST_ROOT/bin/amass" ai \
  -dir "$AI_SEMANTIC_ROOT" \
  -model qwen3:8b \
  -model-timeout 4m -investigation-timeout 12m \
  -question "Starting from tech.acme.example, which organizations are connected through the stored domain, then website, then subsidiary relationships, in that traversal order?" \
  -depth 8 -max-paths-per-asset 3 -format json ask |
  tee "$AI_SEMANTIC_ROOT/semantic-ordered.json"

jq '{
  goal,
  matches:[.matches[]|{
    path_id,depth:(.edges|length),
    target:(.nodes[-1].content.name // .nodes[-1].key),
    labels:[.edges[].label]
  }],
  graph_incomplete:.incomplete,
  evidence_incomplete
}' "$AI_SEMANTIC_ROOT/semantic-ordered.json"
```

Expected: a goal with `path_rule:"ordered"` and exactly
registered OAM relations. The shortest matching Organization is
Acme Holdings at three hops (rather than Acme Technologies at two).
Qwen's goal interpretation must be inspected independently from
the deterministic path validator.

## Non-model regression checks

```bash
cd /path/to/asset-db
go test ./internal/aitestfixture -run '^TestSemantic' -v -count=1
cd ../amass
go test ./internal/ai -run \
 'TestGoalRelationships|TestPathEvidence|TestGetEdgeEvidenceUsesExactRelationNamespace|TestAdaptiveQuestionUsesGenericRelationshipGoalAndSourceDossier' -v -count=1
```

The tests include source-tag deduplication, missing metadata,
fake relation tags, overlapping ID namespaces, constrained paths,
and deliberate evidence-budget exhaustion. All remain read-only.
