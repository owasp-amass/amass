# Iterative, question-guided OAM graph investigation

This experimental feature branch upgrades the natural-language `amass ai ask`
path from a single breadth-first search to a **bounded, staged, schema-aware
graph navigator**.

The user supplies the question; the model selects a typed OAM subject and a
goal. Amass resolves the subject, then explores the actual stored database
edges. A model may advise which valid OAM relationship labels and existing
frontier assets to investigate first, but it cannot add edges, change the
approved scope, invent asset IDs, or silently exclude a relationship.

## What changed

- The navigator advances a **frontier of witnessed simple paths** rather
  than globally marking every asset visited once. Multiple paths to the
  same asset can therefore be retained (default: 3 per asset).
- Each path has a stable `path_id` derived from the witnessed graph asset and
  edge identifiers. The model selects **path IDs**, not merely destination
  assets. Legacy single-path asset-ID selections still work when unambiguous.
- Edges are fetched using the Asset Database's **bounded edge reader**,
  validated against the authoritative OAM relationship catalog, and cached
  per node. Cycles within a path are prohibited.
- Frontier ranking favors types closer to the requested destination types,
  OAM relationship labels preferred by the question navigator, and approved
  frontier asset priorities. Every affordable branch remains eligible.
- Stage-by-stage guidance is **advisory**: it is validated against existing
  catalog labels and frontier asset IDs. Invalid responses are recorded and
  ignored; no model response can authorize Internet collection.
- The search reports `mode: "guided"`, `expanded_paths`,
  `alternative_matches`, and `alternative_paths_skipped`.
  Limits report `truncated: true` and an explicit `reason`.
- The existing `ultimate_parent` rule still checks the direction of
  `subsidiary` edges, preventing a sibling from becoming a parent simply
  because the sibling is reachable.

### Limitations

- The default goal vocabulary is still `connected` / `ultimate_parent`.
  Future work should introduce a broader typed semantic goal vocabulary.
- This is **priority-guided bounded exploration**, not yet full autonomous
  search with a learned stop decision. The frontier is explored to
  exhaustion or to a configured limit.
- Stages request extra model guidance only for **larger frontiers**
  (at least seven pending paths after a stage); a small Acme fixture may
  require only the initial goal call and final evidence selection.
- Each asset retains at most three paths by default (configurable 1–8).
  When alternate paths are skipped, the result is marked truncated.
  Some meaningful longer paths may still be missed.
- Evidence consists of stored OAM graph relationships. Independent
  provenance, corroboration, and confidence assessment require further work.
- The AI tool remains read-only. Missing data may produce a passive
  enumeration proposal, but **no network collection starts without
  explicit approval via the separate collect command**.

## Update local feature branch

Do not discard your local `go.mod` replacement for the sibling Asset
Database checkout. `git pull` may try to rebase and reject that change;
instead fetch and fast-forward.

```bash
cd /path/to/asset-db
git switch feature/ai-investigation-inference
git fetch origin feature/ai-investigation-inference
git merge --ff-only origin/feature/ai-investigation-inference

cd ../amass
git switch feature/ai-investigation-inference
git status --short
git fetch origin feature/ai-investigation-inference
git merge --ff-only origin/feature/ai-investigation-inference

# Pair feature branches locally; do not commit the go.mod replacement.
go mod edit -replace=github.com/owasp-amass/asset-db=../asset-db

go test ./internal/ai/... -count=1
go test ./internal/ai -run '^TestGuided' -v -count=1
go test ./internal/ai -run '^TestAdaptive' -v -count=1
go vet ./internal/ai/...
CGO_ENABLED=0 go build -o "$AI_TEST_ROOT/bin/amass" ./cmd/amass
```

If the fast-forward merge warns about uncommitted local files being
overwritten, stop and preserve the changes; do not reset or force-pull.

## Natural-language manual acceptance tests

Use your **existing, disposable** Acme OAM test database and a running local
model. Save the JSON result and check the mode, path IDs, result depths and
partial coverage signals.

```bash
mkdir -p "$AI_TEST_ROOT/qa"
set -o pipefail

"$AI_TEST_ROOT/bin/amass" ai \
  -config "$AI_TEST_ROOT/config.yaml" \
  -model qwen3:8b \
  -model-timeout 4m -investigation-timeout 12m \
  -question "Which organizations are associated with tech.acme.example?" \
  -depth 8 \
  -max-paths-per-asset 3 \
  -max-expansions 120 \
  -guidance-rounds 2 \
  -format json ask |
  tee "$AI_TEST_ROOT/qa/guided-organizations.json"

jq '{
  goal,
  answer,
  mode:.search.mode,
  depths:[.matches[]|(.edges|length)],
  selected_paths:[.matches[]|{path_id,asset:(.nodes[-1].content.name // .nodes[-1].key)}],
  found:(.search.matches|length),
  expanded:.search.expanded_paths,
  alternatives:.search.alternative_matches,
  alternatives_skipped:.search.alternative_paths_skipped,
  truncated:.search.truncated,
  incomplete
}' "$AI_TEST_ROOT/qa/guided-organizations.json"
```

Expected, with the synthetic Acme data: three reachable Organization assets
at 2, 3 and 4 hops (subject to the model's relevance selection), a
`search.mode` of `guided`, stable nonempty `path_id` for each selected path,
and no reported truncation if the fixture and budgets fit.

For the ultimate-parent question:

```bash
"$AI_TEST_ROOT/bin/amass" ai \
  -config "$AI_TEST_ROOT/config.yaml" \
  -model qwen3:8b \
  -model-timeout 4m -investigation-timeout 12m \
  -question "What is the highest parent organization associated with tech.acme.example?" \
  -depth 8 -max-paths-per-asset 3 \
  -max-expansions 120 -guidance-rounds 2 \
  -format json ask |
  tee "$AI_TEST_ROOT/qa/guided-parent.json"

jq '{
  purpose:.goal.purpose,
  answer,
  selected:[.matches[]|{path_id,depth:(.edges|length),
    organization:(.nodes[-1].content.name // .nodes[-1].key)}],
  mode:.search.mode,
  truncated:.search.truncated,
  incomplete
}' "$AI_TEST_ROOT/qa/guided-parent.json"
```

Expected: the documented Acme Holdings Inc. ancestor, no sibling falsely
presented as a parent, and a witnessed path with three edges.

### Exercise visible partial-coverage reporting

Set a deliberately small expansion budget. This test performs only
**database reads**, never Internet enumeration.

```bash
"$AI_TEST_ROOT/bin/amass" ai \
  -config "$AI_TEST_ROOT/config.yaml" \
  -model qwen3:8b \
  -model-timeout 4m -investigation-timeout 12m \
  -question "Which organizations are associated with tech.acme.example?" \
  -depth 8 -max-expansions 1 -guidance-rounds 0 \
  -format json ask |
  jq '{mode:.search.mode,expanded:.search.expanded_paths,
       truncated:.search.truncated,reason:.search.reason,
       incomplete}'
```

Expected: `mode: "guided"`, `expanded: 1`, `truncated: true`,
`reason: "path expansion limit"`, and `incomplete: true`.

### Tests that require no LLM

The standalone Go tests build an alternate-route diamond, enforce
path-preserving limits, reject invented model-selected path IDs,
validate allowed priority labels and pending IDs, test cancellation, and
exercise a 15-hop graph.

```bash
go test ./internal/ai -run \
  'TestGuidedSearch|TestGuidedInvestigation|TestAdaptive' -v -count=1
```

Note: `-guidance-rounds 0` disables optional intermediate navigation
advice for the CLI, while the model is still required to interpret the
natural-language question and select relevant witnessed paths.
