# Adaptive natural-language OAM investigation (feature branch)

This milestone connects `amass ai ask` to bounded, schema-validated OAM graph
search without requiring a fixed sequence of model-predicted relationship hops.

## How it works

1. The configured model interprets the question as a typed `goal`, consisting
   of an indexed OAM starting-asset selector, desired destination asset types,
   an allowed graph direction, and an investigation purpose. No model-generated
   relation labels or fixed hop sequences are accepted in the goal.
2. The existing `resolve_asset` or `resolve_organization` tools identify
   the exact starting asset, and ambiguity is reported rather than guessed.
3. `SearchGraph` explores stored OAM edges in both directions as needed,
   enforcing the OAM taxonomy, traversal budgets, and a configurable depth.
   Paths may be returned at different depths, including beyond 10 hops.
4. For general `connected` queries, the model receives bounded, witnessed
   paths and selects only existing database asset IDs. Go rejects invented IDs.
   For `ultimate_parent`, direction-sensitive subsidiary logic first removes
   sibling and descendant routes, keeping documented terminal ancestors.
5. The answer cites witnessed OAM asset/edge IDs in the displayed paths.
   A Mermaid diagram is generated from those exact paths.
6. Missing root assets produce an explicit unresolved result and, for
   supported selectors, a passive collection *proposal* requiring separate
   permission. The `ask` command does not start collection.

**Important limitations:** Graph search currently retains one shortest
witnessed path per destination, not all possible paths. A shorter but
semantically irrelevant route can therefore hide a more relevant longer
route to the same destination. The semantic evaluator sees a bounded set
of candidate paths; it is not a replacement for independent attribution
verification. The reported `search.exhausted` refers only to the bounded
search, not to the complete OAM dataset or the real-world existence of
additional relationships. The ultimate-parent rule currently recognizes
the OAM `subsidiary` relation specifically. The classifier/inference
pipeline is still being generalized beyond organizations.

## Update local checkouts

Assumes the existing Amass + Asset Database feature branch checkout.

```bash
cd /path/to/asset-db
git switch feature/ai-investigation-inference
git pull --ff-only origin feature/ai-investigation-inference

cd ../amass
git switch feature/ai-investigation-inference
git pull --ff-only origin feature/ai-investigation-inference

# Local-only pairing, because the bounded edge API is on asset-db's branch.
go mod edit -replace=github.com/owasp-amass/asset-db=../asset-db

go test ./internal/ai/... -count=1
go test ./internal/ai -run 'TestAdaptive' -v -count=1
go vet ./internal/ai/...
CGO_ENABLED=0 go build -o "$AI_TEST_ROOT/bin/amass" ./cmd/amass
```

## Terminal acceptance: natural language with a local model

Run against your existing **disposable** seeded OAM test database. These
are real user-facing CLI tests, not mocked output.

```bash
AMASS="$AI_TEST_ROOT/bin/amass"
CFG="$AI_TEST_ROOT/config.yaml"

"$AMASS" ai -config "$CFG" -model qwen3:8b \
  -model-timeout 4m -investigation-timeout 12m \
  -question "Which organizations are associated with tech.acme.example?" \
  -depth 8 -format json ask |
  tee "$AI_TEST_ROOT/qa/adaptive-organizations.json" |
  jq '{goal, answer, target_depths:[.matches[]|(.edges|length)],
       selected_assets:[.matches[]|.nodes[-1].key],
       incomplete, searched:.search.visited_nodes, truncated:.search.truncated}'

"$AMASS" ai -config "$CFG" -model qwen3:8b \
  -model-timeout 4m -investigation-timeout 12m \
  -question "What is the highest parent organization associated with tech.acme.example?" \
  -depth 8 -format json ask |
  tee "$AI_TEST_ROOT/qa/adaptive-ultimate-parent.json" |
  jq '{goal, answer, target_depths:[.matches[]|(.edges|length)],
       selected_assets:[.matches[]|.nodes[-1].key],
       incomplete, truncated:.search.truncated}'

"$AMASS" ai -config "$CFG" -model qwen3:8b \
  -model-timeout 4m -investigation-timeout 12m \
  -question "What is the highest parent organization associated with tech.acme.example?" \
  -depth 8 -format text ask

"$AMASS" ai -config "$CFG" -model qwen3:8b \
  -model-timeout 4m -investigation-timeout 12m \
  -question "What is the highest parent organization associated with tech.acme.example?" \
  -depth 8 -format mermaid ask
```

With the synthetic fixture, the broad Organization query should be able to
choose stored Organization destinations at heterogeneous depths, while the
highest-parent query should select Acme Holdings Inc., without presenting
the sibling Acme Europe GmbH as a parent. The model may return an incomplete
result when it cannot interpret the question or evidence reliably: inspect
the JSON goal and graph search coverage to distinguish model errors from
missing data.

## Terminal acceptance: other OAM starting asset types

```bash
"$AMASS" ai -config "$CFG" -model qwen3:8b \
  -model-timeout 4m -investigation-timeout 12m \
  -question "What organizations are associated with the URL https://tech.acme.example/?" \
  -depth 8 -format text ask

"$AMASS" ai -config "$CFG" -model qwen3:8b \
  -model-timeout 4m -investigation-timeout 12m \
  -question "What FQDN assets are associated with Acme Technologies Ltd.?" \
  -depth 8 -format json ask | jq '{goal,answer,depths:[.matches[]|(.edges|length)],incomplete}'
```

The model should choose the exact indexed URL or Organization selector and
appropriate target types. The returned paths must be grounded in the fixture,
not guessed. Other OAM roots work with the same schema; only indexed selectors
or user-supplied database entity IDs can be safely resolved.

## Terminal acceptance: missing asset never triggers collection

```bash
"$AMASS" ai -config "$CFG" -model qwen3:8b \
  -model-timeout 4m -investigation-timeout 12m \
  -question "Which organizations are associated with nonexistent-subdomain.example.org?" \
  -depth 8 -format json ask |
  jq '{goal, answer, incomplete, collection, tool_calls}'
```

Expected if the model identifies the FQDN correctly: an unresolved answer,
`incomplete: true`, and a collection proposal; **no enumeration**.

## Regression on the deterministic graph oracle

```bash
"$AMASS" ai -config "$CFG" \
  -subject-type FQDN -subject-field name -subject-value tech.acme.example \
  -target-types Organization -depth 8 -format json search |
  jq '{depths:[.search.matches[]|(.edges|length)], truncated:.search.truncated}'
```

This is the unchanged deterministic baseline for comparing what the adaptive
model chooses against what the database actually contains.
