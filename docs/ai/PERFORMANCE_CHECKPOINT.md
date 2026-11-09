# AI investigation performance milestone: semantic grouping and zero-model fast path

This is the checkpoint to run **before** switching to the experimental
Docker Compose stack. Both the default Amass collection services and
the full Compose deployment can remain unchanged while these Go and
local Qwen3 tests are verified.

## Baseline

The six-path synthetic alternative-route investigation previously
measured approximately:

- Qwen goal planning: **98.112 seconds**.
- Database traversal: **0.005 seconds**.
- Source evidence inspection: **0.001 seconds**.
- Qwen path selection: **218.784 seconds**.

This is one observed local model run, **not** a baseline prediction for
future hardware, datasets, or prompts.

## Improvements

1. The final answer groups witnesses by both the destination asset ID
   **and** the stored OAM relationship semantics: edge labels,
   relation types, intermediate asset types, and traversal directions.
   Routes with different semantics are not silently merged.
2. When routes in a group are semantically equivalent, deterministic
   source-tag *coverage* selects the preferred witnessed route and
   preserves every alternative path ID in `answer_groups` and the full
   `evidence_dossier`. No source independence or factual confidence is
   inferred from tag counts.
3. When an explicit relationship goal is already satisfied at an
   earlier target node, farther target nodes are listed as context,
   not automatically returned as equally direct answers. This
   remains generic across OAM target types.
4. When there is only one primary candidate after grouping, the
   investigator skips Qwen path selection. Multiple genuinely
   different semantic candidates still require model evaluation.
5. A very narrow deterministic goal planner handles questions
   explicitly naming a single FQDN (including a two-label domain),
   an Organization target, and exact OAM relationship labels.
   The full taxonomy and indexed selectors validate the result.
   If this pattern is not unambiguous, Amass uses the existing model
   planner. This avoids Qwen transcribing schemas for requests that
   already explicitly specify the relevant entities and relations.
6. For questions not handled by this fast path, the model-planning
   prompt is shorter when the user explicitly names relationships;
   complete OAM schema validation still applies.

`trace[].detail` makes the optimization visible:
`deterministic_schema_grounding` on `goal_planning`,
and `deterministic_destination_grouping` on `path_selection`.

These optimizations do **not** create an automatic network scanner,
permit model-created OAM edges, or bypass path- and evidence-query
budgets.

## Local update and tests

```bash
cd /path/to/amass
git fetch origin feature/ai-investigation-inference
git merge --ff-only origin/feature/ai-investigation-inference
go mod edit -replace=github.com/owasp-amass/asset-db=../asset-db

go test ./internal/ai \
  -run 'TestExplicitOrganizationQuestionUsesZeroModelCalls|TestDeterministicGoal|TestAnswerGrouping|TestAdaptiveAskFindsParentWithoutSibling|TestAdaptiveQuestionUsesGenericRelationshipGoalAndSourceDossier' \
  -v -count=1

go test ./config ./internal/ai/... -count=1
go vet ./config ./internal/ai/...
CGO_ENABLED=0 go build -o "$AI_TEST_ROOT/bin/amass" ./cmd/amass

# Pure Go CPU benchmark: not a proxy for total model/network time.
go test ./internal/ai \
  -run '^$' -bench '^BenchmarkDeterministicExplicitOrganizationGoal$' \
  -benchmem -count=3
```

The key end-to-end Go test is
`TestExplicitOrganizationQuestionUsesZeroModelCalls`:
it uses the complete synthetic graph investigation and evidence
dossier but a model with no responses. It must return exactly one
direct Acme Technologies answer, keep parent and sibling context,
and make **zero** model calls.

`TestAnswerGroupingCollapsesEquivalentRoutesWithoutModelCall`
checks preferred source-tag coverage and retained alternatives.
`TestAnswerGroupingDoesNotCollapseDifferentRelationshipMeanings`
ensures that genuinely different paths remain eligible for model
interpretation.

## Repeat the local Qwen3 acceptance test

Reuse the existing disposable semantic fixture from
`asset-db/testdata/ai/semantic`. No Docker or fresh database is
necessary.

```bash
set -o pipefail
CGO_ENABLED=0 go build -o "$AI_TEST_ROOT/bin/amass" ./cmd/amass

"$AI_TEST_ROOT/bin/amass" ai \
  -dir "$AI_SEMANTIC_ROOT" \
  -model qwen3:8b \
  -model-timeout 4m \
  -investigation-timeout 12m \
  -question "Which organization is connected to tech.acme.example through website and domain relationships, and which witnessed route has better named source-tag coverage?" \
  -depth 8 \
  -max-paths-per-asset 3 \
  -format json \
  ask | tee "$AI_SEMANTIC_ROOT/fast-alternates.json"

jq '{
  goal,
  selected:[.matches[]|{
    path_id,
    organization:(.nodes[-1].content.name // .nodes[-1].key),
    edge_labels:[.edges[].label]
  }],
  preferred_and_alternates:.answer_groups,
  graph_candidates:(.search.matches|length),
  evidence_paths:(.evidence_dossier.paths|length),
  stages:[.trace[]|{stage,duration_ms,detail}],
  graph_incomplete:.incomplete,
  evidence_incomplete
}' "$AI_SEMANTIC_ROOT/fast-alternates.json"
```

Expected on the committed six-path fixture:

- The typed goal has `path_rule: all` and exactly the stored
  `domain` and `website` relationship constraints.
- All **six** eligible paths remain available in the database
  result and source dossier.
- The primary selected result is the direct Organization,
  **Acme Technologies Ltd.**, via the better-documented path.
- `answer_groups` identifies the weaker direct path as an
  alternative, and the parent/sibling as indirect context.
- `goal_planning` and `path_selection` show deterministic modes,
  avoiding both Qwen inference calls for this **specific** question.
- No source evidence becomes independently verified merely because
  it has multiple source tags.

There is **no fixed promise for total runtime**: graph size, storage
performance, model fallback, and other environmental factors still
matter. Run the commands and inspect their actual `trace` before
concluding how much time was saved.

## Legacy regression: keep model-based parent reasoning

```bash
"$AI_TEST_ROOT/bin/amass" ai \
  -config "$AI_TEST_ROOT/config.yaml" \
  -model qwen3:8b \
  -model-timeout 4m -investigation-timeout 12m \
  -question "What is the highest parent organization associated with tech.acme.example?" \
  -depth 8 -format json ask |
  tee "$AI_TEST_ROOT/qa/performance-regression-parent.json"
```

This question intentionally does NOT hit the narrow deterministic
FQDN->Organization relationship fast path. It still uses the model
to interpret the ultimate-parent intent, then applies the existing
OAM subsidiary-direction check. Its answer should continue to name
Acme Holdings Inc., exclude siblings, and qualify evidence support.

## Deployment sequencing

The feature-branch Compose overlay and model settings are committed
separately, but **do not start the Compose stack until the Go suite,
the local alternative-route acceptance test and the parent-query
regression have passed**. The original Compose services remain
unchanged and AI is opt-in.
