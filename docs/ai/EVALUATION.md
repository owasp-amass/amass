# Question evaluation set

Every question a user reports becomes a case in
`internal/ai/questions/questions.json`, not a code path. A fix counts when
the new case and every earlier one pass without code that matches the
question's wording.

## A case

```json
{
  "id": "colgate-asn",
  "question": "Which ASN is associated to the Colgate University organization?",
  "expect": {"answer": "controlled", "subject_type": "Organization", "max_model_calls": 1},
  "offline": {
    "fixture": "campus",
    "planner_replies": ["{...the goal a correct planner returns...}"],
    "checks": {"results_include": ["1289"], "results_exclude": ["54113"]}
  },
  "live": {"results_include": ["1289"]}
}
```

- `expect` applies to both runs: the answer kind (`paths`, `route`,
  `hierarchy`, `controlled`, `third_party`), subject type, purpose and the
  most model calls allowed.
- `offline` runs in CI against a fixture graph defined in `eval_test.go`.
  `planner_replies` replay what a correct planner returns, so CI checks
  everything after the model's choice. A case without replies must not call
  the model.
- `live` holds checks for a run against a real Asset Database.
- Checks: `answer_contains`, `answer_excludes`, `results_include` and
  `results_exclude` (labels of matched assets, vendors and controlled
  assets), `min_results` and `complete`. Comparisons ignore case.

## Running

CI runs every offline case (`TestQuestionEvaluationSet`). To measure a real
model against your Asset Database:

```bash
amass ai -model qwen3:8b eval                      # embedded set, text table
amass ai -model qwen3:8b -format json eval         # JSON results
amass ai -model qwen3:8b -eval-cases my.json eval  # your own set
```

In amass-docker-compose:

```bash
docker compose run --rm ai eval
```

`eval` exits non-zero when any case fails. A live failure points at the
model (wrong answer kind or subject), the data (a missing relationship) or
the code; the per-case failures say which check failed.
