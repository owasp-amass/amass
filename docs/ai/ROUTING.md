# Cost-aware classification routing (development preview)

The AI initiative supports an **optional**, provider-independent linear classifier for candidate triage. The classifier runs locally, before any generative request. Classification output is **not** a finding and never writes an OAM relationship.

## How it works

- The existing Amass repository adapter retrieves evidence IDs and typed source properties. A source property `Name()` is used as its identity; confidence **is not** part of that identity. Multiple source observations with the same name count only once.
- `ExtractProvenanceFeatures` derives bounded, numeric input (`oam-provenance-v1`) from repository-verified evidence IDs. It does **not** interpret raw DNS, certificate, or web content as instructions.
- `Inferrer.AnalyzeRouted` checks that at least two attributed source IDs exist before attempting classification or using a generative model. Separate names may still refer to correlated underlying feeds; this is a coarse gate, not verified independence.
- A local `review` decision can be recorded as a **triage** event if explicitly enabled. It has no predicate, no ownership claim, and is not an accepted graph edge.
- An uncalibrated `skip` prediction always escalates instead of dropping candidates. The CLI does not enable classifier-based automatic skipping. Calibrated skips are available only as an explicit *Go API policy* and need independent calibration and safety review.
- Ambiguous candidates are escalated to the configured generative model, with structured proposal validation. The model still cannot write OAM edges.

## CLI (optional)

Provide a JSON linear classifier model matching `task=organization_relation` and `feature_version=oam-provenance-v1`. Model files are local; model weights are not bundled or claimed to be trained/calibrated.

```sh
amass ai -model YOUR_GENERATIVE_MODEL -classifier-model /models/org-relation.json \
  -classifier-review -candidate /data/candidate.json -journal /data/proposals.jsonl infer
```

`-classifier-review` is opt-in. Without it, positives/negatives that need contextual interpretation escalate to the generative model. To scan using the classifier, pass the same `-classifier-model` and optional `-classifier-review` flags with `scan`; use a bounded `-scan-limit`.

## Evaluation

The `classify.Evaluate` helper reports correct/incorrect labels, `skip`, `review`, and `escalate` counts, and `UnsafeSkips` (ground-truth positives mistakenly skipped). Its unit tests demonstrate deliberately erroneous predictions to exercise the accounting.

**No accuracy, savings, or calibration claims are made** from the four synthetic classifier unit cases or the existing 15-asset fixture. A larger independently labeled dataset, held-out evaluation, task-specific precision/recall, and a stated maximum false-negative threshold are prerequisites for automatic negative skipping.

## Scope and caveats

- Candidate source IDs are checked against the database in `amass ai infer`; file-supplied evidence is not blindly accepted.
- The `scan` operation currently uses normalized organization names to select candidate pairs. It is *not* intended as evidence of common ownership.
- Journal events are append-only and local. The current journal is not a transactional multi-process queue. A durable worker and reviewer UI remain future work.
- The `asset-db` fixture lives under `testdata/ai`, with SQLite integration tests and a PostgreSQL CI service. Fixture database files are generated in disposable locations and excluded from Git.
