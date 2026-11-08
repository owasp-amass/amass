# Cost-aware AI classification for OWASP Amass

**Status:** Implementation design; a trained classifier, learned weights, benchmark results, and a production routing policy are not included in the initial AI prototype.

## Objective

Use lightweight **local classification** to avoid unnecessary generative-model calls and to route ambiguous findings to the appropriate investigation path. This preserves the existing architecture: deterministic candidate selection -> evidence gathering -> reviewable proposal -> optional human acceptance. Classification **never directly changes trusted OAM edges**.

## Inference cascade

1. **Deterministic rules:** Deduplicate, enforce types, reject impossible relations, extract evidence and known strong/weak signals. Zero model tokens.
2. **Candidate scoring:** A small CPU model scores a bounded feature vector: e.g. character n-gram similarity, LEI match, jurisdiction, parent-company declarations, registrant patterns, common infrastructure signals, source independence, and contradictory evidence. No hosted LLM tokens.
3. **Decision gate:** Reject obvious negatives; queue high-evidence candidates for policy validation and review; abstain on ambiguous cases. Disagreement, missing evidence, high-impact ownership assertions, or unsupported labels escalate to a configurable LLM.
4. **LLM investigation:** Only selected evidence subgraphs are sent to a configured model (Ollama or approved hosted provider). Structured output and all evidence IDs are checked in Go.
5. **Provenance and review:** Proposed relations remain separate from accepted OAM facts. The engine records model identity/version, calibration version, feature/extractor version, evidence IDs, decisions, and reviewer actions.

A classifier's score is **not** a defensible probability until calibrated on an independent, representative labeled validation set. Thresholds must be empirically selected for each task and cannot be universal. High-risk attribution still requires evidence-based validation and review.

## Classification tasks

| Task | Candidate labels | Feature examples | Action |
|---|---|---|---|
| Service classification | SaaS, hosting, CDN, email, unknown | DNS TXT/CNAME patterns, validated metadata | Classify product category |
| Organization entity matching | same-entity, different-entity, unknown | Legal IDs, jurisdiction, aliases, name similarity | Propose matching or abstain |
| Relationship type | subsidiary, org_unit, none, unknown | Registries, LEIs, corporate disclosures, contradictions | Propose OAM relation |
| Hosting control | first-party, third-party, unknown | Cloud account ownership, netblock and RDAP signals | Add review context |
| Intent routing | graph lookup, aggregate, temporal, complex | Question templates and verified structured parsing | Execute deterministic tools or escalate |

The candidate relation label and direction must be validated against OAM's `ValidRelationship` taxonomy before any proposal is stored.

## Provider-neutral implementation boundary

Start with a pure-Go interface, e.g.:

```go
type Classification struct {
    Label string
    Score float64 // raw or calibrated; explicit ScoreKind required
    ScoreKind string
    ModelID string
    FeatureVersion string
}
type Classifier interface {
    Classify(ctx context.Context, task string, features map[string]float64) (Classification, error)
}
```

Keep the classifier interface separate from the generative `ai.Model` abstraction. Begin with a transparent deterministic baseline and a CPU-friendly model (e.g. regularized linear classification or tree ensembles); an ONNX runtime can be an optional adapter, not a required or CGO-dependent package for standard Amass installation.

For text-only categories, a small local text classifier may also help. Vector similarity is useful for **retrieving candidates**, but is not ownership evidence.

## Economics

The main optimization is **LLM escalation rate**, not choosing an LLM with a smaller context window. Example only: if 10,000 candidate pairs arise and deterministic checks/classifiers resolve 9,800 safely, only 200 reach expensive generative analysis. That is a 98% reduction in candidate-level generative requests *in this hypothetical scenario*; real savings depend on data distribution, batching, model token usage, and measured quality.

Record candidates evaluated, rejected, abstained, escalated, token usage, latency, false positive rate, precision/recall by label, and dollar cost per validated proposal. Never tune solely for low cost at the expense of attribution precision.

## Evaluation data

The public, synthetic scenario source belongs in `owasp-amass/asset-db/testdata/ai`. Reproducible seeders should create isolated SQLite and PostgreSQL databases from those fixtures. The AI-specific evaluation harness and classifier tests belong in this repository. Private representative data, trained weights whose licenses are unclear, and generated binary database files **do not** belong in public Git history.

**Implementation prerequisites:** repository-backed seeder, evidence IDs on candidate pairs, calibrated classification thresholds, and a regression test suite containing shared-CDN/issuer negatives. In the current prototype, name-only candidate pairs are not enough to create valid inferences because proposal validation requires two independent supporting sources.
