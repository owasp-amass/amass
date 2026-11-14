# Implementation notes, OAM semantics and follow-up patches

## Package layout

The AI code is split by what each part does. A package may import only the
packages above it in this list, so the layers cannot form cycles:

| Package | Holds |
| --- | --- |
| `internal/ai/semantics` | The data files (relation semantics, vocabularies, lens rules, fingerprints) and the code that loads them. New behavior is added here as data, not code. |
| `internal/ai/graph` | The read-only view of the asset database: `Asset`, `Relation`, the `Graph` interface and its bounded readers, the schema and semantics catalogs, and naming helpers. |
| `internal/ai/llm` | Model providers (Anthropic, Ollama), structured output, tool specifications and usage metering. |
| `internal/ai/lens` | Lenses computed in Go without a model: vendors, family, corporate group, group vendors, services, network infrastructure, duplicates, identity, person-named organizations, ownership gaps and signals. |
| `internal/ai/review` | The proposal journal, evidence bundles, model ownership advice, rechecks, and the code that applies accepted merges, identity corrections and removals. |
| `internal/ai` | Question planning and adaptive investigation: the `Agent`, query compilation, guided search, routing, narratives and the answer kinds that dispatch to the lenses. |
| `internal/ai/oamrepo` | The `graph.Graph` implementation over Amass's asset database (SQLite, Postgres and Neo4j) and the writers used by review. |
| `internal/ai/cli`, `internal/ai/mcp` | The `amass` subcommands and the MCP server. |
| `internal/ai/classify` | Evidence classifiers and their training. |
| `internal/ai/aitest` | In-memory graphs and fixtures shared by the tests; imported only by tests. |

New work goes in the package its job belongs to: a new lens in `lens` with
its rules in `semantics`, a new kind of proposal in `review`, a new provider in
`llm`, and only the wiring (answer kind, `Agent` method, CLI command) in `ai`
and `cli`. Engine plugins that collect data for the lenses stay under
`engine/plugins`.

## Module integration

The core packages have no external dependencies. The `graph.Graph`
interface is implemented by `internal/ai/oamrepo.Adapter`, which uses actual
`repository.Repository` methods:

- `FindEntityById(ctx, id)`
- `FindEntitiesByType(ctx, atype, since, limit)`
- `IncomingEdges(ctx, entity, since, labels...)`
- `OutgoingEdges(ctx, entity, since, labels...)`
- `FindEntityTags(ctx, entity, since, names...)`
- `FindEdgeTags(ctx, edge, since, names...)`

The existing Amass `tools.OpenGraphDatabase(cfg)` is used to open the configured
database, exactly as the `assoc` subcommand does. This avoids a forked database
schema. `oam.ValidRelationship(...)` checks that a proposed edge label is
allowed by the taxonomy. **No automatic edge insertion is implemented.**

## Tool and model flow

1. Agent receives question; issues model request with a small set of typed tools.
2. Model requests one or more tool calls.
3. ToolRunner validates arguments and executes the repository adapter.
4. Tool results return ID-indexed evidence under output-size limits.
5. The model summarizes, optionally using Mermaid or Markdown tables.
6. CLI returns the answer and complete JSON tool observations.

LLMs can hallucinate in final prose. Review observations, and add a strict
citation verifier before using this for automated decisions.

## Inference flow

1. Deterministic candidates from normalized names (initial implementation).
2. Re-hydrate all submitted IDs and tags from the actual Asset Database.
3. Filter predicates through OAM `ValidRelationship`.
4. Model proposes a structured relation and lists exact evidence IDs.
5. Validate endpoint IDs, taxonomy and at least two distinct SourceProperty
   values drawn from retrieved tags.
6. Append proposal to a local journal. Human review is a separate action.

The model confidence value is **not calibrated** and should not be interpreted
as an empirical probability. A future assessor can use held-out labeled
examples to calibrate scores and thresholds.

The initial selector is a proof of integration, not a general purpose
entity-resolution algorithm. Subsidiary inference may require legal registry
records; duplicate or near-identical names alone are weak evidence. OAM
currently supports `Organization -> subsidiary -> Organization` and
`Organization -> org_unit -> Organization`. An alias/same-as concept should be
modeled explicitly, likely in a separate entity-resolution schema, rather than
misusing `subsidiary`.

## Production changes recommended in asset-db

`repository.Repository` currently has no pagination/limit arguments for
`IncomingEdges` or `OutgoingEdges`. Add new **additive** methods rather than
breaking current implementations:

```go
// Example proposed API, not yet implemented in asset-db.
type EdgePager interface {
    IncomingEdgesPage(ctx context.Context, id string, since time.Time,
        labels []string, cursor string, pageSize int) (edges []*types.Edge, next string, err error)
    OutgoingEdgesPage(ctx context.Context, id string, since time.Time,
        labels []string, cursor string, pageSize int) (edges []*types.Edge, next string, err error)
}
```

Implement consistent indexed keyset pagination in SQLite and PostgreSQL;
apply database statement timeouts, cancellation, row/byte budgets, and
transaction/snapshot semantics. Consider adding a safe `FindPaths` API for
bidirectional search and a query-plan cost estimator.

## Security work before deployment

- Authorize every query against the user's allowed root Organizations, and
  enforce authorized traversal **on every visited node**, not just the start.
- Gate external model egress with explicit consent and data redaction.
- Use a reviewed prompt-injection defense and contextual evidence boundaries.
- Add per-session token and cost budgets and concurrent-work admission control.
- Add independent evidence-source IDs based on source records, not user text.
- Avoid logging unredacted data returned by model calls or graph tools.
- Add journal signing/transactions or persistent database tables for concurrent
  multi-process writers and tamper-evident review history.
- Add actual event-to-candidate queue integration with idempotent work keys,
  backpressure, retries, and deadlines outside the collection hot path.
- Test the MCP server against current MCP inspectors/clients; the current
  implementation supports the 2025-11-25 legacy stdio flow, not 2026-07-28.

## Evaluation

Add a curated synthetic and real-world (properly licensed) OAM corpus with
positive and negative attribution examples, and run tests for:
independent source counting; shared-CDN false positives; cross-tenant traversal;
malicious TXT records; huge fan-out; stale evidence; long model responses;
model tool-call loops; resource cancellation; and result truncation.
