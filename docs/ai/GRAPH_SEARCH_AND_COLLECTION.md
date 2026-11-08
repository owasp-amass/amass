# AI graph search and explicitly approved collection (feature branch)

This is an experimental, deterministic user-facing baseline. It supplements,
but does NOT yet replace, the existing fixed-hop `amass ai ask` planner.

## Commands

- `amass ai ... search`: **read-only**, schema-validated, bounded graph search.
  Accepts any registered OAM asset type as the starting subject. Returns one
  shortest witnessed path per matching destination, at varying depths. Stored
  OAM directions are preserved in text and Mermaid. `exhausted` only applies
  to the explored bounded neighborhood; it is not a claim about the complete
  database. All edges must be present in the OAM schema catalog.
- `amass ai ... collect-plan`: **read-only**, proposes an explicit collection
  scope and a deterministic approval identifier; does not contact the Internet.
- `amass ai ... collect`: starts a **single passive** session through the
  configured Amass engine, only after the matching plan identifier is supplied.
  It strips inherited collection scope and prevents active probing, brute
  forcing, alterations, recursion, and scope expansion. The resulting session
  token is returned. It does NOT automatically resume an AI investigation.

All commands use the configured Asset Database, except that `collect-plan`
does not inspect it. The CLI still initializes the configured database before
dispatching these operations. None of these commands requires an LLM model.

## Updating local source

The graph adapter requires the matching `asset-db` feature branch for
bounded database queries. In sibling checkouts:

```bash
cd /path/to/asset-db
git switch feature/ai-investigation-inference
git pull --ff-only origin feature/ai-investigation-inference

cd ../amass
git switch feature/ai-investigation-inference
git pull --ff-only origin feature/ai-investigation-inference

# Local-only pairing: do not commit this replacement.
go mod edit -replace=github.com/owasp-amass/asset-db=../asset-db
go test ./internal/ai/... -count=1
go test ./internal/ai/cli -v -run 'TestGraphSearch|TestCollection' -count=1
CGO_ENABLED=0 go build -o "${AI_TEST_ROOT}/bin/amass" ./cmd/amass
```

The path `../asset-db` assumes these two repositories are sibling
directories. Adjust it to your local layout. To remove the temporary module
replacement later: `go mod edit -dropreplace=github.com/owasp-amass/asset-db`.

## Manual graph-search acceptance tests

Use only an existing **disposable** AI test configuration and database.
The existing asset-db synthetic fixture contains:
`tech.acme.example`, `https://tech.acme.example/`, `Acme Technologies Ltd.`,
and `Acme Holdings Inc.`, connected through inverse `domain`, `website`
and `subsidiary` relationships.

```bash
AMASS="${AI_TEST_ROOT}/bin/amass"
CFG="${AI_TEST_ROOT}/config.yaml"

"$AMASS" ai -config "$CFG" \
  -subject-type FQDN -subject-field name -subject-value tech.acme.example \
  -target-types Organization -depth 8 -format text search

"$AMASS" ai -config "$CFG" \
  -subject-type FQDN -subject-field name -subject-value tech.acme.example \
  -target-types Organization -depth 8 -format json search |
  jq '{status, root:.search.root.key, depths:[.search.matches[]|(.edges|length)], truncated:.search.truncated, exhausted:.search.exhausted}'

"$AMASS" ai -config "$CFG" \
  -subject-type FQDN -subject-field name -subject-value tech.acme.example \
  -target-types Organization -depth 8 -format mermaid search

"$AMASS" ai -config "$CFG" \
  -subject-type FQDN -subject-field name -subject-value tech.acme.example \
  -depth 1 -format text search
```

With the matching synthetic fixture, the first two commands should return
an Organization at depth 2 and another at depth 3, using the actual stored
directions. The Mermaid output should begin `flowchart LR`. The final
command should show the immediate URL neighbor rather than guessing a full path.

The root `acme.example` fixture has its own URL and Organization pathway,
so this query should also succeed without requiring a `registration` edge:

```bash
"$AMASS" ai -config "$CFG" \
  -subject-type FQDN -subject-field name -subject-value acme.example \
  -target-types Organization -depth 8 -format text search
```

A missing subject should not trigger network collection:

```bash
"$AMASS" ai -config "$CFG" \
  -subject-type FQDN -subject-field name \
  -subject-value nonexistent-subdomain.example.org search |
  jq '{status, collection}'
```

Expected status: `not_found`; the response may include an
`approval_required` passive collection plan. No enumeration occurs.

## Explicit permission checks

Preview a plan, without network enumeration:

```bash
"$AMASS" ai -config "$CFG" \
  -subject-type FQDN -subject-field name -subject-value owasp.org collect-plan |
  jq .
```

Attempt an unapproved launch. It **must fail**:

```bash
"$AMASS" ai -config "$CFG" \
  -subject-type FQDN -subject-field name -subject-value owasp.org \
  -approve-collection incorrect-token collect
```

To test a **real authorized collection**, ensure the engine is running, use a
disposable test configuration, and explicitly review the approved scope.
Then capture the precise plan identifier:

```bash
PLAN_ID=$("$AMASS" ai -config "$CFG" \
  -subject-type FQDN -subject-field name -subject-value owasp.org collect-plan |
  jq -r '.plan.id')
printf 'Exact passive collection approval: %s\n' "$PLAN_ID"

# Starts an actual Internet collection session. Only execute on an
# authorized target when you intend to initiate real enumeration:
"$AMASS" ai -config "$CFG" \
  -subject-type FQDN -subject-field name -subject-value owasp.org \
  -approve-collection "$PLAN_ID" collect
```

Expected success: JSON with `status: "started"` and `session_token`.
Monitor the engine and database through your existing Amass tooling.
Session completion, automatic investigation resumption, and full provenance
reports are **not implemented yet**.

### Coverage caveats

- A depth limit is a search boundary, not evidence that longer paths do
  not exist.
- Search currently retains the shortest witnessed path for each destination
  and cannot enumerate every alternative route through cyclic or branching
  graphs.
- Graph search may be truncated due to per-node, total-edge, node, or
  match limits; inspect `truncated` and `reason`.
- Only direct, exact FQDN, IPAddress, Netblock, and AutonomousSystem
  selectors are eligible for this initial collection adapter.
- The existing natural-language `ask` planner still uses fixed three-hop
  patterns until adaptive planning is integrated.
