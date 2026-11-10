# Query: the single investigation representation

Every `amass ai ask` investigation is now a **Query**: one JSON document that
says what to read from the Asset Database. The four question routes in
[INTENT_ROUTING.md](INTENT_ROUTING.md) each compile to a Query; a single
validator checks it against the OAM catalog, and a single executor runs it.

```text
question ──► CompileQuestion ──► Query ──► ValidateQuery ──► AskQuery ──► Investigation
               (deterministic                (OAM catalog,     (resolve root, search,
                compilers, then               no database)      evidence, answer)
                model planner)
-query file ───────────────────► Query ──┘
```

## Fields

| Field | Meaning |
| --- | --- |
| `version` | Schema version, currently `1` |
| `question` | The user's wording, if any; explore uses it to guide path selection |
| `subject` | The root asset selector, as in `TypedPlan` and `InvestigationGoal` |
| `traversal` | `explore`, `route` or `hierarchy` (below) |
| `target_types` | OAM asset types the answer is about; empty means any (explore only) |
| `direction` | Stored edge direction for explore: `both`, `in` or `out` |
| `purpose` | `connected` or `ultimate_parent` (explore only) |
| `relationships`, `path_rule` | Explore path constraints; for a route, the transition behind each hop |
| `hops` | The exact route, for `route` |
| `exclude_root` | Omit the root from a hierarchy listing (subdomains, not FQDNs) |
| `source` | Which compiler produced it: `fqdn_hierarchy`, `typed_relation`, `organization_relation`, `model_goal` or `caller` |

## Traversals

| Traversal | What it reads | Needs a model | Answer |
| --- | --- | --- | --- |
| `hierarchy` | FQDN `node` edges below the root | No | Every witnessed FQDN, sorted |
| `route` | Exactly the listed hops, in order (up to 3) | No | Every witnessed destination |
| `explore` | Any schema-valid path within limits, filtered by `relationships`/`path_rule`/`purpose` | Yes | Paths the model selects from those witnessed |

A hierarchy inventory is listed by Go and never sent to the model, so it is
bounded by `-max-names` (default 1000, at most 10000) rather than the smaller
model-context limits. Subdomain wordings such as "What are all the subdomains
within example.com?" compile directly. When the model planner produces a goal
that starts at an FQDN, asks for FQDNs and either uses only `node` edges or
comes from a subdomain or DNS namespace question, it is promoted to the
hierarchy traversal, so the listing is the same as `amass subs -names`.

## Lenses

A lens answers a fixed question about the subject from the reviewed
relationship attribution table (`RELATION_SEMANTICS.md`) instead of a
traversal. It needs no model and its answer is built in Go.

`"lens": "third_party"` (subject an Organization or FQDN) lists the outside
parties that the subject's controlled assets depend on:

1. **Controlled footprint.** Starting from the subject (and, for an FQDN, the
   Organization documented as its registrant), follow `same_subject` edges
   (FQDN `node` only downward), `controls` edges forward and `controller`
   edges backward. Another Organization is entered only through `controls`
   (subsidiary, org_unit), and a Person is never expanded, so a shared
   contact cannot merge two footprints.
2. **Dependencies.** From each controlled asset, a `third_party` edge is a
   dependency on the asset it reaches; an `infrastructure` edge is a
   dependency too, and that asset's own `third_party` edges also count (a
   service's provider and software); a `shared` edge into a controlled asset
   (a certificate listing a controlled name) counts its `third_party` edges
   (the issuer). Edges marked `vendor: false` in the table (abuse desks,
   RDAP, WHOIS and OCSP endpoints) are skipped.
3. **Who controls each dependency.** A best-first search follows ownership
   attribution (`same_subject`, hierarchy edges only upward, `controller`
   forward, `controls` backward) to the closest Organization, ordered by the
   type distance to an Organization computed from the table, so a netblock's
   registration record is read before its addresses. Without an
   Organization, the operator of a network carrying the asset (an incoming
   `infrastructure` edge with purpose `network`, such as an announcing AS)
   is tried, then the most registration-like asset reached. A dependency
   that leads back into the footprint is the subject's own.
4. **Groups.** Vendors are grouped by the purpose of the dependency edge and
   the type depended on, for example "DNS: IP addresses" (hosting networks),
   "DNS: FQDNs" (CNAME, NS and MX targets), "Registration: contact records"
   (registrars) and "Certificate: contact records" (certificate
   authorities).

Nothing in the lens names an OAM type or relationship label: a new OAM
relationship takes part as soon as its row in the semantics table is
annotated (a test adds a hypothetical CloudResource and CloudAccount this
way).

Questions such as "Which third-party vendors are used by Colgate
University?" compile to this lens directly; model goals for vendor questions
about an Organization or FQDN are promoted to it. When nothing is documented
as controlled by the subject, the answer says so rather than listing
unrelated connections.

`"lens": "controlled"` (subject an Organization or FQDN) lists the assets
attributed to the subject by that same footprint walk, optionally only those
of `target_types`, each with the witnessed path that attributes it (for
example Organization <- ContactRecord <- registrant AutnumRecord <-
registration AutonomousSystem). With target types set, the walk only expands
asset types that can still lead to one, so an ASN question does not read the
organization's URLs and hostnames. A model goal that asks which assets of
attributable types an Organization has (not other Organizations or People,
and not a vendor question) is promoted to this lens.

Organization names are resolved by exact match, also trying lower, upper and title
case and a final period, never by similarity.

`ValidateQuery` rejects any subject selector, type, label, relation type or
hop that is not in the OAM catalog, and any field that does not belong to the
chosen traversal (for example `hops` on an explore query). Validation never
touches the database, so an invalid query fails before any graph read.

## CLI

Print the Query a question compiles to, without opening the database:

```bash
amass ai -question "Which subdomains are associated with owasp.org?" plan
```

Narrow, explicit questions compile without a model. Other questions need
`-model` (or `AMASS_AI_MODEL`) so the goal planner can run.

Run a saved or hand-written Query. Route and hierarchy queries need no model:

```bash
amass ai -question "Which subdomains are associated with owasp.org?" plan > subdomains.json
amass ai -query subdomains.json -format text ask
```

```json
{
  "version": 1,
  "subject": {"type": "Organization", "name": "Acme Holdings Inc."},
  "traversal": "route",
  "target_types": ["URL"],
  "direction": "both",
  "purpose": "connected",
  "hops": [
    {"direction": "out", "label": "subsidiary", "relation_type": "SimpleRelation", "destination_type": "Organization"},
    {"direction": "out", "label": "website", "relation_type": "SimpleRelation", "destination_type": "URL"}
  ],
  "source": "caller"
}
```

`-query -` reads the Query from standard input. Unknown JSON keys are
rejected. The JSON output of `ask` now includes the executed `query`.

## Go API

- `Agent.CompileQuestion(ctx, question)` returns a validated Query.
- `Agent.AskQuery(ctx, q, opts)` validates and executes one.
- `Agent.AskAdaptive(ctx, question, opts)` is `CompileQuestion` then
  execution, with the same trace stages as before.

Every model reply that drives execution is schema-constrained when the
provider supports it (Ollama `format`, Anthropic forced tool use):

| Call | Schema | Allowed values |
|------|--------|----------------|
| Goal planner | `investigation_goal` | whole OAM transitions from the catalog |
| Path selection | `path_selection` | witnessed candidate path IDs, at most 5 |
| Navigation advice | `navigation_priorities` | allowed labels and pending frontier IDs, at most 5 each |
| Relation inference | `relation_proposal` | the candidate's endpoints, allowed labels or `none`, its evidence IDs |

A schema narrows what the model can say; Go validation still decides what is
accepted. Route queries (explicit hops) replace the earlier hop-only planner.
