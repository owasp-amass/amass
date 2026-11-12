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
within example.com?" compile directly; otherwise the planner chooses the
`hierarchy` answer kind (below). A goal that starts at an FQDN, asks for
FQDNs and follows only `node` edges is also run as a hierarchy listing, so
the listing is the same as `amass subs -names`.

## Answer kinds

The goal planner returns an `answer` field naming the kind of answer the
question asks for. The schema enum and the prompt text are generated from
the `answerKinds` registry in `answer_kinds.go`, and the model chooses by
meaning rather than by wording rules:

| Answer | Subject | Runs |
| --- | --- | --- |
| `paths` (default) | any | explore traversal and model path selection |
| `hierarchy` | FQDN | hierarchy traversal |
| `controlled` | Organization or FQDN | controlled lens |
| `third_party` | Organization or FQDN | third-party lens; from an FQDN, the full vendors lens (`amass lens vendors`) |
| `table` | Organization or FQDN | table lens (rows of one controlled type, a chain of columns) |
| `ownership_gaps` | Organization or FQDN | ownership gaps lens |
| `family` | FQDN | organization family lens (`amass lens family`) |
| `org_group` | Organization or FQDN | corporate group lens (`amass lens org-group`) |

`validateAnswer` rejects a kind that does not fit the subject, targets or
purpose (for example `controlled` with a type that the semantics table
cannot attribute to an owner), and the planner retries with the reason.
Registering a new kind makes it available to the model with no other
change.

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
   that leads back into the footprint is the subject's own. The subject's
   own owner (for an FQDN subject) is found breadth first, a level at a
   time, because many URLs or certificates can share its name.
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
University?" compile to this lens directly; other wordings reach it through
the planner's `third_party` answer kind. When nothing is documented
as controlled by the subject, the answer says so rather than listing
unrelated connections.

From an FQDN subject the answer is the vendors lens described in
[LENSES.md](../LENSES.md#vendors): it adds the organizations behind the
domain's verification tokens and the mail senders in its SPF record, sets
the institution and its affiliates apart using the family lens, and lists
the SPF includes and verification-like records nothing recognizes.

`"lens": "family"` (subject an FQDN) answers with the organization family
of an enumerated domain, as `amass lens family` does: the organizations that
are its institution, departments or affiliates with the evidence for each,
the networks serving its names, and the other domains those networks serve.
Questions such as "Which organizations make up jhu.edu's institution?" reach
it through the planner's `family` answer kind. Nothing is written.

`"lens": "org_group"` (subject an Organization, or an FQDN for its main
organization) answers with the corporate group, as `amass lens org-group` does:
the ultimate parent and every subsidiary and unit below it. Questions such as
"Who owns Spotify USA Inc.?" reach it through the planner's `org_group` answer
kind. Nothing is written.

`"lens": "controlled"` (subject an Organization or FQDN) lists the assets
attributed to the subject by that same footprint walk, optionally only those
of `target_types`, each with the witnessed path that attributes it (for
example Organization <- ContactRecord <- registrant AutnumRecord <-
registration AutonomousSystem). With target types set, the walk only expands
asset types that can still lead to one, so an ASN question does not read the
organization's URLs and hostnames. The planner reaches it through the
`controlled` answer kind.

`"lens": "table"` builds a table from the controlled footprint: one row per
controlled asset of the single type in `target_types`, and one column per
entry of `columns`. Columns form a chain, each derived from the previous
column (the first from the row):

- `{"type": T, "role": ""}` is the nearest asset of type T, reached through
  `same_subject` edges (not the hierarchy) in either direction and
  `infrastructure` edges forward, up to three steps: a URL reaches its IP
  address through its domain name and that name's DNS records.
- `{"type": "Organization", "role": "controller"}` is the party that
  controls or operates the previous cell's asset, found as for the
  third-party lens; cells the subject controls read "(self)".

"Please create a table with each website, its IP address, and hosting
provider within the Colgate University organization" plans to rows `URL`
with columns `IPAddress` then the controlling `Organization`.

The planner's schema allows exactly these two column shapes. Planned chains
are repaired before validation rather than rejected: a controller column
naming another type is read as a column of that type, repeated columns
collapse, a leading column that repeats the row is dropped, and columns for
asset types the question names are added before the first controller.
Cells show the fields a stored relation carries, so a service reached over
a port relation reads `https (443/tcp)`.

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
