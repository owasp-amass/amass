# Schema-grounded OAM investigation intents

The AI investigation system separates question interpretation from graph
execution. The Open Asset Model schema catalog is authoritative for supported
asset selectors, relation labels, relation types, and stored directions.

## Routing order for amass ai ask

1. FQDN hierarchy: narrowly recognized subdomain inventory questions follow
   outgoing FQDN --node/SimpleRelation--> FQDN hierarchy edges.
2. Typed relationship inventory: questions explicitly naming a subject, target
   OAM asset type and relationship labels compile into up to three exact,
   directed, taxonomy-validated hops. Forward and reverse traversal work.
   Competing valid schema routes fail closed.
3. Explicit organization relationship: existing narrow FQDN-to-Organization
   grounding for user-named labels remains available.
4. Semantic goal planning: ambiguous questions, ultimate parent, ownership
   inference and evidence-quality comparison use the configured LLM and
   strict schema validation.

All routes use read-only stored graph data; neither source-tag counts nor LLM
claims establish legal ownership.

## Cross-type explicit relationship questions

The deterministic typed relationship grammar is deliberately narrow:

    Which <OAM type> assets are connected to <exact subject>
      via <OAM label> [and <OAM label> ...] relationships?

Equivalent What, List, Show, associated with, linked to, through, and using
forms are accepted. Labels must exist in the authoritative catalog.
Target names are derived from registered OAM asset types; extra aliases cover
FQDN, URL, IPAddress, TLSCertificate and AutonomousSystem.

For example, when the taxonomy contains the relevant transitions:

    docker compose run --rm ai \
      -question "Which URLs are connected to tech.acme.example via domain relationships?" \
      -format text ask

    docker compose run --rm ai \
      -question "Which organizations are connected to tech.acme.example via domain and website relationships?" \
      -format json ask

The second query follows two incoming stored edges if the schema provides
Organization --website--> URL --domain--> FQDN. This is a witnessed association,
not proof of corporate ownership.

An explicitly typed exact indexed selector may disambiguate a named subject,
for example Organization:name="Acme Technologies Ltd." in the user question.
Only selector fields returned by the OAM catalog are accepted.

## Bounded execution and incomplete searches

The typed executor requests exact labels and directions from the database
server-side on every hop. It also validates exact relation types, edge
orientation and destination types. A path with unknown semantics is rejected.

- depth limits hops.
- max-matches limits distinct terminal assets.
- max-expansions limits expanded paths.
- Global policy caps limit nodes, edges, and per-node fetches.
- An independent intermediate-frontier cap prevents dense paths from
  exhausting memory.

Results preserve witnessed path IDs, evidence dossiers, and the existing
search.truncated, search.reason and incomplete fields. Truncated searches
report the matches actually seen, never claim complete coverage, and
do not turn absence from the bounded search into universal absence.

Text answers include the terminal assets and explicit stored path
orientation. JSON includes paths and provenance; Mermaid renders the graph.

## Current limits

The typed compiler is a reusable schema-grounded execution specialization,
not an ontology-wide deterministic natural-language parser. Bare questions
such as "Who owns this?" or "What else is associated?" still use the LLM.
Additional intent families can be compiled into the same executor once their
semantics and ambiguity rules are tested.

Regressions cover incoming URL association, FQDN/URL/Organization two-hop
routes, alternate relation types, noisy graph neighborhoods, bounded
partial results, and rejection of invented or ambiguous relations.

 
## Understanding empty multi-hop answers

A completed typed search with zero results means that **no witnessed path
matching the exact requested edge labels, relation types and directions**
was returned by the bounded database reader. It does NOT mean there are no
assets of the destination type or that no other association exists.

In JSON, `search.hop_diagnostics` now exposes the attempted hops,
including `queried_paths`, `returned_edges`, `accepted_edges`, and
`output_paths`. If an intermediate hop produces zero destinations,
subsequent hops are skipped and the text answer identifies the first empty
transition. For example, a request for Organizations connected to a FQDN
via `domain` and `website` first traverses the **incoming**
`URL --domain--> FQDN` relationship; without a witnessed URL candidate,
the incoming `Organization --website--> URL` hop cannot run.

To inspect the root's stored edge labels independently, first obtain the
root entity ID from `asset_resolution.candidates[].asset.id`. On an
isolated PostgreSQL deployment, perform a **read-only** check:

```bash
docker compose exec -T assetdb sh -c '
  psql -U postgres -d "$AMASS_DB" -P pager=off -c "
    SELECT CASE WHEN e.to_entity_id=1 THEN '\''in'\''
                ELSE '\''out'\'' END AS direction,
           e.label, count(*) AS edges
    FROM public.edge e
    WHERE e.to_entity_id=1 OR e.from_entity_id=1
    GROUP BY 1, 2 ORDER BY 1, 2;"
'
```

Replace ID `1` with the entity ID returned by resolution; it is not
stable across deployments. This check distinguishes genuinely absent stored
edges from a mistaken assumption that FQDN collection automatically creates
URL and Organization relationship assets. It does not collect new data.

The graph result intentionally avoids filling in missing URL or
Organization relationships from an LLM response.

## Natural-language OAM asset names

Users should not have to know an internal Open Asset Model asset type to
ask an investigation question. `intent_vocabulary.go` provides a curated,
schema-filtered alias registry. It is used by both the deterministic typed
relation compiler and the semantic goal-planning prompt.

| User terms | Registered OAM type | Interpretation |
| --- | --- | --- |
| FQDNs, hostnames, DNS names | `FQDN` | Hostname assets |
| Subdomains, subdomain names | `FQDN` | **Hierarchy constraint:** stored `node` relationships; apex is excluded from subdomain-only inventory |
| IPs, IP addresses, IPv4 addresses, IPv6 addresses | `IPAddress` | Network address asset |
| Companies, businesses, corporations, firms, legal entities | `Organization` | Organization asset; not proof of corporate registration |
| Physical, postal, street addresses | `Location` | Geographic/address asset |
| TLS, SSL or X.509 certificates | `TLSCertificate` | Certificate asset |
| Networks, subnets, IP ranges | `Netblock` | Address range/block |
| ASNs, autonomous systems | `AutonomousSystem` | Autonomous system asset |

The bare word **"addresses"** is intentionally ambiguous: it can mean
`IPAddress` or `Location`. The typed compiler evaluates candidates
against the **requested OAM relationship labels and traversal topology**.
It uses a deterministic mapping only if exactly one registered candidate
type has exactly one valid route. If multiple meanings remain viable, the
query falls back to semantic planning rather than silently choosing one.

The word **"domain"** is similarly not forced to `FQDN`: a question can
refer to the FQDN hierarchy, DNS records, or `DomainRecord` registration
assets. The explicit relation and context determine how it should be
interpreted. Ambiguous questions retain model-planning and schema
validation.

The alias registry cannot register new asset types, selectors, or OAM
relationships. Synonyms do not grant permissions and cannot transform
an association into a verified ownership claim.

### Examples

```bash
# "subdomains" intentionally excludes the apex from the returned list
docker compose run --rm ai \
  -question "Which subdomains are under owasp.org?" -format text ask

# Companies → Organization, with exact registered edge semantics
docker compose run --rm ai \
  -question "Which companies are connected to owasp.org via domain and website relationships?" \
  -format json ask

# Addresses can mean IPAddress when a unique dns_record path exists
docker compose run --rm ai \
  -question "Which IP addresses are connected to owasp.org via dns_record relationships?" \
  -format json ask
```

These queries still return only assets and relationships already collected
in the database. Vocabulary recognition does not manufacture missing
edges or authorize new discovery.
