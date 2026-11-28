# Ownership gaps

Phase 2 starts with assets whose owner is not documented. The
`ownership_gaps` answer kind (planner answer `ownership_gaps`, Query lens
`ownership_gaps`, MCP `investigate` answer `ownership_gaps`) starts from an
Organization's controlled assets, or an FQDN's documented owner, and looks
outward for unattributed assets linked to that footprint by ownership
signals: shared registrant details, shared DNS verification tokens,
certificate key reuse, a private CA's issuing key, self-hosted name and
mail servers, SPF and DMARC delegation, web redirects into the
organization's names, reverse DNS in its namespace, the same DNS provider
account, shared analytics or tag identifiers, favicons and page content,
hosting and certificate co-listing, with a matching TLS (JARM)
fingerprint, page title and the organization's name as tiebreakers, and a
parked or for-sale page counting against ownership. The web fingerprints
are extracted by `internal/fingerprint`, which every collector (the HTTP
probes today, a web scraper later) uses so the stored values are the same.
SSH host key reuse is a strong signal compared only between addresses in
the organization's footprint and others. The SSH-Probes engine plugin
collects host keys in active enumeration, for in-scope public addresses
on port 22 unless the configuration's `scope.ports` leaves it out: it completes the SSH key exchange once per host key type
(Ed25519, ECDSA, RSA) and records each key's SHA-256 fingerprint and the
server's banner, and it never authenticates (no user name or credential is
sent).

Every signal, with what it finds, why it counts, the guards that stop it
misfiring and when it can still mislead, is defined in
`internal/semantics/signals.json` (each signal's owned-asset use) and documented in
[Ownership signals](SIGNALS.md), which is generated from that file. `amass
review signals` prints the same text, and `amass review proposals` shows the
rationale of each signal behind a proposal. Signals that compare values
(verification tokens, SPF and DMARC references, certificate key
identifiers, redirects, TLS fingerprints) use asset-db's value search (`repository.ValueFinder`) and are
skipped on an asset-db without it.

Assets documented as controlled by any organization are excluded; those are
partner signals, not gaps. Whether one is controlled is settled by a search
from the asset toward its owner, bounded by the owner step limit
(`LensLimits.OwnerSteps`, `-owner-steps`, MCP `owner_steps`). A search that
stops at that limit, or at the run's read limit, with paths left and no
owner found is inconclusive: the asset is left out of the candidates rather
than proposed, and listed in `undetermined_owners` (its type, label and how
many assets the search visited); the text answer names up to three. An
inconclusive search is never evidence that no one owns an asset.

A value held by more assets than the hub limit (see the main guard in
[Ownership signals](SIGNALS.md)) never counts. The report lists each value
a signal passed over this way in `hub_skips`: the value, what links it to
its holders (a relation label, or the property a search matched), how many
hold it, the limit and whether the database derived it (`internal/hubs`,
tuned by `internal/semantics/hubs.json`) or the fixed one applied. Each
signal's fixed limit, and whether the database may derive one for it, is
the `hub` parameter of its entry in `internal/semantics/signals.json`.
`options.hubs.derive: false`, or the lens `-fixed-hubs` flag, keeps every
limit fixed. The text answer names up to three of them. The
related-domains lens reports its own skips the same way (`lens.HubSkip`,
`hubCheck` in `internal/lens/hub_skips.go`).

## Scoring

The score ranks candidates and is not a probability. Each signal is
strong or supporting, with a weight, in the catalog:

- **propose:** two strong signals, or a strong signal and a different
  second signal, and exactly one relationship can record the owner;
- **review:** any strong signal, two signals of any strength, or more
  than one possible relationship;
- **weak:** a single supporting signal.

A tiebreaker never counts as the second signal, and a negative signal
keeps a candidate at review at most.

Review-only signals (`lens.ReviewOnlyKind`: kind `document`, from what an
organization's documents state, and kind `declaration`, from a bug-bounty
program's scope) add to the score and can raise a candidate to review, but
`AutoDecision` and the ownership model are computed without them
(`lens.WithoutDocumentSignals`, `review.withoutDocumentEvidence`), so they
never cause or help cause an automatic write.

The bug-bounty signal (`bug-bounty-scope`, matcher `bounty_program_scope`)
runs for every controlled FQDN: an `Account` of type `bug_bounty_program`
(stored by `engine/plugins/bounty`) with an `in_scope` edge to the name is
read once per search. `lens.BountyAnchor` must tie the
program to the subject (its website, `Account --contact--> ContactRecord
--url--> URL`, in the subject's namespace, its `bounty_program_name` equal to the subject's name
after case and white-space folding, the platform's `txt_prefix` record on the
apex, or a policy, acknowledgments, hiring or contact URL in the apex's
security.txt (the `URL --contact--> ContactRecord --url--> URL` layout read
by `readSecurityTxt`, with the field in the `url` edge's evidence) pointing at the program page
with every part of the handle in its path). Its other `in_scope` assets, at
most 200, become candidates; names under `cloud_providers.json` hosting
domains and the platforms' own hosts are skipped. The horizontal
`bug-bounty-scope` signal (supporting) uses the same anchor
(`bountyScopePivot`) over the apex and up to 200 of its `node` hosts.
Platforms and feeds are in `internal/semantics/bounty_platforms.json`.

A trained ownership model replaces these rules (see Learning from reviews).

## Attachment

The proposed relationship is the one OAM relationship that would attribute
the candidate's ownership chain to the subject, found from the semantics
table. It goes from the closest asset on the chain that can be attributed
to an Organization (`same_subject` or `controller` toward Organization, or
`controls` from Organization): for example `ContactRecord --organization-->
Organization` or `Organization --website--> URL`. The answer lists the
assets that relationship would bring under the subject. A candidate with no
such asset is reported without a proposal: recording its owner would need
new records.

The lens only proposes. What gets written is decided by the attribution
mode, during enumeration or by a reviewer.

## During enumeration (automatic)

Most users never ask these questions, so the engine's `AI-Attribution`
plugin answers them while an enumeration runs. It needs no model. Its
handlers note each arriving Organization, ContactRecord, DomainRecord,
IPNetRecord, AutnumRecord, FQDN, IPAddress and TLSCertificate. Once an
in-scope organization has been seen and the signals settle (5 seconds of
quiet, or at least once a minute while the enumeration is busy), a pass
runs the ownership-gap lens for each in-scope organization whose footprint
includes one of the enumeration's domains (`-d`), and then:

- writes each `propose` proposal as described under Review and write, with
  the reviewer recorded as `amass-ai (automatic)`;
- widens the session scope with the assets the relationship brings under
  the organization, and queues them for another look when the
  configuration's confidence for their type allows it, exactly as the
  Horizontals plugin does (nothing is widened when the expansion policy's
  confidence is above 100);
- leaves `review` proposals in the journal for a person.

Organizations an enumeration only touched, such as certificate
authorities and other vendors pulled into scope, are not attribution
roots: their footprints hold none of the enumerated domains.

A pending pass counts as session work, so `amass enum` does not finish
before it runs, and anything it adds is enumerated in the same session.

| Setting | YAML (`options.ai`) | Environment | Default |
| --- | --- | --- | --- |
| Mode: `auto`, `journal` (write nothing automatically) or `off` | `attribution` | `AMASS_ATTRIBUTION` | `auto` |
| Review journal | `journal` | `AMASS_REVIEW_JOURNAL` | `ai-review.jsonl` in the output directory |

The environment variables apply to the engine process. The journal is
always kept, because it is what makes a person's decision stick: a
proposal that was rejected or retracted is never written again, and one
still pending is written once its evidence reaches `propose`.

## Review and write

Advanced users can review the journal with `amass review`, which uses the
same journal by default (`-journal` overrides it); nothing is written by
these commands without a named reviewer. See [Lenses and review](../LENSES.md)
for every review command. `ask` records the gap answer's proposals (propose
and review decisions with exactly one attachment) in the journal, with
their signals and evidence lines. Asking again does not duplicate a
proposal; its ID is a hash of the relationship it would write.

```bash
amass ai -model qwen3:8b \
  -question "Which assets probably belong to OWASP Foundation but are not attributed to it?" ask
amass review proposals
amass review approve -proposal own-1a2b3c4d5e6f7a8b -reviewer jeff
amass review reject -proposal own-1a2b3c4d5e6f7a8b -reviewer jeff
amass review retract -proposal own-1a2b3c4d5e6f7a8b -reviewer jeff
```

`approve` re-reads both entities, checks that their types still match the
proposal and that OAM defines the relationship (`oam.ValidRelationship`,
SimpleRelation only), and writes it with asset-db's `CreateEdge` and a
`SourceProperty` named `amass-ai` whose confidence is the score times 100.
This is how Amass plugins record relationships, so the written edge looks
like collected data except for its source, and every later answer that
cites it shows `amass-ai`. When the relationship is already stored, nothing
is written and the existing edge is recorded. `reject` records the decision
and writes nothing. `retract` undoes an applied proposal, automatic or not:
it deletes the edge, or only its `amass-ai` source when another source also
recorded the relationship. The journal keeps every proposal, decision,
reviewer and edge ID.

No OAM relationship types are added: a proposal uses only relationships OAM
already defines.

An automatic write stays tied to its evidence. When an enumeration finishes
in `auto` mode, the engine re-checks every relationship automatic
attribution wrote: if a relationship its proposal's evidence was read from
no longer exists (a contact's shared phone was corrected, a record was
merged), the write is retracted and recorded with the reviewer
`amass-ai (re-check)`. Unlike a person's retraction, this one does not stop
the relationship from being written again: the next pass writes it if the
remaining evidence still supports it. Re-check retractions are not training
labels, and writes a person approved are never re-checked.

## Learning from reviews

The scoring weights above are a starting point. Every approve, reject and
retract a person records is a labeled example: approvals are positive,
rejections and retractions negative. No `amass-ai` decision (automatic
writes, model decisions, re-checks) and no model advice is a label, so the
model does not learn from its own decisions.

```bash
amass ai train -kind ownership
```

(`internal/ai/adjudicator.go`: ownership is one `AdjudicatorKind`, with
horizontal expansion; `amass ai train` trains every kind with at least 20
labels, and `amass ai status` reports each.)

trains a small logistic model (task `ownership_attribution`, features
`ownership-signals-v1`) and keeps it where the journal is: as a record of
the Asset Database journal's `models` topic when the journal is kept there,
so every engine on the database uses the newest, otherwise as
`attribution-model.json` beside the journal file. The engine loads it at
the start of each enumeration. Its
features are the counts of each signal kind and one feature per kind and
route (`identity:Phone`, `hosting:IPAddress`, `colisting:san_dns_name`), so
new signal kinds become features without code changes. Training needs at
least 40 reviewed proposals across 20 independent cases, holds a fifth out
for evaluation and refuses a model whose held-out precision is below 0.9.
The probability needed for an automatic write is set just above the highest
score any rejected or retracted proposal received, and never below 0.7.

With a model, it decides which attachable proposals are written, its
probability becomes the written confidence, and the journal records the
model ID and score. Without one, the rules above decide.

## Model advice

```bash
amass ai -model qwen3:8b review
```

asks the language model to recommend approve, reject or unsure for each
pending proposal without verified advice (`-proposal ID` for one,
`-scan-limit` to bound how many). The model sees only the proposal and its
numbered evidence. Its rationale must cite that evidence, and the same
citation checker that verifies cited summaries rejects advice that cites
nothing, cites unknown items or names assets its citations do not mention;
the model gets one retry. Advice is recorded in the journal and shown by
`proposals`. It never approves, rejects or writes anything, and it is
never a training label.
