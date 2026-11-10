# Ownership gaps

Phase 2 starts with assets whose owner is not documented. The
`ownership_gaps` answer kind (planner answer `ownership_gaps`, Query lens
`ownership_gaps`, MCP `investigate` answer `ownership_gaps`) starts from an
Organization's controlled assets, or an FQDN's documented owner, and looks
outward for unattributed assets linked by three kinds of signal. Each kind
is the attribution of the bridging edge in the semantics table:

| Signal | Bridging edge | Example |
| --- | --- | --- |
| identity | `attribute` from a controlled asset to a value another asset also has | another registrant contact with the same phone and address |
| hosting | `infrastructure` into a controlled asset | a name outside the namespace resolving into an owned netblock |
| co-listing | `shared` asset listing a controlled asset and the candidate (at most 10 listed) | a certificate naming both |

Assets documented as controlled by any organization are excluded; those are
partner signals, not gaps. An identity signal never passes through a value
that identifies no one: a redaction or privacy-service placeholder (phrases
in `internal/ai/semantics/placeholder_values.json`) or a value more than 50
assets carry.

## Scoring

The score ranks candidates and is not a probability. Identity counts most;
hosting and co-listing are suggestive, because a customer can be hosted by
another party or share its certificate.

- **propose:** two identity signals, or identity plus another kind, and
  exactly one relationship can record the owner;
- **review:** any identity signal, two kinds of signal, or more than one
  possible relationship;
- **weak:** a single non-identity signal.

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
runs the ownership-gap lens for each in-scope organization and then:

- writes each `propose` proposal as described under Review and write, with
  the reviewer recorded as `amass-ai (automatic)`;
- widens the session scope with the assets the relationship brings under
  the organization, and queues them for another look when the
  configuration's confidence for their type allows it, exactly as the
  Horizontals plugin does (nothing is widened when the config is `rigid`);
- leaves `review` proposals in the journal for a person.

A pending pass counts as session work, so `amass enum` does not finish
before it runs, and anything it adds is enumerated in the same session.

| Setting | YAML (`ai:` section) | Environment | Default |
| --- | --- | --- | --- |
| Mode: `auto`, `journal` (write nothing automatically) or `off` | `attribution` | `AMASS_AI_ATTRIBUTION` | `auto` |
| Review journal | `journal` | `AMASS_AI_JOURNAL` | `ai-review.jsonl` in the output directory |

The environment variables apply to the engine process. The journal is
always kept, because it is what makes a person's decision stick: a
proposal that was rejected or retracted is never written again, and one
still pending is written once its evidence reaches `propose`.

## Review and write

Advanced users can review the journal. `amass ai` uses the same journal by
default (`-journal` overrides it), and nothing is written by these commands
without a named reviewer. `ask` records the gap answer's proposals (propose
and review decisions with exactly one attachment) in the journal, with
their signals and evidence lines. Asking again does not duplicate a
proposal; its ID is a hash of the relationship it would write.

```bash
amass ai -model qwen3:8b \
  -question "Which assets probably belong to Colgate University but are not attributed to it?" ask
amass ai proposals
amass ai -proposal own-1a2b3c4d5e6f7a8b -reviewer jeff approve
amass ai -proposal own-1a2b3c4d5e6f7a8b -reviewer jeff reject
amass ai -proposal own-1a2b3c4d5e6f7a8b -reviewer jeff retract
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

## Learning from reviews

The scoring weights above are a starting point. Every approve, reject and
retract a person records is a labeled example: approvals are positive,
rejections and retractions negative. Automatic writes and model advice are
never labels, so the model does not learn from its own decisions.

```bash
amass ai train-attribution
```

trains a small logistic model (task `ownership_attribution`, features
`ownership-signals-v1`) and saves it as `attribution-model.json` beside the
journal, where the engine loads it at the start of each enumeration. Its
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
