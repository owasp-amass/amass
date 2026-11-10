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
partner signals, not gaps.

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

The lens only proposes. Writing approved proposals is a separate, reviewed
step.

## Review and write

Nothing reaches the Asset Database without a named reviewer approving one
proposal. With `-journal`, `ask` records the gap answer's proposals (propose
and review decisions with exactly one attachment) in the review journal,
with their signals and evidence lines. Asking again does not duplicate a
proposal; its ID is a hash of the relationship it would write.

```bash
amass ai -model qwen3:8b -journal review.jsonl \
  -question "Which assets probably belong to Colgate University but are not attributed to it?" ask
amass ai -journal review.jsonl proposals
amass ai -journal review.jsonl -proposal own-1a2b3c4d5e6f7a8b -reviewer jeff approve
amass ai -journal review.jsonl -proposal own-1a2b3c4d5e6f7a8b -reviewer jeff reject
```

`approve` re-reads both entities, checks that their types still match the
proposal and that OAM defines the relationship (`oam.ValidRelationship`,
SimpleRelation only), and writes it with asset-db's `CreateEdge` and a
`SourceProperty` named `amass-ai` whose confidence is the score times 100.
This is how Amass plugins record relationships, so the written edge looks
like collected data except for its source, and every later answer that
cites it shows `amass-ai`. When the relationship is already stored, nothing
is written and the existing edge is recorded. `reject` records the decision
and writes nothing. The journal keeps every proposal, decision, reviewer and
edge ID.

No OAM relationship types are added: a proposal uses only relationships OAM
already defines.
