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
