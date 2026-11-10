# Evidence and cited summaries

Every answer carries the stored OAM relationships it rests on, and an
optional model-written summary is accepted only when Go verifies its
citations against them.

## Evidence

Each kind of answer keeps its witnesses:

- path, route and hierarchy answers: the witnessed paths;
- controlled assets: the attribution path of each asset;
- third-party vendors: for each vendor, the edges from a controlled asset to
  the dependency and on to the party that controls it (for example
  `FQDN --dns_record--> IPAddress <--contains-- Netblock <--announces--
  AutonomousSystem --registration--> AutnumRecord`);
- tables: for each row, the attribution path of the row asset and the edges
  behind every cell.

`BuildEvidenceBundle` numbers these edges `E1`, `E2`, ... in answer order,
without repeats, adding the source tags found when provenance was inspected.

## Cited summaries

`amass ai -narrate ... ask` (and `"narrate": true` in an evaluation case)
asks the model for one short paragraph using only the bundle, citing items
after every sentence, like `[E1]` or `[E2, E5]`. `VerifyCitations` rejects
the paragraph when:

- a sentence has no citation;
- a citation names an item that is not in the bundle;
- a sentence names an asset of the bundle that none of its citations
  mention (names are matched longest first, so `www.example.com` is not
  also `example.com`); the question's subject and its documented owners
  are exempt, since every item is about them;
- a hostname or IP address appears that is nowhere in the evidence.

A rejected paragraph is retried once with the problems listed; if it is
still rejected, only the computed answer is shown and the narrative's
`rejected` field says why. Organization names that are not in the evidence
cannot be recognized in free text, so the computed answer, not the
summary, remains the authoritative result.

Text output prints a verified summary, its cited evidence, then the
computed answer. JSON output includes `narrative` with the text, the cited
items and the attempts.
