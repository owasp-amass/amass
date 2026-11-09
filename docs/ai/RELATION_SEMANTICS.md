# OAM relationship semantics

`internal/ai/semantics/oam_relations.yaml` records what every Open Asset
Model relationship means for AI investigations. It is keyed exactly like
OAM's relationship table (source type, label, relation type, destination
type) so it can move into open-asset-model unchanged. A CI test fails when
OAM defines a relationship the table lacks, or the table lists one OAM does
not have, and when any entry is still marked `review: true`.

## Attribution

What an edge says about who controls its **source** asset:

| Value | Meaning | Examples |
| --- | --- | --- |
| `controller` | The destination identifies a party controlling the source | DomainRecord `registrant_contact`, TLSCertificate `subject_contact` |
| `controls` | The source party controls the destination | Organization `website`, `subsidiary`, `account` |
| `same_subject` | The same subject in another form; attribution passes through | FQDN `registration`, `node`; ContactRecord `organization` |
| `shared` | Possibly shared with unrelated parties; attribution does not pass | TLSCertificate SANs |
| `infrastructure` | Technical dependency; reaches hosts and networks | FQDN `dns_record`, `port`, AS `announces` |
| `third_party` | A separate provider, issuer, registrar or operator | `issuer_contact`, `registrar_contact`, Service `provider` |
| `attribute` | Descriptive data | identifiers, addresses, phones |

The baseline follows the engine's scope association rules, which already
treat `registrant`, `registrant_contact`, `common_name`, `subject_contact`,
`node` and `registration` as tying assets together, and skip SANs.

## Highest parent questions

For `ultimate_parent` goals, a path qualifies only if every step from the
asset to the first Organization passes owner attribution:
`same_subject` in either direction, `controller` followed forward, or
`controls` followed backward. The parent chain above that Organization
still follows `subsidiary` edges.

Organizations whose last non-passing link is `third_party` are reported
separately in `third_parties` and in the answer, for example:

```text
No organization is documented as the owner of owasp.org (asset 29448) in the
stored OAM paths, so no parent organization can be named. This does not prove
that none exists. Organizations connected only as third parties (providers,
issuers or registrars, not owners): let's encrypt (asset 2355) via
TLSCertificate issuer_contact.
```

## Next uses

The same table can answer "what does this organization control?" (walk
owner-attributing edges outward from it) and "which third parties does this
asset depend on?" (collect `third_party` and `infrastructure` connections).
The `purpose` field can focus planning on registration, certificate,
corporate, DNS or network relationships.
