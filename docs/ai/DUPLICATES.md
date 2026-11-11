# Duplicate organizations

<!-- Generated from internal/ai/semantics/duplicate_signals.json by `amass ai duplicate-signals -format markdown`. Edit that file, not this one. -->

Sources record one company several times: a certificate, an RDAP lookup and GLEIF can each create an organization under a different spelling. Amass proposes merging two stored organizations only from stored evidence. Each kind of evidence is a signal, listed here with why it counts, what stops it from misfiring, and when it can still mislead. The same text is shown by `amass ai duplicate-signals`.

## How signals decide

- Two strong signals, or one strong signal and a different signal that is not a tiebreaker, **propose** a merge. During enumeration a proposed merge is applied automatically when the session ends (with the `amass-ai` source on every moved relationship) unless attribution is set to `journal` or `off`.
- One strong signal, or two signals of any strength, **needs review**: it waits in the review journal for a person. A pair linked only by its name, with nothing against it, also needs review.
- A **negative** signal lowers the score and keeps a pair from being merged automatically; without a strong signal it also keeps the pair out of review.
- A matching name is never strong: organizations in different jurisdictions often share a name and are different companies.
- A merge moves the duplicate's properties and relationships onto the organization that has more recorded evidence, then deletes the duplicate. Fields the kept organization lacks, such as its legal name, jurisdiction or registration number, are filled from the duplicate; a value is never replaced. The journal records everything the merge changed, so `amass ai -proposal <id> -reviewer <name> retract` restores the duplicate and removes the relationships, properties and filled fields the merge added. A filled field that has changed since the merge is kept.

| Signal | Strength | Kind | Weight |
| --- | --- | --- | --- |
| [Same registry identifier](#shared_registry_identifier) | strong | identity | 0.50 |
| [Same jurisdiction and registration number](#shared_registration) | strong | identity | 0.50 |
| [Same internet registry handle](#shared_network_handle) | strong | identity | 0.50 |
| [Named by the same contact record](#shared_contact_record) | strong | identity | 0.45 |
| [Same name](#same_brand_name) | supporting | name | 0.20 |
| [Same address](#shared_location) | supporting | location | 0.15 |
| [Name is the other's abbreviation](#name_abbreviation) | supporting (tiebreaker) | name | 0.10 |
| [Different jurisdictions or registrations](#jurisdiction_conflict) | negative | conflict | 0.50 |
| [Different Legal Entity Identifiers](#conflicting_registry_identifier) | negative | conflict | 0.50 |
| [Recorded as parent and subsidiary](#parent_or_subsidiary) | negative | conflict | 0.50 |

<a id="shared_registry_identifier"></a>
## Same registry identifier

`shared_registry_identifier`: strong identity signal, weight 0.50.

**Finds:** Two organizations that carry the same Legal Entity Identifier, OpenCorporates ID, D-U-N-S number, tax number or other registry identifier, and that share at least one name.

**Why it counts:** A registry identifier is issued to exactly one legal entity, so two organizations holding the same one are the same entity recorded twice. The names must also agree because enrichment can attach an identifier to the wrong organization; a shared identifier between organizations with unrelated names points to that mistake, not to a duplicate.

**Guards:**

- Counts only when the two organizations share a name after legal forms (Inc, LLC, Ltd and the like) are removed.
- A parent and subsidiary linked in the graph are never merged automatically, even with the same identifier (see parent_or_subsidiary).

**Can still mislead when:**

- Enrichment that matched a subsidiary to its parent's record gives both the parent's identifier.

**Identifier types:** `lei`, `ocid`, `duns`, `ein`, `tin`, `gln`, `spglobal`

<a id="shared_registration"></a>
## Same jurisdiction and registration number

`shared_registration`: strong identity signal, weight 0.50.

**Finds:** Two organizations registered in the same jurisdiction under the same registration number.

**Why it counts:** A company registry assigns each registration number once within its jurisdiction, so the pair identifies one legal entity. The same number in two different jurisdictions means nothing: registries number independently.

**Guards:**

- The jurisdictions must match exactly, including the subdivision (US-DE is not US-NV).

**Can still mislead when:**

- A registration number copied onto the wrong organization by enrichment.

<a id="shared_network_handle"></a>
## Same internet registry handle

`shared_network_handle`: strong identity signal, weight 0.50.

**Finds:** Two organizations that carry the same ARIN organization handle.

**Why it counts:** An internet registry issues an organization handle to one registrant, which uses it for every netblock and autonomous system it holds. Two stored organizations with the same handle are that registrant recorded twice, typically once from a registry lookup and once from a certificate or WHOIS record under a different spelling.

**Guards:**

- Point-of-contact handles are not organization handles and are not used.

**Can still mislead when:**

- A registry handle reassigned after an acquisition can sit on the old and new company.

**Identifier types:** `arin`

<a id="shared_contact_record"></a>
## Named by the same contact record

`shared_contact_record`: strong identity signal, weight 0.45.

**Finds:** One registration or certificate contact record that names both organizations.

**Why it counts:** A contact record describes one registrant. When it points to two organizations, the same registrant was recorded under two names, such as a brand and its legal name.

**Guards:**

- Placeholder and privacy-service organizations are never candidates.

**Can still mislead when:**

- A record that names a registrant and a separate administrative organization.

<a id="same_brand_name"></a>
## Same name

`same_brand_name`: supporting name signal, weight 0.20.

**Finds:** Two organizations whose names are the same once case, punctuation and legal forms such as Inc, LLC, Ltd or NV-SA are removed.

**Why it counts:** Sources spell one company's name differently: a certificate says 'Google Trust Services LLC' where another says 'Google Trust Services'. A matching name supports other evidence, but it is never strong: organizations in different jurisdictions often share a name and are different companies.

**Guards:**

- Never proposes a merge alone, and a jurisdiction conflict overrides it.

**Can still mislead when:**

- Unrelated companies with the same name in different countries or states.

<a id="shared_location"></a>
## Same address

`shared_location`: supporting location signal, weight 0.15.

**Finds:** Two organizations that share a stored address, directly or through their contact records.

**Why it counts:** Two spellings of a company found in certificates or registrations usually carry the same street address. A shared address supports a name match, but on its own it describes a building, not a company.

**Guards:**

- Never proposes a merge alone.

**Can still mislead when:**

- Office buildings, campuses and registered-agent addresses shared by unrelated companies.

<a id="name_abbreviation"></a>
## Name is the other's abbreviation

`name_abbreviation`: supporting name signal, weight 0.10. Tiebreaker.

**Finds:** An organization whose name is the initials of the other's name, such as ISRG and Internet Security Research Group.

**Why it counts:** Organizations are often recorded under their initials. Initials are short and collide often, so this only ranks candidates and sends a pair to review together with other evidence.

**Guards:**

- The abbreviation must have at least three letters.
- A tiebreaker: it never counts as the second signal that lets a strong signal propose.

**Can still mislead when:**

- Unrelated organizations with the same initials.

<a id="jurisdiction_conflict"></a>
## Different jurisdictions or registrations

`jurisdiction_conflict`: negative conflict signal, weight 0.50.

**Finds:** Two organizations registered in different countries, or in the same jurisdiction under different registration numbers.

**Why it counts:** Companies with the same name in different jurisdictions are separate legal entities, and one jurisdiction does not register one company twice. Either difference is evidence of two companies, so the pair is never merged automatically; a person who knows better can still merge it.

**Guards:**

- Counts only when both organizations have a jurisdiction; an unknown jurisdiction is not a conflict.

**Can still mislead when:**

- An organization whose recorded jurisdiction came from a wrong enrichment match.

<a id="conflicting_registry_identifier"></a>
## Different Legal Entity Identifiers

`conflicting_registry_identifier`: negative conflict signal, weight 0.50.

**Finds:** Two organizations that each carry a Legal Entity Identifier, and none in common.

**Why it counts:** Each legal entity has at most one LEI, so different LEIs mean different legal entities, even under the same name.

**Guards:**

- Counts only when both organizations carry an LEI.

**Can still mislead when:**

- An LEI attached to the wrong organization by enrichment.

**Identifier types:** `lei`

<a id="parent_or_subsidiary"></a>
## Recorded as parent and subsidiary

`parent_or_subsidiary`: negative conflict signal, weight 0.50.

**Finds:** Two organizations already linked as parent and subsidiary or as an organizational unit.

**Why it counts:** The graph records them as distinct organizations in a corporate structure. Merging them would erase that structure, so the pair is never merged automatically; when the link itself came from a bad match, a person can still merge them.

**Guards:**

- Applies to a direct link in either direction.

**Can still mislead when:**

- A subsidiary link created by an enrichment that matched the organization to its own record.
