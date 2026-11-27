# Organization name comparison

Every place Amass compares organization names uses one key and one match,
defined in `internal/semantics/org_names.go` from the catalog
`internal/semantics/org_names.json`.

## The key: `semantics.OrgNameKey`

A name's key is the name:

1. folded to plain lower case (NFKD, combining marks removed: "Société
   Générale" is "societe generale");
2. split into words on spaces and commas, with `. , ; : ( ) " '` trimmed from
   each word;
3. with a standalone `&` read as `and` and each `abbreviations` entry written
   out (`intl` is `international`, `univ` is `university`);
4. without a leading `governance_prefixes` wrapper ("The Trustees of Utica
   College" is "utica university");
5. without trailing `legal_forms`, one- or two-word ("Proofpoint Pty Ltd" is
   "proofpoint").

A wrapper or a legal form is never the whole key ("Inc." stays "inc").

## The match: `semantics.OrgNameMatch`

- **exact**: the keys are equal.
- **near**: the keys have the same number of words, and the words pair one to
  one, each pair equal or, for two words of at least `near_min_length`
  letters and no digits, Jaro-Winkler at least `near_similarity` (a
  misspelling). At least one word must be distinctive, that is, not one of
  `generic_words`.
- otherwise **none**. A name that only contains the other ("Apple
  Hospitality REIT" and "Apple") is none, as are names differing only in a
  generic word ("Acme Holdings" and "Acme Group"). Acronyms are not
  expanded.

`internal/semantics/testdata/org_name_pairs.json` holds labeled pairs;
`TestOrgNamePairs` checks the match against them both ways. Add pairs from
real enumerations there when tuning the catalog.

## Callers

- `support/org`: `CreateOrgAsset` stores the key as the organization's name
  (`genNormName`), and `NameMatch` returns the exact and near names.
- `lens.BrandKey` and every lens comparison that used the old brand form
  (duplicates, family, identity, org units, vendors).
- The family lens's generic words are `semantics.OrgGenericWords`.
- `semantics.GenericOrganizationName` (document leads) treats a legal form as
  an entity form.
- The GLEIF, Aviato and documents collectors, and `ai.CandidatePairs`.
- `semantics.SameOrgName` (an exact or near match) is how the funding and
  contract collectors (USAspending, US grants, OCDS, TED, ProPublica) decide a
  record's recipient, supplier or winner is the organization, and EDGAR keys
  its company index by `OrgNameKey`, leaving out a key two companies share.
- The session scope (`engine/sessions/scope`): scope organizations are kept
  by key, an exact match has accuracy 100 and a near one 90, and a
  certificate's subject domain is named for an organization when
  `semantics.OrgNameMatchesLabel` says its label spells the name.
- `semantics.OrgNameMatchesLabel` is also the family and vendor lenses'
  label test, and `initials_stop_words` the words every initials check skips.

`graph.NormalizeOrganizationAlias` is separate on purpose: curated aliases
are compared with only whitespace, case and a final full stop normalized.

## Stored names

Each engine session runs `db.NormalizeOrganizationNames` on the asset
database before collection starts. It rewrites the name of each organization
the engine created (ID `<name>:<UUID>` with the stored name) to the current
key, so key lookups (`FindOrgByNormNameAndJurisdictionClaim`) find records
stored under an earlier normalization. Seed and curated organizations are
left as they are. The duplicate sweep's `brand_key` tags are recomputed by
`EnsureBrandKeys`, which writes the current key for any organization that
lacks it.
