# Lenses and review

Amass answers some questions about the Asset Database directly from the
evidence it stores, without a language model. These views are **lenses**:
`amass lens` runs them. What they find that would change the database, such
as two records of one organization that should be merged, becomes a
**proposal** in the review journal, which `amass review` lists, approves,
rejects and undoes. `amass ai` is for what uses a language model: asking
questions in plain language, the MCP tools, and model advice on proposals.

Lenses compute their answers from stored evidence each time. They never
write a conclusion into the Asset Database, so an answer changes when the
evidence does and nothing is left behind to clean up.

| Command | What it does |
| --- | --- |
| `amass lens family -d <domain>` | The organizations behind an enumerated domain, the networks and other registered domains that serve it |
| `amass lens duplicates` | Organizations stored more than once, recorded as merge proposals |
| `amass lens identity` | Organizations whose legal identity contradicts their own evidence, recorded as correction proposals |
| `amass review proposals` | Every proposal in the journal and its status |
| `amass review approve -proposal <id> -reviewer <name>` | Apply a proposal |
| `amass review reject -proposal <id> -reviewer <name>` | Decline a proposal; it is never applied automatically |
| `amass review retract -proposal <id> -reviewer <name>` | Undo an applied proposal |
| `amass review signals` | Why each ownership signal counts ([SIGNALS.md](ai/SIGNALS.md)) |
| `amass review duplicate-signals` | Why each duplicate signal counts ([DUPLICATES.md](ai/DUPLICATES.md)) |

Every command takes `-format text` (the default) or `-format json`, `-dir`
and `-config` like the other subcommands, and `-journal` for the review
journal (by default the one automatic attribution uses, set by
`AMASS_AI_JOURNAL`).

## Organization family

```bash
amass lens family -d jhu.edu
```

Sources record one institution under several names (a certificate's
"University at Albany", ARIN's "University at Albany, State University of
New York", WHOIS's "UAlbany ITS Enterprise Infrastructure"), and an
institution has departments and affiliates with their own networks and
domains. The family lens finds the organizations tied to the domain:

- the domain's registrant and the organizations named on certificates for
  its names;
- a registration contact for the domain that uses an address in it, such as
  an IT department;
- the holders of networks that mostly serve the domain's names. The lens
  samples where the domain's names resolve and then samples each of those
  networks: a network that mostly serves the domain is dedicated, and one
  serving many other customers is a hosting provider, which is listed but
  is not family.

It classifies each organization against the one with the most ties:

- **same institution** when its name is a variant of another's (all its
  words appear in the other, with initials allowed, as in SUNY for State
  University of New York) or their street addresses match after
  normalization (`5801 Smith Avenue` and `5801 Smith Ave, Suite 3110B`);
- **department** when its name carries a department or role word (IT
  services, hostmaster, school of);
- **affiliate** otherwise, for example the Johns Hopkins Medical
  Institutions, whose network serves jhu.edu names.

The report also lists the networks serving the domain and the other
registered domains on its dedicated networks.

The lens records two kinds of proposal in the review journal, and the
engine records the same ones for each enumerated domain when an
enumeration finishes. Neither is ever applied automatically:

- each **department** as an `org_unit` relationship from the main
  organization, the relationship OAM already defines for an organization's
  units. Approving writes it with the `amass-ai` source; retracting removes
  it. Department decisions are not used to train the ownership model.
- each **same-institution** organization as a merge proposal, reviewed and
  undone like the duplicate search's.

Affiliates are only reported: OAM has no affiliate relationship, and the
lens finds them again from the evidence whenever it is asked. The words, thresholds and
sample sizes are in `internal/ai/semantics/family.json`, address spellings
in `internal/ai/semantics/address_terms.json`.

## Duplicates and merges

```bash
amass lens duplicates
amass review proposals
amass review approve -proposal dup-<id> -reviewer jeff
amass review retract -proposal dup-<id> -reviewer jeff
```

The rules are in [DUPLICATES.md](ai/DUPLICATES.md). A matching name is never
enough on its own, because organizations in different jurisdictions often
share a name and are different companies. Approving a merge moves the
duplicate's relationships and properties onto the organization with more
evidence, fills that organization's empty fields and deletes the duplicate.
Retracting restores the duplicate and removes what the merge added. During
an enumeration with `AMASS_AI_ATTRIBUTION=auto`, proposed merges are applied
once the engine's enumerations have finished their work.

## Identity corrections

```bash
amass lens identity
amass review approve -proposal idc-<id> -reviewer jeff
```

An enrichment source that looks companies up by name, such as GLEIF, can
attach another company's legal record. The lens flags an organization whose
jurisdiction is in none of its contact records' countries, or whose legal
name matches none of the names other sources gave it. Approving removes
what only the enrichment source recorded and clears the legal fields;
retracting restores them. Corrections are never applied automatically,
because companies do rename and relocate. The enrichment sources and what
they record are in `internal/ai/semantics/identity_checks.json`.

## Earlier command names

These commands were first released under `amass ai`, which still runs them
and prints the new name: `amass ai family` is `amass lens family`, `amass ai
identity-conflicts` is `amass lens identity`, and `amass ai proposals`,
`approve`, `reject`, `retract`, `signals` and `duplicate-signals` are under
`amass review`.
