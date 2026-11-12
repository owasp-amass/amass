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
| `amass lens vendors -d <domain>` | The outside parties the domain and its organization's assets depend on |
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
- the holders of networks dedicated to the domain. The lens samples where
  the domain's names resolve. A network is dedicated when an organization
  tied in one of the ways above holds it, or when most of the names stored
  for it are the domain's; otherwise it is a hosting provider.

It classifies each organization against the one with the most ties:

- **same institution** when its name is a variant of another's (all its
  words appear in the other, with initials allowed, as in SUNY for State
  University of New York) or their street addresses match after
  normalization (`5801 Smith Avenue` and `5801 Smith Ave, Suite 3110B`);
- **department** when its name carries a department or role word (IT
  services, hostmaster, school of);
- **affiliate** when its name shares a distinctive word with the
  institution's (generic words such as university or college do not count)
  or it registered the domain, for example the Johns Hopkins Medical
  Institutions, whose network serves jhu.edu names;
- **other organizations on its assets** otherwise: hosting providers,
  internet service providers and vendors named on certificates. The
  database stores only the addresses an enumeration found, so a provider's
  network can look dedicated to the domain; without the institution's name
  or registration its holder is listed here, not as family.

A shared street address alone puts an organization with the same
institution in the report, but only a name variant is proposed for merging:
a registrant who is a person can share the institution's address.

The report also lists the networks serving the domain and the other
registered domains on dedicated networks the family holds.

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

## Vendors

```bash
amass lens vendors -d colgate.edu
```

Lists the outside parties the domain, and the assets its registrant
organization controls, depend on: registrars, DNS hosts, certificate
authorities, hosting networks and service providers, from the stored
relationships the [relationship semantics](ai/RELATION_SEMANTICS.md) mark as
third-party dependencies. It adds the services the domain's DNS TXT records
name:

- the organizations behind its verification tokens, from the `verified_for`
  relationships the DNS-SD plugin stores. They are read by label, so they
  appear even for a domain with more relationships than the lens reads;
- the mail senders its SPF record authorizes, from
  `internal/ai/semantics/txt_vendors.json`. Each entry is the include the
  vendor's own documentation tells customers to publish, with that page as
  its `source`.

It then lists what nothing recognizes: SPF includes that match no entry
(other than the domain's own), and TXT records that look like verification
tokens but match no DNS-SD prefix. Confirm each against the vendor's
documentation before adding it, so the catalog grows from enumerated data.

A party with no stored organization is named by the registrable domain it was
reached through. Reverse lookup names and private or reserved addresses are
not reported, an address inside one of the organization's netblocks counts as
its own, other bare addresses are grouped as having no recorded network owner,
and providers whose names span many domains (such as Amazon Route 53's
`awsdns-NN` name servers) are grouped by `internal/ai/semantics/vendor_names.json`.
A party reached once through its organization and once only through its
domain (`dnsmadeeasy` and `dnsmadeeasy.com`) is listed once, under the
organization's name. Organizations named by a placeholder such as
`domain admin` are skipped when naming a party.

The lens also runs the family lens for the domain. Organizations the family
lens counts as the institution itself (the same institution or a department)
are listed as the institution's own instead of as vendors, and affiliates,
with the domains the institution's dedicated networks also serve, are listed
as affiliated. This matters most for a domain with no documented owner, whose
own networks would otherwise appear as its largest vendor.

These are stored records, not verified contracts: a token or SPF include can
outlive the service.

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
