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
| `amass lens report -d <domain>` or `-org <name>` | An attack surface report: key findings first, then each posture lens |
| `amass lens family -d <domain>` | The organizations behind an enumerated domain, the networks and other registered domains that serve it |
| `amass lens vendors -d <domain>` | The outside parties the domain and its organization's assets depend on |
| `amass lens org-group -org <name>` or `-d <domain>` | An organization's corporate group: its ultimate parent and every subsidiary and unit |
| `amass lens services -d <domain>` or `-org <name>` | The services stored for what the domain or organization controls: ports, software, certificates, products, and what stands out |
| `amass lens network -d <domain>` or `-org <name>` | The netblocks and autonomous systems registered to it, where its names are hosted, address space none of its names use, and other domains in its space |
| `amass lens dangling -d <domain>` or `-org <name>` | DNS records that may point at something it no longer holds: possible subdomain takeovers, lapsed domains, stale addresses |
| `amass lens changes -d <domain>` or `-org <name>` `[-since 2026-11-01\|7d]` | What appeared since a time, and what later enumerations stopped seeing |
| `amass lens certificates -d <domain>` or `-org <name>` | Its certificates: expired, expiring, weak, self-issued or overlong ones, wildcards, and the authorities it relies on |
| `amass lens domains -d <domain>` or `-org <name>` | Its registered domains: registrar, expiry, transfer lock, DNSSEC and DNS providers |
| `amass lens email -d <domain>` or `-org <name>` | Its mail providers and SPF, DMARC and DKIM records, and which domains can be spoofed |
| `amass lens exposure -d <domain>` or `-org <name>` | What it exposes that deserves attention: remote access, databases, file sharing, management interfaces, login pages |
| `amass lens concentration -d <domain>` or `-org <name>` | How much it relies on single providers for DNS, registration, certificates, hosting and mail |
| `amass lens coverage -d <domain>` or `-org <name>` | How complete the stored data is, and what collection would fill each gap |
| `amass lens geography -d <domain>` or `-org <name>` | The countries of its stored addresses and of the parties hosting its names |
| `amass lens compare -d <domain>` or `-org <name>`, `-with <domain>` or `-with-org <name>` | What two domains or organizations share: assets and outside parties |
| `amass lens group-vendors -org <name>` or `-d <domain>` | The outside parties a whole corporate group depends on, and which of its organizations use each |
| `amass lens duplicates` | Organizations stored more than once, recorded as merge proposals |
| `amass lens identity` | Organizations whose legal identity contradicts their own evidence, recorded as correction proposals |
| `amass lens person-named` | Organizations recorded under a person's name, recorded as removal proposals |
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
- an organization named like the domain whose networks, together, serve
  enough of its names: the domain's label spells the leading words of its
  name (`automattic`), begins with them (`nationalgridus` for National Grid
  USA Service Company), is their initials (`nasa`, `ngc` for Northrop Grumman
  Corporation), or their initials and a last word (`ngrid`);
- the holders of networks dedicated to the domain. The lens samples where
  the domain's names resolve. A network is dedicated when an organization
  tied in one of the ways above holds it, or an organization whose name is a
  variant of the domain's registrant's or of one named like the domain, or
  when most of the names stored for it are the domain's or the other domains
  those organizations registered (a company's network serving northgrum.com,
  ngc.com and northropgrumman.com); otherwise it is a hosting provider.

The organization with the most ties is the main one. A registration and a
name like the domain's each weigh as much as five certificates, so a platform
vendor named on a few certificates for the domain's names, such as a hosted
portal's, does not outweigh the company it serves.

It classifies each organization against the one with the most ties:

- **same institution** when its name is a variant of another's (all its
  words appear in the other, with initials allowed, as in SUNY for State
  University of New York) or their street addresses match after
  normalization (`5801 Smith Avenue` and `5801 Smith Ave, Suite 3110B`), or
  the names have the same distinctive words and differ only in words such as
  college and university, as after Utica College became Utica University;
- **department** when its name carries a department or role word (IT
  services, hostmaster, school of), or is another tied organization's name
  followed by a unit such as a center, laboratory or hospital (University of
  Rochester Medical Center for the University of Rochester), or is a shorter
  name of a department that ends in such a word;
- **affiliate** when its name shares a distinctive word with the
  institution's (generic words such as university or college do not count)
  or it registered the domain, for example the Johns Hopkins Medical
  Institutions, whose network serves jhu.edu names;
- **other organizations on its assets** otherwise: hosting providers,
  internet service providers and vendors named on certificates. The
  database stores only the addresses an enumeration found, so a provider's
  network can look dedicated to the domain; without the institution's name
  or registration its holder is listed here, not as family.

A shared street address or a rename puts an organization with the same
institution in the report, but only a name variant is proposed for merging:
a registrant who is a person can share the institution's address, and a
renamed institution's records may be worth keeping apart.

The lens reads outward from the domain: its registration records, the
certificates for its sampled names and the records of the networks those
names resolve into. Only the organizations reached that way are compared, so
a run costs the same however many other organizations the database holds.

The report also lists the networks serving the domain and the other
registered domains on dedicated networks the family holds. A domain on one
of the institution's own networks is its own only when one of its
organizations registered it or the domain spells its name; otherwise it is
listed as hosted there, as a hosting company's customers are. A network the institution itself holds is the
family's, however few of the names stored for it are the domain's, and when
its names are spread over networks too small to count alone, up to ten of
them are sampled for the other domains they serve.

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
sample sizes are in `internal/semantics/family.json`, address spellings
in `internal/semantics/address_terms.json`.

## Corporate group

```bash
amass lens org-group -org "Spotify USA Inc."
amass lens org-group -d spotify.com
```

Climbs from an organization to the organizations with no stored parent above
it, then lists every organization below them, as an indented tree with each
one's jurisdiction and registration number. With `-d`, the organization is
the domain's main organization as the family lens decides it. The links are
the stored relationships the [relationship semantics](ai/RELATION_SEMANTICS.md)
mark as one organization controlling another for corporate reasons: today
`subsidiary`, which the GLEIF plugin records from GLEIF's parent and child
records for organizations with an LEI, and `org_unit`, which reviewed
department proposals add. When sources name different parents, the report
lists each one, and when the stored relationships form a cycle it names the
relationship that closes it. Nothing is written.

## Exposed services

```bash
amass lens services -d colgate.edu
amass lens services -org "Colgate University"
```

Lists the services stored for the names, addresses and URLs the domain or
organization controls (the same footprint the vendors lens walks): where each
listens, its type, the software its response headers name (such as
`server: nginx/1.18.0`), the certificates it presented and any products stored
for it. It also identifies the software a service runs from its stored
headers and banners (`nginx 1.24.0`, `OpenSSH 9.6p1`, `Exim 4.97`) by the fingerprints in
`internal/semantics/product_fingerprints.json`, each citing the
documentation that describes what the software sends, and counts the services
per product and version. Identification is computed when asked and never
written: the header or banner is the evidence, and software can hide or fake
it. It reports first what stands out: services on ports their type does not
usually use, and certificates that have expired, expire within 30 days or were
issued by their own subject. Services are what the HTTP, SSH and banner probes
stored during past active enumerations, not a live scan. The Banner-Probes
engine plugin connects to in-scope addresses on the SMTP, FTP, POP3 and IMAP
ports, including the implicit TLS ports 465, 993 and 995, and stores the
greeting the server sends first, with the certificate a TLS port presented; it
never sends a command or credential. `scope.ports` in the configuration lists every port active
enumeration may probe: the SSH and banner probes try the ports they know that it
lists, and the HTTP probes try the rest. Without `scope.ports`, every port the
probes know is probed (`config.DefaultPorts`). Its ports and greeting patterns, each citing the
protocol's RFC, are in
`engine/plugins/service_discovery/banner_probes/protocols.json`. The header names, expected
ports and warning period are in `internal/semantics/services.json`.

## Network infrastructure

```bash
amass lens network -d colgate.edu
amass lens network -org "Colgate University"
```

Shows the address space of what the domain or organization controls (the
same footprint the vendors lens walks): the netblocks registered to it, by IP
version, with how many of its names resolve into each, how many of its
addresses and services are stored inside, and which of its autonomous systems
announce it; and the autonomous systems registered to it, with any prefixes
they announce that are not its own (a customer's or a provider's space). It
then shows where each of its names is hosted: its own networks, or the
party holding the provider's netblock or autonomous system, with the share
of names each hosts. A name that is an alias (CNAME) is followed, as a
resolver would, to the addresses stored for the end of its chain; an alias
to a name with no stored address is hosted by whoever controls that name's
domain. The record types and chain limit are in
`internal/semantics/dns.json`. An address with no stored netblock counts
as its own when it falls inside one of its netblocks' ranges. Finally it lists
the netblocks registered to it that none of its names resolve into, which are
worth checking for forgotten or unmonitored space, and the names of other
domains found on addresses inside its netblocks, by an address or pointer
record: tenants, partners, or something left behind. Its own names and
systems are read first; the contents of its netblocks, which can be large,
take what the read limit leaves. These come from stored
registrations (RDAP and WHOIS) and DNS resolutions, not a live scan.

## Dangling DNS

```bash
amass lens dangling -d colgate.edu
amass lens dangling -org "Colgate University"
```

Checks the DNS records of every name the domain or organization controls
for ones that may point at something it no longer holds, most severe first:

- **Claimable aliases:** an alias (CNAME) to a name on a hosted service where
  anyone can claim a deleted resource's name, such as Azure App Service, an
  S3 bucket or GitHub Pages, with no address stored for it. This is the
  classic subdomain takeover.
- **Expired and expiring domains:** an alias target or a name server (an NS
  record or a registration's name servers) in another domain whose stored
  registration has expired, or expires within 30 days. Anyone may register
  an expired domain and answer for the name.
- **Unresolved aliases:** an alias to an outside name with no stored address.
- **Alias loops:** chains that return to themselves or never end.
- **Stale addresses:** an address record outside the subject's own networks
  not seen again within 30 days of the last time its name was seen. The
  address may have been released to someone else.

Findings come from stored records, so each is a lead to confirm with a live
lookup before acting. The claimable services, each citing the provider's
documentation of the risk, and the periods are in
`internal/semantics/dangling_dns.json`.

## Changes since a time

```bash
amass lens changes -d colgate.edu -since 2026-11-01
amass lens changes -org "Colgate University" -since 7d
```

Compares what the domain or organization controls with an earlier time,
using the times every stored asset and relationship was first stored and
last seen. It lists what was first stored since then, assets by type and
relationships by purpose (new names, addresses, certificates, hosting and
DNS providers, registrants), and what later enumerations stopped seeing:
assets and relationships last seen before the time while the subject itself
was seen after it. Something quiet was not observed again, which is not
proof that it was removed. When no enumeration has seen the subject since
the time, nothing is reported as quiet. `-since` takes a date, an RFC 3339
time or an age (`7d`, `72h`); without it, and for questions asked in plain
language, the window is the last 30 days (`internal/semantics/changes.json`).

## Certificates

```bash
amass lens certificates -d colgate.edu
```

Lists the certificates presented by the services, or covering the names,
of what the domain or organization controls, and the authorities that
issued them. It reports first those that expired or expire within 30 days,
then those signed with a weak algorithm (SHA-1, MD5), issued by their own
subject, valid longer than the CA/Browser Forum allowed on the day they
were issued (398 days from September 2020, 200 from March 2026, then 100
and 47), wildcards and the hosts they cover, and certificates that also
cover other domains' names. The rules are in
`internal/semantics/certificates.json`.

## Domain portfolio

```bash
amass lens domains -org "Colgate University"
```

Lists the registered domains of what the domain or organization controls,
each with its registrar, creation and expiry dates, status, DNSSEC and DNS
providers, with registrars and DNS providers counted. It reports domains
whose registration expired or expires within 60 days, domains with no
transfer lock among their EPP or RDAP statuses, domains with no stored
registration and domains whose record says they are not signed with
DNSSEC; a record that does not say shows DNSSEC as not stated
(`internal/semantics/domains.json`).

## Email security

```bash
amass lens email -d colgate.edu
```

For each registered domain, shows who handles its mail (MX), its SPF
policy, its DMARC policy and the DKIM keys stored for it, and reports what
lets it be spoofed: an SPF record that lets anyone send (`+all`, `?all`), no
SPF, a softfail (`~all`), no DMARC record, a DMARC policy of `p=none` or one
applied to part of the mail, and domains with no mail server that do not
publish `v=spf1 -all` and a DMARC reject policy
(`internal/semantics/email.json`).

Mail handlers are named by provider when their MX host matches one the
provider documents for its customers (Google Workspace, Microsoft 365,
Mimecast, Barracuda, Cisco Secure Email, Proofpoint Essentials; each entry in
`mail_providers` cites that documentation). Other MX hosts are named by their
registrable domain.

A DMARC or DKIM record is only stored when the enumeration queried its name.
At every zone apex it finds, the DNS plugin asks for `_dmarc`, `_mta-sts`,
`_smtp._tls` and the DKIM selectors vendors document as fixed for every
customer (Microsoft 365, Google Workspace, SendGrid, Mailchimp
Transactional), listed with their sources in
`engine/plugins/dns/policy.go`. A DKIM key under any other selector is
stored only when something else finds its name, and a database from an
enumeration before this change can lack DMARC records that exist.

## Exposure

```bash
amass lens exposure -d colgate.edu
```

Groups what the domain or organization exposes into classes that deserve
attention: remote access and shells (SSH, RDP, Telnet, VNC), databases,
file sharing, infrastructure management interfaces, URLs with a password
written into them (shown masked), login and administration pages (found by
URL path or by the page title a probe stored for a web service), TXT
records that disclose internal details (Kubernetes ExternalDNS ownership
records), services on unusual ports, services with expired or self-issued
certificates, and software in a release line its maker no longer supports
(`internal/semantics/software_lifecycle.json`, each line citing the maker's
lifecycle page).
Each class says why it matters and lists examples. The classes, ports, URL,
title and TXT patterns are in `internal/semantics/exposure.json`.

## Attack surface report

```bash
amass lens report -d colgate.edu > colgate-report.md
```

Writes one Markdown report for a domain or organization: key findings first
(possible subdomain takeovers, records pointing into expired domains,
passwords in URLs, exposed databases and remote access, expired domains and
certificates, unsupported software, email spoofing and more, by priority,
each with a count and examples), then the results of the exposure, dangling
DNS, certificates, domains, email, services, network, concentration,
changes and coverage lenses. Every lens reads the footprint once. The
sections and which findings count, with their priorities, are in
`internal/semantics/report.json`. Assistants get it as the `report` answer
kind and the `amass_report` and `amass_attack_surface_overview` prompts.

## Provider concentration

```bash
amass lens concentration -d colgate.edu
```

Measures how the domain or organization's DNS providers, registrars,
certificate authorities, hosting and mail providers are spread, from the
domains, certificates, network and email lenses. A category whose outside
providers are one is a single point of failure; one whose largest provider
serves 80% or more is concentrated. Its own infrastructure is never counted
as a concern (`internal/semantics/concentration.json`).

## Data coverage

```bash
amass lens coverage -d colgate.edu
```

Counts the controlled assets by type and measures what is missing: names
with no stored address, registered domains with no registration record,
netblocks with no registration, addresses not placed in a netblock, and
assets not seen within 30 days of the subject's latest sighting. Each gap
says what collection would fill it (`internal/semantics/coverage.json`).

## Geography

```bash
amass lens geography -org "Colgate University"
```

Shows the countries of the stored addresses of what the domain or
organization controls (its organizations, the contacts of its
registrations) and the countries the parties hosting its names are
registered in, weighted by the names they host. A registration address says
where a party is registered, not where its servers run
(`internal/semantics/geography.json`).

## Compare two subjects

```bash
amass lens compare -d colgate.edu -with hamilton.edu
amass lens compare -org "Colgate University" -with-org "Hamilton College"
```

Compares the controlled footprints of two domains or organizations and the
outside parties each depends on, and reports what they share: the same
netblocks, certificates, contacts or organizations, and the same vendors.
Sharing is a lead to a relationship (one organization, an affiliate, a
common supplier), not proof of one. Plain-language questions cannot name
two subjects, so this is a command only.

## Vendors across a corporate group

```bash
amass lens group-vendors -org "Spotify AB"
amass lens group-vendors -d spotify.com
```

Runs the vendors walk for each organization of the corporate group the
org-group lens finds, and, with `-d`, for the domain, then merges the outside
parties: each is listed once, with how many of the group's organizations use
it, which ones, and for what. The most widely used come first. Each
organization is scanned on its own (a parent's scan does not follow its
subsidiaries), and an asset two organizations reach is counted once, for the
first. A party that is itself one of the group's organizations, such as a
subsidiary hosting another's services, is listed apart from outside parties.
The `-max-reads` budget (20,000 by default) is shared across the group; a
report that ran out says how many organizations were not scanned. Up to 50
organizations are scanned.

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
  `internal/semantics/txt_vendors.json`. Each entry is the include the
  vendor's own documentation tells customers to publish, with that page as
  its `source`.

It then lists what nothing recognizes: SPF includes that match no entry
(other than the domain's own), and TXT records that look like verification
tokens but match no DNS-SD prefix. Confirm each against the vendor's
documentation before adding it, so the catalog grows from enumerated data.

A party with no stored organization is named by the registrable domain it was
reached through (a URL by its host's), or an autonomous system by its number
(`AS22903`). Reverse lookup names, names in special-use domains such as
`.invalid`, and private or reserved addresses are
not reported, an address inside one of the organization's netblocks counts as
its own, other bare addresses are grouped as having no recorded network owner,
and providers whose names span many domains (such as Amazon Route 53's
`awsdns-NN` name servers) are grouped by `internal/semantics/vendor_names.json`.
A registration contact with no organization is the institution's own when its
email is in one of the institution's domains, and is named by its email domain
otherwise.
A party reached once through its organization and once only through its
domain (`dnsmadeeasy` and `dnsmadeeasy.com`) is listed once, under the
organization's name. Organizations named by a placeholder such as
`domain admin` are skipped when naming a party.

The lens also runs the family lens for the domain. Organizations the family
lens counts as the institution itself (the same institution or a department)
are listed as the institution's own instead of as vendors, and affiliates,
with the domains the institution's dedicated networks also serve, are listed
as affiliated, except that a domain on a network the institution itself
holds is listed as its own when the family lens found it registered by or
named for the institution, and as hosted on its networks otherwise. Another name of the institution (National Grid for National
Grid USA Service Company, or a name the domain spells) is its own, and a
system whose initials are a word of its name (the State University of New
York for SUNY Mohawk Valley Community College) is affiliated. So are a
registry label carrying a distinctive word of the
institution's name, such as the network names `GRUMMAN1` and `UK_NORTHROP`,
and a domain whose label spells the institution's name (`ngc.com` for
Northrop Grumman Corporation). An SPF include in the institution's or an
affiliate's domain is not listed as unrecognized. This matters most for a domain with no documented owner, whose
own networks would otherwise appear as its largest vendor.

Lenses read the database in bounded pages. One read returns at most 500 of an
asset's relationships; when that is not enough, the lens reads each
relationship label on its own, and pages through a label with more than 500
relationships up to 5,000 per asset. A report that reached a bound says so and
names the relationship that stayed partial. Outside the controlled footprint
the lens only looks for who controls an asset, so it never pages down a
provider's hierarchy, such as the names under amazonaws.com.

Every lens follows at most 2,000 controlled assets and makes at most 20,000
database reads per run. When the footprint is larger, the asset limit is
shared out a kind of asset at a time in turn, so the result samples names,
addresses, URLs, services, certificates and networks alike rather than the
first subdomains found, and is marked partial. URLs take their turn, but
their own relations are followed last: they are numerous and mostly lead
back to names already in the footprint (`follow_last` in
`internal/semantics/lens.json`). A lens that reads only some kinds of asset
focuses its walk on them (`focus` in the same file): the email lens admits
only names and the kinds of asset that can lead to names, not addresses,
netblocks or autonomous systems, so its limit covers more domains; the
domains and certificates lenses are focused the same way. Without a limit,
focusing does not change what a lens reports. Raise the limits for one run with
`-max-assets` (up to 100,000) and `-max-reads` (up to 1,000,000); MCP
callers pass `max_assets` to `investigate`. A larger run takes longer and may need a longer
`-investigation-timeout` (8 minutes by default, up to 30):

```bash
amass lens vendors -d jhu.edu -max-assets 10000 -max-reads 100000 -investigation-timeout 20m
```

`-read-stats` prints, after the result, how many database reads of each kind
the run made and how long they took, to measure a lens against a database.
A lens reads the edges of the asset it follows together with those of the
next assets in turn (up to 64, in one query per direction) and the assets at
their far ends in one batch. An asset with more edges than one read returns
has each relationship's first edges read in one query; only a relationship
with more is then paged on its own. These use asset-db's
`ReadEdgesForEntities`, `FindEntitiesByIds` and `ReadEdgesPerLabel`, and fall
back to one read at a time on a repository without them. Reading ahead does
not change which assets a limited footprint samples.
The same batch reads serve the graph search and guided investigation tools,
the duplicate, identity, corporate group and person-named checks, `amass viz`
and the enumeration engine's name-to-address lookups, and each MCP tool call
reads an asset or edge list once however many of its lenses ask.

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
Retracting restores the duplicate and removes what the merge added. When
more than two organizations are linked as one (NASA stored five times), each
is proposed for merging into the one with the most evidence, not into every
other: four proposals instead of ten. During
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
they record are in `internal/semantics/identity_checks.json`.

## Organizations recorded under a person's name

```bash
amass lens person-named
amass review approve -proposal pno-<id> -reviewer jeff
amass review retract -proposal pno-<id> -reviewer jeff
```

A WHOIS contact with no organization was once stored with the person's name
as an organization. The lens flags an organization only on evidence of that,
not from how its name looks: one of its own contact records also names a Person
with the same full name (in any word order), it has no legal name,
jurisdiction or registration, and only domain registration records name it. A
network registry or certificate naming it is evidence that it is an
organization, so it is left alone. Approving deletes the organization and its
relationships, keeping the person; retracting recreates it with its
relationships and their sources. Removals are never applied automatically.

## Earlier command names

These commands were first released under `amass ai`, which still runs them
and prints the new name: `amass ai family` is `amass lens family`, `amass ai
identity-conflicts` is `amass lens identity`, and `amass ai proposals`,
`approve`, `reject`, `retract`, `signals` and `duplicate-signals` are under
`amass review`.
