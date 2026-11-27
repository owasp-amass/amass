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
| `amass lens subdomains -d <domain>` or `-org <name>` | The names it controls, each with its stored IP addresses, and how many names fall into each autonomous system and netblock |
| `amass lens family -d <domain>` | The organizations behind an enumerated domain, the networks and other registered domains that serve it |
| `amass lens vendors -d <domain>` | The outside parties the domain and its organization's assets depend on |
| `amass lens org-group -org <name>` or `-d <domain>` | An organization's corporate group: its ultimate parent and every subsidiary and unit |
| `amass lens services -d <domain>` or `-org <name>` | The services stored for what the domain or organization controls: ports, software, certificates, products, and what stands out |
| `amass lens network -d <domain>` or `-org <name>` | The netblocks and autonomous systems registered to it, where its names are hosted, address space none of its names use, and other domains in its space |
| `amass lens cloud -d <domain>` or `-org <name>` | The public cloud and CDN providers hosting its names, by provider, region and service, from the providers' own published IP ranges |
| `amass lens web -d <domain>` or `-org <name>` | Its web presence: the URLs it controls, the host and address each reaches, off-domain URLs (social profiles, third-party pages), and the web applications recognized on its sites |
| `amass lens identifiers -d <domain>` or `-org <name>` | The registered identifiers attached to what it controls — LEI, tax, company and registry numbers and handles — grouped by type |
| `amass lens accounts -d <domain>` or `-org <name>` | The platform accounts (code hosts, social media) it has, computed from its stored profile URLs, with the handle on each |
| `amass lens funding -d <domain>` or `-org <name>` | The funding rounds its company has received — amount, date and stage — and the investors behind them |
| `amass lens group-funding -org <name>` or `-d <domain>` | Funding across a whole corporate group — each parent, subsidiary and unit — merged, with which one received each round |
| `amass lens contacts -d <domain>` or `-org <name>` | Its contact details: phone numbers, email addresses, contact people and postal addresses |
| `amass lens affiliation -d <domain>` or `-org <name>` | Other organizations tied to it by a shared phone, person, funder or address, scored by confidence |
| `amass lens dangling -d <domain>` or `-org <name>` | DNS records that may point at something it no longer holds: possible subdomain takeovers, lapsed domains, stale addresses |
| `amass lens changes -d <domain>` or `-org <name>` `[-since 2026-11-01\|7d]` | What appeared since a time, and what later enumerations stopped seeing |
| `amass lens certificates -d <domain>` or `-org <name>` | Its certificates: expired, expiring, weak, self-issued or overlong ones, wildcards, and the authorities it relies on |
| `amass lens domains -d <domain>` or `-org <name>` | Its registered domains: registrar, expiry, transfer lock, DNSSEC and DNS providers |
| `amass lens email -d <domain>` or `-org <name>` | Its mail providers and SPF, DMARC and DKIM records, and which domains can be spoofed |
| `amass lens disclosure -d <domain>` or `-org <name>` | How it invites vulnerability reports: security.txt contacts, policy and encryption links, and which files have expired |
| `amass lens headers -d <domain>` or `-org <name>` | The HTTP security headers of its web services: HSTS, CSP, clickjacking and MIME-sniffing protection, cookie flags, and what is missing |
| `amass lens exposure -d <domain>` or `-org <name>` | What it exposes that deserves attention: remote access, databases, file sharing, management interfaces, login pages |
| `amass lens concentration -d <domain>` or `-org <name>` | How much it relies on single providers for DNS, registration, certificates, hosting and mail |
| `amass lens coverage -d <domain>` or `-org <name>` | How complete the stored data is, and what collection would fill each gap |
| `amass lens geography -d <domain>` or `-org <name>` | The countries of its stored addresses and of the parties hosting its names |
| `amass lens compare -d <domain>` or `-org <name>`, `-with <domain>` or `-with-org <name>` | What two domains or organizations share: assets and outside parties |
| `amass lens group-vendors -org <name>` or `-d <domain>` | The outside parties a whole corporate group depends on, and which of its organizations use each |
| `amass db duplicates` | Organizations stored more than once, recorded as merge proposals |
| `amass db identity` | Organizations whose legal identity contradicts their own evidence, recorded as correction proposals |
| `amass db person-named` | Organizations recorded under a person's name, recorded as removal proposals |
| `amass db org-named` | People recorded under an organization's name, recorded as conversion proposals |
| `amass review proposals` | Every proposal in the journal and its status |
| `amass review approve -proposal <id> -reviewer <name>` | Apply a proposal |
| `amass review approve -proposal nk-<id> -as person\|organization -reviewer <name>` | Decide what a kept name names |
| `amass review reject -proposal <id> -reviewer <name>` | Decline a proposal; it is never applied automatically |
| `amass review retract -proposal <id> -reviewer <name>` | Undo an applied proposal |
| `amass review signals` | Why each ownership signal counts ([SIGNALS.md](ai/SIGNALS.md)) |
| `amass review duplicate-signals` | Why each duplicate signal counts ([DUPLICATES.md](ai/DUPLICATES.md)) |
| `amass review signal-precision` | How reviewers judged the proposals each ownership signal stood behind: applied, rejected, retracted and pending counts, and precision (applied over applied plus rejected); signals with fewer than 5 reviewed proposals are flagged |
| `amass review migrate-signals` | Once, after upgrading past the merged signal catalog: renames the ownership signals in the review journal's records to the catalog's hyphenated IDs, keeping the journal as it was beside it; retrain with `amass ai train -kind ownership` afterwards |
| `amass review keep-merged-names` | Once, after upgrading to merges that keep every name: for each merge applied before, shows the more complete of the two names on the merged record and keeps the other as a name claim (organizations) or an `also_known_as` property (people). Undoing such a merge removes them and gives the record its name back |

Every command takes `-format text` (the default) or `-format json`, `-dir`
and `-config` like the other subcommands, and `-journal` for the review
journal (by default the one automatic attribution uses, set by
`AMASS_REVIEW_JOURNAL`).

## Subdomains

```bash
amass lens subdomains -d owasp.org
amass lens subdomains -org "OWASP Foundation"
```

Lists the names (FQDNs) the domain or organization controls, in order, each
with the IP addresses stored for it. A name whose addresses are reached
through an alias (CNAME) is followed to the end of its chain, as a resolver
would, and marked as resolved through an alias. It then summarizes how many
of the names fall into each autonomous system and netblock: each resolved
address is placed in the netblock stored as containing it or, when the
database can search address ranges, the most specific stored netblock whose
range holds it, and that netblock's autonomous system. Names with an address
that no stored netblock holds are counted under "(no stored netblock)".

This replaces the former `subs` subcommand: the plain list of names, the
names with their addresses, and the names-per-autonomous-system-and-netblock
summary are all here. These are stored names and resolutions, not a live
scan; the report says when the time limit, or an optional `-max-assets`
or `-max-reads`, cut it short.

## Organization family

```bash
amass lens family -d utica.edu
```

Sources record one institution under several names (a certificate's
"SUNY Polytechnic Institute", ARIN's "State University of New York
Polytechnic Institute", WHOIS's "SUNY Poly ITS Enterprise
Infrastructure"), and an institution has departments and affiliates with
their own networks and domains. The family lens finds the organizations
tied to the domain:

- the domain's registrant and the organizations named on certificates for
  its names;
- a registration contact for the domain that uses an address in it, such as
  an IT department;
- an organization named like the domain whose networks, together, serve
  enough of its names: the domain's label spells the leading words of its
  name (`owasp`), begins with them (`uticaproductsus` for Utica Products
  USA Service Company), is their initials (`owasp` for Open Worldwide
  Application Security Project), or their initials and a last word
  (`uproducts` for Utica Products);
- the holders of networks dedicated to the domain. The lens samples where
  the domain's names resolve. A network is dedicated when an organization
  tied in one of the ways above holds it, or an organization whose name is a
  variant of the domain's registrant's or of one named like the domain, or
  when most of the names stored for it are the domain's or the other domains
  those organizations registered (a company's network serving three domains
  it registered under different names); otherwise it is a hosting provider.

The organization with the most ties is the main one. A registration and a
name like the domain's each weigh as much as five certificates, so a platform
vendor named on a few certificates for the domain's names, such as a hosted
portal's, does not outweigh the company it serves.

It classifies each organization against the one with the most ties:

- **same institution** when its name is a variant of another's (all its
  words appear in the other, with initials allowed, as in SUNY for State
  University of New York) or their street addresses match after
  normalization (`5801 Sample Avenue` and `5801 Sample Ave, Suite 3110B`), or
  the names have the same distinctive words and differ only in words such as
  college and university, as after Utica College became Utica University;
- **department** when its name carries a department or role word (IT
  services, hostmaster, school of), or is another tied organization's name
  followed by a unit such as a center, laboratory or hospital (Utica
  University Medical Center for Utica University), or is a shorter
  name of a department that ends in such a word;
- **affiliate** when its name shares a distinctive word with the
  institution's (generic words such as university or college do not count)
  or it registered the domain, for example a university's medical
  institutions, whose network serves the university's names;
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
amass lens org-group -org "Utica Products USA Inc."
amass lens org-group -d uticaproducts.com
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
amass lens services -d owasp.org
amass lens services -org "OWASP Foundation"
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
ports and warning period are in `internal/semantics/services.json`. It also
lists the web applications recognized from the stored URLs, such as WordPress
sites with their release, bundled jQuery, plugins and themes
(`internal/semantics/web_applications.json`).

## Network infrastructure

```bash
amass lens network -d owasp.org
amass lens network -org "OWASP Foundation"
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
systems are read first, then the contents of its netblocks, which can be
large. These come from stored
registrations (RDAP and WHOIS) and DNS resolutions, not a live scan.

When the database can search address ranges (PostgreSQL, SQLite and Neo4j
with asset-db's range indexes), an address with no stored netblock relation
is placed in the most specific stored netblock that contains it, and a
netblock's contents include every stored address inside its range, not only
those linked to it; up to 1,000 addresses are read for each netblock, and the
report says when there are more. The third-party lenses use the same
containment to name the party hosting an address.

## Cloud and CDN hosting

```bash
amass lens cloud -d owasp.org
amass lens cloud -org "OWASP Foundation"
```

Shows which public cloud and CDN providers host the domain's or
organization's names, grouped by provider, with the regions and services
those names resolve into and example names for each. It reports how many of
the controlled names are on a recognized provider, out of how many resolve
and how many there are in all, so a footprint concentrated in one provider —
or one region — stands out.

The recognized providers are AWS, Google Cloud, Azure, Oracle Cloud,
Cloudflare, Fastly, DigitalOcean and GitHub (see
`internal/semantics/cloud_providers.json`). A name is attributed to one of
them two ways, needing no collection beyond ordinary resolution:

- **By hosting party.** A name's address is attributed to whoever operates it
  exactly as the network lens does (through the provider's published prefix
  when recorded, otherwise through the netblock's registration), and that
  party is then matched against the catalog's provider `names`. This catches
  cloud hosting recorded only through registration, with no `provider` edge
  written.
- **By alias.** A name CNAME'd to a provider-operated domain (the catalog's
  `domains` — `azurefd.net`, `cloudfront.net`, `fastly.net`, `github.io` and
  the like) is on that provider even when its final address was never
  resolved. This is the common shape of edge and CDN hosting (Azure Front
  Door, CloudFront, Fastly, GitHub Pages), which an address-only view misses.

Regions and services come from the `cloud_region` and `cloud_service`
properties the collector writes from the providers' published feeds, shown
for the names that carry them. This is hosting, not ownership: an address in
a provider's range, or a CNAME to its domain, means the provider operates
that hosting, never that it owns the names, and two parties sharing a
provider are not related. These are stored attributions, not a live scan.

## Web presence

```bash
amass lens web -d owasp.org
amass lens web -org "OWASP Foundation"
```

Lists the URLs the domain or organization controls — its websites and the
endpoints stored for it — with the host and the addresses each reaches, and
the service stored on it when there is one. URLs on one of the subject's own
registered domains are shown as its own web surface; URLs on other domains
(social-media profiles, third-party policy or hosting pages) are shown
separately as an off-domain presence. It then lists the web applications
recognized on the sites from the stored URLs (for example a content
management system with its version and add-ons), using the same
`web_applications.json` catalog the services and report lenses use. These are
stored URLs, not a live crawl.

## Identifiers

```bash
amass lens identifiers -d owasp.org
amass lens identifiers -org "OWASP Foundation"
```

Lists the registered identifiers attached to what the domain or organization
controls — Legal Entity Identifiers (LEI), tax and employer numbers, company
and registry numbers, OpenCorporates and registry handles and the like — each
with the asset it hangs off (usually an organization) and its status, grouped
by identifier type. These identifiers tie an organization to outside
registries and are useful for confirming identity and corporate structure.
The types are the Open Asset Model's `id_type` values. These are stored
identifiers, not a live registry lookup.

For an email identifier, the lens also reports the known data **breaches** it
appears in — the breach names, with a count of exposed identifiers — when the
breach-exposure collector has recorded them. That collector queries defensive
breach-notification sources (XposedOrNot by default, free and keyless; Have I
Been Pwned with a key), is opt-in per source through the data-source
configuration, and records **metadata only** — which breach, when, and the
categories of data exposed — never a leaked secret.

## Accounts

```bash
amass lens accounts -d owasp.org
amass lens accounts -org "OWASP Foundation"
```

Lists the platform accounts the domain or organization has — code hosts
(GitHub, GitLab, Docker Hub), social media (X, LinkedIn, Facebook,
Instagram, YouTube) and the like — computed from the profile URLs already
stored for it. For each known platform a URL names, the handle is read from
the URL path; site pages that are not accounts (a platform's own feature or
login pages) are skipped. The platforms and how their handles are read are
data, in `account_platforms.json`, each citing the platform's own
documentation. These accounts are derived from stored URLs with the URL as
the evidence — a computed view, not written to the database, and not a live
lookup against the platform.

To persist an account, run the lens through review: `amass review accounts -d
<domain> -journal <path>` records each computed account as a proposal, and
`amass review approve -proposal <id> -journal <path>` writes it as an
`Account` asset the organization controls (`Organization --account-->
Account`), tagged `amass-ai` and reversible with `amass review retract`. So a
computed conclusion becomes a stored observation only after a human accepts
it (the compute → review → store path), never as a silent write.

## Funding

```bash
amass lens funding -d owasp.org
amass lens funding -org "OWASP Foundation"
```

Lists the funding rounds a domain's or organization's company has received,
from the funding records stored during enumeration (`FundsTransfer` assets,
collected by the aviato data source). Each round shows its amount, currency,
date and stage, and the investors behind it. An investor is found without
reading relationship labels: a round's recipient account is the one belonging
to the subject, so every *other* account the round points at is a sender, and
the organizations holding those sender accounts are the investors; an
organization named directly on the round (a `third_party` to the transfer) is
listed too. The report also totals the rounds when they share a currency.

Investors, co-investors and the parties on a transfer are a strong signal of
an organization's backers, partners and suppliers during enumeration — the
relationships worth following into their own attack surface. These are stored
records, not a live feed.

## Contacts

```bash
amass lens contacts -d owasp.org
amass lens contacts -org "OWASP Foundation"
```

Gathers the contact details of what a domain or organization controls into one
view: phone numbers, email addresses, contact people and postal addresses. The
details come from the stored contact records (registration registrant, admin and
technical contacts), the organization's members, and the person records tied to
it — reached by destination type, not by relationship label, so any contact
record contributes. Phone numbers come from several collectors (RDAP and WHOIS
registration contacts, and the OpenStreetMap collector worldwide); emails are the
`email` identifiers; addresses are the stored locations. These are stored
records, not a live lookup.

## Affiliation

```bash
amass lens affiliation -d owasp.org
amass lens affiliation -org "OWASP Foundation"
```

Computes the organizations a domain or organization is *affiliated* with —
distinct organizations tied to it, not the same organization (that is the
duplicates lens) and not mere coincidence. It looks for shared attributes: a
phone number used by both, a person who is a contact or member of both, a funder
or investor both received money from, or a shared postal address. Each shared
attribute is a signal with a weight and rationale (`affiliation_signals.json`,
cited per principle 8), and a candidate's signals combine by noisy-OR into a
confidence, so independent signals reinforce each other and no single weak one
is decisive. A matching organization name is never a signal, because
organizations in different jurisdictions often share a name.

This is a computed view, not stated ownership: a shared attribute is evidence of
a tie, not proof. Nothing is written — to record an affiliation, take the result
through review, so a computed conclusion becomes a stored observation only after
a human accepts it (principle 10).

## Dangling DNS

```bash
amass lens dangling -d owasp.org
amass lens dangling -org "OWASP Foundation"
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
amass lens changes -d owasp.org -since 2026-11-01
amass lens changes -org "OWASP Foundation" -since 7d
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

When the database records collection runs, the comparison is with the most
recent finished run whose scope covered the subject and that started after
the time: what that run did not see is reported as not seen by it, which is
firmer than comparing times alone because the run is known to have looked.
Runs that stopped early are not used. Amass records each enumeration as a
run (its scope, mode and session), and any other tool can record its own
through asset-db's `RunRecorder`.

## Certificates

```bash
amass lens certificates -d owasp.org
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
amass lens domains -org "OWASP Foundation"
```

Lists the registered domains of what the domain or organization controls,
each with its registrar, creation and expiry dates, status, DNSSEC and DNS
providers, with registrars and DNS providers counted. It reports domains
whose registration expired or expires within 60 days, domains with no
transfer lock among their EPP or RDAP statuses, domains with no stored
registration and domains whose record says they are not signed with
DNSSEC; a record that does not say shows DNSSEC as not stated
(`internal/semantics/domains.json`).

## Vulnerable software

```bash
amass vuln-update                 # fetch or refresh the vulnerability data
amass lens vulnerable -d example.com
```

Checks the software versions the services lens identifies against NVD's CVE
data, and lists those with CVEs, known exploited ones first (CISA's Known
Exploited Vulnerabilities catalog), with each CVE's score and NVD link. Which
products can be checked, and their NVD CPE names, are in
`internal/semantics/vulnerabilities.json`; every product the services lens
identifies is there, as checked or with the reason it cannot be (a header
that gives a build number or no version). A version the data does not cover
yet, or a product without a version, is listed as not checked.

Web applications are recognized from the URLs stored for the subject
(`internal/semantics/web_applications.json`). For WordPress, the release
comes from the scripts WordPress versions with its own release
(`comment-reply.js`, `wp-embed.js`) and the bundled jQuery from its own file,
both as WordPress's script loader writes them; plugins and themes are listed
by name, with the version written in their asset URLs, but not checked,
because each add-on chooses that value. The services lens lists these sites
too.

`amass vuln-update` asks the NVD CVE API for every CVE naming each
catalog product, with the versions it affects, and reads the KEV catalog; it
writes `vulnerabilities.json` in the output directory (or `AMASS_VULN_DATA`,
or `-vuln-data`). Later runs fetch only what changed, and a product added to
the catalog is fetched in full. Without an NVD API key (`NVD_API_KEY`) the
first run takes a few minutes, at NVD's published rate limit. A dropped
connection, rate limit or server error is asked again after a pause; a
product NVD still does not answer keeps its previous data, the rest is
saved, and the next refresh asks for it again.
`amass vuln-update -every 24h` keeps running and refreshes the data once a
day (NVD asks for no more than once every two hours); so does the MCP server.

Matching is by the version in stored headers and banners. A Linux
distribution backports fixes without changing the version it first shipped,
so a server's upstream version alone overstates its CVEs: Apache 2.4.37 on
Red Hat Enterprise Linux 8 matches over a hundred CVEs Red Hat has fixed
since. When the same header or banner that identified the software names the
distribution (`Apache/2.4.37 (Red Hat Enterprise Linux)`,
`OpenSSH_9.6p1 Ubuntu-3ubuntu13.5`, `PHP/8.2.7-1~deb12u1`;
`internal/semantics/distributions.json`), the lens judges each CVE by that
distribution's own records for the release the version belongs to:

- settled, and not counted: the distribution says the CVE does not affect
  it, or the banner names a package release that has the fix;
- fixed by an update: the distribution fixed it in a package update the host
  may or may not have installed (a header names the version, not the
  package release, except in some banners);
- still applies: the distribution has not fixed it, or does not track it.

`amass vuln-update` reads that data for the catalog's packages and the CVEs
it holds: Debian's security tracker, Ubuntu's CVE API, and Red Hat's
Security Data API (a CVE at a time for those Red Hat has not fixed in every
release, at most 400 a refresh, each read again when its advisories change
or after 30 days). Requests to Ubuntu and Red Hat are spaced a second apart.
Rebuilds of a distribution (Rocky Linux, AlmaLinux, Oracle Linux, CentOS)
are named, but their CVEs are matched by version alone, since their own
errata, published on their own schedule, are not read. Software can hide or
fake its version, so confirm a CVE with the vendor's advisory.

## Lookalike domains

```bash
amass lens lookalikes -d example.com
```

Lists the stored registered domains one typing mistake away from the
subject's (one insertion, deletion, adjacent-key substitution or
transposition, the typo models of Moore and Edelman), or with the same name
under another common suffix, and says whom each seems to belong to: in the
subject's footprint, on its own name servers or registrant (often a
defensive registration), or not tied to it. Those not tied to it that
receive mail come first. During enumeration the Lookalike-Domains
engine plugin checks the same candidates for each in-scope registered
domain and stores those DNS delegates, with their name and mail servers, so
the lens has them to report. The typo models, keyboard, suffixes and limits
are in `internal/semantics/lookalikes.json`. A lookalike is not necessarily
hostile.

## Email security

```bash
amass lens email -d owasp.org
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
amass lens exposure -d owasp.org
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
amass lens report -d owasp.org > owasp-report.md
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
amass lens concentration -d owasp.org
```

Measures how the domain or organization's DNS providers, registrars,
certificate authorities, hosting and mail providers are spread, from the
domains, certificates, network and email lenses. A category whose outside
providers are one is a single point of failure; one whose largest provider
serves 80% or more is concentrated. Its own infrastructure is never counted
as a concern (`internal/semantics/concentration.json`).

## Data coverage

```bash
amass lens coverage -d owasp.org
```

Counts the controlled assets by type and measures what is missing: names
with no stored address, registered domains with no registration record,
netblocks with no registration, addresses not placed in a netblock, and
assets not seen within 30 days of the subject's latest sighting. Each gap
says what collection would fill it (`internal/semantics/coverage.json`).

## Geography

```bash
amass lens geography -org "OWASP Foundation"
```

Shows the countries of the stored addresses of what the domain or
organization controls (its organizations, the contacts of its
registrations) and the countries the parties hosting its names are
registered in, weighted by the names they host. A registration address says
where a party is registered, not where its servers run
(`internal/semantics/geography.json`).

## Compare two subjects

```bash
amass lens compare -d owasp.org -with utica.edu
amass lens compare -org "OWASP Foundation" -with-org "Utica University"
```

Compares the controlled footprints of two domains or organizations and the
outside parties each depends on, and reports what they share: the same
netblocks, certificates, contacts or organizations, and the same vendors.
Sharing is a lead to a relationship (one organization, an affiliate, a
common supplier), not proof of one. Plain-language questions cannot name
two subjects, so this is a command only.

## Vendors across a corporate group

```bash
amass lens group-vendors -org "Utica Products AB"
amass lens group-vendors -d uticaproducts.com
```

Runs the vendors walk for each organization of the corporate group the
org-group lens finds, and, with `-d`, for the domain, then merges the outside
parties: each is listed once, with how many of the group's organizations use
it, which ones, and for what. The most widely used come first. Each
organization is scanned on its own (a parent's scan does not follow its
subsidiaries), and an asset two organizations reach is counted once, for the
first. A party that is itself one of the group's organizations, such as a
subsidiary hosting another's services, is listed apart from outside parties.
Every organization in the group is scanned. An optional `-max-reads` limit
is shared across the group (`groupReadShare`); a report that ran out says
how many organizations were not scanned.

## Vendors

```bash
amass lens vendors -d owasp.org
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
named for the institution, and as hosted on its networks otherwise. Another name of the institution (Utica Products for Utica
Products USA Service Company, or a name the domain spells) is its own, and a
system whose initials are a word of its name (the State University of New
York for SUNY Polytechnic Institute) is affiliated. So are a
registry label carrying a distinctive word of the
institution's name, such as the network names `FOUNDATION1` and `UK_OWASP`,
and a domain whose label spells the institution's name (`owasp.org` for
the OWASP Foundation). An SPF include in the institution's or an
affiliate's domain is not listed as unrecognized. This matters most for a domain with no documented owner, whose
own networks would otherwise appear as its largest vendor.

Lenses read the database in bounded pages. One read returns at most 500 of an
asset's relationships; when that is not enough, the lens reads each
relationship label on its own, and pages through a label with more than 500
relationships to its end. On a store that cannot page, a report says which
relationship stayed partial. The database hygiene scans (`amass db`:
duplicates, identity, person-named, org-named, person-duplicates, org-units,
and the corporate group) have no organization, person or read limit either:
they page through, or load, the whole type (`walkType`), and read every
relationship of what they check (`graph.ReadEdges` with no cap). Outside the controlled footprint
the lens only looks for who controls an asset, so it never pages down a
provider's hierarchy, such as the names under amazonaws.com.

Control does not pass between a URL and its host when the host is a shared
platform where unrelated parties each have a page: a code host or social
network (`account_platforms.json`) or a package registry's site
(`package_registries.json` `registry_hosts`; `lens.SharedPlatformHost`). An
organization's GitHub or LinkedIn URL is in its footprint; github.com and
linkedin.com are not.

A lens reads the whole controlled footprint; it has no size limit of its
own. The walk goes a round at a time (`controlledFootprint`): the footprint
rule compiles from the catalog to type-level steps (`footprintSteps`:
`footprintPass`, never from or to a Person, into an Organization only
through `controls`), and each round reads, in one asset-db step read per
1,000 assets (`graph.StepsFrom`, asset-db `ReadSteps`), only the edges those
steps follow from the assets the last round admitted. The per-asset rules
(shared platforms, `stopAt`, hosted URLs, a held netblock's bare addresses,
read in one step read per round with `addressesHosting`) are applied to each
round's results in Go. A graph without step reads falls back to each
asset's edges.

A run is bounded by its time: the footprint walk stops when it has used all
but a fifth of the run's time (`footprintReserve`), leaving the rest for the
lens's own reads, and reports the result as partial ("time limit").
Automatic attribution (`review.AttributeOwnership`) treats a partial
ownership-gap search as incomplete: it records its proposals for review and
applies none (`AttributionResult.Partial`).
`-investigation-timeout` is 8 minutes by default, up to 30. `-max-assets`
and `-max-reads` (MCP `investigate`'s `max_assets`) are optional limits for
a quick, partial answer; a run they stop says so. `-owner-steps` (default
100) bounds the best-first search for an asset's controller, which stops
at the nearest organization, so it matters only when none is near;
`-owner-depth` (default 8) bounds the climb to the subject's own owner
(`LensLimits.OwnerSteps` and `OwnerDepth`; MCP `investigate`'s
`owner_steps` and `owner_depth`). A lens that reads only
some kinds of asset focuses its walk on them (`focus` in
`internal/semantics/lens.json`): the email lens admits only names and the
kinds of asset that can lead to names, not addresses, netblocks or
autonomous systems, so it reads less; the domains and certificates lenses
are focused the same way. Focusing does not change what a lens reports.

```bash
amass lens vendors -d utica.edu -investigation-timeout 20m
```

`-read-stats` prints, after the result, how many database reads of each kind
the run made and how long they took, to measure a lens against a database.
After the walk, a lens reading an asset's edges reads those of the next
footprint assets with it (up to 64, in one query per direction,
`prefetchFootprint`) and the assets at their far ends in one batch. An asset with more edges than one read returns
has each relationship's first edges read in one query; only a relationship
with more is then paged on its own. These use asset-db's
`ReadEdgesForEntities`, `FindEntitiesByIds` and `ReadEdgesPerLabel`, and fall
back to one read at a time on a repository without them. A relationship with
more edges than one read returns is paged to the end.
The same batch reads serve the graph search and guided investigation tools,
the duplicate, identity, corporate group and person-named checks, the visualize
tool and the enumeration engine's name-to-address lookups, and each MCP tool call
reads an asset or edge list once however many of its lenses ask.

These are stored records, not verified contracts: a token or SPF include can
outlive the service.

## Duplicates and merges

```bash
amass db duplicates
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
more than two organizations are linked as one (one organization stored five times), each
is proposed for merging into the one with the most evidence, not into every
other: four proposals instead of ten. During
an enumeration with `AMASS_ATTRIBUTION=auto`, proposed merges are applied
once the engine's enumerations have finished their work.

## Identity corrections

```bash
amass db identity
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
amass db person-named
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

## People recorded under an organization's name

```bash
amass db org-named
amass review approve -proposal onp-<id> -reviewer jeff
amass review reject -proposal onp-<id> -reviewer jeff
amass review retract -proposal onp-<id> -reviewer jeff
```

The reverse mistake: a contact's person field held an organization's name,
so a Person was stored for it. The lens checks every Person's full name with
`semantics.NameKindOf`, weighing the organizations and email addresses its
contact records give, and proposes only a name with organization evidence and
no person evidence (a legal suffix, an institution's words, or the name of
the organization the same record names).

Approving converts the Person into an Organization. If one of its contact
records already names an organization with the same name, that organization
is reused; otherwise one is created with the Person's properties. The
records' `person` relationships become `organization` relationships, and
every other relationship moves to the organization when the Open Asset Model
allows it on an Organization. One it does not allow (a phone number or
email address on the Person) is dropped from the organization and kept in the
journal. Retracting deletes what the conversion added, deletes an
organization it created that has nothing left, and restores the Person with
all of its relationships. Rejecting records that the name is a person's.
Conversions are never applied automatically. When a trained name-kind
classifier is trained (`ai.NameKindKind.LoadFor`) and is sure, a new proposal records its
answer as advice (`ai.OrgNamedAdvice`, with the same features it learns
`onp-` decisions from), shown with the proposal and never applied.

These decisions, and person-named ones, also teach the name classifier
(`amass ai train -kind name_kind`): an applied `onp-` proposal is an
organization's name, a rejected one a person's, and the reverse for `pno-`.

## Names to decide as a person or an organization

```bash
amass review proposals
amass review approve -proposal nk-<id> -as person -reviewer jeff
amass review approve -proposal nk-<id> -as organization -reviewer jeff
amass review approve -proposal nk-<id> -as person -only -reviewer jeff
amass review reject -proposal nk-<id> -reviewer jeff
amass review retract -proposal nk-<id> -reviewer jeff
```

A field meant for a person (a WHOIS or RDAP contact's name, a person a
document lists) sometimes holds an organization's name, and the words alone
do not always say which. `semantics.NameKindOf` (`name_kinds.json`) and
what the graph already stores decide most names; one they leave uncertain is
kept on the record that gave it as the `uncertain_name` property, and a name
proposal (`nk-`) is recorded in the review journal with the evidence weighed.
The proposal ID is stable for a record, its field and the name, so a name
seen again is not proposed twice, and a merge of the record moves the
proposal to the record that holds it.

The proposals of one name in one field (`review.NameKindGroup`: the label
and the name, case and spacing aside, such as "jgordon" as the author of
five files) are decided together. `amass review proposals` lists a group's
pending proposals as one entry, under the first one's ID; approving or
rejecting it decides every pending proposal of the group, each recorded on
its own so any one can be retracted, and `-only` decides just the one
(`ApplyNameKindGroup`, `RejectNameKindGroup`; the MCP `review_proposal`
tool's `only`). The engine asks its decider once per group: a proposal
whose group already has an answer (a decision that stands, a person's at
confidence 100, or a model's advice) takes it without a question
(`Journal.NameKindGroupAnswer`), and an answer is given to every
unanswered pending proposal of the group (`UnansweredNameKindGroup`).
The name-kind classifier learns one example per group.

Approving says what the name is. As a person, a Person is written from the
parsed name (the stored one is reused) and linked from the record by its
field. As an organization, the Organization stored under the name's
normalized form is linked, or a new one is created; a contact record links
it as its `organization`. Either way the kept name is removed. Retracting
removes the relationship, deletes the Person or Organization when the
decision created it and nothing else relates to it, and keeps the name on
the record again. Rejecting leaves the name where it is.

With a main model and attribution not `off`, the session's name decider
(`ai.NameKindModel`, set by `engine/sessions` as `et.Session.NameKinds`) is
asked about each new proposal beside the pipeline, one name at a time
(`support.BackgroundLane`, the same lane type the archive readers use, so
`options.background_hold` bounds it). The question carries the layer-1
reasons, the record, its properties and what it relates to, numbered; an
answer naming a kind must cite them. Under attribution `auto` an answer at
`support.NameKindApplyConfidence` (90) or above is applied with reviewer
`amass-ai (model …)`; any other answer is recorded as `name_kind_advice` and
shown with the proposal. A pending proposal with no answer (the model failed
or there was no decider when it was proposed) is asked again when a later run
meets the same name on the same record (`Journal.NameKindsToAsk`); one with
advice keeps it.

A trained name-kind classifier (`ai.NameKindKind`, `amass ai train -kind
name_kind`) answers first through `ai.NameKindDecider`, which the session
sets up when there is a main model or a trained classifier. It decides both
ways (organization at the model's `review_threshold`, person at its
`skip_threshold`, each at least 0.90). Its answers carry `AdviceOnly` unless
`options.ai.classifier_applies` is set, and the main model is asked when the
classifier is unsure, or when it may only advise and a model is configured.
It learns from people's `-as` decisions and, through
`AdjudicatorKind.ModelExamples`, from the main model's answers at 0.90 or
above (applied and standing, or cited advice on pending names), but
`TrainWith` judges it only on people's held-out decisions (`classify.HeldOut`,
at least two of each kind) and sets its thresholds from people's decisions
alone. With `classifier_applies`, one name in ten it is sure of
(`nameKindAudited`, by hash) is still asked of the main model; a
disagreement is kept as advice for a person.

## Earlier command names

These commands were first released under `amass ai`, which still runs them
and prints the new name: `amass ai family` is `amass lens family`, `amass ai
identity-conflicts` is `amass db identity`, and `amass ai proposals`,
`approve`, `reject`, `retract`, `signals` and `duplicate-signals` are under
`amass review`.
