# Horizontal domain correlation

<!-- Generated from internal/semantics/signals.json (related-domain uses) by `amass review horizontal-signals -format markdown`. Edit that file, not this one. -->

Horizontal correlation associates more registered (apex) domains with a target organization, so an enumeration's scope can be made more complete. Each kind of evidence is a signal, listed here with why it counts, what stops it from misfiring, and when it can still mislead. The same text is shown by `amass review horizontal-signals`.

## How signals decide

- The `related-domains` lens surfaces a candidate apex domain for every signal that supports it, recording the strongest signal's confidence (its weight times 100) and the evidence; it never changes scope itself.
- During enumeration the scope-expansion decision scores a candidate over its strong signals, with provider- and proxy-owned shared values excluded and a name match never sufficient on its own, and is reevaluated as new evidence arrives. The classifier reads the same catalog.
- A **strong** signal is direct ownership evidence (a shared registrant or certificate-subject organization, an official website); a **supporting** signal (a shared name server) corroborates but can be shared infrastructure.

| Signal | Strength | Kind | Weight |
| --- | --- | --- | --- |
| [Listed in the organization's bug-bounty program](#bug-bounty-scope) | supporting | declaration | 0.70 |
| [Email authentication delegated to the organization](#spf-authorizes) | supporting | infrastructure | 0.55 |
| [Same DNS provider delegation set](#dns-provider-delegation-set) | supporting | infrastructure | 0.70 |
| [Shared analytics or tag identifier](#shared-analytics-id) | strong | identity | 0.70 |
| [Shared favicon](#shared-favicon) | supporting | content | 0.60 |
| [Shared page content](#shared-page-content) | supporting | content | 0.60 |
| [Shared registrant organization](#shared-registrant-org) | strong | identity | 0.70 |
| [Shared certificate subject organization](#cert-subject-org) | strong | identity | 0.75 |
| [Shared name server](#shared-name-server) | supporting | infrastructure | 0.65 |
| [Allowed cross-origin by the organization's site](#allowed-origin) | supporting | web | 0.55 |
| [Shared DIRECT ad seller account](#shared-ads-seller) | strong | identity | 0.70 |
| [Domain an ad system gives for the organization's seller account](#ads-seller-domain) | supporting | identity | 0.50 |
| [Owner domain named in the organization's ads.txt](#ads-owner-domain) | supporting | declaration | 0.50 |
| [Names the organization as its owner in ads.txt](#ads-owned-by) | supporting | declaration | 0.50 |
| [Publisher site of the organization's verified Maven group](#package-publisher-site) | strong | declaration | 0.70 |
| [Named by the organization's published packages](#package-website) | supporting | declaration | 0.50 |
| [SOA administrator mailbox at the organization's domain](#soa-mailbox-own-domain) | strong | dns | 0.70 |
| [Shared SOA administrator mailbox](#shared-soa-mailbox) | supporting | dns | 0.50 |
| [Name server run by the organization](#name-server-own-domain) | strong | dns | 0.75 |
| [Mail exchanger run by the organization](#mx-own-domain) | strong | dns | 0.70 |
| [Sends all its mail through the organization](#spf-authorizes-exclusive) | strong | dns | 0.70 |
| [Shared mail exchanger](#shared-mx) | supporting | infrastructure | 0.60 |
| [DMARC reports to the organization](#dmarc-reports-to) | strong | infrastructure | 0.70 |
| [Official website](#official-website) | strong | identity | 0.80 |
| [Shared identity tenant](#shared-identity-tenant) | strong | identity | 0.75 |
| [Federated sibling domain](#federated-sibling) | strong | identity | 0.75 |
| [Shared federation signing certificate](#shared-signing-certificate) | strong | identity | 0.70 |
| [Named by the organization's code-host organization](#code-host-website) | supporting | declaration | 0.50 |

<a id="bug-bounty-scope"></a>
## Listed in the organization's bug-bounty program

`bug-bounty-scope`: supporting declaration signal, weight 0.70 (confidence 70).

**Finds:** Another registered domain that a public bug-bounty program lists in scope beside one of the organization's names, when the program is tied to the organization by its website, its exact name, the platform's verification TXT record on the organization's domain, or a link from the organization's security.txt.

**Why it counts:** A program's scope is the organization's own public list of the assets it is responsible for, so the other domains it lists are usually the organization's. It is supporting rather than strong because it is review-only evidence: a scope can list a partner's or a vendor's domain, or a subsidiary that is a separate organization.

**Guards:**

- Only programs tied to the organization count.
- Names under cloud providers' hosting domains and the platforms' own sites are skipped.
- Never expands scope on its own.

**Can still mislead when:**

- A vendor-hosted tenant or a partner's system can be listed so researchers may test it.
- A parent's program can cover subsidiaries and acquisitions that are separate organizations.

The same evidence is also ownership evidence: see [Listed in the organization's bug-bounty program](SIGNALS.md#bug-bounty-scope).

<a id="spf-authorizes"></a>
## Email authentication delegated to the organization

`spf-authorizes`: supporting infrastructure signal, weight 0.55 (confidence 55).

**Finds:** Another registered domain whose SPF record delegates its sending (include: or redirect=) to a domain the organization owns.

**Why it counts:** An SPF include or redirect names a domain allowed to send mail as the publishing domain. Delegating to a domain the organization controls means the organization's mail infrastructure sends on the other domain's behalf, which is evidence of common administration. It is supporting rather than strong because a provider's SPF macro is included by many unrelated customers.

**Guards:**

- A domain that sends all its mail through the organization, when few domains do, gives the strong spf-authorizes-exclusive signal instead.
- An SPF domain referenced by more distinct apex domains than the lens cap is a shared sending provider (a mail provider's SPF macro) and is skipped, not scored.
- An SPF domain a known mail-policy provider operates is skipped regardless of coverage.
- Only the organization's own domains are used as the SPF anchor.

**Can still mislead when:**

- A hosting or email provider's SPF macro domain is included by all of its customers.
- A domain can keep an include for a service it no longer uses.

**Hub limit:** 25, fixed.

The same evidence is also ownership evidence: see [Email authentication delegated to the organization](SIGNALS.md#spf-authorizes).

<a id="dns-provider-delegation-set"></a>
## Same DNS provider delegation set

`dns-provider-delegation-set`: supporting infrastructure signal, weight 0.70 (confidence 70).

**Finds:** Another registered domain whose registration lists exactly the same full set of at least four name servers as one of the organization's own domains, all from a provider that gives each account or hosted zone its own set drawn from a large pool (dns.json assignment unique_set, such as an Amazon Route 53 delegation set).

**Why it counts:** Route 53 gives each hosted zone four name servers chosen from thousands, and an account can reuse one delegation set across its zones. An identical full set recurring by chance is vanishingly rare, so two domains sharing it are almost certainly in one provider account. It is supporting rather than strong for scope expansion because one account shows a common operator, not a common owner: agencies, resellers and managed-service providers run many clients' zones from one account. On its own it sends the domain to review; with a strong signal it expands scope. For owned-asset, where nothing is collected, the same evidence is strong.

**Guards:**

- The whole set must match: every name server, at least four, all from the one unique_set provider.
- Only name servers reached from the organization's own domain records are used as anchors.
- A set listed by more distinct apex domains than the hub limit for name servers is skipped.

**Can still mislead when:**

- A reseller, agency or managed-service provider can host many clients' zones in its own account, so the domains share an operator rather than an owner.

The same evidence is also ownership evidence: see [Same DNS provider delegation set](SIGNALS.md#dns-provider-delegation-set).

<a id="shared-analytics-id"></a>
## Shared analytics or tag identifier

`shared-analytics-id`: strong identity signal, weight 0.70 (confidence 70).

**Finds:** Another registered domain whose web service embeds the same analytics or tag-manager identifier (a Google Analytics or Tag Manager property, a Facebook pixel and the like) as one of the organization's own services.

**Why it counts:** An analytics or tag-manager property is registered to one account and embedded by that account's own sites to report their traffic together. Two sites carrying the same property identifier are administered by the same account, which is strong evidence of common control. The identifier is a shared Identifier asset, so the match is a one-hop graph pivot, not a value scan.

**Guards:**

- A default or signal-free identifier value is skipped (internal/semantics/fingerprint_defaults.json).
- An identifier embedded on more distinct apex domains than the hub limit for its fingerprint type is treated as a shared marketing or agency account, not common ownership, and is skipped.
- Only identifiers on the organization's own services are used as anchors.

**Can still mislead when:**

- A marketing agency can embed one analytics property across several unrelated clients.
- A template or theme can ship a placeholder property identifier that several unrelated sites keep.

**Hub limit:** 25 until the database holds enough values of this kind to derive its own (internal/semantics/hubs.json; `options.hubs.derive`).

The same evidence is also ownership evidence: see [Shared analytics or tag identifier](SIGNALS.md#shared-analytics-id).

<a id="shared-favicon"></a>
## Shared favicon

`shared-favicon`: supporting content signal, weight 0.60 (confidence 60).

**Finds:** Another registered domain whose web service serves a favicon with the same hash as one of the organization's own services.

**Why it counts:** Organizations reuse one brand favicon across their sites, so two services serving a byte-identical favicon are often the same operator's. It is supporting rather than strong because content-management frameworks and hosting panels ship default favicons that many unrelated sites keep unchanged.

**Guards:**

- A default or framework favicon hash is skipped (fingerprint_defaults.json).
- A favicon served by more distinct apex domains than the hub limit for its fingerprint type is treated as a shared default or CDN asset and is skipped.
- Only favicons on the organization's own services are used as anchors.

**Can still mislead when:**

- A framework, CMS theme or hosting panel ships a default favicon that unrelated sites keep.
- A hosting provider can serve one favicon across many parked or placeholder sites.

**Hub limit:** 25 until the database holds enough values of this kind to derive its own (internal/semantics/hubs.json; `options.hubs.derive`).

The same evidence is also ownership evidence: see [Shared favicon](SIGNALS.md#shared-favicon).

<a id="shared-page-content"></a>
## Shared page content

`shared-page-content`: supporting content signal, weight 0.60 (confidence 60).

**Finds:** Another registered domain whose web service returns a page body with the same hash as one of the organization's own services.

**Why it counts:** A byte-identical, non-trivial page body served from two domains is usually one deployment answering on both, which is evidence of common control. It is supporting because parked, placeholder and default-install pages are identical across many unrelated domains.

**Guards:**

- A default, parked or placeholder page hash is skipped (fingerprint_defaults.json), and only normalized bodies above a minimum size are hashed at collection.
- A body served by more distinct apex domains than the hub limit for its fingerprint type is treated as a shared parked or default page and is skipped.
- Only page bodies on the organization's own services are used as anchors.

**Can still mislead when:**

- Parking services, registrars and hosting providers serve one placeholder body across many unrelated domains.
- A CDN error or maintenance page can be identical across unrelated sites.

**Hub limit:** 25 until the database holds enough values of this kind to derive its own (internal/semantics/hubs.json; `options.hubs.derive`).

The same evidence is also ownership evidence: see [Shared page content](SIGNALS.md#shared-page-content).

<a id="shared-registrant-org"></a>
## Shared registrant organization

`shared-registrant-org`: strong identity signal, weight 0.70 (confidence 70).

**Finds:** Another registered domain whose WHOIS/RDAP registrant contact names the same organization as the target's.

**Why it counts:** The registrant organization on a domain record is the party that registered the domain, recorded by the registry. When two domains name the same organization as registrant, the same party registered both, which is direct evidence they belong to the same footprint.

**Guards:**

- A WHOIS privacy or registrar proxy (for example Domains By Proxy, LLC) is never an anchor: thousands of unrelated domains share one, so the match is suppressed (internal/registrant).
- A placeholder or redaction organization value is excluded the same way.
- A matching organization name alone, with no shared registrant record, is never sufficient: unrelated companies share names across jurisdictions.

**Can still mislead when:**

- Resellers, registrars and agencies sometimes register domains for clients under their own organization.
- A parent holding company can be the registrant of record for legally separate subsidiaries.

<a id="cert-subject-org"></a>
## Shared certificate subject organization

`cert-subject-org`: strong identity signal, weight 0.75 (confidence 75).

**Finds:** The apex domains covered by a TLS certificate (its common name and DNS subject-alternative names) whose subject contact names the organization.

**Why it counts:** An organization-validated certificate carries a subject organization the certificate authority verified against the requesting entity. The apex domains such a certificate covers were presented together by that organization, so they tie to its footprint.

**Guards:**

- A certificate covering more distinct apex domains than the hub limit for certificate names is treated as shared or CDN infrastructure (many tenants on one certificate), not shared ownership, and is skipped.
- A privacy-proxy or placeholder subject organization is excluded.

**Can still mislead when:**

- A hosting or SaaS provider can name itself as the subject organization on certificates it issues for customer domains.
- A domain-validated certificate carries no verified organization and does not produce this signal.

**Hub limit:** 25 until the database holds enough values of this kind to derive its own (internal/semantics/hubs.json; `options.hubs.derive`).

<a id="shared-name-server"></a>
## Shared name server

`shared-name-server`: supporting infrastructure signal, weight 0.65 (confidence 65).

**Finds:** Another registered domain served by the same authoritative name server as one of the organization's own domains.

**Why it counts:** A private or vanity name server operated by one organization serves only that organization's domains, so sharing it is evidence of common control. It is supporting rather than strong because a small hosting provider's shared name server can serve unrelated customers.

**Guards:**

- A name server inside the organization's own domains gives the strong name-server-own-domain signal instead.
- A name server serving more distinct apex domains than the hub limit for name servers is treated as shared or provider infrastructure and is skipped.
- Only name servers reached from the organization's own domain records are used as anchors.

**Can still mislead when:**

- Managed DNS and small hosting providers run name servers shared by many unrelated customers.
- A registrar's default name servers are shared across its whole customer base.

**Hub limit:** 25 until the database holds enough values of this kind to derive its own (internal/semantics/hubs.json; `options.hubs.derive`).

<a id="allowed-origin"></a>
## Allowed cross-origin by the organization's site

`allowed-origin`: supporting web signal, weight 0.55 (confidence 55).

**Finds:** Another registered domain that a web service on one of the organization's own hosts names in its CORS Access-Control-Allow-Origin or CSP frame-ancestors header, letting that domain call or embed it.

**Why it counts:** Sites usually let their own sister sites (an application portal, a student system, a regional site) call their APIs or frame their pages, and they name them one by one. It is supporting rather than strong because partners and vendors are allowed the same way.

**Guards:**

- Only services on the organization's own hosts are read.
- Only named origins count: a wildcard (*) or 'null' names no domain.
- Never expands scope on its own.

**Can still mislead when:**

- A partner, payment provider or embedding vendor is allowed exactly like a sister site.
- Some frameworks echo back whatever origin asked, so the header names the prober's origin rather than a chosen one; Amass's probes send no Origin header.

<a id="shared-ads-seller"></a>
## Shared DIRECT ad seller account

`shared-ads-seller`: strong identity signal, weight 0.70 (confidence 70).

**Finds:** Another registered domain whose ads.txt or app-ads.txt lists, as DIRECT, the same advertising seller account (an ad system and account ID, such as a Google AdSense publisher ID) as one of the organization's own domains.

**Why it counts:** A DIRECT line names an ad account the publisher controls itself and is paid through, so it is as specific to its owner as an analytics property: the domains that list it are run by the same publisher.

**Guards:**

- Only DIRECT lines count; RESELLER lines name the companies that sell on the publisher's behalf.
- An account the ad system's sellers.json lists as an INTERMEDIARY (a sales house) is skipped.
- An account listed by more than 25 registered domains is treated as a network's, not an owner's, and skipped.

**Can still mislead when:**

- A sales house or agency can list its own account as DIRECT on the sites it manages.
- A copied ads.txt can keep a former owner's accounts.

**Hub limit:** 25 until the database holds enough values of this kind to derive its own (internal/semantics/hubs.json; `options.hubs.derive`).

<a id="ads-seller-domain"></a>
## Domain an ad system gives for the organization's seller account

`ads-seller-domain`: supporting identity signal, weight 0.50 (confidence 50).

**Finds:** The domain an ad system's sellers.json gives as the business domain of the seller behind one of the organization's DIRECT ad accounts, when it is another domain.

**Why it counts:** sellers.json names the business behind each account, by name and domain, as the ad system knows it from paying it. A different domain there is usually the publisher's corporate site. It is supporting because the seller can be a parent, an agency or a sales house that the ad system lists as a publisher.

**Guards:**

- Accounts the ad system lists as INTERMEDIARY or keeps confidential are skipped.
- The ad system's own domain is skipped.
- Never expands scope on its own.

**Can still mislead when:**

- An agency that manages a site's ads can be the seller of record.
- A parent company's domain can be listed for its brands' accounts.

<a id="ads-owner-domain"></a>
## Owner domain named in the organization's ads.txt

`ads-owner-domain`: supporting declaration signal, weight 0.50 (confidence 50).

**Finds:** The business domain of the site's owner that one of the organization's own ads.txt or app-ads.txt files names in its OWNERDOMAIN variable, when it is another domain.

**Why it counts:** Only a site's operator can publish its ads.txt, and OWNERDOMAIN is where the operator names the business domain of the company that owns the site, for ad buyers to check the seller's identity. It is supporting because the owner can be a parent or holding company that is a separate organization, and a copied file can keep another owner's value.

**Guards:**

- Only the organization's own domains' files are read.
- Never expands scope on its own.

**Can still mislead when:**

- A parent company's domain names the owner of a brand that is run as a separate organization.
- An ads.txt template copied from another site can keep its OWNERDOMAIN.

<a id="ads-owned-by"></a>
## Names the organization as its owner in ads.txt

`ads-owned-by`: supporting declaration signal, weight 0.50 (confidence 50).

**Finds:** Another registered domain whose ads.txt or app-ads.txt names one of the organization's own domains in its OWNERDOMAIN variable, as the business domain of the company that owns the site.

**Why it counts:** OWNERDOMAIN is the site operator's own statement of who owns the site, for ad buyers to check. A site that names the organization's domain there is usually one of its brands or properties. It is supporting because any site can write any domain there: ad-fraud sites spoof well-known owners, and nothing but the buyers' own checks against sellers.json holds it to the truth.

**Guards:**

- Only files Amass has read are seen, so the signal confirms domains found by other evidence more often than it discovers new ones.
- Never expands scope on its own.

**Can still mislead when:**

- A spoofing site names a well-known owner to sell its ad space at a better price.
- A former brand can keep naming its old owner after a sale.

<a id="package-publisher-site"></a>
## Publisher site of the organization's verified Maven group

`package-publisher-site`: strong declaration signal, weight 0.70 (confidence 70).

**Finds:** Another registered domain a package in the organization's Maven Central group names as its publisher's organization URL, where the group is the reverse of one of the organization's own domains.

**Why it counts:** Maven Central lets a publisher use a groupId only after proving, with a DNS TXT record, that it controls the domain the groupId names. A package in that group names its publisher's organization in its POM, so the site it names there is the organization's own declaration of its site.

**Guards:**

- Only groups named for one of the organization's own domains count.
- Only the POM's organization URL counts; its project and repository URLs are the supporting package-website signal.
- URLs on registries, documentation and code hosts, and cloud providers' hosting domains are never stored.

**Can still mislead when:**

- A POM copied from a parent project or a template can keep another organization's URL.
- A group handed to a spun-off project can keep naming the former parent.

<a id="package-website"></a>
## Named by the organization's published packages

`package-website`: supporting declaration signal, weight 0.50 (confidence 50).

**Finds:** Another registered domain one of the organization's packages names as its homepage, project page or repository: a package in a Maven group named for one of the organization's domains, or an npm package maintained from an address at one.

**Why it counts:** A package's homepage and project pages are usually its publisher's sites. It is supporting because a package can point to a community site, a hosted documentation service or a partner's product page.

**Guards:**

- Only namespaces tied to one of the organization's domains count: a Maven group named for it, or an npm namespace with a maintainer address at it.
- URLs on registries, documentation and code hosts, and cloud providers' hosting domains are never stored.
- Never expands scope on its own.

**Can still mislead when:**

- An open-source project can live on its own community domain that no organization owns.
- A maintainer can keep a work address on a personal project.

<a id="soa-mailbox-own-domain"></a>
## SOA administrator mailbox at the organization's domain

`soa-mailbox-own-domain`: strong dns signal, weight 0.70 (confidence 70).

**Finds:** Another registered domain whose SOA record names, as its zone administrator (RNAME), a mailbox at one of the organization's own domains that one of the organization's zones also names.

**Why it counts:** A zone's SOA record names the mailbox of the person responsible for it. A zone whose administrator is a mailbox at the organization's own domain, the same one its own zones list, is run by the organization's DNS staff.

**Guards:**

- The mailbox must be at one of the organization's own registered domains or a name below one.
- A DNS host's default mailbox is skipped: a managed-DNS provider's, or one at the registered domain of a primary name server outside the organization.
- A mailbox that more domains list than the hub limit for SOA mailboxes is skipped.

**Can still mislead when:**

- A zone copied from the organization's template can keep its mailbox after the domain changes hands.
- An agency running DNS for a client may list the client's mailbox in zones of its own.

<a id="shared-soa-mailbox"></a>
## Shared SOA administrator mailbox

`shared-soa-mailbox`: supporting dns signal, weight 0.50 (confidence 50).

**Finds:** Another registered domain whose SOA record names the same zone administrator mailbox (RNAME) as one of the organization's zones, when that mailbox is outside the organization's domains.

**Why it counts:** The same administrator mailbox in two zones points to one administrator. It is supporting rather than strong for an outside mailbox: a web agency, registrar or IT contractor administers many clients' zones from its own mailbox.

**Guards:**

- A DNS host's default mailbox is skipped.
- A mailbox that more domains list than the hub limit for SOA mailboxes is skipped.
- Never expands scope on its own.

**Can still mislead when:**

- An agency or contractor administers unrelated clients' zones from one mailbox.

**Hub limit:** 25 until the database holds enough values of this kind to derive its own (internal/semantics/hubs.json; `options.hubs.derive`).

<a id="name-server-own-domain"></a>
## Name server run by the organization

`name-server-own-domain`: strong dns signal, weight 0.75 (confidence 75).

**Finds:** Another registered domain served by a name server that is a host inside one of the organization's own domains (ns1.example.com serving example-labs.org), the same server one of the organization's domains uses.

**Why it counts:** An organization that runs its own name servers hosts its own zones on them. A domain delegated to a name server inside the organization's namespace is served by the organization's DNS, which it rarely does for anyone else.

**Guards:**

- The name server must be one of the organization's own registered domains or a name below one.
- A name server more domains use than the hub limit for name servers is skipped.
- A managed-DNS provider's name server is never used.

**Can still mislead when:**

- A university or ISP running DNS for affiliated or customer organizations serves their zones from its own servers.
- A delegation can outlive a domain's sale until the new owner moves it.

<a id="mx-own-domain"></a>
## Mail exchanger run by the organization

`mx-own-domain`: strong dns signal, weight 0.70 (confidence 70).

**Finds:** Another registered domain whose mail is handled by a mail exchanger that is a host inside one of the organization's own domains, the same one one of the organization's domains uses.

**Why it counts:** A domain whose mail goes to the organization's own mail server receives its mail at the organization, which an organization does for its own domains and rarely for others.

**Guards:**

- The mail exchanger must be one of the organization's own registered domains or a name below one.
- A mail exchanger more than 25 domains use is skipped.
- A known mail provider's exchanger is never used.

**Can still mislead when:**

- An organization can relay mail for affiliated organizations or customers through its own servers.

<a id="spf-authorizes-exclusive"></a>
## Sends all its mail through the organization

`spf-authorizes-exclusive`: strong dns signal, weight 0.70 (confidence 70).

**Finds:** Another registered domain whose SPF record authorizes only names inside the organization's own domains to send its mail, when at most 5 domains authorize the organization's domain.

**Why it counts:** A domain that sends all of its mail through the organization, and through no one else, is the organization's: an outside sender would list its own servers or its other providers too.

**Guards:**

- Every name and address range the domain's SPF record authorizes must be inside the organization's domains.
- At most 5 domains may authorize the organization's domain; an email or IT provider is authorized by many.
- A known mail-policy provider's domain is never used.

**Can still mislead when:**

- When the organization is itself an email, hosting or IT provider, a small client can send only through it.

<a id="shared-mx"></a>
## Shared mail exchanger

`shared-mx`: supporting infrastructure signal, weight 0.60 (confidence 60).

**Finds:** Another registered domain whose mail is handled by the same mail exchanger (MX host) as one of the organization's own domains.

**Why it counts:** A mail exchanger an organization runs for its own mail serves only that organization's domains, so two apex domains pointing their MX at the same host are evidence of common control. It is supporting rather than strong because a mail provider's exchanger is shared by many unrelated customers; in OAM an MX record is the same shape as a name-server record (an apex FQDN pointing to a server FQDN), so this mirrors the shared-name-server signal.

**Guards:**

- A mail exchanger inside the organization's own domains gives the strong mx-own-domain signal instead.
- A mail exchanger serving more distinct apex domains than the lens cap is treated as a shared mail provider (Google Workspace, Microsoft 365, Proofpoint and the like) and is skipped, not scored.
- Only mail exchangers reached from the organization's own domains are used as anchors.

**Can still mislead when:**

- Managed mail providers and SaaS email gateways are the MX for many unrelated customers.
- A parent company can run one mail system for legally separate subsidiaries.

**Hub limit:** 25, fixed.

<a id="dmarc-reports-to"></a>
## DMARC reports to the organization

`dmarc-reports-to`: strong infrastructure signal, weight 0.70 (confidence 70).

**Finds:** Another registered domain whose DMARC record sends its aggregate or forensic reports (rua/ruf) to a domain the organization owns.

**Why it counts:** A domain's DMARC record names where its mail-authentication reports are sent. Pointing them at a domain the organization controls is a deliberate administrative act: that organization's mail team collects and acts on the reports, so the two domains are administered together. The reporting address is derived from the published DMARC TXT record, which is kept as evidence.

**Guards:**

- A reporting domain referenced by more distinct apex domains than the lens cap is a shared DMARC processor (dmarcian, Valimail and the like), not common ownership, and is skipped, not scored.
- A reporting domain a known mail-policy provider operates is skipped regardless of how many referencing domains are in the database.
- Only the organization's own domains are used as the reporting anchor.

**Can still mislead when:**

- A managed DMARC service receives many unrelated customers' reports at its own domain.
- An external reporting destination requires the destination to authorize it, which this signal does not yet verify.

**Hub limit:** 25, fixed.

<a id="official-website"></a>
## Official website

`official-website`: strong identity signal, weight 0.80 (confidence 80).

**Finds:** A domain the organization publishes as its own website (Organization --website--> URL --domain--> FQDN), for example recorded by the Wikidata official-website collector.

**Why it counts:** An official website recorded for an organization is a curated, third-party-asserted claim that the organization owns that domain, so it is the strongest of the current horizontal signals.

**Guards:**

- Only a website edge on the subject organization itself is used.
- The apex (registered domain) of the website host is taken, not the full host name.

**Can still mislead when:**

- A curated source can record a campaign or microsite domain hosted by a third party as an official website.
- An out-of-date record can name a domain the organization no longer controls.

<a id="shared-identity-tenant"></a>
## Shared identity tenant

`shared-identity-tenant`: strong identity signal, weight 0.75 (confidence 75).

**Finds:** Another registered domain whose identity tenant is the same as one of the organization's domains': the same Microsoft Entra tenant GUID, or the same Okta organization, read from the provider's own metadata (FQDN --identity_tenant--> Identifier).

**Why it counts:** An identity tenant is one organization's user directory. Adding a domain to an Entra tenant requires proving control of it with a DNS record, and an Okta organization is a single customer account, so two domains on one tenant are almost always run by the same organization.

**Guards:**

- A tenant shared by more registered domains than the hub limit for identity tenants is skipped: a managed service provider's or a provider's shared tenant.
- The organization's own domains are not candidates.

**Can still mislead when:**

- A managed service provider can run several clients' domains in its own tenant.
- After an acquisition, a parent's tenant can hold the domains of a company that was later sold.

**Hub limit:** 25 until the database holds enough values of this kind to derive its own (internal/semantics/hubs.json; `options.hubs.derive`).

<a id="federated-sibling"></a>
## Federated sibling domain

`federated-sibling`: strong identity signal, weight 0.75 (confidence 75).

**Finds:** A registered domain Microsoft lists as sharing the tenant of one of the organization's domains (GetFederationInformation, FQDN --federated_with--> FQDN).

**Why it counts:** Microsoft lists only domains verified in the same tenant, and verifying a domain requires a DNS record in its zone, so the tenant's administrator controls every listed domain.

**Guards:**

- Microsoft's *.onmicrosoft.com routing names and the domain's own subdomains are not recorded.
- The organization's own domains are not candidates.

**Can still mislead when:**

- A tenant can hold a partner's or a former subsidiary's domain that was verified there and never removed.

<a id="shared-signing-certificate"></a>
## Shared federation signing certificate

`shared-signing-certificate`: strong identity signal, weight 0.70 (confidence 70).

**Finds:** A registered domain whose federation server, or the federation server its users sign in at, signs tokens with the same certificate as a federation server inside the organization's domains (FQDN --identity_provider--> FQDN --signing_certificate--> TLSCertificate).

**Why it counts:** A token-signing certificate belongs to one federation farm (an AD FS deployment, for example): whoever signs with it holds its private key, so two sign-in hosts sharing it are one identity system.

**Guards:**

- Only federation servers inside the organization's own domains are compared; a hosted identity provider's tenant hosts are never asked for signing certificates.
- A certificate on more federation servers than the hub limit is skipped.
- The organization's own domains are not candidates.

**Can still mislead when:**

- An outsourced identity service can sign several customers' tokens with one certificate.

**Hub limit:** 10, fixed.

<a id="code-host-website"></a>
## Named by the organization's code-host organization

`code-host-website`: supporting declaration signal, weight 0.50 (confidence 50).

**Finds:** Another registered domain that a GitHub or GitLab organization tied to one of the organization's domains names as its website or as a repository's homepage (Account --website--> URL).

**Why it counts:** An organization's code-host profile and its repositories' homepages usually point at its own sites. It is supporting because a repository can point to a community site, a hosted documentation service or a partner's product page.

**Guards:**

- Only code-host organizations tied to one of the organization's domains count: named by its stored profile URLs, or guessed from the domain and naming a website or email in the footprint.
- URLs on registries, documentation and code hosts, and cloud providers' hosting domains are never counted.
- Never expands scope on its own.

**Can still mislead when:**

- An open-source project the organization hosts can live on its own community domain that no organization owns.
- A repository can be a fork-like copy whose homepage still names the original project's site.
