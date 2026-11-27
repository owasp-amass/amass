# Ownership signals

<!-- Generated from internal/semantics/signals.json (owned-asset uses) by `amass review signals -format markdown`. Edit that file, not this one. -->

Amass proposes that an organization owns an asset it has not been attributed to only from stored evidence. Each kind of evidence is a signal, listed here with why it counts, what stops it from misfiring, and when it can still mislead. The same text is shown by `amass review signals`.

## How signals decide

- A candidate with two strong signals, or one strong signal and a different second signal, is **proposed** when exactly one OAM relationship can record the owner. During enumeration a proposed candidate is written automatically (with the `amass-ai` source) unless attribution is set to `journal` or `off`.
- One strong signal, or two signals of any strength, **needs review**: it waits in the review journal for a person.
- Anything less is **weak** and only reported.
- A **tiebreaker** (marked below) ranks candidates and can send one to review, but never counts as the second signal that lets a strong signal propose.
- A **negative** signal lowers the score and keeps a candidate from being proposed: at most it needs review.
- Weights rank candidates; they are not probabilities. Once enough proposals have been reviewed, `amass ai train -kind ownership` learns the weights from those decisions and the trained model decides instead.

| Signal | Strength | Kind | Weight |
| --- | --- | --- | --- |
| [Shared registrant details](#shared-registrant-details) | strong | identity | 0.45 |
| [Shared registrant email domain](#shared-registrant-email-domain) | strong | identity | 0.40 |
| [DKIM signing key reuse](#dkim-key-reuse) | strong | identity | 0.40 |
| [Shared DNS verification token](#txt-verification-token) | strong | identity | 0.45 |
| [Certificate key reuse](#certificate-key-reuse) | strong | identity | 0.45 |
| [Certificate public key reuse](#certificate-public-key-reuse) | strong | identity | 0.45 |
| [Issued by the organization's private CA](#private-ca-issuance) | strong | identity | 0.45 |
| [security.txt points to the organization](#security-txt-reference) | supporting | operation | 0.25 |
| [Listed in the organization's bug-bounty program](#bug-bounty-scope) | strong | declaration | 0.40 |
| [RPKI ROA authorizes the organization's AS](#roa-authorizes-own-asn) | strong | operation | 0.40 |
| [Name or mail servers run by the organization](#self-hosted-dns) | strong | operation | 0.35 |
| [Email authentication delegated to the organization](#spf-authorizes) | strong | operation | 0.35 |
| [Hosted on the organization's infrastructure](#hosting-in-footprint) | supporting | hosting | 0.20 |
| [Listed on the organization's certificate](#certificate-colisting) | supporting | colisting | 0.15 |
| [Web redirect to the organization](#web-redirect-to-organization) | supporting | operation | 0.30 |
| [Reverse DNS in the organization's namespace](#reverse-dns-in-namespace) | supporting | operation | 0.25 |
| [Same DNS provider delegation set](#dns-provider-delegation-set) | strong | operation | 0.40 |
| [Same DNS provider account](#shared-nameserver-set) | supporting | operation | 0.25 |
| [Same TLS server fingerprint](#tls-fingerprint-match) | supporting (tiebreaker) | fingerprint | 0.10 |
| [Organization name in the asset's name](#name-token) | supporting (tiebreaker) | lexical | 0.10 |
| [A document states the organization operates it](#document-operator) | supporting | document | 0.25 |
| [Parked or for sale](#parked-for-sale) | negative | negative | 0.30 |
| [Shared analytics or tag identifier](#shared-analytics-id) | supporting | fingerprint | 0.30 |
| [Shared favicon](#shared-favicon) | supporting | fingerprint | 0.15 |
| [Shared page content](#shared-page-content) | supporting | fingerprint | 0.20 |
| [Same page title](#shared-page-title) | supporting (tiebreaker) | fingerprint | 0.10 |
| [SSH host key reuse](#ssh-host-key-reuse) | strong | identity | 0.40 |
| [Same certificate account in CAA](#caa-account-binding) | strong | identity | 0.50 |
| [Same internal addresses in public DNS](#shared-private-addresses) | strong | operation | 0.40 |
| [Mark certificate for the organization's LEI](#mark-certificate-identifier) | strong | identity | 0.50 |
| [security.txt names the organization's encryption key](#security-txt-shared-key) | strong | identity | 0.45 |
| [Web page names the organization](#page-names-organization) | supporting | operation | 0.30 |
| [Organization's pages load from the bucket](#page-references-bucket) | supporting | operation | 0.30 |

<a id="shared-registrant-details"></a>
## Shared registrant details

`shared-registrant-details`: strong identity signal, weight 0.45.

**Finds:** A registration contact the organization does not yet own that carries the same phone, postal address, email address or other identifier as a contact the organization controls. Only contact records count: a service's fingerprints are judged by the fingerprint signals.

**Why it counts:** Registrant details are entered by whoever registers the asset. Two registrations with the same phone and address were almost always made by the same party, and registries verify some of these details. One shared value can be a coincidence or a typo; two different shared values rarely are, which is why one shared value needs review and two may propose.

**Guards:**

- A third party's contact record never counts on either side: one named only as a domain's registrar, a network's abuse desk or a certificate's issuer (semantics.ThirdPartyContactLabels).
- Redaction and privacy-service placeholders never count (phrases in semantics/placeholder_values.json).
- A value carried by more contact records outside the organization's footprint than the hub limit never counts: it belongs to a registrar, provider or privacy service, not an owner. The hub limit is how many assets may carry a value of its kind before the value is an outlier in the database (a robust z-score above 3.5 on a log scale, never below 5). It is 50 until the database holds 1,000 values of the kind, and for values a search matches by part of their text rather than exactly.
- Assets another organization is documented as controlling are never candidates.
- A phone number that independent sources (registration records, OpenStreetMap, SEC filings) all give for the organization counts twice: it is corroborated as the organization's own.

**Can still mislead when:**

- Resellers and agencies sometimes register assets for clients with their own details.
- A university or holding company address can be shared by legally separate tenants or affiliates.

<a id="shared-registrant-email-domain"></a>
## Shared registrant email domain

`shared-registrant-email-domain`: strong identity signal, weight 0.40.

**Finds:** A registration contact the organization does not yet own whose email address is at the same custom domain as a contact of a registration the organization controls, such as admin@acme.com and security@acme.com. The controlled registration can be a domain, IP network or autonomous-system record.

**Why it counts:** A registrant email address is a mailbox at a domain the registrant controls. Two registrations whose contacts use the same custom mail domain were almost always made by the same organization, even when the mailboxes differ, which a match on the exact email address misses. Domain, network and autonomous-system registrations all carry these contacts, so the signal links assets across them. The registered domain is compared, so a mailbox at a subdomain still counts.

**Guards:**

- Webmail and free-email domains never count (this signal's free_mail).
- A mail domain carried by more than 50 registration contacts never counts: a provider, registrar or free service, not one owner.
- Redaction and privacy-service placeholders never count (the contacts are reached through stored identifiers, which the placeholder guards exclude).

**Can still mislead when:**

- A parent company or shared-services provider may register domains for several affiliates from one mailbox domain.
- Resellers and agencies sometimes register client domains using their own email domain.

<a id="dkim-key-reuse"></a>
## DKIM signing key reuse

`dkim-key-reuse`: strong identity signal, weight 0.40.

**Finds:** A domain the organization does not yet own that publishes the same DKIM public key as a domain the organization controls.

**Why it counts:** A DKIM public key in DNS pairs with a private key held by whoever signs the domain's mail. The same public key on two domains means their mail is signed by the same private key, so the same party operates both.

**Guards:**

- Only DKIM records (v=DKIM1) with a non-empty public key count; a revoked key (empty p=) never counts.
- A key published by more than 50 domains never counts: a mail provider's shared or CNAME-delegated key, not one owner's.
- Only the DKIM selectors the collector probes are seen, so a shared key under an unprobed selector is missed, not miscounted.

**Can still mislead when:**

- A mail provider or marketing platform may publish one DKIM key, through CNAME delegation, across many customers' domains (the 50-domain limit catches large ones).

<a id="txt-verification-token"></a>
## Shared DNS verification token

`txt-verification-token`: strong identity signal, weight 0.45.

**Finds:** A domain the organization does not yet own whose DNS TXT records carry the same service verification token as a domain the organization controls.

**Why it counts:** SaaS providers ask a customer to publish a token in DNS to prove control of a domain, and the token is issued to one customer account. The same token on two domains means one account verified both, so the same administrators control them.

**Guards:**

- Only TXT records that start with a known verification prefix count.
- A token on more domains than the hub limit for the signal's own tokens never counts.

**Can still mislead when:**

- A managed-service provider or agency may verify client domains under its own account.
- Tokens copied from documentation or templates appear on unrelated domains (the 50-domain limit catches the common ones).

**Verification prefixes:** `google-site-verification=`, `ms=`, `facebook-domain-verification=`, `atlassian-domain-verification=`, `apple-domain-verification=`, `adobe-idp-site-verification=`, `docusign=`, `zoom-domain-verification=`, `slack-domain-verification=`, `dropbox-domain-verification=`, `stripe-verification=`, `hubspot-developer-verification=`, `onetrust-domain-verification=`, `cisco-ci-domain-verification=`, `globalsign-domain-verification=`, `_globalsign-domain-verification=`

<a id="certificate-key-reuse"></a>
## Certificate key reuse

`certificate-key-reuse`: strong identity signal, weight 0.45.

**Finds:** A certificate whose subject key identifier matches a certificate the organization controls; the candidate is the name that certificate was issued to.

**Why it counts:** The subject key identifier is derived from the certificate's public key. Two certificates with the same identifier were issued for the same key pair, and only the holder of the private key can request them, so the same party operates both.

**Guards:**

- A certificate a CDN or hosting provider manages for many customers (one covering a name in provider_managed_names in certificates.json, such as cloudflaressl.com or incapsula.com) never counts.
- A key identifier shared by more certificates than the hub limit for key identifiers never counts.

**Can still mislead when:**

- A hosting or CDN provider that reuses one key across its customers' certificates (the 50-certificate limit catches large providers).

<a id="certificate-public-key-reuse"></a>
## Certificate public key reuse

`certificate-public-key-reuse`: strong identity signal, weight 0.45.

**Finds:** A certificate whose public key (the SHA-256 of its SubjectPublicKeyInfo) matches a certificate the organization controls; the candidate is the name that certificate was issued to.

**Why it counts:** The public key hash identifies the key pair itself, whatever the subject key identifier, which some certificates omit or set non-standardly. Two certificates with the same public key were issued for the same key pair, and only the holder of the private key can request them, so the same party operates both.

**Guards:**

- A certificate a CDN or hosting provider manages for many customers (one covering a name in provider_managed_names in certificates.json, such as cloudflaressl.com or incapsula.com) never counts.
- A public key shared by more certificates than the hub limit for public keys never counts.

**Can still mislead when:**

- A hosting or CDN provider that reuses one key pair across its customers' certificates (the 50-certificate limit catches large providers).

<a id="private-ca-issuance"></a>
## Issued by the organization's private CA

`private-ca-issuance`: strong identity signal, weight 0.45.

**Finds:** A certificate signed by the same issuing key as a certificate the organization controls, when that issuer is not a public certificate authority; the candidate is the name that certificate was issued to.

**Why it counts:** Organizations run private certificate authorities for internal and partner-facing services, and only they can sign with that CA's key. A certificate from the same private issuing key was issued by the same organization.

**Guards:**

- A certificate a CDN or hosting provider manages for many customers (one covering a name in provider_managed_names in certificates.json, such as cloudflaressl.com or incapsula.com) never counts.
- The issuing certificate must be stored, and no certificate up the chain (to four levels) may name a public certificate authority (the authorities in certificates.json). Public intermediates with short names chain to well-known public roots, so the walk finds them; a certificate whose chain is unknown never counts.
- An issuing key shared by more certificates than the hub limit for issuing keys never counts.

**Can still mislead when:**

- A managed PKI provider can operate one private CA for several customers.
- A public root missing from the authorities in certificates.json would wrongly count until it is added.

<a id="security-txt-reference"></a>
## security.txt points to the organization

`security-txt-reference`: supporting operation signal, weight 0.25.

**Finds:** A name the organization does not yet own whose security.txt names a security contact at the organization's domain, or gives a canonical or policy URL in the organization's namespace.

**Why it counts:** A security.txt is published by whoever runs the site, and its contact and canonical URL are normally the operator's own. A file that reports to the organization's mailbox or points to the organization's canonical copy was usually published for the organization.

**Guards:**

- The contact host or URL host must be one of the organization's apex domains or a name below one; a name that merely contains it never counts.
- A value shared by more than 50 security.txt files never counts.
- Never proposes on its own; it needs a strong signal.

**Can still mislead when:**

- A managed security provider or bug-bounty platform may publish one organization's contact across several clients' files.
- A template copied between unrelated sites can carry another organization's canonical URL.

<a id="bug-bounty-scope"></a>
## Listed in the organization's bug-bounty program

`bug-bounty-scope`: strong declaration signal, weight 0.40.

**Finds:** A name or address range the organization does not yet own that a public bug-bounty program lists in scope beside one of the organization's names, when the program is tied to the organization: its website is in the organization's namespace, its name is exactly the organization's name, the organization's domain carries the platform's verification TXT record (bugcrowd-verification), or the organization's security.txt links the program's page.

**Why it counts:** A bug-bounty program's scope is the organization declaring, in public, the assets it is responsible for and invites researchers to test. Once the program is tied to the organization by its own records, the rest of its scope is the organization's own account of what it runs.

**Guards:**

- Review only: it raises a candidate to review but never causes or helps cause an automatic write.
- A program the organization's records do not tie to it gives no signal; its listing stays an observation.
- Names under cloud providers' hosting domains and the platforms' own sites are skipped.
- Only in-scope entries count; out-of-scope entries are mostly vendors' services.

**Can still mislead when:**

- Programs sometimes list a vendor-hosted tenant or a partner's system the organization tests but does not own.
- A parent company's program can cover subsidiaries and acquisitions that are separate organizations in the graph.
- Scopes go stale: a divested business can stay listed until the program is updated.

The same evidence also ties other domains to the organization: see [Listed in the organization's bug-bounty program](HORIZONTALS.md#bug-bounty-scope).

<a id="roa-authorizes-own-asn"></a>
## RPKI ROA authorizes the organization's AS

`roa-authorizes-own-asn`: strong operation signal, weight 0.40.

**Finds:** A netblock the organization does not yet own that a valid RPKI Route Origin Authorization (ROA) authorizes one of the organization's autonomous systems to announce.

**Why it counts:** Only the holder of address space can sign a ROA for it. A ROA naming the organization's AS is the holder's signed statement that the organization's network routes the prefix, so the netblock is operated for the organization.

**Guards:**

- Only valid ROAs whose prefix and maximum length cover the netblock count.

**Can still mislead when:**

- A provider can sign a ROA for its own space naming a customer's AS, so the organization operates the netblock without holding it.

<a id="self-hosted-dns"></a>
## Name or mail servers run by the organization

`self-hosted-dns`: strong operation signal, weight 0.35.

**Finds:** A name or domain registration the organization does not yet own whose NS or MX records, SOA primary name server, or registered name servers are names the organization controls.

**Why it counts:** Pointing a domain's name servers or mail exchangers at another party's hosts hands that party the domain's DNS or email. Organizations do that for their own domains; DNS and email providers do it for customers, but those providers' names are third parties in the semantics table, not part of the organization's footprint.

**Guards:**

- Only name servers and mail exchangers in the organization's controlled footprint count; provider hosts never do.

**Can still mislead when:**

- Universities, ISPs and holding companies sometimes host DNS or mail for affiliates and customers.

<a id="spf-authorizes"></a>
## Email authentication delegated to the organization

`spf-authorizes`: strong operation signal, weight 0.35.

**Finds:** A domain the organization does not yet own whose SPF record includes or redirects to a domain the organization controls, or whose DMARC record sends aggregate or forensic reports to an address at such a domain.

**Why it counts:** SPF authorizes the referenced domain's mail servers to send as this domain, and DMARC sends this domain's authentication reports to the referenced mailbox. Both hand email control to the referenced party, which is normally the domain's own owner.

**Guards:**

- The referenced host must be one of the organization's apex domains or a name below one, parsed from the SPF include:/redirect= terms or the DMARC rua=/ruf= addresses; a name that merely contains it never counts.

**Can still mislead when:**

- An email service provider's customers include the provider's SPF domain, but a provider is not the organization being investigated.
- Report-processing services receive DMARC reports for their customers.

The same evidence also ties other domains to the organization: see [Email authentication delegated to the organization](HORIZONTALS.md#spf-authorizes).

<a id="hosting-in-footprint"></a>
## Hosted on the organization's infrastructure

`hosting-in-footprint`: supporting hosting signal, weight 0.20.

**Finds:** An asset the organization does not yet own that depends on infrastructure the organization controls, such as a name resolving into its network.

**Why it counts:** Organizations host their own assets, so dependence on their infrastructure is consistent with ownership. It is only supporting evidence: customers, tenants and vendors are hosted on other parties' networks every day.

**Guards:**

- Never counts through shared infrastructure: an address in a cloud or CDN provider's published range, a private or reserved address, or a name that resolves only to such addresses.
- Never proposes on its own; it needs a strong signal.

**Can still mislead when:**

- Shared hosting, colocation and customers of a network operator.
- A provider's own netblocks: its customers depend on them without being owned by it, which is why provider ranges are skipped.

<a id="certificate-colisting"></a>
## Listed on the organization's certificate

`certificate-colisting`: supporting colisting signal, weight 0.15.

**Finds:** A name the organization does not yet own that appears as a subject alternative name on a certificate that also lists a name the organization controls.

**Why it counts:** One certificate covering several names was usually requested by one party for its own services. Certificates listing many names are often a provider's shared certificate, so this counts only for certificates with few names and only as supporting evidence.

**Guards:**

- A certificate a CDN or hosting provider manages for many customers (one covering a name in provider_managed_names in certificates.json, such as cloudflaressl.com or incapsula.com) never counts.
- Certificates listing more names than the hub limit never count (10 until the database holds enough certificates).
- Never proposes on its own; it needs a strong signal.

**Can still mislead when:**

- CDN and hosting certificates that cover several customers.

<a id="web-redirect-to-organization"></a>
## Web redirect to the organization

`web-redirect-to-organization`: supporting operation signal, weight 0.30.

**Finds:** A name or address the organization does not yet own whose web service redirects to a name in the organization's namespace (its Location, Content-Location or Refresh response header).

**Why it counts:** Organizations point the domains they hold, such as typo, campaign and legacy domains, at their main site. A redirect into the organization's namespace is set by whoever operates the redirecting service, which is usually the domain's owner.

**Guards:**

- The redirect target must be one of the organization's apex domains or a name below one; a name that merely contains it never counts.
- Never proposes on its own; it needs a strong signal.

**Can still mislead when:**

- Link shorteners, affiliates, news sites and partners also redirect to an organization's pages.
- A squatter can redirect a look-alike domain to the real site.

<a id="reverse-dns-in-namespace"></a>
## Reverse DNS in the organization's namespace

`reverse-dns-in-namespace`: supporting operation signal, weight 0.25.

**Finds:** An IP address the organization does not yet own whose reverse DNS (PTR) name is a name the organization controls, and the names that resolve to that address.

**Why it counts:** Reverse DNS is set by whoever controls the address space, so an address that names itself inside the organization's namespace is usually run for the organization. A provider can set PTR names on a customer's request, which is why it only supports other evidence.

**Guards:**

- Addresses that more names resolve to than the hub limit never pass the signal on to those names.
- Never proposes on its own; it needs a strong signal.

**Can still mislead when:**

- Hosting providers set PTR names a customer asks for on addresses the provider still controls.
- Stale PTR records outlive a move to new infrastructure.

<a id="dns-provider-delegation-set"></a>
## Same DNS provider delegation set

`dns-provider-delegation-set`: strong operation signal, weight 0.40.

**Finds:** A domain registration the organization does not yet own that lists exactly the same full set of name servers as one of the organization's domain registrations, when the set belongs to a provider that gives each account or hosted zone its own set drawn from a large pool (dns.json assignment unique_set, such as an Amazon Route 53 delegation set of four servers).

**Why it counts:** Route 53 gives each hosted zone four name servers chosen from thousands, and an account can reuse one delegation set across its zones. Two unrelated zones landing on the identical set of four by chance is vanishingly rare, so a shared full set is strong evidence the domains are in one account.

**Guards:**

- The whole set must match, at least four servers, all from the one provider.
- None may be the organization's own servers (that is the self-hosted DNS signal).
- A set shared by more registrations than the hub limit never counts.
- Providers whose customers share servers (assignment shared) give no signal, and providers that reuse sets across accounts (assignment account, such as Cloudflare's per-account pairs) give only the supporting same-provider-account signal.

**Can still mislead when:**

- A reseller, agency or managed-service provider can host many clients' zones in its own account, so the domains share an operator rather than an owner.

The same evidence also ties other domains to the organization: see [Same DNS provider delegation set](HORIZONTALS.md#dns-provider-delegation-set).

<a id="shared-nameserver-set"></a>
## Same DNS provider account

`shared-nameserver-set`: supporting operation signal, weight 0.25.

**Finds:** A domain registration the organization does not yet own that lists every name server of one of the organization's domain registrations.

**Why it counts:** Several DNS providers assign each customer account its own pair or set of name servers. A domain served by exactly the same set as the organization's domain was likely set up in the same provider account.

**Guards:**

- Only sets of at least two name servers count, and none may be the organization's own servers (that is the self-hosted DNS signal).
- A set shared by more registrations than the hub limit never counts.
- A set of a provider whose customers share servers (dns.json assignment shared) never counts; a full set of a provider that gives each account or zone its own set (unique_set) counts as the strong delegation-set signal instead.
- Never proposes on its own; it needs a strong signal.

**Can still mislead when:**

- Providers that give every customer the same name servers make unrelated domains share a set; the 50-registration limit catches large ones.

<a id="tls-fingerprint-match"></a>
## Same TLS server fingerprint

`tls-fingerprint-match`: supporting fingerprint signal, weight 0.10. Tiebreaker.

**Finds:** A name or address the organization does not yet own whose service has the same JARM TLS fingerprint as a service on a name the organization controls.

**Why it counts:** A JARM fingerprint summarizes how a TLS server answers ten crafted handshakes, which reflects its software and configuration. A matching fingerprint is consistent with the same team deploying both servers, but many unrelated servers share common configurations, so it is only a tiebreaker.

**Guards:**

- Never counts from a service on shared infrastructure (a cloud or CDN provider's range, or a private address): behind a CDN the fingerprint is the CDN's, not the site's.
- A fingerprint shared by more services than the hub limit never counts.
- A tiebreaker: it never counts as the second signal that lets a strong signal propose, so it can only rank candidates or send one to review.

**Can still mislead when:**

- Default configurations of popular servers, load balancers and CDNs produce the same fingerprint for unrelated sites.

<a id="name-token"></a>
## Organization name in the asset's name

`name-token`: supporting lexical signal, weight 0.10. Tiebreaker.

**Finds:** A candidate that other signals already link to the organization and whose name contains a distinctive word of the organization's name, such as owasp in owasp-events.com.

**Why it counts:** Organizations name their assets after themselves. The word must be distinctive, so generic words like university or group never count, and it is only ever added to a candidate other evidence already found.

**Guards:**

- Only words of at least five letters that are not in this signal's stop_words count.
- A tiebreaker: it never counts as the second signal that lets a strong signal propose, so it can only rank candidates or send one to review.
- Never finds candidates by itself.

**Can still mislead when:**

- Fans, critics, resellers, squatters and unrelated organizations with similar names use the same words.

<a id="document-operator"></a>
## A document states the organization operates it

`document-operator`: supporting document signal, weight 0.25.

**Finds:** A finding the document model read from a stored document that a host name or URL is operated by the subject organization, named exactly by its name or legal name.

**Why it counts:** Organizations name the systems they run in policies, reports and help pages (the VPN, the student portal), and the quote was checked against the text. It points at assets the network evidence has not yet tied to the organization.

**Guards:**

- Supporting only: it weighs 0.15, 0.05 more when the document is published on one of the organization's own domains and 0.05 more when two or more distinct document versions state it, never more than 0.25 (see semantics/document_signals.json).
- The organization must be named exactly, and the host or URL must already be stored.
- It never helps an ownership relationship be written automatically: a candidate qualifies for that only on its other evidence.

**Can still mislead when:**

- A document can name a service a vendor runs for the organization.
- Old documents name systems since retired or handed to someone else.

<a id="parked-for-sale"></a>
## Parked or for sale

`parked-for-sale`: negative negative signal, weight 0.30.

**Finds:** A candidate name whose web page is a parking or domain-for-sale page.

**Why it counts:** A parked or for-sale page means a domainer or registrar, not the organization, controls the name today, whatever its other links. It counts against ownership.

**Guards:**

- A candidate with this signal is never proposed for an automatic write; at most it waits for review.

**Can still mislead when:**

- Organizations sometimes park defensive registrations with a registrar's default page.

**Page phrases:** `this domain is for sale`, `this domain may be for sale`, `buy this domain`, `domain is parked`, `parked free`, `parkingcrew`, `sedoparking`, `bodis.com`, `dan.com`, `afternic`, `hugedomains`, `undeveloped.com`

<a id="shared-analytics-id"></a>
## Shared analytics or tag identifier

`shared-analytics-id`: supporting fingerprint signal, weight 0.30.

**Finds:** A name, address or URL the organization does not yet own whose pages carry an analytics or tag-manager identifier (Google Analytics, Google Tag Manager, Google Ads, AdSense, Meta pixel, Hotjar, Clarity) that a page of the organization also carries.

**Why it counts:** Analytics and tag-manager identifiers are issued to one account, and the account's owner adds them to the sites it runs, so two sites reporting to the same account are usually run by the same team. They are copied along with a page, though, so they only support other evidence.

**Guards:**

- Identifiers are recognized by provider-specific patterns (internal/fingerprint), not any string that looks like one.
- An identifier on more services or URLs than the hub limit never counts.
- Supporting only: without a strong signal it can at most send a candidate to review.

**Can still mislead when:**

- A cloned or phishing copy of the organization's site carries the same identifiers; this is why it is never strong evidence.
- Agencies sometimes run one tag-manager container across several clients.

The same evidence also ties other domains to the organization: see [Shared analytics or tag identifier](HORIZONTALS.md#shared-analytics-id).

<a id="shared-favicon"></a>
## Shared favicon

`shared-favicon`: supporting fingerprint signal, weight 0.15.

**Finds:** A name, address or URL the organization does not yet own whose site has the same favicon (by its MurmurHash3, as Shodan computes it) as a site of the organization.

**Why it counts:** A custom favicon is a brand asset an organization reuses across its own sites, so the same icon suggests the same owner. Default icons of web servers, frameworks and hosting panels are shared by countless unrelated sites, which the hub limit excludes.

**Guards:**

- A favicon on more services or URLs than the hub limit never counts (default and framework icons).
- Supporting only: without a strong signal it can at most send a candidate to review.

**Can still mislead when:**

- A cloned or phishing copy of the organization's site carries the same favicon; this is why it is never strong evidence.
- Resellers and partners display the organization's logo as their icon.

The same evidence also ties other domains to the organization: see [Shared favicon](HORIZONTALS.md#shared-favicon).

<a id="shared-page-content"></a>
## Shared page content

`shared-page-content`: supporting fingerprint signal, weight 0.20.

**Finds:** A name, address or URL the organization does not yet own that serves exactly the same page (by the SHA-256 of its normalized body) as a site of the organization.

**Why it counts:** Serving byte-for-byte the same page usually means the same deployment behind several names, such as mirrors, aliases and old domains. Pages under 512 bytes are never hashed, because redirects, error stubs and default pages are identical everywhere.

**Guards:**

- Bodies shorter than 512 bytes are not hashed (internal/fingerprint).
- A hash on more services or URLs than the hub limit never counts.
- Supporting only: without a strong signal it can at most send a candidate to review.

**Can still mislead when:**

- A cloned or phishing copy of the organization's site carries the same page; this is why it is never strong evidence.
- Parking, maintenance and hosting-provider pages are identical across their customers.

The same evidence also ties other domains to the organization: see [Shared page content](HORIZONTALS.md#shared-page-content).

<a id="shared-page-title"></a>
## Same page title

`shared-page-title`: supporting fingerprint signal, weight 0.10. Tiebreaker.

**Finds:** A name, address or URL the organization does not yet own whose page has the same title as a page of the organization.

**Why it counts:** A distinctive title, such as one naming the organization or a product of it, is often reused across its sites. Titles are short, chosen freely and copied, so a title only breaks ties between candidates other evidence found.

**Guards:**

- Titles shorter than 8 characters and generic titles (this signal's ignore_values) never count.
- A title on more services or URLs than the hub limit never counts.
- A tiebreaker: it never counts as the second signal that lets a strong signal propose.

**Can still mislead when:**

- A cloned or phishing copy of the organization's site carries the same title; this is why it is never strong evidence.
- Products and templates give unrelated sites the same title.

<a id="ssh-host-key-reuse"></a>
## SSH host key reuse

`ssh-host-key-reuse`: strong identity signal, weight 0.40.

**Finds:** An address or name the organization does not yet own whose SSH server presents a host key that an SSH server on an address the organization controls also presents.

**Why it counts:** An SSH host key is a private key generated on the server. The same key on two servers means they are the same machine reachable at two addresses, or were built from the same image by whoever holds the key, so the same party operates both.

**Guards:**

- Only addresses inside the organization's controlled footprint (its netblocks) are compared, never hosting it merely resolves to.
- A host key on more services than the hub limit never counts: vendor appliances and cloud images that ship with a baked-in key.
- Collected only in active enumeration, by completing the SSH key exchange; no user name or credential is ever sent.

**Can still mislead when:**

- Vendor appliances and published VM images that share one default key across customers (the 50-service limit catches widely deployed ones).

<a id="caa-account-binding"></a>
## Same certificate account in CAA

`caa-account-binding`: strong identity signal, weight 0.50.

**Finds:** A domain the organization does not yet own whose CAA record binds certificate issuance to the same ACME account (accounturi, RFC 8657) as a CAA record of a domain the organization controls.

**Why it counts:** An accounturi parameter lets only one ACME account obtain certificates for the domain. The account belongs to whoever requests the certificates, so two domains bound to the same account have their certificates issued by the same operator.

**Guards:**

- The account URI must match exactly.
- An account URI published by more than 50 domains never counts: a hosting provider's shared account.

**Can still mislead when:**

- A managed hosting or certificate service may bind all its customers' domains to its own account.

<a id="shared-private-addresses"></a>
## Same internal addresses in public DNS

`shared-private-addresses`: strong operation signal, weight 0.40.

**Finds:** Names under a domain the organization does not yet own that resolve to at least two of the same private (RFC 1918) or other reserved addresses as names the organization controls.

**Why it counts:** A private address only means something inside one network. Public names that resolve to the same internal addresses come from the same internal DNS, which one operator runs; two unrelated organizations rarely publish the same two internal addresses.

**Guards:**

- At least two distinct addresses must be shared with the same registered domain.
- Addresses in the most common default ranges (192.168.0.0/23, 10.0.0.0/24, 172.16.0.0/24) and addresses ending in .0, .1, .254 or .255 never count.
- An address more names resolve to than the hub limit never counts.

**Can still mislead when:**

- Two organizations that merged, or that share an outsourced IT provider's internal DNS, can publish the same internal addresses.

<a id="mark-certificate-identifier"></a>
## Mark certificate for the organization's LEI

`mark-certificate-identifier`: strong identity signal, weight 0.50.

**Finds:** A domain the organization does not yet own with a BIMI mark certificate whose subject carries the same Legal Entity Identifier as the organization.

**Why it counts:** A certificate authority verifies the organization behind a mark certificate before issuing it, and the LEI it records identifies exactly one legal entity. A domain with a mark certificate for the organization's LEI was certified as the organization's.

**Guards:**

- The LEI must match exactly.
- Only mark certificates (extended key usage for BIMI) count; an ordinary certificate's subject is not verified the same way.

**Can still mislead when:**

- A brand licensed to another company can be certified for the licensee, whose LEI is its own.

<a id="security-txt-shared-key"></a>
## security.txt names the organization's encryption key

`security-txt-shared-key`: strong identity signal, weight 0.45.

**Finds:** A name the organization does not yet own whose security.txt gives the same Encryption key URL as a security.txt of a domain the organization controls.

**Why it counts:** The Encryption field names the key reports to the security team should be encrypted with. One security team holds that key, so two files naming the same key report to the same team.

**Guards:**

- The key URL must match exactly.
- A key URL named by more than 50 security.txt files never counts: a managed provider's or platform's key.

**Can still mislead when:**

- A managed security provider or bug-bounty platform may publish its own key in several clients' files.

<a id="page-names-organization"></a>
## Web page names the organization

`page-names-organization`: supporting operation signal, weight 0.30.

**Finds:** A name or address the organization does not yet own whose web page carries a copyright notice for the organization, or describes the organization in its schema.org Organization markup.

**Why it counts:** A site's footer and its structured data name whoever publishes it. A page that declares itself the organization's was usually published for the organization, though a vendor building a site for a client publishes the client's name too.

**Guards:**

- The organization's name must follow a copyright marker (©, &copy; or Copyright) or be the name of a schema.org Organization; a mention anywhere else on the page never counts.
- Names shorter than six characters never count.
- A name found on more than 50 services never counts.
- Never proposes on its own; it needs a strong signal.

**Can still mislead when:**

- A news site, directory or partner page can carry markup describing the organization.
- A site copied from a template can keep another organization's copyright line.

<a id="page-references-bucket"></a>
## Organization's pages load from the bucket

`page-references-bucket`: supporting operation signal, weight 0.30.

**Finds:** An object-storage bucket host (Amazon S3, Google Cloud Storage, Azure Blob and the other providers in bucket_providers.json) the organization does not yet own that a web page on a name the organization controls loads from or links to.

**Why it counts:** Organizations serve their sites' images, documents and scripts from their own buckets, so a bucket their pages load from is usually theirs. It is only supporting evidence: pages also load from vendors' buckets.

**Guards:**

- The host must match a provider's bucket host pattern; a provider's own hostname without a bucket name never counts.
- Never proposes on its own; it needs a strong signal.

**Can still mislead when:**

- Widgets, fonts and embedded tools are often served from their vendors' buckets.
