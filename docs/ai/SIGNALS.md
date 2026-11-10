# Ownership signals

<!-- Generated from internal/ai/semantics/ownership_signals.json by `amass ai signals -format markdown`. Edit that file, not this one. -->

Amass proposes that an organization owns an asset it has not been attributed to only from stored evidence. Each kind of evidence is a signal, listed here with why it counts, what stops it from misfiring, and when it can still mislead. The same text is shown by `amass ai signals`.

## How signals decide

- A candidate with two strong signals, or one strong signal and a different second signal, is **proposed** when exactly one OAM relationship can record the owner. During enumeration a proposed candidate is written automatically (with the `amass-ai` source) unless attribution is set to `journal` or `off`.
- One strong signal, or two signals of any strength, **needs review**: it waits in the review journal for a person.
- Anything less is **weak** and only reported.
- A **tiebreaker** (marked below) ranks candidates and can send one to review, but never counts as the second signal that lets a strong signal propose.
- A **negative** signal lowers the score and keeps a candidate from being proposed: at most it needs review.
- Weights rank candidates; they are not probabilities. Once enough proposals have been reviewed, `amass ai train-attribution` learns the weights from those decisions and the trained model decides instead.

| Signal | Strength | Kind | Weight |
| --- | --- | --- | --- |
| [Shared registrant details](#shared_registrant_details) | strong | identity | 0.45 |
| [Shared DNS verification token](#txt_verification_token) | strong | identity | 0.45 |
| [Certificate key reuse](#certificate_key_reuse) | strong | identity | 0.45 |
| [Issued by the organization's private CA](#private_ca_issuance) | strong | identity | 0.45 |
| [Name or mail servers run by the organization](#self_hosted_dns) | strong | operation | 0.35 |
| [Email authentication delegated to the organization](#email_auth_reference) | strong | operation | 0.35 |
| [Hosted on the organization's infrastructure](#hosting_in_footprint) | supporting | hosting | 0.20 |
| [Listed on the organization's certificate](#certificate_colisting) | supporting | colisting | 0.15 |
| [Web redirect to the organization](#web_redirect_to_organization) | supporting | operation | 0.30 |
| [Reverse DNS in the organization's namespace](#reverse_dns_in_namespace) | supporting | operation | 0.25 |
| [Same DNS provider account](#shared_nameserver_set) | supporting | operation | 0.25 |
| [Same TLS server fingerprint](#tls_fingerprint_match) | supporting (tiebreaker) | fingerprint | 0.10 |
| [Organization name in the asset's name](#name_token) | supporting (tiebreaker) | lexical | 0.10 |
| [Parked or for sale](#parked_for_sale) | negative | negative | 0.30 |
| [Same analytics or tag identifier](#shared_analytics_id) | supporting | fingerprint | 0.30 |
| [Same favicon](#same_favicon) | supporting | fingerprint | 0.15 |
| [Same page content](#same_page_content) | supporting | fingerprint | 0.20 |
| [Same page title](#same_page_title) | supporting (tiebreaker) | fingerprint | 0.10 |
| [SSH host key reuse](#ssh_host_key_reuse) | strong | identity | 0.40 |

<a id="shared_registrant_details"></a>
## Shared registrant details

`shared_registrant_details`: strong identity signal, weight 0.45.

**Finds:** A registration contact the organization does not yet own that carries the same phone, postal address, email address or other identifier as a contact the organization controls.

**Why it counts:** Registrant details are entered by whoever registers the asset. Two registrations with the same phone and address were almost always made by the same party, and registries verify some of these details. One shared value can be a coincidence or a typo; two different shared values rarely are, which is why one shared value needs review and two may propose.

**Guards:**

- Redaction and privacy-service placeholders never count (phrases in semantics/placeholder_values.json).
- A value carried by more than 50 assets never counts: it belongs to a registrar, provider or privacy service, not an owner.
- Assets another organization is documented as controlling are never candidates.

**Can still mislead when:**

- Resellers and agencies sometimes register assets for clients with their own details.
- A university or holding company address can be shared by legally separate tenants or affiliates.

<a id="txt_verification_token"></a>
## Shared DNS verification token

`txt_verification_token`: strong identity signal, weight 0.45.

**Finds:** A domain the organization does not yet own whose DNS TXT records carry the same service verification token as a domain the organization controls.

**Why it counts:** SaaS providers ask a customer to publish a token in DNS to prove control of a domain, and the token is issued to one customer account. The same token on two domains means one account verified both, so the same administrators control them.

**Guards:**

- Only TXT records that start with a known verification prefix count.
- A token on more than 50 domains never counts.

**Can still mislead when:**

- A managed-service provider or agency may verify client domains under its own account.
- Tokens copied from documentation or templates appear on unrelated domains (the 50-domain limit catches the common ones).

**Verification prefixes:** `google-site-verification=`, `ms=`, `facebook-domain-verification=`, `atlassian-domain-verification=`, `apple-domain-verification=`, `adobe-idp-site-verification=`, `docusign=`, `zoom-domain-verification=`, `slack-domain-verification=`, `dropbox-domain-verification=`, `stripe-verification=`, `hubspot-developer-verification=`, `onetrust-domain-verification=`, `cisco-ci-domain-verification=`, `globalsign-domain-verification=`, `_globalsign-domain-verification=`

<a id="certificate_key_reuse"></a>
## Certificate key reuse

`certificate_key_reuse`: strong identity signal, weight 0.45.

**Finds:** A certificate whose subject key identifier matches a certificate the organization controls; the candidate is the name that certificate was issued to.

**Why it counts:** The subject key identifier is derived from the certificate's public key. Two certificates with the same identifier were issued for the same key pair, and only the holder of the private key can request them, so the same party operates both.

**Guards:**

- A key identifier shared by more than 50 certificates never counts.

**Can still mislead when:**

- A hosting or CDN provider that reuses one key across its customers' certificates (the 50-certificate limit catches large providers).

<a id="private_ca_issuance"></a>
## Issued by the organization's private CA

`private_ca_issuance`: strong identity signal, weight 0.45.

**Finds:** A certificate signed by the same issuing key as a certificate the organization controls, when that issuer is not a public certificate authority; the candidate is the name that certificate was issued to.

**Why it counts:** Organizations run private certificate authorities for internal and partner-facing services, and only they can sign with that CA's key. A certificate from the same private issuing key was issued by the same organization.

**Guards:**

- Issuers that name a public certificate authority never count (list in this signal's public_issuers).
- An issuing key shared by more than 50 certificates never counts.

**Can still mislead when:**

- A managed PKI provider can operate one private CA for several customers.
- A public CA missing from public_issuers would wrongly count until it is added (the 50-certificate limit catches large ones).

<a id="self_hosted_dns"></a>
## Name or mail servers run by the organization

`self_hosted_dns`: strong operation signal, weight 0.35.

**Finds:** A name or domain registration the organization does not yet own whose NS or MX records, or whose registered name servers, are names the organization controls.

**Why it counts:** Pointing a domain's name servers or mail exchangers at another party's hosts hands that party the domain's DNS or email. Organizations do that for their own domains; DNS and email providers do it for customers, but those providers' names are third parties in the semantics table, not part of the organization's footprint.

**Guards:**

- Only name servers and mail exchangers in the organization's controlled footprint count; provider hosts never do.

**Can still mislead when:**

- Universities, ISPs and holding companies sometimes host DNS or mail for affiliates and customers.

<a id="email_auth_reference"></a>
## Email authentication delegated to the organization

`email_auth_reference`: strong operation signal, weight 0.35.

**Finds:** A domain the organization does not yet own whose SPF record includes or redirects to a domain the organization controls, or whose DMARC record sends aggregate or forensic reports to an address at such a domain.

**Why it counts:** SPF authorizes the referenced domain's mail servers to send as this domain, and DMARC sends this domain's authentication reports to the referenced mailbox. Both hand email control to the referenced party, which is normally the domain's own owner.

**Guards:**

- The referenced host must be one of the organization's apex domains or a name below one, parsed from the SPF include:/redirect= terms or the DMARC rua=/ruf= addresses; a name that merely contains it never counts.

**Can still mislead when:**

- An email service provider's customers include the provider's SPF domain, but a provider is not the organization being investigated.
- Report-processing services receive DMARC reports for their customers.

<a id="hosting_in_footprint"></a>
## Hosted on the organization's infrastructure

`hosting_in_footprint`: supporting hosting signal, weight 0.20.

**Finds:** An asset the organization does not yet own that depends on infrastructure the organization controls, such as a name resolving into its network.

**Why it counts:** Organizations host their own assets, so dependence on their infrastructure is consistent with ownership. It is only supporting evidence: customers, tenants and vendors are hosted on other parties' networks every day.

**Guards:**

- Never proposes on its own; it needs a strong signal.

**Can still mislead when:**

- Shared hosting, colocation and customers of a network operator.

<a id="certificate_colisting"></a>
## Listed on the organization's certificate

`certificate_colisting`: supporting colisting signal, weight 0.15.

**Finds:** A name the organization does not yet own that appears as a subject alternative name on a certificate that also lists a name the organization controls.

**Why it counts:** One certificate covering several names was usually requested by one party for its own services. Certificates listing many names are often a provider's shared certificate, so this counts only for certificates with few names and only as supporting evidence.

**Guards:**

- Certificates listing more than 10 names never count.
- Never proposes on its own; it needs a strong signal.

**Can still mislead when:**

- CDN and hosting certificates that cover several customers.

<a id="web_redirect_to_organization"></a>
## Web redirect to the organization

`web_redirect_to_organization`: supporting operation signal, weight 0.30.

**Finds:** A name or address the organization does not yet own whose web service redirects to a name in the organization's namespace (its Location, Content-Location or Refresh response header).

**Why it counts:** Organizations point the domains they hold, such as typo, campaign and legacy domains, at their main site. A redirect into the organization's namespace is set by whoever operates the redirecting service, which is usually the domain's owner.

**Guards:**

- The redirect target must be one of the organization's apex domains or a name below one; a name that merely contains it never counts.
- Never proposes on its own; it needs a strong signal.

**Can still mislead when:**

- Link shorteners, affiliates, news sites and partners also redirect to an organization's pages.
- A squatter can redirect a look-alike domain to the real site.

<a id="reverse_dns_in_namespace"></a>
## Reverse DNS in the organization's namespace

`reverse_dns_in_namespace`: supporting operation signal, weight 0.25.

**Finds:** An IP address the organization does not yet own whose reverse DNS (PTR) name is a name the organization controls, and the names that resolve to that address.

**Why it counts:** Reverse DNS is set by whoever controls the address space, so an address that names itself inside the organization's namespace is usually run for the organization. A provider can set PTR names on a customer's request, which is why it only supports other evidence.

**Guards:**

- Addresses that more than 50 names resolve to never pass the signal on to those names.
- Never proposes on its own; it needs a strong signal.

**Can still mislead when:**

- Hosting providers set PTR names a customer asks for on addresses the provider still controls.
- Stale PTR records outlive a move to new infrastructure.

<a id="shared_nameserver_set"></a>
## Same DNS provider account

`shared_nameserver_set`: supporting operation signal, weight 0.25.

**Finds:** A domain registration the organization does not yet own that lists every name server of one of the organization's domain registrations.

**Why it counts:** Several DNS providers assign each customer account its own pair or set of name servers. A domain served by exactly the same set as the organization's domain was likely set up in the same provider account.

**Guards:**

- Only sets of at least two name servers count, and none may be the organization's own servers (that is the self-hosted DNS signal).
- A set shared by more than 50 registrations never counts.
- Never proposes on its own; it needs a strong signal.

**Can still mislead when:**

- Providers that give every customer the same name servers make unrelated domains share a set; the 50-registration limit catches large ones.

<a id="tls_fingerprint_match"></a>
## Same TLS server fingerprint

`tls_fingerprint_match`: supporting fingerprint signal, weight 0.10. Tiebreaker.

**Finds:** A name or address the organization does not yet own whose service has the same JARM TLS fingerprint as a service on a name the organization controls.

**Why it counts:** A JARM fingerprint summarizes how a TLS server answers ten crafted handshakes, which reflects its software and configuration. A matching fingerprint is consistent with the same team deploying both servers, but many unrelated servers share common configurations, so it is only a tiebreaker.

**Guards:**

- A fingerprint shared by more than 50 services never counts.
- A tiebreaker: it never counts as the second signal that lets a strong signal propose, so it can only rank candidates or send one to review.

**Can still mislead when:**

- Default configurations of popular servers, load balancers and CDNs produce the same fingerprint for unrelated sites.

<a id="name_token"></a>
## Organization name in the asset's name

`name_token`: supporting lexical signal, weight 0.10. Tiebreaker.

**Finds:** A candidate that other signals already link to the organization and whose name contains a distinctive word of the organization's name, such as colgate in colgate-events.com.

**Why it counts:** Organizations name their assets after themselves. The word must be distinctive, so generic words like university or group never count, and it is only ever added to a candidate other evidence already found.

**Guards:**

- Only words of at least five letters that are not in this signal's stop_words count.
- A tiebreaker: it never counts as the second signal that lets a strong signal propose, so it can only rank candidates or send one to review.
- Never finds candidates by itself.

**Can still mislead when:**

- Fans, critics, resellers, squatters and unrelated organizations with similar names use the same words.

<a id="parked_for_sale"></a>
## Parked or for sale

`parked_for_sale`: negative negative signal, weight 0.30.

**Finds:** A candidate name whose web page is a parking or domain-for-sale page.

**Why it counts:** A parked or for-sale page means a domainer or registrar, not the organization, controls the name today, whatever its other links. It counts against ownership.

**Guards:**

- A candidate with this signal is never proposed for an automatic write; at most it waits for review.

**Can still mislead when:**

- Organizations sometimes park defensive registrations with a registrar's default page.

**Page phrases:** `this domain is for sale`, `this domain may be for sale`, `buy this domain`, `domain is parked`, `parked free`, `parkingcrew`, `sedoparking`, `bodis.com`, `dan.com`, `afternic`, `hugedomains`, `undeveloped.com`

<a id="shared_analytics_id"></a>
## Same analytics or tag identifier

`shared_analytics_id`: supporting fingerprint signal, weight 0.30.

**Finds:** A name, address or URL the organization does not yet own whose pages carry an analytics or tag-manager identifier (Google Analytics, Google Tag Manager, Google Ads, AdSense, Meta pixel, Hotjar, Clarity) that a page of the organization also carries.

**Why it counts:** Analytics and tag-manager identifiers are issued to one account, and the account's owner adds them to the sites it runs, so two sites reporting to the same account are usually run by the same team. They are copied along with a page, though, so they only support other evidence.

**Guards:**

- Identifiers are recognized by provider-specific patterns (internal/fingerprint), not any string that looks like one.
- An identifier on more than 50 services or URLs never counts.
- Supporting only: without a strong signal it can at most send a candidate to review.

**Can still mislead when:**

- A cloned or phishing copy of the organization's site carries the same identifiers; this is why it is never strong evidence.
- Agencies sometimes run one tag-manager container across several clients.

<a id="same_favicon"></a>
## Same favicon

`same_favicon`: supporting fingerprint signal, weight 0.15.

**Finds:** A name, address or URL the organization does not yet own whose site has the same favicon (by its MurmurHash3, as Shodan computes it) as a site of the organization.

**Why it counts:** A custom favicon is a brand asset an organization reuses across its own sites, so the same icon suggests the same owner. Default icons of web servers, frameworks and hosting panels are shared by countless unrelated sites, which the 50-asset limit excludes.

**Guards:**

- A favicon on more than 50 services or URLs never counts (default and framework icons).
- Supporting only: without a strong signal it can at most send a candidate to review.

**Can still mislead when:**

- A cloned or phishing copy of the organization's site carries the same favicon; this is why it is never strong evidence.
- Resellers and partners display the organization's logo as their icon.

<a id="same_page_content"></a>
## Same page content

`same_page_content`: supporting fingerprint signal, weight 0.20.

**Finds:** A name, address or URL the organization does not yet own that serves exactly the same page (by the SHA-256 of its normalized body) as a site of the organization.

**Why it counts:** Serving byte-for-byte the same page usually means the same deployment behind several names, such as mirrors, aliases and old domains. Pages under 512 bytes are never hashed, because redirects, error stubs and default pages are identical everywhere.

**Guards:**

- Bodies shorter than 512 bytes are not hashed (internal/fingerprint).
- A hash on more than 50 services or URLs never counts.
- Supporting only: without a strong signal it can at most send a candidate to review.

**Can still mislead when:**

- A cloned or phishing copy of the organization's site carries the same page; this is why it is never strong evidence.
- Parking, maintenance and hosting-provider pages are identical across their customers.

<a id="same_page_title"></a>
## Same page title

`same_page_title`: supporting fingerprint signal, weight 0.10. Tiebreaker.

**Finds:** A name, address or URL the organization does not yet own whose page has the same title as a page of the organization.

**Why it counts:** A distinctive title, such as one naming the organization or a product of it, is often reused across its sites. Titles are short, chosen freely and copied, so a title only breaks ties between candidates other evidence found.

**Guards:**

- Titles shorter than 8 characters and generic titles (this signal's ignore_values) never count.
- A title on more than 50 services or URLs never counts.
- A tiebreaker: it never counts as the second signal that lets a strong signal propose.

**Can still mislead when:**

- A cloned or phishing copy of the organization's site carries the same title; this is why it is never strong evidence.
- Products and templates give unrelated sites the same title.

<a id="ssh_host_key_reuse"></a>
## SSH host key reuse

`ssh_host_key_reuse`: strong identity signal, weight 0.40.

**Finds:** An address or name the organization does not yet own whose SSH server presents a host key that an SSH server on an address the organization controls also presents.

**Why it counts:** An SSH host key is a private key generated on the server. The same key on two servers means they are the same machine reachable at two addresses, or were built from the same image by whoever holds the key, so the same party operates both.

**Guards:**

- Only addresses inside the organization's controlled footprint (its netblocks) are compared, never hosting it merely resolves to.
- A host key on more than 50 services never counts: vendor appliances and cloud images that ship with a baked-in key.
- Collected only in active enumeration, by completing the SSH key exchange; no user name or credential is ever sent.

**Can still mislead when:**

- Vendor appliances and published VM images that share one default key across customers (the 50-service limit catches widely deployed ones).
