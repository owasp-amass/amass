# Ownership signals

<!-- Generated from internal/ai/semantics/ownership_signals.json by `amass ai signals -format markdown`. Edit that file, not this one. -->

Amass proposes that an organization owns an asset it has not been attributed to only from stored evidence. Each kind of evidence is a signal, listed here with why it counts, what stops it from misfiring, and when it can still mislead. The same text is shown by `amass ai signals`.

## How signals decide

- A candidate with two strong signals, or one strong signal and a different second signal, is **proposed** when exactly one OAM relationship can record the owner. During enumeration a proposed candidate is written automatically (with the `amass-ai` source) unless attribution is set to `journal` or `off`.
- One strong signal, or two signals of any strength, **needs review**: it waits in the review journal for a person.
- Anything less is **weak** and only reported.
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
