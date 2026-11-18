# Horizontal domain correlation

<!-- Generated from internal/semantics/horizontal_signals.json by `amass review horizontal-signals -format markdown`. Edit that file, not this one. -->

Horizontal correlation associates more registered (apex) domains with a target organization, so an enumeration's scope can be made more complete. Each kind of evidence is a signal, listed here with why it counts, what stops it from misfiring, and when it can still mislead. The same text is shown by `amass review horizontal-signals`.

## How signals decide

- The `related-domains` lens surfaces a candidate apex domain for every signal that supports it, recording the strongest signal's confidence (its weight times 100) and the evidence; it never changes scope itself.
- During enumeration the scope-expansion decision scores a candidate over its strong signals, with provider- and proxy-owned shared values excluded and a name match never sufficient on its own, and is reevaluated as new evidence arrives. The classifier reads the same catalog.
- A **strong** signal is direct ownership evidence (a shared registrant or certificate-subject organization, an official website); a **supporting** signal (a shared name server) corroborates but can be shared infrastructure.

| Signal | Strength | Kind | Weight |
| --- | --- | --- | --- |
| [Shared registrant organization](#shared-registrant-org) | strong | identity | 0.70 |
| [Shared certificate subject organization](#cert-subject-org) | strong | identity | 0.75 |
| [Shared name server](#shared-name-server) | supporting | infrastructure | 0.65 |
| [Official website](#official-website) | strong | identity | 0.80 |

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

- A certificate covering more distinct apex domains than the lens cap is treated as shared or CDN infrastructure (many tenants on one certificate), not shared ownership, and is skipped.
- A privacy-proxy or placeholder subject organization is excluded.

**Can still mislead when:**

- A hosting or SaaS provider can name itself as the subject organization on certificates it issues for customer domains.
- A domain-validated certificate carries no verified organization and does not produce this signal.

<a id="shared-name-server"></a>
## Shared name server

`shared-name-server`: supporting infrastructure signal, weight 0.65 (confidence 65).

**Finds:** Another registered domain served by the same authoritative name server as one of the organization's own domains.

**Why it counts:** A private or vanity name server operated by one organization serves only that organization's domains, so sharing it is evidence of common control. It is supporting rather than strong because a small hosting provider's shared name server can serve unrelated customers.

**Guards:**

- A name server serving more distinct apex domains than the lens cap is treated as shared or provider infrastructure and is skipped.
- Only name servers reached from the organization's own domain records are used as anchors.

**Can still mislead when:**

- Managed DNS and small hosting providers run name servers shared by many unrelated customers.
- A registrar's default name servers are shared across its whole customer base.

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
