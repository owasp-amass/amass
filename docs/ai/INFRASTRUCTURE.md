# Infrastructure correlation

<!-- Generated from internal/semantics/infrastructure_signals.json by `amass review infrastructure-signals -format markdown`. Edit that file, not this one. -->

Infrastructure correlation associates more netblocks and autonomous systems with a target organization, so an enumeration's scope can be made more complete. Each kind of evidence is a signal, listed here with why it counts, what stops it from misfiring, and when it can still mislead. The same text is shown by `amass review infrastructure-signals`.

## How signals decide

- The scope-expansion decision scores a candidate over these signals, with privacy-proxy registrant organizations excluded and a name match never sufficient on its own; a strong signal (an RIR registration naming the organization) may widen scope, while a supporting signal alone (a prefix merely announced by the organization's AS) needs review.

| Signal | Strength | Kind | Weight |
| --- | --- | --- | --- |
| [Shared netblock registrant organization](#ipnet-registrant-org) | strong | identity | 0.75 |
| [Shared AS registrant organization](#asn-registrant-org) | strong | identity | 0.75 |
| [Netblock announced by the organization's AS](#asn-announced-netblock) | supporting | infrastructure | 0.60 |
| [RPKI ROA authorizes the organization's AS](#roa-authorizes-own-asn) | strong | infrastructure | 0.75 |
| [Routing registry maintainer of the organization's netblocks](#irr-maintainer-own-origins) | strong | infrastructure | 0.70 |
| [Shared routing registry maintainer](#shared-irr-maintainer) | supporting | infrastructure | 0.50 |
| [Mail sender declared in the organization's SPF record](#spf-declared-range) | supporting | infrastructure | 0.50 |
| [Netblock announced by the organization's small AS](#small-asn-announced-netblock) | strong | infrastructure | 0.70 |

<a id="ipnet-registrant-org"></a>
## Shared netblock registrant organization

`ipnet-registrant-org`: strong identity signal, weight 0.75 (confidence 75).

**Finds:** A netblock whose RIR/WHOIS registration (IPNetRecord) names the same organization as its registrant as the target's.

**Why it counts:** A Regional Internet Registry assigns an IP allocation to a specific organization and records it as the registrant of the inetnum/NetRange. When a netblock's registration names the target organization, the registry attributes that address space to it, which is direct evidence it belongs to the organization's footprint.

**Guards:**

- A privacy or proxy registrant organization is never an anchor: it is shared by many unrelated allocations.
- A matching organization name alone, with no shared registration record, is never sufficient.

**Can still mislead when:**

- A hosting or transit provider is the RIR registrant for address space it sub-allocates to many customers.
- Legacy allocations can name a predecessor organization after an acquisition.

<a id="asn-registrant-org"></a>
## Shared AS registrant organization

`asn-registrant-org`: strong identity signal, weight 0.75 (confidence 75).

**Finds:** An autonomous system whose RIR/WHOIS registration (AutnumRecord) names the same organization as its registrant as the target's.

**Why it counts:** An autonomous system number is registered to one operator, recorded as the registrant of the aut-num. When an AS registration names the target organization, the registry attributes that AS to it, direct evidence the AS is part of its network.

**Guards:**

- A privacy or proxy registrant organization is never an anchor.
- A matching organization name alone is never sufficient.

**Can still mislead when:**

- A parent or network operator can hold the AS registration for legally separate subsidiaries.
- Upstream providers sometimes register AS numbers on behalf of customers.

<a id="asn-announced-netblock"></a>
## Netblock announced by the organization's AS

`asn-announced-netblock`: supporting infrastructure signal, weight 0.60 (confidence 60).

**Finds:** A netblock announced (originated) by an autonomous system whose RIR registration names the target organization.

**Why it counts:** A prefix originated by the organization's own AS is routed by its network, corroborating that the address space is operated by it. It is supporting rather than strong because an AS routinely announces space it does not own — transit and customer routes among them — so announcement is operation, not registration. Combined with an RIR registration naming the organization (ipnet-registrant-org) it raises a netblock's confidence; announcement alone needs review.

**Guards:**

- Counts only when the AS announces more than 32 prefixes; a smaller AS gives the strong small-asn-announced-netblock signal instead.
- Counts only for a netblock announced by an AS that is itself registered to the organization (asn-registrant-org).
- A privacy or proxy registrant organization on the AS is never an anchor.

**Can still mislead when:**

- A transit AS announces its customers' prefixes without owning them.
- Route leaks and hijacks announce prefixes the AS has no claim to.

<a id="roa-authorizes-own-asn"></a>
## RPKI ROA authorizes the organization's AS

`roa-authorizes-own-asn`: strong infrastructure signal, weight 0.75 (confidence 75).

**Finds:** A netblock that a valid RPKI Route Origin Authorization (ROA) authorizes an autonomous system registered to the target organization to announce.

**Why it counts:** Only the holder of address space can sign a ROA for it, through its Regional Internet Registry's RPKI. A ROA naming the organization's own AS is the holder's signed statement that the organization's network may route the prefix, so the netblock is operated for the organization. Unlike an announcement, which any AS can make, a ROA cannot be created by a third party.

**Guards:**

- Counts only for a ROA naming an AS that is itself registered to the organization (asn-registrant-org).
- Only valid ROAs whose prefix and maximum length cover the netblock count.

**Can still mislead when:**

- A provider can sign a ROA for its own space naming a customer's AS (provider-assigned space): the customer operates the netblock without holding it.
- A ROA can outlive the arrangement it was made for until the holder revokes it.

<a id="irr-maintainer-own-origins"></a>
## Routing registry maintainer of the organization's netblocks

`irr-maintainer-own-origins`: strong infrastructure signal, weight 0.70 (confidence 70).

**Finds:** A netblock whose routing registry (IRR) route object is kept by the same maintainer as one of the organization's own netblocks, when every route object that maintainer keeps is originated by an autonomous system registered to the organization.

**Why it counts:** A maintainer is an account in a routing registry, and an operator files all its route objects under its own. When a maintainer keeps routes only for the organization's ASes, it is the organization's account, and every netblock it keeps is the organization's network.

**Guards:**

- Every origin AS among the maintainer's route objects must be registered to the organization.
- A maintainer keeping more than 100 route objects, or routes from more than 5 origin ASes, gives no signal.
- The registries' own maintainers (allocation, legacy and RPKI-generated objects) are never used.

**Can still mislead when:**

- A consultant or managed network provider can keep route objects for a single client under its own maintainer.
- Route objects are not removed when address space changes hands, so a maintainer's old routes can outlive the arrangement.

<a id="shared-irr-maintainer"></a>
## Shared routing registry maintainer

`shared-irr-maintainer`: supporting infrastructure signal, weight 0.50 (confidence 50).

**Finds:** A netblock whose routing registry (IRR) route object is kept by the same maintainer as one of the organization's own netblocks, when that maintainer also keeps routes originated by other autonomous systems.

**Why it counts:** Operators reuse one maintainer across their route objects, so a shared maintainer points to a common operator. It is supporting rather than strong when the maintainer's routes come from other ASes too: upstream providers and hosting companies keep route objects for their customers, so the maintainer shows who files the paperwork, not who runs the network.

**Guards:**

- A maintainer keeping more than 100 route objects, or routes from more than 5 origin ASes, gives no signal.
- The registries' own maintainers are never used.
- Never expands scope on its own.

**Can still mislead when:**

- An upstream ISP or hosting provider keeps route objects for many customers under one maintainer.

<a id="spf-declared-range"></a>
## Mail sender declared in the organization's SPF record

`spf-declared-range`: supporting infrastructure signal, weight 0.50 (confidence 50).

**Finds:** A netblock that the SPF record of a domain registered to the target organization authorizes to send its mail (an ip4: or ip6: mechanism), or the stored netblock holding an address it authorizes.

**Why it counts:** An organization lists its own mail servers' addresses in its SPF record, so a declared range is often its own network. It is supporting rather than strong because SPF also lists the addresses of outside senders: marketing, ticketing and newsletter services the organization mails through.

**Guards:**

- Ranges broader than a /16 (IPv4) or a /32 (IPv6), private ranges, and ranges a minus qualifier excludes are not stored.
- A netblock a cloud provider publishes as its own is skipped.
- Never expands scope on its own.

**Can still mislead when:**

- A bulk-mail or ticketing vendor's sending range is listed exactly like the organization's own.

<a id="small-asn-announced-netblock"></a>
## Netblock announced by the organization's small AS

`small-asn-announced-netblock`: strong infrastructure signal, weight 0.70 (confidence 70).

**Finds:** A netblock announced by an autonomous system registered to the target organization that announces at most 32 prefixes.

**Why it counts:** An enterprise, campus or government network announces a handful of its own prefixes; carrying other networks' routes is what transit and hosting networks do, and they announce many. A prefix originated by the organization's own small AS is routed for the organization.

**Guards:**

- Counts only for an AS registered to the organization (asn-registrant-org).
- The AS must announce at most 32 prefixes; one announcing more gives the supporting asn-announced-netblock signal instead.

**Can still mislead when:**

- A small AS can announce a customer's or affiliate's prefix, such as a university announcing a hospital's space.
- Route leaks and hijacks announce prefixes the AS has no claim to.
