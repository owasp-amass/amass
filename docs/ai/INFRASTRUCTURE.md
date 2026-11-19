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

- Counts only for a netblock announced by an AS that is itself registered to the organization (asn-registrant-org).
- A privacy or proxy registrant organization on the AS is never an anchor.

**Can still mislead when:**

- A transit AS announces its customers' prefixes without owning them.
- Route leaks and hijacks announce prefixes the AS has no claim to.
