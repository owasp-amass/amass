# Reputation feeds

The `Reputation-Feeds` plugin (`engine/plugins/reputation`) matches the IP
addresses and netblocks an enumeration reaches against keyless reputation
feeds; the catalog is `internal/semantics/reputation_feeds.json`.

**Feeds:** Spamhaus DROP (IPv4 and IPv6, `ndjson_cidr`), the Tor exit list
and FireHOL level 1 (`lines`). Each is downloaded at most once per its
`refresh_hours` with `support.CachedDownload` into
`$TMPDIR/amass-reputation`, read into a range trie (`cidranger`) when its
file changes, and shared by every session of the engine. Reserved and private
ranges a feed lists are skipped (`listedRange`, `net.IsReservedAddress`), so
FireHOL's bogons never flag in-house space.

**Matching:** an IPAddress is listed when a listed range holds it; a Netblock
when a listed range holds it or lies inside it. A listed asset gets the
`reputation_listing` property (`semantics.ReputationListingProperty`), the
feed's name. A listing describes the address, not who runs it: no lens uses
it as ownership evidence.

**Exposure lens:** `reputationListed` reads the listings with one value search
per feed and asset type and reports the footprint's listed addresses and
netblocks in the class `reputation_listed`, with the feed's title. The report
lens shows it with the other exposure classes.
