// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

type Tier uint8

const (
	Tier1 Tier = 1 // Always-on, highest ROI: core infra, AD/M365, email, web, common collaboration
	Tier2 Tier = 2 // Common enterprise/devops/cloud-native and security controls
	Tier3 Tier = 3 // Niche/vertical/gaming/IoT/vendor-specific; opt-in due to lower base-rate
)

type Confidence uint8

const (
	ConfHigh   Confidence = 90 // widely deployed / standardized and frequently observed
	ConfMedium Confidence = 70 // common but less universal, or more vendor-/vertical-specific
	ConfLow    Confidence = 50 // niche or historically relevant; keep for completeness
)

// SRVName is the left-hand label pair for SRV lookups: _service._proto
// Example query: _ldap._tcp.example.com IN SRV ?
type SRVName struct {
	Name       string     // "_service._tcp|_udp|_tls" etc.
	Tier       Tier       // Tier1/2/3
	Category   string     // coarse grouping (identity, mail, rtc, devops, etc.)
	Vendor     string     // "IETF/IANA", "Microsoft", "Apple", etc. (best-effort)
	Confidence Confidence // see constants above
	Notes      string     // short rationale / special handling notes
}

// SRVNames is the tiered corpus.
// Intentionally includes a blend of:
//   - IETF/IANA-standardized services
//   - widely-used vendor SRVs (notably Microsoft)
//   - modern operational signals (DevOps, service discovery, databases)
//
// You can filter by Tier and/or Confidence at runtime.
var SRVNames = []SRVName{
	// ----------------------------------------------------------------------------
	// Tier 1: Identity / Directory / Core
	// -------------------------
	{Name: "_ldap._tcp", Tier: Tier1, Category: "identity", Vendor: "IETF/IANA", Confidence: ConfHigh, Notes: "LDAP"},
	{Name: "_ldap._udp", Tier: Tier1, Category: "identity", Vendor: "IETF/IANA", Confidence: ConfMedium, Notes: "LDAP (UDP less common)"},
	{Name: "_ldaps._tcp", Tier: Tier1, Category: "identity", Vendor: "IETF/IANA", Confidence: ConfHigh, Notes: "LDAP over TLS"},
	{Name: "_kerberos._tcp", Tier: Tier1, Category: "identity", Vendor: "IETF/IANA", Confidence: ConfHigh, Notes: "Kerberos"},
	{Name: "_kerberos._udp", Tier: Tier1, Category: "identity", Vendor: "IETF/IANA", Confidence: ConfHigh, Notes: "Kerberos"},
	{Name: "_kerberos-master._tcp", Tier: Tier1, Category: "identity", Vendor: "IETF/IANA", Confidence: ConfMedium, Notes: "Kerberos master"},
	{Name: "_kerberos-master._udp", Tier: Tier1, Category: "identity", Vendor: "IETF/IANA", Confidence: ConfMedium, Notes: "Kerberos master"},
	{Name: "_kerberos-adm._tcp", Tier: Tier1, Category: "identity", Vendor: "IETF/IANA", Confidence: ConfMedium, Notes: "Kerberos admin"},
	{Name: "_kerberos-adm._udp", Tier: Tier1, Category: "identity", Vendor: "IETF/IANA", Confidence: ConfMedium, Notes: "Kerberos admin"},
	{Name: "_kpasswd._tcp", Tier: Tier1, Category: "identity", Vendor: "IETF/IANA", Confidence: ConfHigh, Notes: "Kerberos password change"},
	{Name: "_kpasswd._udp", Tier: Tier1, Category: "identity", Vendor: "IETF/IANA", Confidence: ConfHigh, Notes: "Kerberos password change"},
	{Name: "_gc._tcp", Tier: Tier1, Category: "identity", Vendor: "Microsoft", Confidence: ConfHigh, Notes: "AD Global Catalog"},
	{Name: "_msft-gc-ssl._tcp", Tier: Tier1, Category: "identity", Vendor: "Microsoft", Confidence: ConfHigh, Notes: "AD GC over SSL/TLS"},

	// -------------------------
	// Tier 1: Microsoft / M365 / Endpoint discovery
	// -------------------------
	{Name: "_autodiscover._tcp", Tier: Tier1, Category: "mail", Vendor: "Microsoft", Confidence: ConfHigh, Notes: "Exchange/Outlook autodiscover"},
	{Name: "_enterpriseregistration._tcp", Tier: Tier1, Category: "device_mgmt", Vendor: "Microsoft", Confidence: ConfHigh, Notes: "Azure AD device registration"},
	{Name: "_deviceenrollment._tcp", Tier: Tier1, Category: "device_mgmt", Vendor: "Microsoft", Confidence: ConfHigh, Notes: "MDM enrollment"},
	{Name: "_sip._tls", Tier: Tier1, Category: "rtc", Vendor: "Microsoft", Confidence: ConfHigh, Notes: "SIP over TLS (often used for OCS/Lync/Skype/Teams legacy interop)"},
	{Name: "_sipfederationtls._tcp", Tier: Tier1, Category: "rtc", Vendor: "Microsoft", Confidence: ConfMedium, Notes: "SIP federation over TLS"},
	{Name: "_sipinternaltls._tcp", Tier: Tier1, Category: "rtc", Vendor: "Microsoft", Confidence: ConfMedium, Notes: "Internal SIP TLS"},
	{Name: "_sipexternaltls._tcp", Tier: Tier1, Category: "rtc", Vendor: "Microsoft", Confidence: ConfMedium, Notes: "External SIP TLS"},
	{Name: "_lyncdiscover._tcp", Tier: Tier1, Category: "rtc", Vendor: "Microsoft", Confidence: ConfMedium, Notes: "Lync/Skype discovery"},
	{Name: "_sipinternal._tcp", Tier: Tier2, Category: "rtc", Vendor: "Microsoft", Confidence: ConfLow, Notes: "Legacy/less common without TLS"},
	{Name: "_sipexternal._tcp", Tier: Tier2, Category: "rtc", Vendor: "Microsoft", Confidence: ConfLow, Notes: "Legacy/less common without TLS"},

	// -------------------------
	// Tier 1: Mail submission / retrieval / modern mail APIs
	// -------------------------
	{Name: "_smtp._tcp", Tier: Tier1, Category: "mail", Vendor: "IETF/IANA", Confidence: ConfHigh, Notes: "SMTP"},
	{Name: "_smtp._tls", Tier: Tier1, Category: "mail", Vendor: "IETF/IANA", Confidence: ConfMedium, Notes: "SMTP with explicit TLS service label"},
	{Name: "_submission._tcp", Tier: Tier1, Category: "mail", Vendor: "IETF/IANA", Confidence: ConfHigh, Notes: "Message submission"},
	{Name: "_submissions._tcp", Tier: Tier1, Category: "mail", Vendor: "IETF/IANA", Confidence: ConfHigh, Notes: "Message submission over TLS"},
	{Name: "_imap._tcp", Tier: Tier1, Category: "mail", Vendor: "IETF/IANA", Confidence: ConfHigh, Notes: "IMAP"},
	{Name: "_imaps._tcp", Tier: Tier1, Category: "mail", Vendor: "IETF/IANA", Confidence: ConfHigh, Notes: "IMAP over TLS"},
	{Name: "_pop3._tcp", Tier: Tier2, Category: "mail", Vendor: "IETF/IANA", Confidence: ConfMedium, Notes: "POP3 (declining but present)"},
	{Name: "_pop3s._tcp", Tier: Tier2, Category: "mail", Vendor: "IETF/IANA", Confidence: ConfMedium, Notes: "POP3 over TLS"},
	{Name: "_jmap._tcp", Tier: Tier2, Category: "mail", Vendor: "IETF/IANA", Confidence: ConfMedium, Notes: "JMAP mail access API"},
	{Name: "_mta-sts._tcp", Tier: Tier2, Category: "mail", Vendor: "IETF", Confidence: ConfMedium, Notes: "MTA-STS policy endpoint (not SRV-standard everywhere, but seen)"},

	// -------------------------
	// Tier 1: Web and general service endpoints
	// -------------------------
	{Name: "_http._tcp", Tier: Tier1, Category: "web", Vendor: "IETF/IANA", Confidence: ConfHigh, Notes: "HTTP"},
	{Name: "_https._tcp", Tier: Tier1, Category: "web", Vendor: "IETF/IANA", Confidence: ConfHigh, Notes: "HTTPS"},
	{Name: "_http-alt._tcp", Tier: Tier2, Category: "web", Vendor: "IETF/IANA", Confidence: ConfMedium, Notes: "Alternate HTTP (legacy/varies)"},
	{Name: "_http3._udp", Tier: Tier2, Category: "web", Vendor: "IETF", Confidence: ConfMedium, Notes: "HTTP/3 (QUIC)"},
	{Name: "_xmlrpc-beep._tcp", Tier: Tier3, Category: "web", Vendor: "IETF/IANA", Confidence: ConfLow, Notes: "Legacy XML-RPC over BEEP"},

	// -------------------------
	// Tier 1: Collaboration / Messaging
	// -------------------------
	{Name: "_xmpp-client._tcp", Tier: Tier1, Category: "messaging", Vendor: "IETF/IANA", Confidence: ConfHigh, Notes: "XMPP client"},
	{Name: "_xmpp-server._tcp", Tier: Tier1, Category: "messaging", Vendor: "IETF/IANA", Confidence: ConfHigh, Notes: "XMPP server"},
	{Name: "_xmpp-bosh._tcp", Tier: Tier2, Category: "messaging", Vendor: "IETF/IANA", Confidence: ConfMedium, Notes: "XMPP BOSH"},
	{Name: "_matrix._tcp", Tier: Tier2, Category: "messaging", Vendor: "Matrix", Confidence: ConfMedium, Notes: "Matrix federation/client (deployment-specific)"},
	{Name: "_matrix-vnet._tcp", Tier: Tier3, Category: "messaging", Vendor: "Matrix", Confidence: ConfLow, Notes: "Matrix virtual network; niche"},

	// -------------------------
	// Tier 1: RTC / NAT traversal (SIP/STUN/TURN already in your list; include modern WebRTC hint)
	// -------------------------
	{Name: "_sip._tcp", Tier: Tier1, Category: "rtc", Vendor: "IETF/IANA", Confidence: ConfHigh, Notes: "SIP"},
	{Name: "_sip._udp", Tier: Tier1, Category: "rtc", Vendor: "IETF/IANA", Confidence: ConfHigh, Notes: "SIP"},
	{Name: "_sips._tcp", Tier: Tier1, Category: "rtc", Vendor: "IETF/IANA", Confidence: ConfHigh, Notes: "SIPS"},
	{Name: "_stun._tcp", Tier: Tier2, Category: "rtc", Vendor: "IETF/IANA", Confidence: ConfMedium, Notes: "STUN"},
	{Name: "_stun._udp", Tier: Tier2, Category: "rtc", Vendor: "IETF/IANA", Confidence: ConfHigh, Notes: "STUN (common)"},
	{Name: "_stuns._tcp", Tier: Tier2, Category: "rtc", Vendor: "IETF/IANA", Confidence: ConfMedium, Notes: "STUN over TLS"},
	{Name: "_turn._tcp", Tier: Tier2, Category: "rtc", Vendor: "IETF/IANA", Confidence: ConfMedium, Notes: "TURN"},
	{Name: "_turn._udp", Tier: Tier2, Category: "rtc", Vendor: "IETF/IANA", Confidence: ConfHigh, Notes: "TURN (common)"},
	{Name: "_turns._tcp", Tier: Tier2, Category: "rtc", Vendor: "IETF/IANA", Confidence: ConfMedium, Notes: "TURN over TLS"},
	{Name: "_turns._udp", Tier: Tier2, Category: "rtc", Vendor: "IETF/IANA", Confidence: ConfMedium, Notes: "TURN over DTLS/TLS variants"},
	{Name: "_webrtc._udp", Tier: Tier3, Category: "rtc", Vendor: "De facto", Confidence: ConfLow, Notes: "Non-standard but seen in some deployments"},

	// -------------------------
	// Tier 2: Security / PKI / AAA
	// -------------------------
	{Name: "_ocsp._tcp", Tier: Tier2, Category: "pki", Vendor: "IETF/IANA", Confidence: ConfMedium, Notes: "OCSP responder"},
	{Name: "_crls._tcp", Tier: Tier2, Category: "pki", Vendor: "IETF/IANA", Confidence: ConfMedium, Notes: "CRL distribution"},
	{Name: "_certificates._tcp", Tier: Tier2, Category: "pki", Vendor: "IETF/IANA", Confidence: ConfLow, Notes: "Certificate distribution (varies)"},
	{Name: "_radsec._tcp", Tier: Tier2, Category: "aaa", Vendor: "IETF", Confidence: ConfMedium, Notes: "RADIUS over TLS (RadSec)"},
	{Name: "_radiustls._tcp", Tier: Tier2, Category: "aaa", Vendor: "IETF", Confidence: ConfMedium, Notes: "RADIUS/TLS"},
	{Name: "_radiusdtls._udp", Tier: Tier2, Category: "aaa", Vendor: "IETF", Confidence: ConfMedium, Notes: "RADIUS/DTLS"},

	// -------------------------
	// Tier 2: File / Storage
	// -------------------------
	{Name: "_nfs._tcp", Tier: Tier2, Category: "storage", Vendor: "IETF/IANA", Confidence: ConfMedium, Notes: "NFS"},
	{Name: "_nfs._udp", Tier: Tier2, Category: "storage", Vendor: "IETF/IANA", Confidence: ConfLow, Notes: "NFS over UDP (legacy)"},
	{Name: "_nfs-domainroot._tcp", Tier: Tier2, Category: "storage", Vendor: "IETF/IANA", Confidence: ConfLow, Notes: "NFS domain root"},
	{Name: "_smb._tcp", Tier: Tier2, Category: "storage", Vendor: "Microsoft", Confidence: ConfMedium, Notes: "SMB/CIFS (SRV usage varies)"},
	{Name: "_afp._tcp", Tier: Tier3, Category: "storage", Vendor: "Apple", Confidence: ConfLow, Notes: "AFP (legacy)"},
	{Name: "_ceph._tcp", Tier: Tier2, Category: "storage", Vendor: "Ceph", Confidence: ConfMedium, Notes: "Ceph services"},
	{Name: "_ceph-mon._tcp", Tier: Tier2, Category: "storage", Vendor: "Ceph", Confidence: ConfMedium, Notes: "Ceph monitors"},
	{Name: "_gluster._tcp", Tier: Tier3, Category: "storage", Vendor: "Gluster", Confidence: ConfLow, Notes: "GlusterFS (niche)"},
	{Name: "_ftp._tcp", Tier: Tier3, Category: "storage", Vendor: "IETF/IANA", Confidence: ConfLow, Notes: "FTP (legacy)"},
	{Name: "_sftp._tcp", Tier: Tier2, Category: "storage", Vendor: "De facto", Confidence: ConfMedium, Notes: "SFTP (not formally standardized as SRV everywhere)"},
	{Name: "_ssh._tcp", Tier: Tier2, Category: "remote_access", Vendor: "IETF/IANA", Confidence: ConfMedium, Notes: "SSH (SRV usage varies but useful)"},
	{Name: "_telnet._tcp", Tier: Tier3, Category: "remote_access", Vendor: "IETF/IANA", Confidence: ConfLow, Notes: "Telnet (legacy)"},

	// -------------------------
	// Tier 2: DevOps / Cloud-native service discovery
	// -------------------------
	{Name: "_kubernetes._tcp", Tier: Tier2, Category: "devops", Vendor: "Kubernetes", Confidence: ConfMedium, Notes: "Kubernetes API (SRV varies by distro)"},
	{Name: "_etcd-client._tcp", Tier: Tier2, Category: "devops", Vendor: "CoreOS/etcd", Confidence: ConfMedium, Notes: "etcd client endpoint"},
	{Name: "_etcd-server._tcp", Tier: Tier2, Category: "devops", Vendor: "CoreOS/etcd", Confidence: ConfMedium, Notes: "etcd peer/server endpoint"},
	{Name: "_consul._tcp", Tier: Tier2, Category: "devops", Vendor: "HashiCorp", Confidence: ConfMedium, Notes: "Consul service discovery"},
	{Name: "_vault._tcp", Tier: Tier2, Category: "devops", Vendor: "HashiCorp", Confidence: ConfMedium, Notes: "Vault"},
	{Name: "_nomad._tcp", Tier: Tier3, Category: "devops", Vendor: "HashiCorp", Confidence: ConfLow, Notes: "Nomad (less common SRV usage)"},
	{Name: "_git._tcp", Tier: Tier3, Category: "devops", Vendor: "De facto", Confidence: ConfLow, Notes: "Git over TCP (rare SRV usage)"},
	{Name: "_git-ssh._tcp", Tier: Tier2, Category: "devops", Vendor: "De facto", Confidence: ConfMedium, Notes: "Git over SSH (occasionally via SRV)"},

	// -------------------------
	// Tier 2: Configuration management / orchestration
	// -------------------------
	{Name: "_puppet._tcp", Tier: Tier2, Category: "automation", Vendor: "Puppet", Confidence: ConfMedium, Notes: "Puppet master"},
	{Name: "_x-puppet._tcp", Tier: Tier2, Category: "automation", Vendor: "Puppet", Confidence: ConfLow, Notes: "Legacy/alternate puppet label"},
	{Name: "_salt-master._tcp", Tier: Tier3, Category: "automation", Vendor: "Salt", Confidence: ConfLow, Notes: "Salt master (SRV uncommon)"},
	{Name: "_ansible._tcp", Tier: Tier3, Category: "automation", Vendor: "Ansible", Confidence: ConfLow, Notes: "Ansible (SRV uncommon)"},
	{Name: "_docker._tcp", Tier: Tier3, Category: "automation", Vendor: "Docker", Confidence: ConfLow, Notes: "Docker API (SRV uncommon)"},
	{Name: "_docker-registry._tcp", Tier: Tier3, Category: "automation", Vendor: "Docker", Confidence: ConfLow, Notes: "Registry (SRV uncommon)"},

	// -------------------------
	// Tier 2: Databases commonly advertised via SRV-like patterns
	// -------------------------
	{Name: "_mongodb._tcp", Tier: Tier2, Category: "database", Vendor: "MongoDB", Confidence: ConfMedium, Notes: "MongoDB SRV"},
	{Name: "_mongodb+srv._tcp", Tier: Tier2, Category: "database", Vendor: "MongoDB", Confidence: ConfHigh, Notes: "MongoDB+SRV URI discovery pattern"},
	{Name: "_postgresql._tcp", Tier: Tier3, Category: "database", Vendor: "IETF/IANA", Confidence: ConfLow, Notes: "PostgreSQL (SRV uncommon but exists)"},
	{Name: "_mysql._tcp", Tier: Tier3, Category: "database", Vendor: "IETF/IANA", Confidence: ConfLow, Notes: "MySQL (SRV uncommon)"},
	{Name: "_redis._tcp", Tier: Tier3, Category: "database", Vendor: "Redis", Confidence: ConfLow, Notes: "Redis (SRV uncommon)"},
	{Name: "_cassandra._tcp", Tier: Tier3, Category: "database", Vendor: "Apache", Confidence: ConfLow, Notes: "Cassandra (SRV uncommon)"},
	{Name: "_elasticsearch._tcp", Tier: Tier3, Category: "database", Vendor: "Elastic", Confidence: ConfLow, Notes: "Elasticsearch (SRV uncommon)"},

	// -------------------------
	// Tier 2: Printing / device services
	// -------------------------
	{Name: "_ipp._tcp", Tier: Tier2, Category: "printing", Vendor: "IETF/IANA", Confidence: ConfMedium, Notes: "IPP"},
	{Name: "_ipps._tcp", Tier: Tier2, Category: "printing", Vendor: "IETF/IANA", Confidence: ConfLow, Notes: "IPP over TLS"},
	{Name: "_printer._tcp", Tier: Tier3, Category: "printing", Vendor: "De facto", Confidence: ConfLow, Notes: "Generic printer"},
	{Name: "_scanner._tcp", Tier: Tier3, Category: "printing", Vendor: "De facto", Confidence: ConfLow, Notes: "Scanner services (niche)"},

	// -------------------------
	// Tier 3: Gaming / community platforms (opt-in)
	// -------------------------
	{Name: "_minecraft._tcp", Tier: Tier3, Category: "gaming", Vendor: "Mojang/Microsoft", Confidence: ConfMedium, Notes: "Common gaming SRV"},
	{Name: "_ts3._udp", Tier: Tier3, Category: "gaming", Vendor: "TeamSpeak", Confidence: ConfLow, Notes: "TeamSpeak"},
	{Name: "_steam._tcp", Tier: Tier3, Category: "gaming", Vendor: "Valve", Confidence: ConfLow, Notes: "Steam-related (varies)"},
	{Name: "_xboxlive._tcp", Tier: Tier3, Category: "gaming", Vendor: "Microsoft", Confidence: ConfLow, Notes: "Varies by service"},
	{Name: "_psn._tcp", Tier: Tier3, Category: "gaming", Vendor: "Sony", Confidence: ConfLow, Notes: "Varies by service"},

	// -------------------------
	// Tier 2: DNS ecosystem
	// -------------------------
	{Name: "_dns._udp", Tier: Tier2, Category: "dns", Vendor: "IETF/IANA", Confidence: ConfHigh, Notes: "DNS"},
	{Name: "_dns-update._udp", Tier: Tier2, Category: "dns", Vendor: "IETF/IANA", Confidence: ConfMedium, Notes: "Dynamic DNS update"},
	{Name: "_dns-update._tcp", Tier: Tier2, Category: "dns", Vendor: "IETF/IANA", Confidence: ConfMedium, Notes: "Dynamic DNS update"},
	{Name: "_dns-update-tls._tcp", Tier: Tier2, Category: "dns", Vendor: "IETF", Confidence: ConfMedium, Notes: "DDNS over TLS"},
	{Name: "_dns-llq._tcp", Tier: Tier3, Category: "dns", Vendor: "Apple/De facto", Confidence: ConfLow, Notes: "LLQ"},
	{Name: "_dns-llq._udp", Tier: Tier3, Category: "dns", Vendor: "Apple/De facto", Confidence: ConfLow, Notes: "LLQ"},
	{Name: "_dns-llq-tls._tcp", Tier: Tier3, Category: "dns", Vendor: "Apple/De facto", Confidence: ConfLow, Notes: "LLQ over TLS"},
	{Name: "_dns-push-tls._tcp", Tier: Tier3, Category: "dns", Vendor: "IETF", Confidence: ConfLow, Notes: "DNS Push (rare)"},
	{Name: "_dns-sd._udp", Tier: Tier3, Category: "dns", Vendor: "IETF/IANA", Confidence: ConfLow, Notes: "DNS-SD"},

	// -------------------------
	// Tier 2/3: Calendar / contacts (useful for enterprise footprinting)
	// -------------------------
	{Name: "_caldav._tcp", Tier: Tier2, Category: "groupware", Vendor: "IETF/Apple", Confidence: ConfMedium, Notes: "CalDAV"},
	{Name: "_caldavs._tcp", Tier: Tier2, Category: "groupware", Vendor: "IETF/Apple", Confidence: ConfMedium, Notes: "CalDAV over TLS"},
	{Name: "_carddav._tcp", Tier: Tier2, Category: "groupware", Vendor: "IETF/Apple", Confidence: ConfMedium, Notes: "CardDAV"},
	{Name: "_carddavs._tcp", Tier: Tier2, Category: "groupware", Vendor: "IETF/Apple", Confidence: ConfMedium, Notes: "CardDAV over TLS"},
}

// Convenience: legacy compatibility with existing Amass patterns (string slice only).
func NamesByTier(maxTier Tier) []string {
	out := make([]string, 0, len(SRVNames))
	for _, s := range SRVNames {
		if s.Tier <= maxTier {
			out = append(out, s.Name)
		}
	}
	return out
}
