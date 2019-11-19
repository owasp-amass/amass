// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package requests

import (
	"net"
	"time"

	"github.com/OWASP/Amass/v3/stringset"
)

// Request tag types.
const (
	NONE     = "none"
	ALT      = "alt"
	GUESS    = "guess"
	ARCHIVE  = "archive"
	API      = "api"
	AXFR     = "axfr"
	BRUTE    = "brute"
	CERT     = "cert"
	DNS      = "dns"
	EXTERNAL = "ext"
	SCRAPE   = "scrape"
)

// ContextKey is the type used for context value keys.
type ContextKey int

// The key used when values are obtained during service requests.
const (
	ContextConfig ContextKey = iota
	ContextEventBus
)

// Request Pub/Sub topics used across Amass.
const (
	NameRequestTopic   = "amass:namereq"
	NewNameTopic       = "amass:newname"
	AddrRequestTopic   = "amass:addrreq"
	NewAddrTopic       = "amass:newaddr"
	SubDiscoveredTopic = "amass:newsub"
	ResolveNameTopic   = "amass:resolve"
	NameResolvedTopic  = "amass:resolved"
	ASNRequestTopic    = "amass:asnreq"
	NewASNTopic        = "amass:newasn"
	WhoisRequestTopic  = "amass:whoisreq"
	NewWhoisTopic      = "amass:whoisinfo"
	LogTopic           = "amass:log"
	OutputTopic        = "amass:output"
	SetActiveTopic     = "amass:setactive"
	ResolveCompleted   = "amass:resolvecomp"
)

// DNSAnswer is the type used by Amass to represent a DNS record.
type DNSAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}

// DNSRequest handles data needed throughout Service processing of a DNS name.
type DNSRequest struct {
	Name    string
	Domain  string
	Records []DNSAnswer
	Tag     string
	Source  string
}

// AddrRequest handles data needed throughout Service processing of a network address.
type AddrRequest struct {
	Address string
	Domain  string
	Tag     string
	Source  string
}

// ASNRequest handles all autonomous system information needed by Amass.
type ASNRequest struct {
	Address        string
	ASN            int
	Prefix         string
	CC             string
	Registry       string
	AllocationDate time.Time
	Description    string
	Netblocks      stringset.Set
	Tag            string
	Source         string
}

// WhoisRequest handles data needed throughout Service processing of reverse whois.
type WhoisRequest struct {
	Domain     string
	Company    string
	Email      string
	NewDomains []string
	Tag        string
	Source     string
}

// Output contains all the output data for an enumerated DNS name.
type Output struct {
	Name      string        `json:"name"`
	Domain    string        `json:"domain"`
	Addresses []AddressInfo `json:"addresses"`
	Tag       string        `json:"tag"`
	Source    string        `json:"source"`
}

// AddressInfo stores all network addressing info for the Output type.
type AddressInfo struct {
	Address     net.IP     `json:"ip"`
	Netblock    *net.IPNet `json:"-"`
	CIDRStr     string     `json:"cidr"`
	ASN         int        `json:"asn"`
	Description string     `json:"desc"`
}

// TrustedTag returns true when the tag parameter is of a type that should be trusted even
// facing DNS wildcards.
func TrustedTag(tag string) bool {
	if tag == DNS || tag == CERT || tag == ARCHIVE || tag == AXFR {
		return true
	}
	return false
}
