// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package requests

import (
	"net"
	"strings"
	"time"

	amassdns "github.com/OWASP/Amass/v3/net/dns"
	"github.com/caffix/pipeline"
	"github.com/caffix/stringset"
	"github.com/miekg/dns"
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
	RIR      = "rir"
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
	NewNameTopic       = "amass:newname"
	NewAddrTopic       = "amass:newaddr"
	SubDiscoveredTopic = "amass:newsub"
	ASNRequestTopic    = "amass:asnreq"
	NewASNTopic        = "amass:newasn"
	WhoisRequestTopic  = "amass:whoisreq"
	NewWhoisTopic      = "amass:whoisinfo"
	LogTopic           = "amass:log"
	OutputTopic        = "amass:output"
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

// Clone implements pipeline Data.
func (d *DNSRequest) Clone() pipeline.Data {
	return &DNSRequest{
		Name:    d.Name,
		Domain:  d.Domain,
		Records: append([]DNSAnswer(nil), d.Records...),
		Tag:     d.Tag,
		Source:  d.Source,
	}
}

// MarkAsProcessed implements pipeline Data.
func (d *DNSRequest) MarkAsProcessed() {}

// Valid performs input validation of the receiver.
func (d *DNSRequest) Valid() bool {
	if _, ok := dns.IsDomainName(d.Name); !ok {
		return false
	}
	if _, ok := dns.IsDomainName(d.Domain); !ok {
		return false
	}
	if !dns.IsSubDomain(d.Domain, d.Name) {
		return false
	}
	return true
}

// ResolvedRequest allows services to identify DNS names that have been resolved.

type ResolvedRequest struct {
	Name    string
	Domain  string
	Records []DNSAnswer
	Tag     string
	Source  string
}

// Clone implements pipeline Data.
func (r *ResolvedRequest) Clone() pipeline.Data {
	return &ResolvedRequest{
		Name:    r.Name,
		Domain:  r.Domain,
		Records: append([]DNSAnswer(nil), r.Records...),
		Tag:     r.Tag,
		Source:  r.Source,
	}
}

// MarkAsProcessed implements pipeline Data.
func (r *ResolvedRequest) MarkAsProcessed() {}

// Valid performs input validation of the receiver.
func (r *ResolvedRequest) Valid() bool {
	if _, ok := dns.IsDomainName(r.Name); !ok {
		return false
	}
	if _, ok := dns.IsDomainName(r.Domain); !ok {
		return false
	}
	if !dns.IsSubDomain(r.Domain, r.Name) {
		return false
	}
	return true
}

// SubdomainRequest handles subdomain data processed by enumeration.
type SubdomainRequest struct {
	Name    string
	Domain  string
	Records []DNSAnswer
	Tag     string
	Source  string
	Times   int
}

// Clone implements pipeline Data.
func (s *SubdomainRequest) Clone() pipeline.Data {
	return &SubdomainRequest{
		Name:    s.Name,
		Domain:  s.Domain,
		Records: append([]DNSAnswer(nil), s.Records...),
		Tag:     s.Tag,
		Source:  s.Source,
	}
}

// MarkAsProcessed implements pipeline Data.
func (s *SubdomainRequest) MarkAsProcessed() {}

// Valid performs input validation of the receiver.
func (s *SubdomainRequest) Valid() bool {
	if _, ok := dns.IsDomainName(s.Name); !ok {
		return false
	}
	if _, ok := dns.IsDomainName(s.Domain); !ok {
		return false
	}
	if !dns.IsSubDomain(s.Domain, s.Name) {
		return false
	}
	if s.Times == 0 {
		return false
	}
	return true
}

// ZoneXFRRequest handles zone transfer requests.
type ZoneXFRRequest struct {
	Name   string
	Domain string
	Server string
	Tag    string
	Source string
}

// Clone implements pipeline Data.
func (z *ZoneXFRRequest) Clone() pipeline.Data {
	return &ZoneXFRRequest{
		Name:   z.Name,
		Domain: z.Domain,
		Server: z.Server,
		Tag:    z.Tag,
		Source: z.Source,
	}
}

// MarkAsProcessed implements pipeline Data.
func (z *ZoneXFRRequest) MarkAsProcessed() {}

// AddrRequest handles data needed throughout Service processing of a network address.
type AddrRequest struct {
	Address string
	Domain  string
	Tag     string
	Source  string
}

// Clone implements pipeline Data.
func (a *AddrRequest) Clone() pipeline.Data {
	return &AddrRequest{
		Address: a.Address,
		Domain:  a.Domain,
		Tag:     a.Tag,
		Source:  a.Source,
	}
}

// MarkAsProcessed implements pipeline Data.
func (a *AddrRequest) MarkAsProcessed() {}

// Valid performs input validation of the receiver.
func (a *AddrRequest) Valid() bool {
	if ip := net.ParseIP(a.Address); ip == nil {
		return false
	}
	if _, ok := dns.IsDomainName(a.Domain); !ok {
		return false
	}
	return true
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

// Clone implements pipeline Data.
func (a *ASNRequest) Clone() pipeline.Data {
	return &ASNRequest{
		Address:        a.Address,
		ASN:            a.ASN,
		Prefix:         a.Prefix,
		CC:             a.CC,
		Registry:       a.Registry,
		AllocationDate: a.AllocationDate,
		Description:    a.Description,
		Netblocks:      stringset.New(a.Netblocks.Slice()...),
		Tag:            a.Tag,
		Source:         a.Source,
	}
}

// MarkAsProcessed implements pipeline Data.
func (a *ASNRequest) MarkAsProcessed() {}

// Valid performs input validation of the receiver.
func (a *ASNRequest) Valid() bool {
	if ip := net.ParseIP(a.Address); ip == nil {
		return false
	}
	if _, _, err := net.ParseCIDR(a.Prefix); err != nil {
		return false
	}
	for _, netblock := range a.Netblocks.Slice() {
		if _, _, err := net.ParseCIDR(netblock); err != nil {
			return false
		}
	}
	return true
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
	Sources   []string      `json:"sources"`
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

// SanitizeDNSRequest cleans the Name and Domain elements of the receiver.
func SanitizeDNSRequest(req *DNSRequest) {
	req.Name = strings.ToLower(req.Name)
	req.Name = strings.TrimSpace(req.Name)
	req.Name = amassdns.RemoveAsteriskLabel(req.Name)
	req.Name = strings.Trim(req.Name, ".")

	req.Domain = strings.ToLower(req.Domain)
	req.Domain = strings.TrimSpace(req.Domain)
	req.Domain = strings.Trim(req.Domain, ".")
}
