// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package requests

import (
	"net"
	"strings"
	"time"

	"github.com/caffix/pipeline"
	"github.com/miekg/dns"
	amassdns "github.com/owasp-amass/amass/v4/net/dns"
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
}

// Clone implements pipeline Data.
func (d *DNSRequest) Clone() pipeline.Data {
	return &DNSRequest{
		Name:    d.Name,
		Domain:  d.Domain,
		Records: append([]DNSAnswer(nil), d.Records...),
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
}

// Clone implements pipeline Data.
func (r *ResolvedRequest) Clone() pipeline.Data {
	return &ResolvedRequest{
		Name:    r.Name,
		Domain:  r.Domain,
		Records: append([]DNSAnswer(nil), r.Records...),
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
	Times   int
}

// Clone implements pipeline Data.
func (s *SubdomainRequest) Clone() pipeline.Data {
	return &SubdomainRequest{
		Name:    s.Name,
		Domain:  s.Domain,
		Records: append([]DNSAnswer(nil), s.Records...),
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
}

// Clone implements pipeline Data.
func (z *ZoneXFRRequest) Clone() pipeline.Data {
	return &ZoneXFRRequest{
		Name:   z.Name,
		Domain: z.Domain,
		Server: z.Server,
	}
}

// MarkAsProcessed implements pipeline Data.
func (z *ZoneXFRRequest) MarkAsProcessed() {}

// AddrRequest handles data needed throughout Service processing of a network address.
type AddrRequest struct {
	Address string
	InScope bool
	Domain  string
}

// Clone implements pipeline Data.
func (a *AddrRequest) Clone() pipeline.Data {
	return &AddrRequest{
		Address: a.Address,
		InScope: a.InScope,
		Domain:  a.Domain,
	}
}

// MarkAsProcessed implements pipeline Data.
func (a *AddrRequest) MarkAsProcessed() {}

// Valid performs input validation of the receiver.
func (a *AddrRequest) Valid() bool {
	if ip := net.ParseIP(a.Address); ip == nil {
		return false
	}
	if a.Domain != "" {
		if _, ok := dns.IsDomainName(a.Domain); !ok {
			return false
		}
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
	Netblocks      []string
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
		Netblocks:      a.Netblocks,
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
	for _, netblock := range a.Netblocks {
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
}

// Output contains all the output data for an enumerated DNS name.
type Output struct {
	Name      string        `json:"name"`
	Domain    string        `json:"domain"`
	Addresses []AddressInfo `json:"addresses"`
}

// Clone implements pipeline Data.
func (o *Output) Clone() pipeline.Data {
	return &Output{
		Name:      o.Name,
		Domain:    o.Domain,
		Addresses: append([]AddressInfo(nil), o.Addresses...),
	}
}

// MarkAsProcessed implements pipeline Data.
func (o *Output) MarkAsProcessed() {}

// Complete checks that all the required fields have been populated.
func (o *Output) Complete(passive bool) bool {
	if o.Name == "" || o.Domain == "" {
		return false
	}

	if !passive {
		for _, a := range o.Addresses {
			if a.Address == nil || a.Netblock == nil || a.CIDRStr == "" || a.Description == "" {
				return false
			}
		}
	}

	return true
}

// AddressInfo stores all network addressing info for the Output type.
type AddressInfo struct {
	Address     net.IP     `json:"ip"`
	Netblock    *net.IPNet `json:"-"`
	CIDRStr     string     `json:"cidr"`
	ASN         int        `json:"asn"`
	Description string     `json:"desc"`
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
