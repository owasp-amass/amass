// Copyright 2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package resolvers

import (
	"net"
	"strings"

	"github.com/miekg/dns"
)

// RemoveLastDot removes the '.' at the end of the provided FQDN.
func RemoveLastDot(name string) string {
	sz := len(name)
	if sz > 0 && name[sz-1] == '.' {
		return name[:sz-1]
	}
	return name
}

// QueryMsg generates a message used for a forward DNS query.
func QueryMsg(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)

	m.SetQuestion(dns.Fqdn(name), qtype)
	m.Extra = append(m.Extra, SetupOptions())
	return m
}

// ReverseMsg generates a message used for a reverse DNS query.
func ReverseMsg(addr string) *dns.Msg {
	if r, err := dns.ReverseAddr(addr); err == nil {
		return QueryMsg(r, dns.TypePTR)
	}
	return nil
}

// WalkMsg generates a message used for a NSEC walk query.
func WalkMsg(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)

	m.SetQuestion(dns.Fqdn(name), qtype)
	m.SetEdns0(dns.DefaultMsgSize, true)
	return m
}

// SetupOptions returns the EDNS0_SUBNET option for hiding our location.
func SetupOptions() *dns.OPT {
	e := &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        1,
		SourceNetmask: 0,
		SourceScope:   0,
		Address:       net.ParseIP("0.0.0.0").To4(),
	}

	return &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
			Class:  dns.DefaultMsgSize,
		},
		Option: []dns.EDNS0{e},
	}
}

// ExtractedAnswer contains information from the DNS response Answer section.
type ExtractedAnswer struct {
	Name string
	Type uint16
	Data string
}

// AnswersByType returns only the answers from the DNS Answer section matching the provided type.
func AnswersByType(answers []*ExtractedAnswer, qtype uint16) []*ExtractedAnswer {
	var subset []*ExtractedAnswer

	for _, a := range answers {
		if a.Type == qtype {
			subset = append(subset, a)
		}
	}

	return subset
}

// ExtractAnswers returns information from the DNS Answer section of the provided Msg in ExtractedAnswer type.
func ExtractAnswers(msg *dns.Msg) []*ExtractedAnswer {
	var data []*ExtractedAnswer

	for _, a := range msg.Answer {
		var value string

		switch a.Header().Rrtype {
		case dns.TypeA:
			value = parseAType(a)
		case dns.TypeAAAA:
			value = parseAAAAType(a)
		case dns.TypeCNAME:
			value = parseCNAMEType(a)
		case dns.TypePTR:
			value = parsePTRType(a)
		case dns.TypeNS:
			value = parseNSType(a)
		case dns.TypeMX:
			value = parseMXType(a)
		case dns.TypeTXT:
			value = parseTXTType(a)
		case dns.TypeSOA:
			value = parseSOAType(a)
		case dns.TypeSPF:
			value = parseSPFType(a)
		case dns.TypeSRV:
			value = parseSRVType(a)
		}

		if value != "" {
			data = append(data, &ExtractedAnswer{
				Name: strings.ToLower(RemoveLastDot(a.Header().Name)),
				Type: a.Header().Rrtype,
				Data: strings.TrimSpace(value),
			})
		}
	}

	return data
}

func parseAType(rr dns.RR) string {
	var value string

	if t, ok := rr.(*dns.A); ok {
		if ip := net.ParseIP(t.A.String()); ip != nil {
			value = ip.String()
		}
	}

	return value
}

func parseAAAAType(rr dns.RR) string {
	var value string

	if t, ok := rr.(*dns.AAAA); ok {
		if ip := net.ParseIP(t.AAAA.String()); ip != nil {
			value = ip.String()
		}
	}

	return value
}

func parseCNAMEType(rr dns.RR) string {
	var value string

	if t, ok := rr.(*dns.CNAME); ok {
		name := RemoveLastDot(t.Target)

		if _, ok := dns.IsDomainName(name); ok {
			value = name
		}
	}

	return value
}

func parsePTRType(rr dns.RR) string {
	var value string

	if t, ok := rr.(*dns.PTR); ok {
		name := RemoveLastDot(t.Ptr)

		if _, ok := dns.IsDomainName(name); ok {
			value = name
		}
	}

	return value
}

func parseNSType(rr dns.RR) string {
	var value string

	if t, ok := rr.(*dns.NS); ok {
		name := RemoveLastDot(t.Ns)

		if _, ok := dns.IsDomainName(name); ok {
			value = name
		}
	}

	return value
}

func parseMXType(rr dns.RR) string {
	var value string

	if t, ok := rr.(*dns.MX); ok {
		name := RemoveLastDot(t.Mx)

		if _, ok := dns.IsDomainName(name); ok {
			value = name
		}
	}

	return value
}

func parseTXTType(rr dns.RR) string {
	var value string

	if t, ok := rr.(*dns.TXT); ok {
		value = strings.Join(t.Txt, " ")
	}

	return value
}

func parseSOAType(rr dns.RR) string {
	var value string

	if t, ok := rr.(*dns.SOA); ok {
		value = t.Ns + "," + t.Mbox
	}

	return value
}

func parseSPFType(rr dns.RR) string {
	var value string

	if t, ok := rr.(*dns.SPF); ok {
		value = strings.Join(t.Txt, " ")
	}

	return value
}

func parseSRVType(rr dns.RR) string {
	var value string

	if t, ok := rr.(*dns.SRV); ok {
		name := RemoveLastDot(t.Target)

		if _, ok := dns.IsDomainName(name); ok {
			value = name
		}
	}

	return value
}
