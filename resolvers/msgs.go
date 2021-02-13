// Copyright 2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package resolvers

import (
	"net"
	"strings"

	"github.com/OWASP/Amass/v3/requests"
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
			if t, ok := a.(*dns.A); ok {
				if ip := net.ParseIP(t.A.String()); ip != nil {
					value = ip.String()
				}
			}
		case dns.TypeAAAA:
			if t, ok := a.(*dns.AAAA); ok {
				if ip := net.ParseIP(t.AAAA.String()); ip != nil {
					value = ip.String()
				}
			}
		case dns.TypeCNAME:
			if t, ok := a.(*dns.CNAME); ok {
				name := RemoveLastDot(t.Target)

				if _, ok := dns.IsDomainName(name); ok {
					value = name
				}
			}
		case dns.TypePTR:
			if t, ok := a.(*dns.PTR); ok {
				name := RemoveLastDot(t.Ptr)

				if _, ok := dns.IsDomainName(name); ok {
					value = name
				}
			}
		case dns.TypeNS:
			if t, ok := a.(*dns.NS); ok {
				name := RemoveLastDot(t.Ns)

				if _, ok := dns.IsDomainName(name); ok {
					value = name
				}
			}
		case dns.TypeMX:
			if t, ok := a.(*dns.MX); ok {
				name := RemoveLastDot(t.Mx)

				if _, ok := dns.IsDomainName(name); ok {
					value = name
				}
			}
		case dns.TypeTXT:
			if t, ok := a.(*dns.TXT); ok {
				value = strings.Join(t.Txt, " ")
			}
		case dns.TypeSOA:
			if t, ok := a.(*dns.SOA); ok {
				value = t.Ns + "," + t.Mbox
			}
		case dns.TypeSPF:
			if t, ok := a.(*dns.SPF); ok {
				value = strings.Join(t.Txt, " ")
			}
		case dns.TypeSRV:
			if t, ok := a.(*dns.SRV); ok {
				name := RemoveLastDot(t.Target)

				if _, ok := dns.IsDomainName(name); ok {
					value = name
				}
			}
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

func realName(hdr dns.RR_Header) string {
	pieces := strings.Split(hdr.Name, " ")

	return RemoveLastDot(pieces[len(pieces)-1])
}

func getXfrRequests(en *dns.Envelope, domain string) []*requests.DNSRequest {
	if en.Error != nil {
		return nil
	}

	reqs := make(map[string]*requests.DNSRequest)
	for _, a := range en.RR {
		var record requests.DNSAnswer

		switch v := a.(type) {
		case *dns.CNAME:
			record.Name = RemoveLastDot(v.Hdr.Name)
			record.Type = int(dns.TypeCNAME)
			record.Data = RemoveLastDot(v.Target)
		case *dns.A:
			record.Name = RemoveLastDot(v.Hdr.Name)
			record.Type = int(dns.TypeA)
			record.Data = v.A.String()
		case *dns.AAAA:
			record.Name = RemoveLastDot(v.Hdr.Name)
			record.Type = int(dns.TypeAAAA)
			record.Data = v.AAAA.String()
		case *dns.PTR:
			record.Name = RemoveLastDot(v.Hdr.Name)
			record.Type = int(dns.TypePTR)
			record.Data = RemoveLastDot(v.Ptr)
		case *dns.NS:
			record.Name = realName(v.Hdr)
			record.Type = int(dns.TypeNS)
			record.Data = RemoveLastDot(v.Ns)
		case *dns.MX:
			record.Name = RemoveLastDot(v.Hdr.Name)
			record.Type = int(dns.TypeMX)
			record.Data = RemoveLastDot(v.Mx)
		case *dns.TXT:
			record.Name = RemoveLastDot(v.Hdr.Name)
			record.Type = int(dns.TypeTXT)
			for _, piece := range v.Txt {
				record.Data += piece + " "
			}
		case *dns.SOA:
			record.Name = RemoveLastDot(v.Hdr.Name)
			record.Type = int(dns.TypeSOA)
			record.Data = v.Ns + " " + v.Mbox
		case *dns.SPF:
			record.Name = RemoveLastDot(v.Hdr.Name)
			record.Type = int(dns.TypeSPF)
			for _, piece := range v.Txt {
				record.Data += piece + " "
			}
		case *dns.SRV:
			record.Name = RemoveLastDot(v.Hdr.Name)
			record.Type = int(dns.TypeSRV)
			record.Data = RemoveLastDot(v.Target)
		default:
			continue
		}

		if r, found := reqs[record.Name]; found {
			r.Records = append(r.Records, record)
		} else {
			reqs[record.Name] = &requests.DNSRequest{
				Name:    record.Name,
				Domain:  domain,
				Records: []requests.DNSAnswer{record},
				Tag:     requests.AXFR,
				Source:  "DNS Zone XFR",
			}
		}
	}

	var requests []*requests.DNSRequest
	for _, r := range reqs {
		requests = append(requests, r)
	}
	return requests
}
