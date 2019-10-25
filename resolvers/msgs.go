// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package resolvers

import (
	"fmt"
	"net"
	"strings"

	amassdns "github.com/OWASP/Amass/v3/net/dns"
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

func queryMessage(id uint16, name string, qtype uint16) *dns.Msg {
	m := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Authoritative:     false,
			AuthenticatedData: false,
			CheckingDisabled:  false,
			RecursionDesired:  true,
			Opcode:            dns.OpcodeQuery,
			Id:                id,
			Rcode:             dns.RcodeSuccess,
		},
		Question: make([]dns.Question, 1),
	}
	m.Question[0] = dns.Question{
		Name:   dns.Fqdn(name),
		Qtype:  qtype,
		Qclass: uint16(dns.ClassINET),
	}
	m.Extra = append(m.Extra, setupOptions())
	return m
}

// setupOptions - Returns the EDNS0_SUBNET option for hiding our location
func setupOptions() *dns.OPT {
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
		},
		Option: []dns.EDNS0{e},
	}
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

func textToTypeNum(text string) (uint16, error) {
	var qtype uint16

	switch text {
	case "CNAME":
		qtype = dns.TypeCNAME
	case "A":
		qtype = dns.TypeA
	case "AAAA":
		qtype = dns.TypeAAAA
	case "PTR":
		qtype = dns.TypePTR
	case "NS":
		qtype = dns.TypeNS
	case "MX":
		qtype = dns.TypeMX
	case "TXT":
		qtype = dns.TypeTXT
	case "SOA":
		qtype = dns.TypeSOA
	case "SPF":
		qtype = dns.TypeSPF
	case "SRV":
		qtype = dns.TypeSRV
	}

	if qtype == 0 {
		return qtype, fmt.Errorf("DNS message type '%s' not supported", text)
	}
	return qtype, nil
}

func extractRawData(msg *dns.Msg, qtype uint16) []string {
	var data []string

	for _, a := range msg.Answer {
		if a.Header().Rrtype == qtype {
			var value string

			switch qtype {
			case dns.TypeA:
				if t, ok := a.(*dns.A); ok {
					value = amassdns.CopyString(t.A.String())
				}
			case dns.TypeAAAA:
				if t, ok := a.(*dns.AAAA); ok {
					value = amassdns.CopyString(t.AAAA.String())
				}
			case dns.TypeCNAME:
				if t, ok := a.(*dns.CNAME); ok {
					value = amassdns.CopyString(t.Target)
				}
			case dns.TypePTR:
				if t, ok := a.(*dns.PTR); ok {
					value = amassdns.CopyString(t.Ptr)
				}
			case dns.TypeNS:
				if t, ok := a.(*dns.NS); ok {
					value = realName(t.Hdr) + "," + RemoveLastDot(t.Ns)
				}
			case dns.TypeMX:
				if t, ok := a.(*dns.MX); ok {
					value = amassdns.CopyString(t.Mx)
				}
			case dns.TypeTXT:
				if t, ok := a.(*dns.TXT); ok {
					for _, piece := range t.Txt {
						value += piece + " "
					}
				}
			case dns.TypeSOA:
				if t, ok := a.(*dns.SOA); ok {
					value = t.Ns + " " + t.Mbox
				}
			case dns.TypeSPF:
				if t, ok := a.(*dns.SPF); ok {
					for _, piece := range t.Txt {
						value += piece + " "
					}
				}
			case dns.TypeSRV:
				if t, ok := a.(*dns.SRV); ok {
					value = amassdns.CopyString(t.Target)
				}
			}

			if value != "" {
				data = append(data, strings.TrimSpace(value))
			}
		}
	}
	return data
}

func realName(hdr dns.RR_Header) string {
	pieces := strings.Split(hdr.Name, " ")

	return RemoveLastDot(pieces[len(pieces)-1])
}
