// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/OWASP/Amass/amass/internal/utils"
	"github.com/miekg/dns"
)

type DNSAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}

func Resolve(name, qtype string) ([]DNSAnswer, error) {
	qt, err := textToTypeNum(qtype)
	if err != nil {
		return nil, err
	}

	conn, err := DNSDialContext(context.Background(), "udp", "")
	if err != nil {
		return nil, fmt.Errorf("Failed to obtain UDP connection to the DNS resolver: %v", err)
	}
	defer conn.Close()

	ans, err := ExchangeConn(conn, name, qt)
	if err != nil {
		return nil, err
	}
	return ans, nil
}

func ObtainAllRecords(name string) ([]DNSAnswer, error) {
	var answers []DNSAnswer

	if ans, err := Resolve(name, "TXT"); err == nil {
		answers = append(answers, ans...)
	}

	var hasA bool
	if ans, err := Resolve(name, "A"); err == nil {
		hasA = true
		answers = append(answers, ans...)
	}

	if ans, err := Resolve(name, "AAAA"); err == nil {
		hasA = true
		answers = append(answers, ans...)
	}

	if hasA {
		return answers, nil
	}

	if ans, err := Resolve(name, "CNAME"); err == nil {
		answers = append(answers, ans...)
		return answers, nil
	}

	if ans, err := Resolve(name, "PTR"); err == nil {
		answers = append(answers, ans...)
		return answers, nil
	}

	if ans, err := Resolve(name, "SRV"); err == nil {
		answers = append(answers, ans...)
	}

	if len(answers) == 0 {
		return nil, fmt.Errorf("No DNS records were resolved for the name: %s", name)
	}
	return answers, nil
}

func Reverse(addr string) (string, error) {
	var name, ptr string

	ip := net.ParseIP(addr)
	if len(ip.To4()) == net.IPv4len {
		ptr = utils.ReverseIP(addr) + ".in-addr.arpa"
	} else if len(ip) == net.IPv6len {
		ptr = utils.IPv6NibbleFormat(utils.HexString(ip)) + ".ip6.arpa"
	} else {
		return "", fmt.Errorf("Invalid IP address parameter: %s", addr)
	}

	answers, err := Resolve(ptr, "PTR")
	if err == nil {
		if answers[0].Type == 12 {
			l := len(answers[0].Data)

			name = answers[0].Data[:l-1]
		}

		if name == "" {
			err = fmt.Errorf("PTR record not found for IP address: %s", addr)
		}
	}
	return name, err
}

// ExchangeConn - Encapsulates miekg/dns usage
func ExchangeConn(conn net.Conn, name string, qtype uint16) ([]DNSAnswer, error) {
	var err error
	var m, r *dns.Msg

	tries := 3
	if qtype == dns.TypeNS || qtype == dns.TypeMX ||
		qtype == dns.TypeSOA || qtype == dns.TypeSPF {
		tries = 7
	} else if qtype == dns.TypeTXT {
		tries = 10
	}

	for i := 0; i < tries; i++ {
		m = &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Authoritative:     false,
				AuthenticatedData: false,
				CheckingDisabled:  false,
				RecursionDesired:  true,
				Opcode:            dns.OpcodeQuery,
				Id:                dns.Id(),
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

		// Perform the DNS query
		co := &dns.Conn{Conn: conn}
		if err = co.WriteMsg(m); err != nil {
			return nil, fmt.Errorf("DNS error: Failed to write msg to the resolver: %v", err)
		}
		// Set the maximum time for receiving the answer
		co.SetReadDeadline(time.Now().Add(2 * time.Second))
		r, err = co.ReadMsg()
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, err
	}
	// Check that the query was successful
	if r != nil && r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("Resolver returned an error %v", r)
	}

	var answers []DNSAnswer
	for _, a := range extractRawData(r, qtype) {
		answers = append(answers, DNSAnswer{
			Name: name,
			Type: int(qtype),
			TTL:  0,
			Data: strings.TrimSpace(a),
		})
	}

	if len(answers) == 0 {
		return nil, fmt.Errorf("DNS query for %s, type %d returned 0 records", name, qtype)
	}
	return answers, nil
}

func ZoneTransfer(domain, sub, server string) ([]string, error) {
	var results []string

	a, err := Resolve(server, "A")
	if err != nil {
		return results, fmt.Errorf("DNS A record query error: %s: %v", server, err)
	}
	addr := a[0].Data

	// Set the maximum time allowed for making the connection
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := DialContext(ctx, "tcp", addr+":53")
	if err != nil {
		return results, fmt.Errorf("Zone xfr error: Failed to obtain TCP connection to %s: %v", addr+":53", err)
	}
	defer conn.Close()

	xfr := &dns.Transfer{
		Conn:        &dns.Conn{Conn: conn},
		ReadTimeout: 10 * time.Second,
	}

	m := &dns.Msg{}
	m.SetAxfr(dns.Fqdn(sub))

	in, err := xfr.In(m, "")
	if err != nil {
		return results, fmt.Errorf("DNS zone transfer error: %s: %v", addr+":53", err)
	}

	for en := range in {
		names := getXfrNames(en)
		if names == nil {
			continue
		}

		for _, name := range names {
			n := name[:len(name)-1]

			results = append(results, n)
		}
	}
	return results, nil
}

//-------------------------------------------------------------------------------------------------
// Support functions
//-------------------------------------------------------------------------------------------------

func getXfrNames(en *dns.Envelope) []string {
	var names []string

	if en.Error != nil {
		return nil
	}

	for _, a := range en.RR {
		var name string

		switch v := a.(type) {
		case *dns.A:
			name = v.Hdr.Name
		case *dns.AAAA:
			name = v.Hdr.Name
		case *dns.NS:
			name = v.Ns
		case *dns.CNAME:
			name = v.Hdr.Name
		case *dns.SRV:
			name = v.Hdr.Name
		case *dns.TXT:
			name = v.Hdr.Name
		default:
			continue
		}

		names = append(names, name)
	}
	return names
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
			switch qtype {
			case dns.TypeA:
				if t, ok := a.(*dns.A); ok {
					data = append(data, t.A.String())
				}
			case dns.TypeAAAA:
				if t, ok := a.(*dns.AAAA); ok {
					data = append(data, t.AAAA.String())
				}
			case dns.TypeCNAME:
				if t, ok := a.(*dns.CNAME); ok {
					data = append(data, t.Target)
				}
			case dns.TypePTR:
				if t, ok := a.(*dns.PTR); ok {
					data = append(data, t.Ptr)
				}
			case dns.TypeNS:
				if t, ok := a.(*dns.NS); ok {
					data = append(data, t.Ns)
				}
			case dns.TypeMX:
				if t, ok := a.(*dns.MX); ok {
					data = append(data, t.Mx)
				}
			case dns.TypeTXT:
				if t, ok := a.(*dns.TXT); ok {
					var all string

					for _, piece := range t.Txt {
						all += piece + " "
					}
					data = append(data, all)
				}
			case dns.TypeSOA:
				if t, ok := a.(*dns.SOA); ok {
					data = append(data, t.Ns+" "+t.Mbox)
				}
			case dns.TypeSPF:
				if t, ok := a.(*dns.SPF); ok {
					var all string

					for _, piece := range t.Txt {
						all += piece + " "
					}
					data = append(data, all)
				}
			case dns.TypeSRV:
				if t, ok := a.(*dns.SRV); ok {
					data = append(data, t.Target)
				}
			}
		}
	}
	return data
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
