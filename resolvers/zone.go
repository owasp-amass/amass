// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package resolvers

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	amassdns "github.com/OWASP/Amass/v3/net/dns"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/miekg/dns"
)

// ZoneTransfer attempts a DNS zone transfer using the server identified in the parameters.
// The returned slice contains all the records discovered from the zone transfer.
func ZoneTransfer(sub, domain, server string) ([]*requests.DNSRequest, error) {
	var results []*requests.DNSRequest

	// Set the maximum time allowed for making the connection
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", server+":53")
	if err != nil {
		return results, fmt.Errorf("Zone xfr error: Failed to obtain TCP connection to %s: %v", server+":53", err)
	}
	defer conn.Close()

	xfr := &dns.Transfer{
		Conn:        &dns.Conn{Conn: conn},
		ReadTimeout: 30 * time.Second,
	}

	m := &dns.Msg{}
	m.SetAxfr(dns.Fqdn(sub))

	in, err := xfr.In(m, "")
	if err != nil {
		return results, fmt.Errorf("DNS zone transfer error: %s: %v", server+":53", err)
	}

	for en := range in {
		reqs := getXfrRequests(en, domain)
		if reqs == nil {
			continue
		}

		for _, r := range reqs {
			results = append(results, r)
		}
	}
	return results, nil
}

// NsecTraversal attempts to retrieve a DNS zone using NSEC-walking.
func NsecTraversal(domain, server string) ([]*requests.DNSRequest, error) {
	var results []*requests.DNSRequest

	d := &net.Dialer{}
	conn, err := d.Dial("udp", server+":53")
	if err != nil {
		return results, fmt.Errorf("Failed to setup UDP connection with the DNS server: %s: %v", server, err)
	}
	defer conn.Close()
	co := &dns.Conn{Conn: conn}

	re := amassdns.SubdomainRegex(domain)
loop:
	for next := domain; next != ""; {
		name := next
		next = ""
		for _, attempt := range walkAttempts(name, domain) {
			id := dns.Id()
			msg := walkMsg(id, attempt, dns.TypeA)

			co.SetWriteDeadline(time.Now().Add(2 * time.Second))
			if err := co.WriteMsg(msg); err != nil {
				continue
			}

			co.SetReadDeadline(time.Now().Add(2 * time.Second))
			in, err := co.ReadMsg()
			if err != nil || in == nil || in.MsgHdr.Id != id {
				continue
			}

			for _, rr := range in.Answer {
				if rr.Header().Rrtype != dns.TypeA {
					continue
				}

				n := strings.ToLower(RemoveLastDot(rr.Header().Name))
				results = append(results, &requests.DNSRequest{
					Name:   n,
					Domain: domain,
					Tag:    requests.DNS,
					Source: "NSEC Walk",
				})

				if _, ok := rr.(*dns.NSEC); ok {
					next = rr.(*dns.NSEC).NextDomain
					continue loop
				}
			}

			for _, rr := range in.Ns {
				if rr.Header().Rrtype != dns.TypeNSEC {
					continue
				}

				prev := strings.ToLower(RemoveLastDot(rr.Header().Name))
				nn := walkHostPart(name, domain)
				hp := walkHostPart(prev, domain)
				if !re.MatchString(prev) || hp >= nn {
					continue
				}

				results = append(results, &requests.DNSRequest{
					Name:   prev,
					Domain: domain,
					Tag:    requests.DNS,
					Source: "NSEC Walk",
				})

				n := strings.ToLower(RemoveLastDot(rr.(*dns.NSEC).NextDomain))
				hn := walkHostPart(n, domain)
				if n != "" && nn < hn {
					next = n
					continue loop
				}
			}
		}
	}
	return results, nil
}

func walkAttempts(name, domain string) []string {
	name = strings.ToLower(name)
	domain = strings.ToLower(domain)

	// The original subdomain name and another with a zero label prepended
	attempts := []string{name, "0." + name}
	if name == domain {
		return attempts
	}

	host := walkHostPart(name, domain)
	// A hyphen appended to the hostname portion + the domain name
	attempts = append(attempts, host+"-."+domain)

	rhost := []rune(host)
	last := string(rhost[len(rhost)-1])
	// The last character of the hostname portion duplicated/appended
	return append(attempts, host+last+"."+domain)
}

func walkHostPart(name, domain string) string {
	dlen := len(strings.Split(domain, "."))
	parts := strings.Split(name, ".")

	return strings.Join(parts[0:len(parts)-dlen], ".")
}

func walkMsg(id uint16, name string, qtype uint16) *dns.Msg {
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
	opt := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
		},
	}
	opt.SetDo()
	opt.SetUDPSize(dns.DefaultMsgSize)
	m.Extra = append(m.Extra, opt)
	return m
}
