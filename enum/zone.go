// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package enum

import (
	"context"
	"fmt"
	"strings"
	"time"

	amassnet "github.com/OWASP/Amass/v3/net"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/caffix/resolve"
	"github.com/miekg/dns"
)

// ZoneTransfer attempts a DNS zone transfer using the provided server.
// The returned slice contains all the records discovered from the zone transfer.
func ZoneTransfer(sub, domain, server string) ([]*requests.DNSRequest, error) {
	var results []*requests.DNSRequest

	// Set the maximum time allowed for making the connection
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, err := amassnet.DialContext(ctx, "tcp", server+":53")
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

		results = append(results, reqs...)
	}
	return results, nil
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
			record.Type = int(dns.TypeCNAME)
			record.Name = resolve.RemoveLastDot(v.Hdr.Name)
			record.Data = resolve.RemoveLastDot(v.Target)
		case *dns.A:
			record.Type = int(dns.TypeA)
			record.Name = resolve.RemoveLastDot(v.Hdr.Name)
			record.Data = v.A.String()
		case *dns.AAAA:
			record.Type = int(dns.TypeAAAA)
			record.Name = resolve.RemoveLastDot(v.Hdr.Name)
			record.Data = v.AAAA.String()
		case *dns.PTR:
			record.Type = int(dns.TypePTR)
			record.Name = resolve.RemoveLastDot(v.Hdr.Name)
			record.Data = resolve.RemoveLastDot(v.Ptr)
		case *dns.NS:
			record.Type = int(dns.TypeNS)
			record.Name = realName(v.Hdr)
			record.Data = resolve.RemoveLastDot(v.Ns)
		case *dns.MX:
			record.Type = int(dns.TypeMX)
			record.Name = resolve.RemoveLastDot(v.Hdr.Name)
			record.Data = resolve.RemoveLastDot(v.Mx)
		case *dns.TXT:
			record.Type = int(dns.TypeTXT)
			record.Name = resolve.RemoveLastDot(v.Hdr.Name)
			for _, piece := range v.Txt {
				record.Data += piece + " "
			}
		case *dns.SOA:
			record.Type = int(dns.TypeSOA)
			record.Name = resolve.RemoveLastDot(v.Hdr.Name)
			record.Data = v.Ns + " " + v.Mbox
		case *dns.SPF:
			record.Type = int(dns.TypeSPF)
			record.Name = resolve.RemoveLastDot(v.Hdr.Name)
			for _, piece := range v.Txt {
				record.Data += piece + " "
			}
		case *dns.SRV:
			record.Type = int(dns.TypeSRV)
			record.Name = resolve.RemoveLastDot(v.Hdr.Name)
			record.Data = resolve.RemoveLastDot(v.Target)
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

func realName(hdr dns.RR_Header) string {
	pieces := strings.Split(hdr.Name, " ")

	return resolve.RemoveLastDot(pieces[len(pieces)-1])
}
