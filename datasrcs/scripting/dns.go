// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scripting

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	amassnet "github.com/owasp-amass/amass/v4/net"
	amassdns "github.com/owasp-amass/amass/v4/net/dns"
	"github.com/owasp-amass/amass/v4/requests"
	"github.com/owasp-amass/resolve"
	bf "github.com/tylertreat/BoomFilters"
	lua "github.com/yuin/gopher-lua"
	"golang.org/x/net/publicsuffix"
)

const (
	defaultSweepSize = 250
	activeSweepSize  = 500
	maxSweepSize     = 1000
)

var (
	sweepLock   sync.Mutex
	sweepMaxCh  chan struct{}         = make(chan struct{}, maxSweepSize)
	sweepFilter *bf.StableBloomFilter = bf.NewDefaultStableBloomFilter(1000000, 0.01)
)

func init() {
	for i := 0; i < maxSweepSize; i++ {
		sweepMaxCh <- struct{}{}
	}
}

// Wrapper so that scripts can make DNS queries.
func (s *Script) resolve(L *lua.LState) int {
	ctx, err := extractContext(L.CheckUserData(1))
	name := L.CheckString(2)
	qtype := convertType(L.CheckString(3))
	if err != nil || name == "" || qtype == 0 {
		L.Push(lua.LNil)
		L.Push(lua.LString("proper parameters were not provided"))
		return 2
	}

	resp, err := s.fwdQuery(ctx, name, qtype)
	if err != nil || resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
		L.Push(lua.LNil)
		L.Push(lua.LString("the query was unsuccessful for " + name))
		return 2
	}

	detection := true
	if L.GetTop() == 4 {
		detection = L.CheckBool(4)
	}

	if detection {
		domain, err := publicsuffix.EffectiveTLDPlusOne(name)

		if err != nil || s.sys.TrustedResolvers().WildcardDetected(ctx, resp, domain) {
			L.Push(lua.LNil)
			L.Push(lua.LString("DNS wildcard detection made a positive match for " + name))
			return 2
		}
	}

	tb := L.NewTable()
	if ans := resolve.ExtractAnswers(resp); len(ans) > 0 {
		if records := resolve.AnswersByType(ans, qtype); len(records) > 0 {
			for _, rr := range records {
				entry := L.NewTable()
				entry.RawSetString("rrname", lua.LString(rr.Name))
				entry.RawSetString("rrtype", lua.LNumber(rr.Type))
				entry.RawSetString("rrdata", lua.LString(rr.Data))
				tb.Append(entry)
			}
		}
	}
	L.Push(tb)
	L.Push(lua.LNil)
	return 2
}

func (s *Script) fwdQuery(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	msg := resolve.QueryMsg(name, qtype)
	resp, err := s.dnsQuery(ctx, msg, s.sys.Resolvers(), 5)
	if err != nil {
		return resp, err
	}
	if resp == nil && err == nil {
		return nil, errors.New("query failed")
	}

	resp, err = s.dnsQuery(ctx, msg, s.sys.TrustedResolvers(), 3)
	if resp == nil && err == nil {
		err = errors.New("query failed")
	}
	return resp, err
}

func (s *Script) dnsQuery(ctx context.Context, msg *dns.Msg, r *resolve.Resolvers, attempts int) (*dns.Msg, error) {
	for num := 0; num < attempts; num++ {
		select {
		case <-ctx.Done():
			return nil, errors.New("context expired")
		default:
		}

		resp, err := r.QueryBlocking(ctx, msg)
		if err != nil {
			continue
		}
		if resp.Rcode == dns.RcodeNameError {
			return nil, errors.New("name does not exist")
		}
		if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) == 0 {
			return nil, errors.New("no record of this type")
		}
		if resp.Rcode == dns.RcodeSuccess {
			return resp, nil
		}
	}
	return nil, nil
}

func convertType(qtype string) uint16 {
	var t uint16

	switch strings.ToLower(qtype) {
	case "a":
		t = dns.TypeA
	case "aaaa":
		t = dns.TypeAAAA
	case "cname":
		t = dns.TypeCNAME
	case "ptr":
		t = dns.TypePTR
	case "ns":
		t = dns.TypeNS
	case "mx":
		t = dns.TypeMX
	case "txt":
		t = dns.TypeTXT
	case "soa":
		t = dns.TypeSOA
	case "srv":
		t = dns.TypeSRV
	}
	return t
}

func (s *Script) reverseSweep(L *lua.LState) int {
	ctx, err := extractContext(L.CheckUserData(1))
	if err != nil {
		L.Push(lua.LString("failed to obtain the context"))
		return 1
	}

	addr := L.CheckString(2)
	if addr == "" {
		L.Push(lua.LString("failed to obtain the IP address"))
		return 1
	}

	size := defaultSweepSize
	if s.sys.Config().Active {
		size = activeSweepSize
	}

	var cidr *net.IPNet
	if asn := s.sys.Cache().AddrSearch(addr); asn != nil {
		if _, c, err := net.ParseCIDR(asn.Prefix); err == nil {
			cidr = c
		}
	}

	if cidr == nil {
		ip := net.ParseIP(addr)
		mask := net.CIDRMask(18, 32)
		if amassnet.IsIPv6(ip) {
			mask = net.CIDRMask(64, 128)
		}

		cidr = &net.IPNet{
			IP:   ip.Mask(mask),
			Mask: mask,
		}
	}

	var count int
	for _, ip := range amassnet.CIDRSubset(cidr, addr, size) {
		select {
		case <-ctx.Done():
			L.Push(lua.LString("the context expired"))
			return 1
		default:
		}

		sweepLock.Lock()
		if a := ip.String(); !sweepFilter.TestAndAdd([]byte(a)) {
			count++
			<-sweepMaxCh
			go s.getPTR(ctx, a, sweepMaxCh)
		}
		sweepLock.Unlock()
	}

	L.Push(lua.LNil)
	return 1
}

func (s *Script) getPTR(ctx context.Context, addr string, ch chan struct{}) {
	defer func() { ch <- struct{}{} }()

	if reserved, _ := amassnet.IsReservedAddress(addr); reserved {
		return
	}

	msg := resolve.ReverseMsg(addr)
	resp, err := s.dnsQuery(ctx, msg, s.sys.Resolvers(), 5)
	if err != nil || resp == nil {
		return
	}

	resp, err = s.dnsQuery(ctx, msg, s.sys.TrustedResolvers(), 3)
	if err != nil || resp == nil {
		return
	}

	if ans := resolve.ExtractAnswers(resp); len(ans) > 0 {
		if records := resolve.AnswersByType(ans, dns.TypePTR); len(records) > 0 {
			s.newPTR(ctx, records[0])
			return
		}
	}
}

func (s *Script) zoneWalk(L *lua.LState) int {
	ctx, err := extractContext(L.CheckUserData(1))
	if err != nil {
		L.Push(lua.LString("failed to obtain the context"))
		return 1
	}

	name := L.CheckString(2)
	if name == "" {
		L.Push(lua.LString("failed to obtain the DNS name"))
		return 1
	}

	server := L.CheckString(3)
	if server == "" {
		L.Push(lua.LString("failed to obtain the nameserver"))
		return 1
	}

	domain := s.sys.Config().WhichDomain(name)
	if domain == "" {
		L.Push(lua.LString("the name " + name + " was not in scope"))
		return 1
	}

	r := resolve.NewResolvers()
	r.SetLogger(s.sys.Config().Log)
	_ = r.AddResolvers(15, server)
	defer r.Stop()

	names, err := r.NsecTraversal(ctx, name)
	if err != nil {
		L.Push(lua.LString(fmt.Sprintf("Zone Walk failed: %s: %v", name, err)))
		return 1
	}

	for _, nsec := range names {
		name := resolve.RemoveLastDot(nsec.NextDomain)

		if domain := s.sys.Config().WhichDomain(name); domain != "" {
			s.Output() <- &requests.DNSRequest{
				Name:   name,
				Domain: domain,
			}
		}
	}

	L.Push(lua.LNil)
	return 1
}

func (s *Script) wrapZoneTransfer(L *lua.LState) int {
	ctx, err := extractContext(L.CheckUserData(1))
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString("failed to obtain the context"))
		return 2
	}

	name := L.CheckString(2)
	if name == "" {
		L.Push(lua.LNil)
		L.Push(lua.LString("failed to obtain the DNS name"))
		return 2
	}

	server := L.CheckString(3)
	if server == "" {
		L.Push(lua.LNil)
		L.Push(lua.LString("failed to obtain the nameserver"))
		return 2
	}

	domain := s.sys.Config().WhichDomain(name)
	if domain == "" {
		L.Push(lua.LNil)
		L.Push(lua.LString("the name " + name + " was not in scope"))
		return 2
	}

	tb := L.NewTable()
	if reqs, err := ZoneTransfer(ctx, name, domain, server); err == nil && len(reqs) > 0 {
		for _, req := range reqs {
			for _, rr := range req.Records {
				entry := L.NewTable()
				entry.RawSetString("rrname", lua.LString(rr.Name))
				entry.RawSetString("rrtype", lua.LNumber(rr.Type))
				entry.RawSetString("rrdata", lua.LString(rr.Data))
				tb.Append(entry)
			}
			// Zone Transfers can reveal DNS wildcards
			if n := amassdns.RemoveAsteriskLabel(req.Name); len(n) < len(req.Name) {
				// Signal the wildcard discovery
				s.Output() <- &requests.DNSRequest{
					Name:   "www." + n,
					Domain: req.Domain,
				}
			} else {
				s.Output() <- req
			}
		}
	}
	L.Push(tb)
	L.Push(lua.LNil)
	return 2
}

// ZoneTransfer attempts a DNS zone transfer using the provided server.
// The returned slice contains all the records discovered from the zone transfer.
func ZoneTransfer(ctx context.Context, sub, domain, server string) ([]*requests.DNSRequest, error) {
	timeout := 15 * time.Second
	var results []*requests.DNSRequest

	// Set the maximum time allowed for making the connection
	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	addr := net.JoinHostPort(server, "53")
	conn, err := amassnet.DialContext(tctx, "tcp", addr)
	if err != nil {
		return results, fmt.Errorf("zone xfr error: Failed to obtain TCP connection to [%s]: %v", addr, err)
	}
	defer conn.Close()

	xfr := &dns.Transfer{
		Conn:        &dns.Conn{Conn: conn},
		ReadTimeout: timeout,
	}

	m := &dns.Msg{}
	m.SetAxfr(dns.Fqdn(sub))

	in, err := xfr.In(m, "")
	if err != nil {
		return results, fmt.Errorf("DNS zone transfer error for [%s]: %v", addr, err)
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
