// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package resolvers

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/OWASP/Amass/v3/eventbus"
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

		results = append(results, reqs...)
	}
	return results, nil
}

// NsecTraversal attempts to retrieve a DNS zone using NSEC-walking.
func (r *BaseResolver) NsecTraversal(ctx context.Context, domain string, priority int) ([]string, bool, error) {
	if priority != PriorityCritical && priority != PriorityHigh && priority != PriorityLow {
		return []string{}, false, &ResolveError{
			Err:   fmt.Sprintf("Resolver: Invalid priority parameter: %d", priority),
			Rcode: ResolverErrRcode,
		}
	}

	if avail, err := r.Available(); !avail {
		return []string{}, true, err
	}

	var err error
	var results []string
	for next := "0"; next != ""; {
		query := next

		for _, qtype := range []uint16{dns.TypeNSEC, dns.TypeA} {
			var found string

			found, next, err = r.searchGap(ctx, query, domain+".", qtype, priority)
			if err != nil {
				continue
			}

			if found != "" {
				results = append(results, found+"."+domain)
			}

			if next == "" {
				break
			}
		}
	}

	return results, false, nil
}

func (r *BaseResolver) searchGap(ctx context.Context, name, domain string, qtype uint16, priority int) (string, string, error) {
	re := amassdns.SubdomainRegex(domain)

	for _, attempt := range walkAttempts(name, domain, qtype) {
		result := r.walkMsgRequest(ctx, attempt+"."+domain, qtype, priority)
		if result.Msg == nil {
			continue
		}

		for _, rr := range result.Msg.Answer {
			if prev, next := checkRecord(rr, attempt, name, domain, re); prev != "" || next != "" {
				return prev, next, nil
			}
		}
		for _, rr := range result.Msg.Ns {
			if prev, next := checkRecord(rr, attempt, name, domain, re); prev != "" || next != "" {
				return prev, next, nil
			}
		}
	}

	return "", "", fmt.Errorf("NsecTraversal: Resolver %s: NSEC record not found", r.String())
}

func checkRecord(rr dns.RR, attempt, name, domain string, re *regexp.Regexp) (string, string) {
	n := domain
	if name != "0" {
		n = name + "." + domain
	}

	rName := strings.ToLower(strings.TrimSpace(rr.Header().Name))
	if rr.Header().Rrtype != dns.TypeNSEC || rName != n {
		return "", ""
	}

	return parseNsecRecord(rr, attempt, domain, re)
}

func parseNsecRecord(rr dns.RR, attempt, domain string, re *regexp.Regexp) (string, string) {
	prev := strings.ToLower(strings.TrimSpace(rr.Header().Name))
	next := strings.ToLower(strings.TrimSpace(rr.(*dns.NSEC).NextDomain))
	if (prev != domain && !re.MatchString(prev)) || !re.MatchString(next) {
		return "", ""
	}

	prev = removeDomainPortion(prev, domain)
	next = removeDomainPortion(next, domain)
	if firstIsLess(prev, attempt) && (firstIsLess(attempt, next) || next == "") {
		return prev, next
	}

	return "", ""
}

func firstIsLess(prev, next string) bool {
	prevParts := strings.Split(prev, ".")
	nextParts := strings.Split(next, ".")
	plen := len(prevParts)
	nlen := len(nextParts)

	for p, n := plen-1, nlen-1; p >= 0 && n >= 0; {
		if prevParts[p] <= nextParts[n] {
			return true
		}
		p--
		n--
	}

	return false
}

func (r *BaseResolver) walkMsgRequest(ctx context.Context, name string, qt uint16, priority int) *resolveResult {
	var bus *eventbus.EventBus

	// Obtain the event bus reference and report the resolver activity
	if b := ctx.Value(requests.ContextEventBus); b != nil {
		bus = b.(*eventbus.EventBus)
	}

	var result *resolveResult
	for i := 0; i < 100; i++ {
		if bus != nil {
			bus.Publish(requests.SetActiveTopic, eventbus.PriorityCritical, "Resolver "+r.String())
		}

		result = r.queueQuery(walkMsg(r.getID(), name, qt), name, qt, priority)
		// Report the completion of the DNS query
		if bus != nil {
			rcode := dns.RcodeSuccess
			if result.Err != nil {
				rcode = (result.Err.(*ResolveError)).Rcode
			}

			bus.Publish(requests.ResolveCompleted, eventbus.PriorityCritical, time.Now(), rcode)
		}
		if result.Msg != nil {
			break
		}
	}

	return result
}

func walkAttempts(name, domain string, qtype uint16) []string {
	nn := checkLength(strings.ToLower(name), strings.ToLower(domain))
	if qtype == dns.TypeNSEC {
		return []string{nn}
	}

	// The last character of the hostname portion duplicated/appended
	parts := strings.Split(nn, ".")
	plen := len(parts)
	rhost := []rune(parts[plen-1])
	last := string(rhost[len(rhost)-1])
	parts[plen-1] = parts[plen-1] + last

	return []string{"0." + nn, strings.Join(parts, "."), nn + "0", nn + "-"}
}

func checkLength(name, domain string) string {
	parts := strings.Split(name, ".")
	nlen := len(name + "." + domain)

	if nlen > MaxDNSNameLen && len(parts) >= 2 {
		parts = parts[1:]
	}

	var newparts []string
	// Check each label for size
	for _, label := range parts {
		newlabel := label
		llen := len(label)

		if llen > MaxDNSLabelLen {
			lrunes := []rune(label)
			last := lrunes[len(lrunes)-1]

			if last == '-' {
				newlabel = string(lrunes[:MaxDNSLabelLen]) + "0"
			} else if last == '9' {
				newlabel = string(lrunes[:MaxDNSLabelLen]) + "a"
			} else {
				newlabel = string(lrunes[:MaxDNSLabelLen]) + "z"
			}
		}

		newparts = append(newparts, newlabel)
	}

	return strings.Join(newparts, ".")
}

func removeDomainPortion(name, domain string) string {
	if name == domain {
		return ""
	}

	dp := strings.Split(domain, ".")
	dp = dp[:len(dp)-1]
	dlen := len(dp)

	np := strings.Split(name, ".")
	np = np[:len(np)-1]
	plen := len(np)

	if plen <= dlen {
		return ""
	}

	return strings.Join(np[:plen-dlen], ".")
}

func walkMsg(id uint16, name string, qtype uint16) *dns.Msg {
	m := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			RecursionDesired: true,
			Id:               id,
			Opcode:           dns.OpcodeQuery,
			Rcode:            dns.RcodeSuccess,
		},
		Question: make([]dns.Question, 1),
	}
	m.Question[0] = dns.Question{
		Name:   dns.Fqdn(name),
		Qtype:  qtype,
		Qclass: uint16(dns.ClassINET),
	}
	m.SetEdns0(dns.DefaultMsgSize, true)
	return m
}
