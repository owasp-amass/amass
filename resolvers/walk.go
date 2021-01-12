// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package resolvers

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	amassdns "github.com/OWASP/Amass/v3/net/dns"
	"github.com/miekg/dns"
)

// NsecTraversal attempts to retrieve a DNS zone using NSEC-walking.
func NsecTraversal(ctx context.Context, r Resolver, domain string, priority int) ([]string, bool, error) {
	if priority != PriorityCritical && priority != PriorityHigh && priority != PriorityLow {
		return []string{}, false, &ResolveError{
			Err:   fmt.Sprintf("Resolver: Invalid priority parameter: %d", priority),
			Rcode: ResolverErrRcode,
		}
	}

	if r.Stopped() {
		return []string{}, true, errors.New("Resolver: The resolver has been stopped")
	}

	var err error
	var results []string
	for next := "0"; next != ""; {
		query := next

		for _, qtype := range []uint16{dns.TypeNSEC, dns.TypeA} {
			var found string

			found, next, err = searchGap(ctx, r, query, domain+".", qtype, priority)
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

func searchGap(ctx context.Context, r Resolver, name, domain string, qtype uint16, priority int) (string, string, error) {
	re := amassdns.SubdomainRegex(domain)

	for _, attempt := range walkAttempts(name, domain, qtype) {
		msg := walkMsgRequest(ctx, r, attempt+"."+domain, qtype, priority)
		if msg == nil {
			continue
		}

		for _, rr := range msg.Answer {
			if prev, next := checkRecord(rr, attempt, name, domain, re); prev != "" || next != "" {
				return prev, next, nil
			}
		}
		for _, rr := range msg.Ns {
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

func walkMsgRequest(ctx context.Context, r Resolver, name string, qt uint16, priority int) *dns.Msg {
	for i := 0; i < 100; i++ {
		resp, err := r.Query(ctx, WalkMsg(name, qt), priority, RetryPolicy)
		if err == nil && resp != nil {
			return resp
		}
	}
	return nil
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
