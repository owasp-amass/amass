// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"strings"

	"github.com/caffix/amass/amass/stringset"
	"github.com/caffix/recon"
)

type wildcard struct {
	Sub *Subdomain
	Ans chan bool
}

type dnsWildcard struct {
	HasWildcard bool
	Answers     *stringset.StringSet
}

// Goroutine that keeps track of DNS wildcards discovered
func (a *Amass) processWildcardMatches() {
	wildcards := make(map[string]*dnsWildcard)
loop:
	for {
		select {
		case req := <-a.wildcardMatches:
			var answer bool

			labels := strings.Split(req.Sub.Name, ".")
			last := len(labels) - len(strings.Split(req.Sub.Domain, "."))
			// Iterate over all the subdomains looking for wildcards
			for i := 1; i <= last; i++ {
				sub := strings.Join(labels[i:], ".")

				w, ok := wildcards[sub]
				if !ok {
					w = a.checkDomainForWildcard(sub, req.Sub.Domain)
					wildcards[sub] = w
				}

				if w.HasWildcard && w.Answers.Contains(req.Sub.Address) {
					answer = true
					break
				}
			}
			req.Ans <- answer
		case <-a.quit:
			break loop
		}
	}
	a.done <- struct{}{}
}

func answersToStringSet(answers []recon.DNSAnswer) *stringset.StringSet {
	ss := stringset.NewStringSet()

	for _, a := range answers {
		ss.Add(a.Data)
	}
	return ss
}

// checkDomainForWildcard detects if a domain returns an IP
// address for "bad" names, and if so, which address is used
func (a *Amass) checkDomainForWildcard(sub, root string) *dnsWildcard {
	var ss1, ss2, ss3 *stringset.StringSet

	name1 := "81very92unlikely03name." + sub
	name2 := "45another34random99name." + sub
	name3 := "just555little333me." + sub
	server := "8.8.8.8:53"

	if a1, err := a.dnsQuery(root, name1, server); err == nil {
		ss1 = answersToStringSet(a1)
	}

	if a2, err := a.dnsQuery(root, name2, server); err == nil {
		ss2 = answersToStringSet(a2)
	}

	if a3, err := a.dnsQuery(root, name3, server); err == nil {
		ss3 = answersToStringSet(a3)
	}

	if ss1 != nil && ss2 != nil && ss3 != nil {
		if !ss1.Empty() && (ss1.Equal(ss2) && ss2.Equal(ss3)) {
			return &dnsWildcard{
				HasWildcard: true,
				Answers:     ss1,
			}
		}
	}
	return &dnsWildcard{
		HasWildcard: false,
		Answers:     nil,
	}
}

// matchesWildcard - Checks subdomains in the wildcard cache for matches on the IP address
func (a *Amass) matchesWildcard(subdomain *Subdomain) bool {
	answer := make(chan bool, 2)

	a.wildcardMatches <- &wildcard{
		Sub: subdomain,
		Ans: answer,
	}
	return <-answer
}
