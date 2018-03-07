// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"math/rand"
	"strings"

	"github.com/caffix/amass/amass/stringset"
	"github.com/caffix/recon"
)

const (
	maxNameLen  = 253
	maxLabelLen = 63

	ldhChars = "abcdefghijklmnopqrstuvwxyz0123456789-"
)

type wildcard struct {
	Sub *Subdomain
	Ans chan bool
}

type dnsWildcard struct {
	HasWildcard bool
	Answers     *stringset.StringSet
}

// DNSWildcardMatch - Checks subdomains in the wildcard cache for matches on the IP address
func (a *Amass) DNSWildcardMatch(subdomain *Subdomain) bool {
	answer := make(chan bool, 2)

	a.wildcardMatches <- &wildcard{
		Sub: subdomain,
		Ans: answer,
	}
	return <-answer
}

// Goroutine that keeps track of DNS wildcards discovered
func (a *Amass) processWildcardMatches() {
	wildcards := make(map[string]*dnsWildcard)
loop:
	for {
		select {
		case req := <-a.wildcardMatches:
			var answer bool

			// Obtain the subdomain from the name
			labels := strings.Split(req.Sub.Name, ".")
			sub := strings.Join(labels[1:], ".")
			// See if detection has been performed for this subdomain
			w, found := wildcards[sub]
			if !found {
				entry := &dnsWildcard{
					HasWildcard: false,
					Answers:     nil,
				}

				if ss := a.wildcardDetection(sub, req.Sub.Domain); ss != nil {
					entry.HasWildcard = true
					entry.Answers = ss
				}

				w = entry
				wildcards[sub] = w
			}
			// Check if the subdomain and address in question match a wildcard
			if w.HasWildcard && w.Answers.Contains(req.Sub.Address) {
				answer = true
			}
			req.Ans <- answer
		case <-a.quit:
			break loop
		}
	}
	a.done <- struct{}{}
}

// wildcardDetection detects if a domain returns an IP
// address for "bad" names, and if so, which address is used
func (a *Amass) wildcardDetection(sub, root string) *stringset.StringSet {
	var result *stringset.StringSet

	//server := a.NextNameserver()
	// Only the most reliable server will be good enough
	server := "8.8.8.8:53"

	// Three unlikely names will be checked for this subdomain
	ss1 := a.checkForWildcard(sub, root, server)
	if ss1 == nil {
		return result
	}
	ss2 := a.checkForWildcard(sub, root, server)
	if ss2 == nil {
		return result
	}
	ss3 := a.checkForWildcard(sub, root, server)
	if ss3 == nil {
		return result
	}
	// If they all provide the same records, we have a wildcard
	if !ss1.Empty() && (ss1.Equal(ss2) && ss2.Equal(ss3)) {
		result = ss1
	}
	return result
}

func (a *Amass) checkForWildcard(sub, root, server string) *stringset.StringSet {
	var ss *stringset.StringSet

	name := unlikelyName(sub)
	if name != "" {
		if ans, err := a.dnsQuery(root, name, server); err == nil {
			ss = answersToStringSet(ans)
		}
	}
	return ss
}

func unlikelyName(sub string) string {
	var newlabel string
	ldh := []byte(ldhChars)
	ldhLen := len(ldh)

	// Determine the max label length
	l := maxNameLen - len(sub)
	if l > maxLabelLen {
		l = maxLabelLen / 2
	} else if l < 1 {
		return ""
	}
	// Shuffle our LDH characters
	rand.Shuffle(ldhLen, func(i, j int) {
		ldh[i], ldh[j] = ldh[j], ldh[i]
	})

	for i := 0; i < l; i++ {
		sel := rand.Int() % ldhLen

		// The first nor last char may be a hyphen
		if (i == 0 || i == l-1) && ldh[sel] == '-' {
			continue
		}
		newlabel = newlabel + string(ldh[sel])
	}

	if newlabel == "" {
		return newlabel
	}
	return newlabel + "." + sub
}

func answersToStringSet(answers []recon.DNSAnswer) *stringset.StringSet {
	ss := stringset.NewStringSet()

	for _, a := range answers {
		ss.Add(a.Data)
	}
	return ss
}
