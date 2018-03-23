// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"math/rand"
	"strings"

	"github.com/caffix/amass/amass/stringset"
	"github.com/caffix/recon"
)

type wildcard struct {
	Req *AmassRequest
	Ans chan bool
}

type dnsWildcard struct {
	HasWildcard bool
	Answers     *stringset.StringSet
}

// Requests are sent through this channel to check DNS wildcard matches
var wildcardRequest chan *wildcard

func init() {
	wildcardRequest = make(chan *wildcard, 50)
	go processWildcardMatches()
}

// DNSWildcardMatch - Checks subdomains in the wildcard cache for matches on the IP address
func DetectDNSWildcard(req *AmassRequest) bool {
	answer := make(chan bool, 2)

	wildcardRequest <- &wildcard{
		Req: req,
		Ans: answer,
	}
	return <-answer
}

// Goroutine that keeps track of DNS wildcards discovered
func processWildcardMatches() {
	wildcards := make(map[string]*dnsWildcard)

	for {
		select {
		case wr := <-wildcardRequest:
			wr.Ans <- matchesWildcard(wr.Req, wildcards)
		}
	}
}

func matchesWildcard(req *AmassRequest, wildcards map[string]*dnsWildcard) bool {
	var answer bool

	name := req.Name
	root := req.Domain
	ip := req.Address

	base := len(strings.Split(root, "."))
	// Obtain all parts of the subdomain name
	labels := strings.Split(name, ".")

	for i := len(labels) - base; i > 0; i-- {
		sub := strings.Join(labels[i:], ".")

		// See if detection has been performed for this subdomain
		w, found := wildcards[sub]
		if !found {
			entry := &dnsWildcard{
				HasWildcard: false,
				Answers:     nil,
			}
			// Try three times for good luck
			for i := 0; i < 3; i++ {
				// Does this subdomain have a wildcard?
				if ss := wildcardDetection(sub); ss != nil {
					entry.HasWildcard = true
					entry.Answers = ss
					break
				}
			}
			w = entry
			wildcards[sub] = w
		}
		// Check if the subdomain and address in question match a wildcard
		if w.HasWildcard && w.Answers.Contains(ip) {
			answer = true
		}
	}
	return answer
}

// wildcardDetection detects if a domain returns an IP
// address for "bad" names, and if so, which address(es) are used
func wildcardDetection(sub string) *stringset.StringSet {
	// An unlikely name will be checked for this subdomain
	name := unlikelyName(sub)
	if name == "" {
		return nil
	}
	// Check if the name resolves
	ans, err := DNS.Query(name, Resolvers.NextNameserver())
	if err != nil {
		return nil
	}
	result := answersToStringSet(ans)
	if result.Empty() {
		return nil
	}
	return result
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
