// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"math/rand"
	"strings"

	"github.com/caffix/amass/amass/stringset"
)

type wildcard struct {
	Req *AmassRequest
	Ans chan bool
}

type dnsWildcard struct {
	HasWildcard bool
	Answers     *stringset.StringSet
}

type Wildcards struct {
	// Requests are sent through this channel to check DNS wildcard matches
	Request chan *wildcard

	// The amass enumeration configuration
	Config *AmassConfig
}

func NewWildcardDetection(config *AmassConfig) *Wildcards {
	wd := &Wildcards{
		Request: make(chan *wildcard, 50),
		Config:  config,
	}

	go wd.processWildcardMatches()
	return wd
}

// DetectWildcard - Checks subdomains in the wildcard cache for matches on the IP address
func (wd *Wildcards) DetectWildcard(req *AmassRequest) bool {
	answer := make(chan bool, 2)

	wd.Request <- &wildcard{
		Req: req,
		Ans: answer,
	}
	return <-answer
}

// Goroutine that keeps track of DNS wildcards discovered
func (wd *Wildcards) processWildcardMatches() {
	wildcards := make(map[string]*dnsWildcard)

	for {
		select {
		case wr := <-wd.Request:
			wr.Ans <- wd.matchesWildcard(wr.Req, wildcards)
		}
	}
}

func (wd *Wildcards) matchesWildcard(req *AmassRequest, wildcards map[string]*dnsWildcard) bool {
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
				if ss := wd.wildcardDetection(sub); ss != nil {
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
func (wd *Wildcards) wildcardDetection(sub string) *stringset.StringSet {
	// An unlikely name will be checked for this subdomain
	name := unlikelyName(sub)
	if name == "" {
		return nil
	}
	// Check if the name resolves
	ans, err := wd.Config.dns.Query(name)
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

func answersToStringSet(answers []DNSAnswer) *stringset.StringSet {
	ss := stringset.NewStringSet()

	for _, a := range answers {
		ss.Add(a.Data)
	}
	return ss
}
