// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package dnssrv

import (
	"math/rand"
	"strings"
	"sync"

	"github.com/OWASP/Amass/amass/core"
)

const (
	maxNameLen  = 253
	maxLabelLen = 63

	ldhChars = "abcdefghijklmnopqrstuvwxyz0123456789-"
)

type wildcard struct {
	HasWildcard bool
	Answers     []core.DNSAnswer
}

var (
	wildcardsLock sync.Mutex
	wildcards     map[string]*wildcard
)

func init() {
	wildcards = make(map[string]*wildcard)
}

// MatchesWildcard returns true if the request provided resolved to a DNS wildcard.
func MatchesWildcard(req *core.AmassRequest) bool {
	wildcardsLock.Lock()
	defer wildcardsLock.Unlock()

	base := len(strings.Split(req.Domain, "."))
	labels := strings.Split(req.Name, ".")

	var answer bool
	for i := len(labels) - base; i > 0; i-- {
		sub := strings.Join(labels[i:], ".")

		// See if detection has been performed for this subdomain
		w, found := wildcards[sub]
		if !found {
			entry := &wildcard{
				HasWildcard: false,
				Answers:     nil,
			}
			// Try three times for good luck
			for i := 0; i < 3; i++ {
				if a := wildcardTestResolution(sub); a != nil {
					entry.HasWildcard = true
					entry.Answers = append(entry.Answers, a...)
				}
			}
			w = entry
			wildcards[sub] = w
		}
		// Check if the subdomain and address in question match a wildcard
		if w.HasWildcard && compareAnswers(req.Records, w.Answers) {
			answer = true
		}
	}
	return answer
}

// HasWildcard checks subdomains for a DNS wildcard
func HasWildcard(domain, subdomain string) bool {
	base := len(strings.Split(domain, "."))
	labels := strings.Split(subdomain, ".")

	for i := len(labels) - base; i > 0; i-- {
		sub := strings.Join(labels[i:], ".")

		// Try three times for good luck
		for i := 0; i < 3; i++ {
			// Does this subdomain have a wildcard?
			if wildcardTestResolution(sub) != nil {
				return true
			}
		}
	}
	return false
}

func compareAnswers(ans1, ans2 []core.DNSAnswer) bool {
	var match bool
loop:
	for _, a1 := range ans1 {
		for _, a2 := range ans2 {
			if strings.EqualFold(a1.Data, a2.Data) {
				match = true
				break loop
			}
		}
	}
	return match
}

// wildcardDetection detects if a domain returns an IP
// address for "bad" names, and if so, which address(es) are used
func wildcardTestResolution(sub string) []core.DNSAnswer {
	var answers []core.DNSAnswer

	name := UnlikelyName(sub)
	if name == "" {
		return nil
	}
	// Check if the name resolves
	core.MaxConnections.Acquire(3)
	if a, err := Resolve(name, "CNAME"); err == nil {
		answers = append(answers, a...)
	}
	if a, err := Resolve(name, "A"); err == nil {
		answers = append(answers, a...)
	}
	if a, err := Resolve(name, "AAAA"); err == nil {
		answers = append(answers, a...)
	}
	core.MaxConnections.Release(3)

	if len(answers) == 0 {
		return nil
	}
	return answers
}

// UnlikelyName takes a subdomain name and returns an unlikely DNS name within that subdomain
func UnlikelyName(sub string) string {
	var newlabel string
	ldh := []rune(ldhChars)
	ldhLen := len(ldh)

	// Determine the max label length
	l := maxNameLen - (len(sub) + 1)
	if l >= maxLabelLen {
		l = maxLabelLen / 2
	} else if l < 1 {
		return ""
	}
	// Shuffle our LDH characters
	rand.Shuffle(ldhLen, func(i, j int) {
		ldh[i], ldh[j] = ldh[j], ldh[i]
	})

	l = (rand.Int() % l) + 1
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
