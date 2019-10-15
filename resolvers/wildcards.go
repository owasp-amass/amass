// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package resolvers

import (
	"context"
	"errors"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/OWASP/Amass/requests"
	"github.com/miekg/dns"
)

// Constants related to DNS labels.
const (
	MaxDNSNameLen  = 253
	MaxDNSLabelLen = 63
	MinLabelLen    = 6
	MaxLabelLen    = 24
	LDHChars       = "abcdefghijklmnopqrstuvwxyz0123456789-"
)

const numOfWildcardTests = 5

// Names for the different types of wildcards that can be detected.
const (
	WildcardTypeNone = iota
	WildcardTypeStatic
	WildcardTypeDynamic
)

type wildcard struct {
	sync.RWMutex
	WildcardType int
	Answers      []requests.DNSAnswer
}

// MatchesWildcard returns true if the request provided resolved to a DNS wildcard.
func (rp *ResolverPool) MatchesWildcard(req *requests.DNSRequest) bool {
	if rp.performWildcardRequest(req) == WildcardTypeNone {
		return false
	}
	return true
}

// GetWildcardType returns the DNS wildcard type for the provided subdomain name.
func (rp *ResolverPool) GetWildcardType(req *requests.DNSRequest) int {
	return rp.performWildcardRequest(req)
}

func (rp *ResolverPool) performWildcardRequest(req *requests.DNSRequest) int {
	base := len(strings.Split(req.Domain, "."))
	labels := strings.Split(strings.ToLower(req.Name), ".")
	if len(labels) > base {
		labels = labels[1:]
	}

	for i := len(labels) - base; i >= 0; i-- {
		w := rp.getWildcard(strings.Join(labels[i:], "."))

		if w.WildcardType == WildcardTypeDynamic {
			return WildcardTypeDynamic
		} else if w.WildcardType == WildcardTypeStatic {
			if len(req.Records) == 0 || compareAnswers(req.Records, w.Answers) {
				return WildcardTypeStatic
			}
		}
	}
	return rp.checkIPsAcrossLevels(req)
}

func (rp *ResolverPool) checkIPsAcrossLevels(req *requests.DNSRequest) int {
	if len(req.Records) == 0 {
		return WildcardTypeNone
	}

	base := len(strings.Split(req.Domain, "."))
	labels := strings.Split(strings.ToLower(req.Name), ".")
	if len(labels) <= base || (len(labels)-base) < 3 {
		return WildcardTypeNone
	}

	w1 := rp.getWildcard(strings.Join(labels[1:], "."))
	if w1.Answers != nil && compareAnswers(req.Records, w1.Answers) {
		w2 := rp.getWildcard(strings.Join(labels[2:], "."))

		if w2.Answers != nil && compareAnswers(req.Records, w2.Answers) {
			w3 := rp.getWildcard(strings.Join(labels[3:], "."))

			if w3.Answers != nil && compareAnswers(req.Records, w3.Answers) {
				return WildcardTypeStatic
			}
		}
	}
	return WildcardTypeNone
}

func (rp *ResolverPool) getWildcard(sub string) *wildcard {
	var test bool

	rp.wildcardLock.Lock()
	entry, found := rp.wildcards[sub]
	if !found {
		entry = &wildcard{
			WildcardType: WildcardTypeNone,
			Answers:      nil,
		}
		rp.wildcards[sub] = entry
		test = true
		entry.Lock()
	}
	rp.wildcardLock.Unlock()
	// Check if the subdomain name is still to be tested for a wildcard
	if !test {
		entry.RLock()
		entry.RUnlock()
		return entry
	}
	// Query multiple times with unlikely names against this subdomain
	set := make([][]requests.DNSAnswer, numOfWildcardTests)
	for i := 0; i < numOfWildcardTests; i++ {
		a, err := rp.wildcardTest(sub)
		if err != nil {
			// A test error gives it the most severe wildcard type
			entry.WildcardType = WildcardTypeDynamic
			entry.Unlock()
			return entry
		} else if a == nil {
			// There is no DNS wildcard
			entry.Unlock()
			return entry
		}
		set[i] = a
		time.Sleep(time.Second)
	}
	// Check if we have a static or dynamic DNS wildcard
	match := true
	for i := 0; i < numOfWildcardTests-1; i++ {
		if !compareAnswers(set[i], set[i+1]) {
			match = false
			break
		}
	}
	if match {
		entry.WildcardType = WildcardTypeStatic
		entry.Answers = set[0]
	} else {
		entry.WildcardType = WildcardTypeDynamic
	}
	entry.Unlock()
	return entry
}

var wildcardQueryTypes = []string{
	"CNAME",
	"A",
	"AAAA",
}

func (rp *ResolverPool) wildcardTest(sub string) ([]requests.DNSAnswer, error) {
	name := UnlikelyName(sub)
	if name == "" {
		return nil, errors.New("Failed to generate the unlikely name for DNS wildcard testing")
	}

	var answers []requests.DNSAnswer
	for _, t := range wildcardQueryTypes {
		if a, _, err := rp.Resolve(context.TODO(), name, t, PriorityCritical); err == nil {
			if a != nil && len(a) > 0 {
				answers = append(answers, a...)
			}
		} else if (err.(*ResolveError)).Rcode == 100 ||
			(err.(*ResolveError)).Rcode == dns.RcodeRefused ||
			(err.(*ResolveError)).Rcode == dns.RcodeServerFailure ||
			(err.(*ResolveError)).Rcode == dns.RcodeNotImplemented {
			return nil, errors.New("Failed to get a DNS server response during wildcard testing")
		}
	}
	if len(answers) == 0 {
		return nil, nil
	}
	return answers, nil
}

func compareAnswers(ans1, ans2 []requests.DNSAnswer) bool {
	for _, a1 := range ans1 {
		for _, a2 := range ans2 {
			if strings.EqualFold(a1.Data, a2.Data) {
				return true
			}
		}
	}
	return false
}

// UnlikelyName takes a subdomain name and returns an unlikely DNS name within that subdomain.
func UnlikelyName(sub string) string {
	var newlabel string
	ldh := []rune(LDHChars)
	ldhLen := len(ldh)

	// Determine the max label length
	l := MaxDNSNameLen - (len(sub) + 1)
	if l > MaxLabelLen {
		l = MaxLabelLen
	} else if l < MinLabelLen {
		return ""
	}
	// Shuffle our LDH characters
	rand.Shuffle(ldhLen, func(i, j int) {
		ldh[i], ldh[j] = ldh[j], ldh[i]
	})

	l = MinLabelLen + rand.Intn((l-MinLabelLen)+1)
	for i := 0; i < l; i++ {
		sel := rand.Int() % ldhLen

		newlabel = newlabel + string(ldh[sel])
	}

	if newlabel == "" {
		return newlabel
	}
	return strings.Trim(newlabel, "-") + "." + sub
}
