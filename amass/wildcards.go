// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"errors"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/miekg/dns"
)

const (
	numOfWildcardTests = 5

	maxDNSNameLen  = 253
	maxDNSLabelLen = 63
	minLabelLen    = 6
	maxLabelLen    = 24
	ldhChars       = "abcdefghijklmnopqrstuvwxyz0123456789-"
)

// Names for the different types of wildcards that can be detected.
const (
	WildcardTypeNone = iota
	WildcardTypeStatic
	WildcardTypeDynamic
)

var (
	wildcardLock sync.Mutex
	wildcards    map[string]*wildcard
)

type wildcard struct {
	sync.RWMutex
	WildcardType int
	Answers      []core.DNSAnswer
}

func init() {
	wildcards = make(map[string]*wildcard)
}

// MatchesWildcard returns true if the request provided resolved to a DNS wildcard.
func MatchesWildcard(req *core.Request) bool {
	if performWildcardRequest(req) == WildcardTypeNone {
		return false
	}
	return true
}

// GetWildcardType returns the DNS wildcard type for the provided subdomain name.
func GetWildcardType(req *core.Request) int {
	return performWildcardRequest(req)
}

func performWildcardRequest(req *core.Request) int {
	base := len(strings.Split(req.Domain, "."))
	labels := strings.Split(strings.ToLower(req.Name), ".")
	if len(labels) > base {
		labels = labels[1:]
	}

	for i := len(labels) - base; i >= 0; i-- {
		w := getWildcard(strings.Join(labels[i:], "."))

		if w.WildcardType == WildcardTypeDynamic {
			return WildcardTypeDynamic
		} else if w.WildcardType == WildcardTypeStatic {
			if len(req.Records) == 0 || compareAnswers(req.Records, w.Answers) {
				return WildcardTypeStatic
			}
		}
	}
	return WildcardTypeNone
}

func getWildcard(sub string) *wildcard {
	var test bool

	wildcardLock.Lock()
	entry, found := wildcards[sub]
	if !found {
		entry = &wildcard{
			WildcardType: WildcardTypeNone,
			Answers:      nil,
		}
		wildcards[sub] = entry
		test = true
		entry.Lock()
	}
	wildcardLock.Unlock()
	// Check if the subdomain name is still be tested for a wildcard
	if !test {
		entry.RLock()
		entry.RUnlock()
		return entry
	}
	// Query multiple times with unlikely names against this subdomain
	set := make([][]core.DNSAnswer, numOfWildcardTests)
	for i := 0; i < numOfWildcardTests; i++ {
		a, err := wildcardTest(sub)
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

func wildcardTest(sub string) ([]core.DNSAnswer, error) {
	name := UnlikelyName(sub)
	if name == "" {
		return nil, errors.New("Failed to generate the unlikely name for DNS wildcard testing")
	}

	var answers []core.DNSAnswer
	for _, t := range wildcardQueryTypes {
		if a, err := Resolve(name, t, PriorityCritical); err == nil {
			if a != nil && len(a) > 0 {
				answers = append(answers, a...)
			}
		} else if (err.(*resolveError)).Rcode == 100 ||
			(err.(*resolveError)).Rcode == dns.RcodeRefused ||
			(err.(*resolveError)).Rcode == dns.RcodeServerFailure ||
			(err.(*resolveError)).Rcode == dns.RcodeNotImplemented {
			return nil, errors.New("Failed to get a DNS server response during wildcard testing")
		}
	}
	if len(answers) == 0 {
		return nil, nil
	}
	return answers, nil
}

func compareAnswers(ans1, ans2 []core.DNSAnswer) bool {
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
	ldh := []rune(ldhChars)
	ldhLen := len(ldh)

	// Determine the max label length
	l := maxDNSNameLen - (len(sub) + 1)
	if l > maxLabelLen {
		l = maxLabelLen
	} else if l < minLabelLen {
		return ""
	}
	// Shuffle our LDH characters
	rand.Shuffle(ldhLen, func(i, j int) {
		ldh[i], ldh[j] = ldh[j], ldh[i]
	})

	l = minLabelLen + rand.Intn((l-minLabelLen)+1)
	for i := 0; i < l; i++ {
		sel := rand.Int() % ldhLen

		newlabel = newlabel + string(ldh[sel])
	}

	if newlabel == "" {
		return newlabel
	}
	return strings.Trim(newlabel, "-") + "." + sub
}
