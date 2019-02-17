// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"strings"
	"sync"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/google/uuid"
)

const (
	numOfWildcardTests = 5

	maxDNSNameLen  = 253
	maxDNSLabelLen = 63
	maxLabelLen    = 24

	// The hyphen has been removed
	ldhChars = "abcdefghijklmnopqrstuvwxyz0123456789"
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
	labels := strings.Split(req.Name, ".")

	for i := len(labels) - base; i > 0; i-- {
		sub := strings.Join(labels[i:], ".")
		w := getWildcard(sub)

		if w.WildcardType == WildcardTypeDynamic {
			return WildcardTypeDynamic
		} else if w.WildcardType == WildcardTypeStatic {
			if len(req.Records) == 0 {
				return WildcardTypeStatic
			} else if compareAnswers(req.Records, w.Answers) {
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
		defer entry.Unlock()
	}
	wildcardLock.Unlock()
	// Check if the subdomain name is still be tested for a wildcard
	if !test {
		entry.RLock()
		defer entry.RUnlock()
		return entry
	}
	// Query multiple times with unlikely names against this subdomain
	set := make([][]core.DNSAnswer, numOfWildcardTests)
	for i := 0; i < numOfWildcardTests; i++ {
		a := wildcardTest(sub)
		if a == nil {
			// There is no DNS wildcard
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
	return entry
}

func wildcardTest(sub string) []core.DNSAnswer {
	var answers []core.DNSAnswer

	name := UnlikelyName(sub)
	if name == "" {
		return nil
	}
	// Check if the name resolves
	if a, err := Resolve(name, "CNAME"); err == nil {
		answers = append(answers, a...)
	}
	if a, err := Resolve(name, "A"); err == nil {
		answers = append(answers, a...)
	}
	if a, err := Resolve(name, "AAAA"); err == nil {
		answers = append(answers, a...)
	}
	if len(answers) == 0 {
		return nil
	}
	return answers
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

// UnlikelyName takes a subdomain name and returns an unlikely DNS name within that subdomain
func UnlikelyName(sub string) string {
	newlabel := uuid.New().String()

	return newlabel + "." + sub
}
