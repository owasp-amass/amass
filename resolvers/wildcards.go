// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package resolvers

import (
	"context"
	"math/rand"
	"strings"
	"time"

	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/stringset"
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
	WildcardType int
	Answers      []requests.DNSAnswer
	beingTested  bool
}

// MatchesWildcard returns true if the request provided resolved to a DNS wildcard.
func (rp *ResolverPool) MatchesWildcard(ctx context.Context, req *requests.DNSRequest) bool {
	if rp.hasWildcard(ctx, req) == WildcardTypeNone {
		return false
	}
	return true
}

// GetWildcardType returns the DNS wildcard type for the provided subdomain name.
func (rp *ResolverPool) GetWildcardType(ctx context.Context, req *requests.DNSRequest) int {
	return rp.hasWildcard(ctx, req)
}

func (rp *ResolverPool) hasWildcard(ctx context.Context, req *requests.DNSRequest) int {
	req.Name = strings.ToLower(strings.Trim(req.Name, "."))
	req.Domain = strings.ToLower(strings.Trim(req.Domain, "."))

	base := len(strings.Split(req.Domain, "."))
	labels := strings.Split(req.Name, ".")
	if len(labels) > base {
		labels = labels[1:]
	}

	// Check for a DNS wildcard at each label starting with the root domain
	for i := len(labels) - base; i >= 0; i-- {
		w := rp.fetchWildcard(ctx, strings.Join(labels[i:], "."))

		if w.WildcardType == WildcardTypeDynamic {
			return WildcardTypeDynamic
		} else if w.WildcardType == WildcardTypeStatic {
			if len(req.Records) == 0 {
				return w.WildcardType
			}

			set := stringset.New()

			intersectRecordData(set, req.Records)
			intersectRecordData(set, w.Answers)
			if set.Len() > 0 {
				return w.WildcardType
			}
		}
	}

	return rp.checkIPsAcrossLevels(req)
}

func (rp *ResolverPool) fetchWildcard(ctx context.Context, sub string) *wildcard {
	curIdx := 0
	maxIdx := 7
	delays := []int{10, 25, 50, 75, 100, 150, 250, 500}

	// Check if the wildcard information has been cached
	if w := rp.getWildcard(sub); w == nil {
		rp.wildcardTest(ctx, sub)
	} else if !w.beingTested {
		return w
	}

	// Wait for the wildcard detection process to complete
	for {
		select {
		case <-rp.Done:
			return nil
		default:
			// Check if the wildcard information has been cached
			if w := rp.getWildcard(sub); w != nil && !w.beingTested {
				return w
			}

			time.Sleep(time.Duration(delays[curIdx]) * time.Millisecond)
			if curIdx < maxIdx {
				curIdx++
			}
		}
	}

	return nil
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

	l := len(labels) - base
	records := stringset.New()
	for i := 1; i <= l; i++ {
		w := rp.getWildcard(strings.Join(labels[i:], "."))
		if w.Answers == nil || len(w.Answers) == 0 {
			break
		}

		intersectRecordData(records, w.Answers)
	}

	if records.Len() > 0 {
		return WildcardTypeStatic
	}

	return WildcardTypeNone
}

var wildcardQueryTypes = []string{
	"CNAME",
	"A",
	"AAAA",
}

func (rp *ResolverPool) wildcardTest(ctx context.Context, sub string) {
	// Create the wildcard entry and mark it as being tested
	wasSet := rp.testAndSetWildcard(sub, &wildcard{
		WildcardType: WildcardTypeNone,
		Answers:      []requests.DNSAnswer{},
		beingTested:  true,
	})
	if !wasSet {
		return
	}

	var retRecords bool
	set := stringset.New()
	var answers []requests.DNSAnswer
	// Query multiple times with unlikely names against this subdomain
	for i := 0; i < numOfWildcardTests; i++ {
		// Generate the unlikely label / name
		name := UnlikelyName(sub)
		for name == "" {
			name = UnlikelyName(sub)
		}

		var ans []requests.DNSAnswer
		for _, t := range wildcardQueryTypes {
			if a, _, err := rp.Resolve(ctx, name, t, PriorityCritical); err == nil {
				if a != nil && len(a) > 0 {
					retRecords = true
					ans = append(ans, a...)
				}
			}
		}

		intersectRecordData(set, ans)
		answers = append(answers, ans...)
		time.Sleep(time.Second)
	}

	var final []requests.DNSAnswer
	// Create the slice of answers common across all the unlikely name queries
loop:
	for set.Len() > 0 {
		data := strings.Trim(set.Slice()[0], ".")

		for _, a := range answers {
			if set.Has(data) {
				set.Remove(data)
				final = append(final, a)
				continue loop
			}
		}
	}

	// Determine whether the subdomain has a DNS wildcard, and if so, which type is it?
	wildcardType := WildcardTypeNone
	if retRecords {
		wildcardType = WildcardTypeStatic

		if len(final) == 0 {
			wildcardType = WildcardTypeDynamic
		}
		rp.Log.Printf("DNS wildcard detected: %s", "*."+sub)
	}

	// Enter the final wildcard information
	rp.setWildcard(sub, &wildcard{
		WildcardType: wildcardType,
		Answers:      final,
		beingTested:  false,
	})
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

func (rp *ResolverPool) getWildcard(sub string) *wildcard {
	rp.wildcardLock.Lock()
	defer rp.wildcardLock.Unlock()

	if w, found := rp.wildcards[sub]; found {
		return w
	}
	return nil
}

func (rp *ResolverPool) setWildcard(sub string, w *wildcard) {
	rp.wildcardLock.Lock()
	defer rp.wildcardLock.Unlock()

	rp.wildcards[sub] = w
}

func (rp *ResolverPool) testAndSetWildcard(sub string, w *wildcard) bool {
	rp.wildcardLock.Lock()
	defer rp.wildcardLock.Unlock()

	if _, found := rp.wildcards[sub]; !found {
		rp.wildcards[sub] = w
		return true
	}
	return false
}

func intersectRecordData(set stringset.Set, ans []requests.DNSAnswer) {
	records := stringset.New()

	for _, a := range ans {
		records.Insert(strings.Trim(a.Data, "."))
	}

	set.Intersect(records)
}
