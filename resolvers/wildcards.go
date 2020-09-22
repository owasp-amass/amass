// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package resolvers

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/queue"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/stringset"
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

const numOfWildcardTests = 3

// Names for the different types of wildcards that can be detected.
const (
	WildcardTypeNone = iota
	WildcardTypeStatic
	WildcardTypeDynamic
)

var wildcardQueryTypes = []string{
	"CNAME",
	"A",
	"AAAA",
}

type wildcard struct {
	WildcardType int
	Answers      []requests.DNSAnswer
	beingTested  bool
}

type wildcardChans struct {
	WildcardReq     *queue.Queue
	IPsAcrossLevels chan *ipsAcrossLevels
	TestResult      chan *testResult
}

type wildcardReq struct {
	Ctx context.Context
	Sub string
	Ch  chan *wildcard
}

type ipsAcrossLevels struct {
	Req *requests.DNSRequest
	Ch  chan int
}

type testResult struct {
	Sub    string
	Result *wildcard
}

// MatchesWildcard returns true if the request provided resolved to a DNS wildcard.
func (r *BaseResolver) MatchesWildcard(ctx context.Context, req *requests.DNSRequest) bool {
	return r.hasWildcard(ctx, req) != WildcardTypeNone
}

// GetWildcardType returns the DNS wildcard type for the provided subdomain name.
func (r *BaseResolver) GetWildcardType(ctx context.Context, req *requests.DNSRequest) int {
	return r.hasWildcard(ctx, req)
}

func (r *BaseResolver) hasWildcard(ctx context.Context, req *requests.DNSRequest) int {
	req.Name = strings.ToLower(strings.Trim(req.Name, "."))
	req.Domain = strings.ToLower(strings.Trim(req.Domain, "."))

	base := len(strings.Split(req.Domain, "."))
	labels := strings.Split(req.Name, ".")
	if len(labels) > base {
		labels = labels[1:]
	}

	// Check for a DNS wildcard at each label starting with the root domain
	for i := len(labels) - base; i >= 0; i-- {
		w := r.fetchWildcardType(ctx, strings.Join(labels[i:], "."))

		if w.WildcardType == WildcardTypeDynamic {
			return WildcardTypeDynamic
		} else if w.WildcardType == WildcardTypeStatic {
			if len(req.Records) == 0 {
				return w.WildcardType
			}

			set := stringset.New()
			insertRecordData(set, req.Records)
			intersectRecordData(set, w.Answers)
			if set.Len() > 0 {
				return w.WildcardType
			}
		}
	}

	return r.checkIPsAcrossLevels(req)
}

func (r *BaseResolver) fetchWildcardType(ctx context.Context, sub string) *wildcard {
	ch := make(chan *wildcard, 2)

	r.wildcardChannels.WildcardReq.Append(&wildcardReq{
		Ctx: ctx,
		Sub: sub,
		Ch:  ch,
	})

	return <-ch
}

func (r *BaseResolver) checkIPsAcrossLevels(req *requests.DNSRequest) int {
	ch := make(chan int, 2)

	r.wildcardChannels.IPsAcrossLevels <- &ipsAcrossLevels{
		Req: req,
		Ch:  ch,
	}

	return <-ch
}

func (r *BaseResolver) manageWildcards(chs *wildcardChans) {
	wildcards := make(map[string]*wildcard)

	for {
		select {
		case <-r.Done:
			return
		case <-chs.WildcardReq.Signal:
			if e, found := chs.WildcardReq.Next(); found {
				req := e.(*wildcardReq)

				r.wildcardRequest(wildcards, req)
				chs.WildcardReq.SendSignal()
			}
		case test := <-chs.TestResult:
			wildcards[test.Sub] = test.Result
		case ips := <-chs.IPsAcrossLevels:
			r.testIPsAcrossLevels(wildcards, ips)
		}
	}
}

func (r *BaseResolver) wildcardRequest(wildcards map[string]*wildcard, req *wildcardReq) {
	// Check if the wildcard information has been cached
	if w, found := wildcards[req.Sub]; found && !w.beingTested {
		req.Ch <- w
		return
	} else if found && w.beingTested {
		// Wait for the test to complete
		go r.delayAppend(req)
		return
	}

	// Start the DNS wildcard test for this subdomain
	wildcards[req.Sub] = &wildcard{
		WildcardType: WildcardTypeNone,
		Answers:      []requests.DNSAnswer{},
		beingTested:  true,
	}
	go r.wildcardTest(req.Ctx, req.Sub)
	go r.delayAppend(req)
}

func (r *BaseResolver) delayAppend(req *wildcardReq) {
	time.Sleep(time.Second)
	r.wildcardChannels.WildcardReq.Append(req)
}

func (r *BaseResolver) testIPsAcrossLevels(wildcards map[string]*wildcard, req *ipsAcrossLevels) {
	if len(req.Req.Records) == 0 {
		req.Ch <- WildcardTypeNone
		return
	}

	base := len(strings.Split(req.Req.Domain, "."))
	labels := strings.Split(strings.ToLower(req.Req.Name), ".")
	if len(labels) <= base || (len(labels)-base) < 3 {
		req.Ch <- WildcardTypeNone
		return
	}

	l := len(labels) - base
	records := stringset.New()
	for i := 1; i <= l; i++ {
		w, found := wildcards[strings.Join(labels[i:], ".")]
		if !found || w.Answers == nil || len(w.Answers) == 0 {
			break
		}

		if i == 1 {
			insertRecordData(records, w.Answers)
		} else {
			intersectRecordData(records, w.Answers)
		}
	}

	result := WildcardTypeNone
	if records.Len() > 0 {
		result = WildcardTypeStatic
	}

	req.Ch <- result
}

func (r *BaseResolver) wildcardTest(ctx context.Context, sub string) {
	var retRecords bool
	set := stringset.New()
	var answers []requests.DNSAnswer

	// Query multiple times with unlikely names against this subdomain
	for i := 0; i < numOfWildcardTests; i++ {
		var name string

		// Generate the unlikely label / name
		for j := 0; j < 10; j++ {
			name = UnlikelyName(sub)
			if name != "" {
				break
			}
		}

		var ans []requests.DNSAnswer
		for _, t := range wildcardQueryTypes {
			if a, err := r.Resolve(ctx, name, t, PriorityCritical, func(times int, priority int, msg *dns.Msg) bool {
				return times < 3
			}); err == nil {
				if len(a) > 0 {
					retRecords = true
					ans = append(ans, a...)
				}
			}
		}

		if i == 0 {
			insertRecordData(set, ans)
		} else {
			intersectRecordData(set, ans)
		}
		answers = append(answers, ans...)
	}

	already := stringset.New()
	var final []requests.DNSAnswer
	// Create the slice of answers common across all the unlikely name queries
	for _, a := range answers {
		a.Data = strings.Trim(a.Data, ".")

		if set.Has(a.Data) && !already.Has(a.Data) {
			final = append(final, a)
			already.Insert(a.Data)
		}
	}

	// Determine whether the subdomain has a DNS wildcard, and if so, which type is it?
	wildcardType := WildcardTypeNone
	if retRecords {
		wildcardType = WildcardTypeStatic

		if len(final) == 0 {
			wildcardType = WildcardTypeDynamic
		}

		var bus *eventbus.EventBus
		if b := ctx.Value(requests.ContextEventBus); b != nil {
			bus = b.(*eventbus.EventBus)
		}

		if bus != nil {
			bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
				fmt.Sprintf("DNS wildcard detected: Resolver %s: %s: type: %d", r.String(), "*."+sub, wildcardType))
		}
	}

	r.wildcardChannels.TestResult <- &testResult{
		Sub: sub,
		Result: &wildcard{
			WildcardType: wildcardType,
			Answers:      final,
			beingTested:  false,
		},
	}
}

// UnlikelyName takes a subdomain name and returns an unlikely DNS name within that subdomain.
func UnlikelyName(sub string) string {
	ldh := []rune(LDHChars)
	ldhLen := len(ldh)

	// Determine the max label length
	l := MaxDNSNameLen - (len(sub) + 1)
	if l > MaxLabelLen {
		l = MaxLabelLen
	} else if l < MinLabelLen {
		l = MinLabelLen
	}
	// Shuffle our LDH characters
	rand.Shuffle(ldhLen, func(i, j int) {
		ldh[i], ldh[j] = ldh[j], ldh[i]
	})

	var newlabel string
	l = MinLabelLen + rand.Intn((l-MinLabelLen)+1)
	for i := 0; i < l; i++ {
		sel := rand.Int() % (ldhLen - 1)

		newlabel = newlabel + string(ldh[sel])
	}

	newlabel = strings.Trim(newlabel, "-")
	if newlabel == "" {
		return newlabel
	}
	return newlabel + "." + sub
}

func intersectRecordData(set stringset.Set, ans []requests.DNSAnswer) {
	records := stringset.New()

	for _, a := range ans {
		records.Insert(strings.Trim(a.Data, "."))
	}

	set.Intersect(records)
}

func insertRecordData(set stringset.Set, ans []requests.DNSAnswer) {
	records := stringset.New()

	for _, a := range ans {
		records.Insert(strings.Trim(a.Data, "."))
	}

	set.Union(records)
}
