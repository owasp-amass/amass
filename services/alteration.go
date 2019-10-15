// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"github.com/OWASP/Amass/config"
	"github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/resolvers"
)

// Cache maintains counters for word usage within alteration techniques.
type Cache struct {
	sync.RWMutex
	Counters map[string]int
}

// NewCache returns an initialized Cache.
func NewCache(seed []string) *Cache {
	c := &Cache{Counters: make(map[string]int)}

	c.Lock()
	defer c.Unlock()

	for _, word := range seed {
		c.Counters[word] = 0
	}

	return c
}

// Update increments the count for the provided word.
func (c *Cache) Update(word string) int {
	c.Lock()
	defer c.Unlock()

	if _, ok := c.Counters[word]; ok {
		c.Counters[word]++
	} else {
		c.Counters[word] = 1
	}

	return c.Counters[word]
}

// State maintains the word prefix and suffix counters.
type State struct {
	Prefixes *Cache
	Suffixes *Cache
}

// NewState returns an initialized State.
func NewState(wordlist []string) *State {
	return &State{
		Prefixes: NewCache(wordlist),
		Suffixes: NewCache(wordlist),
	}
}

// AlterationService is the Service that handles most DNS name permutations within the architecture.
type AlterationService struct {
	BaseService

	SourceType string
}

// NewAlterationService returns he object initialized, but not yet started.
func NewAlterationService(sys System) *AlterationService {
	as := &AlterationService{SourceType: requests.ALT}

	as.BaseService = *NewBaseService(as, "Alterations", sys)
	return as
}

// Type implements the Service interface.
func (as *AlterationService) Type() string {
	return as.SourceType
}

// OnDNSRequest implements the Service interface.
func (as *AlterationService) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	bus.Publish(requests.SetActiveTopic, as.String())

	if !cfg.IsDomainInScope(req.Name) ||
		(len(strings.Split(req.Domain, ".")) == len(strings.Split(req.Name, "."))) {
		return
	}

	if cfg.FlipNumbers {
		as.flipNumbersInName(ctx, req)
	}
	if cfg.AddNumbers {
		as.appendNumbers(ctx, req)
	}
	if cfg.FlipWords {
		as.flipWords(ctx, req)
	}
	if cfg.AddWords {
		as.addSuffixWord(ctx, req)
		as.addPrefixWord(ctx, req)
	}
	if cfg.EditDistance > 0 {
		as.fuzzyLabelSearches(ctx, req)
	}
}

func (as *AlterationService) flipWords(ctx context.Context, req *requests.DNSRequest) {
	names := strings.SplitN(req.Name, ".", 2)
	subdomain := names[0]
	domain := names[1]

	parts := strings.Split(subdomain, "-")
	if len(parts) < 2 {
		return
	}

	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	state := ctx.Value(requests.ContextAltState).(*State)
	if cfg == nil || state == nil {
		return
	}

	pre := parts[0]
	state.Prefixes.Update(pre)
	state.Prefixes.RLock()
	for k, count := range state.Prefixes.Counters {
		if count >= cfg.MinForWordFlip {
			newName := k + "-" + strings.Join(parts[1:], "-") + "." + domain
			as.sendAlteredName(ctx, newName, req.Domain)
		}
	}
	state.Prefixes.RUnlock()

	post := parts[len(parts)-1]
	state.Suffixes.Update(post)
	state.Suffixes.RLock()
	for k, count := range state.Suffixes.Counters {
		if count >= cfg.MinForWordFlip {
			newName := strings.Join(parts[:len(parts)-1], "-") + "-" + k + "." + domain
			as.sendAlteredName(ctx, newName, req.Domain)
		}
	}
	state.Suffixes.RUnlock()
}

// flipNumbersInName flips numbers in a subdomain name.
func (as *AlterationService) flipNumbersInName(ctx context.Context, req *requests.DNSRequest) {
	n := req.Name
	parts := strings.SplitN(n, ".", 2)
	// Find the first character that is a number
	first := strings.IndexFunc(parts[0], unicode.IsNumber)
	if first < 0 {
		return
	}
	// Flip the first number and attempt a second number
	for i := 0; i < 10; i++ {
		sf := n[:first] + strconv.Itoa(i) + n[first+1:]

		as.secondNumberFlip(ctx, sf, req.Domain, first+1)
	}
	// Take the first number out
	as.secondNumberFlip(ctx, n[:first]+n[first+1:], req.Domain, -1)
}

func (as *AlterationService) secondNumberFlip(ctx context.Context, name, domain string, minIndex int) {
	parts := strings.SplitN(name, ".", 2)

	// Find the second character that is a number
	last := strings.LastIndexFunc(parts[0], unicode.IsNumber)
	if last < 0 || last < minIndex {
		as.sendAlteredName(ctx, name, domain)
		return
	}
	// Flip those numbers and send out the mutations
	for i := 0; i < 10; i++ {
		n := name[:last] + strconv.Itoa(i) + name[last+1:]

		as.sendAlteredName(ctx, n, domain)
	}
	// Take the second number out
	as.sendAlteredName(ctx, name[:last]+name[last+1:], domain)
}

// appendNumbers appends a number to a subdomain name.
func (as *AlterationService) appendNumbers(ctx context.Context, req *requests.DNSRequest) {
	parts := strings.SplitN(req.Name, ".", 2)

	for i := 0; i < 10; i++ {
		as.addSuffix(ctx, parts, strconv.Itoa(i), req.Domain)
	}
}

func (as *AlterationService) addSuffix(ctx context.Context, parts []string, suffix, domain string) {
	nn := parts[0] + suffix + "." + parts[1]
	as.sendAlteredName(ctx, nn, domain)

	nn = parts[0] + "-" + suffix + "." + parts[1]
	as.sendAlteredName(ctx, nn, domain)
}

func (as *AlterationService) addPrefix(ctx context.Context, name, prefix, domain string) {
	nn := prefix + name
	as.sendAlteredName(ctx, nn, domain)

	nn = prefix + "-" + name
	as.sendAlteredName(ctx, nn, domain)
}

func (as *AlterationService) addSuffixWord(ctx context.Context, req *requests.DNSRequest) {
	parts := strings.SplitN(req.Name, ".", 2)

	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	state := ctx.Value(requests.ContextAltState).(*State)
	if cfg == nil || state == nil {
		return
	}

	state.Suffixes.RLock()
	defer state.Suffixes.RUnlock()

	for word, count := range state.Suffixes.Counters {
		if count >= cfg.MinForWordFlip {
			as.addSuffix(ctx, parts, word, req.Domain)
		}
	}
}

func (as *AlterationService) addPrefixWord(ctx context.Context, req *requests.DNSRequest) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	state := ctx.Value(requests.ContextAltState).(*State)
	if cfg == nil || state == nil {
		return
	}

	state.Prefixes.RLock()
	defer state.Prefixes.RUnlock()

	for word, count := range state.Prefixes.Counters {
		if count >= cfg.MinForWordFlip {
			as.addPrefix(ctx, req.Name, word, req.Domain)
		}
	}
}

func (as *AlterationService) fuzzyLabelSearches(ctx context.Context, req *requests.DNSRequest) {
	parts := strings.SplitN(req.Name, ".", 2)

	results := []string{parts[0]}
	for i := 0; i < as.System().Config().EditDistance; i++ {
		var conv []string

		conv = append(conv, as.additions(results)...)
		conv = append(conv, as.deletions(results)...)
		conv = append(conv, as.substitutions(results)...)
		results = append(results, conv...)
	}

	for _, alt := range results {
		name := alt + "." + parts[1]

		as.sendAlteredName(ctx, name, req.Domain)
	}
}

func (as *AlterationService) additions(set []string) []string {
	ldh := []rune(resolvers.LDHChars)
	ldhLen := len(ldh)

	var results []string
	for _, str := range set {
		rstr := []rune(str)
		rlen := len(rstr)

		for i := 0; i <= rlen; i++ {
			for j := 0; j < ldhLen; j++ {
				temp := append(rstr, ldh[0])

				copy(temp[i+1:], temp[i:])
				temp[i] = ldh[j]
				results = append(results, string(temp))
			}
		}
	}
	return results
}

func (as *AlterationService) deletions(set []string) []string {
	var results []string

	for _, str := range set {
		rstr := []rune(str)
		rlen := len(rstr)

		for i := 0; i < rlen; i++ {
			if del := string(append(rstr[:i], rstr[i+1:]...)); del != "" {
				results = append(results, del)
			}
		}
	}
	return results
}

func (as *AlterationService) substitutions(set []string) []string {
	ldh := []rune(resolvers.LDHChars)
	ldhLen := len(ldh)

	var results []string
	for _, str := range set {
		rstr := []rune(str)
		rlen := len(rstr)

		for i := 0; i < rlen; i++ {
			temp := rstr

			for j := 0; j < ldhLen; j++ {
				temp[i] = ldh[j]
				results = append(results, string(temp))
			}
		}
	}
	return results
}

// sendAlteredName checks that the provided name is valid before publishing it as a new name.
func (as *AlterationService) sendAlteredName(ctx context.Context, name, domain string) {
	name = strings.Trim(name, "-")
	if name == "" {
		return
	}

	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	if re := cfg.DomainRegex(domain); re == nil || !re.MatchString(name) {
		return
	}

	bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
		Name:   name,
		Domain: domain,
		Tag:    as.Type(),
		Source: as.String(),
	})
}
