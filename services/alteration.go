// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"strconv"
	"strings"
	"sync"
	"unicode"

	"github.com/OWASP/Amass/config"
	eb "github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/resolvers"
	"github.com/OWASP/Amass/utils"
	"github.com/miekg/dns"
)

type alterationCache struct {
	sync.RWMutex
	cache map[string]int
}

func newAlterationCache(seed []string) *alterationCache {
	ac := &alterationCache{
		cache: make(map[string]int),
	}

	ac.Lock()
	for _, word := range seed {
		ac.cache[word] = 0
	}
	ac.Unlock()

	return ac
}

func (ac *alterationCache) update(word string) int {
	ac.Lock()
	if _, ok := ac.cache[word]; ok {
		ac.cache[word]++
	} else {
		ac.cache[word] = 1
	}
	count := ac.cache[word]
	ac.Unlock()
	return count
}

// AlterationService is the Service that handles all DNS name permutations within
// the architecture.
type AlterationService struct {
	BaseService

	filter   *utils.StringFilter
	prefixes *alterationCache
	suffixes *alterationCache
}

// NewAlterationService returns he object initialized, but not yet started.
func NewAlterationService(cfg *config.Config, bus *eb.EventBus, pool *resolvers.ResolverPool) *AlterationService {
	as := &AlterationService{
		filter:   utils.NewStringFilter(),
		prefixes: newAlterationCache(cfg.AltWordlist),
		suffixes: newAlterationCache(cfg.AltWordlist),
	}

	as.BaseService = *NewBaseService(as, "Alterations", cfg, bus, pool)
	return as
}

// OnStart implements the Service interface
func (as *AlterationService) OnStart() error {
	as.BaseService.OnStart()

	if as.Config().Alterations {
		as.Bus().Subscribe(requests.NameResolvedTopic, as.SendDNSRequest)
	}
	go as.processRequests()
	return nil
}

// OnLowNumberOfNames implements the Service interface.
func (as *AlterationService) OnLowNumberOfNames() error {
loop:
	for i := 0; i < 10; i++ {
		select {
		case req := <-as.DNSRequestChan():
			go as.executeAlterations(req)
		default:
			break loop
		}
	}
	return nil
}

func (as *AlterationService) processRequests() {
	for {
		select {
		case <-as.PauseChan():
			<-as.ResumeChan()
		case <-as.Quit():
			return
		case <-as.AddrRequestChan():
		case <-as.ASNRequestChan():
		case <-as.WhoisRequestChan():
		}
	}
}

// executeAlterations runs all the DNS name alteration methods as goroutines.
func (as *AlterationService) executeAlterations(req *requests.DNSRequest) {
	if !as.correctRecordTypes(req) ||
		!as.Config().IsDomainInScope(req.Name) ||
		(len(strings.Split(req.Domain, ".")) == len(strings.Split(req.Name, "."))) {
		return
	}

	if as.filter.Duplicate(req.Name) {
		return
	}

	as.SetActive()
	if as.Config().FlipNumbers {
		as.flipNumbersInName(req)
	}
	if as.Config().AddNumbers {
		as.appendNumbers(req)
	}
	if as.Config().FlipWords {
		as.flipWords(req)
	}
	if as.Config().AddWords {
		as.addSuffixWord(req)
		as.addPrefixWord(req)
	}
	if as.Config().EditDistance > 0 {
		as.fuzzyLabelSearches(req)
	}
}

func (as *AlterationService) correctRecordTypes(req *requests.DNSRequest) bool {
	var ok bool
	for _, r := range req.Records {
		t := uint16(r.Type)

		if t == dns.TypeTXT || t == dns.TypeA || t == dns.TypeAAAA || t == dns.TypeCNAME {
			ok = true
			break
		}
	}
	return ok
}

func (as *AlterationService) flipWords(req *requests.DNSRequest) {
	names := strings.SplitN(req.Name, ".", 2)
	subdomain := names[0]
	domain := names[1]

	parts := strings.Split(subdomain, "-")
	if len(parts) < 2 {
		return
	}

	pre := parts[0]
	as.prefixes.update(pre)
	as.prefixes.RLock()
	for k, count := range as.prefixes.cache {
		if count >= as.Config().MinForWordFlip {
			newName := k + "-" + strings.Join(parts[1:], "-") + "." + domain
			as.sendAlteredName(newName, req.Domain)
		}
	}
	as.prefixes.RUnlock()

	post := parts[len(parts)-1]
	as.suffixes.update(post)
	as.suffixes.RLock()
	for k, count := range as.suffixes.cache {
		if count >= as.Config().MinForWordFlip {
			newName := strings.Join(parts[:len(parts)-1], "-") + "-" + k + "." + domain
			as.sendAlteredName(newName, req.Domain)
		}
	}
	as.suffixes.RUnlock()
}

// flipNumbersInName flips numbers in a subdomain name.
func (as *AlterationService) flipNumbersInName(req *requests.DNSRequest) {
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

		as.secondNumberFlip(sf, req.Domain, first+1)
	}
	// Take the first number out
	as.secondNumberFlip(n[:first]+n[first+1:], req.Domain, -1)
}

func (as *AlterationService) secondNumberFlip(name, domain string, minIndex int) {
	parts := strings.SplitN(name, ".", 2)

	// Find the second character that is a number
	last := strings.LastIndexFunc(parts[0], unicode.IsNumber)
	if last < 0 || last < minIndex {
		as.sendAlteredName(name, domain)
		return
	}
	// Flip those numbers and send out the mutations
	for i := 0; i < 10; i++ {
		n := name[:last] + strconv.Itoa(i) + name[last+1:]

		as.sendAlteredName(n, domain)
	}
	// Take the second number out
	as.sendAlteredName(name[:last]+name[last+1:], domain)
}

// appendNumbers appends a number to a subdomain name.
func (as *AlterationService) appendNumbers(req *requests.DNSRequest) {
	parts := strings.SplitN(req.Name, ".", 2)

	for i := 0; i < 10; i++ {
		as.addSuffix(parts, strconv.Itoa(i), req.Domain)
	}
}

func (as *AlterationService) addSuffix(parts []string, suffix, domain string) {
	nn := parts[0] + suffix + "." + parts[1]
	as.sendAlteredName(nn, domain)

	nn = parts[0] + "-" + suffix + "." + parts[1]
	as.sendAlteredName(nn, domain)
}

func (as *AlterationService) addPrefix(name, prefix, domain string) {
	nn := prefix + name
	as.sendAlteredName(nn, domain)

	nn = prefix + "-" + name
	as.sendAlteredName(nn, domain)
}

func (as *AlterationService) addSuffixWord(req *requests.DNSRequest) {
	parts := strings.SplitN(req.Name, ".", 2)

	as.suffixes.RLock()
	for word, count := range as.suffixes.cache {
		if count >= as.Config().MinForWordFlip {
			as.addSuffix(parts, word, req.Domain)
		}
	}
	as.suffixes.RUnlock()
}

func (as *AlterationService) addPrefixWord(req *requests.DNSRequest) {
	as.prefixes.RLock()
	for word, count := range as.prefixes.cache {
		if count >= as.Config().MinForWordFlip {
			as.addPrefix(req.Name, word, req.Domain)
		}
	}
	as.prefixes.RUnlock()
}

func (as *AlterationService) fuzzyLabelSearches(req *requests.DNSRequest) {
	parts := strings.SplitN(req.Name, ".", 2)

	results := []string{parts[0]}
	for i := 0; i < as.Config().EditDistance; i++ {
		var conv []string

		conv = append(conv, as.additions(results)...)
		conv = append(conv, as.deletions(results)...)
		conv = append(conv, as.substitutions(results)...)
		results = append(results, conv...)
	}

	for _, alt := range results {
		name := alt + "." + parts[1]

		as.sendAlteredName(name, req.Domain)
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
func (as *AlterationService) sendAlteredName(name, domain string) {
	name = strings.Trim(name, "-")
	if name == "" {
		return
	}

	re := as.Config().DomainRegex(domain)
	if re == nil || !re.MatchString(name) {
		return
	}

	as.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
		Name:   name,
		Domain: domain,
		Tag:    requests.ALT,
		Source: as.String(),
	})
}
