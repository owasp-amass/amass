// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"strconv"
	"strings"
	"sync"
	"unicode"

	"github.com/OWASP/Amass/amass/core"
	"github.com/miekg/dns"
)

var (
	altWords []string
)

type alterationCache struct {
	sync.RWMutex
	cache map[string]int
}

func init() {
	altWords = []string{
		"1",
		"10",
		"11",
		"12",
		"13",
		"14",
		"15",
		"16",
		"17",
		"18",
		"19",
		"2",
		"20",
		"2009",
		"2010",
		"2011",
		"2012",
		"2013",
		"2014",
		"2015",
		"2016",
		"2017",
		"2018",
		"2019",
		"3",
		"4",
		"5",
		"6",
		"7",
		"8",
		"9",
		"a",
		"acc",
		"account",
		"accounts",
		"admin",
		"admin1",
		"administrator",
		"akali",
		"akamai",
		"alpha",
		"alt",
		"america",
		"analytics",
		"api",
		"api-docs",
		"api1",
		"apollo",
		"app",
		"april",
		"auth",
		"aws",
		"b",
		"backend",
		"beta",
		"billing",
		"boards",
		"box",
		"brand",
		"brasil",
		"brazil",
		"bucket",
		"bucky",
		"c",
		"cdn",
		"cf",
		"cfg",
		"chef",
		"ci",
		"client",
		"cloudfront",
		"cms",
		"cms1",
		"cn",
		"com",
		"confluence",
		"container",
		"control",
		"d",
		"data",
		"db",
		"dec",
		"demo",
		"dev",
		"dev1",
		"developer",
		"devops",
		"docker",
		"docs",
		"drop",
		"e",
		"edge",
		"elasticbeanstalk",
		"elb",
		"email",
		"eng",
		"engima",
		"engine",
		"engineering",
		"eu",
		"europe",
		"europewest",
		"euw",
		"euwe",
		"evelynn",
		"events",
		"f",
		"feb",
		"firewall",
		"forms",
		"forum",
		"frontpage",
		"ftp",
		"fw",
		"g",
		"games",
		"germany",
		"gh",
		"ghcpi",
		"git",
		"github",
		"global",
		"h",
		"hkg",
		"hw",
		"hwcdn",
		"i",
		"ids",
		"imap",
		"int",
		"internal",
		"j",
		"jenkins",
		"jinx",
		"july",
		"june",
		"k",
		"kor",
		"korea",
		"kr",
		"l",
		"lan",
		"las",
		"latin",
		"latinamerica",
		"lax",
		"lax1",
		"lb",
		"loadbalancer",
		"login",
		"m",
		"machine",
		"mail",
		"march",
		"merch",
		"mirror",
		"mon",
		"n",
		"na",
		"nautilus",
		"net",
		"netherlands",
		"new",
		"nginx",
		"nl",
		"node",
		"northamerica",
		"nov",
		"o",
		"oceania",
		"oct",
		"old",
		"ops",
		"org",
		"origin",
		"p",
		"page",
		"pantheon",
		"pass",
		"pay",
		"payment",
		"pc",
		"php",
		"pl",
		"poland",
		"prd",
		"preferences",
		"priv",
		"private",
		"prod",
		"production",
		"profile",
		"profiles",
		"promo",
		"promotion",
		"proxy",
		"pub",
		"q",
		"qa",
		"r",
		"redirector",
		"region",
		"repo",
		"repository",
		"reset",
		"restrict",
		"restricted",
		"reviews",
		"s",
		"s3",
		"sandbox",
		"search",
		"secure",
		"security",
		"sept",
		"server",
		"service",
		"singed",
		"skins",
		"smtp",
		"spring",
		"sql",
		"ssl",
		"sso",
		"staff",
		"stage",
		"stage1",
		"staging",
		"static",
		"stg",
		"support",
		"swagger",
		"system",
		"t",
		"team",
		"test",
		"test1",
		"testbed",
		"testing",
		"testing1",
		"tomcat",
		"tpe",
		"tr",
		"trial",
		"tst",
		"tur",
		"turk",
		"turkey",
		"twitch",
		"u",
		"uat",
		"users",
		"v",
		"v1",
		"v2",
		"vi",
		"vpn",
		"w",
		"w3",
		"web",
		"web1",
		"webapp",
		"westeurope",
		"www",
		"x",
		"y",
		"z",
	}
}

// AlterationService is the Service that handles all DNS name permutation within
// the architecture. This is achieved by receiving all the RESOLVED events.
type AlterationService struct {
	core.BaseService
	prefixes *alterationCache
	suffixes *alterationCache
}

// NewAlterationService returns he object initialized, but not yet started.
func NewAlterationService(config *core.Config, bus *core.EventBus) *AlterationService {
	as := new(AlterationService)

	as.BaseService = *core.NewBaseService(as, "Alterations", config, bus)
	as.prefixes = NewAlterationCache(altWords)
	as.suffixes = NewAlterationCache(altWords)
	return as
}

// OnStart implements the Service interface
func (as *AlterationService) OnStart() error {
	as.BaseService.OnStart()

	if as.Config().Alterations {
		as.Bus().Subscribe(core.NameResolvedTopic, as.SendRequest)
		go as.processRequests()
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
		case req := <-as.RequestChan():
			go as.executeAlterations(req)
		}
	}
}

// executeAlterations runs all the DNS name alteration methods as goroutines.
func (as *AlterationService) executeAlterations(req *core.Request) {
	if !as.correctRecordTypes(req) || !as.Config().IsDomainInScope(req.Name) {
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

}

func (as *AlterationService) correctRecordTypes(req *core.Request) bool {
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

func (as *AlterationService) flipWords(req *core.Request) {
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
		if count >= as.Config().WordAlterationMin {
			newName := k + "-" + strings.Join(parts[1:], "-") + "." + domain
			as.sendAlteredName(newName, req.Domain)
		}
	}
	as.prefixes.RUnlock()

	post := parts[len(parts)-1]
	as.suffixes.update(post)
	as.suffixes.RLock()
	for k, count := range as.suffixes.cache {
		if count >= as.Config().WordAlterationMin {
			newName := strings.Join(parts[:len(parts)-1], "-") + "-" + k + "." + domain
			as.sendAlteredName(newName, req.Domain)
		}
	}
	as.suffixes.RUnlock()
}

func NewAlterationCache(seed []string) *alterationCache {
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
		ac.cache[word] += 1
	} else {
		ac.cache[word] = 1
	}
	count := ac.cache[word]
	ac.Unlock()
	return count
}

// flipNumbersInName flips numbers in a subdomain name.
func (as *AlterationService) flipNumbersInName(req *core.Request) {
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
func (as *AlterationService) appendNumbers(req *core.Request) {
	n := req.Name
	parts := strings.SplitN(n, ".", 2)

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

func (as *AlterationService) addSuffixWord(req *core.Request) {
	n := req.Name
	parts := strings.SplitN(n, ".", 2)

	as.suffixes.RLock()
	for word, count := range as.suffixes.cache {
		if count >= as.Config().WordAlterationMin {
			as.addSuffix(parts, word, req.Domain)
		}
	}
	as.suffixes.RUnlock()
}

func (as *AlterationService) addPrefixWord(req *core.Request) {
	as.prefixes.RLock()
	for word, count := range as.prefixes.cache {
		if count >= as.Config().WordAlterationMin {
			as.addPrefix(req.Name, word, req.Domain)
		}
	}
	as.prefixes.RUnlock()
}

// sendAlteredName checks that the provided name is valid before publishing it as a new name.
func (as *AlterationService) sendAlteredName(name, domain string) {
	re := as.Config().DomainRegex(domain)
	if re == nil || !re.MatchString(name) {
		return
	}

	as.Bus().Publish(core.NewNameTopic, &core.Request{
		Name:   name,
		Domain: domain,
		Tag:    core.ALT,
		Source: as.String(),
	})
}
