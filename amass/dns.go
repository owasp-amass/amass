// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type googleDNSAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}

type googleDNSResolve struct {
	Status   int  `json:"Status"`
	TC       bool `json:"TC"`
	RD       bool `json:"RD"`
	RA       bool `json:"RA"`
	AD       bool `json:"AD"`
	CD       bool `json:"CD"`
	Question []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
	} `json:"Question"`
	Answer    []googleDNSAnswer `json:"Answer"`
	Authority []googleDNSAnswer `json:"Authority"`
}

type googleDNS struct {
	valid, subdomains chan *Subdomain
	rfilter           map[string]bool
	lock              sync.Mutex
	queue             []*Subdomain
	showReverse       bool
}

func Resolve(name, t string) ([]googleDNSAnswer, error) {
	var answers []googleDNSAnswer

	u, _ := url.Parse("https://dns.google.com/resolve")
	// do not send our location information with the query
	u.RawQuery = url.Values{"name": {name}, "type": {t}, "edns_client_subnet": {"0.0.0.0/0"}}.Encode()

	page := GetWebPage(u.String())
	if page == "" {
		return answers, errors.New("Failed to reach the Google DNS service")
	}

	var r googleDNSResolve

	err := json.Unmarshal([]byte(page), &r)
	if err != nil {
		return answers, err
	}

	for _, a := range r.Authority {
		if a.Type == 6 {
			err = errors.New(a.Data)
		} else {
			err = fmt.Errorf("Querying %s record returned status: %d", t, r.Status)
		}
		return answers, err
	}

	for _, a := range r.Answer {
		answers = append(answers, a)
	}

	return answers, err
}

func ReverseDNS(ip string) (string, error) {
	var name string

	answers, err := Resolve(ip, "PTR")
	if err == nil {
		for _, a := range answers {
			if a.Type == 12 {
				l := len(a.Data)

				name = a.Data[:l-1]
				break
			}
		}

		if name == "" {
			err = errors.New("PTR record not found")
		}
	}

	return name, err
}

type dnsWildcard struct {
	HasWildcard bool
	IP          string
}

func getARecordData(answers []googleDNSAnswer) string {
	for _, a := range answers {
		if a.Type == 1 || a.Type == 28 {
			return a.Data
		}
	}

	return ""
}

func (gd *googleDNS) checkDomainForWildcards(domain string) *dnsWildcard {
	name1 := "81very92unlikely03name." + domain
	name2 := "45another34random99name." + domain
	name3 := "just555little333me." + domain

	a1, _ := Resolve(name1, "A")
	ip1 := getARecordData(a1)

	a2, _ := Resolve(name2, "A")
	ip2 := getARecordData(a2)

	a3, _ := Resolve(name3, "A")
	ip3 := getARecordData(a3)

	if (ip1 != "" && ip2 != "" && ip3 != "") && (ip1 == ip2 && ip2 == ip3) {
		return &dnsWildcard{HasWildcard: true, IP: ip1}
	}
	return &dnsWildcard{HasWildcard: false, IP: ""}
}

func LimitToDuration(limit int64) time.Duration {
	if limit > 0 {
		d := time.Duration(limit)

		if d < 60 {
			// we are dealing with number of seconds
			return (60 / d) * time.Second
		}

		// make it times per second
		d = d / 60

		m := 1000 / d
		if d < 1000 && m > 5 {
			return m * time.Millisecond
		}
	}

	// use the default rate
	return 5 * time.Millisecond
}

func (gd *googleDNS) tryIP(name *Subdomain, t string, wildcard *dnsWildcard) bool {
	answers, err := Resolve(name.Name, t)

	if err != nil {
		gd.inspectError(name.Domain, err)
		return false
	}
	gd.inspectAnswers(name.Domain, answers)

	ip := getARecordData(answers)
	if ip == "" || (wildcard.HasWildcard == true && wildcard.IP == ip) {
		return false
	}

	name.Address = ip
	return true
}

func (gd *googleDNS) inspectError(domain string, err error) {
	re, _ := regexp.Compile(SUBRE + domain)

	for _, sd := range re.FindAllString(err.Error(), -1) {
		gd.subdomains <- &Subdomain{Name: sd, Domain: domain, Tag: DNSTag}
	}
	return
}

func (gd *googleDNS) inspectAnswers(domain string, answers []googleDNSAnswer) {
	re, _ := regexp.Compile(SUBRE + domain)

	for _, a := range answers {
		for _, sd := range re.FindAllString(a.Data, -1) {
			gd.subdomains <- &Subdomain{Name: sd, Domain: domain, Tag: DNSTag}
		}
	}
	return
}

func reverseAddress(ip string) string {
	var reversed []string

	parts := strings.Split(ip, ".")
	li := len(parts) - 1

	for i := li; i >= 0; i-- {
		reversed = append(reversed, parts[i])
	}

	return strings.Join(reversed, ".")
}

func (gd *googleDNS) oneNetworkDown(domain, ip string, limit time.Duration) {
	parts := strings.Split(ip, ".")
	sub, _ := strconv.Atoi(parts[2])

	if sub == 1 {
		return
	}

	parts[2] = strconv.Itoa(sub - 1)
	parts[3] = "254"

	gd.sweepIPAddressRange(domain, strings.Join(parts, "."), limit)
	return
}

func (gd *googleDNS) oneNetworkUp(domain, ip string, limit time.Duration) {
	parts := strings.Split(ip, ".")
	sub, _ := strconv.Atoi(parts[2])

	if sub == 254 {
		return
	}

	parts[2] = strconv.Itoa(sub + 1)
	parts[3] = "1"

	gd.sweepIPAddressRange(domain, strings.Join(parts, "."), limit)
	return
}

// performs reverse dns across the 254 addresses near the ip param
func (gd *googleDNS) sweepIPAddressRange(domain, ip string, limit time.Duration) {
	t := time.NewTicker(limit)
	defer t.Stop()

	re, _ := regexp.Compile(SUBRE + domain)
	parts := strings.Split(ip, ".")

	if len(parts) != 4 {
		// this only works for IPv4 right now
		return
	}

	val, _ := strconv.Atoi(parts[3])
	parts = parts[:3]
	b := strings.Join(parts, ".")

	start := val - 20
	if start <= 0 {
		start = 1
	}

	stop := val + 20
	if stop >= 255 {
		stop = 254
	}

	for i := start; i <= stop; i++ {
		addr := b + "." + strconv.Itoa(i)
		if addr == ip {
			gd.rfilter[addr] = true
			continue
		}

		if _, ok := gd.rfilter[addr]; ok {
			continue
		}
		gd.rfilter[addr] = true

		reversed := reverseAddress(addr) + ".in-addr.arpa"
		<-t.C // we can't be going too fast
		name, err := ReverseDNS(reversed)
		if err == nil && re.MatchString(name) {
			if gd.showReverse {
				// name is valid in the reverse direction
				gd.valid <- &Subdomain{
					Name:    name,
					Domain:  domain,
					Address: addr,
					Tag:     DNSTag,
				}
			}

			// send the name to be resolved in the forward direction
			gd.subdomains <- &Subdomain{
				Name:   name,
				Domain: domain,
				Tag:    DNSTag,
			}
			// keep looking
			if i == 1 {
				gd.oneNetworkDown(domain, ip, limit)
			} else if i == 254 {
				gd.oneNetworkUp(domain, ip, limit)
			}
		}
	}
	return
}

func (gd *googleDNS) processSubdomains(limit int64) {
	dur := LimitToDuration(limit)
	wildcards := make(map[string]*dnsWildcard)

	t := time.NewTicker(dur)
	defer t.Stop()

	for range t.C {
		subdomain := gd.getNext()
		if subdomain == nil || subdomain.Domain == "" {
			continue
		}
		domain := subdomain.Domain

		answers, err := Resolve(subdomain.Name, "CNAME")
		if err != nil {
			gd.inspectError(domain, err)
		}
		gd.inspectAnswers(domain, answers)

		w, ok := wildcards[domain]
		if !ok {
			w = gd.checkDomainForWildcards(domain)
			wildcards[domain] = w
		}

		resolved := gd.tryIP(subdomain, "A", w)
		if !resolved {
			resolved = gd.tryIP(subdomain, "AAAA", w)
		}

		if resolved {
			// look for name nearby the ip address
			gd.sweepIPAddressRange(subdomain.Domain, subdomain.Address, dur)
			// return the successfully resolved name + address
			gd.valid <- subdomain
		}
	}
	return
}

func (gd *googleDNS) getNext() *Subdomain {
	var l int
	var s *Subdomain

	gd.lock.Lock()

	l = len(gd.queue)
	if l > 1 {
		s = gd.queue[0]
		gd.queue = gd.queue[1:]
	} else if l == 1 {
		s = gd.queue[0]
		gd.queue = []*Subdomain{}
	}

	gd.lock.Unlock()
	return s
}

func (gd *googleDNS) CheckSubdomain(sd *Subdomain) {
	gd.lock.Lock()
	gd.queue = append(gd.queue, sd)
	gd.lock.Unlock()
	return
}

func (gd *googleDNS) TagQueriesFinished(tag string) bool {
	result := true

	gd.lock.Lock()
	for _, element := range gd.queue {
		if element.Tag == tag {
			result = false
			break
		}
	}
	gd.lock.Unlock()

	return result
}

func (gd *googleDNS) AllQueriesFinished() bool {
	var result bool

	gd.lock.Lock()
	if len(gd.queue) == 0 {
		result = true
	}
	gd.lock.Unlock()

	return result
}

func GoogleDNS(valid chan *Subdomain, subdomains chan *Subdomain, limit int64, rShow bool) DNSChecker {
	gd := new(googleDNS)

	gd.valid = valid
	gd.subdomains = subdomains
	gd.rfilter = make(map[string]bool)
	gd.showReverse = rShow

	go gd.processSubdomains(limit)
	return gd
}
