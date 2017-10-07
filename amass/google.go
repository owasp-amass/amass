// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"encoding/json"
	"net/url"
	"sync"
	"time"
)

type GoogleDNSResolve struct {
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
	Answer []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		TTL  int    `json:"TTL"`
		Data string `json:"data"`
	} `json:"Answer"`
}

type googleDNS struct {
	valid, subdomains chan *Subdomain
	lock              sync.Mutex
	queue             []*Subdomain
}

func (gd *googleDNS) resolve(domain, name, t string) string {
	u, _ := url.Parse("https://dns.google.com/resolve")
	// do not send our location information with the query
	u.RawQuery = url.Values{"name": {name}, "type": {t}, "edns_client_subnet": {"0.0.0.0/0"}}.Encode()

	rt := 1
	if t == "AAAA" {
		rt = 28
	}

	page := GetWebPage(u.String())
	if page == "" {
		return ""
	}

	var addr GoogleDNSResolve

	err := json.Unmarshal([]byte(page), &addr)
	if err != nil || addr.Status != 0 {
		return ""
	}

	var ip string

	for _, a := range addr.Answer {
		ni := len(a.Name) - 1

		if a.Type == 5 && a.Name[:ni] == name {
			di := len(a.Data) - 1

			gd.subdomains <- &Subdomain{Name: a.Data[:di], Domain: domain, Tag: DNSTag}
		} else if a.Type == rt {
			ip = a.Data
			break
		}
	}
	return ip
}

type DNSWildcard struct {
	HasWildcard bool
	IP          string
}

func (gd *googleDNS) checkDomainForWildcards(domain string) *DNSWildcard {
	name1 := "81very92unlikely03name." + domain
	name2 := "45another34random99name." + domain
	name3 := "just555little333me." + domain

	ip1 := gd.resolve(domain, name1, "A")
	ip2 := gd.resolve(domain, name2, "A")
	ip3 := gd.resolve(domain, name3, "A")

	if (ip1 != "" && ip2 != "" && ip3 != "") && (ip1 == ip2 && ip2 == ip3) {
		return &DNSWildcard{HasWildcard: true, IP: ip1}
	}
	return &DNSWildcard{HasWildcard: false, IP: ""}
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
		if d < 1000 && m > 10 {
			return m * time.Millisecond
		}
	}

	// use the default rate
	return 10 * time.Millisecond
}

func (gd *googleDNS) processSubdomains(limit int64) {
	wildcards := make(map[string]*DNSWildcard)

	t := time.NewTicker(LimitToDuration(limit))
	defer t.Stop()

	for range t.C {
		subdomain := gd.getNext()
		if subdomain == nil {
			continue
		}

		domain := subdomain.Domain
		if domain == "" {
			continue
		}

		w, ok := wildcards[domain]
		if !ok {
			w = gd.checkDomainForWildcards(domain)
			wildcards[domain] = w
		}

		ip := gd.resolve(domain, subdomain.Name, "A")
		if ip == "" {
			ip = gd.resolve(domain, subdomain.Name, "AAAA")
		}

		if ip == "" || (w.HasWildcard == true && w.IP == ip) {
			continue
		}

		subdomain.Address = ip
		gd.valid <- subdomain
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
}

func GoogleDNS(valid chan *Subdomain, subdomains chan *Subdomain, limit int64) DNSChecker {
	gd := new(googleDNS)

	gd.valid = valid
	gd.subdomains = subdomains

	go gd.processSubdomains(limit)
	return gd
}
