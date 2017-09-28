// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"encoding/json"
	"net/url"
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
	valid            chan *ValidSubdomain
	subdomains, next chan string
}

func (gd *googleDNS) resolve(name, t string) string {
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

			gd.subdomains <- a.Data[:di]
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

	ip1 := gd.resolve(name1, "A")
	ip2 := gd.resolve(name2, "A")
	ip3 := gd.resolve(name3, "A")

	if (ip1 != "" && ip2 != "" && ip3 != "") && (ip1 == ip2 && ip2 == ip3) {
		return &DNSWildcard{HasWildcard: true, IP: ip1}
	}
	return &DNSWildcard{HasWildcard: false, IP: ""}
}

func (gd *googleDNS) processSubdomains() {
	wildcards := make(map[string]*DNSWildcard)
	// do not use this service more than once every 1/20 a second
	t := time.NewTicker(50 * time.Millisecond)
	defer t.Stop()

	for range t.C {
		subdomain := <-gd.next

		domain := ExtractDomain(subdomain)
		if domain == "" {
			continue
		}

		w, ok := wildcards[domain]
		if !ok {
			w = gd.checkDomainForWildcards(domain)
			wildcards[domain] = w
		}

		ip := gd.resolve(subdomain, "A")
		if ip == "" {
			ip = gd.resolve(subdomain, "AAAA")
		}

		if ip == "" || (w.HasWildcard == true && w.IP == ip) {
			continue
		}

		gd.valid <- &ValidSubdomain{Subdomain: subdomain, Address: ip}
	}
	return
}

func (gd *googleDNS) CheckSubdomain(sd string) {
	gd.next <- sd
}

func (gd *googleDNS) CheckSubdomains(sds []string) {
	for _, s := range sds {
		gd.next <- s
	}
}

func GoogleDNS(valid chan *ValidSubdomain, subdomains chan string) DNSChecker {
	gd := new(googleDNS)

	gd.valid = valid
	gd.subdomains = subdomains
	gd.next = make(chan string, 200)

	go gd.processSubdomains()
	return gd
}
