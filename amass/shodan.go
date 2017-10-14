// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Shodan struct {
	subdomains chan *Subdomain
	filter     map[string]bool
	lock       sync.Mutex
	queue      []*Subdomain
}

func (s *Shodan) processRequests() {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()

	for {
		host := s.getNext()
		if host == nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}

		re, _ := regexp.Compile(SUBRE + host.Domain)
		parts := strings.Split(host.Address, ".")
		val, _ := strconv.Atoi(parts[3])
		parts = parts[:3]
		b := strings.Join(parts, ".")

		start := val - 5
		if start <= 0 {
			start = 1
		}

		stop := val + 5
		if stop >= 255 {
			stop = 254
		}

		for i := start; i <= stop; i++ {
			addr := b + "." + strconv.Itoa(i)
			if addr == host.Address {
				s.filter[addr] = true
				continue
			}

			if _, ok := s.filter[addr]; ok {
				continue
			}
			s.filter[addr] = true

			<-t.C // we can't be going too fast
			page := GetWebPage("https://www.shodan.io/host/" + addr)
			if page != "" {
				for _, sd := range re.FindAllString(page, -1) {
					s.subdomains <- &Subdomain{Name: sd, Domain: host.Domain, Tag: SHODAN}
				}
			}
		}
	}
	return
}

func (s *Shodan) getNext() *Subdomain {
	var l int
	var sd *Subdomain

	s.lock.Lock()

	l = len(s.queue)
	if l > 1 {
		sd = s.queue[0]
		s.queue = s.queue[1:]
	} else if l == 1 {
		sd = s.queue[0]
		s.queue = []*Subdomain{}
	}

	s.lock.Unlock()
	return sd
}

func (s *Shodan) FindHosts(host *Subdomain) {
	s.lock.Lock()
	s.queue = append(s.queue, host)
	s.lock.Unlock()
	return
}

func ShodanHostLookup(subdomains chan *Subdomain) *Shodan {
	s := new(Shodan)

	s.subdomains = subdomains
	s.filter = make(map[string]bool)

	go s.processRequests()
	return s
}
