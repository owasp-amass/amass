// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/caffix/recon"
)

type ReverseIPService struct {
	BaseAmassService

	frequency time.Duration
	responses chan *AmassRequest
	searches  []ReverseIper
}

func NewReverseIPService(in, out chan *AmassRequest) *ReverseIPService {
	ris := &ReverseIPService{
		responses: make(chan *AmassRequest, 50),
	}

	ris.BaseAmassService = *NewBaseAmassService("Reverse IP Service", ris)
	ris.searches = []ReverseIper{
		//BingReverseIPSearch(ris.responses),
		//ShodanReverseIPSearch(ris.responses),
		ReverseDNSSearch(ris.responses),
	}

	ris.input = in
	ris.output = out
	return ris
}

func (ris *ReverseIPService) OnStart() error {
	ris.BaseAmassService.OnStart()

	go ris.processRequests()
	go ris.processOutput()
	return nil
}

func (ris *ReverseIPService) OnStop() error {
	ris.BaseAmassService.OnStop()
	return nil
}

func (ris *ReverseIPService) Frequency() time.Duration {
	ris.Lock()
	defer ris.Unlock()

	return ris.frequency
}

func (ris *ReverseIPService) SetFrequency(freq time.Duration) {
	ris.Lock()
	defer ris.Unlock()

	ris.frequency = freq
}

func (ris *ReverseIPService) sendOut(req *AmassRequest) {
	ris.Output() <- req
	ris.SetActive(true)
}

func (ris *ReverseIPService) processRequests() {
	filter := make(map[string]struct{})
	// Do not perform reverse lookups on localhost
	filter["127.0.0.1"] = struct{}{}

	t := time.NewTicker(ris.Frequency())
	defer t.Stop()
loop:
	for {
		select {
		case req := <-ris.Input():
			if _, found := filter[req.Address]; !found {
				filter[req.Address] = struct{}{}
				ris.SetActive(true)
				<-t.C
				ris.executeAllSearches(req.Domain, req.Address)
			}
		case <-ris.Quit():
			break loop
		}
	}
}

func (ris *ReverseIPService) processOutput() {
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
loop:
	for {
		select {
		case out := <-ris.responses:
			go ris.sendOut(out)
			ris.SetActive(true)
		case <-t.C:
			ris.SetActive(false)
		case <-ris.Quit():
			break loop
		}
	}
}

func (ris *ReverseIPService) executeAllSearches(domain, ip string) {
	done := make(chan int)

	for _, search := range ris.searches {
		go search.Search(domain, ip, done)
	}

	for i := 0; i < len(ris.searches); i++ {
		ris.SetActive(true)
		<-done
	}
}

// ReverseIper - represents all types that perform reverse IP lookups
type ReverseIper interface {
	Search(domain, ip string, done chan int)
	fmt.Stringer
}

// reverseIPSearchEngine - A searcher that attempts to discover DNS names from an IP address using a search engine
type reverseIPSearchEngine struct {
	Name     string
	Quantity int
	Limit    int
	Output   chan<- *AmassRequest
	Callback func(*reverseIPSearchEngine, string, int) string
}

func (se *reverseIPSearchEngine) String() string {
	return se.Name
}

func (se *reverseIPSearchEngine) urlByPageNum(ip string, page int) string {
	return se.Callback(se, ip, page)
}

func (se *reverseIPSearchEngine) Search(domain, ip string, done chan int) {
	var unique []string

	re := SubdomainRegex(domain)
	num := se.Limit / se.Quantity
	for i := 0; i < num; i++ {
		page := GetWebPage(se.urlByPageNum(ip, i))
		if page == "" {
			break
		}

		for _, sd := range re.FindAllString(page, -1) {
			u := NewUniqueElements(unique, sd)

			if len(u) > 0 {
				unique = append(unique, u...)
				se.Output <- &AmassRequest{
					Name:   sd,
					Domain: domain,
					Tag:    SEARCH,
					Source: se.Name,
				}
			}
		}
		// Do not hit Bing too hard
		time.Sleep(500 * time.Millisecond)
	}
	done <- len(unique)
}

func bingReverseIPURLByPageNum(b *reverseIPSearchEngine, ip string, page int) string {
	first := strconv.Itoa((page * b.Quantity) + 1)
	u, _ := url.Parse("http://www.bing.com/search")

	u.RawQuery = url.Values{"q": {"ip%3a" + ip},
		"first": {first}, "FORM": {"PORE"}}.Encode()
	return u.String()
}

func BingReverseIPSearch(out chan<- *AmassRequest) ReverseIper {
	b := &reverseIPSearchEngine{
		Name:     "Bing Reverse IP Search",
		Quantity: 10,
		Limit:    50,
		Output:   out,
		Callback: bingReverseIPURLByPageNum,
	}
	return b
}

// reverseIPLookup - A searcher that attempts to discover DNS names from an IP address using a single web page
type reverseIPLookup struct {
	Name     string
	Output   chan<- *AmassRequest
	Callback func(string) string
}

func (l *reverseIPLookup) String() string {
	return l.Name
}

func (l *reverseIPLookup) Search(domain, ip string, done chan int) {
	var unique []string

	re := SubdomainRegex(domain)
	page := GetWebPage(l.Callback(ip))
	if page == "" {
		done <- 0
		return
	}

	for _, sd := range re.FindAllString(page, -1) {
		u := NewUniqueElements(unique, sd)

		if len(u) > 0 {
			unique = append(unique, u...)
			l.Output <- &AmassRequest{
				Name:   sd,
				Domain: domain,
				Tag:    SEARCH,
				Source: l.Name,
			}
		}
	}
	done <- len(unique)
}

func shodanReverseIPURL(ip string) string {
	format := "https://www.shodan.io/host/%s"

	return fmt.Sprintf(format, ip)
}

func ShodanReverseIPSearch(out chan<- *AmassRequest) ReverseIper {
	ss := &reverseIPLookup{
		Name:     "Shodan",
		Output:   out,
		Callback: shodanReverseIPURL,
	}
	return ss
}

// reverseDNSLookup - Attempts to discover DNS names from an IP address using a reverse DNS
type reverseDNSLookup struct {
	Name   string
	Output chan<- *AmassRequest
}

func (l *reverseDNSLookup) String() string {
	return l.Name
}

func (l *reverseDNSLookup) Search(domain, ip string, done chan int) {
	re := SubdomainRegex(domain)

	name, err := recon.ReverseDNS(ip, NextNameserver())
	if err == nil && re.MatchString(name) {
		// Send the name to be resolved in the forward direction
		l.Output <- &AmassRequest{
			Name:   name,
			Domain: domain,
			Tag:    DNS,
			Source: l.Name,
		}
		done <- 1
	}
	done <- 0
}

func ReverseDNSSearch(out chan<- *AmassRequest) ReverseIper {
	ds := &reverseDNSLookup{
		Name:   "Reverse DNS",
		Output: out,
	}
	return ds
}
