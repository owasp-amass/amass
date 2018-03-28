// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"fmt"
	"net/url"
	"strconv"
	"time"
)

type ReverseIPService struct {
	BaseAmassService

	responses chan *AmassRequest
	dns       ReverseIper
	others    []ReverseIper

	queue []*AmassRequest

	// Ensures that the same IP is not sent out twice
	filter map[string]struct{}
}

func NewReverseIPService(in, out chan *AmassRequest, config *AmassConfig) *ReverseIPService {
	ris := &ReverseIPService{
		responses: make(chan *AmassRequest, 50),
		filter:    make(map[string]struct{}),
	}

	ris.BaseAmassService = *NewBaseAmassService("Reverse IP Service", config, ris)
	ris.dns = ReverseDNSSearch(ris.responses, config)
	ris.others = []ReverseIper{
		BingReverseIPSearch(ris.responses, config),
		ShodanReverseIPSearch(ris.responses, config),
	}
	// Do not perform reverse lookups on localhost
	ris.filter["127.0.0.1"] = struct{}{}

	ris.input = in
	ris.output = out
	return ris
}

func (ris *ReverseIPService) OnStart() error {
	ris.BaseAmassService.OnStart()

	go ris.processAlternatives()
	go ris.processRequests()
	go ris.processOutput()
	return nil
}

func (ris *ReverseIPService) OnStop() error {
	ris.BaseAmassService.OnStop()
	return nil
}

func (ris *ReverseIPService) processRequests() {
	t := time.NewTicker(ris.Config().Frequency)
	defer t.Stop()
loop:
	for {
		select {
		case req := <-ris.Input():
			<-t.C
			go ris.execReverseDNS(req)
		case <-ris.Quit():
			break loop
		}
	}
}

func (ris *ReverseIPService) processAlternatives() {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
loop:
	for {
		select {
		case <-t.C:
			ris.execAlternatives(ris.nextFromQueue())
		case <-ris.Quit():
			break loop
		}
	}
}

func (ris *ReverseIPService) addToQueue(req *AmassRequest) {
	ris.Lock()
	defer ris.Unlock()

	ris.queue = append(ris.queue, req)
}

func (ris *ReverseIPService) nextFromQueue() *AmassRequest {
	ris.Lock()
	defer ris.Unlock()

	var next *AmassRequest
	if len(ris.queue) > 0 {
		next = ris.queue[0]
		// Remove the first slice element
		if len(ris.queue) > 1 {
			ris.queue = ris.queue[1:]
		} else {
			ris.queue = []*AmassRequest{}
		}
	}
	return next
}

func (ris *ReverseIPService) processOutput() {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
loop:
	for {
		select {
		case req := <-ris.responses:
			ris.performOutput(req)
		case <-t.C:
			ris.SetActive(false)
		case <-ris.Quit():
			break loop
		}
	}
}

func (ris *ReverseIPService) performOutput(req *AmassRequest) {
	config := ris.Config()

	ris.SetActive(true)
	if req.addDomains {
		req.Domain = config.domainLookup.SubdomainToDomain(req.Name)
		if req.Domain != "" {
			if config.AdditionalDomains {
				config.AddDomains([]string{req.Domain})
			}
			ris.SendOut(req)
		}
		return
	}
	// Check if the discovered name belongs to a root domain of interest
	for _, domain := range config.Domains() {
		re := SubdomainRegex(domain)
		re.Longest()

		// Once we have a match, the domain is added to the request
		if match := re.FindString(req.Name); match != "" {
			req.Name = match
			req.Domain = domain
			ris.SendOut(req)
			break
		}
	}
}

// Returns true if the IP is a duplicate entry in the filter.
// If not, the IP is added to the filter
func (ris *ReverseIPService) duplicate(ip string) bool {
	ris.Lock()
	defer ris.Unlock()

	if _, found := ris.filter[ip]; found {
		return true
	}
	ris.filter[ip] = struct{}{}
	return false
}

func (ris *ReverseIPService) execReverseDNS(req *AmassRequest) {
	ris.SetActive(true)
	if req.Address == "" || ris.duplicate(req.Address) {
		return
	}

	done := make(chan int)
	ris.dns.Search(req, done)
	if <-done == 0 {
		ris.addToQueue(req)
	}
}

func (ris *ReverseIPService) execAlternatives(req *AmassRequest) {
	if req == nil {
		return
	}

	ris.SetActive(true)
	done := make(chan int)
	for _, s := range ris.others {
		go s.Search(req, done)
	}
	// Wait for the lookups to complete
	for i := 0; i < len(ris.others); i++ {
		ris.SetActive(true)
		<-done
		ris.SetActive(true)
	}
}

// ReverseIper - represents all types that perform reverse IP lookups
type ReverseIper interface {
	Search(req *AmassRequest, done chan int)
	fmt.Stringer
}

// reverseIPSearchEngine - A searcher that attempts to discover DNS names from an IP address using a search engine
type reverseIPSearchEngine struct {
	Name     string
	Quantity int
	Limit    int
	Output   chan<- *AmassRequest
	Callback func(*reverseIPSearchEngine, string, int) string
	Config   *AmassConfig
}

func (se *reverseIPSearchEngine) String() string {
	return se.Name
}

func (se *reverseIPSearchEngine) urlByPageNum(ip string, page int) string {
	return se.Callback(se, ip, page)
}

func (se *reverseIPSearchEngine) Search(req *AmassRequest, done chan int) {
	var unique []string

	re := AnySubdomainRegex()
	num := se.Limit / se.Quantity
	for i := 0; i < num; i++ {
		page := GetWebPageWithDialContext(
			se.Config.DialContext, se.urlByPageNum(req.Address, i))
		if page == "" {
			break
		}

		for _, sd := range re.FindAllString(page, -1) {
			u := NewUniqueElements(unique, sd)

			if len(u) > 0 {
				unique = append(unique, u...)
				se.Output <- &AmassRequest{
					Name:       sd,
					Tag:        SEARCH,
					Source:     se.Name,
					addDomains: req.addDomains,
				}
			}
		}
		// Do not hit Bing too hard
		time.Sleep(500 * time.Millisecond)
	}
	done <- len(unique)
}

func bingReverseIPURLByPageNum(b *reverseIPSearchEngine, ip string, page int) string {
	first := "1"
	if page > 0 {
		first = strconv.Itoa(page * b.Quantity)
	}
	u, _ := url.Parse("https://www.bing.com/search")
	u.RawQuery = url.Values{"q": {"ip:" + ip},
		"first": {first}, "FORM": {"PORE"}}.Encode()
	return u.String()
}

func BingReverseIPSearch(out chan<- *AmassRequest, config *AmassConfig) ReverseIper {
	b := &reverseIPSearchEngine{
		Name:     "Bing Reverse IP Search",
		Quantity: 10,
		Limit:    50,
		Output:   out,
		Callback: bingReverseIPURLByPageNum,
		Config:   config,
	}
	return b
}

// reverseIPLookup - A searcher that attempts to discover DNS names from an IP address using a single web page
type reverseIPLookup struct {
	Name     string
	Output   chan<- *AmassRequest
	Callback func(string) string
	Config   *AmassConfig
}

func (l *reverseIPLookup) String() string {
	return l.Name
}

func (l *reverseIPLookup) Search(req *AmassRequest, done chan int) {
	var unique []string

	re := AnySubdomainRegex()
	page := GetWebPageWithDialContext(l.Config.DialContext, l.Callback(req.Address))
	if page == "" {
		done <- 0
		return
	}

	for _, sd := range re.FindAllString(page, -1) {
		u := NewUniqueElements(unique, sd)

		if len(u) > 0 {
			unique = append(unique, u...)
			l.Output <- &AmassRequest{
				Name:       sd,
				Tag:        SEARCH,
				Source:     l.Name,
				addDomains: req.addDomains,
			}
		}
	}
	done <- len(unique)
}

func shodanReverseIPURL(ip string) string {
	format := "https://www.shodan.io/host/%s"

	return fmt.Sprintf(format, ip)
}

func ShodanReverseIPSearch(out chan<- *AmassRequest, config *AmassConfig) ReverseIper {
	ss := &reverseIPLookup{
		Name:     "Shodan",
		Output:   out,
		Callback: shodanReverseIPURL,
		Config:   config,
	}
	return ss
}

// reverseDNSLookup - Attempts to discover DNS names from an IP address using a reverse DNS
type reverseDNSLookup struct {
	Name   string
	Output chan<- *AmassRequest
	Config *AmassConfig
}

func (l *reverseDNSLookup) String() string {
	return l.Name
}

func (l *reverseDNSLookup) Search(req *AmassRequest, done chan int) {
	re := AnySubdomainRegex()

	name, err := ReverseDNSWithDialContext(l.Config.DNSDialContext, req.Address)
	if err == nil && re.MatchString(name) {
		// Send the name to be resolved in the forward direction
		l.Output <- &AmassRequest{
			Name:       name,
			Tag:        "dns",
			Source:     l.Name,
			addDomains: req.addDomains,
		}
		done <- 1
		return
	}
	done <- 0
}

func ReverseDNSSearch(out chan<- *AmassRequest, config *AmassConfig) ReverseIper {
	ds := &reverseDNSLookup{
		Name:   "Reverse DNS",
		Output: out,
		Config: config,
	}
	return ds
}
