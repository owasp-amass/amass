// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const (
	// Tags used to mark the data source with the Subdomain struct
	DNS     = "dns"
	ALT     = "alt"
	BRUTE   = "brute"
	SEARCH  = "search"
	ARCHIVE = "archive"

	// An IPv4 regular expression
	IPv4RE = "((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.]){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
	// This regular expression + the base domain will match on all names and subdomains
	SUBRE = "(([a-zA-Z0-9]{1}|[a-zA-Z0-9]{1}[a-zA-Z0-9-]{0,61}[a-zA-Z0-9]{1})[.]{1})+"

	USER_AGENT  = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
	ACCEPT      = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
	ACCEPT_LANG = "en-US,en;q=0.8"

	defaultWordlistURL = "https://raw.githubusercontent.com/caffix/amass/master/wordlists/namelist.txt"
)

func StartAmass(config *AmassConfig) error {
	var resolved []chan *AmassRequest
	var services []AmassService

	if err := CheckConfig(config); err != nil {
		return err
	}
	// Setup all the channels used by the AmassServices
	bufSize := 50
	final := make(chan *AmassRequest, bufSize)
	ngram := make(chan *AmassRequest, bufSize)
	brute := make(chan *AmassRequest, bufSize)
	dns := make(chan *AmassRequest, bufSize)
	dnsMux := make(chan *AmassRequest, bufSize)
	netblock := make(chan *AmassRequest, bufSize)
	netblockMux := make(chan *AmassRequest, bufSize)
	reverseip := make(chan *AmassRequest, bufSize)
	archive := make(chan *AmassRequest, bufSize)
	alt := make(chan *AmassRequest, bufSize)
	sweep := make(chan *AmassRequest, bufSize)
	resolved = append(resolved, netblock, archive, alt, brute, ngram)
	// DNS and Reverse IP need the frequency set
	config.Frequency *= 2
	dnsSrv := NewDNSService(dns, dnsMux, config)
	reverseipSrv := NewReverseIPService(reverseip, dns, config)
	// Add these service to the slice
	services = append(services, dnsSrv, reverseipSrv)
	// Setup the service that jump-start the process
	searchSrv := NewSubdomainSearchService(nil, dns, config)
	iphistSrv := NewIPHistoryService(nil, netblock, config)
	// Add them to the services slice
	services = append(services, searchSrv, iphistSrv)
	// These services find more names based on previous findings
	netblockSrv := NewNetblockService(netblock, netblockMux, config)
	archiveSrv := NewArchiveService(archive, dns, config)
	altSrv := NewAlterationService(alt, dns, config)
	sweepSrv := NewSweepService(sweep, reverseip, config)
	// Add these service to the slice
	services = append(services, netblockSrv, archiveSrv, altSrv, sweepSrv)
	// The brute forcing related services are setup here
	bruteSrv := NewBruteForceService(brute, dns, config)
	ngramSrv := NewNgramService(ngram, dns, config)
	// Add these services to the slice
	services = append(services, bruteSrv, ngramSrv)
	// Some service output needs to be sent in multiple directions
	go requestMultiplexer(dnsMux, resolved...)
	go requestMultiplexer(netblockMux, sweep, final)
	// This is the where filtering is performed
	go finalCheckpoint(final, config.Output)
	// Start all the services
	for _, service := range services {
		service.Start()
	}
	// We periodically check if all the services have finished
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for range t.C {
		done := true

		for _, service := range services {
			if service.IsActive() {
				done = false
				break
			}
		}

		if done {
			break
		}
	}
	// Stop all the services
	for _, service := range services {
		service.Stop()
	}
	return nil
}

func requestMultiplexer(in chan *AmassRequest, outs ...chan *AmassRequest) {
	for req := range in {
		for _, out := range outs {
			sendOut(req, out)
		}
	}
}

func finalCheckpoint(in, out chan *AmassRequest) {
	filter := make(map[string]struct{})

	for req := range in {
		if _, found := filter[req.Name]; req.Name == "" || found {
			continue
		}
		filter[req.Name] = struct{}{}
		sendOut(req, out)
	}
}

func sendOut(req *AmassRequest, out chan *AmassRequest) {
	go func() {
		out <- req
	}()
}

// NewUniqueElements - Removes elements that have duplicates in the original or new elements
func NewUniqueElements(orig []string, add ...string) []string {
	var n []string

	for _, av := range add {
		found := false
		s := strings.ToLower(av)

		// Check the original slice for duplicates
		for _, ov := range orig {
			if s == strings.ToLower(ov) {
				found = true
				break
			}
		}
		// Check that we didn't already add it in
		if !found {
			for _, nv := range n {
				if s == nv {
					found = true
					break
				}
			}
		}
		// If no duplicates were found, add the entry in
		if !found {
			n = append(n, s)
		}
	}
	return n
}

// UniqueAppend - Behaves like the Go append, but does not add duplicate elements
func UniqueAppend(orig []string, add ...string) []string {
	return append(orig, NewUniqueElements(orig, add...)...)
}

func SubdomainRegex(domain string) *regexp.Regexp {
	// Change all the periods into literal periods for the regex
	d := strings.Replace(domain, ".", "[.]", -1)

	return regexp.MustCompile(SUBRE + d)
}

func GetWebPage(u string) string {
	client := &http.Client{}

	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return ""
	}

	req.Header.Add("User-Agent", USER_AGENT)
	req.Header.Add("Accept", ACCEPT)
	req.Header.Add("Accept-Language", ACCEPT_LANG)

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}

	in, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	return string(in)
}
