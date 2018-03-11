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

	// This regular expression + the base domain will match on all names and subdomains
	SUBRE = "(([a-zA-Z0-9]{1}|[a-zA-Z0-9]{1}[a-zA-Z0-9-]{0,61}[a-zA-Z0-9]{1})[.]{1})+"

	USER_AGENT  = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
	ACCEPT      = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
	ACCEPT_LANG = "en-US,en;q=0.8"
)

func StartAmass(config *AmassConfig) {
	var resolved []chan *AmassRequest
	var services []AmassService

	// Setup all the channels used by the AmassServices
	search := make(chan *AmassRequest)
	ngram := make(chan *AmassRequest)
	brute := make(chan *AmassRequest)
	dns := make(chan *AmassRequest)
	dnsMux := make(chan *AmassRequest)
	netblock := make(chan *AmassRequest)
	netblockMux := make(chan *AmassRequest)
	reverseip := make(chan *AmassRequest)
	archive := make(chan *AmassRequest)
	alt := make(chan *AmassRequest)
	sweep := make(chan *AmassRequest)
	resolved = append(resolved, netblock, archive, alt)

	// DNS and Reverse IP need the frequency set
	config.Frequency *= 2
	dnsSrv := NewDNSService(dns, dnsMux)
	dnsSrv.SetFrequency(config.Frequency)
	reverseipSrv := NewReverseIPService(reverseip, dns)
	reverseipSrv.SetFrequency(config.Frequency)
	// Add these service to the slice
	services = append(services, dnsSrv, reverseipSrv)

	searchSrv := NewSubdomainSearchService(search, dns)
	netblockSrv := NewNetblockService(netblock, netblockMux)
	archiveSrv := NewArchiveService(archive, dns)
	altSrv := NewAlterationService(alt, dns)
	sweepSrv := NewSweepService(sweep, reverseip)
	// Add these service to the slice
	services = append(services, searchSrv, netblockSrv, archiveSrv, altSrv, sweepSrv)

	// The BruteForceService will be created either way
	bruteSrv := NewBruteForceService(brute, dns)
	bruteSrv.SetWordlist(config.Wordlist)
	// Same for the NgramService for guessing names
	ngramSrv := NewNgramService(ngram, dns)
	// Check if we will be linking brute forcing in and starting it
	if config.BruteForcing {
		resolved = append(resolved, brute, ngram)
		// Add these service to the slice
		services = append(services, bruteSrv, ngramSrv)

		if !config.Recursive {
			bruteSrv.DisableRecursive()
			ngramSrv.DisableRecursive()
		}
	}

	// Some service output needs to be sent in multiple directions
	go requestMultiplexer(dnsMux, resolved...)
	go requestMultiplexer(netblockMux, sweep, config.Output)
	// Start all the services
	for _, service := range services {
		service.Start()
	}
	// Send all domains to the Search and Brute Forcing services
	for _, domain := range config.Domains {
		req := &AmassRequest{Domain: domain}

		search <- req
		if config.BruteForcing {
			brute <- req
		}
	}
	// We periodically check if all the services have finished
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
loop:
	for {
		select {
		case <-t.C:
			done := true
			for _, service := range services {
				if service.IsActive() {
					done = false
					break
				}
			}

			if done {
				break loop
			}
		}
	}
	// Stop all the services
	for _, service := range services {
		service.Stop()
	}
}

func requestMultiplexer(in chan *AmassRequest, outs ...chan *AmassRequest) {
	filter := make(map[string]struct{})

	for req := range in {
		if _, found := filter[req.Name]; found {
			continue
		}
		filter[req.Name] = struct{}{}

		for _, out := range outs {
			go sendOut(req, out)
		}
	}
}

func sendOut(req *AmassRequest, out chan *AmassRequest) {
	out <- req
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

func trim252F(name string) string {
	s := strings.ToLower(name)

	re, err := regexp.Compile("^((252f)|(2f)|(3d))+")
	if err != nil {
		return s
	}

	i := re.FindStringIndex(s)
	if i != nil {
		return s[i[1]:]
	}
	return s
}
