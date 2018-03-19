// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"io/ioutil"
	"net"
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

type IPRange struct {
	// The first IP address in the range
	Start net.IP

	// The last IP address in the range
	End net.IP
}

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
	activecert := make(chan *AmassRequest, bufSize)
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
	actcertSrv := NewActiveCertService(activecert, dns, config)
	iphistSrv := NewIPHistoryService(nil, netblock, config)
	// Add them to the services slice
	services = append(services, actcertSrv, iphistSrv)
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
	go requestMultiplexer(netblockMux, sweep, activecert, final)
	// This is the where filtering is performed
	go finalCheckpoint(final, config.Output)
	// Start all the services, except the search service
	for _, service := range services {
		service.Start()
	}

	var searchesStarted bool
	if !config.AddDomains {
		searchSrv.Start()
		searchesStarted = true
	}
	// We periodically check if all the services have finished
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for range t.C {
		done := true

		for _, service := range services {
			if service.IsActive() {
				done = false
				break
			}
		}

		if done && !searchSrv.IsActive() {
			if searchesStarted {
				break
			}
			searchSrv.Start()
			searchesStarted = true
		}
	}
	// Stop all the services
	searchSrv.Stop()
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

func AnySubdomainRegex() *regexp.Regexp {
	return regexp.MustCompile(SUBRE + "[a-zA-Z0-9-]{0,61}[.][a-zA-Z]")
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

func RangeHosts(rng *IPRange) []string {
	var ips []string

	stop := net.ParseIP(rng.End.String())
	inc(stop)
	for ip := net.ParseIP(rng.Start.String()); !ip.Equal(stop); inc(ip) {
		ips = append(ips, ip.String())
	}
	return ips
}

// Obtained/modified the next two functions from the following:
// https://gist.github.com/kotakanbe/d3059af990252ba89a82
func NetHosts(cidr *net.IPNet) []string {
	var ips []string

	for ip := cidr.IP.Mask(cidr.Mask); cidr.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	// Remove network address and broadcast address
	return ips[1 : len(ips)-1]
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
