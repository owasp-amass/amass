// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/caffix/amass/amass"
	"github.com/sensepost/maltegolocal/maltegolocal"
)

func main() {
	var domains []string
	names := make(chan *amass.Subdomain, 100)

	lt := maltegolocal.ParseLocalArguments(os.Args)
	domains = append(domains, lt.Value)
	trx := maltegolocal.MaltegoTransform{}

	go func() {
		for {
			n := <-names
			if n.Domain == domains[0] {
				trx.AddEntity("maltego.DNSName", n.Name)
			}
		}
	}()

	trx.AddUIMessage("The amass transform can take a few minutes to complete.", "Inform")
	enumeration(domains, names, amass.DefaultConfig())
	fmt.Println(trx.ReturnOutput())
}

// This is the driver function that performs a complete enumeration.
func enumeration(domains []string, names chan *amass.Subdomain, config amass.AmassConfig) {
	var activity bool
	var completed int
	var filterLock sync.Mutex

	done := make(chan int, 20)
	a := amass.NewAmassWithConfig(config)
	totalSearches := amass.NUM_SEARCHES * len(domains)
	// Start the simple searches to get us started
	startSearches(domains, a, done)
	// Get all the archives to be used
	archives := getArchives(a)
	// When this timer fires, the program will end
	t := time.NewTimer(30 * time.Second)
	defer t.Stop()
	// Filter for not double-checking subdomain names
	filterNames := make(map[string]struct{})
	// Filter for not double-checking IP addresses
	filterRDNS := make(map[string]struct{})
	filter := func(ip string) bool {
		filterLock.Lock()
		defer filterLock.Unlock()

		if _, ok := filterRDNS[ip]; ok {
			return true
		}
		filterRDNS[ip] = struct{}{}
		return false
	}
	// Make sure resolved names are not provided to the user more than once
	legitimate := make(map[string]struct{})
	// Start brute forcing
	go a.BruteForce(domains)
loop:
	for {
		select {
		case sd := <-a.Names: // New subdomains come in here
			sd.Name = trim252F(sd.Name)

			if sd.Name != "" {
				if _, ok := filterNames[sd.Name]; !ok {
					filterNames[sd.Name] = struct{}{}

					if sd.Domain == "" {
						sd.Domain = getDomainFromName(sd.Name, domains)
					}

					if sd.Domain != "" {
						// Is this new name valid?
						a.AddDNSRequest(sd)
					}
				}
			}
			activity = true
		case r := <-a.Resolved: // Names that have been resolved via dns lookup
			r.Name = trim252F(r.Name)

			if _, ok := legitimate[r.Name]; !ok {
				legitimate[r.Name] = struct{}{}

				a.AttemptSweep(r.Domain, r.Address, filter)
				// Give it to the user!
				names <- r
				// Check if this subdomain/host name has an archived web page
				for _, ar := range archives {
					ar.CheckHistory(r)
				}
				// Try altering the names to create new names
				a.ExecuteAlterations(r)
			}
			activity = true
		case <-done: // Searches that have finished
			completed++
		case <-t.C: // Periodic checks happen in here
			if !activity && completed == totalSearches && a.DNSRequestQueueEmpty() {
				// We are done if searches are finished, no dns queries left, and no activity
				break loop
			}
			// Otherwise, keep the process going
			t.Reset(5 * time.Second)
			activity = false
		}
	}
}

func startSearches(domains []string, a *amass.Amass, done chan int) {
	searches := []amass.Searcher{
		a.PGPSearch(),
		a.AskSearch(),
		a.CensysSearch(),
		a.CrtshSearch(),
		a.NetcraftSearch(),
		a.RobtexSearch(),
		a.BingSearch(),
		a.DogpileSearch(),
		a.YahooSearch(),
		a.GigablastSearch(),
		a.VirusTotalSearch(),
	}

	// Fire off the searches
	for _, d := range domains {
		for _, s := range searches {
			go s.Search(d, done)
		}
	}
}

func getArchives(a *amass.Amass) []amass.Archiver {
	archives := []amass.Archiver{
		a.WaybackMachineArchive(),
		a.LibraryCongressArchive(),
		a.ArchiveIsArchive(),
		a.ArchiveItArchive(),
		a.ArquivoArchive(),
		a.BayerischeArchive(),
		a.PermaArchive(),
		a.UKWebArchive(),
		a.UKGovArchive(),
	}
	return archives
}

func getDomainFromName(name string, domains []string) string {
	var result string

	for _, d := range domains {
		if strings.HasSuffix(name, d) {
			result = d
			break
		}
	}
	return result
}

func trim252F(subdomain string) string {
	s := strings.ToLower(subdomain)

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
