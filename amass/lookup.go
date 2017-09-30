// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"os"
	"strings"
	"time"

	"github.com/irfansharif/cfilter"
)

const NUM_SEARCHES int = 10

func startSearches(domain string, subdomains chan string, done chan int) {
	searches := []Searcher{
		PGPSearch(domain, subdomains),
		AskSearch(domain, subdomains),
		CensysSearch(domain, subdomains),
		CrtshSearch(domain, subdomains),
		RobtexSearch(domain, subdomains),
		HackerTargetSearch(domain, subdomains),
		BingSearch(domain, subdomains),
		DogpileSearch(domain, subdomains),
		YahooSearch(domain, subdomains),
		GigablastSearch(domain, subdomains),
	}

	// fire off the searches
	for _, s := range searches {
		go s.Search(done)
	}
	return
}

func executeSearchesForDomains(domains []string, subdomains chan string, done chan int) {
	for _, d := range domains {
		startSearches(d, subdomains, done)
	}
}

func checkForDomains(candidate string, domains []string) bool {
	result := false

	for _, d := range domains {
		if strings.HasSuffix(candidate, d) {
			result = true
			break
		}
	}

	return result
}

func getArchives(subdomains chan string) []Archiver {
	archives := []Archiver{
		WaybackMachineArchive(subdomains),
		LibraryCongressArchive(subdomains),
		ArchiveIsArchive(subdomains),
		ArchiveItArchive(subdomains),
		ArquivoArchive(subdomains),
		BayerischeArchive(subdomains),
		PermaArchive(subdomains),
		UKWebArchive(subdomains),
		UKGovArchive(subdomains),
	}

	return archives
}

// This is the driver function that performs a complete enumeration.
func LookupSubdomainNames(domains []string, names chan *ValidSubdomain, wordlist *os.File, limit int64) {
	var completed int
	var legitimate []string
	var done chan int = make(chan int, 20)
	var subdomains chan string = make(chan string, 200)
	var valid chan *ValidSubdomain = make(chan *ValidSubdomain, 5)
	totalSearches := NUM_SEARCHES * len(domains)

	go executeSearchesForDomains(domains, subdomains, done)
	// initialize the dns resolver that will validate subdomains
	dns := GoogleDNS(valid, subdomains, limit)
	// initialize the archives that will obtain additional subdomains
	archives := getArchives(subdomains)
	// when this timer fires, the program will end
	t := time.NewTimer(5 * time.Second)
	defer t.Stop()
	// cuckoo filter for not double-checking subdomain names
	filter := cfilter.New()
	// detect when the lookup process is finished
	activity := false
	//start brute forcing
	go BruteForce(domains, wordlist, subdomains)

loop:
	for {
		select {
		case sd := <-subdomains: // new subdomains come in here
			s := Trim252F(sd)

			if s != "" && !filter.Lookup([]byte(s)) {
				filter.Insert([]byte(s))

				if checkForDomains(s, domains) {
					// is this new name valid?
					go dns.CheckSubdomain(s)
				}
			}

			activity = true
		case v := <-valid: // subdomains that passed a dns lookup
			v.Subdomain = Trim252F(v.Subdomain)
			n := NewUniqueElements(legitimate, v.Subdomain)

			if len(n) > 0 {
				legitimate = append(legitimate, n...)

				// give it to the user!
				names <- v
				// check if this subdomain/host name has an archived web page
				for _, a := range archives {
					go a.CheckHistory(v.Subdomain)
				}
			}

			activity = true
		case <-done: // searches that have finished
			completed++
		case <-t.C:
			// we are not done if searches are still running
			if !activity && completed == totalSearches {
				break loop
			}
			// keep the process going
			t.Reset(5 * time.Second)
			activity = false
		}
	}
	return
}
