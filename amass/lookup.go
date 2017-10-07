// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"os"
	"strings"
	"time"
)

const NUM_SEARCHES int = 10

func startSearches(domain string, subdomains chan *Subdomain, done chan int) {
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

func executeSearchesForDomains(domains []string, subdomains chan *Subdomain, done chan int) {
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

func getArchives(subdomains chan *Subdomain) []Archiver {
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
func LookupSubdomainNames(domains []string, names chan *Subdomain, wordlist *os.File, maxSmart int, limit int64) {
	var completed int
	var ngramStarted bool
	var legitimate []string

	done := make(chan int, 20)
	subdomains := make(chan *Subdomain, 200)
	valid := make(chan *Subdomain, 5)
	totalSearches := NUM_SEARCHES * len(domains)
	// start the simple searches to get us started
	go executeSearchesForDomains(domains, subdomains, done)
	// initialize the dns resolver that will validate subdomains
	dns := GoogleDNS(valid, subdomains, limit)
	// initialize the archives that will obtain additional subdomains
	archives := getArchives(subdomains)
	// when this timer fires, the program will end
	t := time.NewTimer(20 * time.Second)
	defer t.Stop()
	// filter for not double-checking subdomain names
	filter := make(map[string]bool)
	// detect when the lookup process is finished
	activity := false
	//start brute forcing
	go BruteForce(domains, wordlist, subdomains, limit)
	// setup ngram guessers
	ngrams := make(map[string]Guesser)
	if maxSmart > 0 {
		for _, d := range domains {
			ngrams[d] = NgramGuess(d, subdomains, limit, maxSmart)
		}
	}
	// setup number flipping guessers
	numflip := make(map[string]Guesser)
	for _, d := range domains {
		numflip[d] = NumFlipGuess(d, subdomains)
	}
loop:
	for {
		select {
		case sd := <-subdomains: // new subdomains come in here
			sd.Name = Trim252F(sd.Name)

			if sd.Name != "" {
				if _, ok := filter[sd.Name]; !ok {
					filter[sd.Name] = true

					if checkForDomains(sd.Name, domains) {
						// is this new name valid?
						dns.CheckSubdomain(sd)
					}
				}
			}

			activity = true
		case v := <-valid: // subdomains that passed a dns lookup
			v.Name = Trim252F(v.Name)
			n := NewUniqueElements(legitimate, v.Name)

			if len(n) > 0 {
				legitimate = append(legitimate, n...)

				// give it to the user!
				names <- v
				// check if this subdomain/host name has an archived web page
				for _, a := range archives {
					a.CheckHistory(v)
				}

				// try flipping some numbers for more names
				nf := numflip[v.Domain]
				nf.AddName(v)

				// send the name to the ngram guesser
				if maxSmart > 0 && v.Domain != "" {
					ng := ngrams[v.Domain]
					ng.AddName(v)
				}
			}

			activity = true
		case <-done: // searches that have finished
			completed++
		case <-t.C:
			if !ngramStarted && completed == totalSearches {
				// searches are done, start ngram guessers
				for _, g := range ngrams {
					g.Start()
				}

				ngramStarted = true
			} else if !activity && completed == totalSearches {
				// we are not done if searches are still running
				break loop
			}
			// keep the process going
			t.Reset(10 * time.Second)
			activity = false
		}
	}
	return
}
