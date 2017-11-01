// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	SMART   = "smart"
	FLIP    = "numflip"
	BRUTE   = "brute"
	SEARCH  = "search"
	ARCHIVE = "archive"
	DNSTag  = "dns"
	SHODAN  = "shodan"
)

type Amass struct {
	wordlist    *os.File
	maxSmart    int
	limit       int64
	showReverse bool
	dns         DNSChecker
	subdomains  chan *Subdomain
	valid       chan *Subdomain
	archives    []Archiver
	shodan      *Shodan
}

type AmassConfig struct {
	Wordlist    *os.File
	MaxSmart    int
	Rate        int64
	ShowReverse bool
}

type Searcher interface {
	Search(domain string, done chan int)
	fmt.Stringer
}

type Archiver interface {
	CheckHistory(subdomain *Subdomain)
}

type Guesser interface {
	AddName(name *Subdomain)
	Start()
}

type DNSChecker interface {
	CheckSubdomain(sd *Subdomain)
	TagQueriesFinished(tag string) bool
	AllQueriesFinished() bool
}

type Subdomain struct {
	Name, Domain, Address, Tag string
}

func startSearches(domains []string, subdomains chan *Subdomain, done chan int) {
	searches := []Searcher{
		PGPSearch(subdomains),
		AskSearch(subdomains),
		CensysSearch(subdomains),
		CrtshSearch(subdomains),
		RobtexSearch(subdomains),
		BingSearch(subdomains),
		DogpileSearch(subdomains),
		YahooSearch(subdomains),
		GigablastSearch(subdomains),
	}

	// fire off the searches
	for _, d := range domains {
		for _, s := range searches {
			go s.Search(d, done)
		}
	}
	return
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
func (a *Amass) LookupSubdomainNames(domains []string, names chan *Subdomain) {
	var completed int
	var ngramStarted bool

	done := make(chan int, 20)
	totalSearches := NUM_SEARCHES * len(domains)
	// start the simple searches to get us started
	go startSearches(domains, a.subdomains, done)
	// when this timer fires, the program will end
	t := time.NewTimer(30 * time.Second)
	defer t.Stop()
	// filter for not double-checking subdomain names
	filter := make(map[string]bool)
	// make sure legitimate names are not provided more than once
	legitimate := make(map[string]bool)
	// initialize the dns resolver that will validate subdomains
	dns := GoogleDNS(a.valid, a.subdomains, a.limit, a.showReverse)
	// detect when the lookup process is finished
	activity := false
	//start brute forcing
	go BruteForce(domains, a.wordlist, a.subdomains, a.limit)
	// setup ngram guessers
	ngrams := make(map[string]Guesser)
	if a.maxSmart > 0 {
		for _, d := range domains {
			ngrams[d] = NgramGuess(d, a.subdomains, a.maxSmart)
		}
	}
	// setup the number flip guesser
	numflip := NumFlipGuess(a.subdomains)
loop:
	for {
		select {
		case sd := <-a.subdomains: // new subdomains come in here
			sd.Name = Trim252F(sd.Name)

			if sd.Name != "" {
				if _, ok := filter[sd.Name]; !ok {
					filter[sd.Name] = true

					if sd.Domain == "" {
						sd.Domain = getDomainFromName(sd.Name, domains)
					}

					if sd.Domain != "" {
						// is this new name valid?
						dns.CheckSubdomain(sd)
					}
				}
			}

			activity = true
		case v := <-a.valid: // subdomains that passed a dns lookup
			v.Name = Trim252F(v.Name)

			if _, ok := legitimate[v.Name]; !ok {
				legitimate[v.Name] = true

				// give it to the user!
				names <- v
				// check if this subdomain/host name has an archived web page
				for _, ar := range a.archives {
					ar.CheckHistory(v)
				}

				// try looking for hosts nearby
				a.shodan.FindHosts(v)

				// try flipping some numbers for more names
				numflip.AddName(v)

				// send the name to the ngram guesser
				if a.maxSmart > 0 && v.Domain != "" {
					ng := ngrams[v.Domain]
					ng.AddName(v)
				}
			}

			activity = true
		case <-done: // searches that have finished
			completed++
		case <-t.C: // periodic checks happen in here
			// we will build the ngram corpus as much as possible
			if !ngramStarted && a.maxSmart > 0 &&
				dns.TagQueriesFinished(SEARCH) &&
				dns.TagQueriesFinished(FLIP) &&
				dns.TagQueriesFinished(BRUTE) {

				// searches, brute forcing, and number flips are done
				for _, g := range ngrams {
					g.Start()
				}

				ngramStarted = true
			} else if !activity && completed == totalSearches && dns.AllQueriesFinished() {
				// we are done if searches are finished, no dns queries left, and no activity
				break loop
			}
			// keep the process going
			t.Reset(10 * time.Second)
			activity = false
		}
	}
	return
}

func NewAmass() *Amass {
	return NewAmassWithConfig(nil)
}

func NewAmassWithConfig(config *AmassConfig) *Amass {
	a := new(Amass)

	if config != nil {
		if config.MaxSmart != 0 {
			a.maxSmart = config.MaxSmart
		}

		if config.Rate != 0 {
			a.limit = config.Rate
		}

		if config.Wordlist != nil {
			a.wordlist = config.Wordlist
		}

		if config.ShowReverse {
			a.showReverse = true
		}
	}

	a.subdomains = make(chan *Subdomain, 200)
	a.valid = make(chan *Subdomain, 50)

	// initialize the archives that will obtain additional subdomains
	a.archives = getArchives(a.subdomains)
	// shodan will help find nearby hosts
	a.shodan = ShodanHostLookup(a.subdomains)
	return a
}
